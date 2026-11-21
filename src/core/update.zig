//! Automatic updates from GitHub Releases.
//!
//! One tag publishes a release per language (v<version>-<lang>); every asset
//! has a sibling "<asset>.sig" with a base64 Ed25519 signature made by CI
//! (src/tools/sign.zig). The client trusts only the public key built into
//! it: nothing downloaded is unpacked before its signature checks out.
//!
//! Installing swaps the app next to itself with two renames and keeps the
//! old copy as "<name>.previous" until the new version has started once; if
//! it never does, the next start puts the old copy back (see `startup`).
//! The user's data lives elsewhere and is never touched here.
//!
//! Selection, versions and signatures are pure functions; the file steps
//! work on any directory, so they are tested on fake installs.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Ed25519 = std.crypto.sign.Ed25519;
const SemanticVersion = std.SemanticVersion;
const b64 = std.base64.standard;

/// Generic on purpose: the request says nothing about the user.
pub const user_agent = "BLACKWALL-updater";
const max_index_bytes = 4 << 20;
const max_asset_bytes = 256 << 20;
const max_sig_bytes = 1024;

pub const Config = struct {
    /// "owner/name" of the GitHub repository
    repo: []const u8,
    public_key: [Ed25519.PublicKey.encoded_length]u8,
    lang: []const u8,
    /// version of the running app, X.Y.Z
    version: []const u8,
};

/// How a release is packed for one platform (matches build.zig's package step).
pub const Package = enum {
    /// BLACKWALL.app inside a zip (macOS)
    app_zip,
    /// the window inside a tar.gz, with the service and blackwall-tun next
    /// to it (`companions`; Linux)
    tar_gz,
    /// the executable itself (Windows)
    exe,

    fn ext(p: Package) []const u8 {
        return switch (p) {
            .app_zip => "zip",
            .tar_gz => "tar.gz",
            .exe => "exe",
        };
    }

    /// What the asset unpacks to inside the staging directory.
    fn staged(p: Package) []const u8 {
        return switch (p) {
            .app_zip => "BLACKWALL.app",
            .tar_gz => "blackwall",
            .exe => "blackwall.exe",
        };
    }
};

pub const Platform = struct {
    os: []const u8,
    arch: []const u8,
    package: Package,
};

pub const native: Platform = .{
    .os = switch (builtin.os.tag) {
        .macos => "macos",
        .windows => "windows",
        else => "linux",
    },
    .arch = switch (builtin.cpu.arch) {
        .aarch64 => "arm64",
        else => @tagName(builtin.cpu.arch),
    },
    .package = switch (builtin.os.tag) {
        .macos => .app_zip,
        .windows => .exe,
        else => .tar_gz,
    },
};

// ---------------------------------------------------------------- versions

/// Strict X.Y.Z; release tags never carry pre-release or build parts.
pub fn parseVersion(text: []const u8) ?SemanticVersion {
    const v = SemanticVersion.parse(text) catch return null;
    if (v.pre != null or v.build != null) return null;
    return v;
}

pub const Tag = struct {
    version: SemanticVersion,
    version_text: []const u8,
    lang: []const u8,
};

/// "v0.2.0-ru" → 0.2.0, "ru". The language is split off first: semver
/// would otherwise read it as a pre-release.
pub fn parseTag(tag: []const u8) ?Tag {
    if (tag.len < 2 or tag[0] != 'v') return null;
    const dash = std.mem.indexOfScalar(u8, tag, '-') orelse return null;
    const text = tag[1..dash];
    const lang = tag[dash + 1 ..];
    if (lang.len == 0) return null;
    for (lang) |c| if (!std.ascii.isLower(c)) return null;
    return .{ .version = parseVersion(text) orelse return null, .version_text = text, .lang = lang };
}

pub fn assetName(gpa: std.mem.Allocator, version: []const u8, lang: []const u8, p: Platform) ![]u8 {
    return std.fmt.allocPrint(gpa, "BLACKWALL-{s}-{s}-{s}-{s}.{s}", .{ version, lang, p.os, p.arch, p.package.ext() });
}

/// Every executable carries this marker with its own version (exported from
/// src/app.zig), so an old signed release cannot pose as a new one.
pub const stamp_prefix = "BLACKWALL-VERSION=";

pub fn stamp(comptime version: []const u8) [stamp_prefix.len + version.len + 1]u8 {
    return (stamp_prefix ++ version ++ ";").*;
}

fn hasStamp(bin: []const u8, version: []const u8) bool {
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, bin, pos, stamp_prefix)) |i| {
        const rest = bin[i + stamp_prefix.len ..];
        if (std.mem.startsWith(u8, rest, version) and rest.len > version.len and rest[version.len] == ';') return true;
        pos = i + 1;
    }
    return false;
}

/// CFBundleShortVersionString of an Info.plist as written by build.zig.
pub fn plistVersion(plist: []const u8) ?[]const u8 {
    const key = "<key>CFBundleShortVersionString</key>";
    const k = std.mem.indexOf(u8, plist, key) orelse return null;
    const rest = std.mem.trimStart(u8, plist[k + key.len ..], " \t\r\n");
    if (!std.mem.startsWith(u8, rest, "<string>")) return null;
    const value = rest["<string>".len..];
    const end = std.mem.indexOf(u8, value, "</string>") orelse return null;
    return value[0..end];
}

// ---------------------------------------------------------------- signatures

pub fn decodeKey(text: []const u8) ![Ed25519.PublicKey.encoded_length]u8 {
    @setEvalBranchQuota(10_000);
    const t = std.mem.trim(u8, text, " \t\r\n");
    var key: [Ed25519.PublicKey.encoded_length]u8 = undefined;
    if (try b64.Decoder.calcSizeForSlice(t) != key.len) return error.BadKey;
    try b64.Decoder.decode(&key, t);
    _ = try Ed25519.PublicKey.fromBytes(key);
    return key;
}

/// `sig_text` is the content of a .sig file: base64 of a 64-byte signature.
pub fn verify(public_key: [Ed25519.PublicKey.encoded_length]u8, bytes: []const u8, sig_text: []const u8) error{BadSignature}!void {
    const t = std.mem.trim(u8, sig_text, " \t\r\n");
    var raw: [Ed25519.Signature.encoded_length]u8 = undefined;
    const n = b64.Decoder.calcSizeForSlice(t) catch return error.BadSignature;
    if (n != raw.len) return error.BadSignature;
    b64.Decoder.decode(&raw, t) catch return error.BadSignature;
    const pk = Ed25519.PublicKey.fromBytes(public_key) catch return error.BadSignature;
    Ed25519.Signature.fromBytes(raw).verify(bytes, pk) catch return error.BadSignature;
}

// ---------------------------------------------------------------- release selection

const AssetJson = struct { name: []const u8 };

const ReleaseJson = struct {
    tag_name: []const u8,
    draft: bool = false,
    prerelease: bool = false,
    assets: []const AssetJson = &.{},
};

pub const Found = struct {
    version: SemanticVersion,
    version_text: []const u8,
    tag: []const u8,
    /// asset file name; its signature is "<asset>.sig"
    asset: []const u8,
};

/// The newest published release for our language and platform that is newer
/// than the running version (and than `skip`, a version that was rolled back).
/// `json` is the body of GET /repos/<repo>/releases; results point into `arena`.
pub fn pick(arena: std.mem.Allocator, json: []const u8, cfg: Config, p: Platform, skip: ?SemanticVersion) !?Found {
    const current = parseVersion(cfg.version) orelse return error.BadVersion;
    const releases = try std.json.parseFromSliceLeaky([]const ReleaseJson, arena, json, .{ .ignore_unknown_fields = true });
    var best: ?Found = null;
    for (releases) |r| {
        if (r.draft or r.prerelease) continue;
        const tag = parseTag(r.tag_name) orelse continue;
        if (!std.mem.eql(u8, tag.lang, cfg.lang)) continue;
        if (best) |b| if (tag.version.order(b.version) != .gt) continue;
        const name = try assetName(arena, tag.version_text, cfg.lang, p);
        const sig = try std.fmt.allocPrint(arena, "{s}.sig", .{name});
        if (!hasAsset(r.assets, name) or !hasAsset(r.assets, sig)) continue;
        best = .{ .version = tag.version, .version_text = tag.version_text, .tag = r.tag_name, .asset = name };
    }
    const b = best orelse return null;
    if (b.version.order(current) != .gt) return null;
    if (skip) |s| if (b.version.order(s) != .gt) return null;
    return b;
}

fn hasAsset(assets: []const AssetJson, name: []const u8) bool {
    for (assets) |a| if (std.mem.eql(u8, a.name, name)) return true;
    return false;
}

fn validRepo(repo: []const u8) bool {
    const slash = std.mem.indexOfScalar(u8, repo, '/') orelse return false;
    if (slash == 0 or slash == repo.len - 1) return false;
    for (repo, 0..) |c, i| {
        if (i == slash) continue;
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '.') return false;
    }
    return true;
}

// ---------------------------------------------------------------- network

/// Asks GitHub for the newest release meant for us; null when up to date.
pub fn check(arena: std.mem.Allocator, client: *std.http.Client, cfg: Config, skip: ?SemanticVersion) !?Found {
    if (!validRepo(cfg.repo)) return error.BadRepo;
    const url = try std.fmt.allocPrint(arena, "https://api.github.com/repos/{s}/releases?per_page=20", .{cfg.repo});
    const body = try get(arena, client, url, "application/vnd.github+json", max_index_bytes);
    return pick(arena, body, cfg, native, skip);
}

/// Downloads the asset and its signature; returns the bytes only once the
/// signature is valid for our key.
pub fn download(arena: std.mem.Allocator, client: *std.http.Client, cfg: Config, found: Found) ![]u8 {
    const url = try std.fmt.allocPrint(arena, "https://github.com/{s}/releases/download/{s}/{s}", .{ cfg.repo, found.tag, found.asset });
    const sig_url = try std.fmt.allocPrint(arena, "{s}.sig", .{url});
    const sig = try get(arena, client, sig_url, "application/octet-stream", max_sig_bytes);
    const asset = try get(arena, client, url, "application/octet-stream", max_asset_bytes);
    try verify(cfg.public_key, asset, sig);
    return asset;
}

/// GET with redirects (release files are served from another host) and a
/// hard size limit. Compression is declined so the limit counts real bytes.
fn get(gpa: std.mem.Allocator, client: *std.http.Client, url: []const u8, accept: []const u8, limit: usize) ![]u8 {
    var req = try client.request(.GET, try std.Uri.parse(url), .{
        .keep_alive = false,
        .headers = .{ .user_agent = .{ .override = user_agent }, .accept_encoding = .{ .override = "identity" } },
        .extra_headers = &.{.{ .name = "accept", .value = accept }},
    });
    defer req.deinit();
    try req.sendBodiless();
    var redirect_buf: [16 * 1024]u8 = undefined;
    var res = try req.receiveHead(&redirect_buf);
    if (res.head.status != .ok) return error.BadStatus;
    if (res.head.content_encoding != .identity) return error.Compressed;
    if ((res.head.content_length orelse 0) > limit) return error.TooLarge;
    var transfer: [64]u8 = undefined;
    const body = res.reader(&transfer);
    return body.allocRemaining(gpa, .limited(limit)) catch |err| switch (err) {
        error.ReadFailed => res.bodyErr() orelse error.ReadFailed,
        else => |e| e,
    };
}

// ---------------------------------------------------------------- install

/// Where the running app lives: the bundle on macOS, the executable elsewhere.
/// Everything the updater writes is a sibling of it in `parent`.
pub const Install = struct {
    parent: []const u8,
    /// "BLACKWALL.app" or the executable's file name
    name: []const u8,

    pub const LocateError = error{ NotBundle, Translocated };

    /// Slices point into `exe_path`. On macOS only a real .app bundle
    /// qualifies; a translocated one (run from a quarantined download) is
    /// read-only and must be moved to Applications first.
    pub fn locate(exe_path: []const u8, os: std.Target.Os.Tag) LocateError!Install {
        if (os != .macos) return .{
            .parent = std.fs.path.dirname(exe_path) orelse ".",
            .name = std.fs.path.basename(exe_path),
        };
        if (std.mem.indexOf(u8, exe_path, "/AppTranslocation/") != null) return error.Translocated;
        const at = std.mem.lastIndexOf(u8, exe_path, "/Contents/MacOS/") orelse return error.NotBundle;
        const bundle = exe_path[0..at];
        if (!std.mem.endsWith(u8, bundle, ".app")) return error.NotBundle;
        return .{ .parent = std.fs.path.dirname(bundle) orelse return error.NotBundle, .name = std.fs.path.basename(bundle) };
    }

    const Names = struct {
        buf: [5][Io.Dir.max_name_bytes]u8 = undefined,
        previous: []const u8 = "",
        failed: []const u8 = "",
        marker: []const u8 = "",
        /// the marker's next content before it is renamed over `marker`
        marker_new: []const u8 = "",
        staging: []const u8 = "",

        fn init(n: *Names, name: []const u8) !void {
            n.previous = try std.fmt.bufPrint(&n.buf[0], "{s}.previous", .{name});
            n.failed = try std.fmt.bufPrint(&n.buf[1], "{s}.failed", .{name});
            n.marker = try std.fmt.bufPrint(&n.buf[2], ".{s}.update", .{name});
            n.staging = try std.fmt.bufPrint(&n.buf[3], ".{s}.staging", .{name});
            n.marker_new = try std.fmt.bufPrint(&n.buf[4], ".{s}.update.new", .{name});
        }
    };

    fn openParent(inst: Install, io: Io) !Io.Dir {
        return Io.Dir.cwd().openDir(io, inst.parent, .{});
    }

    /// One rename inside the install's folder. On Windows by MoveFileExW,
    /// which asks only for the right to delete: std's rename also asks to
    /// write, which a running executable refuses, so the app could never
    /// move itself aside (FileBusy, issue #6). A file just written may be
    /// held a moment longer by a virus scanner: that is waited out.
    fn move(inst: Install, dir: Io.Dir, io: Io, from: []const u8, to: []const u8) !void {
        if (comptime builtin.os.tag != .windows) return dir.rename(from, dir, to, io);
        return moveWindows(io, inst.parent, from, to);
    }

    /// Unpacks a verified asset next to the app and checks that it really is
    /// `version`. The running app is not touched.
    pub fn stage(inst: Install, gpa: std.mem.Allocator, io: Io, package: Package, asset: []const u8, version: []const u8) !void {
        var names: Names = .{};
        try names.init(inst.name);
        var dir = try inst.openParent(io);
        defer dir.close(io);
        try dir.deleteTree(io, names.staging);
        var staging = try dir.createDirPathOpen(io, names.staging, .{});
        defer staging.close(io);

        if (package == .exe) {
            try staging.writeFile(io, .{ .sub_path = package.staged(), .data = asset, .flags = .{ .permissions = .executable_file } });
        } else {
            const archive = "asset";
            try staging.writeFile(io, .{ .sub_path = archive, .data = asset });
            const out = try std.fs.path.join(gpa, &.{ inst.parent, names.staging });
            defer gpa.free(out);
            const in = try std.fs.path.join(gpa, &.{ out, archive });
            defer gpa.free(in);
            try runTool(gpa, io, switch (package) {
                .app_zip => &.{ "/usr/bin/ditto", "-x", "-k", in, out },
                else => &.{ "tar", "-xzf", in, "-C", out },
            });
            try staging.deleteFile(io, archive);
        }
        try checkStaged(gpa, io, staging, package, version);
    }

    /// current → <name>.previous, staged → <name>. Both renames stay inside
    /// one directory, so each is atomic; a failed second one is undone.
    pub fn swap(inst: Install, io: Io, package: Package, version: []const u8) !void {
        var names: Names = .{};
        try names.init(inst.name);
        var dir = try inst.openParent(io);
        defer dir.close(io);
        var staged_buf: [Io.Dir.max_path_bytes]u8 = undefined;
        const staged = try std.fmt.bufPrint(&staged_buf, "{s}/{s}", .{ names.staging, package.staged() });

        try dir.deleteTree(io, names.previous);
        // marker first: a swapped-in version must never run without one,
        // or a crash of it could not be rolled back
        try writeMarker(dir, io, &names, .pending, version);
        errdefer dir.deleteFile(io, names.marker) catch {};
        try inst.move(dir, io, inst.name, names.previous);
        inst.move(dir, io, staged, inst.name) catch |err| {
            inst.move(dir, io, names.previous, inst.name) catch {};
            return err;
        };
        if (package == .tar_gz) swapCompanions(dir, io, names.staging);
        dir.deleteTree(io, names.staging) catch {};
    }

    pub const Startup = union(enum) {
        /// nothing pending; carries a version that was rolled back, which
        /// must not be installed again
        normal: ?SemanticVersion,
        /// first start of a fresh install: call `confirm` once it runs
        verifying,
        /// the fresh install never confirmed; the old copy is back in place
        /// and should be relaunched
        rolled_back,
    };

    /// Call once early at every start, before the updater runs.
    pub fn startup(inst: Install, io: Io) !Startup {
        var names: Names = .{};
        try names.init(inst.name);
        var dir = try inst.openParent(io);
        defer dir.close(io);
        var buf: [128]u8 = undefined;
        const m = try readMarker(dir, io, names.marker, &buf) orelse {
            cleanup(dir, io, &names);
            return .{ .normal = null };
        };
        switch (m.state) {
            .pending => {
                try writeMarker(dir, io, &names, .launched, m.version);
                return .verifying;
            },
            .launched => {
                if (!try inst.putBack(dir, io, &names, m.version)) return .{ .normal = null };
                return .rolled_back;
            },
            .rejected => {
                cleanup(dir, io, &names);
                return .{ .normal = parseVersion(m.version) };
            },
        }
    }

    /// The fresh copy aside, the previous one back at its place, and its
    /// version marked so it is not installed again. False when there was
    /// no previous copy to go back to.
    fn putBack(inst: Install, dir: Io.Dir, io: Io, names: *const Names, version: []const u8) !bool {
        dir.access(io, names.previous, .{}) catch {
            dir.deleteFile(io, names.marker) catch {};
            return false;
        };
        try dir.deleteTree(io, names.failed);
        try inst.move(dir, io, inst.name, names.failed);
        inst.move(dir, io, names.previous, inst.name) catch |err| {
            // never leave the user without an app at its usual place
            inst.move(dir, io, names.failed, inst.name) catch {};
            return err;
        };
        restoreCompanions(dir, io);
        try writeMarker(dir, io, names, .rejected, version);
        // a running Windows executable cannot be deleted; the next start does it
        dir.deleteTree(io, names.failed) catch {};
        return true;
    }

    /// The swapped-in copy could not even be started: put the running one
    /// back now, while it still runs (otherwise nothing would start at all).
    pub fn undo(inst: Install, io: Io, version: []const u8) !void {
        var names: Names = .{};
        try names.init(inst.name);
        var dir = try inst.openParent(io);
        defer dir.close(io);
        _ = try inst.putBack(dir, io, &names, version);
    }

    /// The fresh version started fine: drop the old copy.
    pub fn confirm(inst: Install, io: Io) void {
        var names: Names = .{};
        names.init(inst.name) catch return;
        var dir = inst.openParent(io) catch return;
        defer dir.close(io);
        dir.deleteTree(io, names.previous) catch |err| std.log.warn("update: old copy not removed: {t}", .{err});
        dropCompanions(dir, io);
        dir.deleteFile(io, names.marker) catch {};
    }

    /// Starts the app now at `<parent>/<name>` as a new process.
    pub fn relaunch(inst: Install, gpa: std.mem.Allocator, io: Io) !void {
        const path = try std.fs.path.join(gpa, &.{ inst.parent, inst.name });
        defer gpa.free(path);
        if (builtin.os.tag == .macos) return runTool(gpa, io, &.{ "/usr/bin/open", "-n", path });
        _ = try std.process.spawn(io, .{ .argv = &.{path}, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore });
    }
};

const win = struct {
    extern "kernel32" fn MoveFileExW(from: [*:0]const u16, to: [*:0]const u16, flags: u32) callconv(.winapi) c_int;
    extern "kernel32" fn GetLastError() callconv(.winapi) u32;
    const MOVEFILE_REPLACE_EXISTING = 0x1;
    const ERROR_ACCESS_DENIED = 5;
    const ERROR_SHARING_VIOLATION = 32;
    const ERROR_LOCK_VIOLATION = 33;
};

/// `parent\from` to `parent\to`, retried for a few seconds while another
/// process (a virus scanner) holds the file.
fn moveWindows(io: Io, parent: []const u8, from: []const u8, to: []const u8) !void {
    var a_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    var b_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    var a: [Io.Dir.max_path_bytes:0]u16 = undefined;
    var b: [Io.Dir.max_path_bytes:0]u16 = undefined;
    const an = try std.unicode.wtf8ToWtf16Le(&a, try std.fmt.bufPrint(&a_buf, "{s}\\{s}", .{ parent, from }));
    a[an] = 0;
    const bn = try std.unicode.wtf8ToWtf16Le(&b, try std.fmt.bufPrint(&b_buf, "{s}\\{s}", .{ parent, to }));
    b[bn] = 0;
    for (0..40) |_| {
        if (win.MoveFileExW(a[0..an :0], b[0..bn :0], win.MOVEFILE_REPLACE_EXISTING) != 0) return;
        switch (win.GetLastError()) {
            win.ERROR_SHARING_VIOLATION, win.ERROR_LOCK_VIOLATION, win.ERROR_ACCESS_DENIED => io.sleep(.fromMilliseconds(250), .awake) catch {},
            2, 3 => return error.FileNotFound, // ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND
            else => return error.Unexpected,
        }
    }
    return error.FileBusy;
}

const MarkerState = enum { pending, launched, rejected };
const Marker = struct { state: MarkerState, version: []const u8 };

/// Written aside and renamed over the old one: a crash mid-write must not
/// leave a torn marker, which would read as "no update" and drop .previous.
fn writeMarker(dir: Io.Dir, io: Io, names: *const Install.Names, state: MarkerState, version: []const u8) !void {
    var buf: [128]u8 = undefined;
    const data = try std.fmt.bufPrint(&buf, "{t} {s}\n", .{ state, version });
    try dir.writeFile(io, .{ .sub_path = names.marker_new, .data = data });
    try dir.rename(names.marker_new, dir, names.marker, io);
}

/// null only when there is no marker; any other read error is returned so
/// that a transient failure never counts as "nothing pending".
fn readMarker(dir: Io.Dir, io: Io, name: []const u8, buf: []u8) !?Marker {
    const data = dir.readFile(io, name, buf) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => |e| return e,
    };
    var it = std.mem.tokenizeAny(u8, data, " \r\n");
    const state = std.meta.stringToEnum(MarkerState, it.next() orelse return null) orelse return null;
    return .{ .state = state, .version = it.next() orelse "" };
}

/// Files that travel with the window in a Linux package. The service is
/// replaced with the window; blackwall-tun only when it changed, because a
/// new file loses the network capability granted to the old one.
const companions = [_][]const u8{ "blackwall-service", "blackwall-tun" };
const keep_if_same = "blackwall-tun";

fn swapCompanions(dir: Io.Dir, io: Io, staging: []const u8) void {
    for (companions) |name| {
        var staged_buf: [Io.Dir.max_path_bytes]u8 = undefined;
        var prev_buf: [Io.Dir.max_path_bytes]u8 = undefined;
        const staged = std.fmt.bufPrint(&staged_buf, "{s}/{s}", .{ staging, name }) catch continue;
        const prev = std.fmt.bufPrint(&prev_buf, "{s}.previous", .{name}) catch continue;
        dir.access(io, staged, .{}) catch continue;
        if (std.mem.eql(u8, name, keep_if_same) and sameFile(dir, io, staged, name)) continue;
        dir.deleteFile(io, prev) catch {};
        dir.rename(name, dir, prev, io) catch {};
        dir.rename(staged, dir, name, io) catch |err| {
            std.log.warn("update: {s} not replaced: {t}", .{ name, err });
            dir.rename(prev, dir, name, io) catch {};
        };
    }
}

/// The window went back to its old copy: so do the files that came with it.
fn restoreCompanions(dir: Io.Dir, io: Io) void {
    for (companions) |name| {
        var prev_buf: [Io.Dir.max_path_bytes]u8 = undefined;
        const prev = std.fmt.bufPrint(&prev_buf, "{s}.previous", .{name}) catch continue;
        dir.access(io, prev, .{}) catch continue;
        dir.rename(prev, dir, name, io) catch |err| std.log.warn("update: {s} not restored: {t}", .{ name, err });
    }
}

fn dropCompanions(dir: Io.Dir, io: Io) void {
    for (companions) |name| {
        var prev_buf: [Io.Dir.max_path_bytes]u8 = undefined;
        const prev = std.fmt.bufPrint(&prev_buf, "{s}.previous", .{name}) catch continue;
        dir.deleteFile(io, prev) catch {};
    }
}

fn sameFile(dir: Io.Dir, io: Io, a: []const u8, b: []const u8) bool {
    var ha: [32]u8 = undefined;
    var hb: [32]u8 = undefined;
    if (!hashFile(dir, io, a, &ha) or !hashFile(dir, io, b, &hb)) return false;
    return std.mem.eql(u8, &ha, &hb);
}

fn hashFile(dir: Io.Dir, io: Io, path: []const u8, out: *[32]u8) bool {
    var f = dir.openFile(io, path, .{}) catch return false;
    defer f.close(io);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [64 * 1024]u8 = undefined;
    var r = f.reader(io, &.{});
    while (true) {
        const n = r.interface.readSliceShort(&buf) catch return false;
        if (n == 0) break;
        h.update(buf[0..n]);
    }
    h.final(out);
    return true;
}

/// Leftovers of an earlier update that finished or was interrupted.
fn cleanup(dir: Io.Dir, io: Io, names: *const Install.Names) void {
    for ([_][]const u8{ names.previous, names.failed, names.staging, names.marker_new }) |n| {
        dir.deleteTree(io, n) catch |err| std.log.warn("update: {s} not removed: {t}", .{ n, err });
    }
    dropCompanions(dir, io);
}

fn checkStaged(gpa: std.mem.Allocator, io: Io, staging: Io.Dir, package: Package, version: []const u8) !void {
    const exe_path = switch (package) {
        .app_zip => blk: {
            var buf: [4096]u8 = undefined;
            const plist = try staging.readFile(io, "BLACKWALL.app/Contents/Info.plist", &buf);
            const v = plistVersion(plist) orelse return error.VersionMismatch;
            if (!std.mem.eql(u8, v, version)) return error.VersionMismatch;
            break :blk "BLACKWALL.app/Contents/MacOS/blackwall";
        },
        else => package.staged(),
    };
    const bin = try staging.readFileAlloc(io, exe_path, gpa, .limited(max_asset_bytes));
    defer gpa.free(bin);
    if (!hasStamp(bin, version)) return error.VersionMismatch;
    // macOS refuses to start an app built for a newer system than its own
    if (package == .app_zip) if (machoMinOs(bin)) |need| if (systemVersion()) |have| {
        if (need.order(have) == .gt) return error.NeedsNewerSystem;
    };
}

/// The oldest macOS a Mach-O executable starts on (LC_BUILD_VERSION, or
/// LC_VERSION_MIN_MACOSX in older files); null when it says nothing.
pub fn machoMinOs(bin: []const u8) ?SemanticVersion {
    if (bin.len < 32 or std.mem.readInt(u32, bin[0..4], .little) != 0xfeedfacf) return null;
    const ncmds = std.mem.readInt(u32, bin[16..20], .little);
    var at: usize = 32;
    for (0..ncmds) |_| {
        if (at + 16 > bin.len) return null;
        const cmd = std.mem.readInt(u32, bin[at..][0..4], .little);
        const size = std.mem.readInt(u32, bin[at + 4 ..][0..4], .little);
        const packed_version: ?u32 = switch (cmd) {
            0x32 => std.mem.readInt(u32, bin[at + 12 ..][0..4], .little),
            0x24 => std.mem.readInt(u32, bin[at + 8 ..][0..4], .little),
            else => null,
        };
        if (packed_version) |v| return .{ .major = v >> 16, .minor = (v >> 8) & 0xff, .patch = v & 0xff };
        if (size < 8) return null;
        at += size;
    }
    return null;
}

/// This Mac's macOS version; null elsewhere or when it cannot be read.
fn systemVersion() ?SemanticVersion {
    if (comptime builtin.os.tag != .macos) return null;
    var buf: [32]u8 = undefined;
    var len: usize = buf.len;
    if (std.c.sysctlbyname("kern.osproductversion", &buf, &len, null, 0) != 0) return null;
    return parseLooseVersion(std.mem.sliceTo(buf[0..len], 0));
}

/// "26.6.2" or "26.6"
fn parseLooseVersion(text: []const u8) ?SemanticVersion {
    var it = std.mem.splitScalar(u8, text, '.');
    var parts: [3]usize = .{ 0, 0, 0 };
    var n: usize = 0;
    while (it.next()) |p| : (n += 1) {
        if (n == 3) return null;
        parts[n] = std.fmt.parseInt(usize, p, 10) catch return null;
    }
    if (n < 2) return null;
    return .{ .major = parts[0], .minor = parts[1], .patch = parts[2] };
}

test "the oldest macOS an executable asks for" {
    var bin: [32 + 24 + 32]u8 = @splat(0);
    std.mem.writeInt(u32, bin[0..4], 0xfeedfacf, .little);
    std.mem.writeInt(u32, bin[16..20], 2, .little);
    // LC_UUID first, then LC_BUILD_VERSION platform macOS, minos 26.7.2, sdk 26.5
    std.mem.writeInt(u32, bin[32..36], 0x1b, .little);
    std.mem.writeInt(u32, bin[36..40], 24, .little);
    std.mem.writeInt(u32, bin[56..60], 0x32, .little);
    std.mem.writeInt(u32, bin[60..64], 32, .little);
    std.mem.writeInt(u32, bin[64..68], 1, .little);
    std.mem.writeInt(u32, bin[68..72], (26 << 16) | (7 << 8) | 2, .little);
    std.mem.writeInt(u32, bin[72..76], (26 << 16) | (5 << 8), .little);
    const v = machoMinOs(&bin).?;
    try testing.expectEqual(.gt, v.order(parseLooseVersion("26.6.2").?));
    try testing.expectEqual(.eq, v.order(parseLooseVersion("26.7.2").?));
    try testing.expectEqual(.lt, parseLooseVersion("13.0").?.order(parseLooseVersion("26.6").?));
    try testing.expect(machoMinOs("not a mach-o file at all, really....") == null);
    try testing.expect(parseLooseVersion("26") == null);
}

fn runTool(gpa: std.mem.Allocator, io: Io, argv: []const []const u8) !void {
    const res = try std.process.run(gpa, io, .{ .argv = argv, .stdout_limit = .limited(64 << 10), .stderr_limit = .limited(64 << 10) });
    defer gpa.free(res.stdout);
    defer gpa.free(res.stderr);
    if (!res.term.success()) {
        std.log.warn("update: {s} failed: {s}", .{ argv[0], res.stderr });
        return error.ToolFailed;
    }
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test {
    // the network half only runs in release builds; keep it compiling
    testing.refAllDecls(@This());
    testing.refAllDecls(Install);
}

test "semver order and tag parsing" {
    try testing.expectEqual(.gt, parseVersion("0.10.0").?.order(parseVersion("0.9.9").?));
    try testing.expectEqual(.lt, parseVersion("1.2.3").?.order(parseVersion("1.10.0").?));
    try testing.expect(parseVersion("1.2.3-beta") == null);
    try testing.expect(parseVersion("1.2") == null);

    const t = parseTag("v0.10.0-ru").?;
    try testing.expectEqualStrings("ru", t.lang);
    try testing.expectEqualStrings("0.10.0", t.version_text);
    try testing.expect(parseTag("v0.10.0") == null);
    try testing.expect(parseTag("0.10.0-ru") == null);
    try testing.expect(parseTag("v0.10.0-rc1-ru") == null);
    try testing.expect(parseTag("v0.10-ru") == null);
}

test "asset names match the package step" {
    const name = try assetName(testing.allocator, "0.2.0", "zh", .{ .os = "macos", .arch = "arm64", .package = .app_zip });
    defer testing.allocator.free(name);
    try testing.expectEqualStrings("BLACKWALL-0.2.0-zh-macos-arm64.zip", name);
    const lin = try assetName(testing.allocator, "1.0.0", "en", .{ .os = "linux", .arch = "x86_64", .package = .tar_gz });
    defer testing.allocator.free(lin);
    try testing.expectEqualStrings("BLACKWALL-1.0.0-en-linux-x86_64.tar.gz", lin);
}

test "signature verifies, tampering does not" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(7));
    const msg = "release bytes";
    const sig = try kp.sign(msg, null);
    var sig_b64: [b64.Encoder.calcSize(64)]u8 = undefined;
    _ = b64.Encoder.encode(&sig_b64, &sig.toBytes());
    var key_b64: [b64.Encoder.calcSize(32)]u8 = undefined;
    _ = b64.Encoder.encode(&key_b64, &kp.public_key.toBytes());
    const key = try decodeKey(&key_b64);

    try verify(key, msg, &sig_b64);
    try verify(key, msg, sig_b64 ++ "\n");
    try testing.expectError(error.BadSignature, verify(key, "release byteS", &sig_b64));
    var bad = sig_b64;
    bad[3] = if (bad[3] == 'A') 'B' else 'A';
    try testing.expectError(error.BadSignature, verify(key, msg, &bad));
    const other = try Ed25519.KeyPair.generateDeterministic(@splat(8));
    try testing.expectError(error.BadSignature, verify(other.public_key.toBytes(), msg, &sig_b64));
    try testing.expectError(error.BadSignature, verify(key, msg, "not base64!"));
    try testing.expectError(error.BadKey, decodeKey("AAAA"));
}

const sample_releases =
    \\[
    \\ {"tag_name":"v0.3.0-ru","draft":true,"prerelease":false,"name":null,
    \\  "assets":[{"name":"BLACKWALL-0.3.0-ru-macos-arm64.zip"},{"name":"BLACKWALL-0.3.0-ru-macos-arm64.zip.sig"}]},
    \\ {"tag_name":"v0.2.1-ru","draft":false,"prerelease":true,
    \\  "assets":[{"name":"BLACKWALL-0.2.1-ru-macos-arm64.zip"},{"name":"BLACKWALL-0.2.1-ru-macos-arm64.zip.sig"}]},
    \\ {"tag_name":"v0.10.0-en","draft":false,"prerelease":false,
    \\  "assets":[{"name":"BLACKWALL-0.10.0-en-macos-arm64.zip"},{"name":"BLACKWALL-0.10.0-en-macos-arm64.zip.sig"}]},
    \\ {"tag_name":"v0.10.0-ru","draft":false,"prerelease":false,"body":"notes","author":{"login":"x"},
    \\  "assets":[{"name":"BLACKWALL-0.10.0-ru-macos-arm64.zip","size":123,"browser_download_url":"https://x"},
    \\            {"name":"BLACKWALL-0.10.0-ru-macos-arm64.zip.sig","size":88},
    \\            {"name":"BLACKWALL-0.10.0-ru-linux-x86_64.tar.gz"}]},
    \\ {"tag_name":"v0.9.9-ru","draft":false,"prerelease":false,
    \\  "assets":[{"name":"BLACKWALL-0.9.9-ru-macos-arm64.zip"},{"name":"BLACKWALL-0.9.9-ru-macos-arm64.zip.sig"},
    \\            {"name":"BLACKWALL-0.9.9-ru-linux-x86_64.tar.gz"},{"name":"BLACKWALL-0.9.9-ru-linux-x86_64.tar.gz.sig"}]},
    \\ {"tag_name":"nightly","draft":false,"prerelease":false,"assets":[]}
    \\]
;

test "pick the newest signed release for our language and platform" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const mac: Platform = .{ .os = "macos", .arch = "arm64", .package = .app_zip };
    const linux: Platform = .{ .os = "linux", .arch = "x86_64", .package = .tar_gz };
    var cfg: Config = .{ .repo = "o/r", .public_key = @splat(0), .lang = "ru", .version = "0.9.0" };

    const f = (try pick(a, sample_releases, cfg, mac, null)).?;
    try testing.expectEqualStrings("v0.10.0-ru", f.tag);
    try testing.expectEqualStrings("BLACKWALL-0.10.0-ru-macos-arm64.zip", f.asset);

    // 0.10.0 has no signed Linux build, so Linux gets 0.9.9
    try testing.expectEqualStrings("v0.9.9-ru", (try pick(a, sample_releases, cfg, linux, null)).?.tag);

    cfg.version = "0.10.0";
    try testing.expect(try pick(a, sample_releases, cfg, mac, null) == null);
    cfg.version = "0.9.0";
    try testing.expect(try pick(a, sample_releases, cfg, mac, parseVersion("0.10.0")) == null);
    cfg.lang = "zh";
    try testing.expect(try pick(a, sample_releases, cfg, mac, null) == null);
}

test "repository names" {
    try testing.expect(validRepo("owner/BLACKWALL.vpn-1_x"));
    try testing.expect(!validRepo("owner"));
    try testing.expect(!validRepo("/repo"));
    try testing.expect(!validRepo("o/r/../x"));
    try testing.expect(!validRepo("o/r?x=1"));
}

test "install location" {
    const mac = try Install.locate("/Applications/BLACKWALL.app/Contents/MacOS/blackwall", .macos);
    try testing.expectEqualStrings("/Applications", mac.parent);
    try testing.expectEqualStrings("BLACKWALL.app", mac.name);
    try testing.expectError(error.NotBundle, Install.locate("/Users/x/VPN/zig-out/bin/blackwall", .macos));
    try testing.expectError(error.Translocated, Install.locate("/private/var/folders/ab/T/AppTranslocation/1F/d/BLACKWALL.app/Contents/MacOS/blackwall", .macos));
    const lin = try Install.locate("/opt/blackwall/blackwall", .linux);
    try testing.expectEqualStrings("/opt/blackwall", lin.parent);
    try testing.expectEqualStrings("blackwall", lin.name);
}

test "version stamp and Info.plist" {
    const bin = "\x00junk" ++ stamp("0.10.0") ++ "more";
    try testing.expect(hasStamp(bin, "0.10.0"));
    try testing.expect(!hasStamp(bin, "0.1.0"));
    try testing.expect(!hasStamp(bin, "0.10"));
    const plist = "<dict>\n  <key>CFBundleShortVersionString</key><string>0.2.0</string>\n</dict>";
    try testing.expectEqualStrings("0.2.0", plistVersion(plist).?);
    try testing.expect(plistVersion("<dict></dict>") == null);
}

fn tmpPath(tmp: *const testing.TmpDir) ![]u8 {
    return std.fs.path.join(testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
}

fn readAll(dir: Io.Dir, path: []const u8, buf: []u8) ![]const u8 {
    return dir.readFile(testing.io, path, buf);
}

test "file install: swap, confirm, rollback" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const parent = try tmpPath(&tmp);
    defer testing.allocator.free(parent);
    const inst: Install = .{ .parent = parent, .name = "blackwall" };
    var buf: [256]u8 = undefined;

    try tmp.dir.writeFile(io, .{ .sub_path = "blackwall", .data = "old " ++ stamp("0.1.0") });
    // a signed asset that claims to be 0.2.0 but is the old build is refused
    try testing.expectError(error.VersionMismatch, inst.stage(testing.allocator, io, .exe, "x " ++ stamp("0.1.0"), "0.2.0"));
    try testing.expectEqualStrings("old " ++ stamp("0.1.0"), try readAll(tmp.dir, "blackwall", &buf));

    // the staged file vanished: the current one is put back, no marker is left
    try inst.stage(testing.allocator, io, .exe, "new " ++ stamp("0.2.0"), "0.2.0");
    try tmp.dir.deleteFile(io, ".blackwall.staging/blackwall.exe");
    try testing.expectError(error.FileNotFound, inst.swap(io, .exe, "0.2.0"));
    try testing.expectEqualStrings("old " ++ stamp("0.1.0"), try readAll(tmp.dir, "blackwall", &buf));
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, ".blackwall.update", .{}));

    try inst.stage(testing.allocator, io, .exe, "new " ++ stamp("0.2.0"), "0.2.0");
    try inst.swap(io, .exe, "0.2.0");
    try testing.expectEqualStrings("pending 0.2.0\n", try readAll(tmp.dir, ".blackwall.update", &buf));
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, ".blackwall.update.new", .{}));
    try testing.expectEqualStrings("new " ++ stamp("0.2.0"), try readAll(tmp.dir, "blackwall", &buf));
    try testing.expectEqualStrings("old " ++ stamp("0.1.0"), try readAll(tmp.dir, "blackwall.previous", &buf));

    // first start of the new version, then it confirms
    try testing.expectEqual(.verifying, try inst.startup(io));
    inst.confirm(io);
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, "blackwall.previous", .{}));
    try testing.expectEqual(Install.Startup{ .normal = null }, try inst.startup(io));

    // 0.3.0 is installed but never confirms: the next start restores 0.2.0
    try inst.stage(testing.allocator, io, .exe, "bad " ++ stamp("0.3.0"), "0.3.0");
    try inst.swap(io, .exe, "0.3.0");
    try testing.expectEqual(.verifying, try inst.startup(io));
    try testing.expectEqual(.rolled_back, try inst.startup(io));
    try testing.expectEqualStrings("new " ++ stamp("0.2.0"), try readAll(tmp.dir, "blackwall", &buf));
    const after = try inst.startup(io);
    try testing.expectEqual(.eq, after.normal.?.order(parseVersion("0.3.0").?));
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, "blackwall.failed", .{}));
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, ".blackwall.staging", .{}));
}

/// A fake BLACKWALL.app made the way build.zig makes the real one.
fn fakeBundle(dir: Io.Dir, root: []const u8, comptime version: []const u8) !void {
    const io = testing.io;
    var buf: [256]u8 = undefined;
    var app = try dir.createDirPathOpen(io, try std.fmt.bufPrint(&buf, "{s}/Contents/MacOS", .{root}), .{});
    app.close(io);
    try dir.writeFile(io, .{
        .sub_path = try std.fmt.bufPrint(&buf, "{s}/Contents/Info.plist", .{root}),
        .data = "<plist><dict>\n  <key>CFBundleShortVersionString</key><string>" ++ version ++ "</string>\n</dict></plist>\n",
    });
    try dir.writeFile(io, .{
        .sub_path = try std.fmt.bufPrint(&buf, "{s}/Contents/MacOS/blackwall", .{root}),
        .data = "bin " ++ stamp(version),
        .flags = .{ .permissions = .executable_file },
    });
}

test "macOS bundle: unzip with ditto, swap, roll back" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const parent = try tmpPath(&tmp);
    defer gpa.free(parent);
    var buf: [512]u8 = undefined;

    try fakeBundle(tmp.dir, "BLACKWALL.app", "0.1.0");
    try tmp.dir.writeFile(io, .{ .sub_path = "BLACKWALL.app/Contents/old-only", .data = "0.1.0 content" });
    try tmp.dir.writeFile(io, .{ .sub_path = "Other.app", .data = "not ours" });
    // the release zip, made exactly like build.zig does it
    try fakeBundle(tmp.dir, "build/BLACKWALL.app", "0.2.0");
    const src = try std.fs.path.join(gpa, &.{ parent, "build", "BLACKWALL.app" });
    defer gpa.free(src);
    const zip = try std.fs.path.join(gpa, &.{ parent, "release.zip" });
    defer gpa.free(zip);
    try runTool(gpa, io, &.{ "/usr/bin/ditto", "-c", "-k", "--norsrc", "--noextattr", "--keepParent", src, zip });
    const asset = try tmp.dir.readFileAlloc(io, "release.zip", gpa, .limited(1 << 20));
    defer gpa.free(asset);

    var exe_buf: [512]u8 = undefined;
    const exe = try std.fmt.bufPrint(&exe_buf, "{s}/BLACKWALL.app/Contents/MacOS/blackwall", .{parent});
    const inst = try Install.locate(exe, .macos);
    try testing.expectEqualStrings(parent, inst.parent);

    try testing.expectError(error.VersionMismatch, inst.stage(gpa, io, .app_zip, asset, "0.3.0"));
    try inst.stage(gpa, io, .app_zip, asset, "0.2.0");
    try inst.swap(io, .app_zip, "0.2.0");
    try testing.expectEqualStrings("0.2.0", plistVersion(try readAll(tmp.dir, "BLACKWALL.app/Contents/Info.plist", &buf)).?);
    try testing.expectEqualStrings("0.1.0", plistVersion(try readAll(tmp.dir, "BLACKWALL.app.previous/Contents/Info.plist", &buf)).?);
    try tmp.dir.access(io, "BLACKWALL.app/Contents/MacOS/blackwall", .{ .execute = true });

    // the new version crashes before it confirms: the old bundle comes back
    try testing.expectEqual(.verifying, try inst.startup(io));
    try testing.expectEqual(.rolled_back, try inst.startup(io));
    try testing.expectEqualStrings("0.1.0", plistVersion(try readAll(tmp.dir, "BLACKWALL.app/Contents/Info.plist", &buf)).?);
    try testing.expectEqualStrings("0.1.0 content", try readAll(tmp.dir, "BLACKWALL.app/Contents/old-only", &buf));
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, "BLACKWALL.app.failed", .{}));

    // install again (a later release) and confirm: the old copy goes away
    try inst.stage(gpa, io, .app_zip, asset, "0.2.0");
    try inst.swap(io, .app_zip, "0.2.0");
    try testing.expectEqual(.verifying, try inst.startup(io));
    inst.confirm(io);
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, "BLACKWALL.app.previous", .{}));
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, ".BLACKWALL.app.update", .{}));
    try testing.expectEqualStrings("0.2.0", plistVersion(try readAll(tmp.dir, "BLACKWALL.app/Contents/Info.plist", &buf)).?);
    try testing.expectEqualStrings("not ours", try readAll(tmp.dir, "Other.app", &buf));
}

test "Windows: a running executable moves aside, as the app does to update itself" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];
    // a copy of cmd.exe, running a few seconds
    const cmd = try Io.Dir.cwd().readFileAlloc(io, "C:\\Windows\\System32\\cmd.exe", std.testing.allocator, .limited(16 << 20));
    defer std.testing.allocator.free(cmd);
    try tmp.dir.writeFile(io, .{ .sub_path = "app.exe", .data = cmd });
    var exe_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const exe = try std.fmt.bufPrint(&exe_buf, "{s}\\app.exe", .{dir});
    var child = try std.process.spawn(io, .{ .argv = &.{ exe, "/c", "ping -n 6 127.0.0.1 >nul" }, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore });
    defer {
        child.kill(io);
    }
    io.sleep(.fromMilliseconds(300), .awake) catch {};
    // std asks to write to it as well, which Windows refuses while it runs
    try std.testing.expectError(error.FileBusy, tmp.dir.rename("app.exe", tmp.dir, "app.exe.previous", io));
    const inst: Install = .{ .parent = dir, .name = "app.exe" };
    try inst.move(tmp.dir, io, "app.exe", "app.exe.previous");
    try tmp.dir.access(io, "app.exe.previous", .{});
    try tmp.dir.writeFile(io, .{ .sub_path = "new.exe", .data = "MZ" });
    try inst.move(tmp.dir, io, "new.exe", "app.exe");
    try tmp.dir.access(io, "app.exe", .{});
}
