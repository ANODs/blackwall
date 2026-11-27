//! The window's side of automatic updates: what was left by the previous
//! run is finished or undone at start, a background thread checks for a
//! release and stages it, and the frame loop swaps it in at a quiet moment
//! (update.zig does the checking, the verifying and the swapping).

const std = @import("std");
const builtin = @import("builtin");
const update = @import("update");
const build_options = @import("build_options");
const app = @import("../app.zig");
const tr = @import("../i18n.zig").t;
const Io = std.Io;

/// Every build knows the project's releases and their signing key, unless
/// it was made with `-Dupdate-repo=` (empty): that one never updates itself.
pub const built = build_options.update_repo.len > 0;

const update_cfg: update.Config = .{
    .repo = build_options.update_repo,
    .public_key = if (built)
        update.decodeKey(build_options.update_pubkey) catch @compileError("-Dupdate-pubkey is not a base64 Ed25519 public key")
    else
        @splat(0),
    .lang = build_options.lang,
    .version = build_options.version,
};

/// The updater refuses a downloaded executable without the expected stamp,
/// so an old signed release cannot be passed off as a new one.
const version_stamp = update.stamp(build_options.version);

const update_first_check_s = 15;
/// One small request to GitHub: an hour keeps a fix from waiting half a day
/// for a window that is never closed.
const update_interval_s = 60 * 60;
/// A check that got no answer (the tunnel still coming up, GitHub refusing)
/// is tried again soon, sooner first: 30 s, 1 min, 2 min, then every 5 min
/// until GitHub answers.
const update_retry_first_s = 30;
const update_retry_max_s = 5 * 60;
/// How long a freshly installed version runs before its old copy is removed.
const update_confirm_ns = 3 * std.time.ns_per_s;

var update_install: ?update.Install = null;
/// mirror of settings.auto_update for the updater thread
var update_enabled: std.atomic.Value(bool) = .init(false);
/// verified and unpacked, waiting for a moment without open dialogs
pub var staged: ?std.SemanticVersion = null;
pub var verifying = false;
var update_confirm_at_ns: i128 = 0;
var update_failed_shown = false;

/// rolled-back version from `resume`, never offered again
var update_skip: ?std.SemanticVersion = null;

/// Finishes or undoes an install from the previous run. Silent for builds
/// not installed from a release.
pub fn resumeInstall() void {
    if (!built) return;
    // release builds drop unreferenced data; the stamp must survive
    std.mem.doNotOptimizeAway(&version_stamp);
    // kept for the whole run: the install location points into it
    const exe = std.process.executablePathAlloc(app.io, app.gpa) catch |err| return std.log.warn("update: off, no executable path: {t}", .{err});
    const inst = update.Install.locate(exe, builtin.os.tag) catch |err| {
        app.gpa.free(exe);
        return std.log.info("update: off, not installed from a release ({t})", .{err});
    };
    const startup = inst.startup(app.io) catch |err| return std.log.err("update: off, install state unreadable: {t}", .{err});
    switch (startup) {
        .normal => |rejected| update_skip = rejected,
        .verifying => verifying = true,
        .rolled_back => {
            std.log.warn("update: the new version never started; the previous one is back", .{});
            inst.relaunch(app.gpa, app.io) catch |err| return std.log.err("update: relaunch failed: {t}", .{err});
            std.process.exit(0);
        },
    }
    update_install = inst;
}

/// For the report: whether this copy updates itself, and if not, why.
pub fn stateText() []const u8 {
    if (!built) return "not in this build";
    if (update_install == null) return "off: this copy was not installed as a release lays it out";
    if (!app.state.settings.auto_update) return "off in the settings";
    return "on";
}

/// Background checks, once the settings are loaded.
pub fn start() void {
    const inst = update_install orelse return;
    update_enabled.store(app.state.settings.auto_update, .monotonic);
    const t = std.Thread.spawn(.{}, updateThread, .{ inst, update_skip }) catch return;
    t.detach();
}

pub fn frame(now: i128) void {
    if (!built) return;
    update_enabled.store(app.state.settings.auto_update, .monotonic);
    if (verifying) {
        if (update_confirm_at_ns == 0) update_confirm_at_ns = now + update_confirm_ns;
        // a release is good once its own service carries the traffic too
        if (now >= update_confirm_at_ns and !app.stale_restart) confirm();
    }
    // every floating window (dialog, menu) is a subwindow above the main one
    const calm = app.win.subwindows.stack.items.len <= 1;
    // screenshot mode (`persist` off) never replaces the app
    if (staged) |v| if (app.state.settings.auto_update and app.persist and calm) installStaged(v);
}

pub fn confirm() void {
    verifying = false;
    if (update_install) |inst| inst.confirm(app.io);
}

/// The new release's service did not come up: start again, unconfirmed, so
/// the start-up check puts the previous release back.
pub fn rollBack() void {
    const inst = update_install orelse return;
    std.log.err("update: the new release's service failed; rolling back", .{});
    app.save();
    inst.relaunch(app.gpa, app.io) catch |err| return std.log.err("update: relaunch failed: {t}", .{err});
    std.process.exit(0);
}

/// Swaps the staged release in and hands over to it.
fn installStaged(v: std.SemanticVersion) void {
    staged = null;
    const inst = update_install orelse return;
    var buf: [32]u8 = undefined;
    const version = std.fmt.bufPrint(&buf, "{f}", .{v}) catch return;
    app.save();
    inst.swap(app.io, update.native.package, version) catch |err| {
        std.log.err("update: {s} not installed: {t}", .{ version, err });
        return failed(v);
    };
    // The background service keeps carrying traffic: the new window adopts
    // it and restarts it from the new binary. Only the in-window proxy
    // stops here, to free its port, and comes back in the new window.
    const was_on = app.proxy.running.load(.acquire);
    if (was_on) {
        app.proxy.stop();
        app.setReconnectMark();
    }
    inst.relaunch(app.gpa, app.io) catch |err| {
        // a copy that does not start now would not start at the next login
        // either, and could not roll itself back: put this one back
        std.log.err("update: {s} does not start ({t}); keeping this version", .{ version, err });
        inst.undo(app.io, version) catch |e| std.log.err("update: previous version not put back: {t}", .{e});
        failed(v);
        if (was_on) {
            _ = app.takeReconnectMark();
            app.engine.disconnect();
            app.connect();
        }
        return;
    };
    std.process.exit(0);
}

pub fn failed(v: std.SemanticVersion) void {
    if (update_failed_shown) return;
    update_failed_shown = true;
    var buf: [32]u8 = undefined;
    app.notify(true, tr.update_failed, .{std.fmt.bufPrint(&buf, "{f}", .{v}) catch ""});
}

fn updateThread(inst: update.Install, skip: ?std.SemanticVersion) void {
    app.io.sleep(.fromSeconds(update_first_check_s), .awake) catch return;
    // boot time: wall-clock jumps must not stall or rush the checks
    var next_check: i64 = 0;
    var retry_s: i64 = update_retry_first_s;
    while (true) : (app.io.sleep(.fromSeconds(15), .awake) catch return) {
        if (!update_enabled.load(.monotonic)) continue;
        const now = Io.Clock.boot.now(app.io).toSeconds();
        if (now < next_check) continue;
        switch (stageUpdate(inst, skip)) {
            .staged => return,
            .answered => {
                next_check = now + update_interval_s;
                retry_s = update_retry_first_s;
            },
            .no_answer => {
                next_check = now + retry_s;
                retry_s = @min(retry_s * 2, update_retry_max_s);
            },
        }
    }
}

const Outcome = enum { staged, answered, no_answer };

/// Check, download, verify, unpack. Network trouble is only logged and
/// reported as `no_answer`, so the thread asks again soon.
fn stageUpdate(inst: update.Install, skip: ?std.SemanticVersion) Outcome {
    var arena: std.heap.ArenaAllocator = .init(app.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var client: std.http.Client = .{ .allocator = a, .io = app.io };
    defer client.deinit();
    const found = (update.check(a, &client, update_cfg, skip) catch |err| {
        std.log.info("update: check failed: {t}", .{err});
        return .no_answer;
    }) orelse return .answered;
    const asset = update.download(a, &client, update_cfg, found) catch |err| {
        std.log.warn("update: {s} not downloaded: {t}", .{ found.asset, err });
        return .no_answer;
    };
    inst.stage(a, app.io, update.native.package, asset, found.version_text) catch |err| {
        std.log.err("update: {s} not unpacked: {t}", .{ found.asset, err });
        app.pushResult(.{ .update_failed = found.version });
        // a broken release is not fetched again every few minutes
        return .answered;
    };
    app.pushResult(.{ .update_staged = found.version });
    return .staged;
}
