//! The system learns that `blackwall://` links (core/applink.zig) are this
//! app's to open.
//!
//!   macOS    the bundle says so itself (CFBundleURLTypes in its
//!            Info.plist, build.zig); nothing to do here
//!   Windows  the per-user protocol key of the registry, pointing at the
//!            executable where it is now
//!   Linux    `x-scheme-handler/blackwall` in the menu entry install.sh
//!            put in place; an entry from a release that did not know
//!            links is brought up to date
//!   Android  an intent filter in the manifest
//!
//! Applied at every start, like the login item (autostart.zig): on Windows
//! the app is one file that the user may move, and a release that updated
//! itself is started by nothing that would register it.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

const mime = "x-scheme-handler/blackwall";
const entry_name = "blackwall.desktop";

pub const Env = struct {
    home: ?[]const u8 = null,
    xdg_data: ?[]const u8 = null,
};

/// Failures are only logged: links are a convenience, the app works without.
pub fn register(gpa: std.mem.Allocator, io: Io, env: Env) void {
    registerOrFail(gpa, io, env) catch |err| std.log.warn("links not registered: {t}", .{err});
}

fn registerOrFail(gpa: std.mem.Allocator, io: Io, env: Env) !void {
    switch (builtin.os.tag) {
        .windows => {
            const exe = try std.process.executablePathAlloc(io, gpa);
            defer gpa.free(exe);
            const command = try std.fmt.allocPrint(gpa, "\"{s}\" \"%1\"", .{exe});
            defer gpa.free(command);
            const L = std.unicode.utf8ToUtf16LeStringLiteral;
            try setValue(gpa, L("Software\\Classes\\blackwall"), L(""), "URL:BLACKWALL");
            try setValue(gpa, L("Software\\Classes\\blackwall"), L("URL Protocol"), "");
            try setValue(gpa, L("Software\\Classes\\blackwall\\shell\\open\\command"), L(""), command);
        },
        .linux => {
            if (builtin.abi.isAndroid()) return;
            const apps = if (env.xdg_data) |x|
                try std.fmt.allocPrint(gpa, "{s}/applications", .{x})
            else
                try std.fmt.allocPrint(gpa, "{s}/.local/share/applications", .{env.home orelse return});
            defer gpa.free(apps);
            if (!try refreshEntry(gpa, io, apps)) return;
            std.log.info("the menu entry now opens blackwall:// links", .{});
            // the desktop's index of who opens what; either tool may be missing
            tool(gpa, io, &.{ "update-desktop-database", apps });
            tool(gpa, io, &.{ "xdg-mime", "default", entry_name, mime });
        },
        else => {},
    }
}

/// Bring the menu entry in folder `apps` up to date; false when there is
/// none (the app was not installed, only run) or it needs nothing.
fn refreshEntry(gpa: std.mem.Allocator, io: Io, apps: []const u8) !bool {
    const path = try std.fs.path.join(gpa, &.{ apps, entry_name });
    defer gpa.free(path);
    const dir = Io.Dir.cwd();
    const old = dir.readFileAlloc(io, path, gpa, .limited(64 * 1024)) catch return false;
    defer gpa.free(old);
    const new = try withLinks(gpa, old) orelse return false;
    defer gpa.free(new);
    try dir.writeFile(io, .{ .sub_path = path, .data = new, .flags = .{ .permissions = .fromMode(0o644) } });
    return true;
}

fn tool(gpa: std.mem.Allocator, io: Io, argv: []const []const u8) void {
    const res = std.process.run(gpa, io, .{ .argv = argv, .stdout_limit = .limited(16 << 10), .stderr_limit = .limited(16 << 10) }) catch return;
    gpa.free(res.stdout);
    gpa.free(res.stderr);
}

/// A menu entry that opens links: `%u` on its command and the scheme among
/// its types. Null when it already does.
fn withLinks(gpa: std.mem.Allocator, entry: []const u8) !?[]u8 {
    if (std.mem.indexOf(u8, entry, mime) != null) return null;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var has_type = false;
    var it = std.mem.splitScalar(u8, entry, '\n');
    while (it.next()) |raw| if (std.mem.startsWith(u8, raw, "MimeType=")) {
        has_type = true;
    };
    var done_exec = false;
    it.reset();
    while (it.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        // the last piece after the final line end
        if (it.peek() == null and line.len == 0) break;
        try out.appendSlice(gpa, line);
        if (!done_exec and std.mem.startsWith(u8, line, "Exec=")) {
            done_exec = true;
            if (std.mem.indexOf(u8, line, "%u") == null and std.mem.indexOf(u8, line, "%U") == null) try out.appendSlice(gpa, " %u");
            // right after the command: inside the entry's own group
            if (!has_type) try out.appendSlice(gpa, "\nMimeType=" ++ mime ++ ";");
        } else if (std.mem.startsWith(u8, line, "MimeType=")) {
            if (!std.mem.endsWith(u8, line, ";") and line.len > "MimeType=".len) try out.append(gpa, ';');
            try out.appendSlice(gpa, mime ++ ";");
        }
        try out.append(gpa, '\n');
    }
    // not an entry that starts anything
    if (!done_exec) {
        out.deinit(gpa);
        return null;
    }
    return try out.toOwnedSlice(gpa);
}

const win = if (builtin.os.tag == .windows) std.os.windows else struct {
    const HKEY = *opaque {};
    const DWORD = u32;
    const LSTATUS = i32;
};
extern "advapi32" fn RegSetKeyValueW(key: win.HKEY, sub_key: [*:0]const u16, value_name: [*:0]const u16, kind: win.DWORD, data: ?*const anyopaque, size: win.DWORD) callconv(.winapi) win.LSTATUS;

/// A text value under the user's own registry key; the key is made when it
/// is not there. An empty name is the key's default value.
fn setValue(gpa: std.mem.Allocator, key: [*:0]const u16, name: [*:0]const u16, text: []const u8) !void {
    if (comptime builtin.os.tag != .windows) return;
    const value = try std.unicode.utf8ToUtf16LeAllocZ(gpa, text);
    defer gpa.free(value);
    const bytes: win.DWORD = @intCast((value.len + 1) * 2);
    if (RegSetKeyValueW(win.HKEY_CURRENT_USER, key, name, @backingInt(win.REG.ValueType.SZ), value.ptr, bytes) != 0)
        return error.RegistryFailed;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "the shipped menu entry opens links" {
    const shipped = @embedFile("blackwall_desktop");
    try testing.expect(std.mem.indexOf(u8, shipped, "MimeType=" ++ mime ++ ";\n") != null);
    try testing.expect(std.mem.indexOf(u8, shipped, "Exec=@BIN@/blackwall %u\n") != null);
    // so there is nothing to bring up to date
    try testing.expect(try withLinks(testing.allocator, shipped) == null);
}

test "a menu entry from a release without links is brought up to date, once" {
    const old =
        \\[Desktop Entry]
        \\Type=Application
        \\Name=BLACKWALL
        \\Comment=VPN client with a route for every app
        \\Exec=/home/u/.local/opt/blackwall/blackwall
        \\Icon=/home/u/.local/opt/blackwall/blackwall.png
        \\Categories=Network;Security;
        \\StartupWMClass=blackwall
        \\Terminal=false
        \\
    ;
    const new = (try withLinks(testing.allocator, old)).?;
    defer testing.allocator.free(new);
    try testing.expectEqualStrings(
        \\[Desktop Entry]
        \\Type=Application
        \\Name=BLACKWALL
        \\Comment=VPN client with a route for every app
        \\Exec=/home/u/.local/opt/blackwall/blackwall %u
        \\MimeType=x-scheme-handler/blackwall;
        \\Icon=/home/u/.local/opt/blackwall/blackwall.png
        \\Categories=Network;Security;
        \\StartupWMClass=blackwall
        \\Terminal=false
        \\
    , new);
    try testing.expect(try withLinks(testing.allocator, new) == null);
}

test "an entry with types of its own keeps them" {
    const old = "[Desktop Entry]\r\nExec=/opt/b/blackwall %U\r\nMimeType=x-scheme-handler/other\r\n\r\n[Desktop Action x]\nExec=/opt/b/blackwall --x\n";
    const new = (try withLinks(testing.allocator, old)).?;
    defer testing.allocator.free(new);
    try testing.expectEqualStrings("[Desktop Entry]\nExec=/opt/b/blackwall %U\nMimeType=x-scheme-handler/other;x-scheme-handler/blackwall;\n\n[Desktop Action x]\nExec=/opt/b/blackwall --x\n", new);
}

test "a file that starts nothing is left alone" {
    try testing.expect(try withLinks(testing.allocator, "") == null);
    try testing.expect(try withLinks(testing.allocator, "[Desktop Entry]\nName=BLACKWALL\n") == null);
}

test "the menu entry on disk is rewritten once, and a missing one stays missing" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [128]u8 = undefined;
    const apps = try std.fmt.bufPrint(&buf, ".zig-cache/tmp/{s}", .{&tmp.sub_path});
    try testing.expect(!try refreshEntry(testing.allocator, testing.io, apps));
    try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, entry_name, .{}));

    try tmp.dir.writeFile(testing.io, .{ .sub_path = entry_name, .data = "[Desktop Entry]\nName=BLACKWALL\nExec=/opt/b/blackwall\nTerminal=false\n" });
    try testing.expect(try refreshEntry(testing.allocator, testing.io, apps));
    var text: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "[Desktop Entry]\nName=BLACKWALL\nExec=/opt/b/blackwall %u\nMimeType=x-scheme-handler/blackwall;\nTerminal=false\n",
        try tmp.dir.readFile(testing.io, entry_name, &text),
    );
    try testing.expect(!try refreshEntry(testing.allocator, testing.io, apps));
}
