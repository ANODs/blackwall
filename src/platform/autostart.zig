//! "Launch at login" (Settings): the window starts when the user logs in.
//!
//!   macOS    a LaunchAgent in ~/Library/LaunchAgents that runs the app's own
//!            executable, so Login Items show it under the app's name
//!   Linux    an XDG autostart entry in ~/.config/autostart
//!   Windows  the per-user Run key of the registry
//!
//! Applied again at every start while the setting is on, so an app that was
//! moved (or updated in place) keeps starting from where it is now.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

const label = "dev.blackwall.app";

pub const Env = struct {
    home: ?[]const u8 = null,
    xdg_config: ?[]const u8 = null,
};

/// Turn starting at login on or off; failures are only logged.
pub fn apply(gpa: std.mem.Allocator, io: Io, env: Env, on: bool) void {
    applyOrFail(gpa, io, env, on) catch |err|
        std.log.warn("launch at login not {s}: {t}", .{ if (on) "set" else "cleared", err });
}

fn applyOrFail(gpa: std.mem.Allocator, io: Io, env: Env, on: bool) !void {
    switch (builtin.os.tag) {
        .macos => {
            const home = env.home orelse return error.NoHome;
            const path = try std.fmt.allocPrint(gpa, "{s}/Library/LaunchAgents/" ++ label ++ ".plist", .{home});
            defer gpa.free(path);
            if (!on) return remove(io, path);
            const exe = try std.process.executablePathAlloc(io, gpa);
            defer gpa.free(exe);
            // a copy macOS runs from a random read-only location (an app
            // opened straight from Downloads) is gone after a restart
            if (std.mem.indexOf(u8, exe, "/AppTranslocation/") != null) return error.Translocated;
            const text = try plist(gpa, exe);
            defer gpa.free(text);
            try writeIfChanged(gpa, io, path, text);
        },
        .linux => {
            const base = if (env.xdg_config) |x|
                try gpa.dupe(u8, x)
            else
                try std.fmt.allocPrint(gpa, "{s}/.config", .{env.home orelse return error.NoHome});
            defer gpa.free(base);
            const path = try std.fmt.allocPrint(gpa, "{s}/autostart/blackwall.desktop", .{base});
            defer gpa.free(path);
            if (!on) return remove(io, path);
            const exe = try std.process.executablePathAlloc(io, gpa);
            defer gpa.free(exe);
            const text = try desktopEntry(gpa, exe);
            defer gpa.free(text);
            try writeIfChanged(gpa, io, path, text);
        },
        .windows => {
            const w = std.os.windows;
            const run_key = std.unicode.utf8ToUtf16LeStringLiteral("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            const name = std.unicode.utf8ToUtf16LeStringLiteral("BLACKWALL");
            if (!on) {
                const rc = RegDeleteKeyValueW(w.HKEY_CURRENT_USER, run_key, name);
                // ERROR_FILE_NOT_FOUND: nothing to remove
                if (rc != 0 and rc != 2) return error.RegistryFailed;
                return;
            }
            const exe = try std.process.executablePathAlloc(io, gpa);
            defer gpa.free(exe);
            const quoted = try std.fmt.allocPrint(gpa, "\"{s}\"", .{exe});
            defer gpa.free(quoted);
            const value = try std.unicode.utf8ToUtf16LeAllocZ(gpa, quoted);
            defer gpa.free(value);
            const bytes: w.DWORD = @intCast((value.len + 1) * 2);
            if (RegSetKeyValueW(w.HKEY_CURRENT_USER, run_key, name, @backingInt(w.REG.ValueType.SZ), value.ptr, bytes) != 0)
                return error.RegistryFailed;
        },
        else => {},
    }
}

const win = if (builtin.os.tag == .windows) std.os.windows else struct {
    const HKEY = *opaque {};
    const DWORD = u32;
    const LSTATUS = i32;
};
extern "advapi32" fn RegSetKeyValueW(key: win.HKEY, sub_key: [*:0]const u16, value_name: [*:0]const u16, kind: win.DWORD, data: ?*const anyopaque, size: win.DWORD) callconv(.winapi) win.LSTATUS;
extern "advapi32" fn RegDeleteKeyValueW(key: win.HKEY, sub_key: [*:0]const u16, value_name: [*:0]const u16) callconv(.winapi) win.LSTATUS;

fn remove(io: Io, path: []const u8) !void {
    std.Io.Dir.cwd().deleteFile(io, path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

/// Rewrites only on change: macOS announces every new login item.
fn writeIfChanged(gpa: std.mem.Allocator, io: Io, path: []const u8, text: []const u8) !void {
    const dir = std.Io.Dir.cwd();
    if (dir.readFileAlloc(io, path, gpa, .limited(64 * 1024))) |old| {
        defer gpa.free(old);
        if (std.mem.eql(u8, old, text)) return;
    } else |_| {}
    if (std.fs.path.dirname(path)) |parent| try dir.createDirPath(io, parent);
    try dir.writeFile(io, .{ .sub_path = path, .data = text, .flags = .{ .permissions = .fromMode(0o644) } });
}

fn plist(gpa: std.mem.Allocator, exe: []const u8) ![]u8 {
    var s: std.ArrayList(u8) = .empty;
    errdefer s.deinit(gpa);
    try s.appendSlice(gpa,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<plist version="1.0">
        \\<dict>
        \\  <key>Label</key><string>
    ++ label ++
        \\</string>
        \\  <key>ProgramArguments</key><array><string>
    );
    for (exe) |ch| switch (ch) {
        '&' => try s.appendSlice(gpa, "&amp;"),
        '<' => try s.appendSlice(gpa, "&lt;"),
        '>' => try s.appendSlice(gpa, "&gt;"),
        else => try s.append(gpa, ch),
    };
    try s.appendSlice(gpa,
        \\</string></array>
        \\  <key>RunAtLoad</key><true/>
        \\  <key>ProcessType</key><string>Interactive</string>
        \\</dict>
        \\</plist>
        \\
    );
    return s.toOwnedSlice(gpa);
}

/// Exec quoting of the Desktop Entry specification. The string escapes of
/// the file apply first, so a quoted `"` is written `\\"` and a literal
/// backslash takes four.
fn desktopEntry(gpa: std.mem.Allocator, exe: []const u8) ![]u8 {
    var s: std.ArrayList(u8) = .empty;
    errdefer s.deinit(gpa);
    try s.appendSlice(gpa, "[Desktop Entry]\nType=Application\nName=BLACKWALL\nExec=\"");
    for (exe) |ch| {
        switch (ch) {
            '"', '`', '$' => try s.appendSlice(gpa, "\\\\"),
            '\\' => try s.appendSlice(gpa, "\\\\\\"),
            '%' => try s.append(gpa, '%'),
            else => {},
        }
        try s.append(gpa, ch);
    }
    try s.appendSlice(gpa, "\"\nX-GNOME-Autostart-enabled=true\n");
    return s.toOwnedSlice(gpa);
}

test "launch agent plist escapes the path" {
    const text = try plist(std.testing.allocator, "/Apps/A&B <x>.app/Contents/MacOS/blackwall");
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "<string>/Apps/A&amp;B &lt;x&gt;.app/Contents/MacOS/blackwall</string>") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "<key>Label</key><string>dev.blackwall.app</string>") != null);
}

test "desktop entry quotes Exec" {
    const text = try desktopEntry(std.testing.allocator, "/opt/my \"vpn\"/100%/blackwall");
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "Exec=\"/opt/my \\\\\"vpn\\\\\"/100%%/blackwall\"\n") != null);
    const t2 = try desktopEntry(std.testing.allocator, "/a\\b");
    defer std.testing.allocator.free(t2);
    try std.testing.expect(std.mem.indexOf(u8, t2, "Exec=\"/a\\\\\\\\b\"\n") != null);
}
