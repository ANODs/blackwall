//! Discovery of installed applications, for the list a route is set on.
//!
//! macOS: application bundles in the standard locations.
//! Linux: the desktop entries (.desktop files) of the applications menu.
//! The identity is the program's real path, which is what the service
//! reports for a connection (src/service/linux_proc.zig). Programs started
//! through a wrapper script, Flatpak or Snap run another executable; they
//! join the list under that one as soon as the service sees their traffic
//! (app.zig, `seenApp`).

const std = @import("std");
const builtin = @import("builtin");
const core = @import("core");

pub fn discover(io: std.Io, state: *core.model.State, home: ?[]const u8) void {
    switch (builtin.os.tag) {
        .macos => {
            scan(io, state, "/Applications");
            scan(io, state, "/System/Applications");
            scan(io, state, "/Applications/Utilities");
            if (home) |h| {
                var buf: [std.fs.max_path_bytes]u8 = undefined;
                const p = std.fmt.bufPrint(&buf, "{s}/Applications", .{h}) catch return;
                scan(io, state, p);
            }
        },
        .linux => {
            if (builtin.abi.isAndroid()) return;
            if (home) |h| {
                var buf: [std.fs.max_path_bytes]u8 = undefined;
                const p = std.fmt.bufPrint(&buf, "{s}/.local/share/applications", .{h}) catch return;
                scanDesktop(io, state, p);
            }
            scanDesktop(io, state, "/usr/local/share/applications");
            scanDesktop(io, state, "/usr/share/applications");
        },
        else => return,
    }
    std.mem.sort(core.model.App, state.apps.items, {}, struct {
        fn less(_: void, a: core.model.App, b: core.model.App) bool {
            return std.ascii.lessThanIgnoreCase(a.name, b.name);
        }
    }.less);
}

fn scan(io: std.Io, state: *core.model.State, path: []const u8) void {
    var dir = std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch return;
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (!std.mem.endsWith(u8, entry.name, ".app")) continue;
        if (entry.name[0] == '.') continue;
        const name = entry.name[0 .. entry.name.len - 4];
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const full = std.fmt.bufPrint(&buf, "{s}/{s}", .{ path, entry.name }) catch continue;
        // The bundle path is the identity until Info.plist parsing lands.
        _ = state.addApp(full, name, full) catch return;
    }
}

fn scanDesktop(io: std.Io, state: *core.model.State, path: []const u8) void {
    var dir = std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch return;
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (!std.mem.endsWith(u8, entry.name, ".desktop")) continue;
        var buf: [16 * 1024]u8 = undefined;
        const text = dir.readFile(io, entry.name, &buf) catch continue;
        const e = parseDesktop(text) orelse continue;
        var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
        const exe = resolve(io, e.program, &exe_buf) orelse continue;
        // our own entry, and the launchers that run something else
        if (isLauncher(exe)) continue;
        // an entry of a user overrides the system's (scanned first)
        if (state.appById(exe) != null) continue;
        _ = state.addApp(exe, e.name, exe) catch return;
    }
}

pub const Entry = struct { name: []const u8, program: []const u8 };

/// The [Desktop Entry] group of a .desktop file: its name and the program
/// its Exec line starts. Hidden entries and those that are not
/// applications are skipped.
pub fn parseDesktop(text: []const u8) ?Entry {
    var in_entry = false;
    var name: ?[]const u8 = null;
    var exec: ?[]const u8 = null;
    var lines = std.mem.tokenizeAny(u8, text, "\r\n");
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0 or line[0] == '#') continue;
        if (line[0] == '[') {
            if (in_entry) break;
            in_entry = std.mem.eql(u8, line, "[Desktop Entry]");
            continue;
        }
        if (!in_entry) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const val = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (std.mem.eql(u8, key, "Type") and !std.mem.eql(u8, val, "Application")) return null;
        if ((std.mem.eql(u8, key, "NoDisplay") or std.mem.eql(u8, key, "Hidden")) and std.mem.eql(u8, val, "true")) return null;
        if (std.mem.eql(u8, key, "Name")) name = val;
        if (std.mem.eql(u8, key, "Exec")) exec = val;
    }
    const e = exec orelse return null;
    const program = firstProgram(e) orelse return null;
    return .{ .name = name orelse std.fs.path.basename(program), .program = program };
}

/// The program an Exec line runs: its first word, past `env VAR=value`.
fn firstProgram(exec: []const u8) ?[]const u8 {
    var rest = exec;
    var first = true;
    while (true) {
        rest = std.mem.trimStart(u8, rest, " \t");
        if (rest.len == 0) return null;
        var word: []const u8 = undefined;
        if (rest[0] == '"') {
            const end = std.mem.indexOfScalarPos(u8, rest, 1, '"') orelse return null;
            word = rest[1..end];
            rest = rest[end + 1 ..];
        } else {
            const end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
            word = rest[0..end];
            rest = rest[end..];
        }
        if (first and std.mem.eql(u8, std.fs.path.basename(word), "env")) {
            first = false;
            continue;
        }
        first = false;
        // VAR=value before the program
        if (std.mem.indexOfScalar(u8, word, '=') != null and word[0] != '/') continue;
        return word;
    }
}

/// The program's real path: looked up in PATH when bare, links followed.
fn resolve(io: std.Io, program: []const u8, out: *[std.fs.max_path_bytes]u8) ?[]const u8 {
    var cand_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (std.mem.indexOfScalar(u8, program, '/') != null) return real(io, program, out);
    const path = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/snap/bin:/usr/games";
    var dirs = std.mem.tokenizeScalar(u8, path, ':');
    while (dirs.next()) |d| {
        const cand = std.fmt.bufPrint(&cand_buf, "{s}/{s}", .{ d, program }) catch continue;
        if (real(io, cand, out)) |r| return r;
    }
    return null;
}

fn real(io: std.Io, path: []const u8, out: *[std.fs.max_path_bytes]u8) ?[]const u8 {
    const n = std.Io.Dir.cwd().realPathFile(io, path, out) catch return null;
    return out[0..n];
}

fn isLauncher(exe: []const u8) bool {
    const name = std.fs.path.basename(exe);
    for ([_][]const u8{ "flatpak", "snap", "blackwall", "xdg-open", "sh", "bash", "env" }) |l| {
        if (std.mem.eql(u8, name, l)) return true;
    }
    return false;
}

test "a desktop entry: name and program" {
    const e = parseDesktop(
        \\[Desktop Entry]
        \\Version=1.0
        \\Name=Firefox Web Browser
        \\Name[ru]=Веб-браузер Firefox
        \\Exec=env MOZ_ENABLE_WAYLAND=1 firefox %u
        \\Type=Application
        \\
        \\[Desktop Action new-window]
        \\Exec=firefox --new-window %u
    ).?;
    try std.testing.expectEqualStrings("Firefox Web Browser", e.name);
    try std.testing.expectEqualStrings("firefox", e.program);

    const q = parseDesktop("[Desktop Entry]\nName=X\nExec=\"/opt/My App/app\" --flag\nType=Application\n").?;
    try std.testing.expectEqualStrings("/opt/My App/app", q.program);

    try std.testing.expect(parseDesktop("[Desktop Entry]\nName=X\nExec=x\nNoDisplay=true\n") == null);
    try std.testing.expect(parseDesktop("[Desktop Entry]\nName=X\nExec=x\nType=Link\n") == null);
}
