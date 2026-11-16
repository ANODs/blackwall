//! Discovery of installed applications, for the list a route is set on.
//!
//! macOS: application bundles in the standard locations.
//! Linux: the desktop entries (.desktop files) of the applications menu.
//! Windows: the shortcuts (.lnk files) of the Start menu, by the program
//! they start; the identity is its path in lower case, as the service
//! reports it (src/service/win_owner.zig).
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
        .windows => {
            if (home) |h| {
                var buf: [std.fs.max_path_bytes]u8 = undefined;
                const p = std.fmt.bufPrint(&buf, "{s}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs", .{h}) catch return;
                scanShortcuts(io, state, p, 0);
            }
            scanShortcuts(io, state, "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs", 0);
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

fn scanShortcuts(io: std.Io, state: *core.model.State, path: []const u8, depth: u8) void {
    if (depth > 4) return;
    var dir = std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch return;
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        var sub_buf: [std.fs.max_path_bytes]u8 = undefined;
        if (entry.kind == .directory) {
            const sub = std.fmt.bufPrint(&sub_buf, "{s}\\{s}", .{ path, entry.name }) catch continue;
            scanShortcuts(io, state, sub, depth + 1);
            continue;
        }
        if (!std.ascii.endsWithIgnoreCase(entry.name, ".lnk")) continue;
        var buf: [64 * 1024]u8 = undefined;
        const data = dir.readFile(io, entry.name, &buf) catch continue;
        var target_buf: [1024]u8 = undefined;
        const target = shortcutTarget(data, &target_buf) orelse continue;
        if (!std.ascii.endsWithIgnoreCase(target, ".exe")) continue;
        const name = entry.name[0 .. entry.name.len - 4];
        // uninstallers and help have shortcuts too
        if (std.ascii.findIgnoreCase(name, "uninstall") != null) continue;
        for (target) |*ch| ch.* = std.ascii.toLower(ch.*);
        if (std.mem.endsWith(u8, target, "\\blackwall.exe")) continue;
        if (state.appById(target) != null) continue;
        _ = state.addApp(target, name, target) catch return;
    }
}

/// The local path a shell link (.lnk) points to: its LinkInfo's base path
/// and suffix ([MS-SHLLINK] 2.3). Links without one (installer-advertised
/// shortcuts) give null.
pub fn shortcutTarget(data: []const u8, out: []u8) ?[]u8 {
    if (data.len < 76 or std.mem.readInt(u32, data[0..4], .little) != 0x4c) return null;
    const flags = std.mem.readInt(u32, data[20..24], .little);
    var off: usize = 76;
    if (flags & 0x1 != 0) {
        // the item ID list, skipped
        if (off + 2 > data.len) return null;
        off += 2 + std.mem.readInt(u16, data[off..][0..2], .little);
    }
    if (flags & 0x2 == 0) return null;
    if (off + 28 > data.len) return null;
    const info = data[off..];
    const size = std.mem.readInt(u32, info[0..4], .little);
    if (size < 28 or size > info.len) return null;
    const li = info[0..size];
    const header = std.mem.readInt(u32, li[4..8], .little);
    if (std.mem.readInt(u32, li[8..12], .little) & 0x1 == 0) return null; // no local path
    var n: usize = 0;
    if (header >= 0x24 and size >= 36) {
        // Unicode base path and suffix
        const base = std.mem.readInt(u32, li[28..32], .little);
        const suffix = std.mem.readInt(u32, li[32..36], .little);
        n = appendWide(li, base, out, 0) orelse return null;
        n = appendWide(li, suffix, out, n) orelse return null;
    } else {
        const base = std.mem.readInt(u32, li[16..20], .little);
        const suffix = std.mem.readInt(u32, li[24..28], .little);
        n = appendAnsi(li, base, out, 0) orelse return null;
        n = appendAnsi(li, suffix, out, n) orelse return null;
    }
    if (n == 0) return null;
    return out[0..n];
}

fn appendAnsi(li: []const u8, at: u32, out: []u8, n: usize) ?usize {
    if (at == 0 or at >= li.len) return n;
    const s = std.mem.sliceTo(li[at..], 0);
    // ASCII only: a path in another code page is not read right here
    for (s) |ch| if (ch >= 0x80) return null;
    if (n + s.len > out.len) return null;
    @memcpy(out[n..][0..s.len], s);
    return n + s.len;
}

fn appendWide(li: []const u8, at: u32, out: []u8, n: usize) ?usize {
    if (at == 0 or at + 2 > li.len) return n;
    var units: [512]u16 = undefined;
    var k: usize = 0;
    var i: usize = at;
    while (i + 2 <= li.len and k < units.len) : (i += 2) {
        const u = std.mem.readInt(u16, li[i..][0..2], .little);
        if (u == 0) break;
        units[k] = u;
        k += 1;
    }
    if (n + k * 3 > out.len) return null;
    return n + std.unicode.wtf16LeToWtf8(out[n..], units[0..k]);
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

test "the program a shortcut starts" {
    // a header, no item ID list, and a LinkInfo with an ANSI base path
    var lnk: [76 + 28 + 32]u8 = @splat(0);
    std.mem.writeInt(u32, lnk[0..4], 0x4c, .little);
    std.mem.writeInt(u32, lnk[20..24], 0x2, .little);
    const li = lnk[76..];
    std.mem.writeInt(u32, li[0..4], 60, .little);
    std.mem.writeInt(u32, li[4..8], 0x1c, .little);
    std.mem.writeInt(u32, li[8..12], 0x1, .little);
    std.mem.writeInt(u32, li[16..20], 28, .little);
    std.mem.writeInt(u32, li[24..28], 59, .little);
    @memcpy(li[28..][0..17], "C:\\App\\TOOL.exe\x00"[0..17]);
    var out: [64]u8 = undefined;
    try std.testing.expectEqualStrings("C:\\App\\TOOL.exe", shortcutTarget(&lnk, &out).?);
    // not a shortcut
    try std.testing.expect(shortcutTarget("hello", &out) == null);
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
