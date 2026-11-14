//! Discovery of installed applications. macOS for now: application bundles
//! in the standard locations. Other systems return an empty list until
//! their adapters exist (start-menu entries, .desktop files, packages).

const std = @import("std");
const builtin = @import("builtin");
const core = @import("core");

pub fn discover(io: std.Io, state: *core.model.State, home: ?[]const u8) void {
    if (builtin.os.tag != .macos) return;
    scan(io, state, "/Applications");
    scan(io, state, "/System/Applications");
    scan(io, state, "/Applications/Utilities");
    if (home) |h| {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const p = std.fmt.bufPrint(&buf, "{s}/Applications", .{h}) catch return;
        scan(io, state, p);
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
