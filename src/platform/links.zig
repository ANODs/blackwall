//! How a `blackwall://` link (core/applink.zig) reaches the window.
//!
//!   Windows, Linux   the system starts the app with the link as its
//!                    argument. That start is the window (`at_start`), or
//!                    it finds one running and leaves the link for it
//!                    (app/instance.zig).
//!   macOS            the system starts the app if it must and hands the
//!                    link to the one that runs, as an event; SDL passes
//!                    it on as a "dropped file" whose name is the link.
//!
//! Either way the link ends in `app.queueLink` and is opened on the UI
//! thread. Telling the system that the links are ours is scheme.zig.

const std = @import("std");
const builtin = @import("builtin");
const dvui = @import("dvui");
const core = @import("core");
const app = @import("../app.zig");
const scheme = @import("scheme.zig");

const c = dvui.backend.c;

/// The link this start was given, when this start became the window.
pub var at_start: ?[]const u8 = null;

/// The link among the command line's arguments, if the system put one there.
pub fn fromArgs(args: []const [:0]const u8) ?[]const u8 {
    if (args.len < 2) return null;
    for (args[1..]) |arg| if (core.applink.isAppLink(arg)) return arg;
    return null;
}

/// Call once the window exists.
pub fn init() void {
    if (!app.persist) return;
    if (at_start) |link| app.queueLink(link);
    at_start = null;
    if (builtin.os.tag == .macos) {
        _ = c.SDL_AddEventWatch(onEvent, null);
        // the link that started the app may have come before this line
        var waiting: [8]c.SDL_Event = undefined;
        const n = c.SDL_PeepEvents(&waiting, waiting.len, c.SDL_PEEKEVENT, c.SDL_EVENT_DROP_FILE, c.SDL_EVENT_DROP_FILE);
        if (n > 0) for (waiting[0..@intCast(n)]) |*ev| take(ev);
    }
    // registry and files: not worth a moment of the first frame
    const t = std.Thread.spawn(.{ .stack_size = core.sys.stackSize(256 * 1024) }, register, .{}) catch return;
    t.detach();
}

fn register() void {
    const env: scheme.Env = if (dvui.App.main_init) |mi|
        .{ .home = mi.environ_map.get("HOME"), .xdg_data = mi.environ_map.get("XDG_DATA_HOME") }
    else
        .{};
    scheme.register(app.gpa, app.io, env);
}

/// Every event passes; a link among them is taken on the way.
fn onEvent(_: ?*anyopaque, ev: [*c]c.SDL_Event) callconv(.c) bool {
    if (ev.*.type == c.SDL_EVENT_DROP_FILE) take(ev);
    return true;
}

fn take(ev: [*c]c.SDL_Event) void {
    const data = ev.*.drop.data orelse return;
    const text = std.mem.span(data);
    // a real file dropped on the window is not ours
    if (core.applink.isAppLink(text)) app.queueLink(text);
}
