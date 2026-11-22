const std = @import("std");
const builtin = @import("builtin");
const dvui = @import("dvui");
const build_options = @import("build_options");
const app = @import("app.zig");
const report = @import("report.zig");
const th = @import("ui/theme.zig");
const draw = @import("ui/draw.zig");
const w = @import("ui/widgets.zig");

const connect = @import("ui/screens/connect.zig");
const apps = @import("ui/screens/apps.zig");
const servers = @import("ui/screens/servers.zig");
const stats = @import("ui/screens/stats.zig");
const settings = @import("ui/screens/settings.zig");
const conflicts = @import("ui/conflicts.zig");
const shots = @import("shots.zig");
const tray = @import("platform/tray.zig");
const instance = @import("app/instance.zig");
const tr = @import("i18n.zig").t;

pub const dvui_app: dvui.App = .{
    .config = .{ .startFn = start },
    .initFn = init,
    .deinitFn = deinit,
    .frameFn = frame,
};

/// The window's log goes to a file before anything opens (report.zig).
pub fn main(main_init: std.process.Init) !u8 {
    report.start(main_init);
    // one window per user; screenshot mode touches nothing of the user's
    if (main_init.environ_map.get("BLACKWALL_SHOTS") == null) {
        var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
        if (app.settingsDir(&dir_buf, main_init.environ_map)) |dir|
            if (instance.claim(main_init.gpa, main_init.io, dir, build_options.version) == .second) return 0;
    }
    return dvui.App.main(main_init);
}
/// Written to the log and, on Windows, told to the user (report.zig).
pub const panic = std.debug.FullPanic(report.panicked);
pub const std_options: std.Options = .{
    .logFn = report.logFn,
    // Windows: the window's own handler catches crashes, logs them and says
    // where to report them (report.zig)
    .enable_segfault_handler = builtin.os.tag != .windows and std.debug.default_enable_segfault_handler,
};

fn start() dvui.App.StartOptions {
    // how the system names us (notifications, logs), set after dvui's own
    _ = dvui.backend.c.SDL_SetAppMetadata("BLACKWALL", std.fmt.comptimePrint("{s}", .{build_options.version}), "dev.blackwall");
    return .{
        .size = .{ .w = 940, .h = 620 },
        .min_size = .{ .w = 760, .h = 520 },
        .title = "BLACKWALL",
        // macOS takes the bundle icon; setting one at runtime would replace it in the Dock
        .icon = if (builtin.os.tag == .macos) null else @embedFile("icon_png"),
        .app = "blackwall",
        .org = "dev.blackwall",
        .window_init_options = .{ .keybinds_zoom = true, .theme = th.theme },
    };
}

fn init(win: *dvui.Window) !void {
    dvui.ScrollBarWidget.defaults.min_size_content = .{ .w = 6, .h = 6 };
    dvui.ScrollBarWidget.defaults.color_text = w.col(th.text3);
    try app.init(win);
    shots.init();
    tray.init();
}

fn deinit(_: *dvui.Window) void {
    tray.deinit();
    app.deinit();
}

fn frame() !dvui.App.Result {
    app.frame();
    if (shots.before()) return .close;
    defer shots.after();
    tray.frame();
    // hidden behind the menu bar item: the counters above keep running,
    // there is nothing to draw
    if (tray.hidden) return .ok;

    var root = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .both, .background = true, .color_fill = w.col(th.bg) });
    defer root.deinit();

    sidebar();

    var over = dvui.overlay(@src(), .{ .expand = .both });
    defer over.deinit();
    {
        var content = dvui.box(@src(), .{}, .{ .expand = .both, .padding = .{ .x = 32, .y = 26, .w = 28, .h = 24 } });
        defer content.deinit();
        switch (app.screen) {
            .connect => connect.show(),
            .apps => apps.show(),
            .servers => servers.show(),
            .stats => stats.show(),
            .settings => settings.show(),
        }
    }
    notice();
    conflicts.show();
    return .ok;
}

fn sidebar() void {
    var bar = dvui.box(@src(), .{}, .{ .expand = .vertical, .padding = .{ .x = 12, .y = 18, .w = 12, .h = 14 } });
    defer bar.deinit();
    const edge = bar.data().borderRectScale();
    draw.rectFill(.{ .x = edge.r.x + edge.r.w - edge.s, .y = edge.r.y, .w = edge.s, .h = edge.r.h }, 0, th.hairline);

    const items = [_]struct { app.Screen, draw.Icon, []const u8 }{
        .{ .connect, .power, tr.nav_connect },
        .{ .apps, .apps, tr.nav_apps },
        .{ .servers, .globe, tr.nav_servers },
        .{ .stats, .activity, tr.nav_stats },
    };
    for (items, 0..) |it, i| {
        if (w.iconButton(@src(), it[1], .{ .size = 40, .icon_size = 20, .color = th.text3, .active = app.screen == it[0], .tooltip = it[2] }, .{ .id_extra = i, .gravity_x = 0.5, .gravity_y = 0 })) {
            app.go(it[0]);
        }
        w.gapN(@src(), i, 0, 6);
    }
    _ = dvui.spacer(@src(), .{ .expand = .vertical });
    if (w.iconButton(@src(), .sliders, .{ .size = 40, .icon_size = 20, .color = th.text3, .active = app.screen == .settings, .tooltip = tr.nav_settings }, .{ .gravity_x = 0.5, .gravity_y = 0 })) {
        app.go(.settings);
    }
}

/// Transient one-line message at the bottom of the content area.
fn notice() void {
    const left = app.notice_until_ns - dvui.frameTimeNS();
    if (app.notice_len == 0 or left <= 0) return;
    var b = dvui.box(@src(), .{ .dir = .horizontal }, .{
        .gravity_x = 0.5,
        .gravity_y = 1.0,
        .margin = .{ .h = 18 },
        .padding = .{ .x = 14, .y = 9, .w = 14, .h = 9 },
        .background = true,
        .color_fill = w.col(th.raised),
        .color_border = w.col(th.border),
        .border = .all(1),
        .corners = .all(10),
    });
    defer b.deinit();
    if (app.notice_bad) {
        w.icon(@src(), .block, 13, th.bad, .{});
        w.gap(@src(), 8, 0);
    }
    w.text(@src(), app.notice_buf[0..app.notice_len], th.body(12.5), th.text, .{ .gravity_y = 0.5 });
    // another VPN in the way: the way to fix it starts here
    if (app.notice_fix) {
        w.gap(@src(), 12, 0);
        if (w.primaryButton(@src(), tr.fix, .{ .gravity_y = 0.5 })) {
            app.show_conflicts = true;
            app.notice_until_ns = 0;
        }
    }
    dvui.timer(b.data().id, @intCast(@divTrunc(left, 1000) + 1000));
}
