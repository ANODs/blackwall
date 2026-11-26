//! Developer aid: `BLACKWALL_SHOTS=<dir>` renders every screen to a PNG and exits.
//! Used to review the interface without driving the window by hand. Runs on
//! sample data and never writes the user's configuration.

const std = @import("std");
const dvui = @import("dvui");
const core = @import("core");
const app = @import("app.zig");
const servers = @import("ui/screens/servers.zig");

var dir_path: ?[]const u8 = null;
var step: usize = 0;
var picture: ?dvui.Picture = null;

const settle = 10;
const Action = enum { none, off, click_route, rules, add_site, settings_1, settings_2, settings_3, settings_end, settings_advanced, open_add, add_keys };
const plan = [_]struct { app.Screen, Action, []const u8 }{
    .{ .connect, .off, "1-connect-off" },
    .{ .connect, .none, "2-connect-on" },
    .{ .apps, .none, "3-apps" },
    .{ .apps, .click_route, "4-apps-route-menu" },
    .{ .apps, .rules, "4b-apps-rules" },
    .{ .apps, .add_site, "4c-apps-add-site" },
    .{ .servers, .none, "5-servers" },
    .{ .stats, .none, "6-stats" },
    .{ .settings, .none, "7-settings" },
    .{ .settings, .settings_1, "7a-settings" },
    .{ .settings, .settings_2, "7b-settings" },
    .{ .settings, .settings_3, "7c-settings" },
    .{ .settings, .settings_end, "7d-settings-end" },
    .{ .settings, .settings_advanced, "7e-settings-advanced" },
    .{ .servers, .open_add, "8-add-dialog" },
    .{ .servers, .add_keys, "9-own-keys" },
};

const sample_keys =
    \\vless://11111111-2222-3333-4444-555555555555@nl.example.invalid:443?security=reality&sni=example.com#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam
    \\trojan://secret@de.example.invalid:443#DE%20Frankfurt
    \\vmess://unsupported
    \\hy2://auth@127.0.0.1:9#Local%20closed%20port
;

pub fn init() void {
    const mi = dvui.App.main_init orelse return;
    dir_path = mi.environ_map.get("BLACKWALL_SHOTS");
    if (dir_path != null) {
        app.persist = false;
        dvui.reduce_motion = true;
        for (0..90) |_| app.engine.tick(&app.state);
    }
}

/// How far a settings step scrolls from the one before it (the wheel's
/// units); the last goes to the end of the list.
fn settingsScroll(a: Action) ?f32 {
    return switch (a) {
        .settings_1, .settings_2, .settings_3 => -360,
        .settings_end, .settings_advanced => -6000,
        else => null,
    };
}

/// Returns true when all screenshots are done and the app should quit.
pub fn before() bool {
    if (dir_path == null) return false;
    const idx = step / settle;
    if (idx >= plan.len) {
        // and the report for GitHub, as it would be saved now
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (@import("report.zig").save(dir_path.?, &buf)) |path| std.log.info("report: {s}", .{path});
        return true;
    }
    const p = plan[idx];
    const phase = step % settle;
    app.screen = p[0];

    if (phase == 0) switch (p[1]) {
        .off => app.engine.disconnect(),
        .none, .click_route => if (app.engine.status != .connected) {
            app.engine.status = .connected;
            app.engine.session_secs = 764;
        },
        .rules => @import("ui/screens/apps.zig").filter = 2,
        .add_site => @import("ui/screens/apps.zig").adding = true,
        .settings_1, .settings_2, .settings_3, .settings_end => {},
        .settings_advanced => @import("ui/screens/settings.zig").advanced = true,
        .open_add => {
            @import("ui/screens/apps.zig").filter = 0;
            @import("ui/screens/apps.zig").adding = false;
            servers.show_add = true;
        },
        .add_keys => {
            servers.show_add = false;
            app.addFromText(sample_keys) catch |err| std.log.err("add keys: {t}", .{err});
            roundTrip() catch |err| std.log.err("config round trip: {t}", .{err});
        },
    };
    if (p[1] == .click_route) {
        if (dvui.tagGet("route-first")) |t| {
            const c = t.rect.center();
            if (phase == 3) _ = app.win.addEventMouseMotion(.{ .pt = c }) catch {};
            if (phase == 4) _ = app.win.addEventMouseButton(.left, .press) catch {};
            if (phase == 5) _ = app.win.addEventMouseButton(.left, .release) catch {};
        }
    } else if (settingsScroll(p[1])) |dy| {
        // further down the list, a step at a time
        if (phase == 1) _ = app.win.addEventMouseMotion(.{ .pt = dvui.windowRectPixels().center() }) catch {};
        if (phase == 2) _ = app.win.addEventMouseWheel(dy, .vertical, .mouse) catch {};
    } else if (phase == 0 and p[1] != .add_site) {
        _ = app.win.addEventMouseMotion(.{ .pt = .{ .x = 2, .y = 2 } }) catch {};
        _ = app.win.addEventKey(.{ .code = .escape, .action = .down, .mod = .none }) catch {};
    }
    // let latency probes of the sample keys finish
    if (p[1] == .add_keys and app.probing and phase == settle - 2) return false;

    if (phase == settle - 1) picture = dvui.Picture.start(dvui.windowRectPixels());
    dvui.refresh(null, @src(), null);
    return false;
}

pub fn after() void {
    if (dir_path == null or step / settle >= plan.len) return;
    const p = plan[step / settle];
    if (!(p[1] == .add_keys and app.probing and step % settle == settle - 2)) step += 1;
    var pic = picture orelse return;
    picture = null;
    pic.stop();
    defer pic.deinit();
    write(&pic, p[2]) catch |err| std.log.err("screenshot {s}: {t}", .{ p[2], err });
}

/// Save the config into the screenshot folder and load it back.
fn roundTrip() !void {
    try core.store.save(app.gpa, app.io, dir_path.?, &app.state);
    var copy: core.model.State = .init(app.gpa);
    defer copy.deinit();
    if (!try core.store.load(app.gpa, app.io, dir_path.?, &copy)) return error.NotWritten;
    std.log.info("config round trip ok: {d} servers, {d} subscriptions", .{ copy.servers.items.len, copy.subs.items.len });
}

fn write(pic: *dvui.Picture, name: []const u8) !void {
    const io = app.io;
    var dir = try std.Io.Dir.cwd().createDirPathOpen(io, dir_path.?, .{});
    defer dir.close(io);
    var name_buf: [64]u8 = undefined;
    const file_name = try std.fmt.bufPrint(&name_buf, "{s}.png", .{name});
    var file = try dir.createFile(io, file_name, .{});
    defer file.close(io);
    var buf: [64 * 1024]u8 = undefined;
    var fw = file.writer(io, &buf);
    try pic.png(&fw.interface);
    try fw.interface.flush();
}
