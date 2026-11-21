//! The one place where explanatory text lives.

const std = @import("std");
const dvui = @import("dvui");
const core = @import("core");
const app = @import("../../app.zig");
const th = @import("../theme.zig");
const w = @import("../widgets.zig");
const tr = @import("../../i18n.zig").t;
const build_options = @import("build_options");
const report = @import("../../report.zig");

const Src = std.builtin.SourceLocation;

pub fn show() void {
    const s = &app.state.settings;
    var root = dvui.box(@src(), .{}, .{ .expand = .both });
    defer root.deinit();

    w.heading(@src(), tr.nav_settings);
    w.gap(@src(), 0, 12);

    var scroll = dvui.scrollArea(@src(), .{}, .{ .expand = .both, .background = false });
    defer scroll.deinit();
    var col = dvui.box(@src(), .{}, .{ .expand = .horizontal, .padding = .{ .w = 18 } });
    defer col.deinit();

    section(@src(), tr.sec_protection);
    {
        var r = row(@src(), tr.kill_switch, tr.kill_switch_desc);
        defer r.deinit();
        var i: usize = @intFromEnum(s.kill_switch);
        if (w.segmented(@src(), &.{ tr.ks_off, tr.ks_selective, tr.ks_strict }, &i, .{})) {
            s.kill_switch = @enumFromInt(i);
            app.markDirty();
        }
    }
    {
        var r = row(@src(), "IPv6", tr.ipv6_desc);
        defer r.deinit();
        var i: usize = @intFromEnum(s.ipv6);
        if (w.segmented(@src(), &.{ tr.ipv6_block, tr.ipv6_tunnel, tr.ipv6_system }, &i, .{})) {
            s.ipv6 = @enumFromInt(i);
            app.markDirty();
        }
    }
    _ = switchRow(@src(), tr.failover, tr.failover_desc, &s.failover);
    _ = switchRow(@src(), tr.protect_off, tr.protect_off_desc, &s.protect_when_off);
    _ = switchRow(@src(), tr.check_exit, tr.check_exit_desc, &s.check_exit);
    _ = switchRow(@src(), tr.dns, tr.dns_desc, &s.dns_over_route);
    _ = switchRow(@src(), tr.lan, tr.lan_desc, &s.allow_lan);

    section(@src(), tr.sec_tunnel);
    {
        var r = row(@src(), tr.mode, tr.mode_desc);
        defer r.deinit();
        var i: usize = @intFromEnum(s.tunnel_mode);
        if (w.segmented(@src(), &.{ "TUN", tr.mode_proxy }, &i, .{})) {
            s.tunnel_mode = @enumFromInt(i);
            app.markDirty();
        }
    }
    {
        var r = row(@src(), tr.default_route, tr.default_route_desc);
        defer r.deinit();
        var i: usize = switch (s.default_route) {
            .direct => 1,
            else => 0,
        };
        if (w.segmented(@src(), &.{ "VPN", tr.route_direct }, &i, .{})) {
            s.default_route = if (i == 1) .direct else .auto;
            app.markDirty();
        }
    }

    section(@src(), tr.sec_launch);
    {
        var on = s.launch_at_login;
        if (switchRow(@src(), tr.launch_at_login, null, &on)) app.setLaunchAtLogin(on);
    }
    _ = switchRow(@src(), tr.auto_connect, null, &s.auto_connect);

    section(@src(), tr.sec_notifications);
    _ = switchRow(@src(), tr.notifications, tr.notifications_desc, &s.notifications);
    _ = switchRow(@src(), tr.sound, null, &s.sounds);

    section(@src(), tr.sec_interface);
    if (switchRow(@src(), tr.reduce_motion, null, &s.reduce_motion)) dvui.reduce_motion = s.reduce_motion;

    section(@src(), tr.sec_about);
    {
        var r = row(@src(), tr.version, null);
        defer r.deinit();
        w.text(@src(), build_options.version, th.mono(12), th.text2, .{});
    }
    // builds made without a release repository cannot update themselves
    if (app.updater_built) _ = switchRow(@src(), tr.auto_update, tr.auto_update_desc, &s.auto_update);
    {
        var r = row(@src(), tr.report, tr.report_desc);
        defer r.deinit();
        if (w.quietButton(@src(), tr.report_make, .{ .gravity_y = 0.5 })) report.make();
    }
    {
        // the state only (the SOCKS address is worth seeing); no essay here
        var r = row(@src(), tr.engine, null);
        defer r.deinit();
        var buf: [32]u8 = undefined;
        if (app.service_on and app.service_tun) {
            w.text(@src(), "TUN", th.mono(12), th.ok, .{});
        } else if (app.service_on and app.service_socks != 0) {
            w.text(@src(), std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{app.service_socks}) catch "", th.mono(12), th.ok, .{});
        } else if (app.proxy.running.load(.acquire)) {
            w.text(@src(), std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{app.proxy.port}) catch "", th.mono(12), th.ok, .{});
        } else {
            w.text(@src(), if (app.state.demo) tr.simulation else tr.proxy_off, th.code(12), th.warn, .{});
        }
    }
    w.gap(@src(), 0, 24);
}

fn section(src: Src, title: []const u8) void {
    var b = dvui.box(src, .{}, .{ .expand = .horizontal, .padding = .{ .y = 22, .h = 6 } });
    defer b.deinit();
    w.caption(@src(), title, .{ .gravity_y = 0 });
}

/// Title (+ optional description) on the left; the caller adds the control.
fn row(src: Src, title: []const u8, desc: ?[]const u8) *dvui.BoxWidget {
    const hb = dvui.box(src, .{ .dir = .horizontal }, .{ .expand = .horizontal, .padding = .{ .y = 10, .h = 10 } });
    {
        var left = dvui.box(@src(), .{}, .{ .expand = .horizontal, .gravity_y = 0.5, .padding = .{ .w = 24 }, .max_size_content = .width(330) });
        defer left.deinit();
        w.text(@src(), title, th.body(13.5), th.text, .{ .gravity_y = 0 });
        if (desc) |d| {
            w.gap(@src(), 0, 4);
            var tl = dvui.textLayout(@src(), .{}, .{
                .expand = .horizontal,
                .background = false,
                .padding = .all(0),
                .margin = .all(0),
                .font = th.body(12).withLineHeight(1.35),
                .color_text = w.col(th.text3),
            });
            tl.addText(d, .{});
            tl.deinit();
        }
    }
    return hb;
}

fn switchRow(src: Src, title: []const u8, desc: ?[]const u8, value: *bool) bool {
    var r = row(src, title, desc);
    defer r.deinit();
    if (w.toggle(@src(), value, .{})) {
        app.markDirty();
        return true;
    }
    return false;
}
