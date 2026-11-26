//! The one place where explanatory text lives.
//!
//! Grouped by what the user asks: how it connects, what it blocks when
//! the VPN is not working, where traffic goes, the app itself. Rare
//! technical knobs wait folded under "Advanced".

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

/// "Advanced" unfolded (until the window closes; folded again on start)
pub var advanced = false;

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

    section(@src(), tr.sec_connection);
    _ = switchRow(@src(), tr.auto_connect, null, &s.auto_connect);
    _ = switchRow(@src(), tr.failover, tr.failover_desc, &s.failover);
    _ = switchRow(@src(), tr.check_exit, tr.check_exit_desc, &s.check_exit);

    // what is blocked while the VPN is not working: on a drop, and after
    // Disconnect
    section(@src(), tr.sec_protection);
    {
        var r = row(@src(), tr.kill_switch, tr.kill_switch_desc);
        defer r.deinit();
        var i: usize = @backingInt(s.kill_switch);
        if (w.segmented(@src(), &.{ tr.ks_off, tr.ks_selective, tr.ks_strict }, &i, .{})) {
            s.kill_switch = @fromBackingInt(@intCast(i));
            app.markDirty();
        }
    }
    _ = switchRow(@src(), tr.protect_off, tr.protect_off_desc, &s.protect_when_off);

    section(@src(), tr.sec_routes);
    {
        var r = row(@src(), tr.default_route, null);
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
    _ = switchRow(@src(), tr.ru_direct, tr.ru_direct_desc, &s.ru_direct);
    routing();

    section(@src(), tr.sec_app);
    {
        var on = s.launch_at_login;
        if (switchRow(@src(), tr.launch_at_login, null, &on)) app.setLaunchAtLogin(on);
    }
    // builds made without a release repository cannot update themselves
    if (@import("../../app/updater.zig").built) _ = switchRow(@src(), tr.auto_update, tr.auto_update_desc, &s.auto_update);
    if (switchRow(@src(), tr.reduce_motion, null, &s.reduce_motion)) dvui.reduce_motion = s.reduce_motion;

    if (fold(@src(), tr.sec_advanced, &advanced)) {
        {
            var buf: [256]u8 = undefined;
            var r = row(@src(), tr.mode, std.fmt.bufPrint(&buf, tr.mode_desc, .{proxyAddress()}) catch null);
            defer r.deinit();
            var i: usize = @backingInt(s.tunnel_mode);
            if (w.segmented(@src(), &.{ "TUN", tr.mode_proxy }, &i, .{})) {
                s.tunnel_mode = @fromBackingInt(@intCast(i));
                app.markDirty();
            }
        }
        {
            var r = row(@src(), "IPv6", tr.ipv6_desc);
            defer r.deinit();
            var i: usize = @backingInt(s.ipv6);
            if (w.segmented(@src(), &.{ tr.ipv6_block, tr.ipv6_tunnel, tr.ipv6_system }, &i, .{})) {
                s.ipv6 = @fromBackingInt(@intCast(i));
                app.markDirty();
            }
        }
        _ = switchRow(@src(), tr.lan, tr.lan_desc, &s.allow_lan);
        _ = switchRow(@src(), tr.dns, tr.dns_desc, &s.dns_over_route);
    }

    section(@src(), tr.sec_about);
    {
        var r = row(@src(), tr.version, null);
        defer r.deinit();
        w.text(@src(), build_options.version, th.mono(12), th.text2, .{});
    }
    {
        var r = row(@src(), tr.report, tr.report_desc);
        defer r.deinit();
        if (w.quietButton(@src(), tr.report_make, .{ .gravity_y = 0.5 })) report.make();
    }
    w.gap(@src(), 0, 24);
}

/// Where applications in proxy mode are pointed: the port in use while
/// the proxy runs, the one it asks for otherwise.
fn proxyAddress() []const u8 {
    const S = struct {
        var buf: [24]u8 = undefined;
    };
    const port: u16 = if (app.service_on and app.service_socks != 0)
        app.service_socks
    else if (app.proxy.running.load(.acquire))
        app.proxy.port
    else
        app.preferred_proxy_port;
    return std.fmt.bufPrint(&S.buf, "127.0.0.1:{d}", .{port}) catch "127.0.0.1";
}

/// until when "Reset" asks again before it resets (0: it does not ask)
var reset_ask_until: i128 = 0;

/// The rules for apps and sites with the two settings above: export,
/// import, back to default (a second press within a few seconds confirms,
/// the rules are gone after it).
fn routing() void {
    var r = row(@src(), tr.routing, tr.routing_desc);
    defer r.deinit();
    var bar = dvui.box(@src(), .{ .dir = .horizontal }, .{ .gravity_y = 0.5 });
    defer bar.deinit();
    // narrower than the usual buttons: three fit beside the text
    const pad: dvui.Rect = .{ .x = 12, .y = 9, .w = 12, .h = 9 };
    if (w.quietButton(@src(), tr.profile_export, .{ .padding = pad })) app.exportProfile();
    w.gap(@src(), 6, 0);
    if (w.quietButton(@src(), tr.profile_import, .{ .padding = pad })) app.importProfile();
    w.gap(@src(), 6, 0);
    const now = dvui.frameTimeNS();
    const asking = now < reset_ask_until;
    if (w.quietButton(@src(), if (asking) tr.profile_confirm else tr.profile_default, if (asking) .{ .padding = pad, .color_text = w.col(th.warn), .color_text_hover = w.col(th.warn) } else .{ .padding = pad })) {
        if (asking) {
            reset_ask_until = 0;
            app.resetProfile();
        } else {
            reset_ask_until = now + 4 * std.time.ns_per_s;
        }
    }
    // the question goes away by itself
    if (asking) {
        const id = bar.data().id;
        if (dvui.timerDoneOrNone(id)) dvui.timer(id, @intCast(@divTrunc(reset_ask_until - now, std.time.ns_per_us) + 1));
    }
}

fn section(src: Src, title: []const u8) void {
    var b = dvui.box(src, .{}, .{ .expand = .horizontal, .padding = .{ .y = 22, .h = 6 } });
    defer b.deinit();
    w.caption(@src(), title, .{ .gravity_y = 0 });
}

/// A section title that folds the rows under it away; true while open.
fn fold(src: Src, title: []const u8, open: *bool) bool {
    var bw: dvui.ButtonWidget = undefined;
    bw.init(src, .{}, .{
        .expand = .horizontal,
        .padding = .{ .y = 22, .h = 6 },
        .margin = .all(0),
        .background = false,
        .role = .button,
    });
    bw.processEvents();
    if (bw.clicked()) open.* = !open.*;
    {
        var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
        defer hb.deinit();
        const color = if (bw.hovered()) th.text2 else th.text3;
        w.text(@src(), title, th.medium(11), color, .{ .gravity_y = 0.5 });
        w.gap(@src(), 4, 0);
        w.icon(@src(), if (open.*) .chevron_down else .chevron_right, 12, color, .{ .gravity_y = 0.5 });
    }
    bw.drawFocus();
    bw.deinit();
    return open.*;
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
