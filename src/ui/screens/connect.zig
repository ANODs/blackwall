const std = @import("std");
const dvui = @import("dvui");
const core = @import("core");
const app = @import("../../app.zig");
const th = @import("../theme.zig");
const draw = @import("../draw.zig");
const w = @import("../widgets.zig");
const graph = @import("../graph.zig");
const tr = @import("../../i18n.zig").t;

const pi = std.math.pi;

pub fn show() void {
    var root = dvui.box(@src(), .{}, .{ .expand = .both });
    defer root.deinit();

    _ = dvui.spacer(@src(), .{ .expand = .vertical });

    status();
    w.gap(@src(), 0, 18);
    powerButton();
    w.gap(@src(), 0, 10);
    {
        var buf: [16]u8 = undefined;
        const on = app.engine.status == .connected;
        w.text(@src(), core.fmt.duration(&buf, app.engine.session_secs), th.mono(13), if (on) th.text2 else th.bg, .{ .gravity_x = 0.5, .gravity_y = 0 });
    }
    w.gap(@src(), 0, 14);
    serverPill();

    _ = dvui.spacer(@src(), .{ .expand = .vertical });

    bottom();
}

fn status() void {
    const e = &app.engine;
    const sum = app.summary();
    const mixed = sum.direct + sum.dpi > 0;
    const label: []const u8, const icon: draw.Icon, const color: dvui.Color = switch (e.status) {
        .disconnected => if (app.guarding()) .{ tr.st_guard, .shield, th.text2 } else .{ tr.st_disconnected, .power, th.text3 },
        .connecting => .{ tr.st_connecting, .refresh, th.text2 },
        .reconnecting => .{ tr.st_reconnecting, .refresh, th.warn },
        .blocked => .{ tr.st_blocked, .block, th.bad },
        .connected => if (mixed) .{ tr.st_mixed, .shield, th.text } else .{ tr.st_on, .shield, th.ok },
    };
    var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .gravity_x = 0.5 });
    defer hb.deinit();
    w.icon(@src(), icon, 15, color, .{});
    w.gap(@src(), 8, 0);
    w.text(@src(), label, th.medium(13), if (e.status == .disconnected) th.text2 else th.text, .{});
}

fn powerButton() void {
    const e = &app.engine;
    var bw: dvui.ButtonWidget = undefined;
    bw.init(@src(), .{ .draw_focus = false }, .{
        .min_size_content = .all(172),
        .padding = .all(0),
        .margin = .all(0),
        .background = false,
        .gravity_x = 0.5,
        .label = .{ .text = tr.nav_connect },
    });
    bw.processEvents();
    if (bw.clicked()) {
        if (app.state.servers.items.len == 0) app.go(.servers) else app.toggle();
    }

    const id = bw.data().id;
    const on = dvui.stateFade(id, "on", e.status == .connected, 0.22);
    const hov = dvui.stateFade(id, "hov", bw.hovered(), 0.12);
    const rs = bw.data().contentRectScale();
    const s = rs.s;
    const c = rs.r.center();
    const outer = rs.r.w / 2 - 10 * s;

    if (on > 0) {
        var b: dvui.Path.Builder = .init(dvui.currentWindow().arena());
        b.addArc(c, outer, 2 * pi, 0, true);
        b.build().stroke(.{ .thickness = 16 * s, .color = .{ .color = th.text.opacity(0.07 * on) }, .closed = true, .fade = 8 * s });
    }

    const ring_off = th.border.lerp(th.text3, hov);
    draw.circleStroke(c, outer, (1.5 + 0.5 * on) * s, ring_off.lerp(th.text, on));

    if (e.busy()) {
        const t: f32 = @floatCast(@as(f64, @floatFromInt(@mod(dvui.frameTimeNS(), 1_200_000_000))) / 1.2e9);
        const a = (1 - t) * 2 * pi;
        draw.arcStroke(c, outer, a + 1.5, a, 2 * s, th.text);
    }

    const disc = outer - 14 * s;
    draw.circleFill(c, disc, th.panel.lerp(th.raised, hov).lerp(th.text, on));
    const isz = 46 * s;
    draw.icon(.power, .{ .x = c.x - isz / 2, .y = c.y - isz / 2, .w = isz, .h = isz }, th.text2.lerp(th.text, hov).lerp(th.bg, on), 2.4 * s);

    if (bw.focused()) draw.circleStroke(c, outer + 6 * s, 1.5 * s, th.theme.focus);
    bw.deinit();
}

fn serverPill() void {
    var bw: dvui.ButtonWidget = undefined;
    bw.init(@src(), .{}, .{
        .padding = .{ .x = 10, .y = 8, .w = 10, .h = 8 },
        .margin = .all(0),
        .corners = .all(11),
        .background = true,
        .color_fill = w.col(.transparent),
        .color_fill_hover = w.col(th.panel),
        .color_fill_press = w.col(th.raised),
        .gravity_x = 0.5,
    });
    bw.processEvents();
    bw.drawBackground();
    if (bw.clicked()) app.go(.servers);
    {
        var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{});
        defer hb.deinit();
        if (app.shownServer()) |sv| {
            w.countryTag(@src(), sv.country, .{});
            w.gap(@src(), 10, 0);
            w.text(@src(), sv.name, th.medium(14), th.text, .{});
            if (sv.ping_ms) |ms| {
                w.gap(@src(), 10, 0);
                var buf: [8]u8 = undefined;
                w.text(@src(), std.fmt.bufPrint(&buf, "{d}", .{ms}) catch "", th.mono(12), th.text2, .{});
                w.gap(@src(), 3, 0);
                w.text(@src(), "ms", th.body(11), th.text3, .{});
            }
        } else {
            w.icon(@src(), .plus, 15, th.text2, .{});
            w.gap(@src(), 8, 0);
            w.text(@src(), tr.add_subscription, th.medium(14), th.text, .{});
        }
        w.gap(@src(), 6, 0);
        w.icon(@src(), .chevron_right, 14, th.text3, .{});
    }
    bw.drawFocus();
    bw.deinit();
}

fn bottom() void {
    const e = &app.engine;
    var card = dvui.box(@src(), .{ .dir = .horizontal }, .{
        .expand = .horizontal,
        .background = true,
        .color_fill = w.col(th.panel),
        .corners = .all(14),
        .padding = .{ .x = 20, .y = 16, .w = 20, .h = 16 },
        .min_size_content = .{ .h = 76 },
    });
    defer card.deinit();

    {
        var left = dvui.box(@src(), .{}, .{ .min_size_content = .{ .w = 150 }, .gravity_y = 0.5 });
        defer left.deinit();
        rate(@src(), .arrow_down, e.down_bps, th.text);
        w.gap(@src(), 0, 10);
        rate(@src(), .arrow_up, e.up_bps, th.text3);
    }

    const rs = w.canvas(@src(), .{ .w = 100, .h = 60 }, .{ .expand = .both });
    graph.traffic(rs, e, 60, false);

    w.gap(@src(), 20, 0);
    exits();
}

fn rate(src: std.builtin.SourceLocation, icon: draw.Icon, bps: f32, icon_color: dvui.Color) void {
    var hb = dvui.box(src, .{ .dir = .horizontal }, .{});
    defer hb.deinit();
    w.icon(@src(), icon, 14, icon_color, .{});
    w.gap(@src(), 8, 0);
    const q = core.fmt.rate(bps);
    w.quantity(@src(), q.value(), q.unit, 16, .{});
}

/// How online apps are split between exits: icon + count, nothing else.
fn exits() void {
    const sum = app.summary();
    var vb = dvui.box(@src(), .{}, .{ .gravity_y = 0.5 });
    defer vb.deinit();
    const items = [_]struct { draw.Icon, u32, []const u8 }{
        .{ .globe, sum.vpn, "VPN" },
        .{ .arrow_right, sum.direct, tr.route_direct },
        .{ .bolt, sum.dpi, tr.route_dpi },
        .{ .block, sum.blocked, tr.route_block },
    };
    for (items, 0..) |it, i| {
        if (it[1] == 0) continue;
        var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .id_extra = i, .padding = .{ .y = 2, .h = 2 } });
        defer hb.deinit();
        w.icon(@src(), it[0], 13, th.text3, .{});
        w.gap(@src(), 8, 0);
        var buf: [8]u8 = undefined;
        w.text(@src(), std.fmt.bufPrint(&buf, "{d}", .{it[1]}) catch "", th.mono(12), th.text2, .{});
    }
}
