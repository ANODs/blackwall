const std = @import("std");
const dvui = @import("dvui");
const core = @import("core");
const app = @import("../../app.zig");
const th = @import("../theme.zig");
const draw = @import("../draw.zig");
const w = @import("../widgets.zig");
const graph = @import("../graph.zig");
const tr = @import("../../i18n.zig").t;

var period: usize = 0;

pub fn show() void {
    const e = &app.engine;
    var root = dvui.box(@src(), .{}, .{ .expand = .both });
    defer root.deinit();

    {
        var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
        defer hb.deinit();
        w.heading(@src(), tr.nav_stats);
        _ = dvui.spacer(@src(), .{ .expand = .horizontal });
        _ = w.segmented(@src(), &.{ tr.period_1m, tr.period_2m }, &period, .{});
    }
    w.gap(@src(), 0, 18);

    {
        var card = dvui.box(@src(), .{}, .{
            .expand = .horizontal,
            .background = true,
            .color_fill = w.col(th.panel),
            .corners = .all(14),
            .padding = .all(20),
        });
        defer card.deinit();
        {
            var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
            defer hb.deinit();
            big(@src(), .arrow_down, core.fmt.rate(e.down_bps), th.text);
            w.gap(@src(), 36, 0);
            big(@src(), .arrow_up, core.fmt.rate(e.up_bps), th.text3);
            _ = dvui.spacer(@src(), .{ .expand = .horizontal });
            total(@src(), .arrow_down, core.fmt.bytes(e.total_down));
            w.gap(@src(), 18, 0);
            total(@src(), .arrow_up, core.fmt.bytes(e.total_up));
        }
        w.gap(@src(), 0, 16);
        const rs = w.canvas(@src(), .{ .w = 100, .h = 150 }, .{ .expand = .horizontal, .gravity_y = 0 });
        graph.traffic(rs, e, if (period == 0) 60 else 120, true);
    }
    w.gap(@src(), 0, 18);

    var scroll = dvui.scrollArea(@src(), .{}, .{ .expand = .both, .background = false });
    defer scroll.deinit();

    // top consumers, largest first
    var order: [8]usize = undefined;
    var n: usize = 0;
    for (app.state.apps.items, 0..) |a, i| {
        const v = a.total_down + a.total_up;
        if (v == 0) continue;
        var pos = n;
        while (pos > 0) : (pos -= 1) {
            const o = app.state.apps.items[order[pos - 1]];
            if (o.total_down + o.total_up >= v) break;
        }
        if (pos >= order.len) continue;
        const last = @min(n, order.len - 1);
        var k = last;
        while (k > pos) : (k -= 1) order[k] = order[k - 1];
        order[pos] = i;
        n = @min(n + 1, order.len);
    }
    if (n == 0) return;
    const first = app.state.apps.items[order[0]];
    const max: f32 = @floatFromInt(first.total_down + first.total_up);
    for (order[0..n], 0..) |idx, k| {
        const a = app.state.apps.items[idx];
        var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .id_extra = k, .expand = .horizontal, .padding = .{ .x = 4, .y = 7, .w = 4, .h = 7 } });
        defer hb.deinit();
        w.monogram(@src(), a.name, 26, .{});
        w.gap(@src(), 12, 0);
        w.text(@src(), a.name, th.body(13), th.text, .{ .min_size_content = .{ .w = 170 }, .max_size_content = .width(170) });
        const rs = w.canvas(@src(), .{ .w = 40, .h = 4 }, .{ .expand = .horizontal });
        draw.rectFill(rs.r, rs.r.h / 2, th.panel);
        var bar = rs.r;
        bar.w *= @as(f32, @floatFromInt(a.total_down + a.total_up)) / max;
        draw.rectFill(bar, rs.r.h / 2, th.text2);
        w.gap(@src(), 16, 0);
        const q = core.fmt.bytes(a.total_down + a.total_up);
        var hb2 = dvui.box(@src(), .{ .dir = .horizontal }, .{ .min_size_content = .{ .w = 72 }, .gravity_y = 0.5 });
        defer hb2.deinit();
        _ = dvui.spacer(@src(), .{ .expand = .horizontal });
        w.text(@src(), q.value(), th.mono(12), th.text, .{});
        w.gap(@src(), 4, 0);
        w.text(@src(), q.unit, th.body(11), th.text3, .{});
    }
}

fn big(src: std.builtin.SourceLocation, icon: draw.Icon, q: core.fmt.Quantity, icon_color: dvui.Color) void {
    var hb = dvui.box(src, .{ .dir = .horizontal }, .{});
    defer hb.deinit();
    w.icon(@src(), icon, 18, icon_color, .{});
    w.gap(@src(), 10, 0);
    w.quantity(@src(), q.value(), q.unit, 26, .{});
}

fn total(src: std.builtin.SourceLocation, icon: draw.Icon, q: core.fmt.Quantity) void {
    var hb = dvui.box(src, .{ .dir = .horizontal }, .{ .gravity_y = 0.5 });
    defer hb.deinit();
    w.icon(@src(), icon, 12, th.text3, .{});
    w.gap(@src(), 6, 0);
    w.text(@src(), q.value(), th.mono(12), th.text2, .{});
    w.gap(@src(), 4, 0);
    w.text(@src(), q.unit, th.body(11), th.text3, .{});
}
