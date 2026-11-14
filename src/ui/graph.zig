//! Traffic graph: download as a filled area, upload as a thin line.

const std = @import("std");
const dvui = @import("dvui");
const core = @import("core");
const th = @import("theme.zig");
const draw = @import("draw.zig");

pub fn traffic(rs: dvui.RectScale, e: *const core.engine.Engine, seconds: usize, grid: bool) void {
    const r = rs.r;
    if (r.w < 4 or r.h < 4) return;
    const n = @min(seconds, core.engine.history_len);
    const top = @max(e.peak(n) * 1.2, 64_000);

    if (grid) {
        for (1..4) |i| {
            const y = r.y + r.h * @as(f32, @floatFromInt(i)) / 4.0;
            draw.polyline(&.{ .{ .x = r.x, .y = y }, .{ .x = r.x + r.w, .y = y } }, 1, th.hairline, false);
        }
    }

    const arena = dvui.currentWindow().arena();
    var down: dvui.Path.Builder = .init(arena);
    var up: dvui.Path.Builder = .init(arena);
    var area: dvui.Path.Builder = .init(arena);
    const base = r.y + r.h;
    area.addPoint(.{ .x = r.x, .y = base });
    for (0..n) |k| {
        const i = n - 1 - k; // oldest first
        const x = r.x + r.w * @as(f32, @floatFromInt(k)) / @as(f32, @floatFromInt(n - 1));
        const yd = base - (e.sample(.down, i) / top) * (r.h - 2 * rs.s) - rs.s;
        const yu = base - (e.sample(.up, i) / top) * (r.h - 2 * rs.s) - rs.s;
        down.addPoint(.{ .x = x, .y = yd });
        up.addPoint(.{ .x = x, .y = yu });
        area.addPoint(.{ .x = x, .y = yd });
    }
    area.addPoint(.{ .x = r.x + r.w, .y = base });

    dvui.Path.fill(&.{area.build()}, .{ .color = .{ .color = th.text.opacity(0.07) } });
    up.build().stroke(.{ .thickness = 1.2 * rs.s, .color = .{ .color = th.text3 } });
    down.build().stroke(.{ .thickness = 1.6 * rs.s, .color = .{ .color = th.text } });
}
