//! Hand-drawn vector primitives and the icon set.
//! Icons live on a 24-unit grid and are stroked, so they stay crisp at any
//! scale and need no image assets.

const std = @import("std");
const dvui = @import("dvui");
const Color = dvui.Color;
const Rect = dvui.Rect.Physical;
const Point = dvui.Point.Physical;

const pi = std.math.pi;

fn builder() dvui.Path.Builder {
    return .init(dvui.currentWindow().arena());
}

pub fn circleStroke(c: Point, radius: f32, thickness: f32, color: Color) void {
    var b = builder();
    b.addArc(c, radius, 2 * pi, 0, true);
    b.build().stroke(.{ .thickness = thickness, .color = .{ .color = color }, .closed = true });
}

pub fn circleFill(c: Point, radius: f32, color: Color) void {
    var b = builder();
    b.addArc(c, radius, 2 * pi, 0, true);
    b.build().fillConvex(.{ .color = .{ .color = color }, .fade = 1.0 });
}

/// Arc from angle `a0` down to `a1` (radians, clockwise from +x, a0 >= a1).
pub fn arcStroke(c: Point, radius: f32, a0: f32, a1: f32, thickness: f32, color: Color) void {
    var b = builder();
    b.addArc(c, radius, a0, a1, false);
    b.build().stroke(.{ .thickness = thickness, .color = .{ .color = color } });
}

pub fn polyline(pts: []const Point, thickness: f32, color: Color, closed: bool) void {
    var b = builder();
    for (pts) |p| b.addPoint(p);
    b.build().stroke(.{ .thickness = thickness, .color = .{ .color = color }, .closed = closed });
}

pub fn rectFill(r: Rect, radius: f32, color: Color) void {
    r.fill(.round(radius), .{ .color = .{ .color = color }, .fade = 1.0 });
}

pub fn rectStroke(r: Rect, radius: f32, thickness: f32, color: Color) void {
    r.stroke(.round(radius), .{ .thickness = thickness, .color = .{ .color = color }, .closed = true });
}

pub const Icon = enum {
    power,
    apps,
    globe,
    activity,
    sliders,
    plus,
    search,
    chevron_down,
    chevron_right,
    check,
    star,
    star_filled,
    refresh,
    close,
    arrow_down,
    arrow_up,
    arrow_right,
    arrow_left,
    bolt,
    block,
    shield,
    trash,
    clipboard,
};

const G = struct {
    r: Rect,
    w: f32,
    color: Color,

    fn p(g: G, x: f32, y: f32) Point {
        return .{ .x = g.r.x + x / 24.0 * g.r.w, .y = g.r.y + y / 24.0 * g.r.h };
    }
    fn u(g: G, v: f32) f32 {
        return v / 24.0 * g.r.w;
    }
    fn line(g: G, pts: []const [2]f32) void {
        g.poly(pts, false);
    }
    fn poly(g: G, pts: []const [2]f32, closed: bool) void {
        var b = builder();
        for (pts) |q| b.addPoint(g.p(q[0], q[1]));
        b.build().stroke(.{ .thickness = g.w, .color = .{ .color = g.color }, .closed = closed, .endcap_style = .square });
    }
    fn fill(g: G, pts: []const [2]f32) void {
        var b = builder();
        for (pts) |q| b.addPoint(g.p(q[0], q[1]));
        dvui.Path.fill(&.{b.build()}, .{ .color = .{ .color = g.color }, .fade = 1.0 });
    }
    fn circle(g: G, x: f32, y: f32, radius: f32) void {
        circleStroke(g.p(x, y), g.u(radius), g.w, g.color);
    }
    fn arc(g: G, x: f32, y: f32, radius: f32, a0: f32, a1: f32) void {
        arcStroke(g.p(x, y), g.u(radius), a0, a1, g.w, g.color);
    }
    fn box(g: G, x: f32, y: f32, w: f32, h: f32, radius: f32) void {
        const tl = g.p(x, y);
        rectStroke(.{ .x = tl.x, .y = tl.y, .w = g.u(w), .h = g.u(h) }, g.u(radius), g.w, g.color);
    }
};

const star_pts = blk: {
    var pts: [10][2]f32 = undefined;
    for (0..10) |i| {
        const a = -pi / 2.0 + @as(f32, @floatFromInt(i)) * pi / 5.0;
        const rad: f32 = if (i % 2 == 0) 8.6 else 3.7;
        pts[i] = .{ 12 + rad * @cos(a), 12.6 + rad * @sin(a) };
    }
    break :blk pts;
};

/// Draw `icon` inside the square `r` (physical pixels).
pub fn icon(which: Icon, r: Rect, color: Color, stroke_px: f32) void {
    const g: G = .{ .r = r, .w = stroke_px, .color = color };
    switch (which) {
        .power => {
            g.arc(12, 13, 7.5, 1.5 * pi - 0.72, -0.5 * pi + 0.72);
            g.line(&.{ .{ 12, 3.5 }, .{ 12, 11.5 } });
        },
        .apps => {
            g.box(4, 4, 6.5, 6.5, 1.6);
            g.box(13.5, 4, 6.5, 6.5, 1.6);
            g.box(4, 13.5, 6.5, 6.5, 1.6);
            g.box(13.5, 13.5, 6.5, 6.5, 1.6);
        },
        .globe => {
            g.circle(12, 12, 8.5);
            g.line(&.{ .{ 3.5, 12 }, .{ 20.5, 12 } });
            var b = builder();
            var i: usize = 0;
            while (i < 40) : (i += 1) {
                const a = @as(f32, @floatFromInt(i)) / 40.0 * 2 * pi;
                b.addPoint(g.p(12 + 3.7 * @cos(a), 12 + 8.5 * @sin(a)));
            }
            b.build().stroke(.{ .thickness = g.w, .color = .{ .color = color }, .closed = true });
        },
        .activity => g.line(&.{ .{ 3, 12 }, .{ 7.5, 12 }, .{ 10.5, 4.5 }, .{ 14, 19.5 }, .{ 16.8, 12 }, .{ 21, 12 } }),
        .sliders => {
            g.line(&.{ .{ 4, 7.5 }, .{ 6.6, 7.5 } });
            g.circle(9, 7.5, 2.4);
            g.line(&.{ .{ 11.4, 7.5 }, .{ 20, 7.5 } });
            g.line(&.{ .{ 4, 16.5 }, .{ 12.6, 16.5 } });
            g.circle(15, 16.5, 2.4);
            g.line(&.{ .{ 17.4, 16.5 }, .{ 20, 16.5 } });
        },
        .plus => {
            g.line(&.{ .{ 12, 5 }, .{ 12, 19 } });
            g.line(&.{ .{ 5, 12 }, .{ 19, 12 } });
        },
        .search => {
            g.circle(10.5, 10.5, 6);
            g.line(&.{ .{ 15, 15 }, .{ 20, 20 } });
        },
        .chevron_down => g.line(&.{ .{ 7, 10 }, .{ 12, 15 }, .{ 17, 10 } }),
        .chevron_right => g.line(&.{ .{ 10, 7 }, .{ 15, 12 }, .{ 10, 17 } }),
        .check => g.line(&.{ .{ 5, 12.5 }, .{ 10, 17.5 }, .{ 19, 7.5 } }),
        .star => g.poly(&star_pts, true),
        .star_filled => {
            g.fill(&star_pts);
            g.poly(&star_pts, true);
        },
        .refresh => {
            g.arc(12, 12, 7.5, 1.5 * pi + 0.2, 0.25);
            g.line(&.{ .{ 14.2, 4.2 }, .{ 19.6, 4.6 }, .{ 19.2, 10 } });
        },
        .close => {
            g.line(&.{ .{ 6.5, 6.5 }, .{ 17.5, 17.5 } });
            g.line(&.{ .{ 17.5, 6.5 }, .{ 6.5, 17.5 } });
        },
        .arrow_down => {
            g.line(&.{ .{ 12, 5 }, .{ 12, 19 } });
            g.line(&.{ .{ 6.5, 13.5 }, .{ 12, 19 }, .{ 17.5, 13.5 } });
        },
        .arrow_up => {
            g.line(&.{ .{ 12, 19 }, .{ 12, 5 } });
            g.line(&.{ .{ 6.5, 10.5 }, .{ 12, 5 }, .{ 17.5, 10.5 } });
        },
        .arrow_right => {
            g.line(&.{ .{ 5, 12 }, .{ 19, 12 } });
            g.line(&.{ .{ 13.5, 6.5 }, .{ 19, 12 }, .{ 13.5, 17.5 } });
        },
        .arrow_left => {
            g.line(&.{ .{ 19, 12 }, .{ 5, 12 } });
            g.line(&.{ .{ 10.5, 6.5 }, .{ 5, 12 }, .{ 10.5, 17.5 } });
        },
        .bolt => g.poly(&.{ .{ 13, 3 }, .{ 5.5, 13.5 }, .{ 11.5, 13.5 }, .{ 10.5, 21 }, .{ 18.5, 10.5 }, .{ 12.5, 10.5 } }, true),
        .block => {
            g.circle(12, 12, 8.5);
            g.line(&.{ .{ 6, 6 }, .{ 18, 18 } });
        },
        .shield => g.poly(&.{ .{ 12, 3 }, .{ 19.5, 6 }, .{ 19.5, 12 }, .{ 17.6, 16.6 }, .{ 12, 21 }, .{ 6.4, 16.6 }, .{ 4.5, 12 }, .{ 4.5, 6 } }, true),
        .trash => {
            g.line(&.{ .{ 4.5, 7 }, .{ 19.5, 7 } });
            g.line(&.{ .{ 9.5, 7 }, .{ 9.5, 4 }, .{ 14.5, 4 }, .{ 14.5, 7 } });
            g.line(&.{ .{ 6.5, 7 }, .{ 7.5, 20 }, .{ 16.5, 20 }, .{ 17.5, 7 } });
        },
        .clipboard => {
            g.box(5.5, 5.5, 13, 15, 2);
            g.box(9, 3.5, 6, 4, 1.2);
        },
    }
}
