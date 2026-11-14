//! Small building blocks shared by all screens.

const std = @import("std");
const dvui = @import("dvui");
const th = @import("theme.zig");
const draw = @import("draw.zig");
const app = @import("../app.zig");

const Color = dvui.Color;
const Options = dvui.Options;
const Src = std.builtin.SourceLocation;

pub fn col(c: Color) dvui.ColorOrGradient {
    return .{ .color = c };
}

/// Plain text, no padding. Layout comes from `opts`.
pub fn text(src: Src, str: []const u8, font: dvui.Font, color: Color, opts: Options) void {
    const base: Options = .{ .font = font, .color_text = col(color), .padding = .all(0), .margin = .all(0), .gravity_y = 0.5 };
    dvui.labelNoFmt(src, str, .{}, base.override(opts));
}

pub fn gap(src: Src, w: f32, h: f32) void {
    _ = dvui.spacer(src, .{ .min_size_content = .{ .w = w, .h = h } });
}

/// `gap` for use inside loops, where the call site alone is not unique.
pub fn gapN(src: Src, n: usize, w: f32, h: f32) void {
    _ = dvui.spacer(src, .{ .id_extra = n, .min_size_content = .{ .w = w, .h = h } });
}

/// Reserve a box and return where it landed so the caller can paint into it.
pub fn canvas(src: Src, size: dvui.Size, opts: Options) dvui.RectScale {
    const base: Options = .{ .min_size_content = size, .gravity_y = 0.5 };
    var b = dvui.box(src, .{}, base.override(opts));
    const rs = b.data().contentRectScale();
    b.deinit();
    return rs;
}

pub fn icon(src: Src, which: draw.Icon, size: f32, color: Color, opts: Options) void {
    const rs = canvas(src, .all(size), opts);
    draw.icon(which, rs.r, color, @max(1.2, size / 12.0) * rs.s);
}

pub const IconButton = struct {
    size: f32 = 32,
    icon_size: f32 = 18,
    color: Color = th.text2,
    color_hover: Color = th.text,
    active: bool = false,
    tooltip: ?[]const u8 = null,
};

pub fn iconButton(src: Src, which: draw.Icon, o: IconButton, opts: Options) bool {
    var bw: dvui.ButtonWidget = undefined;
    const base: Options = .{
        .min_size_content = .all(o.size),
        .padding = .all(0),
        .margin = .all(0),
        .corners = .all(9),
        .background = true,
        .color_fill = col(if (o.active) th.raised else .transparent),
        .color_fill_hover = col(th.raised),
        .color_fill_press = col(th.hover),
        .gravity_y = 0.5,
        .label = if (o.tooltip) |t| .{ .text = t } else null,
    };
    bw.init(src, .{}, base.override(opts));
    bw.processEvents();
    bw.drawBackground();
    const rs = bw.data().contentRectScale();
    const s = o.icon_size * rs.s;
    const c = rs.r.center();
    const hot = o.active or bw.hovered();
    draw.icon(which, .{ .x = c.x - s / 2, .y = c.y - s / 2, .w = s, .h = s }, if (hot) o.color_hover else o.color, @max(1.2, o.icon_size / 12.0) * rs.s);
    bw.drawFocus();
    const clicked = bw.clicked();
    const active_rect = bw.data().borderRectScale().r;
    bw.deinit();
    if (o.tooltip) |t| {
        dvui.tooltip(src, .{ .active_rect = active_rect, .delay = 500_000 }, "{s}", .{t}, .{
            .id_extra = (opts.id_extra orelse 0) +% 7919,
            .font = th.body(12),
            .color_text = col(th.text),
            .color_fill = col(th.raised),
            .color_border = col(th.border),
            .border = .all(1),
            .corners = .all(7),
            .background = true,
        });
    }
    return clicked;
}

/// Light button with dark text: the one primary action on a surface.
pub fn primaryButton(src: Src, label: []const u8, opts: Options) bool {
    const base: Options = .{
        .font = th.medium(13),
        .color_fill = col(th.text),
        .color_fill_hover = col(.white),
        .color_fill_press = col(th.text2),
        .color_text = col(th.bg),
        .color_text_hover = col(th.bg),
        .color_text_press = col(th.bg),
        .padding = .{ .x = 16, .y = 9, .w = 16, .h = 9 },
        .margin = .all(0),
        .corners = .all(9),
    };
    return dvui.button(src, label, .{}, base.override(opts));
}

pub fn quietButton(src: Src, label: []const u8, opts: Options) bool {
    const base: Options = .{
        .font = th.medium(13),
        .color_fill = col(th.raised),
        .color_fill_hover = col(th.hover),
        .color_fill_press = col(th.border),
        .color_text = col(th.text),
        .color_text_hover = col(th.text),
        .color_text_press = col(th.text),
        .padding = .{ .x = 16, .y = 9, .w = 16, .h = 9 },
        .margin = .all(0),
        .corners = .all(9),
    };
    return dvui.button(src, label, .{}, base.override(opts));
}

pub fn toggle(src: Src, value: *bool, opts: Options) bool {
    var bw: dvui.ButtonWidget = undefined;
    const base: Options = .{
        .min_size_content = .{ .w = 38, .h = 22 },
        .padding = .all(0),
        .margin = .all(0),
        .background = false,
        .gravity_y = 0.5,
        .role = .check_box,
    };
    bw.init(src, .{}, base.override(opts));
    bw.processEvents();
    if (bw.clicked()) value.* = !value.*;
    const t = dvui.stateFade(bw.data().id, "on", value.*, 0.12);
    const rs = bw.data().contentRectScale();
    draw.rectFill(rs.r, rs.r.h / 2, th.border.lerp(th.text, t));
    const pad = 3 * rs.s;
    const kr = rs.r.h / 2 - pad;
    const x0 = rs.r.x + pad + kr;
    const x1 = rs.r.x + rs.r.w - pad - kr;
    draw.circleFill(.{ .x = x0 + (x1 - x0) * t, .y = rs.r.y + rs.r.h / 2 }, kr, th.text2.lerp(th.bg, t));
    bw.drawFocus();
    const clicked = bw.clicked();
    bw.deinit();
    return clicked;
}

/// Segmented control. Returns true when the selection changed.
pub fn segmented(src: Src, labels: []const []const u8, index: *usize, opts: Options) bool {
    const base: Options = .{
        .background = true,
        .color_fill = col(th.panel),
        .corners = .all(9),
        .padding = .all(3),
        .gravity_y = 0.5,
    };
    var hb = dvui.box(src, .{ .dir = .horizontal }, base.override(opts));
    defer hb.deinit();
    var changed = false;
    for (labels, 0..) |l, i| {
        const sel = index.* == i;
        if (dvui.button(@src(), l, .{ .draw_focus = false }, .{
            .id_extra = i,
            .font = th.medium(12),
            .color_fill = col(if (sel) th.hover else .transparent),
            .color_fill_hover = col(if (sel) th.hover else th.raised),
            .color_fill_press = col(th.hover),
            .color_text = col(if (sel) th.text else th.text2),
            .color_text_hover = col(th.text),
            .color_text_press = col(th.text),
            .padding = .{ .x = 12, .y = 6, .w = 12, .h = 6 },
            .margin = .all(0),
            .corners = .all(7),
        })) {
            if (!sel) {
                index.* = i;
                changed = true;
            }
        }
    }
    return changed;
}

/// Two-letter country code in a quiet tile; stands in for a flag.
pub fn countryTag(src: Src, code: [2]u8, opts: Options) void {
    const base: Options = .{
        .min_size_content = .{ .w = 30, .h = 22 },
        .background = true,
        .color_fill = col(th.raised),
        .corners = .all(6),
        .gravity_y = 0.5,
    };
    var b = dvui.box(src, .{}, base.override(opts));
    defer b.deinit();
    const known = code[0] != '?';
    text(@src(), if (known) &code else "··", th.mono(11), if (known) th.text else th.text3, .{ .gravity_x = 0.5 });
}

/// Rounded tile with the app's initial; stands in for the app icon.
pub fn monogram(src: Src, name: []const u8, size: f32, opts: Options) void {
    const base: Options = .{
        .min_size_content = .all(size),
        .background = true,
        .color_fill = col(th.raised),
        .corners = .all(size * 0.28),
        .gravity_y = 0.5,
    };
    var b = dvui.box(src, .{}, base.override(opts));
    defer b.deinit();
    const n = if (name.len == 0) 0 else std.unicode.utf8ByteSequenceLength(name[0]) catch 1;
    text(@src(), name[0..@min(n, name.len)], th.semibold(size * 0.42), th.text2, .{ .gravity_x = 0.5 });
}

/// A number with a dimmer unit after it, baseline-aligned in a row.
pub fn quantity(src: Src, value: []const u8, unit: []const u8, size: f32, opts: Options) void {
    const base: Options = .{ .gravity_y = 0.5 };
    var hb = dvui.box(src, .{ .dir = .horizontal }, base.override(opts));
    defer hb.deinit();
    text(@src(), value, th.mono(size), th.text, .{ .gravity_y = 1.0 });
    gap(@src(), @max(5, size * 0.3), 0);
    text(@src(), unit, th.body(@max(11, size * 0.6)), th.text3, .{ .gravity_y = 1.0, .padding = .{ .h = size * 0.08 } });
}

pub fn hairline(src: Src) void {
    const rs = canvas(src, .{ .w = 1, .h = 1 }, .{ .expand = .horizontal, .gravity_y = 0 });
    draw.rectFill(rs.r, 0, th.hairline);
}

pub fn pingColor(ms: ?u16) Color {
    const v = ms orelse return th.text3;
    return if (v < 80) th.ok else if (v < 180) th.warn else th.bad;
}

/// Screen title with the back arrow in the top-left corner.
pub fn heading(src: Src, str: []const u8) void {
    var hb = dvui.box(src, .{ .dir = .horizontal }, .{ .gravity_y = 0, .margin = .{ .x = -8 } });
    defer hb.deinit();
    if (iconButton(@src(), .arrow_left, .{ .size = 32, .icon_size = 18 }, .{})) app.back();
    gap(@src(), 8, 0);
    text(@src(), str, th.semibold(20), th.text, .{});
}

/// Small caps section label, used sparingly (settings only).
pub fn caption(src: Src, str: []const u8, opts: Options) void {
    text(src, str, th.medium(11), th.text3, opts);
}
