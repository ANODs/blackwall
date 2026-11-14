//! Visual language: near-black surfaces, one light accent, no decoration.

const dvui = @import("dvui");
const Color = dvui.Color;
const Font = dvui.Font;

fn rgb(comptime hex: u24) Color {
    return .{ .r = @intCast(hex >> 16), .g = @intCast((hex >> 8) & 0xff), .b = @intCast(hex & 0xff) };
}

pub const bg = rgb(0x0B0B0D);
pub const panel = rgb(0x151518);
pub const raised = rgb(0x1C1C20);
pub const hover = rgb(0x222227);
pub const hairline = rgb(0x1F1F23);
pub const border = rgb(0x303036);
pub const text = rgb(0xF2F2F3);
pub const text2 = rgb(0xA6A6AF);
pub const text3 = rgb(0x6A6A73);
pub const ok = rgb(0x4CC38A);
pub const warn = rgb(0xD9A441);
pub const bad = rgb(0xE5604F);

/// DVUI sizes fonts by cap height; Geist caps are ~0.71 em.
fn px(font_px: f32) f32 {
    return font_px * 0.71;
}

/// The zh build draws every UI face with one embedded CJK font, registered once
/// (DVUI keeps only the first source with the same bytes) and in one weight to
/// stay light: medium is the same face, bold is synthesized by DVUI. Untaken
/// comptime branches are not analyzed, so en/ru never embed the CJK font.
const cjk = @import("../i18n.zig").cjk;

pub const sans = "Geist";
pub const sans_medium = if (cjk) sans else "Geist Medium";
pub const mono_family = "Geist Mono";

pub fn body(size_px: f32) Font {
    return .find(.{ .family = sans, .size = px(size_px) });
}
pub fn medium(size_px: f32) Font {
    return .find(.{ .family = sans_medium, .size = px(size_px) });
}
pub fn semibold(size_px: f32) Font {
    return .find(.{ .family = sans, .size = px(size_px), .weight = .bold });
}
pub fn mono(size_px: f32) Font {
    return .find(.{ .family = mono_family, .size = px(size_px) });
}
/// Mono for text that may be translated: Geist Mono has no CJK glyphs, so the
/// zh build falls back to the UI face.
pub fn code(size_px: f32) Font {
    return if (cjk) body(size_px) else mono(size_px);
}

const mono_fonts: []const Font.Source = &.{
    .{ .family = Font.array(mono_family), .bytes = @embedFile("font_mono") },
    .{ .family = Font.array(mono_family), .weight = .bold, .bytes = @embedFile("font_mono") },
};

const fonts: []const Font.Source = if (cjk) &[_]Font.Source{
    .{ .family = Font.array(sans), .bytes = @embedFile("font_cjk") },
} ++ mono_fonts else &[_]Font.Source{
    .{ .family = Font.array(sans), .bytes = @embedFile("font_regular") },
    .{ .family = Font.array(sans), .weight = .bold, .bytes = @embedFile("font_semibold") },
    .{ .family = Font.array(sans_medium), .bytes = @embedFile("font_medium") },
    .{ .family = Font.array(sans_medium), .weight = .bold, .bytes = @embedFile("font_semibold") },
} ++ mono_fonts;

pub const theme: dvui.Theme = .{
    .name = "Mono Dark",
    .dark = true,
    .embedded_fonts = fonts,
    .font_body = .find(.{ .family = sans, .size = px(13) }),
    .font_heading = .find(.{ .family = sans, .size = px(13), .weight = .bold }),
    .font_title = .find(.{ .family = sans, .size = px(20), .weight = .bold }),
    .font_mono = .find(.{ .family = mono_family, .size = px(12) }),
    .corner = .round(8),

    .focus = rgb(0x5C5C68),
    .text_select = rgb(0x3A3A44),

    .fill = panel,
    .fill_hover = raised,
    .fill_press = hover,
    .text = text,
    .border = border,

    .window = .{ .fill = bg },
    .control = .{ .fill = raised, .fill_hover = hover, .fill_press = border, .text = text },
    .highlight = .{ .fill = hover, .fill_hover = hover, .fill_press = border, .text = text, .border = border },
    .err = .{ .fill = bad, .text = text, .border = bad },
};
