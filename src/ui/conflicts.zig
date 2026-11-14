//! The compact list of what stands in the way of the connection (product
//! concept 7.1): one row per program, the reason, and the actions. Opened
//! from the notice's "Fix" button only.

const std = @import("std");
const dvui = @import("dvui");
const app = @import("../app.zig");
const th = @import("theme.zig");
const w = @import("widgets.zig");
const tr = @import("../i18n.zig").t;

var selected: usize = 0;

pub fn show() void {
    if (!app.show_conflicts) return;
    if (app.conflicts.len == 0) {
        app.show_conflicts = false;
        return;
    }
    if (selected >= app.conflicts.len) selected = 0;

    var fw = dvui.floatingWindow(@src(), .{ .modal = true, .modal_alpha = 150, .open_flag = &app.show_conflicts, .resize = .none }, .{
        .min_size_content = .{ .w = 440 },
        .color_fill = w.col(th.panel),
        .color_border = w.col(th.border),
        .border = .all(1),
        .corners = .all(14),
        .padding = .all(22),
        .color_text = w.col(.black),
    });
    defer fw.deinit();
    var body = dvui.box(@src(), .{}, .{ .expand = .both });
    defer body.deinit();

    {
        var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
        defer hb.deinit();
        w.text(@src(), tr.conflict_title, th.semibold(16), th.text, .{ .expand = .horizontal });
        if (w.iconButton(@src(), .close, .{ .size = 28, .icon_size = 14 }, .{})) app.show_conflicts = false;
    }
    w.gap(@src(), 0, 14);

    for (app.conflicts, 0..) |*cf, i| row(cf, i);

    w.gap(@src(), 0, 18);
    const cf = &app.conflicts[selected];
    var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .gravity_x = 1.0 });
    defer hb.deinit();
    if (app.conflict_busy) {
        w.text(@src(), "…", th.body(13), th.text2, .{ .gravity_y = 0.5 });
        return;
    }
    if (app.conflict_failed) {
        // the polite way did not free the network: the app's own switch,
        // or (not for a system VPN service, which would just restart) force
        if (cf.bundle().len > 0) {
            var buf: [96]u8 = undefined;
            if (w.quietButton(@src(), std.fmt.bufPrint(&buf, tr.open_app, .{cf.name()}) catch cf.name(), .{})) app.openConflictApp(selected);
            w.gap(@src(), 8, 0);
        }
        if (cf.service().len == 0 and cf.owner != null) {
            if (w.quietButton(@src(), tr.force_quit, .{ .id_extra = 1 })) app.stopConflict(selected, true);
            w.gap(@src(), 8, 0);
        }
    }
    if (cf.owner != null or cf.service().len > 0) {
        if (w.primaryButton(@src(), tr.stop_reconnect, .{})) app.stopConflict(selected, false);
    }
}

fn row(cf: *const app.Conflict, i: usize) void {
    const chosen = i == selected;
    var b = dvui.box(@src(), .{ .dir = .horizontal }, .{
        .id_extra = i,
        .expand = .horizontal,
        .padding = .{ .x = 12, .y = 10, .w = 12, .h = 10 },
        .margin = .{ .h = 6 },
        .background = true,
        .color_fill = w.col(if (chosen) th.raised else th.panel),
        .color_border = w.col(if (chosen) th.border else th.panel),
        .border = .all(1),
        .corners = .all(10),
    });
    defer b.deinit();
    if (dvui.clicked(b.data(), .{})) selected = i;

    // initial as a badge
    {
        var badge = dvui.box(@src(), .{}, .{
            .min_size_content = .{ .w = 30, .h = 30 },
            .background = true,
            .color_fill = w.col(th.bg),
            .corners = .all(8),
            .gravity_y = 0.5,
        });
        defer badge.deinit();
        const n = cf.name();
        const first = if (n.len > 0) n[0..std.unicode.utf8ByteSequenceLength(n[0]) catch 1] else "?";
        w.text(@src(), first, th.semibold(13), th.text, .{ .gravity_x = 0.5, .gravity_y = 0.5 });
    }
    w.gap(@src(), 12, 0);
    var col = dvui.box(@src(), .{}, .{ .expand = .horizontal, .gravity_y = 0.5 });
    defer col.deinit();
    w.text(@src(), cf.name(), th.medium(13.5), th.text, .{});
    var buf: [128]u8 = undefined;
    const reason = if (cf.kind == .dpi) tr.conflict_reason_dpi else std.fmt.bufPrint(&buf, tr.conflict_reason, .{cf.ifname()}) catch cf.ifname();
    var line_buf: [192]u8 = undefined;
    const line = if (cf.confirmed) reason else std.fmt.bufPrint(&line_buf, "{s} · {s}", .{ reason, tr.presumed }) catch reason;
    w.text(@src(), line, th.body(12), th.text3, .{});
}
