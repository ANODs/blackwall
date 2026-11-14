const std = @import("std");
const dvui = @import("dvui");
const core = @import("core");
const app = @import("../../app.zig");
const th = @import("../theme.zig");
const draw = @import("../draw.zig");
const w = @import("../widgets.zig");
const tr = @import("../../i18n.zig").t;

const model = core.model;

pub var show_add: bool = false;
var add_error: bool = false;

pub fn show() void {
    var root = dvui.box(@src(), .{}, .{ .expand = .both });
    defer root.deinit();

    {
        var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
        defer hb.deinit();
        w.heading(@src(), tr.nav_servers);
        _ = dvui.spacer(@src(), .{ .expand = .horizontal });
        if (app.fetching > 0 or app.probing) {
            dvui.spinner(@src(), .{ .min_size_content = .all(16), .gravity_y = 0.5, .color_text = w.col(th.text3) });
            w.gap(@src(), 8, 0);
        }
        if (w.iconButton(@src(), .refresh, .{ .tooltip = tr.refresh }, .{})) {
            var any_url = false;
            for (app.state.subs.items) |s| {
                if (s.url.len > 0) any_url = true;
            }
            if (any_url) app.fetchAll() else app.probeAll();
        }
        w.gap(@src(), 4, 0);
        if (w.iconButton(@src(), .plus, .{ .tooltip = tr.add_subscription }, .{})) {
            show_add = true;
            add_error = false;
        }
    }
    w.gap(@src(), 0, 14);

    {
        var scroll = dvui.scrollArea(@src(), .{}, .{ .expand = .both, .background = false });
        defer scroll.deinit();

        if (app.state.servers.items.len == 0 and app.state.subs.items.len == 0) {
            empty();
        } else {
            autoRow();
            var remove: ?u32 = null;
            for (app.state.subs.items, 0..) |sub, si| {
                w.gapN(@src(), si, 0, 14);
                if (subHeader(sub, si)) remove = sub.id;
                w.gapN(@src(), si, 0, 6);
                for (app.state.servers.items, 0..) |*sv, i| {
                    if (sv.sub_id == sub.id) serverRow(sv, i);
                }
            }
            if (remove) |id| {
                app.state.removeSubscription(id);
                app.markDirty();
            }
        }
    }

    if (show_add) addDialog();
}

fn empty() void {
    w.gap(@src(), 0, 80);
    w.icon(@src(), .globe, 30, th.border, .{ .gravity_x = 0.5, .gravity_y = 0 });
    w.gap(@src(), 0, 18);
    if (w.primaryButton(@src(), tr.add_subscription, .{ .gravity_x = 0.5 })) {
        show_add = true;
        add_error = false;
    }
}

fn subHeader(sub: model.Subscription, si: usize) bool {
    var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .id_extra = si, .expand = .horizontal, .padding = .{ .x = 10, .w = 4 } });
    defer hb.deinit();
    w.caption(@src(), sub.name, .{});
    if (sub.last_error) {
        w.gap(@src(), 8, 0);
        w.icon(@src(), .block, 12, th.bad, .{});
    }
    _ = dvui.spacer(@src(), .{ .expand = .horizontal });
    if (sub.total_bytes) |total| {
        const used = core.fmt.bytes(sub.used_bytes orelse 0);
        const tot = core.fmt.bytes(total);
        var buf: [48]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, "{s} / {s} {s}", .{ used.value(), tot.value(), tot.unit }) catch "";
        w.text(@src(), s, th.mono(11), th.text3, .{});
        w.gap(@src(), 10, 0);
        const rs = w.canvas(@src(), .{ .w = 56, .h = 3 }, .{});
        draw.rectFill(rs.r, rs.r.h / 2, th.border);
        var fill = rs.r;
        fill.w *= @min(1, @as(f32, @floatFromInt(sub.used_bytes orelse 0)) / @as(f32, @floatFromInt(@max(1, total))));
        draw.rectFill(fill, rs.r.h / 2, th.text2);
        w.gap(@src(), 6, 0);
    }
    if (app.state.demo) return false;
    return w.iconButton(@src(), .trash, .{ .size = 26, .icon_size = 14, .color = th.text3, .tooltip = tr.remove }, .{});
}

fn rowButton(bw: *dvui.ButtonWidget, src: std.builtin.SourceLocation, id_extra: usize, selected: bool) void {
    bw.init(src, .{}, .{
        .id_extra = id_extra,
        .expand = .horizontal,
        .padding = .{ .x = 10, .y = 9, .w = 12, .h = 9 },
        .margin = .all(0),
        .corners = .all(10),
        .background = true,
        .color_fill = w.col(if (selected) th.panel else .transparent),
        .color_fill_hover = w.col(if (selected) th.raised else th.panel),
        .color_fill_press = w.col(th.raised),
    });
    bw.processEvents();
    bw.drawBackground();
}

fn autoRow() void {
    const selected = app.state.settings.selected_server == null;
    var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
    defer hb.deinit();
    var bw: dvui.ButtonWidget = undefined;
    rowButton(&bw, @src(), 0, selected);
    if (bw.clicked() and !selected) app.selectServer(null);
    {
        var row = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
        defer row.deinit();
        {
            var tile = dvui.box(@src(), .{}, .{ .min_size_content = .{ .w = 30, .h = 22 }, .background = true, .color_fill = w.col(th.raised), .corners = .all(6), .gravity_y = 0.5 });
            defer tile.deinit();
            w.icon(@src(), .bolt, 13, th.text, .{ .gravity_x = 0.5 });
        }
        w.gap(@src(), 12, 0);
        w.text(@src(), tr.fastest, th.medium(13.5), th.text, .{ .expand = .horizontal });
        if (selected) w.icon(@src(), .check, 15, th.text, .{});
    }
    bw.drawFocus();
    bw.deinit();
    w.gap(@src(), 36, 0);
}

fn serverRow(sv: *model.Server, i: usize) void {
    const selected = app.state.settings.selected_server == sv.id;
    var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .id_extra = i, .expand = .horizontal });
    defer hb.deinit();

    var bw: dvui.ButtonWidget = undefined;
    rowButton(&bw, @src(), i, selected);
    if (bw.clicked() and sv.available) app.selectServer(sv.id);
    {
        var row = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
        defer row.deinit();
        w.countryTag(@src(), sv.country, .{});
        w.gap(@src(), 12, 0);
        w.text(@src(), sv.name, th.medium(13.5), if (sv.available) th.text else th.text3, .{});
        w.gap(@src(), 10, 0);
        w.text(@src(), sv.protocol.label(), th.mono(10.5), th.text3, .{ .expand = .horizontal });

        if (!sv.available) {
            w.icon(@src(), .block, 13, th.text3, .{});
        } else switch (sv.ping_state) {
            .ok => {
                const rs = w.canvas(@src(), .all(6), .{});
                draw.circleFill(rs.r.center(), rs.r.w / 2, w.pingColor(sv.ping_ms));
                var cell = dvui.box(@src(), .{ .dir = .horizontal }, .{ .min_size_content = .{ .w = 50 }, .gravity_y = 0.5 });
                defer cell.deinit();
                _ = dvui.spacer(@src(), .{ .expand = .horizontal });
                var buf: [8]u8 = undefined;
                w.text(@src(), std.fmt.bufPrint(&buf, "{d}", .{sv.ping_ms orelse 0}) catch "", th.mono(12), th.text, .{});
                w.gap(@src(), 4, 0);
                w.text(@src(), "ms", th.body(11), th.text3, .{});
            },
            .failed => w.text(@src(), "—", th.mono(12), th.bad, .{}),
            .testing => w.text(@src(), "···", th.mono(12), th.text3, .{}),
            .unknown => {},
        }
        w.gap(@src(), 12, 0);
        const rs = w.canvas(@src(), .all(15), .{});
        if (selected) draw.icon(.check, rs.r, th.text, 1.5 * rs.s);
    }
    bw.drawFocus();
    bw.deinit();

    w.gap(@src(), 4, 0);
    if (w.iconButton(@src(), if (sv.favorite) .star_filled else .star, .{
        .size = 32,
        .icon_size = 15,
        .color = if (sv.favorite) th.text else th.border,
    }, .{ .id_extra = i })) {
        sv.favorite = !sv.favorite;
        if (!app.state.demo) app.markDirty();
    }
}

fn addDialog() void {
    var fw = dvui.floatingWindow(@src(), .{ .modal = true, .modal_alpha = 150, .open_flag = &show_add, .resize = .none }, .{
        .min_size_content = .{ .w = 420 },
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
        w.text(@src(), tr.subscription, th.semibold(16), th.text, .{ .expand = .horizontal });
        if (w.iconButton(@src(), .close, .{ .size = 28, .icon_size = 14 }, .{})) show_add = false;
    }
    w.gap(@src(), 0, 16);

    var te = dvui.textEntry(@src(), .{
        .placeholder = tr.link_or_keys,
        .text = .{ .internal = .{ .limit = 256 * 1024 } },
    }, .{
        .expand = .horizontal,
        .font = th.code(12),
        .color_fill = w.col(th.bg),
        .color_border = w.col(if (add_error) th.bad else th.border),
        .color_text = w.col(th.text),
        .corners = .all(9),
        .margin = .all(0),
        .padding = .{ .x = 12, .y = 11, .w = 12, .h = 11 },
    });
    if (dvui.firstFrame(te.data().id)) dvui.focusWidget(te.data().id, null, null);
    if (te.text_changed) add_error = false;
    var submit = te.enter_pressed;
    // the internal buffer outlives the widget for the rest of the frame
    const typed = te.getText();
    te.deinit();

    w.gap(@src(), 0, 18);
    {
        var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .gravity_x = 1.0 });
        defer hb.deinit();
        if (w.quietButton(@src(), tr.cancel, .{})) show_add = false;
        w.gap(@src(), 8, 0);
        if (w.primaryButton(@src(), tr.add, .{})) submit = true;
    }

    if (submit) {
        if (app.addFromText(typed)) |_| {
            show_add = false;
        } else |_| {
            add_error = true;
        }
    }
}
