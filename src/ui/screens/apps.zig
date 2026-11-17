const std = @import("std");
const dvui = @import("dvui");
const core = @import("core");
const app = @import("../../app.zig");
const th = @import("../theme.zig");
const draw = @import("../draw.zig");
const w = @import("../widgets.zig");
const tr = @import("../../i18n.zig").t;

const model = core.model;

pub var filter: usize = 0;
var query_buf: [64]u8 = @splat(0);
var first_shown: usize = 0;
/// the row where a new site is typed is open
pub var adding = false;
var site_buf: [254]u8 = @splat(0);

pub fn show() void {
    var root = dvui.box(@src(), .{}, .{ .expand = .both });
    defer root.deinit();

    {
        var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
        defer hb.deinit();
        w.heading(@src(), tr.nav_apps);
        _ = dvui.spacer(@src(), .{ .expand = .horizontal });
        _ = w.segmented(@src(), &.{ tr.filter_online, tr.filter_all, tr.filter_rules }, &filter, .{});
        w.gap(@src(), 10, 0);
        if (w.iconButton(@src(), .plus, .{ .tooltip = tr.add_site, .active = adding }, .{})) {
            adding = !adding;
            site_buf = @splat(0);
            // sites are rules: the list that shows them
            if (adding and filter == 0) filter = 2;
        }
        w.gap(@src(), 6, 0);
        search();
    }
    w.gap(@src(), 0, 16);

    const query = std.mem.sliceTo(&query_buf, 0);

    var scroll = dvui.scrollArea(@src(), .{}, .{ .expand = .both, .background = false });
    defer scroll.deinit();

    var shown: usize = 0;
    if (adding) newSite();
    // sites first: there are few, and they are rules
    if (filter != 0) {
        var k: usize = 0;
        while (k < app.state.domains.items.len) : (k += 1) {
            const d = &app.state.domains.items[k];
            if (query.len > 0 and !containsIgnoreCase(d.name, query)) continue;
            if (siteRow(d, k)) break; // removed: the list changed
            shown += 1;
        }
    }
    for (app.state.apps.items, 0..) |*a, i| {
        const pass = switch (filter) {
            0 => a.online,
            2 => a.route != .default,
            else => true,
        };
        if (!pass) continue;
        if (query.len > 0 and !containsIgnoreCase(a.name, query)) continue;
        if (shown == 0) first_shown = i;
        row(a, i);
        shown += 1;
    }
    if (shown == 0) {
        w.gap(@src(), 0, 60);
        w.icon(@src(), .apps, 28, th.border, .{ .gravity_x = 0.5, .gravity_y = 0 });
    }
}

fn search() void {
    var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{
        .background = true,
        .color_fill = w.col(th.panel),
        .corners = .all(9),
        .padding = .{ .x = 10, .w = 4 },
        .gravity_y = 0.5,
    });
    defer hb.deinit();
    w.icon(@src(), .search, 14, th.text3, .{});
    var te = dvui.textEntry(@src(), .{ .text = .{ .buffer = &query_buf }, .placeholder = tr.search }, .{
        .min_size_content = .{ .w = 130, .h = 16 },
        .max_size_content = .width(130),
        .font = th.body(13),
        .background = false,
        .border = .all(0),
        .margin = .all(0),
        .padding = .{ .x = 8, .y = 7, .w = 6, .h = 7 },
        .color_text = w.col(th.text),
    });
    te.deinit();
}

fn containsIgnoreCase(hay: []const u8, needle: []const u8) bool {
    if (needle.len > hay.len) return false;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(hay[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn row(a: *model.App, i: usize) void {
    var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{
        .id_extra = i,
        .expand = .horizontal,
        .padding = .{ .x = 4, .y = 7, .w = 4, .h = 7 },
    });
    defer hb.deinit();

    w.monogram(@src(), a.name, 32, .{});
    w.gap(@src(), 14, 0);
    w.text(@src(), a.name, th.medium(13.5), th.text, .{ .expand = .horizontal });

    if (a.down_bps + a.up_bps > 1) {
        const q = core.fmt.rate(a.down_bps + a.up_bps);
        w.text(@src(), q.value(), th.mono(12), th.text2, .{});
        w.gap(@src(), 4, 0);
        w.text(@src(), q.unit, th.body(11), th.text3, .{});
        w.gap(@src(), 18, 0);
    }
    if (routePicker(a.route, i, i == first_shown)) |r| app.setRoute(a, r);
}

/// The row a site is typed into: Enter adds it, Escape or an empty field
/// closes the row.
fn newSite() void {
    var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{
        .expand = .horizontal,
        .padding = .{ .x = 4, .y = 7, .w = 4, .h = 7 },
    });
    defer hb.deinit();
    siteMark(0);
    w.gap(@src(), 14, 0);
    var te = dvui.textEntry(@src(), .{ .text = .{ .buffer = &site_buf }, .placeholder = "example.com" }, .{
        .expand = .horizontal,
        .font = th.body(13.5),
        .corners = .all(9),
        .padding = .{ .x = 10, .y = 7, .w = 10, .h = 7 },
        .color_fill = w.col(th.panel),
        .color_text = w.col(th.text),
        .gravity_y = 0.5,
    });
    if (dvui.firstFrame(te.data().id)) dvui.focusWidget(te.data().id, null, null);
    const entered = te.enter_pressed;
    te.deinit();
    for (dvui.events()) |*e| {
        if (e.evt == .key and e.evt.key.code == .escape and e.evt.key.action == .down) adding = false;
    }
    if (entered) {
        const text = std.mem.sliceTo(&site_buf, 0);
        if (text.len == 0 or app.addDomain(text)) {
            adding = false;
            site_buf = @splat(0);
        }
    }
}

/// A site's mark where an application has its monogram.
fn siteMark(k: usize) void {
    var b = dvui.box(@src(), .{}, .{
        .id_extra = k,
        .min_size_content = .all(32),
        .background = true,
        .color_fill = w.col(th.raised),
        .corners = .all(9),
        .gravity_y = 0.5,
    });
    defer b.deinit();
    w.icon(@src(), .globe, 16, th.text2, .{ .gravity_x = 0.5, .gravity_y = 0.5 });
}

/// True when the site was removed.
fn siteRow(d: *model.Domain, k: usize) bool {
    var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{
        .id_extra = 10_000 + k,
        .expand = .horizontal,
        .padding = .{ .x = 4, .y = 7, .w = 4, .h = 7 },
    });
    defer hb.deinit();
    siteMark(k);
    w.gap(@src(), 14, 0);
    w.text(@src(), d.name, th.medium(13.5), th.text, .{ .expand = .horizontal });
    if (w.iconButton(@src(), .close, .{ .size = 26, .icon_size = 12, .color = th.text3, .tooltip = tr.remove }, .{})) {
        app.removeDomain(k);
        return true;
    }
    w.gap(@src(), 8, 0);
    if (routePicker(d.route, 10_000 + k, false)) |r| app.setDomainRoute(d, r);
    return false;
}

/// The route menu of a row; the route picked, if one was.
fn routePicker(current: model.Route, i: usize, first: bool) ?model.Route {
    var picked: ?model.Route = null;
    var m = dvui.menu(@src(), .horizontal, .{ .id_extra = i, .gravity_y = 0.5 });
    defer m.deinit();

    var mi = dvui.menuItem(@src(), .{ .submenu = true }, .{
        .id_extra = i,
        .tag = if (first) "route-first" else null,
        .min_size_content = .{ .w = 168, .h = 22 },
        .padding = .{ .x = 10, .y = 6, .w = 8, .h = 6 },
        .corners = .all(9),
        .background = true,
        .color_fill = w.col(th.panel),
        .color_border = w.col(th.hairline),
    });
    {
        var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .both });
        defer hb.deinit();
        routeLabel(current, true);
        _ = dvui.spacer(@src(), .{ .expand = .horizontal });
        w.icon(@src(), .chevron_down, 13, th.text3, .{});
    }
    const active = mi.activeRect();
    mi.deinit();

    if (active) |r| {
        var fm = dvui.floatingMenu(@src(), .{ .from = r }, .{
            .id_extra = i,
            .color_fill = w.col(th.raised),
            .color_border = w.col(th.border),
            .corners = .all(11),
            .padding = .all(5),
            .min_size_content = .{ .w = 200 },
            .max_size_content = .height(320),
        });
        defer fm.deinit();

        const fixed = [_]model.Route{ .default, .auto, .direct, .dpi, .block };
        for (fixed, 0..) |route, k| {
            if (choice(current, route, k)) {
                picked = route;
                m.close();
            }
        }
        w.gap(@src(), 0, 4);
        w.hairline(@src());
        w.gap(@src(), 0, 4);
        for (app.state.servers.items, 0..) |sv, k| {
            if (!sv.available) continue;
            if (choice(current, .{ .server = sv.id }, 100 + k)) {
                picked = .{ .server = sv.id };
                m.close();
            }
        }
    }
    return picked;
}

fn choice(current: model.Route, route: model.Route, k: usize) bool {
    var mi = dvui.menuItem(@src(), .{}, .{
        .id_extra = k,
        .expand = .horizontal,
        .padding = .{ .x = 9, .y = 7, .w = 9, .h = 7 },
        .corners = .all(8),
        .color_fill_hover = w.col(th.hover),
    });
    defer mi.deinit();
    {
        var hb = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
        defer hb.deinit();
        routeLabel(route, false);
        _ = dvui.spacer(@src(), .{ .expand = .horizontal, .min_size_content = .{ .w = 16 } });
        if (current.eql(route)) w.icon(@src(), .check, 14, th.text, .{});
    }
    return mi.activeRect() != null;
}

pub fn routeLabel(route: model.Route, dim_default: bool) void {
    const Simple = struct { draw.Icon, []const u8 };
    const simple: ?Simple = switch (route) {
        .default => .{ .chevron_right, tr.route_default },
        .auto => .{ .globe, tr.route_auto },
        .direct => .{ .arrow_right, tr.route_direct },
        .dpi => .{ .bolt, tr.route_dpi },
        .block => .{ .block, tr.route_block },
        .server => null,
    };
    if (simple) |s| {
        const dim = dim_default and route == .default;
        if (route != .default) {
            w.icon(@src(), s[0], 14, th.text2, .{});
            w.gap(@src(), 9, 0);
        }
        w.text(@src(), s[1], th.body(13), if (dim) th.text3 else th.text, .{});
        return;
    }
    if (app.state.serverById(route.server)) |sv| {
        w.serverTag(@src(), sv, .{ .min_size_content = .{ .w = 26, .h = 18 } });
        w.gap(@src(), 9, 0);
        w.text(@src(), sv.name, th.body(13), if (sv.available) th.text else th.text3, .{});
    } else {
        w.text(@src(), "—", th.body(13), th.text3, .{});
    }
}
