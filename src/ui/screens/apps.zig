const std = @import("std");
const dvui = @import("dvui");
const core = @import("core");
const app = @import("../../app.zig");
const th = @import("../theme.zig");
const draw = @import("../draw.zig");
const w = @import("../widgets.zig");
const tr = @import("../../i18n.zig").t;

const model = core.model;

var filter: usize = 0;
var query_buf: [64]u8 = @splat(0);
var first_shown: usize = 0;

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
        search();
    }
    w.gap(@src(), 0, 16);

    const query = std.mem.sliceTo(&query_buf, 0);

    var scroll = dvui.scrollArea(@src(), .{}, .{ .expand = .both, .background = false });
    defer scroll.deinit();

    var shown: usize = 0;
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
    routePicker(a, i);
}

fn routePicker(a: *model.App, i: usize) void {
    var m = dvui.menu(@src(), .horizontal, .{ .id_extra = i, .gravity_y = 0.5 });
    defer m.deinit();

    var mi = dvui.menuItem(@src(), .{ .submenu = true }, .{
        .id_extra = i,
        .tag = if (i == first_shown) "route-first" else null,
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
        routeLabel(a.route, true);
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
            if (choice(a, route, k)) m.close();
        }
        w.gap(@src(), 0, 4);
        w.hairline(@src());
        w.gap(@src(), 0, 4);
        for (app.state.servers.items, 0..) |sv, k| {
            if (!sv.available) continue;
            if (choice(a, .{ .server = sv.id }, 100 + k)) m.close();
        }
    }
}

fn choice(a: *model.App, route: model.Route, k: usize) bool {
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
        if (a.route.eql(route)) w.icon(@src(), .check, 14, th.text, .{});
    }
    if (mi.activeRect() != null) {
        app.setRoute(a, route);
        return true;
    }
    return false;
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
        w.countryTag(@src(), sv.country, .{ .min_size_content = .{ .w = 26, .h = 18 } });
        w.gap(@src(), 9, 0);
        w.text(@src(), sv.name, th.body(13), if (sv.available) th.text else th.text3, .{});
    } else {
        w.text(@src(), "—", th.body(13), th.text3, .{});
    }
}
