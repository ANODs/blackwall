//! The app's configuration (servers, per-application routes, default route)
//! turned into the data plane's routing table.

const std = @import("std");
const core = @import("core");
const model = core.model;
const tunnel = core.tunnel;
const proxy = core.proxy;

pub const Built = struct {
    arena: std.heap.ArenaAllocator,
    cfg: tunnel.Config,
    /// servers whose links this build cannot carry yet
    skipped: usize,
    /// server id of each outbound
    ids: []const u32 = &.{},
    /// which of its group's servers each outbound is (0 for a plain server)
    members: []const u16 = &.{},

    pub fn deinit(b: *Built) void {
        b.arena.deinit();
    }
};

pub fn build(gpa: std.mem.Allocator, state: *const model.State) !Built {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    var obs: std.ArrayList(proxy.Outbound) = .empty;
    // per outbound: its server's id, and its last measured connection time
    var ids: std.ArrayList(u32) = .empty;
    var members_of: std.ArrayList(u16) = .empty;
    var pings: std.ArrayList(?u16) = .empty;
    var skipped: usize = 0;
    // standby: the VPN is off, so no server is used at all
    const standby = state.settings.standby;
    for (state.servers.items) |sv| {
        if (standby) break;
        // a server in use that left its subscription stays until Disconnect
        const in_use = sv.id == state.settings.selected_server or sv.id == state.settings.auto_server;
        if (!(sv.available or in_use) or sv.link.len == 0) continue;
        if (sv.members.len == 0) {
            const ob = proxy.outboundFromLink(try a.dupe(u8, sv.link), try a.dupe(u8, sv.host), sv.port) catch {
                skipped += 1;
                continue;
            };
            try obs.append(a, ob);
            try ids.append(a, sv.id);
            try members_of.append(a, 0);
            try pings.append(a, sv.ping_ms);
            continue;
        }
        // a group: each of its servers is an outbound of the group's id
        var any = false;
        for (sv.members, 0..) |m, k| {
            const ob = proxy.outboundFromLink(try a.dupe(u8, m.link), try a.dupe(u8, m.host), m.port) catch continue;
            try obs.append(a, ob);
            try ids.append(a, sv.id);
            try members_of.append(a, @intCast(@min(k, std.math.maxInt(u16))));
            try pings.append(a, m.ping_ms);
            any = true;
        }
        if (!any) skipped += 1;
    }

    // The main server, then its reserve. A group is its own reserve: its
    // servers, fastest first. Then the starred servers in list order (a
    // starred group with all its servers), when the reserve is on.
    var main: std.ArrayList(u16) = .empty;
    if (currentId(state, ids.items)) |cur| {
        try appendServer(a, &main, ids.items, pings.items, cur);
        if (state.settings.failover) for (state.servers.items) |sv| {
            if (sv.favorite and sv.id != cur) try appendServer(a, &main, ids.items, pings.items, sv.id);
        };
    }
    const has_main = main.items.len > 0;
    var rules: std.ArrayList(tunnel.Rule) = .empty;
    for (state.apps.items) |app| {
        if (app.route == .default) continue;
        try rules.append(a, .{ .app = try a.dupe(u8, app.id), .choice = choiceOf(app.route, ids.items, pings.items, has_main) });
    }
    var domains: std.ArrayList(tunnel.DomainRule) = .empty;
    for (state.domains.items) |d| {
        if (d.route == .default) continue;
        try domains.append(a, .{ .suffix = try a.dupe(u8, d.name), .choice = choiceOf(d.route, ids.items, pings.items, has_main) });
    }
    const default: tunnel.Choice = if (standby)
        // only the applications with a rule are held back
        .direct
    else switch (state.settings.default_route) {
        .default => if (has_main) .main else .block,
        else => |r| choiceOf(r, ids.items, pings.items, has_main),
    };
    var cfg: tunnel.Config = .{ .default = default, .rules = rules.items, .domains = domains.items, .outbounds = obs.items, .main = main.items, .check_exit = state.settings.check_exit };
    // in standby everything without a rule goes direct, so a flow that
    // cannot be attributed might be one of the held applications': refuse it
    if (standby) cfg.unknown = .block;
    // IPv6 "block": refused inside the tunnel too, not only by the kill switch
    if (@hasField(tunnel.Config, "block_ipv6")) cfg.block_ipv6 = state.settings.ipv6 == .block;
    // "DNS through the route" off: real answers instead of fake addresses
    if (@hasField(tunnel.Config, "fake_dns")) cfg.fake_dns = state.settings.dns_over_route;
    return .{ .arena = arena, .cfg = cfg, .skipped = skipped, .ids = ids.items, .members = members_of.items };
}

/// What the main route uses right now: the server (0 when there is none),
/// which of a group's servers, and where it exits ("??" not known yet).
pub const InUse = struct { server: u32 = 0, member: u16 = 0, exit: [2]u8 = "??".* };

pub fn inUse(b: *const Built, t: *tunnel.Tunnel) InUse {
    const u = t.mainExit();
    if (u.index >= b.cfg.main.len) return .{};
    const i = b.cfg.main[u.index];
    return .{ .server = b.ids[i], .member = b.members[i], .exit = u.exit };
}

/// Whether the default route or any rule may send traffic to outbound `i`
/// (the main server's reserve included).
pub fn uses(cfg: tunnel.Config, i: u16) bool {
    if (cfg.default == .outbound and cfg.default.outbound == i) return true;
    var main = cfg.default == .main;
    for (cfg.rules) |r| {
        if (r.choice == .outbound and r.choice.outbound == i) return true;
        main = main or r.choice == .main;
    }
    for (cfg.domains) |d| {
        if (d.choice == .outbound and d.choice.outbound == i) return true;
        main = main or d.choice == .main;
    }
    return main and std.mem.indexOfScalar(u16, cfg.main, i) != null;
}

/// The server the default route uses: the selected one, else the one the
/// window found fastest, if usable; otherwise the first usable one.
fn currentId(state: *const model.State, ids: []const u32) ?u32 {
    if (state.settings.selected_server orelse state.settings.auto_server) |want| {
        if (std.mem.indexOfScalar(u32, ids, want) != null) return want;
    }
    return if (ids.len > 0) ids[0] else null;
}

/// The outbounds of server `id` added to the group, measured ones fastest
/// first, as many as the group holds.
fn appendServer(a: std.mem.Allocator, main: *std.ArrayList(u16), ids: []const u32, pings: []const ?u16, id: u32) !void {
    const start = main.items.len;
    for (ids, 0..) |sid, i| {
        if (sid != id or main.items.len == core.failover.max_members) continue;
        if (std.mem.indexOfScalar(u16, main.items, @intCast(i)) != null) continue;
        try main.append(a, @intCast(i));
    }
    const Ctx = struct {
        pings: []const ?u16,
        fn less(ctx: @This(), x: u16, y: u16) bool {
            const px = ctx.pings[x] orelse return false;
            const py = ctx.pings[y] orelse return true;
            return px < py;
        }
    };
    std.sort.insertion(u16, main.items[start..], Ctx{ .pings = pings }, Ctx.less);
}

/// A route that names a server we cannot reach blocks instead of leaking.
/// In standby no server is reachable, so every VPN route blocks. A group
/// named by a rule is its fastest server.
fn choiceOf(route: model.Route, ids: []const u32, pings: []const ?u16, has_main: bool) tunnel.Choice {
    return switch (route) {
        .direct => .direct,
        .dpi => .dpi,
        .block => .block,
        .default, .auto => if (has_main) .main else .block,
        .server => |id| blk: {
            var best: ?usize = null;
            for (ids, 0..) |sid, i| {
                if (sid != id) continue;
                if (best == null) best = i;
                const p = pings[i] orelse continue;
                if (pings[best.?] == null or p < pings[best.?].?) best = i;
            }
            break :blk if (best) |i| .{ .outbound = @intCast(i) } else .block;
        },
    };
}

test "routes: rules, default, unusable servers block" {
    const gpa = std.testing.allocator;
    var s: model.State = .init(gpa);
    defer s.deinit();
    const sub = try s.addSubscription("t", "");
    const ok = try s.addServer(sub.id, .{
        .name = "NL",
        .host = "nl.example",
        .port = 443,
        .protocol = .vless,
        .link = "vless://11111111-2222-3333-4444-555555555555@nl.example:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.microsoft.com&pbk=jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8&sid=ab12#NL",
    });
    const ok_id = ok.id;
    const ws = try s.addServer(sub.id, .{ .name = "US", .host = "us.example", .port = 443, .protocol = .vless, .link = "vless://11111111-2222-3333-4444-555555555555@us.example:443?type=xhttp&security=reality#US" });
    const ws_id = ws.id;
    (try s.addApp("/Applications/Steam.app", "Steam", "")).route = .direct;
    (try s.addApp("/Applications/Telegram.app", "Telegram", "")).route = .{ .server = ok_id };
    (try s.addApp("/Applications/Discord.app", "Discord", "")).route = .{ .server = ws_id };
    _ = try s.addApp("/Applications/Safari.app", "Safari", "");
    s.settings.default_route = .auto;

    var b = try build(gpa, &s);
    defer b.deinit();
    try std.testing.expectEqual(1, b.skipped);
    try std.testing.expectEqual(1, b.cfg.outbounds.len);
    try std.testing.expectEqual(tunnel.Choice.main, b.cfg.default);
    try std.testing.expectEqualSlices(u16, &.{0}, b.cfg.main);
    try std.testing.expectEqualSlices(u32, &.{ok_id}, b.ids);
    try std.testing.expectEqual(3, b.cfg.rules.len);
    try std.testing.expectEqual(tunnel.Choice.direct, b.cfg.rules[0].choice);
    try std.testing.expectEqual(tunnel.Choice{ .outbound = 0 }, b.cfg.rules[1].choice);
    try std.testing.expectEqual(tunnel.Choice.block, b.cfg.rules[2].choice); // its server needs XHTTP
    try std.testing.expect(uses(b.cfg, 0));
    try std.testing.expect(!uses(b.cfg, 1));
}

test "routes: Fastest follows the server the window measured" {
    const gpa = std.testing.allocator;
    var s: model.State = .init(gpa);
    defer s.deinit();
    const sub = try s.addSubscription("t", "");
    const link = "vless://11111111-2222-3333-4444-555555555555@{s}:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.microsoft.com&pbk=jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8&sid=ab12#X";
    var buf: [256]u8 = undefined;
    _ = try s.addServer(sub.id, .{ .name = "US", .host = "us.example", .port = 443, .protocol = .vless, .link = try std.fmt.bufPrint(&buf, link, .{"us.example"}) });
    const nl = try s.addServer(sub.id, .{ .name = "NL", .host = "nl.example", .port = 443, .protocol = .vless, .link = try std.fmt.bufPrint(&buf, link, .{"nl.example"}) });
    s.settings.auto_server = nl.id;
    var b = try build(gpa, &s);
    defer b.deinit();
    try std.testing.expectEqual(tunnel.Choice.main, b.cfg.default);
    try std.testing.expectEqualSlices(u16, &.{1}, b.cfg.main);
    try std.testing.expectEqualStrings("nl.example", b.cfg.outbounds[1].vless.host);
}

fn testServers(s: *model.State, hosts: []const []const u8) !void {
    const sub = try s.addSubscription("t", "");
    const link = "vless://11111111-2222-3333-4444-555555555555@{s}:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.microsoft.com&pbk=jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8&sid=ab12#X";
    var buf: [256]u8 = undefined;
    for (hosts) |h| _ = try s.addServer(sub.id, .{ .name = h, .host = h, .port = 443, .protocol = .vless, .link = try std.fmt.bufPrint(&buf, link, .{h}) });
}

test "routes: the starred servers are the main server's reserve, in list order" {
    const gpa = std.testing.allocator;
    var s: model.State = .init(gpa);
    defer s.deinit();
    try testServers(&s, &.{ "a.example", "b.example", "c.example", "d.example" });
    const sv = s.servers.items;
    sv[0].favorite = true;
    sv[2].favorite = true; // the main server itself: not listed twice
    sv[3].favorite = true;
    s.settings.selected_server = sv[2].id;
    (try s.addApp("/Applications/Pinned.app", "Pinned", "")).route = .{ .server = sv[1].id };
    {
        var b = try build(gpa, &s);
        defer b.deinit();
        try std.testing.expectEqualSlices(u16, &.{ 2, 0, 3 }, b.cfg.main);
        try std.testing.expect(uses(b.cfg, 0) and uses(b.cfg, 1) and uses(b.cfg, 2) and uses(b.cfg, 3));
        // a pinned application stays on its server
        try std.testing.expectEqual(tunnel.Choice{ .outbound = 1 }, b.cfg.rules[0].choice);
    }
    s.settings.failover = false;
    var b = try build(gpa, &s);
    defer b.deinit();
    try std.testing.expectEqualSlices(u16, &.{2}, b.cfg.main);
    try std.testing.expect(!uses(b.cfg, 0));
}

test "routes: in standby the applications with a rule are held, the rest goes direct" {
    const gpa = std.testing.allocator;
    var s: model.State = .init(gpa);
    defer s.deinit();
    try testServers(&s, &.{"a.example"});
    (try s.addApp("/Applications/Claude.app", "Claude", "")).route = .auto;
    (try s.addApp("/Applications/Pinned.app", "Pinned", "")).route = .{ .server = s.servers.items[0].id };
    (try s.addApp("/Applications/Steam.app", "Steam", "")).route = .direct;
    (try s.addApp("/Applications/Off.app", "Off", "")).route = .block;
    (try s.addDomain("vpn-only.example")).route = .auto;
    (try s.addDomain("local.example")).route = .direct;
    _ = try s.addDomain("unset.example");
    s.settings.default_route = .auto;
    s.settings.standby = true;
    var b = try build(gpa, &s);
    defer b.deinit();
    try std.testing.expectEqual(tunnel.Choice.direct, b.cfg.default);
    try std.testing.expectEqual(@as(?tunnel.Choice, .block), b.cfg.unknown);
    try std.testing.expectEqual(0, b.cfg.outbounds.len);
    try std.testing.expectEqual(0, b.cfg.main.len);
    try std.testing.expectEqual(tunnel.Choice.block, b.cfg.rules[0].choice);
    try std.testing.expectEqual(tunnel.Choice.block, b.cfg.rules[1].choice);
    try std.testing.expectEqual(tunnel.Choice.direct, b.cfg.rules[2].choice);
    try std.testing.expectEqual(tunnel.Choice.block, b.cfg.rules[3].choice);
    // sites held to the VPN are held too; a site without a route is no rule
    try std.testing.expectEqual(2, b.cfg.domains.len);
    try std.testing.expectEqual(tunnel.Choice.block, b.cfg.domains[0].choice);
    try std.testing.expectEqual(tunnel.Choice.direct, b.cfg.domains[1].choice);
}

test "routes: a group is its servers, fastest first, before the starred ones" {
    const gpa = std.testing.allocator;
    var s: model.State = .init(gpa);
    defer s.deinit();
    try testServers(&s, &.{"single.example"});
    const tpl = "vless://11111111-2222-3333-4444-555555555555@{s}:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.microsoft.com&pbk=jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8&sid=ab12#X";
    var bufs: [3][256]u8 = undefined;
    const hosts = [_][]const u8{ "g1.example", "g2.example", "g3.example" };
    var members: [3]model.State.NewMember = undefined;
    for (hosts, &members, &bufs) |h, *m, *buf| m.* = .{ .link = try std.fmt.bufPrint(buf, tpl, .{h}), .host = h, .port = 443 };
    const g = try s.addServer(s.subs.items[0].id, .{ .name = "Auto 1", .host = "g1.example", .port = 443, .protocol = .vless, .link = members[0].link, .members = &members });
    const gid = g.id;
    // measured: g3 fastest, g1 slower, g2 not answering
    g.members[0].ping_ms = 90;
    g.members[2].ping_ms = 40;
    s.servers.items[0].favorite = true;
    s.settings.selected_server = gid;
    (try s.addApp("/Applications/Pinned.app", "Pinned", "")).route = .{ .server = gid };
    var b = try build(gpa, &s);
    defer b.deinit();
    // outbounds: 0 single, 1 g1, 2 g2, 3 g3
    try std.testing.expectEqual(4, b.cfg.outbounds.len);
    try std.testing.expectEqualSlices(u16, &.{ 3, 1, 2, 0 }, b.cfg.main);
    try std.testing.expectEqualSlices(u32, &.{ s.servers.items[0].id, gid, gid, gid }, b.ids);
    try std.testing.expectEqualSlices(u16, &.{ 0, 0, 1, 2 }, b.members);
    try std.testing.expect(b.cfg.check_exit);
    // an application pinned to the group gets its fastest server
    try std.testing.expectEqual(tunnel.Choice{ .outbound = 3 }, b.cfg.rules[0].choice);
}
