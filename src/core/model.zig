//! Data model shared by the engine and the UI: servers, subscriptions,
//! per-application routing rules and user settings.

const std = @import("std");

pub const Protocol = enum {
    vless,
    trojan,
    shadowsocks,
    hysteria2,
    tuic,
    wireguard,

    pub fn label(p: Protocol) []const u8 {
        return switch (p) {
            .vless => "VLESS",
            .trojan => "Trojan",
            .shadowsocks => "SS",
            .hysteria2 => "HY2",
            .tuic => "TUIC",
            .wireguard => "WG",
        };
    }
};

pub const Security = enum { none, tls, reality };

pub const Server = struct {
    id: u32,
    sub_id: u32,
    name: []const u8,
    host: []const u8,
    port: u16,
    protocol: Protocol,
    security: Security = .none,
    /// ISO 3166-1 alpha-2, upper case. "??" when unknown.
    country: [2]u8 = "??".*,
    /// Starred by the user. The starred servers are also the reserve: they
    /// take over, in list order, when the main server stops working.
    favorite: bool = false,
    /// false once the server disappeared from its subscription
    available: bool = true,
    /// Raw link as received. Treated as a secret: never logged or exported.
    link: []const u8 = "",

    // runtime, not persisted
    ping_ms: ?u16 = null,
    ping_state: enum { unknown, testing, ok, failed } = .unknown,
    /// this build can carry its protocol and transport (set by the app)
    carried: bool = true,
};

pub const Subscription = struct {
    id: u32,
    name: []const u8,
    /// Secret. Lives in the config file for now, system keychain later.
    url: []const u8,
    updated_unix: i64 = 0,
    /// Only set when the provider reports them.
    used_bytes: ?u64 = null,
    total_bytes: ?u64 = null,
    expire_unix: ?i64 = null,
    last_error: bool = false,
};

/// Where the traffic of an application goes.
pub const Route = union(enum) {
    /// follow the default route
    default,
    direct,
    /// pinned server id
    server: u32,
    /// fastest available server
    auto,
    /// local DPI bypass, no remote server
    dpi,
    block,

    pub fn eql(a: Route, b: Route) bool {
        return switch (a) {
            .server => |id| b == .server and b.server == id,
            else => std.meta.activeTag(a) == std.meta.activeTag(b),
        };
    }
};

pub const App = struct {
    /// Stable identity: bundle id / package name / executable path.
    id: []const u8,
    name: []const u8,
    path: []const u8 = "",
    route: Route = .default,

    // runtime
    online: bool = false,
    down_bps: f32 = 0,
    up_bps: f32 = 0,
    total_down: u64 = 0,
    total_up: u64 = 0,
};

pub const KillSwitch = enum { off, selective, strict };
pub const TunnelMode = enum { tun, proxy };
pub const Ipv6Mode = enum { block, tunnel, system };

pub const Settings = struct {
    kill_switch: KillSwitch = .selective,
    tunnel_mode: TunnelMode = .tun,
    ipv6: Ipv6Mode = .block,
    dns_over_route: bool = true,
    allow_lan: bool = true,
    launch_at_login: bool = false,
    auto_connect: bool = false,
    notifications: bool = true,
    sounds: bool = false,
    reduce_motion: bool = false,
    /// Install new releases by itself (only in builds made with an update repository).
    auto_update: bool = true,
    mtu: u16 = 0, // 0 = auto
    /// Route for apps without a rule.
    default_route: Route = .auto,
    selected_server: ?u32 = null,
    /// The server "Fastest" resolved to by the latest latency probes, so the
    /// background service (which never probes) uses the one the window shows.
    auto_server: ?u32 = null,
    /// When the main server stops carrying traffic, move to the starred
    /// servers (never to a direct connection).
    failover: bool = true,
    /// After Disconnect, applications with a rule of their own that sends
    /// them through the VPN (or blocks them) stay without network.
    protect_when_off: bool = true,
    /// The VPN is off and the service runs only to keep those applications
    /// blocked; everything else goes direct. Set by Disconnect, cleared by
    /// Connect.
    standby: bool = false,
};

pub const State = struct {
    gpa: std.mem.Allocator,
    servers: std.ArrayList(Server) = .empty,
    subs: std.ArrayList(Subscription) = .empty,
    apps: std.ArrayList(App) = .empty,
    settings: Settings = .{},
    next_id: u32 = 1,
    /// true while the bundled sample data is shown (no real subscription yet)
    demo: bool = false,

    pub fn init(gpa: std.mem.Allocator) State {
        return .{ .gpa = gpa };
    }

    pub fn deinit(s: *State) void {
        for (s.servers.items) |sv| s.freeServer(sv);
        s.servers.deinit(s.gpa);
        for (s.subs.items) |sub| {
            s.gpa.free(sub.name);
            s.gpa.free(sub.url);
        }
        s.subs.deinit(s.gpa);
        for (s.apps.items) |a| s.freeApp(a);
        s.apps.deinit(s.gpa);
    }

    fn freeServer(s: *State, sv: Server) void {
        s.gpa.free(sv.name);
        s.gpa.free(sv.host);
        s.gpa.free(sv.link);
    }

    fn freeApp(s: *State, a: App) void {
        s.gpa.free(a.id);
        s.gpa.free(a.name);
        s.gpa.free(a.path);
    }

    pub fn newId(s: *State) u32 {
        defer s.next_id += 1;
        return s.next_id;
    }

    pub fn serverById(s: *State, id: u32) ?*Server {
        for (s.servers.items) |*sv| if (sv.id == id) return sv;
        return null;
    }

    pub fn subById(s: *State, id: u32) ?*Subscription {
        for (s.subs.items) |*sub| if (sub.id == id) return sub;
        return null;
    }

    pub fn appById(s: *State, id: []const u8) ?*App {
        for (s.apps.items) |*a| if (std.mem.eql(u8, a.id, id)) return a;
        return null;
    }

    /// Fastest available server, or null if none has answered yet.
    /// Lowest latency among the servers this build can carry.
    pub fn fastest(s: *State) ?*Server {
        var best: ?*Server = null;
        for (s.servers.items) |*sv| {
            if (!sv.available or !sv.carried) continue;
            const p = sv.ping_ms orelse continue;
            if (best == null or p < best.?.ping_ms.?) best = sv;
        }
        return best;
    }

    /// The server the default route currently resolves to.
    pub fn currentServer(s: *State) ?*Server {
        if (s.settings.selected_server) |id| {
            // a server this build cannot carry is no choice at all
            if (s.serverById(id)) |sv| if (sv.available and sv.carried) return sv;
        }
        if (s.fastest()) |sv| return sv;
        for (s.servers.items) |*sv| if (sv.available and sv.carried) return sv;
        for (s.servers.items) |*sv| if (sv.available) return sv;
        return null;
    }

    /// Whether any application has a rule that must hold while the VPN is
    /// off: through the VPN only, or no network at all.
    pub fn hasProtectedApps(s: *const State) bool {
        for (s.apps.items) |a| switch (a.route) {
            .auto, .server, .block => return true,
            .default, .direct, .dpi => {},
        };
        return false;
    }

    /// Resolve an app route to a concrete server (null for direct/dpi/block).
    pub fn resolve(s: *State, route: Route) ?*Server {
        return switch (route) {
            .default => switch (s.settings.default_route) {
                .default, .auto => s.currentServer(),
                else => |r| s.resolve(r),
            },
            .auto => s.fastest() orelse s.currentServer(),
            .server => |id| s.serverById(id),
            .direct, .dpi, .block => null,
        };
    }

    pub fn addSubscription(s: *State, name: []const u8, url: []const u8) !*Subscription {
        const sub: Subscription = .{
            .id = s.newId(),
            .name = try s.gpa.dupe(u8, name),
            .url = try s.gpa.dupe(u8, url),
        };
        try s.subs.append(s.gpa, sub);
        return &s.subs.items[s.subs.items.len - 1];
    }

    pub const NewServer = struct {
        name: []const u8,
        host: []const u8,
        port: u16,
        protocol: Protocol,
        security: Security = .none,
        country: [2]u8 = "??".*,
        link: []const u8 = "",
    };

    pub fn addServer(s: *State, sub_id: u32, n: NewServer) !*Server {
        try s.servers.append(s.gpa, .{
            .id = s.newId(),
            .sub_id = sub_id,
            .name = try s.gpa.dupe(u8, n.name),
            .host = try s.gpa.dupe(u8, n.host),
            .port = n.port,
            .protocol = n.protocol,
            .security = n.security,
            .country = n.country,
            .link = try s.gpa.dupe(u8, n.link),
        });
        return &s.servers.items[s.servers.items.len - 1];
    }

    /// Replace the server list of a subscription with a freshly validated one.
    /// Servers are matched by host:port:protocol so ids, favorites and the
    /// rules pointing at them survive. Servers that vanished stay in the list
    /// marked unavailable while something still references them.
    pub fn applySubscription(s: *State, sub_id: u32, fresh: []const NewServer) !void {
        for (s.servers.items) |*sv| {
            if (sv.sub_id == sub_id) sv.available = false;
        }
        for (fresh) |n| {
            var found: ?*Server = null;
            for (s.servers.items) |*sv| {
                if (sv.sub_id == sub_id and sv.port == n.port and sv.protocol == n.protocol and
                    std.mem.eql(u8, sv.host, n.host) and std.mem.eql(u8, sv.name, n.name))
                {
                    found = sv;
                    break;
                }
            }
            if (found) |sv| {
                sv.available = true;
                s.gpa.free(sv.link);
                sv.link = try s.gpa.dupe(u8, n.link);
                sv.security = n.security;
                sv.country = n.country;
            } else {
                _ = try s.addServer(sub_id, n);
            }
        }
        // drop vanished servers nobody refers to
        var i: usize = 0;
        while (i < s.servers.items.len) {
            const sv = s.servers.items[i];
            if (sv.sub_id == sub_id and !sv.available and !s.isReferenced(sv.id)) {
                s.freeServer(sv);
                _ = s.servers.orderedRemove(i);
            } else i += 1;
        }
    }

    pub fn isReferenced(s: *State, server_id: u32) bool {
        if (s.settings.selected_server == server_id) return true;
        for (s.servers.items) |sv| if (sv.id == server_id and sv.favorite) return true;
        for (s.apps.items) |a| if (a.route == .server and a.route.server == server_id) return true;
        return false;
    }

    pub fn removeSubscription(s: *State, sub_id: u32) void {
        var i: usize = 0;
        while (i < s.servers.items.len) {
            const sv = s.servers.items[i];
            if (sv.sub_id == sub_id) {
                if (s.settings.selected_server == sv.id) s.settings.selected_server = null;
                for (s.apps.items) |*a| {
                    if (a.route == .server and a.route.server == sv.id) a.route = .default;
                }
                s.freeServer(sv);
                _ = s.servers.orderedRemove(i);
            } else i += 1;
        }
        for (s.subs.items, 0..) |sub, idx| {
            if (sub.id == sub_id) {
                s.gpa.free(sub.name);
                s.gpa.free(sub.url);
                _ = s.subs.orderedRemove(idx);
                break;
            }
        }
    }

    pub fn addApp(s: *State, id: []const u8, name: []const u8, path: []const u8) !*App {
        if (s.appById(id)) |a| return a;
        try s.apps.append(s.gpa, .{
            .id = try s.gpa.dupe(u8, id),
            .name = try s.gpa.dupe(u8, name),
            .path = try s.gpa.dupe(u8, path),
        });
        return &s.apps.items[s.apps.items.len - 1];
    }

    pub fn clearDemo(s: *State) void {
        if (!s.demo) return;
        s.demo = false;
        while (s.subs.items.len > 0) s.removeSubscription(s.subs.items[0].id);
        for (s.apps.items) |*a| {
            a.route = .default;
            a.online = false;
            a.down_bps = 0;
            a.up_bps = 0;
            // the sample traffic is not the user's
            a.total_down = 0;
            a.total_up = 0;
        }
    }
};

test "applySubscription keeps ids and pinned servers" {
    const gpa = std.testing.allocator;
    var s: State = .init(gpa);
    defer s.deinit();
    const sub = try s.addSubscription("test", "https://example.invalid/sub");
    const sub_id = sub.id;
    try s.applySubscription(sub_id, &.{
        .{ .name = "NL-1", .host = "a.example", .port = 443, .protocol = .vless },
        .{ .name = "DE-1", .host = "b.example", .port = 443, .protocol = .trojan },
    });
    try std.testing.expectEqual(2, s.servers.items.len);
    const nl_id = s.servers.items[0].id;
    const de_id = s.servers.items[1].id;
    s.settings.selected_server = de_id;

    // DE disappears, FR appears
    try s.applySubscription(sub_id, &.{
        .{ .name = "NL-1", .host = "a.example", .port = 443, .protocol = .vless },
        .{ .name = "FR-1", .host = "c.example", .port = 443, .protocol = .vless },
    });
    try std.testing.expectEqual(3, s.servers.items.len);
    try std.testing.expectEqual(nl_id, s.servers.items[0].id);
    // pinned server is kept but flagged, never silently replaced
    try std.testing.expect(!s.serverById(de_id).?.available);

    s.settings.selected_server = null;
    try s.applySubscription(sub_id, &.{
        .{ .name = "NL-1", .host = "a.example", .port = 443, .protocol = .vless },
    });
    try std.testing.expectEqual(1, s.servers.items.len);
}
