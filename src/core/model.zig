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
    vmess,

    pub fn label(p: Protocol) []const u8 {
        return switch (p) {
            .vless => "VLESS",
            .trojan => "Trojan",
            .shadowsocks => "SS",
            .hysteria2 => "HY2",
            .tuic => "TUIC",
            .wireguard => "WG",
            .vmess => "VMess",
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
    /// ISO 3166-1 alpha-2, upper case. "??" when unknown. What the provider
    /// says (the name, a flag).
    country: [2]u8 = "??".*,
    /// Where the server really exits to the internet, as a request through
    /// it showed once it was in use; "??" until then. Shown instead of
    /// `country` once known. A group's is its members'.
    exit: [2]u8 = "??".*,
    /// Starred by the user. The starred servers are also the reserve: they
    /// take over, in list order, when the main server stops working.
    favorite: bool = false,
    /// false once the server disappeared from its subscription
    available: bool = true,
    /// Raw link as received. Treated as a secret: never logged or exported.
    link: []const u8 = "",
    /// A group from the subscription ("⚡ Auto 3": a balancer of several
    /// servers). Shown and chosen as one server; connected through the
    /// reserve logic, best member first. Empty for a plain server. `link`,
    /// `host` and `port` are then those of the first member.
    members: []Member = &.{},

    // runtime, not persisted
    /// a group's is its best member's
    ping_ms: ?u16 = null,
    ping_state: enum { unknown, testing, ok, failed } = .unknown,
    /// this build can carry its protocol and transport (set by the app)
    carried: bool = true,

    pub fn isGroup(sv: *const Server) bool {
        return sv.members.len > 0;
    }

    /// The country to show: where it exits when that was seen, else what
    /// the provider says.
    pub fn shownCountry(sv: *const Server) [2]u8 {
        return if (knownCountry(sv.exit)) sv.exit else sv.country;
    }
};

/// Two capital letters: a country code, not "??".
pub fn knownCountry(cc: [2]u8) bool {
    return std.ascii.isUpper(cc[0]) and std.ascii.isUpper(cc[1]);
}

/// One server of a group. The link is a secret, as a server's.
pub const Member = struct {
    link: []const u8,
    host: []const u8,
    port: u16,
    /// where it exits, as `Server.exit`
    exit: [2]u8 = "??".*,
    // runtime
    ping_ms: ?u16 = null,
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
    /// From the provider's headers: refresh every this many hours (0: only
    /// when asked), a note for the Settings, where to get help.
    update_hours: u16 = 0,
    announce: []const u8 = "",
    support_url: []const u8 = "",
    // runtime: the last automatic refresh attempt, so a failing one waits
    tried_unix: i64 = 0,
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

/// A site and everything under it ("example.com" covers "www.example.com"),
/// with a route. It applies to the applications without a rule of their own.
pub const Domain = struct {
    /// lower case, no leading "*." or dots
    name: []const u8,
    route: Route = .default,
};

/// The form a domain rule keeps: lower case, without "*.", surrounding dots,
/// a scheme or a path. Null when it is not a host name.
pub fn normalizeDomain(text: []const u8, out: []u8) ?[]const u8 {
    var t = std.mem.trim(u8, text, " \t\r\n");
    if (std.mem.indexOf(u8, t, "://")) |i| t = t[i + 3 ..];
    if (std.mem.indexOfAny(u8, t, "/?#")) |i| t = t[0..i];
    if (std.mem.lastIndexOfScalar(u8, t, ':')) |i| {
        // a port after a name (not an IPv6 address)
        if (std.mem.indexOfScalar(u8, t[0..i], ':') == null) t = t[0..i];
    }
    if (std.mem.startsWith(u8, t, "*.")) t = t[2..];
    t = std.mem.trim(u8, t, ".");
    if (t.len == 0 or t.len > out.len or t.len > 253) return null;
    for (t, 0..) |ch, i| {
        const c = std.ascii.toLower(ch);
        if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_')) return null;
        out[i] = c;
    }
    if (std.mem.indexOf(u8, out[0..t.len], "..") != null) return null;
    return out[0..t.len];
}

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
    /// Install new releases by itself (not in builds made with `-Dupdate-repo=`).
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
    /// Once a server is in use, one request through it shows in which
    /// country it really exits to the internet (`Server.exit`).
    check_exit: bool = true,
    /// The VPN is off and the service runs only to keep those applications
    /// blocked; everything else goes direct. Set by Disconnect, cleared by
    /// Connect.
    standby: bool = false,
};

/// What a provider says about its subscription in the answer's headers
/// (decoded already); null where it said nothing.
pub const SubMeta = struct {
    title: ?[]const u8 = null,
    update_hours: ?u16 = null,
    announce: ?[]const u8 = null,
    support_url: ?[]const u8 = null,
};

pub const State = struct {
    gpa: std.mem.Allocator,
    servers: std.ArrayList(Server) = .empty,
    subs: std.ArrayList(Subscription) = .empty,
    apps: std.ArrayList(App) = .empty,
    /// rules by site, in the order they were added
    domains: std.ArrayList(Domain) = .empty,
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
        for (s.subs.items) |sub| s.freeSub(sub);
        s.subs.deinit(s.gpa);
        for (s.apps.items) |a| s.freeApp(a);
        s.apps.deinit(s.gpa);
        for (s.domains.items) |d| s.gpa.free(d.name);
        s.domains.deinit(s.gpa);
    }

    /// The rule for `text` (normalized), made when there is none yet.
    pub fn addDomain(s: *State, text: []const u8) !*Domain {
        var buf: [253]u8 = undefined;
        const name = normalizeDomain(text, &buf) orelse return error.BadDomain;
        if (s.domainByName(name)) |d| return d;
        try s.domains.append(s.gpa, .{ .name = try s.gpa.dupe(u8, name) });
        return &s.domains.items[s.domains.items.len - 1];
    }

    pub fn domainByName(s: *State, name: []const u8) ?*Domain {
        for (s.domains.items) |*d| if (std.mem.eql(u8, d.name, name)) return d;
        return null;
    }

    pub fn removeDomain(s: *State, index: usize) void {
        if (index >= s.domains.items.len) return;
        s.gpa.free(s.domains.items[index].name);
        _ = s.domains.orderedRemove(index);
    }

    fn freeServer(s: *State, sv: Server) void {
        s.gpa.free(sv.name);
        s.gpa.free(sv.host);
        s.gpa.free(sv.link);
        s.freeMembers(sv.members);
    }

    fn freeMembers(s: *State, members: []Member) void {
        for (members) |m| {
            s.gpa.free(m.link);
            s.gpa.free(m.host);
        }
        s.gpa.free(members);
    }

    fn freeSub(s: *State, sub: Subscription) void {
        s.gpa.free(sub.name);
        s.gpa.free(sub.url);
        s.gpa.free(sub.announce);
        s.gpa.free(sub.support_url);
    }

    fn dupeMembers(s: *State, from: []const NewMember) ![]Member {
        const out = try s.gpa.alloc(Member, from.len);
        var n: usize = 0;
        errdefer {
            for (out[0..n]) |m| {
                s.gpa.free(m.link);
                s.gpa.free(m.host);
            }
            s.gpa.free(out);
        }
        for (from) |m| {
            const link = try s.gpa.dupe(u8, m.link);
            const host = s.gpa.dupe(u8, m.host) catch |err| {
                s.gpa.free(link);
                return err;
            };
            out[n] = .{ .link = link, .host = host, .port = m.port };
            n += 1;
        }
        return out;
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
            // a server this build cannot carry is no choice at all; one
            // that left its subscription stays until Disconnect (see
            // `dropVanishedChoice`)
            if (s.serverById(id)) |sv| if (sv.carried) return sv;
        }
        if (s.fastest()) |sv| return sv;
        for (s.servers.items) |*sv| if (sv.available and sv.carried) return sv;
        for (s.servers.items) |*sv| if (sv.available) return sv;
        return null;
    }

    /// Whether any application has a rule that must hold while the VPN is
    /// off: through the VPN only, or no network at all.
    /// Some application or site may only use the VPN (or nothing): it is
    /// held while the VPN is off.
    pub fn hasProtectedApps(s: *const State) bool {
        for (s.apps.items) |a| switch (a.route) {
            .auto, .server, .block => return true,
            .default, .direct, .dpi => {},
        };
        for (s.domains.items) |d| switch (d.route) {
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

    pub const NewMember = struct {
        link: []const u8,
        host: []const u8,
        port: u16,
    };

    pub const NewServer = struct {
        name: []const u8,
        host: []const u8,
        port: u16,
        protocol: Protocol,
        security: Security = .none,
        country: [2]u8 = "??".*,
        link: []const u8 = "",
        /// a group: its servers, the first one's also in the fields above
        members: []const NewMember = &.{},
    };

    pub fn addServer(s: *State, sub_id: u32, n: NewServer) !*Server {
        const members = try s.dupeMembers(n.members);
        errdefer s.freeMembers(members);
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
            .members = members,
        });
        return &s.servers.items[s.servers.items.len - 1];
    }

    /// Replace the server list of a subscription with a freshly validated one.
    /// A server keeps its id, star and the rules pointing at it when the
    /// same one comes again: the same name at the same address, else the
    /// same name alone (providers that keep names stable, as groups whose
    /// servers change, are followed by name). Servers that vanished stay in
    /// the list, marked unavailable, while something still references them.
    pub fn applySubscription(s: *State, sub_id: u32, fresh: []const NewServer) !void {
        for (s.servers.items) |*sv| {
            if (sv.sub_id == sub_id) sv.available = false;
        }
        // matched in two rounds, so that an exact match is never taken by a
        // namesake first
        const matched = try s.gpa.alloc(?u32, fresh.len);
        defer s.gpa.free(matched);
        for (fresh, matched) |n, *m| {
            m.* = null;
            for (s.servers.items) |*sv| {
                if (sv.sub_id == sub_id and !sv.available and sv.port == n.port and sv.protocol == n.protocol and
                    std.mem.eql(u8, sv.host, n.host) and std.mem.eql(u8, sv.name, n.name))
                {
                    sv.available = true;
                    m.* = sv.id;
                    break;
                }
            }
        }
        for (fresh, matched) |n, *m| {
            if (m.* != null) continue;
            for (s.servers.items) |*sv| {
                if (sv.sub_id == sub_id and !sv.available and std.mem.eql(u8, sv.name, n.name)) {
                    sv.available = true;
                    m.* = sv.id;
                    break;
                }
            }
        }
        for (fresh, matched) |n, m| {
            const sv = if (m) |id| s.serverById(id).? else {
                _ = try s.addServer(sub_id, n);
                continue;
            };
            const link = try s.gpa.dupe(u8, n.link);
            errdefer s.gpa.free(link);
            const host = try s.gpa.dupe(u8, n.host);
            errdefer s.gpa.free(host);
            const members = try s.dupeMembers(n.members);
            // the member pings stay with their servers until measured again,
            // and where they exit
            for (members) |*nm| for (sv.members) |old| {
                if (!std.mem.eql(u8, old.link, nm.link)) continue;
                nm.ping_ms = old.ping_ms;
                nm.exit = old.exit;
            };
            // another address may well exit elsewhere
            if (!std.mem.eql(u8, sv.host, n.host)) sv.exit = "??".*;
            s.gpa.free(sv.link);
            s.gpa.free(sv.host);
            s.freeMembers(sv.members);
            sv.link = link;
            sv.host = host;
            sv.members = members;
            sv.port = n.port;
            sv.protocol = n.protocol;
            sv.security = n.security;
            sv.country = n.country;
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
        if (s.settings.auto_server == server_id) return true;
        for (s.servers.items) |sv| if (sv.id == server_id and sv.favorite) return true;
        for (s.apps.items) |a| if (a.route == .server and a.route.server == server_id) return true;
        for (s.domains.items) |d| if (d.route == .server and d.route.server == server_id) return true;
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
                for (s.domains.items) |*d| {
                    if (d.route == .server and d.route.server == sv.id) d.route = .default;
                }
                s.freeServer(sv);
                _ = s.servers.orderedRemove(i);
            } else i += 1;
        }
        for (s.subs.items, 0..) |sub, idx| {
            if (sub.id == sub_id) {
                s.freeSub(sub);
                _ = s.subs.orderedRemove(idx);
                break;
            }
        }
    }

    /// After Disconnect: a chosen server that left its subscription meanwhile
    /// is given up (the next connection takes the fastest), and the servers
    /// nobody refers to any more go. True when something changed.
    pub fn dropVanishedChoice(s: *State) bool {
        var changed = false;
        if (s.settings.selected_server) |id| if (s.serverById(id)) |sv| if (!sv.available) {
            s.settings.selected_server = null;
            changed = true;
        };
        if (s.settings.auto_server) |id| if (s.serverById(id)) |sv| if (!sv.available) {
            s.settings.auto_server = null;
            changed = true;
        };
        var i: usize = 0;
        while (i < s.servers.items.len) {
            const sv = s.servers.items[i];
            if (sv.sub_id != 0 and !sv.available and !s.isReferenced(sv.id)) {
                s.freeServer(sv);
                _ = s.servers.orderedRemove(i);
                changed = true;
            } else i += 1;
        }
        return changed;
    }

    /// What the provider said about the subscription in its headers.
    pub fn applyMeta(s: *State, sub_id: u32, meta: SubMeta) !void {
        const sub = s.subById(sub_id) orelse return;
        if (meta.title) |t| if (t.len > 0) {
            const name = try s.gpa.dupe(u8, t);
            s.gpa.free(sub.name);
            sub.name = name;
        };
        if (meta.update_hours) |h| sub.update_hours = h;
        if (meta.announce) |t| {
            const text = try s.gpa.dupe(u8, t);
            s.gpa.free(sub.announce);
            sub.announce = text;
        }
        if (meta.support_url) |t| {
            const text = try s.gpa.dupe(u8, t);
            s.gpa.free(sub.support_url);
            sub.support_url = text;
        }
    }

    /// A subscription due for its provider's periodic refresh, at `now`
    /// (seconds); it is marked tried. Null when none is.
    pub fn dueForRefresh(s: *State, now: i64) ?*Subscription {
        for (s.subs.items) |*sub| {
            if (sub.url.len == 0 or sub.update_hours == 0) continue;
            const every: i64 = @as(i64, sub.update_hours) * 3600;
            if (now - sub.updated_unix < every) continue;
            // a failing provider is asked again after a quarter of the period
            if (now - sub.tried_unix < @max(@divTrunc(every, 4), 300)) continue;
            sub.tried_unix = now;
            return sub;
        }
        return null;
    }

    /// One connection-time measurement to make: a server, or a group member.
    pub const ProbeTarget = struct { id: u32, member: ?u8, host: []u8, port: u16 };

    /// Everything to measure now, marked as being measured; the caller owns
    /// the hosts and the list.
    pub fn probeTargets(s: *State, gpa: std.mem.Allocator) ![]ProbeTarget {
        var list: std.ArrayList(ProbeTarget) = .empty;
        errdefer {
            for (list.items) |t| gpa.free(t.host);
            list.deinit(gpa);
        }
        for (s.servers.items) |*sv| {
            if (!sv.available or sv.host.len == 0) continue;
            sv.ping_state = .testing;
            if (sv.members.len == 0) {
                try list.append(gpa, .{ .id = sv.id, .member = null, .host = try gpa.dupe(u8, sv.host), .port = sv.port });
                continue;
            }
            for (sv.members, 0..) |*m, i| {
                m.ping_ms = null;
                try list.append(gpa, .{ .id = sv.id, .member = @intCast(i), .host = try gpa.dupe(u8, m.host), .port = m.port });
            }
        }
        return list.toOwnedSlice(gpa);
    }

    /// A measurement came back: a group answers as its best member.
    pub fn recordPing(s: *State, id: u32, member: ?u8, ms: ?u16) void {
        const sv = s.serverById(id) orelse return;
        const m = member orelse {
            sv.ping_ms = ms;
            sv.ping_state = if (ms != null) .ok else .failed;
            return;
        };
        if (m >= sv.members.len) return;
        sv.members[m].ping_ms = ms;
        var best: ?u16 = null;
        for (sv.members) |mb| if (mb.ping_ms) |p| {
            if (best == null or p < best.?) best = p;
        };
        sv.ping_ms = best;
        sv.ping_state = if (best != null) .ok else .failed;
    }

    /// A request through server `id` (a group: through its member `member`)
    /// showed where it exits. True when that is news (worth saving).
    pub fn recordExit(s: *State, id: u32, member: usize, cc: [2]u8) bool {
        if (!knownCountry(cc)) return false;
        const sv = s.serverById(id) orelse return false;
        const at = if (sv.members.len == 0) &sv.exit else if (member < sv.members.len) &sv.members[member].exit else return false;
        if (std.mem.eql(u8, at, &cc)) return false;
        at.* = cc;
        return true;
    }

    /// Where server `id` exits while `member` carries it (a group's member;
    /// ignored for a plain server), as last seen; "??" when not known.
    pub fn exitOf(s: *State, id: u32, member: usize) [2]u8 {
        const sv = s.serverById(id) orelse return "??".*;
        if (sv.members.len == 0) return sv.exit;
        return if (member < sv.members.len) sv.members[member].exit else "??".*;
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

test "domain rules keep the bare host name" {
    var buf: [253]u8 = undefined;
    try std.testing.expectEqualStrings("example.com", normalizeDomain("  *.Example.COM. ", &buf).?);
    try std.testing.expectEqualStrings("youtube.com", normalizeDomain("https://www.youtube.com/watch?v=1", &buf).?[4..]);
    try std.testing.expectEqualStrings("api.example.org", normalizeDomain("api.example.org:8443", &buf).?);
    try std.testing.expect(normalizeDomain("", &buf) == null);
    try std.testing.expect(normalizeDomain("bad name.com", &buf) == null);
    try std.testing.expect(normalizeDomain("a..b", &buf) == null);
    var s: State = .init(std.testing.allocator);
    defer s.deinit();
    const d = try s.addDomain("YouTube.com");
    d.route = .direct;
    try std.testing.expectEqual(d, try s.addDomain("*.youtube.com"));
    try std.testing.expectEqual(1, s.domains.items.len);
    s.removeDomain(0);
    try std.testing.expectEqual(0, s.domains.items.len);
}

test "groups: matched by name when their servers change, pings by member" {
    const gpa = std.testing.allocator;
    var s: State = .init(gpa);
    defer s.deinit();
    const sub_id = (try s.addSubscription("free", "https://example.invalid/s/x")).id;
    const m1: State.NewMember = .{ .link = "vless://a@1.example:443", .host = "1.example", .port = 443 };
    const m2: State.NewMember = .{ .link = "vless://b@2.example:443", .host = "2.example", .port = 443 };
    const m3: State.NewMember = .{ .link = "vless://c@3.example:443", .host = "3.example", .port = 443 };
    try s.applySubscription(sub_id, &.{
        .{ .name = "Auto 1", .host = "1.example", .port = 443, .protocol = .vless, .link = m1.link, .members = &.{ m1, m2 } },
        .{ .name = "Germany 2", .host = "9.example", .port = 443, .protocol = .vless, .link = "vless://z@9.example:443" },
    });
    const auto_id = s.servers.items[0].id;
    s.settings.selected_server = auto_id;
    s.servers.items[0].favorite = true;

    // pings: the group answers as its best member
    const targets = try s.probeTargets(gpa);
    defer {
        for (targets) |t| gpa.free(t.host);
        gpa.free(targets);
    }
    try std.testing.expectEqual(3, targets.len);
    s.recordPing(auto_id, 0, null);
    try std.testing.expectEqual(.failed, s.servers.items[0].ping_state);
    s.recordPing(auto_id, 1, 80);
    try std.testing.expectEqual(80, s.servers.items[0].ping_ms.?);

    // an hour later the group is made of other servers, the single one left
    try s.applySubscription(sub_id, &.{
        .{ .name = "Auto 1", .host = "2.example", .port = 443, .protocol = .vless, .link = m2.link, .members = &.{ m2, m3 } },
    });
    const g = s.serverById(auto_id).?;
    try std.testing.expect(g.available and g.favorite);
    try std.testing.expectEqual(2, g.members.len);
    try std.testing.expectEqualStrings("3.example", g.members[1].host);
    // its measured member keeps its time until measured again
    try std.testing.expectEqual(80, g.members[0].ping_ms.?);
    try std.testing.expectEqualStrings("2.example", g.host);
    try std.testing.expectEqual(1, s.servers.items.len);
}

test "a chosen server that left the subscription stays until Disconnect" {
    const gpa = std.testing.allocator;
    var s: State = .init(gpa);
    defer s.deinit();
    const sub_id = (try s.addSubscription("p", "https://example.invalid/sub")).id;
    try s.applySubscription(sub_id, &.{
        .{ .name = "A", .host = "a.example", .port = 443, .protocol = .vless, .link = "vless://a@a.example:443" },
        .{ .name = "B", .host = "b.example", .port = 443, .protocol = .vless, .link = "vless://b@b.example:443" },
    });
    const a = s.servers.items[0].id;
    s.settings.selected_server = a;
    try s.applySubscription(sub_id, &.{
        .{ .name = "B", .host = "b.example", .port = 443, .protocol = .vless, .link = "vless://b@b.example:443" },
    });
    // still the server in use
    try std.testing.expectEqual(a, s.currentServer().?.id);
    try std.testing.expect(s.dropVanishedChoice());
    try std.testing.expectEqual(null, s.settings.selected_server);
    try std.testing.expectEqual(1, s.servers.items.len);
    try std.testing.expect(!s.dropVanishedChoice());
}

test "the provider's refresh period" {
    var s: State = .init(std.testing.allocator);
    defer s.deinit();
    const sub = try s.addSubscription("p", "https://example.invalid/sub");
    const id = sub.id;
    try s.applyMeta(id, .{ .title = "Free", .update_hours = 1, .announce = "72 servers", .support_url = "https://t.me/x" });
    try std.testing.expectEqualStrings("Free", s.subById(id).?.name);
    s.subById(id).?.updated_unix = 1000;
    try std.testing.expectEqual(null, s.dueForRefresh(1000 + 3599));
    try std.testing.expectEqual(id, s.dueForRefresh(1000 + 3600).?.id);
    // tried just now: not again before a quarter of the period
    try std.testing.expectEqual(null, s.dueForRefresh(1000 + 3601));
    try std.testing.expectEqual(id, s.dueForRefresh(1000 + 3600 + 900).?.id);
}

test "where a server exits: kept across refreshes, per member of a group, reset on a new address" {
    const gpa = std.testing.allocator;
    var s: State = .init(gpa);
    defer s.deinit();
    const sub_id = (try s.addSubscription("free", "https://example.invalid/s/x")).id;
    const m1: State.NewMember = .{ .link = "vless://a@1.example:443", .host = "1.example", .port = 443 };
    const m2: State.NewMember = .{ .link = "vless://b@2.example:443", .host = "2.example", .port = 443 };
    try s.applySubscription(sub_id, &.{
        .{ .name = "Germany 1", .host = "de.example", .port = 443, .protocol = .vless, .country = "DE".* },
        .{ .name = "Auto", .host = "1.example", .port = 443, .protocol = .vless, .link = m1.link, .members = &.{ m1, m2 } },
    });
    const de = s.servers.items[0].id;
    const auto = s.servers.items[1].id;
    try std.testing.expectEqualStrings("DE", &s.servers.items[0].shownCountry());
    // the provider says Germany, the exit is in the Netherlands
    try std.testing.expect(s.recordExit(de, 0, "NL".*));
    try std.testing.expect(!s.recordExit(de, 0, "NL".*));
    try std.testing.expect(!s.recordExit(de, 0, "??".*));
    try std.testing.expectEqualStrings("NL", &s.serverById(de).?.shownCountry());
    try std.testing.expect(s.recordExit(auto, 1, "FI".*));
    try std.testing.expect(!s.recordExit(auto, 2, "FI".*));
    try std.testing.expectEqualStrings("FI", &s.exitOf(auto, 1));
    try std.testing.expectEqualStrings("??", &s.exitOf(auto, 0));

    // refreshed: the same servers keep it; the group's member is followed by its link
    try s.applySubscription(sub_id, &.{
        .{ .name = "Germany 1", .host = "de.example", .port = 443, .protocol = .vless, .country = "DE".* },
        .{ .name = "Auto", .host = "2.example", .port = 443, .protocol = .vless, .link = m2.link, .members = &.{m2} },
    });
    try std.testing.expectEqualStrings("NL", &s.serverById(de).?.exit);
    try std.testing.expectEqualStrings("FI", &s.exitOf(auto, 0));

    // the provider moved the server: what its old address showed is gone
    try s.applySubscription(sub_id, &.{
        .{ .name = "Germany 1", .host = "de2.example", .port = 443, .protocol = .vless, .country = "DE".* },
    });
    try std.testing.expectEqualStrings("DE", &s.serverById(de).?.shownCountry());
}
