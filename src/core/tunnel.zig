//! The TUN data plane.
//!
//! Terminates every flow the system routes into the TUN, finds which
//! application it belongs to, picks its exit (the application's rule, else
//! the default) and carries it. DNS queries are answered with fake
//! addresses so connections arrive with their domain; UDP goes out direct
//! where the route allows it.
//!
//! Threads: one reads the device and runs the TCP stack's timers; each TCP
//! flow has a worker (plus a helper for the reverse direction); each direct
//! UDP flow has a reader.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const c = std.c;
const proxy = @import("proxy.zig");
const sys = @import("sys.zig");
const packet = @import("ipstack/packet.zig");
const tcp = @import("ipstack/stack.zig");
const dns = @import("ipstack/dns.zig");
const tls13 = @import("tls13.zig");
const vision = @import("vision.zig");
const xudp = @import("xudp.zig");
const udp_out = @import("udp_out.zig");
const sni = @import("sni.zig");
const failover = @import("failover.zig");
pub const wintun = @import("wintun.zig");
const windows = builtin.os.tag == .windows;

const Endpoint = packet.Endpoint;

pub const Choice = union(enum) {
    direct,
    block,
    /// direct, with the first bytes shaped past DPI
    dpi,
    /// index into `Config.outbounds`: this server and no other
    outbound: u16,
    /// the main server, or the reserve server standing in for it (`Config.main`)
    main,
};

pub const Rule = struct {
    /// application identity as returned by `AppLookup`
    app: []const u8,
    choice: Choice,
};

/// A site and everything under it, for the applications without a rule
/// of their own.
pub const DomainRule = struct {
    /// lower case, no leading dot: "example.com" covers "a.example.com"
    suffix: []const u8,
    choice: Choice,
};

pub const Config = struct {
    default: Choice = .direct,
    rules: []const Rule = &.{},
    domains: []const DomainRule = &.{},
    outbounds: []const proxy.Outbound = &.{},
    /// Flows whose owner could not be identified; null: as `default`. Set
    /// where `default` is direct but some applications must never be.
    unknown: ?Choice = null,
    /// indices into `outbounds`: the main server first, then its reserve
    /// in the order to prefer them. Empty: `Choice.main` blocks.
    main: []const u16 = &.{},
    dns_exclusions: []const []const u8 = &.{},
    /// QUIC (UDP 443) of proxied applications is dropped so they fall back
    /// to TCP, which the outbound carries
    drop_quic: bool = true,
};

/// Finds which application owns a flow; writes a stable identity (macOS:
/// the outermost .app bundle path, else the executable path) into `buf`.
/// More identities may follow, each after a 0 byte: the applications that
/// started this one, nearest first. A flow without a rule of its own
/// follows the rule of the nearest of them that has one.
pub const AppLookup = struct {
    ctx: *anyopaque,
    find: *const fn (ctx: *anyopaque, udp: bool, local: Endpoint, remote: Endpoint, buf: []u8) ?[]u8,
};

pub const Options = struct {
    mtu: u16 = 1500,
    /// how our own sockets leave the machine (the physical interface)
    bind: sys.Bind = .none,
    /// real DNS servers, reached through `bind`
    upstream_dns: []const Endpoint = &.{},
    lookup: ?AppLookup = null,
};

pub const Tunnel = struct {
    gpa: std.mem.Allocator,
    io: Io,
    stack: *tcp.Stack,
    fake: dns.FakeIp,
    resolver: dns.Resolver,
    dialer: proxy.Dialer,
    lookup: ?AppLookup,
    meter: proxy.Meter = .{},
    device: ?*Device = null,

    cfg_mutex: Io.Mutex = .init,
    cfg_arena: std.heap.ArenaAllocator,
    cfg: Config = .{},
    /// `cfg.domains` by suffix, in `cfg_arena`
    domain_map: std.StringHashMapUnmanaged(Choice) = .empty,

    apps_mutex: Io.Mutex = .init,
    apps: std.StringHashMapUnmanaged(*AppStats) = .empty,

    /// the main server and its reserve
    group: failover.Group,
    /// TCP flows carried by the group's server, to end them when it
    /// changes. Keys, not pointers: a key that outlived its connection finds
    /// nothing (or a newer flow of the same route, which may go as well).
    main_mutex: Io.Mutex = .init,
    main_conns: std.ArrayList(tcp.Key) = .empty,

    udp_mutex: Io.Mutex = .init,
    udp: std.HashMapUnmanaged(UdpKey, *UdpFlow, UdpKeyContext, 80) = .empty,
    sessions: std.HashMapUnmanaged(Endpoint, *UdpSession, EndpointContext, 80) = .empty,

    workers: std.atomic.Value(u32) = .init(0),
    dns_inflight: std.atomic.Value(u32) = .init(0),
    stopping: std.atomic.Value(bool) = .init(false),

    pub const AppStats = struct {
        meter: proxy.Meter = .{},
    };

    pub fn create(gpa: std.mem.Allocator, io: Io, opts: Options) !*Tunnel {
        const t = try gpa.create(Tunnel);
        errdefer gpa.destroy(t);
        const servers = try gpa.dupe(Endpoint, opts.upstream_dns);
        errdefer gpa.free(servers);
        t.* = .{
            .gpa = gpa,
            .io = io,
            .stack = undefined,
            .fake = .init(gpa, io),
            .resolver = .{ .gpa = gpa, .io = io, .servers = servers, .bind = opts.bind },
            .dialer = .{ .bind = opts.bind },
            .lookup = opts.lookup,
            .cfg_arena = .init(gpa),
            .group = .{ .io = io },
        };
        t.dialer.resolver = &t.resolver;
        t.group.dialer = t.dialer;
        t.group.on_switch = .{ .ctx = t, .call = onSwitch };
        t.stack = try tcp.Stack.create(gpa, io, .{ .mtu = opts.mtu }, .{ .ctx = t, .write = writeOut }, .{ .ctx = t, .tcp = onTcp, .udp = onUdp });
        return t;
    }

    /// Stop every flow and free everything. The device loop must have returned.
    pub fn destroy(t: *Tunnel) void {
        t.stopping.store(true, .release);
        t.group.stop();
        t.stack.abortAll();
        t.closeAllUdp();
        // workers notice the reset and leave; wait for them
        while (t.workers.load(.acquire) > 0 or t.dns_inflight.load(.acquire) > 0) {
            t.io.sleep(.fromMilliseconds(5), .awake) catch {};
            _ = t.stack.tick();
        }
        _ = t.stack.tick();
        t.stack.destroy();
        t.fake.deinit();
        t.gpa.free(t.resolver.servers);
        t.resolver.deinit();
        var it = t.apps.iterator();
        while (it.next()) |e| {
            t.gpa.free(e.key_ptr.*);
            t.gpa.destroy(e.value_ptr.*);
        }
        t.apps.deinit(t.gpa);
        t.freeDrops();
        t.udp.deinit(t.gpa);
        t.sessions.deinit(t.gpa);
        t.main_conns.deinit(t.gpa);
        t.cfg_arena.deinit();
        t.gpa.destroy(t);
    }

    /// Replace the routing configuration. Flows already running keep the
    /// exit they started with; new ones use the new configuration.
    pub fn setConfig(t: *Tunnel, cfg: Config) !void {
        var arena: std.heap.ArenaAllocator = .init(t.gpa);
        errdefer arena.deinit();
        const copy = try deepCopy(arena.allocator(), cfg);
        var map: std.StringHashMapUnmanaged(Choice) = .empty;
        for (copy.domains) |d| try map.put(arena.allocator(), d.suffix, d.choice);
        var members: [failover.max_members]proxy.Outbound = undefined;
        var n: usize = 0;
        for (copy.main) |i| {
            if (i >= copy.outbounds.len or n == members.len) continue;
            members[n] = copy.outbounds[i];
            n += 1;
        }
        t.cfg_mutex.lockUncancelable(t.io);
        defer t.cfg_mutex.unlock(t.io);
        // the group copies what it keeps, so the old arena can go
        t.group.set(members[0..n]);
        t.cfg_arena.deinit();
        t.cfg_arena = arena;
        t.cfg = copy;
        t.domain_map = map;
    }

    /// Index into the configuration's `main` list of the server in use.
    pub fn mainInUse(t: *Tunnel) usize {
        return t.group.activeIndex();
    }

    /// How often the group's server changed since the tunnel started.
    pub fn mainSwitches(t: *Tunnel) u32 {
        return t.group.switches.load(.monotonic);
    }

    /// The group moved to another server: flows through the old one would
    /// only time out, so they end now and the applications reconnect.
    fn onSwitch(ctx: *anyopaque) void {
        const t: *Tunnel = @ptrCast(@alignCast(ctx));
        t.main_mutex.lockUncancelable(t.io);
        for (t.main_conns.items) |key| t.stack.abortKey(key);
        t.main_mutex.unlock(t.io);
        t.udp_mutex.lockUncancelable(t.io);
        var it = t.sessions.valueIterator();
        while (it.next()) |x| x.*.closed.store(true, .release);
        t.udp_mutex.unlock(t.io);
    }

    fn holdMain(t: *Tunnel, conn: *tcp.Conn) bool {
        t.main_mutex.lockUncancelable(t.io);
        defer t.main_mutex.unlock(t.io);
        t.main_conns.append(t.gpa, conn.key) catch return false;
        return true;
    }

    fn dropMain(t: *Tunnel, conn: *tcp.Conn) void {
        t.main_mutex.lockUncancelable(t.io);
        defer t.main_mutex.unlock(t.io);
        for (t.main_conns.items, 0..) |x, i| {
            if (std.meta.eql(x, conn.key)) {
                _ = t.main_conns.swapRemove(i);
                return;
            }
        }
    }

    fn deepCopy(a: std.mem.Allocator, cfg: Config) !Config {
        const rules = try a.alloc(Rule, cfg.rules.len);
        for (cfg.rules, rules) |src, *dst| dst.* = .{ .app = try a.dupe(u8, src.app), .choice = src.choice };
        const obs = try a.alloc(proxy.Outbound, cfg.outbounds.len);
        for (cfg.outbounds, obs) |src, *dst| dst.* = try src.dupe(a);
        const ex = try a.alloc([]const u8, cfg.dns_exclusions.len);
        for (cfg.dns_exclusions, ex) |src, *dst| dst.* = try a.dupe(u8, src);
        const doms = try a.alloc(DomainRule, cfg.domains.len);
        for (cfg.domains, doms) |src, *dst| {
            const suffix = try a.dupe(u8, src.suffix);
            for (suffix) |*ch| ch.* = std.ascii.toLower(ch.*);
            dst.* = .{ .suffix = suffix, .choice = src.choice };
        }
        return .{ .default = cfg.default, .unknown = cfg.unknown, .rules = rules, .domains = doms, .outbounds = obs, .main = try a.dupe(u16, cfg.main), .dns_exclusions = ex, .drop_quic = cfg.drop_quic };
    }

    const Decision = struct {
        snap: proxy.Snapshot,
        /// through the group's server: its health is the group's business
        main: bool = false,
    };

    /// The identity a flow is counted under: the first of the chain.
    fn ownApp(chain: []const u8) []const u8 {
        return chain[0 .. std.mem.indexOfScalar(u8, chain, 0) orelse chain.len];
    }

    /// Where the traffic of `app` goes, as a snapshot safe to keep. `app`
    /// is the flow's identity chain (see `AppLookup`): its own rule wins,
    /// then the rule of the nearest application that started it, then the
    /// rule of the site `name` (the destination's name, when known). A site
    /// never takes an application with a rule elsewhere: one held to the
    /// VPN stays there whatever it connects to.
    fn decide(t: *Tunnel, app: ?[]const u8, name: ?[]const u8) Decision {
        t.cfg_mutex.lockUncancelable(t.io);
        defer t.cfg_mutex.unlock(t.io);
        var choice = if (app == null) t.cfg.unknown orelse t.cfg.default else t.cfg.default;
        var ruled = false;
        if (app) |chain| {
            var ids = std.mem.splitScalar(u8, chain, 0);
            found: while (ids.next()) |id| {
                if (id.len == 0) continue;
                for (t.cfg.rules) |r| {
                    if (std.mem.eql(u8, r.app, id)) {
                        choice = r.choice;
                        ruled = true;
                        break :found;
                    }
                }
            }
        }
        // a flow of unknown origin where those are held back (standby) may
        // be a held application's: a site may only block it further
        const held_unknown = app == null and t.cfg.unknown != null;
        if (!ruled) if (name) |n| if (t.domainChoice(n)) |site| {
            if (!held_unknown or site == .block) choice = site;
        };
        return switch (choice) {
            .direct => .{ .snap = .of(.direct) },
            .dpi => .{ .snap = .of(.dpi) },
            .block => .{ .snap = .of(.block) },
            .outbound => |i| .{ .snap = if (i < t.cfg.outbounds.len) .of(t.cfg.outbounds[i]) else .of(.block) },
            .main => if (t.group.current()) |s| .{ .snap = s, .main = true } else .{ .snap = .of(.block) },
        };
    }

    /// Whether a site's rule could decide where a flow of `app` goes: there
    /// are such rules, and the application has none of its own.
    fn sitesMayDecide(t: *Tunnel, app: ?[]const u8) bool {
        t.cfg_mutex.lockUncancelable(t.io);
        defer t.cfg_mutex.unlock(t.io);
        if (t.domain_map.count() == 0) return false;
        const chain = app orelse return t.cfg.unknown == null;
        var ids = std.mem.splitScalar(u8, chain, 0);
        while (ids.next()) |id| {
            for (t.cfg.rules) |rule| if (std.mem.eql(u8, rule.app, id)) return false;
        }
        return true;
    }

    /// How long a flow may take to say which site it wants.
    const sniff_ms = 400;

    /// The site named by the first bytes of `local` (a TLS ClientHello's
    /// server name, an HTTP Host), left unread for the flow; null when it
    /// says nothing in time or nothing of the kind.
    fn sniff(local: anytype) ?[]const u8 {
        const r = local.r;
        var waited: u32 = 0;
        while (true) {
            const have = r.buffered();
            const k, const need = sni.kind(have);
            switch (k) {
                .tls => if (have.len >= need or need > r.buffer.len) return if (sni.serverName(have)) |f| f.name else null,
                .http => if (std.mem.indexOf(u8, have, "\r\n\r\n") != null or have.len == r.buffer.len) return if (sni.httpHost(have)) |f| f.name else null,
                .other => return null,
                .incomplete => {},
            }
            if (waited >= sniff_ms) return null;
            if (!local.waitReadable(50)) {
                waited += 50;
                continue;
            }
            r.fillMore() catch return null;
        }
    }

    /// The rule of `name` or of the nearest site above it. The caller
    /// holds `cfg_mutex`.
    fn domainChoice(t: *Tunnel, name: []const u8) ?Choice {
        if (t.domain_map.count() == 0 or name.len == 0 or name.len > 253) return null;
        var buf: [253]u8 = undefined;
        const lower = std.ascii.lowerString(&buf, std.mem.trimEnd(u8, name, "."));
        var rest: []const u8 = lower;
        while (true) {
            if (t.domain_map.get(rest)) |site| return site;
            const dot = std.mem.indexOfScalar(u8, rest, '.') orelse return null;
            rest = rest[dot + 1 ..];
        }
    }

    fn appStats(t: *Tunnel, app: []const u8) ?*AppStats {
        t.apps_mutex.lockUncancelable(t.io);
        defer t.apps_mutex.unlock(t.io);
        if (t.apps.get(app)) |s| return s;
        if (t.apps.count() >= 4096) return null;
        const key = t.gpa.dupe(u8, app) catch return null;
        const s = t.gpa.create(AppStats) catch {
            t.gpa.free(key);
            return null;
        };
        s.* = .{};
        t.apps.put(t.gpa, key, s) catch {
            t.gpa.free(key);
            t.gpa.destroy(s);
            return null;
        };
        return s;
    }

    /// Visit per-application counters (for status reports).
    pub fn eachApp(t: *Tunnel, ctx: anytype, comptime f: fn (@TypeOf(ctx), []const u8, *const proxy.Meter) void) void {
        t.apps_mutex.lockUncancelable(t.io);
        defer t.apps_mutex.unlock(t.io);
        var it = t.apps.iterator();
        while (it.next()) |e| f(ctx, e.key_ptr.*, &e.value_ptr.*.meter);
    }

    fn findApp(t: *Tunnel, udp: bool, local: Endpoint, remote: Endpoint, buf: []u8) ?[]u8 {
        const l = t.lookup orelse return null;
        return l.find(l.ctx, udp, local, remote, buf);
    }

    // ------------------------------------------------------------ TCP

    fn onTcp(ctx: *anyopaque, conn: *tcp.Conn) bool {
        const t: *Tunnel = @ptrCast(@alignCast(ctx));
        if (t.stopping.load(.acquire)) return false;
        _ = t.workers.fetchAdd(1, .acq_rel);
        const th = std.Thread.spawn(.{ .stack_size = sys.stackSize(proxy.dial_stack_size) }, tcpWorker, .{ t, conn }) catch {
            _ = t.workers.fetchSub(1, .acq_rel);
            return false;
        };
        th.detach();
        return true;
    }

    fn tcpWorker(t: *Tunnel, conn: *tcp.Conn) void {
        defer _ = t.workers.fetchSub(1, .acq_rel);
        defer conn.release();
        var app_buf: [2048]u8 = undefined;
        const app = t.findApp(false, conn.local(), conn.remote(), &app_buf);
        const stats = if (app) |a| t.appStats(ownApp(a)) else null;

        const remote = conn.remote();
        var name_buf: [255]u8 = undefined;
        var target: proxy.Target = undefined;
        var name: ?[]const u8 = null;
        if (dns.isFake(&remote.addr)) {
            // a fake address from before a restart: make the app resolve again
            name = t.fake.lookup(&remote.addr, &name_buf) orelse return conn.reject();
            target = .fromDomain(name.?, remote.port);
        } else {
            target = .fromEndpoint(remote);
        }

        var rb: [tls13.min_read_buffer]u8 = undefined;
        var wb: [4096]u8 = undefined;
        var r: tcp.Reader = .init(conn, &rb);
        var w: tcp.Writer = .init(conn, &wb);
        var local: proxy.Local = .{ .r = &r.interface, .w = &w.interface, .end = .{ .tun = conn } };
        // to a real address, where a site's rule could apply: the name is
        // in the application's first bytes, which come only once it is
        // connected
        if (name == null and t.sitesMayDecide(app)) {
            local.ready() catch return;
            name = sniff(&local);
        }

        const where = t.decide(app, name);
        const ob = where.snap.get();
        // this flow's own counters tell the group how its server did
        var mine: proxy.Meter = .{};
        const flow: proxy.Flow = .{
            .io = t.io,
            .dialer = t.dialer,
            .meters = .{ &t.meter, if (stats) |s| &s.meter else null, if (where.main) &mine else null },
            .stop = &t.stopping,
        };
        const held = where.main and t.holdMain(conn);
        flow.run(&local, &target, &ob) catch {};
        if (held) t.dropMain(conn);
        if (where.main and !t.stopping.load(.acquire)) {
            if (mine.fault.load(.monotonic) != .none) {
                t.group.report(.dial_failed);
            } else if (mine.down.load(.monotonic) > 0) {
                t.group.report(.carried);
            } else if (mine.up.load(.monotonic) > 0) {
                t.group.report(.empty);
            }
        }
    }

    // ------------------------------------------------------------ UDP

    fn onUdp(ctx: *anyopaque, src: Endpoint, dst: Endpoint, payload: []const u8) void {
        const t: *Tunnel = @ptrCast(@alignCast(ctx));
        if (t.stopping.load(.acquire)) return;
        if (dst.port == 53) return t.dnsQuery(src, dst, payload);
        t.udpDatagram(src, dst, payload);
    }

    fn dnsQuery(t: *Tunnel, src: Endpoint, dst: Endpoint, query: []const u8) void {
        var out: [1500]u8 = undefined;
        const verdict = blk: {
            t.cfg_mutex.lockUncancelable(t.io);
            defer t.cfg_mutex.unlock(t.io);
            break :blk dns.answerLocally(&t.fake, query, &out, t.cfg.dns_exclusions);
        };
        switch (verdict) {
            .answered => |n| if (n > 0) t.stack.sendUdp(dst, src, out[0..n]),
            .forward => {
                if (t.dns_inflight.load(.acquire) >= 32) return; // the app will retry
                const copy = t.gpa.dupe(u8, query) catch return;
                _ = t.dns_inflight.fetchAdd(1, .acq_rel);
                const th = std.Thread.spawn(.{ .stack_size = sys.stackSize(64 * 1024) }, dnsForward, .{ t, src, dst, copy }) catch {
                    _ = t.dns_inflight.fetchSub(1, .acq_rel);
                    t.gpa.free(copy);
                    return;
                };
                th.detach();
            },
        }
    }

    fn dnsForward(t: *Tunnel, src: Endpoint, dst: Endpoint, query: []u8) void {
        defer _ = t.dns_inflight.fetchSub(1, .acq_rel);
        defer t.gpa.free(query);
        var out: [1500]u8 = undefined;
        const n = t.resolver.forward(query, &out) catch return;
        if (!t.stopping.load(.acquire)) t.stack.sendUdp(dst, src, out[0..n]);
    }

    const UdpKey = struct { app: Endpoint, remote: Endpoint };
    const EndpointContext = struct {
        pub fn hash(_: EndpointContext, e: Endpoint) u64 {
            var h = std.hash.Wyhash.init(2);
            h.update(&e.addr);
            h.update(std.mem.asBytes(&e.port));
            return h.final();
        }
        pub fn eql(_: EndpointContext, a: Endpoint, b: Endpoint) bool {
            return a.eql(b);
        }
    };
    const UdpKeyContext = struct {
        pub fn hash(_: UdpKeyContext, k: UdpKey) u64 {
            var h = std.hash.Wyhash.init(1);
            h.update(&k.app.addr);
            h.update(&k.remote.addr);
            h.update(std.mem.asBytes(&k.app.port));
            h.update(std.mem.asBytes(&k.remote.port));
            return h.final();
        }
        pub fn eql(_: UdpKeyContext, a: UdpKey, b: UdpKey) bool {
            return a.app.eql(b.app) and a.remote.eql(b.remote);
        }
    };

    /// A direct UDP flow (or, with no socket, a remembered "drop" decision).
    const UdpFlow = struct {
        tunnel: *Tunnel,
        key: UdpKey,
        sock: ?sys.Udp,
        stats: ?*AppStats,
        last_ms: std.atomic.Value(i64) = .init(0),
        closed: std.atomic.Value(bool) = .init(false),
    };

    const udp_idle_ms = 60_000;
    const dns_idle_ms = 10_000;

    fn nowMs(t: *Tunnel) i64 {
        return Io.Clock.awake.now(t.io).toMilliseconds();
    }

    fn dropQuic(t: *Tunnel) bool {
        t.cfg_mutex.lockUncancelable(t.io);
        defer t.cfg_mutex.unlock(t.io);
        return t.cfg.drop_quic;
    }

    fn udpDatagram(t: *Tunnel, src: Endpoint, dst: Endpoint, payload: []const u8) void {
        const key: UdpKey = .{ .app = src, .remote = dst };
        t.udp_mutex.lockUncancelable(t.io);
        if (t.udp.get(key)) |f| {
            t.udp_mutex.unlock(t.io);
            return t.udpSend(f, payload);
        }
        if (t.sessions.get(src)) |sess| {
            sess.enqueue(dst, payload);
            t.udp_mutex.unlock(t.io);
            return;
        }
        t.udp_mutex.unlock(t.io);

        // a new flow: find its application and its route once
        var app_buf: [2048]u8 = undefined;
        const app = t.findApp(true, src, dst, &app_buf);
        const stats = if (app) |a| t.appStats(ownApp(a)) else null;
        var name_buf: [255]u8 = undefined;
        const name = if (dns.isFake(&dst.addr)) t.fake.lookup(&dst.addr, &name_buf) else null;
        const snap = t.decide(app, name).snap;
        switch (snap.outbound) {
            .block => t.rememberDrop(key, stats),
            .direct => t.startDirect(key, payload, stats),
            // QUIC has its own ClientHello, unshaped: browsers fall back to
            // TCP, which this route shapes; other UDP goes as it is
            .dpi => if (dst.port == 443) t.rememberDrop(key, stats) else t.startDirect(key, payload, stats),
            // QUIC of proxied apps is dropped: browsers fall back to TCP,
            // which the servers carry far more efficiently
            .vless, .vmess, .trojan, .shadowsocks => if (dst.port == 443 and t.dropQuic())
                t.rememberDrop(key, stats)
            else
                t.startSession(src, dst, payload, snap, stats),
        }
    }

    fn rememberDrop(t: *Tunnel, key: UdpKey, stats: ?*AppStats) void {
        const flow = t.gpa.create(UdpFlow) catch return;
        flow.* = .{ .tunnel = t, .key = key, .sock = null, .stats = stats };
        flow.last_ms.store(t.nowMs(), .monotonic);
        t.udp_mutex.lockUncancelable(t.io);
        defer t.udp_mutex.unlock(t.io);
        t.udp.put(t.gpa, key, flow) catch t.gpa.destroy(flow);
    }

    fn startDirect(t: *Tunnel, key: UdpKey, payload: []const u8, stats: ?*AppStats) void {
        const dst = key.remote;
        var name_buf: [255]u8 = undefined;
        const addr: packet.Addr = if (dns.isFake(&dst.addr)) blk: {
            const name = t.fake.lookup(&dst.addr, &name_buf) orelse return;
            break :blk t.resolver.resolve(name) catch return;
        } else dst.addr;
        const flow = t.gpa.create(UdpFlow) catch return;
        flow.* = .{ .tunnel = t, .key = key, .sock = null, .stats = stats };
        flow.sock = sys.Udp.open(t.io, &addr, dst.port, t.dialer.bind) catch return t.gpa.destroy(flow);
        flow.last_ms.store(t.nowMs(), .monotonic);
        t.udp_mutex.lockUncancelable(t.io);
        t.udp.put(t.gpa, key, flow) catch {
            t.udp_mutex.unlock(t.io);
            flow.sock.?.close();
            return t.gpa.destroy(flow);
        };
        t.udp_mutex.unlock(t.io);
        _ = t.workers.fetchAdd(1, .acq_rel);
        const th = std.Thread.spawn(.{ .stack_size = sys.stackSize(128 * 1024) }, udpReader, .{ t, flow }) catch {
            _ = t.workers.fetchSub(1, .acq_rel);
            t.removeUdp(flow);
            return;
        };
        th.detach();
        t.udpSend(flow, payload);
    }

    fn udpSend(t: *Tunnel, f: *UdpFlow, payload: []const u8) void {
        f.last_ms.store(t.nowMs(), .monotonic);
        const s = f.sock orelse return; // a remembered drop
        s.send(payload) catch return;
        _ = t.meter.up.fetchAdd(payload.len, .monotonic);
        if (f.stats) |st| _ = st.meter.up.fetchAdd(payload.len, .monotonic);
    }

    /// Reads replies for one direct UDP flow; also the flow's idle timer.
    fn udpReader(t: *Tunnel, f: *UdpFlow) void {
        defer _ = t.workers.fetchSub(1, .acq_rel);
        const idle: i64 = if (f.key.remote.port == 53 or f.key.remote.port == 123) dns_idle_ms else udp_idle_ms;
        var buf: [65535]u8 = undefined;
        while (!f.closed.load(.acquire) and !t.stopping.load(.acquire)) {
            const n = f.sock.?.recv(&buf, 1000) catch |err| switch (err) {
                error.Timeout => 0,
                else => break,
            };
            if (n > 0) {
                f.last_ms.store(t.nowMs(), .monotonic);
                t.stack.sendUdp(f.key.remote, f.key.app, buf[0..n]);
                _ = t.meter.down.fetchAdd(n, .monotonic);
                if (f.stats) |st| _ = st.meter.down.fetchAdd(n, .monotonic);
            }
            if (t.nowMs() - f.last_ms.load(.monotonic) > idle) break;
        }
        t.removeUdp(f);
    }

    fn removeUdp(t: *Tunnel, f: *UdpFlow) void {
        t.udp_mutex.lockUncancelable(t.io);
        _ = t.udp.remove(f.key);
        t.udp_mutex.unlock(t.io);
        if (f.sock) |s| s.close();
        t.gpa.destroy(f);
    }

    /// Forget remembered drops that saw no traffic for a while.
    fn sweepUdp(t: *Tunnel) void {
        const now = t.nowMs();
        var stale: [64]*UdpFlow = undefined;
        var n: usize = 0;
        t.udp_mutex.lockUncancelable(t.io);
        var it = t.udp.valueIterator();
        while (it.next()) |fp| {
            const f = fp.*;
            if (f.sock == null and now - f.last_ms.load(.monotonic) > udp_idle_ms and n < stale.len) {
                stale[n] = f;
                n += 1;
            }
        }
        for (stale[0..n]) |f| _ = t.udp.remove(f.key);
        t.udp_mutex.unlock(t.io);
        for (stale[0..n]) |f| t.gpa.destroy(f);
    }

    fn closeAllUdp(t: *Tunnel) void {
        t.udp_mutex.lockUncancelable(t.io);
        defer t.udp_mutex.unlock(t.io);
        var it = t.udp.valueIterator();
        while (it.next()) |f| f.*.closed.store(true, .release);
        // XUDP sessions notice `stopping` within a second and close themselves
    }

    fn freeDrops(t: *Tunnel) void {
        t.udp_mutex.lockUncancelable(t.io);
        defer t.udp_mutex.unlock(t.io);
        var it = t.udp.valueIterator();
        while (it.next()) |f| {
            if (f.*.sock == null) t.gpa.destroy(f.*);
        }
        t.udp.clearRetainingCapacity();
    }

    fn startSession(t: *Tunnel, src: Endpoint, dst: Endpoint, payload: []const u8, snap: proxy.Snapshot, stats: ?*AppStats) void {
        const sess = t.gpa.create(UdpSession) catch return;
        sess.* = .{ .tunnel = t, .app = src, .stats = stats, .conn = udp_out.Conn.init(t.io, snap.get()) orelse return t.gpa.destroy(sess) };
        if (dst.port == 53 or dst.port == 123) sess.idle_ms = dns_idle_ms;
        sess.last_ms.store(t.nowMs(), .monotonic);
        sess.enqueue(dst, payload);
        t.udp_mutex.lockUncancelable(t.io);
        t.sessions.put(t.gpa, src, sess) catch {
            t.udp_mutex.unlock(t.io);
            return t.gpa.destroy(sess);
        };
        t.udp_mutex.unlock(t.io);
        _ = t.workers.fetchAdd(1, .acq_rel);
        const th = std.Thread.spawn(.{ .stack_size = sys.stackSize(proxy.dial_stack_size) }, UdpSession.uplink, .{sess}) catch {
            _ = t.workers.fetchSub(1, .acq_rel);
            sess.close();
            sess.release();
            return;
        };
        th.detach();
    }

    /// UDP of one application socket carried through a server (see
    /// udp_out.zig), to any number of destinations.
    const UdpSession = struct {
        tunnel: *Tunnel,
        app: Endpoint,
        stats: ?*AppStats,
        conn: udp_out.Conn,
        closed: std.atomic.Value(bool) = .init(false),
        /// threads still using this session (the uplink, then the downlink)
        refs: std.atomic.Value(u8) = .init(1),
        last_ms: std.atomic.Value(i64) = .init(0),
        idle_ms: i64 = udp_idle_ms,

        mutex: Io.Mutex = .init,
        cond: Io.Condition = .init,
        /// datagrams waiting for the uplink: [u16 len][16 addr][u16 port][payload]
        ring: [64 * 1024]u8 = undefined,
        head: usize = 0,
        used: usize = 0,
        /// where the application sent to, to name the source of replies
        dests: [16]Dest = undefined,
        ndests: usize = 0,

        const Dest = struct { app_dst: Endpoint, addr: xudp.Address, name: [255]u8 = undefined };

        fn ringPut(x: *UdpSession, bytes: []const u8) void {
            for (bytes, 0..) |b, i| x.ring[(x.head + x.used + i) % x.ring.len] = b;
            x.used += bytes.len;
        }

        fn ringTake(x: *UdpSession, out: []u8) void {
            for (out, 0..) |*b, i| b.* = x.ring[(x.head + i) % x.ring.len];
            x.head = (x.head + out.len) % x.ring.len;
            x.used -= out.len;
        }

        fn enqueue(x: *UdpSession, dst: Endpoint, payload: []const u8) void {
            if (payload.len > udp_out.max_payload) return;
            const io = x.tunnel.io;
            x.mutex.lockUncancelable(io);
            defer x.mutex.unlock(io);
            if (x.closed.load(.acquire) or x.ring.len - x.used < 20 + payload.len) return; // full: drop, as UDP may
            var hdr: [20]u8 = undefined;
            std.mem.writeInt(u16, hdr[0..2], @intCast(payload.len), .big);
            hdr[2..18].* = dst.addr;
            std.mem.writeInt(u16, hdr[18..20], dst.port, .big);
            x.ringPut(&hdr);
            x.ringPut(payload);
            x.cond.signal(io);
        }

        /// Next queued datagram, or null after `ms` without one.
        fn dequeue(x: *UdpSession, dst: *Endpoint, buf: []u8, ms: i64) ?usize {
            const io = x.tunnel.io;
            x.mutex.lockUncancelable(io);
            defer x.mutex.unlock(io);
            if (x.used == 0 and !x.closed.load(.acquire)) {
                x.cond.waitTimeout(io, &x.mutex, .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } }) catch {};
            }
            if (x.used < 20) return null;
            var hdr: [20]u8 = undefined;
            x.ringTake(&hdr);
            const len = std.mem.readInt(u16, hdr[0..2], .big);
            dst.* = .{ .addr = hdr[2..18].*, .port = std.mem.readInt(u16, hdr[18..20], .big) };
            x.ringTake(buf[0..len]);
            return len;
        }

        fn remember(x: *UdpSession, dst: Endpoint, addr: xudp.Address) void {
            const io = x.tunnel.io;
            x.mutex.lockUncancelable(io);
            defer x.mutex.unlock(io);
            for (x.dests[0..x.ndests]) |d| if (d.app_dst.eql(dst)) return;
            const slot = if (x.ndests < x.dests.len) blk: {
                x.ndests += 1;
                break :blk &x.dests[x.ndests - 1];
            } else &x.dests[x.dests.len - 1];
            slot.* = .{ .app_dst = dst, .addr = addr };
            if (addr == .domain) {
                @memcpy(slot.name[0..addr.domain.len], addr.domain);
                slot.addr = .{ .domain = slot.name[0..addr.domain.len] };
            }
        }

        /// The address a reply should appear to come from: the one the
        /// application sent to (possibly a fake IP), so connected sockets
        /// accept it.
        fn sourceFor(x: *UdpSession, from: ?udp_out.Peer) ?Endpoint {
            const io = x.tunnel.io;
            x.mutex.lockUncancelable(io);
            defer x.mutex.unlock(io);
            if (x.ndests == 0) return null;
            const f = from orelse return x.dests[0].app_dst;
            for (x.dests[0..x.ndests]) |d| {
                if (d.app_dst.port == f.port and d.addr.eql(f.addr)) return d.app_dst;
            }
            // the resolved address of a name we sent to on that port
            var only: ?Endpoint = null;
            var count: usize = 0;
            for (x.dests[0..x.ndests]) |d| if (d.addr == .domain and d.app_dst.port == f.port) {
                only = d.app_dst;
                count += 1;
            };
            if (count == 1) return only;
            return switch (f.addr) {
                .ip4 => |a| .{ .addr = packet.v4(a), .port = f.port },
                .ip6 => |a| .{ .addr = a, .port = f.port },
                .domain => x.dests[0].app_dst,
            };
        }

        fn close(x: *UdpSession) void {
            if (x.closed.swap(true, .acq_rel)) return;
            const t = x.tunnel;
            x.mutex.lockUncancelable(t.io);
            x.cond.broadcast(t.io);
            x.mutex.unlock(t.io);
            t.udp_mutex.lockUncancelable(t.io);
            if (t.sessions.get(x.app)) |cur| {
                if (cur == x) _ = t.sessions.remove(x.app);
            }
            t.udp_mutex.unlock(t.io);
            x.conn.close();
        }

        fn release(x: *UdpSession) void {
            if (x.refs.fetchSub(1, .acq_rel) != 1) return;
            x.conn.deinit();
            x.tunnel.gpa.destroy(x);
        }

        fn flow(x: *UdpSession) proxy.Flow {
            const t = x.tunnel;
            return .{ .io = t.io, .dialer = t.dialer, .meters = .{ &t.meter, if (x.stats) |st| &st.meter else null, null }, .stop = &t.stopping };
        }

        fn uplink(x: *UdpSession) void {
            const t = x.tunnel;
            defer _ = t.workers.fetchSub(1, .acq_rel);
            defer x.release();
            const f = x.flow();
            x.conn.open(&f) catch return x.close();
            _ = x.refs.fetchAdd(1, .acq_rel);
            _ = t.workers.fetchAdd(1, .acq_rel);
            const th = std.Thread.spawn(.{ .stack_size = sys.stackSize(128 * 1024) }, downlink, .{x}) catch {
                _ = x.refs.fetchSub(1, .acq_rel);
                _ = t.workers.fetchSub(1, .acq_rel);
                return x.close();
            };
            th.detach();
            x.sendLoop(&f) catch {};
            x.conn.finish();
            x.close();
        }

        fn sendLoop(x: *UdpSession, f: *const proxy.Flow) !void {
            const t = x.tunnel;
            var dg: [udp_out.max_payload]u8 = undefined;
            while (!x.closed.load(.acquire) and !t.stopping.load(.acquire)) {
                var dst: Endpoint = undefined;
                const n = x.dequeue(&dst, &dg, 1000) orelse {
                    if (t.nowMs() - x.last_ms.load(.monotonic) > x.idle_ms) break;
                    continue;
                };
                x.last_ms.store(t.nowMs(), .monotonic);
                var name_buf: [255]u8 = undefined;
                const addr: xudp.Address = if (dns.isFake(&dst.addr))
                    .{ .domain = t.fake.lookup(&dst.addr, &name_buf) orelse continue }
                else if (packet.isV4(&dst.addr))
                    .{ .ip4 = dst.addr[12..16].* }
                else
                    .{ .ip6 = dst.addr };
                x.remember(dst, addr);
                try x.conn.send(.{ .addr = addr, .port = dst.port }, dg[0..n]);
                f.up(n);
            }
        }

        fn downlink(x: *UdpSession) void {
            const t = x.tunnel;
            defer _ = t.workers.fetchSub(1, .acq_rel);
            defer x.release();
            x.recvLoop() catch {};
            x.close();
        }

        fn recvLoop(x: *UdpSession) !void {
            const t = x.tunnel;
            const f = x.flow();
            while (!x.closed.load(.acquire)) {
                const d = (try x.conn.recv(1000)) orelse {
                    // Shadowsocks has no end: only a quiet second
                    if (x.conn.kind == .shadowsocks) continue;
                    return;
                };
                x.last_ms.store(t.nowMs(), .monotonic);
                const src = x.sourceFor(d.from) orelse continue;
                t.stack.sendUdp(src, x.app, d.payload);
                f.down(d.payload.len);
            }
        }
    };

    // ------------------------------------------------------------ device

    fn writeOut(ctx: *anyopaque, pkt: []const u8) void {
        const t: *Tunnel = @ptrCast(@alignCast(ctx));
        const d = t.device orelse return;
        d.write(pkt);
    }

    /// Read packets from `dev` until `stop` is called. Blocks; run it on its own thread.
    pub fn run(t: *Tunnel, dev: *Device) void {
        t.device = dev;
        var buf: [65536 + 4]u8 = undefined;
        var last_sweep = t.nowMs();
        // Windows: whether the last batch stopped at its limit, and what
        // woke the loop (logged while busy, see below)
        var more = false;
        var woke: [3]u32 = @splat(0);
        var in_packets: u64 = 0;
        var full_batches: u32 = 0;
        // where the loop's time goes (Windows, logged while busy): reading
        // Wintun, the stack's input, its flush, its timers
        var spent: [4]i64 = @splat(0);
        while (!t.stopping.load(.acquire)) {
            var t0 = Io.Clock.awake.now(t.io).toNanoseconds();
            const wait = @min(t.stack.tick(), 10_000);
            if (comptime windows) {
                const t1 = Io.Clock.awake.now(t.io).toNanoseconds();
                spent[3] += @intCast(t1 - t0);
                t0 = t1;
            }
            if (t.nowMs() - last_sweep > 10_000) {
                last_sweep = t.nowMs();
                t.sweepUdp();
                t.group.tick();
                if (comptime windows) {
                    if (in_packets > 1000) std.log.scoped(.tun).info("woken by packets {d}, by time {d}; {d} packets in, {d} full batches, {d} dropped out; ms in read {d}, input {d}, flush {d}, tick {d}", .{
                        woke[0],                  woke[2],                  in_packets,               full_batches, dev.dropped.load(.monotonic),
                        @divTrunc(spent[0], 1_000_000), @divTrunc(spent[1], 1_000_000), @divTrunc(spent[2], 1_000_000), @divTrunc(spent[3], 1_000_000),
                    });
                    woke = @splat(0);
                    in_packets = 0;
                    full_batches = 0;
                    spent = @splat(0);
                }
                t0 = Io.Clock.awake.now(t.io).toNanoseconds();
            }
            if (comptime windows) {
                // Wintun sets its event only after a read found the ring
                // empty: after a batch that stopped at its limit, read on
                // at once instead of waiting for an event that may not come
                if (!more) {
                    woke[@intFromEnum(dev.wait(@intCast(wait)))] += 1;
                    t0 = Io.Clock.awake.now(t.io).toNanoseconds();
                }
                more = false;
                var batch: usize = 0;
                while (batch < 256) : (batch += 1) {
                    const pkt = dev.read(&buf) orelse break;
                    const t1 = Io.Clock.awake.now(t.io).toNanoseconds();
                    spent[0] += @intCast(t1 - t0);
                    if (pkt.len > 0) t.stack.input(pkt);
                    t0 = Io.Clock.awake.now(t.io).toNanoseconds();
                    spent[1] += @intCast(t0 - t1);
                } else {
                    more = true;
                    full_batches += 1;
                }
                in_packets += batch;
                if (batch > 0) t.stack.flush();
                spent[2] += @intCast(Io.Clock.awake.now(t.io).toNanoseconds() - t0);
                continue;
            }
            var fds = [2]c.pollfd{
                .{ .fd = dev.fd, .events = c.POLL.IN, .revents = 0 },
                .{ .fd = dev.wake[0], .events = c.POLL.IN, .revents = 0 },
            };
            const rc = c.poll(&fds, 2, @intCast(wait));
            if (rc < 0) continue;
            if (fds[1].revents != 0) {
                var drain: [64]u8 = undefined;
                _ = c.read(dev.wake[0], &drain, drain.len);
            }
            var batch: usize = 0;
            while (batch < 64) : (batch += 1) {
                const n = c.read(dev.fd, &buf, buf.len);
                if (n <= 0) break;
                const len: usize = @intCast(n);
                const pkt = if (dev.af_header) (if (len > 4) buf[4..len] else continue) else buf[0..len];
                t.stack.input(pkt);
            }
            if (batch > 0) t.stack.flush();
        }
    }

    /// Make `run` return.
    pub fn stop(t: *Tunnel) void {
        t.stopping.store(true, .release);
        const d = t.device orelse return;
        if (comptime windows) d.wake() else _ = c.write(d.wake[1], "x", 1);
    }
};

/// The TUN device: a file descriptor and its packet framing, or on
/// Windows a Wintun session.
pub const Device = if (windows) wintun.Device else PosixDevice;

const PosixDevice = struct {
    fd: c.fd_t,
    /// macOS utun: every packet carries a 4-byte address family in front
    af_header: bool,
    /// self-pipe to wake the reader
    wake: [2]c.fd_t,
    dropped: std.atomic.Value(u64) = .init(0),

    pub fn init(fd: c.fd_t, af_header: bool) !PosixDevice {
        var p: [2]c.fd_t = undefined;
        if (c.pipe(&p) != 0) return error.PipeFailed;
        const nb: c_int = @bitCast(@as(u32, @bitCast(c.O{ .NONBLOCK = true })));
        for ([_]c.fd_t{ fd, p[0], p[1] }) |f| {
            const fl = c.fcntl(f, c.F.GETFL);
            _ = c.fcntl(f, c.F.SETFL, fl | nb);
        }
        return .{ .fd = fd, .af_header = af_header, .wake = p };
    }

    pub fn deinit(d: *PosixDevice) void {
        _ = c.close(d.wake[0]);
        _ = c.close(d.wake[1]);
    }

    pub fn write(d: *PosixDevice, pkt: []const u8) void {
        if (pkt.len == 0) return;
        if (!d.af_header) {
            if (c.write(d.fd, pkt.ptr, pkt.len) < 0) _ = d.dropped.fetchAdd(1, .monotonic);
            return;
        }
        const af: u32 = if (pkt[0] >> 4 == 6) c.AF.INET6 else c.AF.INET;
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u32, &hdr, af, .big);
        const iov = [2]std.posix.iovec_const{
            .{ .base = &hdr, .len = 4 },
            .{ .base = pkt.ptr, .len = pkt.len },
        };
        if (c.writev(d.fd, &iov, 2) < 0) _ = d.dropped.fetchAdd(1, .monotonic);
    }
};

// ---------------------------------------------------------------- tests

test "routing: rule beats default, unknown outbound blocks" {
    const t = try Tunnel.create(std.testing.allocator, std.testing.io, .{});
    defer t.destroy();
    try t.setConfig(.{
        .default = .{ .outbound = 0 },
        .rules = &.{
            .{ .app = "/Applications/Steam.app", .choice = .direct },
            .{ .app = "/Applications/Bad.app", .choice = .{ .outbound = 9 } },
        },
        .outbounds = &.{.{ .vless = .{ .host = "nl.example", .port = 443, .uuid = @splat(1) } }},
    });
    try std.testing.expect(t.decide("/Applications/Steam.app", null).snap.outbound == .direct);
    try std.testing.expect(t.decide("/Applications/Other.app", null).snap.outbound == .vless);
    try std.testing.expectEqualStrings("nl.example", t.decide(null, null).snap.get().vless.host);
    try std.testing.expect(t.decide("/Applications/Bad.app", null).snap.outbound == .block);
    try std.testing.expect(!t.decide(null, null).main);
}

test "tunnel: QUIC is dropped whatever the protocol, not leaked" {
    const t = try Tunnel.create(std.testing.allocator, std.testing.io, .{});
    defer t.destroy();
    const link = "trojan://pw@tj.example:443";
    try t.setConfig(.{
        .default = .{ .outbound = 0 },
        .outbounds = &.{try proxy.outboundFromLink(link, "tj.example", 443)},
    });
    // the copy keeps nothing of the caller's strings
    try std.testing.expect(t.decide(null, null).snap.outbound == .trojan);
    try std.testing.expectEqualStrings("tj.example", t.decide(null, null).snap.get().trojan.host);

    const app: Endpoint = .{ .addr = packet.v4(.{ 198, 18, 0, 1 }), .port = 50000 };
    const there: Endpoint = .{ .addr = packet.v4(.{ 203, 0, 113, 9 }), .port = 443 };
    t.udpDatagram(app, there, "quic initial");
    t.udpDatagram(app, there, "quic again");
    t.udp_mutex.lockUncancelable(t.io);
    defer t.udp_mutex.unlock(t.io);
    // remembered as a drop: no socket of ours, no session to a server
    try std.testing.expectEqual(1, t.udp.count());
    try std.testing.expect(t.udp.get(.{ .app = app, .remote = there }).?.sock == null);
    try std.testing.expectEqual(0, t.sessions.count());
}

test "tunnel: sites take the applications without a rule, never the others" {
    const t = try Tunnel.create(std.testing.allocator, std.testing.io, .{});
    defer t.destroy();
    const obs = [_]proxy.Outbound{.{ .vless = .{ .host = "nl.example", .port = 443, .uuid = @splat(1) } }};
    try t.setConfig(.{
        .default = .{ .outbound = 0 },
        .rules = &.{
            .{ .app = "/Applications/Bank.app", .choice = .{ .outbound = 0 } },
            .{ .app = "/Applications/Game.app", .choice = .direct },
        },
        .domains = &.{
            .{ .suffix = "YouTube.com", .choice = .direct },
            .{ .suffix = "ads.example", .choice = .block },
            .{ .suffix = "work.example", .choice = .{ .outbound = 0 } },
        },
        .outbounds = &obs,
    });
    const browser = "/Applications/Browser.app";
    // a site and everything under it, in any case; its neighbours not
    try std.testing.expect(t.decide(browser, "youtube.com").snap.outbound == .direct);
    try std.testing.expect(t.decide(browser, "i.YTIMG.www.youtube.com.").snap.outbound == .direct);
    try std.testing.expect(t.decide(browser, "notyoutube.com").snap.outbound == .vless);
    try std.testing.expect(t.decide(browser, "com").snap.outbound == .vless);
    try std.testing.expect(t.decide(browser, "x.ads.example").snap.outbound == .block);
    try std.testing.expect(t.decide(browser, null).snap.outbound == .vless);
    // an application's own rule (or its parent's) is never overridden
    try std.testing.expect(t.decide("/Applications/Bank.app", "youtube.com").snap.outbound == .vless);
    try std.testing.expect(t.decide("/usr/bin/curl\x00/Applications/Bank.app", "youtube.com").snap.outbound == .vless);
    try std.testing.expect(t.decide("/Applications/Game.app", "work.example").snap.outbound == .direct);
    // a flow whose application is unknown follows the site
    try std.testing.expect(t.decide(null, "youtube.com").snap.outbound == .direct);

    // standby: unknown flows are held back; a site may block them, not let them out
    try t.setConfig(.{
        .default = .direct,
        .unknown = .block,
        .rules = &.{.{ .app = "/Applications/Bank.app", .choice = .block }},
        .domains = &.{
            .{ .suffix = "youtube.com", .choice = .direct },
            .{ .suffix = "work.example", .choice = .block },
        },
    });
    try std.testing.expect(t.decide(null, "youtube.com").snap.outbound == .block);
    try std.testing.expect(t.decide(null, "other.example").snap.outbound == .block);
    try std.testing.expect(t.decide(browser, "youtube.com").snap.outbound == .direct);
    try std.testing.expect(t.decide(browser, "work.example").snap.outbound == .block);
    try std.testing.expect(t.decide("/Applications/Bank.app", "youtube.com").snap.outbound == .block);
}

test "tunnel: the name a flow asks for, from its first bytes, as they come" {
    var hello_buf: [512]u8 = undefined;
    const hello = sni.testHello(&hello_buf, "video.example.org");
    // the whole ClientHello at once, in two pieces, and an HTTP request
    const Feed = struct {
        parts: []const []const u8,
        next: usize = 0,
        rbuf: [4096]u8 = undefined,
        reader: Io.Reader = undefined,
        r: *Io.Reader = undefined,

        fn init(f: *@This()) void {
            f.reader = .{ .vtable = &.{ .stream = stream }, .buffer = &f.rbuf, .seek = 0, .end = 0 };
            f.r = &f.reader;
        }
        fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
            const f: *@This() = @alignCast(@fieldParentPtr("reader", io_r));
            if (f.next == f.parts.len) return error.EndOfStream;
            const part = f.parts[f.next];
            f.next += 1;
            const dest = limit.slice(try w.writableSliceGreedy(1));
            @memcpy(dest[0..part.len], part);
            w.advance(part.len);
            return part.len;
        }
        pub fn waitReadable(f: *@This(), _: u32) bool {
            return f.next < f.parts.len;
        }
    };
    const cases = [_]struct { []const []const u8, ?[]const u8 }{
        .{ &.{hello}, "video.example.org" },
        .{ &.{ hello[0..3], hello[3..100], hello[100..] }, "video.example.org" },
        .{ &.{ "GET /x HTTP/1.1\r\nHost: plain.example\r\n", "Accept: */*\r\n\r\n" }, "plain.example" },
        .{ &.{"SSH-2.0-OpenSSH_9\r\n"}, null },
        // says nothing: the flow goes on without a name
        .{ &.{}, null },
    };
    for (cases) |case| {
        var f: Feed = .{ .parts = case[0] };
        f.init();
        const got = Tunnel.sniff(&f);
        if (case[1]) |want| try std.testing.expectEqualStrings(want, got.?) else try std.testing.expect(got == null);
        // nothing was consumed: the flow still sends it all
        if (case[0].len > 0) try std.testing.expect(f.r.buffered().len > 0);
    }
}

test "tunnel: a flow without a rule follows the application that started it" {
    const t = try Tunnel.create(std.testing.allocator, std.testing.io, .{});
    defer t.destroy();
    try t.setConfig(.{
        .default = .direct,
        .rules = &.{
            .{ .app = "/Applications/Claude.app", .choice = .block },
            .{ .app = "/Applications/Xcode.app", .choice = .{ .outbound = 0 } },
        },
        .outbounds = &.{.{ .vless = .{ .host = "nl.example", .port = 443, .uuid = @splat(1) } }},
    });
    // a tool run by a shell run by a new version of the CLI that Claude started
    try std.testing.expect(t.decide("/usr/bin/curl\x00/bin/zsh\x00/Users/a/claude-code/2.2.0/claude.app\x00/Applications/Claude.app", null).snap.outbound == .block);
    // its own rule comes first
    try std.testing.expect(t.decide("/Applications/Xcode.app\x00/bin/zsh\x00/Applications/Claude.app", null).snap.outbound == .vless);
    // nobody in the chain has a rule
    try std.testing.expect(t.decide("/usr/bin/curl\x00/bin/zsh\x00/Applications/Terminal.app", null).snap.outbound == .direct);
    try std.testing.expectEqualStrings("/usr/bin/curl", Tunnel.ownApp("/usr/bin/curl\x00/bin/zsh"));
}

test "tunnel: the main route uses the group's server and blocks without one" {
    const t = try Tunnel.create(std.testing.allocator, std.testing.io, .{});
    defer t.destroy();
    const obs = [_]proxy.Outbound{
        .{ .vless = .{ .host = "pinned.example", .port = 443, .uuid = @splat(1) } },
        .{ .vless = .{ .host = "main.example", .port = 443, .uuid = @splat(1) } },
        .{ .vless = .{ .host = "reserve.example", .port = 443, .uuid = @splat(1) } },
    };
    try t.setConfig(.{ .default = .main, .outbounds = &obs, .main = &.{ 1, 2 } });
    const d = t.decide(null, null);
    try std.testing.expect(d.main);
    try std.testing.expectEqualStrings("main.example", d.snap.get().vless.host);
    try std.testing.expectEqual(0, t.mainInUse());
    // no main server at all: the route blocks, it never goes direct
    try t.setConfig(.{ .default = .main, .outbounds = &obs });
    try std.testing.expect(t.decide(null, null).snap.outbound == .block);
}

test "DNS through the tunnel: fake answer goes back to the asking app" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest; // POSIX sockets and pipes
    const T = struct {
        var got: [512]u8 = undefined;
        var got_len: usize = 0;
    };
    const t = try Tunnel.create(std.testing.allocator, std.testing.io, .{});
    defer t.destroy();
    // capture what the stack writes instead of a device
    var p: [2]c.fd_t = undefined;
    try std.testing.expectEqual(0, c.pipe(&p));
    var dev: Device = try .init(p[1], false);
    defer {
        dev.deinit();
        _ = c.close(p[0]);
        _ = c.close(p[1]);
    }
    t.device = &dev;
    const app: Endpoint = .{ .addr = packet.v4(.{ 198, 18, 0, 1 }), .port = 5353 };
    const srv: Endpoint = .{ .addr = packet.v4(dns.server), .port = 53 };
    var q: [64]u8 = undefined;
    const query = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    @memcpy(q[0..query.len], query);
    var pkt: [256]u8 = undefined;
    const n = packet.writeUdp(&pkt, app, srv, q[0..query.len]);
    t.stack.input(pkt[0..n]);
    const m = c.read(p[0], &T.got, T.got.len);
    try std.testing.expect(m > 0);
    T.got_len = @intCast(m);
    const ip = packet.parseIp(T.got[0..T.got_len]).?;
    try std.testing.expectEqualSlices(u8, &srv.addr, &ip.src);
    const u = packet.parseUdp(ip.l4).?;
    try std.testing.expectEqual(5353, u.dst_port);
    const a, _ = dns.firstA(u.payload).?;
    try std.testing.expect(dns.isFake(&a));
    t.device = null;
}

test "tunnel: flows through the main server are forgotten when they end, also while the server changes" {
    const t = try Tunnel.create(std.testing.allocator, std.testing.io, .{});
    defer t.destroy();
    // nothing listens on port 1: every dial is refused at once
    const obs = [_]proxy.Outbound{.{ .vless = .{ .host = "127.0.0.1", .port = 1, .uuid = @splat(1) } }};
    try t.setConfig(.{ .default = .main, .outbounds = &obs, .main = &.{0} });
    const Quiet = struct {
        fn probe(_: *failover.Group, _: *const proxy.Outbound) bool {
            return false;
        }
        fn ping(_: *failover.Group, _: *const proxy.Outbound) ?u32 {
            return null;
        }
    };
    t.group.probe = Quiet.probe;
    t.group.ping = Quiet.ping;

    var pkt: [128]u8 = undefined;
    const there: Endpoint = .{ .addr = packet.v4(.{ 93, 184, 216, 34 }), .port = 443 };
    for (0..300) |i| {
        const me: Endpoint = .{ .addr = packet.v4(.{ 10, 0, 0, 2 }), .port = @intCast(20000 + i) };
        t.stack.input(pkt[0..packet.writeTcp(&pkt, me, there, .{ .seq = 1, .ack = 0, .flags = .{ .syn = true }, .window = 65535 })]);
        // the server changes in the middle of it all
        if (i % 7 == 0) Tunnel.onSwitch(t);
        if (i % 16 == 0) _ = t.stack.tick();
    }
    t.stack.flush();
    var spins: usize = 0;
    while (t.workers.load(.acquire) > 0 and spins < 5000) : (spins += 1) {
        Tunnel.onSwitch(t);
        _ = t.stack.tick();
        std.testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    }
    try std.testing.expectEqual(0, t.workers.load(.acquire));
    t.main_mutex.lockUncancelable(t.io);
    defer t.main_mutex.unlock(t.io);
    try std.testing.expectEqual(0, t.main_conns.items.len);
}
