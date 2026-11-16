//! BLACKWALL on Android: the core behind the Java shell.
//!
//! The shell (android/java) owns what only Android can give: the VpnService
//! and its TUN descriptor, the consent dialog, the list of installed
//! applications, downloads over the system's trust store. Everything else
//! lives here, in the same process: the configuration, the subscriptions,
//! the routes and the data plane.
//!
//! The two talk over one socket pair, a line of JSON per message, so the
//! native interface is a single function taking a descriptor (lib.zig) and
//! this file runs and is tested on any POSIX system.
//!
//! Shell -> core ("cmd"):
//!   init {dir}                    configuration folder; answered with the state
//!   state                         ask for the state again
//!   net {dns:[ip]}                resolvers of the network under the VPN
//!   add {text}                    subscription address or pasted keys
//!   body {id, text?}              a subscription's download (no text: it failed)
//!   refresh                       download every subscription again
//!   remove {id}                   forget a subscription
//!   select {id}                   server for the main route (0: the fastest)
//!   star {id}                     toggle a server's place in the reserve
//!   rule {app, name, route, id}   route of an application: default, vpn,
//!                                 direct, block, server (+ id)
//!   set {key, on | value}         failover, guard, ipv6
//!   ping                          measure every server
//!   connect / disconnect          the user's switch; answered with a plan
//!   up {fd, mtu}                  the TUN the shell established for the plan
//!   down                          the plan needs no TUN: close the one in use
//!   stop                          the VPN was revoked: nothing is held any more
//!   owner {q, apps:[package]}     answer to an "owner" question
//!
//! Core -> shell ("ev"):
//!   state    servers, subscriptions, rules, settings (no links, no
//!            subscription addresses: the shell never needs the secrets)
//!   plan     what the VpnService must look like now: need, standby, only /
//!            except (packages), ipv6, mtu
//!   fetch    {id, url}: download this subscription and send its body
//!   status   once a second while the TUN is up: counters, server in use
//!   owner    {q, udp, la, lp, ra, rp}: which application owns this flow
//!   note     {kind, n, skipped}: something to tell the user once
//!
//! How Android's own per-application VPN does most of the routing work:
//! applications sent "direct" are left out of the VPN altogether, and while
//! the VPN is off but applications must stay held (standby), only those
//! applications are let in, where everything is refused. The owner of a
//! flow is asked for only when rules differ inside the tunnel (a pinned
//! server, or no network).

const std = @import("std");
const builtin = @import("builtin");
const core = @import("core");
const routes = @import("routes");

const Io = std.Io;
const c = std.c;
const model = core.model;
const tunnel = core.tunnel;
const proxy = core.proxy;
const packet = core.ipstack.packet;
const dns = core.ipstack.dns;

const log = std.log.scoped(.android);

const Cmd = struct {
    cmd: []const u8,
    dir: []const u8 = "",
    text: ?[]const u8 = null,
    id: u32 = 0,
    app: []const u8 = "",
    apps: []const []const u8 = &.{},
    name: []const u8 = "",
    route: []const u8 = "",
    key: []const u8 = "",
    on: bool = false,
    value: []const u8 = "",
    fd: i32 = -1,
    mtu: u16 = 1500,
    dns: []const []const u8 = &.{},
    q: u32 = 0,
};

/// Questions to the shell about who owns a flow, and what it answered.
const Owners = struct {
    mutex: Io.Mutex = .init,
    cond: Io.Condition = .init,
    next: u32 = 1,
    /// lookups return at once: the tunnel is going away
    closed: bool = true,
    slots: [slot_count]Slot = @splat(.{}),
    cache: [cache_count]Known = @splat(.{}),
    cache_next: usize = 0,

    const slot_count = 16;
    const cache_count = 64;
    const wait_ms = 300;
    /// a source port is not reused by another application this quickly
    const keep_ms = 5000;
    const id_max = 512;

    const Slot = struct {
        q: u32 = 0,
        done: bool = false,
        len: u16 = 0,
        id: [id_max]u8 = undefined,
    };

    const Known = struct {
        udp: bool = false,
        port: u16 = 0,
        until_ms: i64 = 0,
        len: u16 = 0,
        id: [id_max]u8 = undefined,
    };

    fn cached(o: *Owners, udp: bool, port: u16, now: i64) ?*const Known {
        for (&o.cache) |*k| {
            if (k.until_ms > now and k.port == port and k.udp == udp) return k;
        }
        return null;
    }

    fn remember(o: *Owners, udp: bool, port: u16, now: i64, id: []const u8) void {
        const k = &o.cache[o.cache_next];
        o.cache_next = (o.cache_next + 1) % cache_count;
        k.* = .{ .udp = udp, .port = port, .until_ms = now + keep_ms, .len = @intCast(id.len) };
        @memcpy(k.id[0..id.len], id);
    }
};

pub const Session = struct {
    gpa: std.mem.Allocator,
    io: Io,
    /// the socket to the shell
    fd: c.fd_t,
    out_mutex: Io.Mutex = .init,
    /// the state and the tunnel
    mutex: Io.Mutex = .init,
    dir: []u8 = &.{},
    state: model.State,
    /// the user wants the VPN (or its guard) up; plans follow the changes
    active: bool = false,
    /// the plan the shell was last given, to tell when it must set up anew
    plan_hash: u64 = 0,

    t: ?*tunnel.Tunnel = null,
    device: tunnel.Device = undefined,
    device_thread: ?std.Thread = null,
    built: ?routes.Built = null,
    tun_fd: c.fd_t = -1,

    upstream: [4]packet.Endpoint = undefined,
    upstream_len: usize = 0,

    owners: Owners = .{},
    /// some rule differs inside the tunnel, so flows are asked about; it
    /// follows the rules while the tunnel is up
    ask_owners: std.atomic.Value(bool) = .init(false),
    probing: bool = false,
    ticker: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),

    pub fn init(gpa: std.mem.Allocator, io: Io, fd: c.fd_t) Session {
        return .{ .gpa = gpa, .io = io, .fd = fd, .state = .init(gpa) };
    }

    /// Serve the shell until it closes the socket.
    pub fn run(s: *Session) void {
        s.ticker = std.Thread.spawn(.{ .stack_size = core.sys.stackSize(256 * 1024) }, tick, .{s}) catch null;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(s.gpa);
        var chunk: [16 * 1024]u8 = undefined;
        reading: while (true) {
            const n = c.read(s.fd, &chunk, chunk.len);
            if (n < 0 and c.errno(n) == .INTR) continue;
            if (n <= 0) break;
            buf.appendSlice(s.gpa, chunk[0..@intCast(n)]) catch break;
            while (std.mem.indexOfScalar(u8, buf.items, '\n')) |end| {
                s.handle(buf.items[0..end]);
                const rest = buf.items.len - end - 1;
                std.mem.copyForwards(u8, buf.items[0..rest], buf.items[end + 1 ..]);
                buf.shrinkRetainingCapacity(rest);
            }
            // a pasted subscription can be large; nothing honest is larger
            if (buf.items.len > line_max) break :reading;
        }
        s.stopping.store(true, .release);
        if (s.ticker) |th| th.join();
        s.mutex.lockUncancelable(s.io);
        s.tearDown();
        s.mutex.unlock(s.io);
    }

    const line_max = 8 << 20;

    pub fn deinit(s: *Session) void {
        s.state.deinit();
        s.gpa.free(s.dir);
    }

    // ------------------------------------------------------------ output

    fn emit(s: *Session, value: anytype) void {
        const line = std.json.Stringify.valueAlloc(s.gpa, value, .{}) catch return;
        defer s.gpa.free(line);
        s.out_mutex.lockUncancelable(s.io);
        defer s.out_mutex.unlock(s.io);
        writeAll(s.fd, line);
        writeAll(s.fd, "\n");
    }

    fn writeAll(fd: c.fd_t, bytes: []const u8) void {
        var off: usize = 0;
        while (off < bytes.len) {
            const n = c.send(fd, bytes.ptr + off, bytes.len - off, send_flags);
            if (n < 0 and c.errno(n) == .INTR) continue;
            if (n <= 0) return;
            off += @intCast(n);
        }
    }

    /// A shell that is gone must not take the process down with SIGPIPE.
    const send_flags: u32 = if (builtin.os.tag == .linux) c.MSG.NOSIGNAL else 0;

    fn note(s: *Session, kind: []const u8, n: usize, skipped: usize) void {
        s.emit(.{ .ev = "note", .kind = kind, .n = n, .skipped = skipped });
    }

    // ------------------------------------------------------------ commands

    fn handle(s: *Session, line: []const u8) void {
        const parsed = std.json.parseFromSlice(Cmd, s.gpa, line, .{ .ignore_unknown_fields = true }) catch {
            log.warn("a message from the shell was not understood", .{});
            return;
        };
        defer parsed.deinit();
        const m = parsed.value;
        const is = struct {
            fn f(a: []const u8, b: []const u8) bool {
                return std.mem.eql(u8, a, b);
            }
        }.f;

        // answers to the tunnel's questions must not wait behind the state
        if (is(m.cmd, "owner")) return s.answer(m.q, m.apps);

        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        if (is(m.cmd, "init")) {
            s.gpa.free(s.dir);
            s.dir = s.gpa.dupe(u8, m.dir) catch &.{};
            _ = core.store.load(s.gpa, s.io, s.dir, &s.state) catch |err| log.warn("configuration not readable: {t}", .{err});
            // what was up when the process went away is the shell's to restore
            s.refreshCarried();
            s.sendState();
        } else if (is(m.cmd, "state")) {
            s.sendState();
        } else if (is(m.cmd, "net")) {
            s.setUpstream(m.dns);
        } else if (is(m.cmd, "add")) {
            s.add(m.text orelse "");
        } else if (is(m.cmd, "body")) {
            s.applyFetched(m.id, m.text);
        } else if (is(m.cmd, "refresh")) {
            for (s.state.subs.items) |sub| {
                if (sub.url.len > 0) s.emit(.{ .ev = "fetch", .id = sub.id, .url = sub.url });
            }
        } else if (is(m.cmd, "remove")) {
            s.state.removeSubscription(m.id);
            s.changed();
        } else if (is(m.cmd, "select")) {
            s.state.settings.selected_server = if (m.id == 0) null else m.id;
            s.changed();
        } else if (is(m.cmd, "star")) {
            if (s.state.serverById(m.id)) |sv| sv.favorite = !sv.favorite;
            s.changed();
        } else if (is(m.cmd, "rule")) {
            s.setRule(m);
        } else if (is(m.cmd, "set")) {
            s.setSetting(m);
        } else if (is(m.cmd, "ping")) {
            s.probeAll();
            s.sendState();
        } else if (is(m.cmd, "connect")) {
            s.active = true;
            s.state.settings.standby = false;
            s.save();
            _ = s.sendPlan(true);
            s.sendState();
        } else if (is(m.cmd, "disconnect")) {
            // applications that may only use the VPN stay held after it
            const hold = s.state.settings.protect_when_off and s.state.hasProtectedApps();
            s.active = hold;
            s.state.settings.standby = hold;
            s.save();
            _ = s.sendPlan(true);
            s.sendState();
        } else if (is(m.cmd, "up")) {
            s.up(m.fd, m.mtu);
        } else if (is(m.cmd, "stop")) {
            // the VPN was taken away (another VPN, the system's switch):
            // nothing can be held, and nothing is set up again
            s.active = false;
            s.state.settings.standby = false;
            s.plan_hash = 0;
            s.save();
            s.tearDown();
            s.emit(.{ .ev = "status", .up = false });
            s.sendState();
        } else if (is(m.cmd, "down")) {
            s.tearDown();
            s.emit(.{ .ev = "status", .up = false });
        } else {
            log.warn("unknown message from the shell: {s}", .{m.cmd});
        }
    }

    /// The state changed: keep it, show it, and bring the VPN in line.
    fn changed(s: *Session) void {
        s.save();
        // a change the VpnService itself must reflect ends in a new TUN;
        // anything else is only a new routing table
        if (s.active and !s.sendPlan(false)) s.applyRoutes();
        // last: what the shell shows is already in force
        s.sendState();
    }

    fn save(s: *Session) void {
        if (s.dir.len == 0) return;
        core.store.save(s.gpa, s.io, s.dir, &s.state) catch |err| log.warn("configuration not saved: {t}", .{err});
    }

    fn refreshCarried(s: *Session) void {
        for (s.state.servers.items) |*sv| {
            sv.carried = if (proxy.outboundFromLink(sv.link, sv.host, sv.port)) |_| true else |_| false;
        }
    }

    fn setUpstream(s: *Session, list: []const []const u8) void {
        s.upstream_len = 0;
        for (list) |text| {
            if (s.upstream_len == s.upstream.len) break;
            const ip = Io.net.IpAddress.parse(text, 53) catch continue;
            const a, _ = core.sys.fromIpAddress(ip);
            // the tunnel's resolver speaks IPv4
            if (!packet.isV4(&a)) continue;
            s.upstream[s.upstream_len] = .{ .addr = a, .port = 53 };
            s.upstream_len += 1;
        }
    }

    fn add(s: *Session, raw: []const u8) void {
        const input = std.mem.trim(u8, raw, " \t\r\n");
        if (input.len == 0) return s.note("empty", 0, 0);
        const is_url = std.ascii.startsWithIgnoreCase(input, "https://") or std.ascii.startsWithIgnoreCase(input, "http://");
        if (is_url) {
            const sub = s.state.addSubscription(hostOf(input), input) catch return;
            const id = sub.id;
            s.save();
            s.sendState();
            s.emit(.{ .ev = "fetch", .id = id, .url = input });
            return;
        }
        var parsed = core.sublink.parseBody(s.gpa, input) catch return s.note("empty", 0, 0);
        defer parsed.deinit();
        var sub_id: ?u32 = null;
        for (s.state.subs.items) |sub| {
            if (sub.url.len == 0) sub_id = sub.id;
        }
        if (sub_id == null) sub_id = (s.state.addSubscription("", "") catch return).id;
        for (parsed.servers) |n| _ = s.state.addServer(sub_id.?, n) catch return;
        s.refreshCarried();
        s.note("added", parsed.servers.len, parsed.unsupported + parsed.malformed);
        s.probeAll();
        s.changed();
    }

    fn applyFetched(s: *Session, sub_id: u32, body: ?[]const u8) void {
        const sub = s.state.subById(sub_id) orelse return;
        const bytes = body orelse {
            sub.last_error = true;
            s.note("failed", 0, 0);
            return s.sendState();
        };
        var parsed = core.sublink.parseBody(s.gpa, bytes) catch {
            sub.last_error = true;
            s.note("empty", 0, 0);
            return s.sendState();
        };
        defer parsed.deinit();
        s.state.applySubscription(sub_id, parsed.servers) catch return;
        s.refreshCarried();
        if (s.state.subById(sub_id)) |s2| {
            s2.last_error = false;
            s2.updated_unix = Io.Clock.real.now(s.io).toSeconds();
        }
        s.note("updated", parsed.servers.len, parsed.unsupported + parsed.malformed);
        s.probeAll();
        s.changed();
    }

    fn setRule(s: *Session, m: Cmd) void {
        if (m.app.len == 0) return;
        const route: model.Route = if (std.mem.eql(u8, m.route, "vpn"))
            .auto
        else if (std.mem.eql(u8, m.route, "direct"))
            .direct
        else if (std.mem.eql(u8, m.route, "block"))
            .block
        else if (std.mem.eql(u8, m.route, "server"))
            .{ .server = m.id }
        else
            .default;
        const app = s.state.addApp(m.app, if (m.name.len > 0) m.name else m.app, "") catch return;
        app.route = route;
        s.changed();
    }

    fn setSetting(s: *Session, m: Cmd) void {
        const st = &s.state.settings;
        if (std.mem.eql(u8, m.key, "failover")) {
            st.failover = m.on;
        } else if (std.mem.eql(u8, m.key, "guard")) {
            st.protect_when_off = m.on;
        } else if (std.mem.eql(u8, m.key, "ipv6")) {
            st.ipv6 = std.meta.stringToEnum(model.Ipv6Mode, m.value) orelse return;
        } else if (std.mem.eql(u8, m.key, "default")) {
            st.default_route = if (std.mem.eql(u8, m.value, "direct")) .direct else .auto;
        } else return;
        s.changed();
    }

    // ------------------------------------------------------------ state for the shell

    fn sendState(s: *Session) void {
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const Sv = struct { id: u32, sub: u32, name: []const u8, proto: []const u8, cc: []const u8, ping: ?u16, pinging: bool, star: bool, ok: bool };
        const Sub = struct { id: u32, name: []const u8, link: bool, failed: bool, updated: i64 };
        const Rule = struct { app: []const u8, route: []const u8, id: u32 };
        var servers: std.ArrayList(Sv) = .empty;
        var subs: std.ArrayList(Sub) = .empty;
        var rules: std.ArrayList(Rule) = .empty;
        for (s.state.servers.items) |*sv| servers.append(a, .{
            .id = sv.id,
            .sub = sv.sub_id,
            .name = sv.name,
            .proto = sv.protocol.label(),
            .cc = &sv.country,
            .ping = sv.ping_ms,
            .pinging = sv.ping_state == .testing,
            .star = sv.favorite,
            .ok = sv.available and sv.carried,
        }) catch return;
        for (s.state.subs.items) |sub| subs.append(a, .{
            .id = sub.id,
            .name = sub.name,
            .link = sub.url.len > 0,
            .failed = sub.last_error,
            .updated = sub.updated_unix,
        }) catch return;
        for (s.state.apps.items) |app| {
            if (app.route == .default) continue;
            rules.append(a, .{
                .app = app.id,
                .route = switch (app.route) {
                    .auto => "vpn",
                    .direct, .dpi => "direct",
                    .block => "block",
                    .server => "server",
                    .default => unreachable,
                },
                .id = if (app.route == .server) app.route.server else 0,
            }) catch return;
        }
        const st = s.state.settings;
        const cur = s.state.currentServer();
        s.emit(.{
            .ev = "state",
            .servers = servers.items,
            .subs = subs.items,
            .rules = rules.items,
            .selected = st.selected_server orelse 0,
            .current = if (cur) |sv| sv.id else 0,
            .failover = st.failover,
            .guard = st.protect_when_off,
            .ipv6 = @tagName(st.ipv6),
            .direct = st.default_route == .direct,
            .standby = st.standby,
            .active = s.active,
            .probing = s.probing,
        });
    }

    /// What the VpnService must look like. Returns whether the shell was
    /// told to set up anew (always when `force`).
    fn sendPlan(s: *Session, force: bool) bool {
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const st = s.state.settings;
        var only: std.ArrayList([]const u8) = .empty;
        var except: std.ArrayList([]const u8) = .empty;
        // without a default through the VPN only the applications with a
        // rule of their own enter it, as in standby
        const narrow = st.standby or st.default_route == .direct or st.default_route == .dpi;
        for (s.state.apps.items) |app| switch (app.route) {
            .auto, .server, .block => if (narrow) only.append(a, app.id) catch return false,
            .direct, .dpi => if (!narrow) except.append(a, app.id) catch return false,
            .default => {},
        };
        const need = s.active and (!narrow or only.items.len > 0);
        const mtu: u16 = if (st.mtu >= 1280) st.mtu else 1500;

        var h = std.hash.Wyhash.init(0);
        h.update(&.{ @intFromBool(need), @intFromBool(narrow), @intFromEnum(st.ipv6) });
        h.update(std.mem.asBytes(&mtu));
        for (only.items) |p| {
            h.update(p);
            h.update(&.{0});
        }
        h.update(&.{1});
        for (except.items) |p| {
            h.update(p);
            h.update(&.{0});
        }
        const hash = h.final();
        if (!force and hash == s.plan_hash) return false;
        s.plan_hash = hash;
        s.emit(.{
            .ev = "plan",
            .need = need,
            .standby = st.standby,
            .only = only.items,
            .except = except.items,
            .ipv6 = @tagName(st.ipv6),
            .mtu = mtu,
        });
        return true;
    }

    // ------------------------------------------------------------ the tunnel

    /// Whether flows inside the tunnel are treated differently by application.
    fn needsOwners(s: *Session) bool {
        if (s.state.settings.standby) return false;
        for (s.state.apps.items) |app| switch (app.route) {
            .server, .block => return true,
            else => {},
        };
        // a default that goes direct lets in only applications with rules,
        // all of which use the main server unless the above said otherwise
        return false;
    }

    fn up(s: *Session, fd: c.fd_t, mtu: u16) void {
        s.tearDown();
        if (fd < 0) return;
        s.start(fd, mtu) catch |err| {
            log.err("tunnel not started: {t}", .{err});
            _ = c.close(fd);
            s.emit(.{ .ev = "status", .up = false, .failed = true });
        };
    }

    fn start(s: *Session, fd: c.fd_t, mtu: u16) !void {
        var b = try routes.build(s.gpa, &s.state);
        errdefer b.deinit();
        s.ask_owners.store(s.needsOwners(), .release);
        const t = try tunnel.Tunnel.create(s.gpa, s.io, .{
            .mtu = mtu,
            // our own package is left out of the VPN, so plain sockets do
            .bind = .none,
            .upstream_dns = s.upstream[0..s.upstream_len],
            // always there: a rule made later must hold without a new tunnel
            .lookup = .{ .ctx = s, .find = findApp },
        });
        errdefer t.destroy();
        try t.setConfig(b.cfg);
        s.device = try .init(fd, false);
        errdefer s.device.deinit();
        s.owners.mutex.lockUncancelable(s.io);
        s.owners.closed = false;
        s.owners.mutex.unlock(s.io);
        s.device_thread = try std.Thread.spawn(.{ .stack_size = core.sys.stackSize(512 * 1024) }, tunnel.Tunnel.run, .{ t, &s.device });
        s.t = t;
        s.built = b;
        s.tun_fd = fd;
        if (s.state.settings.standby)
            log.info("tun up: standby, the applications with a rule are held", .{})
        else
            log.info("tun up: {d} servers, {d} rules, {d} in reserve, {d} not supported", .{ b.cfg.outbounds.len, b.cfg.rules.len, b.cfg.main.len -| 1, b.skipped });
    }

    fn tearDown(s: *Session) void {
        const t = s.t orelse return;
        // nobody waits for the shell while the tunnel is being stopped
        s.owners.mutex.lockUncancelable(s.io);
        s.owners.closed = true;
        s.owners.cond.broadcast(s.io);
        s.owners.mutex.unlock(s.io);
        t.stop();
        if (s.device_thread) |th| th.join();
        t.destroy();
        s.device.deinit();
        _ = c.close(s.tun_fd);
        if (s.built) |*b| b.deinit();
        s.t = null;
        s.built = null;
        s.device_thread = null;
        s.tun_fd = -1;
    }

    /// New routes for a tunnel that stays up.
    fn applyRoutes(s: *Session) void {
        const t = s.t orelse return;
        var b = routes.build(s.gpa, &s.state) catch return;
        // before the routes: a rule that needs the owner must find it asked for
        if (s.needsOwners()) s.ask_owners.store(true, .release);
        t.setConfig(b.cfg) catch {
            b.deinit();
            return;
        };
        s.ask_owners.store(s.needsOwners(), .release);
        if (s.built) |*old| old.deinit();
        s.built = b;
    }

    fn tick(s: *Session) void {
        while (!s.stopping.load(.acquire)) {
            s.io.sleep(.fromMilliseconds(1000), .awake) catch {};
            s.mutex.lockUncancelable(s.io);
            defer s.mutex.unlock(s.io);
            const t = s.t orelse continue;
            const b = s.built orelse continue;
            const i = t.mainInUse();
            s.emit(.{
                .ev = "status",
                .up = true,
                .standby = s.state.settings.standby,
                .down = t.meter.down.load(.monotonic),
                .sent = t.meter.up.load(.monotonic),
                .active = t.meter.active.load(.monotonic),
                .server = if (i < b.cfg.main.len) b.ids[b.cfg.main[i]] else 0,
                .switches = t.mainSwitches(),
                .fault = @tagName(t.meter.fault.swap(.none, .monotonic)),
            });
        }
    }

    // ------------------------------------------------------------ who owns a flow

    fn findApp(ctx: *anyopaque, udp: bool, local: packet.Endpoint, remote: packet.Endpoint, buf: []u8) ?[]u8 {
        const s: *Session = @ptrCast(@alignCast(ctx));
        // every flow is treated alike: nobody needs to be asked
        if (!s.ask_owners.load(.acquire)) return null;
        const o = &s.owners;
        const now = Io.Clock.awake.now(s.io).toMilliseconds();
        o.mutex.lockUncancelable(s.io);
        defer o.mutex.unlock(s.io);
        if (o.closed) return null;
        if (o.cached(udp, local.port, now)) |k| return copyOut(buf, k.id[0..k.len]);
        const slot = for (&o.slots) |*sl| {
            if (sl.q == 0) break sl;
        } else return null;
        const q = o.next;
        o.next +%= 1;
        if (o.next == 0) o.next = 1;
        slot.* = .{ .q = q };
        defer slot.q = 0;

        var la: [48]u8 = undefined;
        var ra: [48]u8 = undefined;
        o.mutex.unlock(s.io);
        s.emit(.{ .ev = "owner", .q = q, .udp = udp, .la = addrText(&la, &local.addr), .lp = local.port, .ra = addrText(&ra, &remote.addr), .rp = remote.port });
        o.mutex.lockUncancelable(s.io);

        const deadline = now + Owners.wait_ms;
        while (!slot.done and !o.closed) {
            const left = deadline - Io.Clock.awake.now(s.io).toMilliseconds();
            if (left <= 0) break;
            o.cond.waitTimeout(s.io, &o.mutex, .{ .duration = .{ .raw = .fromMilliseconds(left), .clock = .awake } }) catch {};
        }
        if (!slot.done) return null;
        const id = slot.id[0..slot.len];
        o.remember(udp, local.port, now, id);
        return copyOut(buf, id);
    }

    fn copyOut(buf: []u8, id: []const u8) ?[]u8 {
        if (id.len == 0 or id.len > buf.len) return null;
        @memcpy(buf[0..id.len], id);
        return buf[0..id.len];
    }

    /// The shell's answer: the packages of the flow's owner (none when it
    /// does not know), kept as the identity chain the tunnel's rules read.
    fn answer(s: *Session, q: u32, apps: []const []const u8) void {
        const o = &s.owners;
        o.mutex.lockUncancelable(s.io);
        defer o.mutex.unlock(s.io);
        for (&o.slots) |*sl| {
            if (sl.q != q or q == 0) continue;
            var len: usize = 0;
            for (apps) |p| {
                if (p.len == 0 or len + p.len + 1 > sl.id.len) continue;
                if (len > 0) {
                    sl.id[len] = 0;
                    len += 1;
                }
                @memcpy(sl.id[len..][0..p.len], p);
                len += p.len;
            }
            sl.len = @intCast(len);
            sl.done = true;
            o.cond.broadcast(s.io);
            return;
        }
    }

    // ------------------------------------------------------------ latency

    const Target = struct { id: u32, host: []u8, port: u16 };

    const ProbeJob = struct {
        s: *Session,
        targets: []Target,
        next: std.atomic.Value(usize) = .init(0),
        left: std.atomic.Value(usize),
        servers: [4]packet.Endpoint,
        servers_len: usize,
    };

    const probe_workers = 4;
    const probe_timeout_ms = 2500;

    /// Time to connect to every server, a few at a time. Our own sockets
    /// never enter the VPN, so this measures the servers themselves.
    fn probeAll(s: *Session) void {
        if (s.probing) return;
        var list: std.ArrayList(Target) = .empty;
        for (s.state.servers.items) |*sv| {
            if (!sv.available or sv.host.len == 0) continue;
            const host = s.gpa.dupe(u8, sv.host) catch continue;
            list.append(s.gpa, .{ .id = sv.id, .host = host, .port = sv.port }) catch {
                s.gpa.free(host);
                continue;
            };
            sv.ping_state = .testing;
        }
        const targets = list.toOwnedSlice(s.gpa) catch return;
        if (targets.len == 0) return s.gpa.free(targets);
        const job = s.gpa.create(ProbeJob) catch return;
        const n = @min(probe_workers, targets.len);
        job.* = .{ .s = s, .targets = targets, .left = .init(n), .servers = s.upstream, .servers_len = s.upstream_len };
        s.probing = true;
        for (0..n) |_| {
            const th = std.Thread.spawn(.{ .stack_size = core.sys.stackSize(256 * 1024) }, probeThread, .{job}) catch {
                finishWorker(job);
                continue;
            };
            th.detach();
        }
    }

    fn probeThread(job: *ProbeJob) void {
        const s = job.s;
        var resolver: dns.Resolver = .{ .gpa = s.gpa, .io = s.io, .servers = job.servers[0..job.servers_len] };
        defer resolver.deinit();
        while (true) {
            const i = job.next.fetchAdd(1, .monotonic);
            if (i >= job.targets.len) break;
            const tg = job.targets[i];
            const ms = probe(s.io, &resolver, tg.host, tg.port);
            s.mutex.lockUncancelable(s.io);
            if (s.state.serverById(tg.id)) |sv| {
                sv.ping_ms = ms;
                sv.ping_state = if (ms != null) .ok else .failed;
            }
            s.mutex.unlock(s.io);
        }
        finishWorker(job);
    }

    fn finishWorker(job: *ProbeJob) void {
        if (job.left.fetchSub(1, .acq_rel) != 1) return;
        const s = job.s;
        for (job.targets) |tg| s.gpa.free(tg.host);
        s.gpa.free(job.targets);
        s.gpa.destroy(job);
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        s.probing = false;
        // "the fastest" is settled while nothing is carried: a connection
        // must not hop between servers because a measurement moved
        if (s.t == null or s.state.settings.auto_server == null) {
            const id: ?u32 = if (s.state.fastest()) |sv| sv.id else null;
            if (id != s.state.settings.auto_server) {
                s.state.settings.auto_server = id;
                s.save();
                s.applyRoutes();
            }
        }
        s.sendState();
    }

    fn probe(io: Io, resolver: *dns.Resolver, host: []const u8, port: u16) ?u16 {
        const addr: packet.Addr = if (Io.net.IpAddress.parse(host, port)) |ip| blk: {
            const a, _ = core.sys.fromIpAddress(ip);
            break :blk a;
        } else |_| resolver.resolve(host) catch return null;
        const began = Io.Clock.awake.now(io).toMilliseconds();
        const stream = core.sys.connectTcp(io, &addr, port, .none, probe_timeout_ms) catch return null;
        stream.close(io);
        const ms = Io.Clock.awake.now(io).toMilliseconds() - began;
        return @intCast(std.math.clamp(ms, 1, 9999));
    }
};

fn hostOf(url: []const u8) []const u8 {
    const start = (std.mem.indexOf(u8, url, "://") orelse return url) + 3;
    var end = url.len;
    for (url[start..], start..) |ch, i| {
        if (ch == '/' or ch == '?' or ch == ':' or ch == '#') {
            end = i;
            break;
        }
    }
    const host = url[start..end];
    return if (host.len == 0) url else host;
}

/// An address the way java.net.InetAddress reads it.
fn addrText(buf: []u8, a: *const packet.Addr) []const u8 {
    if (packet.isV4(a)) return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ a[12], a[13], a[14], a[15] }) catch "";
    var w: Io.Writer = .fixed(buf);
    for (0..8) |i| {
        if (i > 0) w.writeByte(':') catch return "";
        w.print("{x}", .{std.mem.readInt(u16, a[i * 2 ..][0..2], .big)}) catch return "";
    }
    return w.buffered();
}

// ---------------------------------------------------------------- tests

const Shell = struct {
    fd: c.fd_t,
    buf: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,

    fn say(sh: *Shell, line: []const u8) void {
        _ = c.write(sh.fd, line.ptr, line.len);
        _ = c.write(sh.fd, "\n", 1);
    }

    /// The next message of kind `ev`; others before it are skipped.
    fn expect(sh: *Shell, ev: []const u8) !std.json.Parsed(std.json.Value) {
        while (true) {
            while (std.mem.indexOfScalar(u8, sh.buf.items, '\n')) |end| {
                const parsed = try std.json.parseFromSlice(std.json.Value, sh.gpa, sh.buf.items[0..end], .{ .allocate = .alloc_always });
                const rest = sh.buf.items.len - end - 1;
                std.mem.copyForwards(u8, sh.buf.items[0..rest], sh.buf.items[end + 1 ..]);
                sh.buf.shrinkRetainingCapacity(rest);
                if (std.mem.eql(u8, parsed.value.object.get("ev").?.string, ev)) return parsed;
                parsed.deinit();
            }
            if (!core.sys.waitFd(sh.fd, false, 5000)) return error.Timeout;
            var chunk: [4096]u8 = undefined;
            const n = c.read(sh.fd, &chunk, chunk.len);
            if (n <= 0) return error.Closed;
            try sh.buf.appendSlice(sh.gpa, chunk[0..@intCast(n)]);
        }
    }

    /// Skip states until one has (or no longer has) a rule for `app`:
    /// states from earlier commands may still be on their way.
    fn untilRule(sh: *Shell, app: []const u8, present: bool) !void {
        while (true) {
            const st = try sh.expect("state");
            defer st.deinit();
            var found = false;
            for (st.value.object.get("rules").?.array.items) |r| {
                if (std.mem.eql(u8, r.object.get("app").?.string, app)) found = true;
            }
            if (found == present) return;
        }
    }
};

const test_link = "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:9?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.microsoft.com&pbk=jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8&sid=ab12#NL";

test "the shell's side of a session: keys, rules, plans" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];

    var fds: [2]c.fd_t = undefined;
    try std.testing.expectEqual(0, c.socketpair(c.AF.UNIX, c.SOCK.STREAM, 0, &fds));
    var s: Session = .init(gpa, io, fds[0]);
    defer s.deinit();
    const th = try std.Thread.spawn(.{}, Session.run, .{&s});
    // the session ends before its state goes, also when an expectation fails
    var ended = false;
    defer if (!ended) {
        _ = c.close(fds[1]);
        th.join();
        _ = c.close(fds[0]);
    };
    var sh: Shell = .{ .fd = fds[1], .gpa = gpa };
    defer sh.buf.deinit(gpa);
    var line: [1024]u8 = undefined;

    sh.say(try std.fmt.bufPrint(&line, "{{\"cmd\":\"init\",\"dir\":\"{s}\"}}", .{dir}));
    (try sh.expect("state")).deinit();

    sh.say("{\"cmd\":\"add\",\"text\":\"" ++ test_link ++ "\\nwireguard://x\"}");
    {
        const n = try sh.expect("note");
        defer n.deinit();
        try std.testing.expectEqualStrings("added", n.value.object.get("kind").?.string);
        try std.testing.expectEqual(1, n.value.object.get("n").?.integer);
    }
    {
        const st = try sh.expect("state");
        defer st.deinit();
        const sv = st.value.object.get("servers").?.array.items[0].object;
        try std.testing.expectEqualStrings("NL", sv.get("name").?.string);
        try std.testing.expect(sv.get("ok").?.bool);
        // the secrets stay in the core
        try std.testing.expect(sv.get("link") == null);
    }

    // off: nothing to set up
    sh.say("{\"cmd\":\"rule\",\"app\":\"org.direct\",\"route\":\"direct\"}");
    sh.say("{\"cmd\":\"rule\",\"app\":\"org.held\",\"route\":\"vpn\"}");
    sh.say("{\"cmd\":\"connect\"}");
    {
        const p = try sh.expect("plan");
        defer p.deinit();
        try std.testing.expect(p.value.object.get("need").?.bool);
        try std.testing.expect(!p.value.object.get("standby").?.bool);
        try std.testing.expectEqual(0, p.value.object.get("only").?.array.items.len);
        try std.testing.expectEqualStrings("org.direct", p.value.object.get("except").?.array.items[0].string);
    }

    // a TUN that carries nothing: the tunnel starts and reports
    var tun: [2]c.fd_t = undefined;
    try std.testing.expectEqual(0, c.socketpair(c.AF.UNIX, c.SOCK.DGRAM, 0, &tun));
    defer _ = c.close(tun[1]);
    sh.say(try std.fmt.bufPrint(&line, "{{\"cmd\":\"up\",\"fd\":{d},\"mtu\":1500}}", .{tun[0]}));
    {
        const st = try sh.expect("status");
        defer st.deinit();
        try std.testing.expect(st.value.object.get("up").?.bool);
        try std.testing.expect(st.value.object.get("server").?.integer != 0);
    }

    // a rule the VpnService must reflect ends in a new plan
    sh.say("{\"cmd\":\"rule\",\"app\":\"org.other\",\"route\":\"direct\"}");
    {
        const p = try sh.expect("plan");
        defer p.deinit();
        try std.testing.expectEqual(2, p.value.object.get("except").?.array.items.len);
    }

    // a rule that differs inside the tunnel: from now on flows are asked
    // about, without a new TUN
    try std.testing.expect(!s.ask_owners.load(.acquire));
    sh.say("{\"cmd\":\"rule\",\"app\":\"org.blocked\",\"route\":\"block\"}");
    try sh.untilRule("org.blocked", true);
    try std.testing.expect(s.ask_owners.load(.acquire));
    sh.say("{\"cmd\":\"rule\",\"app\":\"org.blocked\",\"route\":\"default\"}");
    try sh.untilRule("org.blocked", false);
    try std.testing.expect(!s.ask_owners.load(.acquire));

    // disconnect: the application that may only use the VPN stays held
    sh.say("{\"cmd\":\"disconnect\"}");
    {
        const p = try sh.expect("plan");
        defer p.deinit();
        try std.testing.expect(p.value.object.get("need").?.bool);
        try std.testing.expect(p.value.object.get("standby").?.bool);
        try std.testing.expectEqualStrings("org.held", p.value.object.get("only").?.array.items[0].string);
    }
    // without the guard nothing is needed
    sh.say("{\"cmd\":\"set\",\"key\":\"guard\",\"on\":false}");
    sh.say("{\"cmd\":\"disconnect\"}");
    {
        const p = try sh.expect("plan");
        defer p.deinit();
        try std.testing.expect(!p.value.object.get("need").?.bool);
    }
    sh.say("{\"cmd\":\"down\"}");
    // reports from before the TUN went may still be on their way
    while (true) {
        const st = try sh.expect("status");
        defer st.deinit();
        if (!st.value.object.get("up").?.bool) break;
    }

    _ = c.close(fds[1]);
    th.join();
    _ = c.close(fds[0]);
    ended = true;

    // what was set survives
    var again: model.State = .init(gpa);
    defer again.deinit();
    try std.testing.expect(try core.store.load(gpa, io, dir, &again));
    try std.testing.expectEqual(1, again.servers.items.len);
    try std.testing.expectEqual(3, again.apps.items.len); // the one back on "default" is no rule
    try std.testing.expect(!again.settings.protect_when_off);
}

test "an owner's answer reaches the flow that asked; no answer is no owner" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var fds: [2]c.fd_t = undefined;
    try std.testing.expectEqual(0, c.socketpair(c.AF.UNIX, c.SOCK.STREAM, 0, &fds));
    defer _ = c.close(fds[0]);
    var s: Session = .init(gpa, io, fds[0]);
    defer s.deinit();
    const th = try std.Thread.spawn(.{}, Session.run, .{&s});
    var ended = false;
    defer if (!ended) {
        _ = c.close(fds[1]);
        th.join();
    };
    var sh: Shell = .{ .fd = fds[1], .gpa = gpa };
    defer sh.buf.deinit(gpa);
    s.owners.closed = false;
    s.ask_owners.store(true, .release);

    const Ask = struct {
        fn f(ss: *Session, port: u16, out: *?[]u8, buf: []u8) void {
            out.* = Session.findApp(ss, false, .{ .addr = packet.v4(.{ 10, 0, 0, 2 }), .port = port }, .{ .addr = packet.v4(.{ 1, 2, 3, 4 }), .port = 443 }, buf);
        }
    }.f;
    var buf: [256]u8 = undefined;
    var got: ?[]u8 = null;
    const asker = try std.Thread.spawn(.{}, Ask, .{ &s, 4000, &got, &buf });
    var line: [128]u8 = undefined;
    {
        const q = try sh.expect("owner");
        defer q.deinit();
        try std.testing.expectEqualStrings("10.0.0.2", q.value.object.get("la").?.string);
        try std.testing.expectEqual(4000, q.value.object.get("lp").?.integer);
        sh.say(try std.fmt.bufPrint(&line, "{{\"cmd\":\"owner\",\"q\":{d},\"apps\":[\"org.a\",\"org.b\"]}}", .{q.value.object.get("q").?.integer}));
    }
    asker.join();
    try std.testing.expectEqualStrings("org.a\x00org.b", got.?);

    // the same source port again: answered from memory, nothing is asked
    got = null;
    Ask(&s, 4000, &got, &buf);
    try std.testing.expectEqualStrings("org.a\x00org.b", got.?);

    // a shell that does not answer: the flow goes on as nobody's
    got = buf[0..1];
    Ask(&s, 4001, &got, &buf);
    try std.testing.expect(got == null);

    _ = c.close(fds[1]);
    th.join();
    ended = true;
}
