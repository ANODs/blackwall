//! The main server and its reserve.
//!
//! Routes that go "through the VPN" without naming a server use the first
//! member of this group, the server the user chose. When it stops carrying
//! traffic the group recovers by itself, in this order:
//!
//!   1. the same server once more, from scratch (its address is looked up
//!      again and a real request is sent through it): often a fresh
//!      connection is all it takes;
//!   2. the reserve, the servers the user marked for this: those that
//!      accept a connection are tried fastest first, each with a real
//!      request, and the first that carries it takes over;
//!   3. nothing works: wait (longer each time) and start over when
//!      connections fail again.
//!
//! Traffic never leaves directly meanwhile: flows keep being refused. While
//! a reserve server is in use the main one is looked at every few minutes
//! and taken back once it answers.
//!
//! Nothing here runs while the server works: flows report how they ended,
//! and only a run of failures starts a recovery (one thread, plus a few
//! short-lived ones for the connection checks).
//!
//! The real request asks Cloudflare's trace page, which also says in which
//! country the server's exit to the internet is. So does one request made
//! when a server starts being used (`check_exit`): providers often name a
//! server after another country than the one it exits in.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const c = std.c;
const net = std.Io.net;
const proxy = @import("proxy.zig");
const sys = @import("sys.zig");
const packet = @import("ipstack/packet.zig");

const log = std.log.scoped(.reserve);

/// The main server and up to ten reserve servers.
pub const max_members = 11;

/// How a flow through the group's server ended.
pub const Outcome = enum {
    /// the server sent data back
    carried,
    /// the server could not be reached, or its handshake failed
    dial_failed,
    /// a request went out and nothing came back
    empty,
};

pub const Group = struct {
    io: Io,
    dialer: proxy.Dialer = .{},
    mutex: Io.Mutex = .init,
    members: [max_members]proxy.Snapshot = undefined,
    len: usize = 0,
    /// index of the member in use; 0 is the main server
    active: usize = 0,
    /// how often the member in use changed (the window tells the user)
    switches: std.atomic.Value(u32) = .init(0),

    /// failures since the last flow that carried data
    score: std.atomic.Value(u32) = .init(0),
    /// a recovery or a look back at the main server is under way
    busy: std.atomic.Value(bool) = .init(false),
    stopping: std.atomic.Value(bool) = .init(false),
    /// no recovery before this time (awake clock, ms)
    next_ms: std.atomic.Value(i64) = .init(0),
    /// when to look at the main server again; 0 while it is in use
    back_ms: std.atomic.Value(i64) = .init(0),
    /// recoveries in a row that found no working server
    rounds: u8 = 0,

    /// Where each member exits to the internet, as a request through it
    /// showed ("??" until one did); kept while the member stays.
    exits: [max_members][2]u8 = @splat(unknown),
    /// Ask where the member in use exits once it is in use.
    check_exit: bool = false,
    /// when to ask again after a request that got no country; 0: not due
    exit_ms: std.atomic.Value(i64) = .init(0),
    exit_tries: std.atomic.Value(u8) = .init(0),

    /// called after the member in use changed
    on_switch: ?Hook = null,
    /// the checks, replaceable in tests
    probe: *const fn (g: *Group, ob: *const proxy.Outbound) Probe = realProbe,
    ping: *const fn (g: *Group, ob: *const proxy.Outbound) ?u32 = realPing,

    pub const Hook = struct {
        ctx: *anyopaque,
        call: *const fn (ctx: *anyopaque) void,
    };

    /// a dial failure counts twice: it is the server's for sure, while an
    /// empty answer may be the destination's
    const threshold = 6;
    const settle_ms = 15_000;
    const back_every_ms = 5 * 60_000;
    const waits_s = [_]u16{ 20, 40, 80, 160, 300 };
    /// a check of the exit that got no country is made again this much
    /// later, twice at most
    const exit_retry_ms = 60_000;
    const exit_retries = 2;

    /// Replace the members: `list[0]` is the main server, the rest the
    /// reserve in the user's order. The member in use stays in use when it
    /// is still on the list and the main server did not change.
    pub fn set(g: *Group, list: []const proxy.Outbound) void {
        const ask = blk: {
            g.mutex.lockUncancelable(g.io);
            defer g.mutex.unlock(g.io);
            const n = @min(list.len, max_members);
            var keep: usize = 0;
            if (g.len > 0 and n > 0 and same(&g.members[0].get(), &list[0])) {
                const cur = g.members[g.active].get();
                for (list[0..n], 0..) |*o, i| {
                    if (same(&cur, o)) keep = i;
                }
            }
            // a member that stays keeps what its exit showed
            var exits: [max_members][2]u8 = @splat(unknown);
            for (list[0..n], exits[0..n]) |*o, *e| for (g.members[0..g.len], g.exits[0..g.len]) |*m, old| {
                if (same(&m.get(), o)) e.* = old;
            };
            for (list[0..n], 0..) |o, i| g.members[i] = .of(o);
            g.exits = exits;
            g.len = n;
            if (keep == 0) {
                g.back_ms.store(0, .monotonic);
                g.next_ms.store(0, .monotonic);
            }
            g.active = keep;
            g.score.store(0, .monotonic);
            break :blk g.check_exit and n > 0 and !known(g.exits[keep]);
        };
        if (!ask) return g.exit_ms.store(0, .monotonic);
        g.exit_tries.store(0, .monotonic);
        // a recovery under way asks on its own; if it does not, the next tick
        if (!g.start(checkExit)) g.exit_ms.store(g.nowMs() + settle_ms, .monotonic);
    }

    /// The server to use now, or null when the group is empty.
    pub fn current(g: *Group) ?proxy.Snapshot {
        g.mutex.lockUncancelable(g.io);
        defer g.mutex.unlock(g.io);
        if (g.len == 0) return null;
        return g.members[g.active];
    }

    pub fn activeIndex(g: *Group) usize {
        g.mutex.lockUncancelable(g.io);
        defer g.mutex.unlock(g.io);
        return g.active;
    }

    pub const InUse = struct {
        /// index of the member in use; 0 is the main server
        index: usize,
        /// where it exits to the internet, "??" while not known
        exit: [2]u8,
    };

    /// The member in use and where it exits.
    pub fn inUse(g: *Group) InUse {
        g.mutex.lockUncancelable(g.io);
        defer g.mutex.unlock(g.io);
        return .{ .index = g.active, .exit = if (g.len > 0) g.exits[g.active] else unknown };
    }

    /// A flow through the group's server ended.
    pub fn report(g: *Group, what: Outcome) void {
        const add: u32 = switch (what) {
            .carried => return g.score.store(0, .monotonic),
            .dial_failed => 2,
            .empty => 1,
        };
        if (g.score.fetchAdd(add, .monotonic) + add < threshold) return;
        if (g.nowMs() < g.next_ms.load(.monotonic)) return;
        _ = g.start(recover);
    }

    /// Now and then, from a thread that runs anyway: while a reserve
    /// server is in use, look whether the main one is back; ask again
    /// where the server in use exits when that is due.
    pub fn tick(g: *Group) void {
        const now = g.nowMs();
        const ask = g.exit_ms.load(.monotonic);
        if (ask != 0 and now >= ask and g.start(checkExit)) return;
        const at = g.back_ms.load(.monotonic);
        if (at == 0 or now < at) return;
        _ = g.start(lookBack);
    }

    /// Stop and wait for a recovery under way.
    pub fn stop(g: *Group) void {
        g.stopping.store(true, .release);
        while (g.busy.load(.acquire)) g.io.sleep(.fromMilliseconds(10), .awake) catch {};
    }

    /// Run `work` on a thread of its own, unless one runs already.
    fn start(g: *Group, comptime work: fn (*Group) void) bool {
        if (g.stopping.load(.acquire)) return false;
        if (g.busy.swap(true, .acq_rel)) return false;
        const run = struct {
            fn f(gr: *Group) void {
                work(gr);
                gr.busy.store(false, .release);
                // failures that came meanwhile could not start a recovery
                if (gr.score.load(.monotonic) >= threshold and gr.nowMs() >= gr.next_ms.load(.monotonic))
                    _ = gr.start(recover);
            }
        }.f;
        const th = std.Thread.spawn(.{ .stack_size = sys.stackSize(256 * 1024) }, run, .{g}) catch {
            g.busy.store(false, .release);
            return false;
        };
        th.detach();
        return true;
    }

    /// One request through the member in use, to see where it exits.
    fn checkExit(g: *Group) void {
        g.exit_ms.store(0, .monotonic);
        const i = g.activeIndex();
        const m = g.member(i) orelse return;
        const ob = m.get();
        if (g.learn(i, &ob, g.probe(g, &ob))) return;
        if (g.stopping.load(.acquire)) return;
        // no answer, or no country in it: a little later, a couple of times
        if (g.exit_tries.fetchAdd(1, .monotonic) < exit_retries)
            g.exit_ms.store(g.nowMs() + exit_retry_ms, .monotonic);
    }

    /// A request through member `i` (when it is still `ob`) showed where it
    /// exits. True when it said.
    fn learn(g: *Group, i: usize, ob: *const proxy.Outbound, r: Probe) bool {
        if (!known(r.exit)) return false;
        g.mutex.lockUncancelable(g.io);
        defer g.mutex.unlock(g.io);
        if (i >= g.len or !same(&g.members[i].get(), ob)) return false;
        g.exits[i] = r.exit;
        return true;
    }

    fn nowMs(g: *Group) i64 {
        return Io.Clock.awake.now(g.io).toMilliseconds();
    }

    fn member(g: *Group, i: usize) ?proxy.Snapshot {
        g.mutex.lockUncancelable(g.io);
        defer g.mutex.unlock(g.io);
        return if (i < g.len) g.members[i] else null;
    }

    fn recover(g: *Group) void {
        g.mutex.lockUncancelable(g.io);
        const n = g.len;
        const active = g.active;
        g.mutex.unlock(g.io);
        if (n == 0) return;
        // whatever happens, a new recovery needs new failures
        defer g.score.store(0, .monotonic);

        // 1. the same server once more, from scratch
        const cur = g.member(active) orelse return;
        const cur_ob = cur.get();
        if (cur_ob.host()) |h| if (g.dialer.resolver) |r| r.forget(h);
        const again = g.probe(g, &cur_ob);
        if (again.carries) {
            _ = g.learn(active, &cur_ob, again);
            log.info("{s} answers again after a fresh connection", .{name(&cur_ob)});
            g.rounds = 0;
            g.next_ms.store(g.nowMs() + settle_ms, .monotonic);
            return;
        }
        if (g.stopping.load(.acquire)) return;
        log.warn("{s} does not carry traffic", .{name(&cur_ob)});

        // 2. the reserve: who accepts a connection at all, fastest first
        var times: [max_members]?u32 = @splat(null);
        g.pingAll(n, &times);
        var any = false;
        for (times[0..n]) |t| any = any or t != null;
        if (!any) {
            // not even the server in use: the network itself is down
            log.warn("no server accepts a connection: waiting for the network", .{});
            return g.wait();
        }
        times[active] = null;
        while (!g.stopping.load(.acquire)) {
            var best: ?usize = null;
            for (times[0..n], 0..) |t, i| {
                if (t == null) continue;
                if (best == null or t.? < times[best.?].?) best = i;
            }
            const i = best orelse break;
            times[i] = null;
            const cand = g.member(i) orelse continue;
            const ob = cand.get();
            const r = g.probe(g, &ob);
            if (!r.carries) continue;
            _ = g.learn(i, &ob, r);
            return g.switchTo(i, &ob);
        }
        if (n > 1) log.warn("no reserve server carries traffic either", .{});
        g.wait();
    }

    /// The reserve is in use: is the main server back?
    fn lookBack(g: *Group) void {
        g.mutex.lockUncancelable(g.io);
        const on_reserve = g.len > 0 and g.active != 0;
        g.mutex.unlock(g.io);
        if (!on_reserve) return g.back_ms.store(0, .monotonic);
        const main = g.member(0) orelse return;
        const ob = main.get();
        if (ob.host()) |h| if (g.dialer.resolver) |r| r.forget(h);
        const r = g.probe(g, &ob);
        if (r.carries) {
            _ = g.learn(0, &ob, r);
            return g.switchTo(0, &ob);
        }
        g.back_ms.store(g.nowMs() + back_every_ms, .monotonic);
    }

    fn switchTo(g: *Group, i: usize, ob: *const proxy.Outbound) void {
        g.mutex.lockUncancelable(g.io);
        const ok = i < g.len and same(&g.members[i].get(), ob);
        if (ok) g.active = i;
        g.mutex.unlock(g.io);
        // the list changed while we were looking
        if (!ok) return;
        g.rounds = 0;
        g.score.store(0, .monotonic);
        const now = g.nowMs();
        g.next_ms.store(now + settle_ms, .monotonic);
        g.back_ms.store(if (i == 0) 0 else now + back_every_ms, .monotonic);
        _ = g.switches.fetchAdd(1, .monotonic);
        if (i == 0) log.info("back on the main server {s}", .{name(ob)}) else log.info("reserve server {s} takes over", .{name(ob)});
        // its answer did not say where it exits: asked once it settled
        if (g.check_exit and !known(g.inUse().exit)) {
            g.exit_tries.store(0, .monotonic);
            g.exit_ms.store(now + settle_ms, .monotonic);
        }
        if (g.on_switch) |h| h.call(h.ctx);
    }

    fn wait(g: *Group) void {
        const s = waits_s[@min(g.rounds, waits_s.len - 1)];
        g.rounds +|= 1;
        g.next_ms.store(g.nowMs() + @as(i64, s) * 1000, .monotonic);
    }

    /// Connection time of every member, all at once.
    fn pingAll(g: *Group, n: usize, times: *[max_members]?u32) void {
        const Job = struct {
            g: *Group,
            ob: proxy.Snapshot,
            out: *?u32,
            fn run(j: *@This()) void {
                const ob = j.ob.get();
                j.out.* = j.g.ping(j.g, &ob);
            }
        };
        var jobs: [max_members]Job = undefined;
        var threads: [max_members]?std.Thread = @splat(null);
        for (0..n) |i| {
            jobs[i] = .{ .g = g, .ob = g.member(i) orelse continue, .out = &times[i] };
            threads[i] = std.Thread.spawn(.{ .stack_size = sys.stackSize(128 * 1024) }, Job.run, .{&jobs[i]}) catch blk: {
                jobs[i].run();
                break :blk null;
            };
        }
        for (threads[0..n]) |t| if (t) |th| th.join();
    }
};

fn name(ob: *const proxy.Outbound) []const u8 {
    return ob.host() orelse @tagName(ob.*);
}

/// The same server: address, port and account.
fn same(a: *const proxy.Outbound, b: *const proxy.Outbound) bool {
    return a.sameServer(b);
}

/// What a real request through a server showed.
pub const Probe = struct {
    /// an HTTP answer came back through it
    carries: bool = false,
    /// the country its exit to the internet appears from, as the answer
    /// said; "??" when it did not
    exit: [2]u8 = unknown,
};

/// A country code that is not known.
pub const unknown: [2]u8 = "??".*;

/// Whether `cc` is a country: two capital letters. Cloudflare's own "XX"
/// (not known) and "T1" (Tor) are not.
pub fn known(cc: [2]u8) bool {
    return std.ascii.isUpper(cc[0]) and std.ascii.isUpper(cc[1]) and !std.mem.eql(u8, &cc, "XX");
}

/// The checks the recovery uses, for one server: how fast it accepts a
/// connection, whether a real request gets through it, and where it exits.
pub fn check(io: Io, dialer: proxy.Dialer, ob: *const proxy.Outbound) struct { ping_ms: ?u32, carries: bool, exit: [2]u8 } {
    var g: Group = .{ .io = io, .dialer = dialer };
    const r = realProbe(&g, ob);
    return .{ .ping_ms = realPing(&g, ob), .carries = r.carries, .exit = r.exit };
}

const ping_timeout_ms = 2500;
const probe_wait_ms = 8000;
/// Cloudflare's trace page, over plain HTTP: any HTTP answer through the
/// server proves it carries traffic, and the page's "loc=" line is the
/// country Cloudflare places the server's exit address in. Nothing about
/// the user goes with it: no cookies, no user agent.
const check_host = "cloudflare.com";
const check_request = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: " ++ check_host ++ "\r\nConnection: close\r\n\r\n";

/// Milliseconds to connect to the server, or null when it does not accept.
fn realPing(g: *Group, ob: *const proxy.Outbound) ?u32 {
    const v = ob.via() orelse return null;
    var d = g.dialer;
    d.timeout_ms = ping_timeout_ms;
    const start = g.nowMs();
    const s = d.connect(g.io, v.host, v.port) catch return null;
    s.close(g.io);
    return @intCast(@max(1, g.nowMs() - start));
}

/// One real request through the server: connect, handshake, ask a known
/// address for a page and read what comes back.
fn realProbe(g: *Group, ob: *const proxy.Outbound) Probe {
    if (comptime !sys.supported) return .{};
    if (ob.via() == null) return .{};
    var fds: [2]c.fd_t = undefined;
    if (c.socketpair(c.AF.UNIX, c.SOCK.STREAM, 0, &fds) != 0) return .{};
    defer _ = c.close(fds[1]);
    if (builtin.os.tag.isDarwin()) {
        const one: c_int = 1;
        for (fds) |fd| _ = c.setsockopt(fd, c.SOL.SOCKET, c.SO.NOSIGPIPE, &one, @sizeOf(c_int));
    }

    // the flow's "application" is the other end of the socket pair
    const Runner = struct {
        io: Io,
        dialer: proxy.Dialer,
        ob: *const proxy.Outbound,
        fd: c.fd_t,
        fn run(r: *@This()) void {
            const stream: net.Stream = .{ .socket = .{ .handle = r.fd, .address = sys.toIpAddress(&packet.v4(.{ 127, 0, 0, 1 }), 0) } };
            defer stream.close(r.io);
            var rb: [2048]u8 = undefined;
            var wb: [2048]u8 = undefined;
            var sr = stream.reader(r.io, &rb);
            var sw = stream.writer(r.io, &wb);
            var local: proxy.Local = .{ .r = &sr.interface, .w = &sw.interface, .end = .{ .socks = stream } };
            const target: proxy.Target = .fromDomain(check_host, 80);
            const flow: proxy.Flow = .{ .io = r.io, .dialer = r.dialer };
            flow.run(&local, &target, r.ob) catch {};
        }
    };
    var runner: Runner = .{ .io = g.io, .dialer = g.dialer, .ob = ob, .fd = fds[0] };
    runner.dialer.timeout_ms = 5000;
    const th = std.Thread.spawn(.{ .stack_size = sys.stackSize(512 * 1024) }, Runner.run, .{&runner}) catch {
        _ = c.close(fds[0]);
        return .{};
    };

    _ = c.write(fds[1], check_request, check_request.len);
    // the answer holds the server's address too: it stays in here, unlogged
    var got: [4096]u8 = undefined;
    var len: usize = 0;
    const deadline = g.nowMs() + probe_wait_ms;
    var r: Probe = .{};
    while (len < got.len and !g.stopping.load(.acquire)) {
        const left = deadline - g.nowMs();
        if (left <= 0 or !sys.waitFd(fds[1], false, @intCast(@min(left, 500)))) {
            if (left <= 0) break;
            continue;
        }
        const n = c.read(fds[1], got[len..].ptr, got.len - len);
        if (n <= 0) break;
        len += @intCast(n);
        r = parseTrace(got[0..len]);
        if (known(r.exit)) break;
    }
    // ends the flow, whatever it is waiting for on our side
    _ = c.shutdown(fds[1], c.SHUT.RDWR);
    th.join();
    return r;
}

/// What the trace page's answer (so far) says. After the 10 bytes that
/// say "connected" comes the page: an HTTP answer at all means the server
/// carries traffic; the body of a 200 is "key=value" lines, one of them
/// "loc=" and the country.
pub fn parseTrace(answer: []const u8) Probe {
    const at = std.mem.indexOf(u8, answer, "HTTP/1.") orelse return .{};
    var r: Probe = .{ .carries = true };
    const head = answer[at..];
    // "HTTP/1.1 200 OK": anything else (a redirect, a refusal) is no trace
    if (head.len < 12 or !std.mem.eql(u8, head[8..12], " 200")) return r;
    const body_at = std.mem.indexOf(u8, head, "\r\n\r\n") orelse return r;
    const body = head[body_at + 4 ..];
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |raw| {
        // the last piece may be cut short: only whole lines count
        if (lines.index == null) break;
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (!std.mem.startsWith(u8, line, "loc=")) continue;
        const v = line[4..];
        if (v.len == 2 and known(v[0..2].*)) r.exit = v[0..2].*;
        break;
    }
    return r;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

const Fake = struct {
    /// which hosts carry traffic, and how fast they accept
    var alive: [4]bool = @splat(false);
    var accepts: [4]?u32 = @splat(null);
    /// where each exits, as its answer says
    var exits: [4][2]u8 = @splat(unknown);
    var probes: std.atomic.Value(u32) = .init(0);
    /// a check waits while this is set
    var hold: std.atomic.Value(bool) = .init(false);
    var switched: std.atomic.Value(u32) = .init(0);

    fn index(ob: *const proxy.Outbound) usize {
        return ob.vless.host[0] - 'a';
    }
    fn probe(_: *Group, ob: *const proxy.Outbound) Probe {
        _ = probes.fetchAdd(1, .monotonic);
        while (hold.load(.acquire)) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        const i = index(ob);
        return if (alive[i]) .{ .carries = true, .exit = exits[i] } else .{};
    }
    fn ping(_: *Group, ob: *const proxy.Outbound) ?u32 {
        return accepts[index(ob)];
    }
    fn onSwitch(_: *anyopaque) void {
        _ = switched.fetchAdd(1, .monotonic);
    }
    fn server(comptime host: []const u8) proxy.Outbound {
        return .{ .vless = .{ .host = host, .port = 443, .uuid = @splat(7) } };
    }
    fn group() Group {
        probes.store(0, .monotonic);
        switched.store(0, .monotonic);
        exits = @splat(unknown);
        var g: Group = .{ .io = testing.io, .probe = probe, .ping = ping };
        g.on_switch = .{ .ctx = undefined, .call = onSwitch };
        return g;
    }
    fn settle(g: *Group) void {
        while (g.busy.load(.acquire)) testing.io.sleep(.fromMilliseconds(2), .awake) catch {};
    }
    fn fail(g: *Group, times: usize) void {
        for (0..times) |_| g.report(.dial_failed);
        settle(g);
    }
};

test "a few failures in a row start a recovery; data in between resets the count" {
    var g = Fake.group();
    g.set(&.{ Fake.server("a.example"), Fake.server("b.example") });
    Fake.alive = .{ true, true, false, false };
    Fake.accepts = .{ 10, 10, null, null };
    g.report(.dial_failed);
    g.report(.dial_failed);
    g.report(.carried);
    g.report(.dial_failed);
    g.report(.empty);
    Fake.settle(&g);
    try testing.expectEqual(0, Fake.probes.load(.monotonic));
    // three dial failures in a row
    Fake.fail(&g, 3);
    // the main server answered the fresh request: nothing changes
    try testing.expectEqual(1, Fake.probes.load(.monotonic));
    try testing.expectEqual(0, g.activeIndex());
    try testing.expectEqual(0, Fake.switched.load(.monotonic));
    // and no second check right away
    Fake.fail(&g, 5);
    try testing.expectEqual(1, Fake.probes.load(.monotonic));
}

test "the main server is dead: the fastest reserve server that carries traffic takes over" {
    var g = Fake.group();
    g.set(&.{ Fake.server("a.example"), Fake.server("b.example"), Fake.server("c.example"), Fake.server("d.example") });
    // b accepts but carries nothing, c is slower than d, d is unreachable
    Fake.alive = .{ false, false, true, true };
    Fake.accepts = .{ null, 5, 40, null };
    Fake.fail(&g, 3);
    try testing.expectEqual(2, g.activeIndex());
    try testing.expectEqualStrings("c.example", g.current().?.get().vless.host);
    try testing.expectEqual(1, Fake.switched.load(.monotonic));
    try testing.expectEqual(1, g.switches.load(.monotonic));
    // a (again), b, c were asked; d never accepted a connection
    try testing.expectEqual(3, Fake.probes.load(.monotonic));
    try testing.expect(g.back_ms.load(.monotonic) != 0);

    // the main server comes back: the look back takes it again
    Fake.alive[0] = true;
    g.back_ms.store(1, .monotonic);
    g.tick();
    Fake.settle(&g);
    try testing.expectEqual(0, g.activeIndex());
    try testing.expectEqual(0, g.back_ms.load(.monotonic));
    try testing.expectEqual(2, Fake.switched.load(.monotonic));
}

test "nothing works: the server stays, and the next recovery waits" {
    var g = Fake.group();
    g.set(&.{ Fake.server("a.example"), Fake.server("b.example") });
    Fake.alive = @splat(false);
    Fake.accepts = .{ null, 9, null, null };
    Fake.fail(&g, 3);
    try testing.expectEqual(0, g.activeIndex());
    try testing.expectEqual(2, Fake.probes.load(.monotonic));
    try testing.expect(g.next_ms.load(.monotonic) > g.nowMs() + 10_000);
    Fake.fail(&g, 6);
    try testing.expectEqual(2, Fake.probes.load(.monotonic));

    // the network itself is down: no server is even asked for a page
    g.next_ms.store(0, .monotonic);
    Fake.accepts = @splat(null);
    Fake.fail(&g, 3);
    try testing.expectEqual(3, Fake.probes.load(.monotonic));
    try testing.expectEqual(0, g.activeIndex());
}

test "a new list keeps the server in use; a new main server starts over" {
    var g = Fake.group();
    g.set(&.{ Fake.server("a.example"), Fake.server("b.example"), Fake.server("c.example") });
    Fake.alive = .{ false, false, true, false };
    Fake.accepts = .{ null, null, 7, null };
    Fake.fail(&g, 3);
    try testing.expectEqual(2, g.activeIndex());
    // b left the reserve: c is still the one in use
    g.set(&.{ Fake.server("a.example"), Fake.server("c.example") });
    try testing.expectEqualStrings("c.example", g.current().?.get().vless.host);
    // the user chose another main server
    g.set(&.{ Fake.server("d.example"), Fake.server("c.example") });
    try testing.expectEqualStrings("d.example", g.current().?.get().vless.host);
    try testing.expectEqual(0, g.back_ms.load(.monotonic));
    g.set(&.{});
    try testing.expect(g.current() == null);
}

test "the trace page: an answer carries, its loc line is the exit's country" {
    const head = "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nReport-To: {\"url\":\"https://a.example/?loc=ZZ\"}\r\n\r\n";
    const body = "fl=143f88\nh=cloudflare.com\nip=192.0.2.7\nts=1795109239.000\nvisit_scheme=http\nuag=\ncolo=AMS\nsliver=none\nhttp=http/1.1\nloc=NL\ntls=off\nsni=off\nwarp=off\n";
    const whole = head ++ body;
    const r = parseTrace(whole);
    try testing.expect(r.carries);
    try testing.expectEqualStrings("NL", &r.exit);
    // the line is not complete yet: no country from half of it
    const cut = std.mem.indexOf(u8, whole, "loc=NL").? + 5;
    try testing.expect(!known(parseTrace(whole[0..cut]).exit));
    try testing.expect(!known(parseTrace(whole[0 .. cut + 1]).exit));
    try testing.expectEqualStrings("NL", &parseTrace(whole[0 .. cut + 2]).exit);
    // Windows line ends
    try testing.expectEqualStrings("DE", &parseTrace("HTTP/1.1 200 OK\r\n\r\nloc=DE\r\n").exit);
    // not known to Cloudflare, Tor, a redirect, nothing at all
    try testing.expect(!known(parseTrace("HTTP/1.1 200 OK\r\n\r\nloc=XX\n").exit));
    try testing.expect(!known(parseTrace("HTTP/1.1 200 OK\r\n\r\nloc=T1\n").exit));
    const moved = parseTrace("HTTP/1.1 301 Moved Permanently\r\nLocation: https://x/\r\n\r\nloc=US\n");
    try testing.expect(moved.carries and !known(moved.exit));
    try testing.expect(!parseTrace("\x05\x00\x00\x01").carries);
}

test "the server in use is asked where it exits, once; a server that stays keeps it" {
    var g = Fake.group();
    g.check_exit = true;
    Fake.alive = .{ true, true, true, false };
    Fake.accepts = .{ 10, 10, 10, null };
    Fake.exits = .{ "NL".*, "DE".*, "FI".*, unknown };
    g.set(&.{ Fake.server("a.example"), Fake.server("b.example") });
    Fake.settle(&g);
    try testing.expectEqual(1, Fake.probes.load(.monotonic));
    try testing.expectEqualStrings("NL", &g.inUse().exit);
    // the same list again (a reload): nothing more is asked
    g.set(&.{ Fake.server("a.example"), Fake.server("c.example") });
    Fake.settle(&g);
    try testing.expectEqual(1, Fake.probes.load(.monotonic));
    try testing.expectEqualStrings("NL", &g.inUse().exit);

    // the main server dies: the reserve's own check says where it exits
    Fake.alive[0] = false;
    Fake.fail(&g, 3);
    try testing.expectEqual(1, g.activeIndex());
    try testing.expectEqualStrings("FI", &g.inUse().exit);
    try testing.expectEqual(0, g.exit_ms.load(.monotonic));

    // another main server: asked anew
    g.set(&.{Fake.server("b.example")});
    Fake.settle(&g);
    try testing.expectEqualStrings("DE", &g.inUse().exit);

    // an answer without a country: asked again later, a couple of times
    g.set(&.{Fake.server("d.example")});
    Fake.settle(&g);
    try testing.expect(!known(g.inUse().exit));
    try testing.expect(g.exit_ms.load(.monotonic) != 0);
    Fake.alive[3] = true;
    Fake.exits[3] = "SE".*;
    g.exit_ms.store(1, .monotonic);
    g.tick();
    Fake.settle(&g);
    try testing.expectEqualStrings("SE", &g.inUse().exit);
    try testing.expectEqual(0, g.exit_ms.load(.monotonic));

    // off: nothing is asked
    var quiet = Fake.group();
    quiet.set(&.{Fake.server("a.example")});
    Fake.settle(&quiet);
    try testing.expectEqual(0, Fake.probes.load(.monotonic));
}

test "failures while the exit is being asked start a recovery right after" {
    var g = Fake.group();
    g.check_exit = true;
    Fake.alive = .{ false, true, false, false };
    Fake.accepts = .{ 10, 10, null, null };
    Fake.exits = .{ unknown, "DE".*, unknown, unknown };
    // the check of the main server takes its time
    Fake.hold.store(true, .release);
    g.set(&.{ Fake.server("a.example"), Fake.server("b.example") });
    while (Fake.probes.load(.monotonic) == 0) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    // flows fail meanwhile: no recovery can start yet
    for (0..3) |_| g.report(.dial_failed);
    try testing.expectEqual(0, g.activeIndex());
    Fake.hold.store(false, .release);
    while (Fake.switched.load(.monotonic) == 0) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    Fake.settle(&g);
    try testing.expectEqual(1, g.activeIndex());
    try testing.expectEqualStrings("DE", &g.inUse().exit);
}
