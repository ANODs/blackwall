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
//!      accept a connection are tried best first, each with a real
//!      request, and the first that carries it takes over. "Best" is what
//!      the last measuring pass found (below); servers it has not seen yet
//!      come after the measured ones that worked, fastest to connect
//!      first, and the ones that failed it come last;
//!   3. nothing works: wait (longer each time) and start over when
//!      connections fail again.
//!
//! Traffic never leaves directly meanwhile: flows keep being refused. While
//! a reserve server is in use the main one is looked at every few minutes
//! and taken back once it answers.
//!
//! Nothing of the recovery runs while the server works: flows report how
//! they ended, and only a run of failures starts a recovery (one thread,
//! plus a few short-lived ones for the connection checks).
//!
//! The measuring pass ranks the reserve ahead of time: half a minute after
//! the list changes, then every half hour, but only while data goes through
//! the server in use (an idle or sleeping device measures nothing). One
//! server after another, never two at once (they would share the line), a
//! fresh connection through each asks for half a megabyte: how long until
//! the answer starts is its response time, how fast the rest comes its
//! speed. The rank is the time to get a megabyte that way. A pass takes a
//! few seconds per server and runs apart from the recovery, which never
//! waits for it.

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

/// What the measuring pass found about one server.
pub const Mark = struct {
    state: enum { unknown, ok, failed } = .unknown,
    /// from the request to the first byte of the answer, connection included
    reply_ms: u32 = 0,
    /// bytes per second; 0 when too little came to tell
    speed: u32 = 0,

    /// a server that answered but whose speed is unknown counts as 1 Mbit/s
    const slow_ms = 8000;

    /// Milliseconds to get a megabyte through the server: its response
    /// time plus the transfer. Lower is better.
    pub fn cost(m: Mark) u64 {
        const transfer: u64 = if (m.speed == 0) slow_ms else (1 << 20) * 1000 / @as(u64, m.speed);
        return m.reply_ms + transfer;
    }
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

    /// the last measuring pass, per member (under `mutex`)
    marks: [max_members]Mark = @splat(.{}),
    /// a measuring pass is under way (apart from `busy`: a recovery must
    /// not wait for a pass)
    measuring: std.atomic.Value(bool) = .init(false),
    /// when the next pass is due (awake clock, ms); 0: no reserve to measure
    measure_ms: std.atomic.Value(i64) = .init(0),
    /// data went through the server in use since the last pass
    used: std.atomic.Value(bool) = .init(false),

    /// called after the member in use changed
    on_switch: ?Hook = null,
    /// the checks, replaceable in tests
    probe: *const fn (g: *Group, ob: *const proxy.Outbound) bool = realProbe,
    ping: *const fn (g: *Group, ob: *const proxy.Outbound) ?u32 = realPing,
    measure: *const fn (g: *Group, ob: *const proxy.Outbound) Mark = realMeasure,

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
    const measure_first_ms = 30_000;
    const measure_every_ms = 30 * 60_000;

    /// Replace the members: `list[0]` is the main server, the rest the
    /// reserve in the user's order. The member in use stays in use when it
    /// is still on the list and the main server did not change. Servers
    /// that stay keep what the measuring pass found about them.
    pub fn set(g: *Group, list: []const proxy.Outbound) void {
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
        var marks: [max_members]Mark = @splat(.{});
        var unmeasured = false;
        for (list[0..n], 0..) |*o, i| {
            for (g.members[0..g.len], 0..) |*m, j| {
                if (same(&m.get(), o)) marks[i] = g.marks[j];
            }
            unmeasured = unmeasured or (i > 0 and marks[i].state == .unknown);
        }
        for (list[0..n], 0..) |o, i| g.members[i] = .of(o);
        g.marks = marks;
        g.len = n;
        // a new reserve server is measured soon, the rest when due
        const due = g.measure_ms.load(.monotonic);
        if (n < 2) {
            g.measure_ms.store(0, .monotonic);
        } else if (due == 0 or unmeasured) {
            const soon = g.nowMs() + measure_first_ms;
            if (due == 0 or due > soon) g.measure_ms.store(soon, .monotonic);
        }
        if (keep == 0) {
            g.back_ms.store(0, .monotonic);
            g.next_ms.store(0, .monotonic);
        }
        g.active = keep;
        g.score.store(0, .monotonic);
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

    /// A flow through the group's server ended.
    pub fn report(g: *Group, what: Outcome) void {
        const add: u32 = switch (what) {
            .carried => {
                g.score.store(0, .monotonic);
                if (!g.used.load(.monotonic)) g.used.store(true, .monotonic);
                return;
            },
            .dial_failed => 2,
            .empty => 1,
        };
        if (g.score.fetchAdd(add, .monotonic) + add < threshold) return;
        if (g.nowMs() < g.next_ms.load(.monotonic)) return;
        g.start(recover);
    }

    /// Now and then, from a thread that runs anyway: while a reserve
    /// server is in use, look whether the main one is back; measure the
    /// reserve when that is due.
    pub fn tick(g: *Group) void {
        const now = g.nowMs();
        const at = g.back_ms.load(.monotonic);
        if (at != 0 and now >= at) g.start(lookBack);
        const due = g.measure_ms.load(.monotonic);
        // nothing went through lately: the device is idle, wait for use
        if (due != 0 and now >= due and g.used.load(.monotonic)) g.startMeasuring();
    }

    /// The order the reserve would be tried in now, as member indices, the
    /// member in use left out. For the log and the tests.
    pub fn ranking(g: *Group, out: *[max_members]usize) []usize {
        var pings: [max_members]?u32 = @splat(0);
        g.mutex.lockUncancelable(g.io);
        const n = g.len;
        const active = g.active;
        const marks = g.marks;
        g.mutex.unlock(g.io);
        pings[active] = null;
        var k: usize = 0;
        while (pickBest(n, &pings, &marks)) |i| : (k += 1) {
            pings[i] = null;
            out[k] = i;
        }
        return out[0..k];
    }

    /// Stop and wait for a recovery or a measuring pass under way.
    pub fn stop(g: *Group) void {
        g.stopping.store(true, .release);
        while (g.busy.load(.acquire) or g.measuring.load(.acquire)) g.io.sleep(.fromMilliseconds(10), .awake) catch {};
    }

    fn startMeasuring(g: *Group) void {
        if (g.stopping.load(.acquire)) return;
        if (g.measuring.swap(true, .acq_rel)) return;
        g.used.store(false, .monotonic);
        const run = struct {
            fn f(gr: *Group) void {
                gr.measureAll();
                gr.measuring.store(false, .release);
            }
        }.f;
        const th = std.Thread.spawn(.{ .stack_size = sys.stackSize(256 * 1024) }, run, .{g}) catch {
            g.measuring.store(false, .release);
            return;
        };
        th.detach();
    }

    /// One measuring pass: every member but the one in use, one at a time.
    fn measureAll(g: *Group) void {
        var i: usize = 0;
        while (!g.stopping.load(.acquire)) : (i += 1) {
            g.mutex.lockUncancelable(g.io);
            const more = i < g.len;
            const skip = more and i == g.active;
            const snap = if (more) g.members[i] else undefined;
            g.mutex.unlock(g.io);
            if (!more) break;
            if (skip) continue;
            const ob = snap.get();
            const m = g.measure(g, &ob);
            if (g.stopping.load(.acquire)) break;
            switch (m.state) {
                .ok => log.info("{s}: answers in {d} ms, {d} KB/s", .{ name(&ob), m.reply_ms, m.speed / 1024 }),
                else => log.info("{s}: does not answer", .{name(&ob)}),
            }
            g.mutex.lockUncancelable(g.io);
            // the list may have changed meanwhile
            if (i < g.len and same(&g.members[i].get(), &ob)) g.marks[i] = m;
            g.mutex.unlock(g.io);
        }
        g.mutex.lockUncancelable(g.io);
        const n = g.len;
        g.mutex.unlock(g.io);
        g.measure_ms.store(if (n < 2) 0 else g.nowMs() + measure_every_ms, .monotonic);
        var buf: [max_members]usize = undefined;
        const order = g.ranking(&buf);
        if (order.len > 0) log.info("reserve order: {any}", .{order});
    }

    fn start(g: *Group, comptime work: fn (*Group) void) void {
        if (g.stopping.load(.acquire)) return;
        if (g.busy.swap(true, .acq_rel)) return;
        const run = struct {
            fn f(gr: *Group) void {
                work(gr);
                gr.busy.store(false, .release);
            }
        }.f;
        const th = std.Thread.spawn(.{ .stack_size = sys.stackSize(256 * 1024) }, run, .{g}) catch {
            g.busy.store(false, .release);
            return;
        };
        th.detach();
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
        if (g.probe(g, &cur_ob)) {
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
        g.mutex.lockUncancelable(g.io);
        const marks = g.marks;
        g.mutex.unlock(g.io);
        while (!g.stopping.load(.acquire)) {
            const i = pickBest(n, &times, &marks) orelse break;
            times[i] = null;
            const cand = g.member(i) orelse continue;
            const ob = cand.get();
            if (!g.probe(g, &ob)) continue;
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
        if (g.probe(g, &ob)) return g.switchTo(0, &ob);
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

/// The member to try next among those with a connection time (`pings`):
/// measured and working, cheapest first; then not measured yet, fastest to
/// connect first; then those the last pass found dead. Ties keep the
/// user's order.
fn pickBest(n: usize, pings: *const [max_members]?u32, marks: *const [max_members]Mark) ?usize {
    var best: ?usize = null;
    for (0..n) |i| {
        if (pings[i] == null) continue;
        if (best == null or before(i, best.?, pings, marks)) best = i;
    }
    return best;
}

fn before(a: usize, b: usize, pings: *const [max_members]?u32, marks: *const [max_members]Mark) bool {
    const order = struct {
        fn of(m: Mark) u2 {
            return switch (m.state) {
                .ok => 0,
                .unknown => 1,
                .failed => 2,
            };
        }
    }.of;
    const oa = order(marks[a]);
    const ob = order(marks[b]);
    if (oa != ob) return oa < ob;
    if (marks[a].state == .ok) return marks[a].cost() < marks[b].cost();
    return pings[a].? < pings[b].?;
}

fn name(ob: *const proxy.Outbound) []const u8 {
    return ob.host() orelse @tagName(ob.*);
}

/// The same server: address, port and account.
fn same(a: *const proxy.Outbound, b: *const proxy.Outbound) bool {
    return a.sameServer(b);
}

/// The checks the group uses, for one server: how fast it accepts a
/// connection, whether a real request gets through it, and what a
/// measuring pass finds.
pub fn check(io: Io, dialer: proxy.Dialer, ob: *const proxy.Outbound) struct { ping_ms: ?u32, carries: bool, mark: Mark } {
    var g: Group = .{ .io = io, .dialer = dialer };
    return .{ .ping_ms = realPing(&g, ob), .carries = realProbe(&g, ob), .mark = realMeasure(&g, ob) };
}

const ping_timeout_ms = 2500;
const probe_wait_ms = 8000;
/// A plain-HTTP address made for connectivity checks: any HTTP answer
/// through the server proves it carries traffic.
const check_host = "www.gstatic.com";
const check_request = "GET /generate_204 HTTP/1.1\r\nHost: " ++ check_host ++ "\r\nConnection: close\r\n\r\n";
/// Plain HTTP too (the tunnel is the encryption): a body of any size asked for.
const speed_host = "speed.cloudflare.com";
const speed_bytes = 1024 * 1024;
const speed_request = std.fmt.comptimePrint("GET /__down?bytes={d} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: blackwall\r\nConnection: close\r\n\r\n", .{ speed_bytes, speed_host });
/// the whole measurement of one server, connection included
const measure_wait_ms = 10_000;
/// The speed is taken over what comes after this much of the body: the
/// start of a connection is slow on any line (TCP finds its pace first).
const warmup_bytes = 64 * 1024;

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
/// address for a page and see an HTTP answer come back.
fn realProbe(g: *Group, ob: *const proxy.Outbound) bool {
    return fetch(g, ob, check_host, check_request, 0, probe_wait_ms).reply_ms != null;
}

/// The response time and the download speed through the server.
fn realMeasure(g: *Group, ob: *const proxy.Outbound) Mark {
    const f = fetch(g, ob, speed_host, speed_request, speed_bytes, measure_wait_ms);
    const ms = f.reply_ms orelse return .{ .state = .failed };
    return .{ .state = .ok, .reply_ms = ms, .speed = if (f.ok) f.speed else 0 };
}

const Fetch = struct {
    /// from the request to the first byte of the answer; null: no answer
    reply_ms: ?u32 = null,
    /// the answer is "200 OK"
    ok: bool = false,
    /// bytes of the body that came
    body: u64 = 0,
    /// bytes per second after the warm-up; 0 when too little came to tell
    speed: u32 = 0,
};

/// A request through the server, as an application would send it, and as
/// much of the answer as `want` (bytes of the body; 0: its first line is
/// enough) within `wait_ms`.
fn fetch(g: *Group, ob: *const proxy.Outbound, comptime host: []const u8, request: []const u8, want: u64, wait_ms: i64) Fetch {
    var res: Fetch = .{};
    if (ob.via() == null) return res;
    // on Windows a loopback TCP pair (it has no socketpair)
    const fds = sys.socketPair(g.io) orelse return res;

    // the flow's "application" is the other end of the socket pair
    const Runner = struct {
        io: Io,
        dialer: proxy.Dialer,
        ob: *const proxy.Outbound,
        fd: c.fd_t,
        /// we are done: a server still sending is let go at once
        done: std.atomic.Value(bool) = .init(false),
        fn run(r: *@This()) void {
            const stream: net.Stream = .{ .socket = .{ .handle = r.fd, .address = sys.toIpAddress(&packet.v4(.{ 127, 0, 0, 1 }), 0) } };
            defer stream.close(r.io);
            var rb: [2048]u8 = undefined;
            var wb: [16 * 1024]u8 = undefined;
            var sr = stream.reader(r.io, &rb);
            var sw = stream.writer(r.io, &wb);
            var local: proxy.Local = .{ .r = &sr.interface, .w = &sw.interface, .end = .{ .socks = stream } };
            const target: proxy.Target = .fromDomain(host, 80);
            const flow: proxy.Flow = .{ .io = r.io, .dialer = r.dialer, .stop = &r.done };
            flow.run(&local, &target, r.ob) catch {};
        }
    };
    var runner: Runner = .{ .io = g.io, .dialer = g.dialer, .ob = ob, .fd = fds[0] };
    runner.dialer.timeout_ms = 5000;
    const mine: net.Stream = .{ .socket = .{ .handle = fds[1], .address = sys.toIpAddress(&packet.v4(.{ 127, 0, 0, 1 }), 0) } };
    const th = std.Thread.spawn(.{ .stack_size = sys.stackSize(512 * 1024) }, Runner.run, .{&runner}) catch {
        const theirs: net.Stream = .{ .socket = .{ .handle = fds[0], .address = mine.socket.address } };
        theirs.close(g.io);
        mine.close(g.io);
        return res;
    };

    const start = g.nowMs();
    {
        var wb: [512]u8 = undefined;
        var sw = mine.writer(g.io, &wb);
        sw.interface.writeAll(request) catch {};
        sw.interface.flush() catch {};
    }
    // the answer's head is kept until its end is seen, the body only counted
    var head: [8 * 1024]u8 = undefined;
    var head_len: usize = 0;
    var head_done = false;
    var buf: [16 * 1024]u8 = undefined;
    // the body from the end of the warm-up on
    var warm_ms: ?i64 = null;
    var warm_bytes: u64 = 0;
    const deadline = start + wait_ms;
    while (!g.stopping.load(.acquire)) {
        const left = deadline - g.nowMs();
        if (left <= 0) break;
        if (!sys.waitFd(fds[1], false, @intCast(@min(left, 500)))) continue;
        const n = sys.recvSome(fds[1], &buf) orelse break;
        if (n == 0) break;
        const chunk = buf[0..n];
        const now = g.nowMs();
        if (head_done) {
            res.body += chunk.len;
        } else {
            const before_len = head_len;
            const take = @min(chunk.len, head.len - head_len);
            @memcpy(head[head_len..][0..take], chunk[0..take]);
            head_len += take;
            // after the 10 bytes that say "connected" comes the answer
            const at = std.mem.indexOf(u8, head[0..head_len], "HTTP/1.") orelse {
                if (head_len == head.len) break;
                continue;
            };
            if (res.reply_ms == null) res.reply_ms = @intCast(@max(1, now - start));
            if (want == 0) break;
            const end = std.mem.indexOfPos(u8, head[0..head_len], at, "\r\n\r\n") orelse {
                if (head_len == head.len) break;
                continue;
            };
            head_done = true;
            res.ok = std.mem.startsWith(u8, head[at + "HTTP/1.x".len .. head_len], " 200");
            // what of this chunk comes after the head
            res.body += chunk.len - (end + 4 - before_len);
        }
        if (warm_ms) |t0| {
            if (now > t0) res.speed = @intCast(@min((res.body - warm_bytes) * 1000 / @as(u64, @intCast(now - t0)), std.math.maxInt(u32)));
        } else if (res.body >= warmup_bytes) {
            warm_ms = now;
            warm_bytes = res.body;
        }
        if (head_done and res.body >= want) break;
    }
    // ends the flow, whatever it is waiting for on our side: closed, not
    // just shut down, so that its writes fail and it stops reading the
    // server (with a shutdown, macOS takes them and the download goes on)
    runner.done.store(true, .release);
    mine.close(g.io);
    th.join();
    return res;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

const Fake = struct {
    /// which hosts carry traffic, and how fast they accept
    var alive: [4]bool = @splat(false);
    var accepts: [4]?u32 = @splat(null);
    var probes: std.atomic.Value(u32) = .init(0);
    var switched: std.atomic.Value(u32) = .init(0);

    fn index(ob: *const proxy.Outbound) usize {
        return ob.vless.host[0] - 'a';
    }
    fn probe(_: *Group, ob: *const proxy.Outbound) bool {
        _ = probes.fetchAdd(1, .monotonic);
        return alive[index(ob)];
    }
    fn ping(_: *Group, ob: *const proxy.Outbound) ?u32 {
        return accepts[index(ob)];
    }
    /// what a measuring pass finds; `measured` counts the passes' requests
    var found: [4]Mark = @splat(.{ .state = .failed });
    var measured: std.atomic.Value(u32) = .init(0);
    fn measure(_: *Group, ob: *const proxy.Outbound) Mark {
        _ = measured.fetchAdd(1, .monotonic);
        return found[index(ob)];
    }
    fn hosts(g: *Group, order: []const usize) bool {
        var buf: [max_members]usize = undefined;
        return std.mem.eql(usize, g.ranking(&buf), order);
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
        measured.store(0, .monotonic);
        var g: Group = .{ .io = testing.io, .probe = probe, .ping = ping, .measure = measure };
        g.on_switch = .{ .ctx = undefined, .call = onSwitch };
        return g;
    }
    fn settle(g: *Group) void {
        while (g.busy.load(.acquire) or g.measuring.load(.acquire)) testing.io.sleep(.fromMilliseconds(2), .awake) catch {};
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

test "the measuring pass runs when due and only while data flows, one server at a time" {
    var g = Fake.group();
    g.set(&.{ Fake.server("a.example"), Fake.server("b.example"), Fake.server("c.example") });
    // planned half a minute after the list came
    try testing.expect(g.measure_ms.load(.monotonic) > g.nowMs() + 20_000);
    Fake.found = .{ .{ .state = .ok, .reply_ms = 50, .speed = 1 << 20 }, .{ .state = .ok, .reply_ms = 300, .speed = 512 * 1024 }, .{ .state = .ok, .reply_ms = 90, .speed = 4 << 20 }, .{} };
    g.measure_ms.store(1, .monotonic);
    // nothing went through: an idle device measures nothing
    g.tick();
    Fake.settle(&g);
    try testing.expectEqual(0, Fake.measured.load(.monotonic));
    g.report(.carried);
    g.tick();
    Fake.settle(&g);
    // b and c, never the server in use
    try testing.expectEqual(2, Fake.measured.load(.monotonic));
    try testing.expect(g.measure_ms.load(.monotonic) > g.nowMs() + 20 * 60_000);
    // c: 90 ms + 250 ms a megabyte, b: 300 ms + 2 s
    try testing.expect(Fake.hosts(&g, &.{ 2, 1 }));
    // not due again
    g.report(.carried);
    g.tick();
    Fake.settle(&g);
    try testing.expectEqual(2, Fake.measured.load(.monotonic));

    // a new list keeps the marks of the servers that stay; a newcomer is
    // measured soon, and until then comes after the measured ones
    g.set(&.{ Fake.server("a.example"), Fake.server("d.example"), Fake.server("b.example"), Fake.server("c.example") });
    try testing.expect(g.measure_ms.load(.monotonic) < g.nowMs() + 60_000);
    try testing.expect(Fake.hosts(&g, &.{ 3, 2, 1 }));
    g.set(&.{Fake.server("a.example")});
    try testing.expectEqual(0, g.measure_ms.load(.monotonic));
}

test "the recovery tries the reserve in the measured order, dead and unmeasured servers after" {
    var g = Fake.group();
    g.set(&.{ Fake.server("a.example"), Fake.server("b.example"), Fake.server("c.example"), Fake.server("d.example") });
    // b connects fastest but the pass found it dead; d was measured best
    // but carries nothing now; c was not measured
    g.marks[1] = .{ .state = .failed };
    g.marks[3] = .{ .state = .ok, .reply_ms = 100, .speed = 1 << 20 };
    Fake.alive = .{ false, true, true, false };
    Fake.accepts = .{ null, 5, 30, 60 };
    Fake.fail(&g, 3);
    // a (again), d (measured), c (unmeasured) took it; b never asked
    try testing.expectEqual(2, g.activeIndex());
    try testing.expectEqual(3, Fake.probes.load(.monotonic));
}

test "the cost of a server: response time plus a megabyte's transfer" {
    try testing.expectEqual(1100, (Mark{ .state = .ok, .reply_ms = 100, .speed = 1 << 20 }).cost());
    try testing.expectEqual(8100, (Mark{ .state = .ok, .reply_ms = 100 }).cost());
    // a fast line with a slow answer loses to a fair line that answers at once
    try testing.expect((Mark{ .reply_ms = 900, .speed = 8 << 20 }).cost() > (Mark{ .reply_ms = 80, .speed = 2 << 20 }).cost());
}
