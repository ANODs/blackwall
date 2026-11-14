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

    /// called after the member in use changed
    on_switch: ?Hook = null,
    /// the checks, replaceable in tests
    probe: *const fn (g: *Group, ob: *const proxy.Outbound) bool = realProbe,
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

    /// Replace the members: `list[0]` is the main server, the rest the
    /// reserve in the user's order. The member in use stays in use when it
    /// is still on the list and the main server did not change.
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
        for (list[0..n], 0..) |o, i| g.members[i] = .of(o);
        g.len = n;
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
            .carried => return g.score.store(0, .monotonic),
            .dial_failed => 2,
            .empty => 1,
        };
        if (g.score.fetchAdd(add, .monotonic) + add < threshold) return;
        if (g.nowMs() < g.next_ms.load(.monotonic)) return;
        g.start(recover);
    }

    /// Now and then, from a thread that runs anyway: while a reserve
    /// server is in use, look whether the main one is back.
    pub fn tick(g: *Group) void {
        const at = g.back_ms.load(.monotonic);
        if (at == 0 or g.nowMs() < at) return;
        g.start(lookBack);
    }

    /// Stop and wait for a recovery under way.
    pub fn stop(g: *Group) void {
        g.stopping.store(true, .release);
        while (g.busy.load(.acquire)) g.io.sleep(.fromMilliseconds(10), .awake) catch {};
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
        const th = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, run, .{g}) catch {
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
        if (cur_ob == .vless) if (g.dialer.resolver) |r| r.forget(cur_ob.vless.host);
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
        if (ob == .vless) if (g.dialer.resolver) |r| r.forget(ob.vless.host);
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
            threads[i] = std.Thread.spawn(.{ .stack_size = 128 * 1024 }, Job.run, .{&jobs[i]}) catch blk: {
                jobs[i].run();
                break :blk null;
            };
        }
        for (threads[0..n]) |t| if (t) |th| th.join();
    }
};

fn name(ob: *const proxy.Outbound) []const u8 {
    return switch (ob.*) {
        .vless => |v| v.host,
        else => @tagName(ob.*),
    };
}

/// The same server: address, port and account.
fn same(a: *const proxy.Outbound, b: *const proxy.Outbound) bool {
    if (a.* != .vless or b.* != .vless) return std.meta.activeTag(a.*) == std.meta.activeTag(b.*);
    return a.vless.port == b.vless.port and
        std.mem.eql(u8, a.vless.host, b.vless.host) and
        std.mem.eql(u8, &a.vless.uuid, &b.vless.uuid);
}

/// The two checks the recovery uses, for one server: how fast it accepts a
/// connection, and whether a real request gets through it.
pub fn check(io: Io, dialer: proxy.Dialer, ob: *const proxy.Outbound) struct { ping_ms: ?u32, carries: bool } {
    var g: Group = .{ .io = io, .dialer = dialer };
    return .{ .ping_ms = realPing(&g, ob), .carries = realProbe(&g, ob) };
}

const ping_timeout_ms = 2500;
const probe_wait_ms = 8000;
/// A plain-HTTP address made for connectivity checks: any HTTP answer
/// through the server proves it carries traffic.
const check_host = "www.gstatic.com";
const check_request = "GET /generate_204 HTTP/1.1\r\nHost: " ++ check_host ++ "\r\nConnection: close\r\n\r\n";

/// Milliseconds to connect to the server, or null when it does not accept.
fn realPing(g: *Group, ob: *const proxy.Outbound) ?u32 {
    if (ob.* != .vless) return null;
    var d = g.dialer;
    d.timeout_ms = ping_timeout_ms;
    const start = g.nowMs();
    const s = d.connect(g.io, ob.vless.host, ob.vless.port) catch return null;
    s.close(g.io);
    return @intCast(@max(1, g.nowMs() - start));
}

/// One real request through the server: connect, handshake, ask a known
/// address for a page and see an HTTP answer come back.
fn realProbe(g: *Group, ob: *const proxy.Outbound) bool {
    if (comptime !sys.supported) return false;
    if (ob.* != .vless) return false;
    var fds: [2]c.fd_t = undefined;
    if (c.socketpair(c.AF.UNIX, c.SOCK.STREAM, 0, &fds) != 0) return false;
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
    const th = std.Thread.spawn(.{ .stack_size = 512 * 1024 }, Runner.run, .{&runner}) catch {
        _ = c.close(fds[0]);
        return false;
    };

    _ = c.write(fds[1], check_request, check_request.len);
    var got: [256]u8 = undefined;
    var len: usize = 0;
    const deadline = g.nowMs() + probe_wait_ms;
    var ok = false;
    while (len < got.len and !g.stopping.load(.acquire)) {
        const left = deadline - g.nowMs();
        if (left <= 0 or !sys.waitFd(fds[1], false, @intCast(@min(left, 500)))) {
            if (left <= 0) break;
            continue;
        }
        const n = c.read(fds[1], got[len..].ptr, got.len - len);
        if (n <= 0) break;
        len += @intCast(n);
        // after the 10 bytes that say "connected" comes the page's answer
        if (std.mem.indexOf(u8, got[0..len], "HTTP/1.") != null) {
            ok = true;
            break;
        }
    }
    // ends the flow, whatever it is waiting for on our side
    _ = c.shutdown(fds[1], c.SHUT.RDWR);
    th.join();
    return ok;
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
    fn onSwitch(_: *anyopaque) void {
        _ = switched.fetchAdd(1, .monotonic);
    }
    fn server(comptime host: []const u8) proxy.Outbound {
        return .{ .vless = .{ .host = host, .port = 443, .uuid = @splat(7) } };
    }
    fn group() Group {
        probes.store(0, .monotonic);
        switched.store(0, .monotonic);
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
