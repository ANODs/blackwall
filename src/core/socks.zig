//! The local SOCKS5 inbound: 127.0.0.1:port, every connection one flow
//! (proxy.zig) through the outbound it was started with.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const proxy = @import("proxy.zig");
const tls13 = @import("tls13.zig");
const sys = @import("sys.zig");

const Outbound = proxy.Outbound;
const Snapshot = proxy.Snapshot;
const Target = proxy.Target;
const Dialer = proxy.Dialer;
const Meter = proxy.Meter;
const Local = proxy.Local;
const Flow = proxy.Flow;

pub const Proxy = struct {
    io: Io,
    port: u16 = 0,
    outbound: Outbound = .direct,
    dialer: Dialer = .{},
    meter: Meter = .{},
    /// a second meter fed by every flow (for example the service totals)
    extra: ?*Meter = null,

    server: ?net.Server = null,
    running: std.atomic.Value(bool) = .init(false),
    accept_thread: ?std.Thread = null,
    /// connections being served; `stop` waits for them, since each of
    /// their threads still uses this Proxy
    handlers: std.atomic.Value(u32) = .init(0),
    /// tells flows that only wait for a server to finish to give up
    stopping: std.atomic.Value(bool) = .init(false),

    pub fn setOutbound(p: *Proxy, o: Outbound) void {
        std.debug.assert(!p.running.load(.acquire));
        p.outbound = o;
    }

    /// Listen on 127.0.0.1:`port` (0 = any free port, see `p.port` after).
    /// Strings in the outbound are copied, the caller's may go away.
    pub fn start(p: *Proxy, port: u16) !void {
        if (p.running.load(.acquire)) return;
        const address: net.IpAddress = .{ .ip4 = .loopback(port) };
        var server = try address.listen(p.io, .{ .reuse_address = true });
        errdefer server.deinit(p.io);
        p.port = server.socket.address.getPort();
        p.server = server;
        p.meter.fault.store(.none, .monotonic);
        p.stopping.store(false, .release);
        p.running.store(true, .release);
        // a failed start leaves nothing behind for `stop` to close again
        errdefer {
            p.running.store(false, .release);
            p.server = null;
        }
        p.accept_thread = try std.Thread.spawn(.{}, acceptLoop, .{ p, Snapshot.of(p.outbound) });
    }

    pub fn stop(p: *Proxy) void {
        if (!p.running.swap(false, .acq_rel)) return;
        // wake the blocked accept with a throwaway connection
        const address: net.IpAddress = .{ .ip4 = .loopback(p.port) };
        if (address.connect(p.io, .{ .mode = .stream })) |s| s.close(p.io) else |_| {}
        if (p.accept_thread) |t| t.join();
        p.accept_thread = null;
        if (p.server) |*s| s.deinit(p.io);
        p.server = null;
        // let the connections in flight end: a few seconds for those whose
        // application is still there, the rest is left to the process
        p.stopping.store(true, .release);
        var waited_ms: u32 = 0;
        while (p.handlers.load(.acquire) > 0 and waited_ms < 5000) : (waited_ms += 2) {
            p.io.sleep(.fromMilliseconds(2), .awake) catch {};
        }
    }

    fn acceptLoop(p: *Proxy, snap: Snapshot) void {
        while (p.running.load(.acquire)) {
            const client = p.server.?.accept(p.io) catch {
                // out of descriptors, say: wait instead of spinning on it
                p.io.sleep(.fromMilliseconds(20), .awake) catch {};
                continue;
            };
            if (!p.running.load(.acquire)) {
                client.close(p.io);
                break;
            }
            _ = p.handlers.fetchAdd(1, .acq_rel);
            const t = std.Thread.spawn(.{ .stack_size = sys.stackSize(proxy.dial_stack_size) }, handle, .{ p, client, snap }) catch {
                _ = p.handlers.fetchSub(1, .acq_rel);
                client.close(p.io);
                continue;
            };
            t.detach();
        }
    }

    fn handle(p: *Proxy, client: net.Stream, snap: Snapshot) void {
        // last: nothing of `p` is touched after the count goes down
        defer _ = p.handlers.fetchSub(1, .acq_rel);
        const io = p.io;
        defer client.close(io);
        p.serve(client, &snap) catch {};
    }

    fn serve(p: *Proxy, client: net.Stream, snap: *const Snapshot) !void {
        const io = p.io;
        var crb: [tls13.min_read_buffer]u8 = undefined;
        var cwb: [4096]u8 = undefined;
        var cr = client.reader(io, &crb);
        var cw = client.writer(io, &cwb);
        var local: Local = .{ .r = &cr.interface, .w = &cw.interface, .end = .{ .socks = client } };
        const target = try socksRequest(local.r, local.w);
        const flow: Flow = .{ .io = io, .dialer = p.dialer, .meters = .{ &p.meter, p.extra, null }, .stop = &p.stopping };
        const ob = snap.get();
        try flow.run(&local, &target, &ob);
    }
};

fn socksRequest(r: *Io.Reader, w: *Io.Writer) !Target {
    // greeting: VER NMETHODS METHODS...
    if (try r.takeByte() != 5) return error.NotSocks5;
    const nmethods = try r.takeByte();
    _ = try r.take(nmethods);
    try w.writeAll(&.{ 5, 0 }); // no authentication
    try w.flush();

    // request: VER CMD RSV ATYP ADDR PORT
    const head = (try r.takeArray(4)).*;
    if (head[0] != 5) return error.NotSocks5;
    var target: Target = undefined;
    switch (head[3]) {
        1 => {
            target = .{ .kind = .ip4, .len = 4, .port = 0 };
            @memcpy(target.bytes[0..4], try r.take(4));
        },
        3 => {
            const n = try r.takeByte();
            target = .{ .kind = .domain, .len = n, .port = 0 };
            @memcpy(target.bytes[0..n], try r.take(n));
        },
        4 => {
            target = .{ .kind = .ip6, .len = 16, .port = 0 };
            @memcpy(target.bytes[0..16], try r.take(16));
        },
        else => {
            try proxy.socksReply(w, 8);
            return error.BadAddress;
        },
    }
    target.port = std.mem.readInt(u16, try r.takeArray(2), .big);
    if (head[1] != 1) { // only CONNECT
        try proxy.socksReply(w, 7);
        return error.UnsupportedCommand;
    }
    return target;
}
