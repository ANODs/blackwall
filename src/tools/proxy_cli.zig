//! Headless runner for the local proxy, for testing the data plane without
//! the UI:  blackwall-proxy <listen-port> [link]
//!          blackwall-proxy check <link>   connect time, whether a real
//!                                         request gets through, and the
//!                                         reserve's measurement (response
//!                                         time, download speed)
//!          blackwall-proxy udp <link> <ip:port>   one datagram through the
//!                                         server and its answer (port 53:
//!                                         a DNS query for example.com)
//! A link is vless://, trojan://, ss:// or vmess://. `--trust <ca.pem>` in
//! front of either form adds a certificate authority to the system's, for
//! tests against a local server with a throwaway certificate.
//! `--bind <interface>` (first) sends the tool's own connections out of that
//! interface, past a VPN that captures the default route, as the service
//! does: `blackwall-proxy --bind en0 check <link>`.

const std = @import("std");
const core = @import("core");

pub fn main(init: std.process.Init) !void {
    var args = try init.minimal.args.toSlice(init.arena.allocator());
    var bind: core.sys.Bind = .none;
    if (args.len > 2 and std.mem.eql(u8, args[1], "--bind")) {
        bind = .interface(args[2]);
        args = args[2..];
    }
    // names are then asked of public resolvers through the same interface:
    // the system's resolver may be the VPN's
    var resolver: core.ipstack.dns.Resolver = .{ .gpa = init.gpa, .io = init.io, .servers = &.{}, .bind = bind };
    defer resolver.deinit();
    const dialer: core.proxy.Dialer = .{ .bind = bind, .resolver = if (bind == .none) null else &resolver };
    if (args.len > 2 and std.mem.eql(u8, args[1], "--trust")) {
        if (!std.fs.path.isAbsolute(args[2])) {
            std.debug.print("--trust takes an absolute path\n", .{});
            return;
        }
        try core.tls13.addTestRoot(init.io, args[2]);
        args = args[2..];
    }
    if (args.len < 2) {
        std.debug.print("usage: blackwall-proxy [--trust <ca.pem>] <listen-port> [link]\n", .{});
        return;
    }
    if (std.mem.eql(u8, args[1], "check")) {
        if (args.len < 3) return;
        const sv = try core.sublink.parseLink(init.arena.allocator(), args[2]);
        const ob = try core.proxy.outboundFromLink(args[2], sv.host, sv.port);
        const r = core.failover.check(init.io, dialer, &ob);
        if (r.ping_ms) |ms| std.debug.print("connects in {d} ms, ", .{ms}) else std.debug.print("does not accept a connection, ", .{});
        std.debug.print("{s}\n", .{if (r.carries) "carries traffic" else "carries nothing"});
        switch (r.mark.state) {
            .ok => std.debug.print("measured: answers in {d} ms, {d} KB/s, a megabyte in {d} ms\n", .{ r.mark.reply_ms, r.mark.speed / 1024, r.mark.cost() }),
            else => std.debug.print("measured: no answer\n", .{}),
        }
        return;
    }
    if (std.mem.eql(u8, args[1], "udp")) {
        if (args.len < 4) return;
        const sv = try core.sublink.parseLink(init.arena.allocator(), args[2]);
        const ob = try core.proxy.outboundFromLink(args[2], sv.host, sv.port);
        return udpCheck(init, dialer, ob, args[3]);
    }
    var proxy: core.proxy.Proxy = .{ .io = init.io };
    proxy.dialer = dialer;
    if (args.len > 2 and std.mem.startsWith(u8, args[2], "dpi")) {
        // the DPI bypass route; "dpi:segments" fixes one way for every host
        proxy.setOutbound(.dpi);
        if (args[2].len > 4) core.dpi.force = std.meta.stringToEnum(core.dpi.Strategy, args[2][4..]) orelse return error.UnknownStrategy;
    } else if (args.len > 2) {
        const sv = try core.sublink.parseLink(init.arena.allocator(), args[2]);
        proxy.setOutbound(try core.proxy.outboundFromLink(args[2], sv.host, sv.port));
    }
    try proxy.start(try std.fmt.parseInt(u16, args[1], 10));
    const o = proxy.outbound;
    // how the server is reached, without anything of the link itself
    const via = o.via();
    std.debug.print("socks5 on 127.0.0.1:{d}, outbound {t}{s}{s}{s}{s}\n", .{
        proxy.port,
        o,
        if (via) |v| (if (v.reality != null) " +reality" else if (v.tls != null) " +tls" else "") else "",
        if (via != null) " +" else "",
        if (via) |v| @tagName(v.transport.*) else "",
        if (o == .vless and o.vless.vision) " +vision" else "",
    });
    while (true) {
        try init.io.sleep(.fromSeconds(2), .awake);
        std.debug.print("down {d} up {d} active {d} failed {d} direct up/down {d}/{d} fault {t}\n", .{
            proxy.meter.down.load(.monotonic),      proxy.meter.up.load(.monotonic),
            proxy.meter.active.load(.monotonic),    proxy.meter.failed.load(.monotonic),
            proxy.meter.direct_up.load(.monotonic), proxy.meter.direct_down.load(.monotonic),
            proxy.meter.fault.load(.monotonic),
        });
    }
}

/// One datagram to `to` through the server of `ob`, and what comes back.
fn udpCheck(init: std.process.Init, dialer: core.proxy.Dialer, ob: core.proxy.Outbound, to: []const u8) !void {
    const ip = try std.Io.net.IpAddress.parseLiteral(to);
    const addr, const port = core.sys.fromIpAddress(ip);
    const c = try init.gpa.create(core.udp_out.Conn);
    defer init.gpa.destroy(c);
    c.* = core.udp_out.Conn.init(init.io, ob) orelse return std.debug.print("this server carries no UDP\n", .{});
    const f: core.proxy.Flow = .{ .io = init.io, .dialer = dialer };
    const t0 = std.Io.Clock.awake.now(init.io).toMilliseconds();
    c.open(&f) catch |err| return std.debug.print("does not open: {t}\n", .{err});
    defer c.deinit();
    defer c.close();
    // a stream with no answer would be read for ever: end it after a while
    const watchdog = try std.Thread.spawn(.{}, struct {
        fn run(io: std.Io, conn: *core.udp_out.Conn) void {
            io.sleep(.fromSeconds(8), .awake) catch {};
            conn.close();
        }
    }.run, .{ init.io, c });
    watchdog.detach();
    const query = [_]u8{ 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7 } ++ "example".* ++ [_]u8{3} ++ "com".* ++ [_]u8{ 0, 0, 1, 0, 1 };
    const payload: []const u8 = if (port == 53) &query else "ping through blackwall";
    const peer: core.udp_out.Peer = .{ .port = port, .addr = if (core.ipstack.packet.isV4(&addr)) .{ .ip4 = addr[12..16].* } else .{ .ip6 = addr } };
    for (0..3) |_| {
        c.send(peer, payload) catch |err| return std.debug.print("send: {t}\n", .{err});
        const d = (c.recv(3000) catch |err| return std.debug.print("recv: {t}\n", .{err})) orelse continue;
        const ms = std.Io.Clock.awake.now(init.io).toMilliseconds() - t0;
        if (port == 53) {
            const ok = d.payload.len > 12 and d.payload[0] == 0x12 and d.payload[1] == 0x34 and std.mem.readInt(u16, d.payload[6..8], .big) > 0;
            std.debug.print("{s}: a DNS answer of {d} bytes in {d} ms\n", .{ if (ok) "ok" else "BAD", d.payload.len, ms });
        } else std.debug.print("answer in {d} ms: {s}\n", .{ ms, d.payload });
        return;
    }
    std.debug.print("no answer\n", .{});
}
