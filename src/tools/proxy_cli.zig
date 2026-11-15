//! Headless runner for the local proxy, for testing the data plane without
//! the UI:  blackwall-proxy <listen-port> [link]
//!          blackwall-proxy check <link>   connect time, and whether a real
//!                                         request gets through
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
        return;
    }
    var proxy: core.proxy.Proxy = .{ .io = init.io };
    proxy.dialer = dialer;
    if (args.len > 2) {
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
