//! Headless runner for the local proxy, for testing the data plane without
//! the UI:  blackwall-proxy <listen-port> [vless-link]
//!          blackwall-proxy check <vless-link>   connect time, and whether a
//!                                               real request gets through

const std = @import("std");
const core = @import("core");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) {
        std.debug.print("usage: {s} <listen-port> [vless-link]\n", .{args[0]});
        return;
    }
    if (std.mem.eql(u8, args[1], "check")) {
        if (args.len < 3) return;
        const sv = try core.sublink.parseLink(init.arena.allocator(), args[2]);
        const ob: core.proxy.Outbound = .{ .vless = try core.proxy.vlessFromLink(args[2], sv.host, sv.port) };
        const r = core.failover.check(init.io, .{}, &ob);
        if (r.ping_ms) |ms| std.debug.print("connects in {d} ms, ", .{ms}) else std.debug.print("does not accept a connection, ", .{});
        std.debug.print("{s}\n", .{if (r.carries) "carries traffic" else "carries nothing"});
        return;
    }
    var proxy: core.proxy.Proxy = .{ .io = init.io };
    if (args.len > 2) {
        const sv = try core.sublink.parseLink(init.arena.allocator(), args[2]);
        proxy.setOutbound(.{ .vless = try core.proxy.vlessFromLink(args[2], sv.host, sv.port) });
    }
    try proxy.start(try std.fmt.parseInt(u16, args[1], 10));
    const o = proxy.outbound;
    std.debug.print("socks5 on 127.0.0.1:{d}, outbound {t}{s}{s}\n", .{
        proxy.port,
        o,
        if (o == .vless and o.vless.reality != null) " +reality" else "",
        if (o == .vless and o.vless.vision) " +vision" else "",
    });
    while (true) {
        try init.io.sleep(.fromSeconds(2), .awake);
        std.debug.print("down {d} up {d} active {d} failed {d} direct up/down {d}/{d} fault {t}\n", .{
            proxy.meter.down.load(.monotonic),     proxy.meter.up.load(.monotonic),
            proxy.meter.active.load(.monotonic),   proxy.meter.failed.load(.monotonic),
            proxy.meter.direct_up.load(.monotonic), proxy.meter.direct_down.load(.monotonic),
            proxy.meter.fault.load(.monotonic),
        });
    }
}
