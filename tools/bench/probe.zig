//! The client side of tools/bench/android.py, run inside the Android emulator: it
//! downloads through whatever VPN is on there, from the bench site behind the server.
//! Plain HTTP to an IP address, so no DNS is involved and no client takes the address for
//! a local one (the server sends that address to the site; see android.py).
//!
//!   probe get <ip> <port> <bytes>        one download             → "<bytes> <seconds>"
//!   probe par <ip> <port> <n> <bytes>    n downloads at once      → "<bytes> <seconds>"
//!   probe hs <ip> <port> <n>             n small requests, each on a new connection
//!                                                                 → "<median ms>"
//!
//!   zig build-exe tools/bench/probe.zig -target aarch64-linux-musl -O ReleaseFast

const std = @import("std");
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var args = init.minimal.args.iterate();
    _ = args.next();
    const cmd = args.next() orelse return usage();
    const ip = args.next() orelse return usage();
    const port = try std.fmt.parseInt(u16, args.next() orelse return usage(), 10);
    const addr = try Io.net.IpAddress.parse(ip, port);

    var out_buf: [256]u8 = undefined;
    var out = Io.File.stdout().writer(io, &out_buf);
    const w = &out.interface;

    if (std.mem.eql(u8, cmd, "get")) {
        const size = try std.fmt.parseInt(u64, args.next() orelse return usage(), 10);
        const t0 = Io.Clock.awake.now(io);
        const got = try fetch(io, addr, size);
        try w.print("{d} {d:.3}\n", .{ got, seconds(io, t0) });
    } else if (std.mem.eql(u8, cmd, "par")) {
        const n = try std.fmt.parseInt(usize, args.next() orelse return usage(), 10);
        const size = try std.fmt.parseInt(u64, args.next() orelse return usage(), 10);
        var got: [64]u64 = @splat(0);
        var threads: [64]std.Thread = undefined;
        if (n > threads.len) return usage();
        const t0 = Io.Clock.awake.now(io);
        for (0..n) |i| threads[i] = try std.Thread.spawn(.{}, worker, .{ io, addr, size, &got[i] });
        for (threads[0..n]) |t| t.join();
        var total: u64 = 0;
        for (got[0..n]) |g| total += g;
        try w.print("{d} {d:.3}\n", .{ total, seconds(io, t0) });
    } else if (std.mem.eql(u8, cmd, "hs")) {
        const n = try std.fmt.parseInt(usize, args.next() orelse return usage(), 10);
        var ms: [1000]f64 = undefined;
        if (n == 0 or n > ms.len) return usage();
        for (ms[0..n]) |*m| {
            const t0 = Io.Clock.awake.now(io);
            _ = try fetch(io, addr, 2);
            m.* = seconds(io, t0) * 1000;
        }
        std.mem.sort(f64, ms[0..n], {}, std.sort.asc(f64));
        try w.print("{d:.1}\n", .{ms[n / 2]});
    } else return usage();
    try w.flush();
}

fn usage() error{Usage} {
    std.debug.print("usage: probe get|par|hs <ip> <port> ...\n", .{});
    return error.Usage;
}

fn seconds(io: Io, t0: Io.Timestamp) f64 {
    const ns = t0.durationTo(Io.Clock.awake.now(io)).toNanoseconds();
    return @as(f64, @floatFromInt(ns)) / 1e9;
}

fn worker(io: Io, addr: Io.net.IpAddress, size: u64, got: *u64) void {
    got.* = fetch(io, addr, size) catch 0;
}

/// GET /bytes/<size> on a new connection; the body's length.
fn fetch(io: Io, addr: Io.net.IpAddress, size: u64) !u64 {
    const s = try addr.connect(io, .{ .mode = .stream });
    defer s.close(io);
    var wb: [256]u8 = undefined;
    var sw = s.writer(io, &wb);
    try sw.interface.print("GET /bytes/{d} HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n", .{size});
    try sw.interface.flush();
    var rb: [64 * 1024]u8 = undefined;
    var sr = s.reader(io, &rb);
    const r = &sr.interface;
    // the head, up to the empty line
    while (true) {
        const line = try r.takeDelimiterInclusive('\n');
        if (line.len <= 2) break;
    }
    var body: u64 = 0;
    while (body < size) {
        const chunk = r.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        body += chunk.len;
        r.toss(chunk.len);
    }
    return body;
}
