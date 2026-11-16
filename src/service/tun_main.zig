//! blackwall-tun: the one part of BLACKWALL on Linux that needs a network
//! capability (CAP_NET_ADMIN, granted to this file once through polkit).
//!
//!   blackwall-tun up --sock FD [--mtu N] [--hold] [--ipv6]
//!   blackwall-tun strict --servers A,B --dns C,D [--lan] [--ipv6-block]
//!   blackwall-tun open
//!   blackwall-tun release
//!
//! `up` creates the device, its address and routes (linux.zig), and hands
//! the device's descriptor to the service over the socket it inherited,
//! with what the service needs to know as one line of JSON:
//!   {"bind":"wlan0","dns":["192.168.1.1"]}
//! A failure is reported the same way: {"error":"NeedsAdministrator"}.
//! `strict` sets the strict kill switch (nft.zig), `open` removes it.
//! `release` lets go of a device that a service which is gone still holds,
//! and of the kill switch.
//!
//! The service itself runs without any capability, so replacing it (an
//! update) asks for nothing; this file stays as long as it does not change.

const std = @import("std");
const builtin = @import("builtin");
const fdpass = @import("fdpass");
const linux = @import("linux.zig");
const nft = @import("nft.zig");
const c = std.c;

pub fn main(init: std.process.Init) !void {
    if (comptime builtin.os.tag != .linux) return error.Unsupported;
    const a = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(a);
    if (argv.len < 2) return usage();
    if (std.mem.eql(u8, argv[1], "release")) {
        linux.remove();
        nftApply(init.io, nft.open_script) catch {};
        return;
    }
    if (std.mem.eql(u8, argv[1], "open")) return nftApply(init.io, nft.open_script);
    if (std.mem.eql(u8, argv[1], "strict")) {
        var servers: [64][4]u8 = undefined;
        var dns: [16][4]u8 = undefined;
        var o: nft.Options = .{ .servers4 = &.{}, .dns4 = &.{}, .allow_lan = false, .ipv6_block = false };
        var i: usize = 2;
        while (i < argv.len) : (i += 1) {
            const val = if (i + 1 < argv.len) argv[i + 1] else "";
            if (std.mem.eql(u8, argv[i], "--servers")) {
                o.servers4 = servers[0..nft.parseList(val, &servers)];
                i += 1;
            } else if (std.mem.eql(u8, argv[i], "--dns")) {
                o.dns4 = dns[0..nft.parseList(val, &dns)];
                i += 1;
            } else if (std.mem.eql(u8, argv[i], "--lan")) {
                o.allow_lan = true;
            } else if (std.mem.eql(u8, argv[i], "--ipv6-block")) {
                o.ipv6_block = true;
            } else return usage();
        }
        return nftApply(init.io, try nft.rules(a, o));
    }
    if (!std.mem.eql(u8, argv[1], "up")) return usage();

    var sock: ?std.c.fd_t = null;
    var o: linux.Options = .{ .hold = false, .ipv6 = false };
    var i: usize = 2;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        const val = if (i + 1 < argv.len) argv[i + 1] else "";
        if (std.mem.eql(u8, arg, "--sock")) {
            sock = try std.fmt.parseInt(std.c.fd_t, val, 10);
            i += 1;
        } else if (std.mem.eql(u8, arg, "--mtu")) {
            o.mtu = try std.fmt.parseInt(u16, val, 10);
            i += 1;
        } else if (std.mem.eql(u8, arg, "--hold")) {
            o.hold = true;
        } else if (std.mem.eql(u8, arg, "--ipv6")) {
            o.ipv6 = true;
        } else return usage();
    }
    const s = sock orelse return usage();

    var line: std.Io.Writer.Allocating = .init(a);
    const lease = linux.up(init.io, a, o) catch |err| {
        line.writer.print("{{\"error\":\"{t}\"}}\n", .{err}) catch {};
        fdpass.sendAll(s, line.written()) catch {};
        return err;
    };
    var dns: [4][]const u8 = undefined;
    for (lease.dns[0..lease.dns_len], 0..) |ip, k| dns[k] = try std.fmt.allocPrint(a, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
    try std.json.Stringify.value(.{ .bind = lease.bindName(), .dns = dns[0..lease.dns_len] }, .{}, &line.writer);
    try line.writer.writeByte('\n');
    try fdpass.sendFd(s, lease.fd, line.written());
}

fn usage() error{Usage} {
    std.debug.print("usage: blackwall-tun up --sock FD [--mtu N] [--hold] [--ipv6] | strict --servers A,B --dns C,D [--lan] [--ipv6-block] | open | release\n", .{});
    return error.Usage;
}

const CapHeader = extern struct { version: u32 = 0x20080522, pid: c_int = 0 };
const CapData = extern struct { effective: u32, permitted: u32, inheritable: u32 };
extern "c" fn capget(h: *CapHeader, d: *[2]CapData) c_int;
extern "c" fn capset(h: *CapHeader, d: *const [2]CapData) c_int;
extern "c" fn prctl(option: c_int, ...) c_int;
const CAP_NET_ADMIN = 12;
const PR_CAP_AMBIENT = 47;
const PR_CAP_AMBIENT_RAISE = 2;

/// Runs `nft -f -` with `script`. nft needs CAP_NET_ADMIN too: it is passed
/// on to it as an ambient capability (file capabilities do not cross exec).
fn nftApply(io: std.Io, script: []const u8) !void {
    var h: CapHeader = .{};
    var d: [2]CapData = undefined;
    if (capget(&h, &d) == 0) {
        d[0].inheritable |= 1 << CAP_NET_ADMIN;
        _ = capset(&h, &d);
        _ = prctl(PR_CAP_AMBIENT, @as(c_ulong, PR_CAP_AMBIENT_RAISE), @as(c_ulong, CAP_NET_ADMIN), @as(c_ulong, 0), @as(c_ulong, 0));
    }
    const exe = for ([_][]const u8{ "/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft" }) |p| {
        std.Io.Dir.cwd().access(io, p, .{}) catch continue;
        break p;
    } else return error.NftMissing;
    var pipe: [2]c.fd_t = undefined;
    // close-on-exec: nft must not inherit the write end, or it never sees
    // the end of its input (its stdin is a dup, which drops the flag)
    if (c.pipe2(&pipe, .{ .CLOEXEC = true }) != 0) return error.PipeFailed;
    var child = std.process.spawn(io, .{
        .argv = &.{ exe, "-f", "-" },
        .stdin = .{ .file = .{ .handle = pipe[0], .flags = .{ .nonblocking = false } } },
        .stdout = .ignore,
        .stderr = .inherit,
    }) catch |err| {
        _ = c.close(pipe[0]);
        _ = c.close(pipe[1]);
        return err;
    };
    _ = c.close(pipe[0]);
    var off: usize = 0;
    while (off < script.len) {
        const n = c.write(pipe[1], script[off..].ptr, script.len - off);
        if (n <= 0) break;
        off += @intCast(n);
    }
    _ = c.close(pipe[1]);
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) return error.NftFailed;
}
