//! Linux pieces of the data plane: the TUN device and everything around it.
//!
//! `openTun` opens a device somebody else set up (a script, systemd).
//! `up` does the whole job by itself (in `blackwall-tun`, see
//! tun_main.zig, or in a service that runs with the capability): it
//! creates the device, gives it its address, sends the default route and
//! the network's resolvers into it, and tells which physical interface the
//! service's own sockets must stay on. It needs CAP_NET_ADMIN and nothing
//! else: no root daemon, no `ip`, no netlink, only the classic ioctls.
//!
//! The kill switch is the device itself. It is created persistent, so when
//! the service dies the device and its routes stay and the traffic they
//! capture goes nowhere instead of out through the physical interface. A
//! service that starts again finds the device and takes it over; `remove`
//! lets the traffic go.

const std = @import("std");
const builtin = @import("builtin");
const c = std.c;

const log = std.log.scoped(.linux);

const TUNSETIFF: u32 = 0x400454ca; // _IOW('T', 202, int)
const TUNSETPERSIST: u32 = 0x400454cb; // _IOW('T', 203, int)
const TUNSETOWNER: u32 = 0x400454cc; // _IOW('T', 204, int)
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;

const SIOCADDRT: u32 = 0x890b;
const SIOCGIFFLAGS: u32 = 0x8913;
const SIOCSIFFLAGS: u32 = 0x8914;
const SIOCSIFADDR: u32 = 0x8916;
const SIOCSIFNETMASK: u32 = 0x891c;
const SIOCSIFMTU: u32 = 0x8922;
const SIOCGIFINDEX: u32 = 0x8933;
const IFF_UP: u16 = 0x1;
const IFF_RUNNING: u16 = 0x40;
const RTF_UP: u16 = 0x1;
const RTF_HOST: u16 = 0x4;

/// The device the app creates.
pub const device = "blackwall0";
/// Its address, and the address the fake DNS answers as (helper_ipc has the
/// same two for macOS).
const tun_addr = [4]u8{ 198, 18, 0, 1 };
const tun_mask = [4]u8{ 255, 254, 0, 0 };
const tun_addr6 = [16]u8{ 0xfd, 0x62, 0x6c, 0x61, 0x63, 0x6b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

const Ifreq = extern struct {
    name: [16]u8 = @splat(0),
    u: extern union {
        addr: SockaddrIn,
        flags: u16,
        index: c_int,
        mtu: c_int,
        pad: [24]u8,
    } = .{ .pad = @splat(0) },
};

const SockaddrIn = extern struct {
    family: u16 = 2, // AF_INET
    port: u16 = 0,
    addr: [4]u8 = @splat(0),
    zero: [8]u8 = @splat(0),
};

/// struct rtentry of <linux/route.h>
const Rtentry = extern struct {
    pad1: c_ulong = 0,
    dst: SockaddrIn = .{},
    gateway: SockaddrIn = .{},
    genmask: SockaddrIn = .{},
    flags: u16 = 0,
    pad2: i16 = 0,
    pad3: c_ulong = 0,
    pad4: ?*anyopaque = null,
    metric: i16 = 0,
    dev: ?[*:0]const u8 = null,
    mtu: c_ulong = 0,
    window: c_ulong = 0,
    irtt: u16 = 0,
};

/// struct in6_ifreq and struct in6_rtmsg of <linux/ipv6.h>, <linux/ipv6_route.h>
const In6Ifreq = extern struct { addr: [16]u8, prefixlen: u32, ifindex: c_int };
const In6Rtmsg = extern struct {
    dst: [16]u8 = @splat(0),
    src: [16]u8 = @splat(0),
    gateway: [16]u8 = @splat(0),
    type: u32 = 0,
    dst_len: u16 = 0,
    src_len: u16 = 0,
    metric: u32 = 1,
    info: c_ulong = 0,
    flags: u32 = RTF_UP,
    ifindex: c_int = 0,
};

/// Open (or create) the TUN interface `name`. Needs CAP_NET_ADMIN.
pub fn openTun(name: []const u8) !c.fd_t {
    if (name.len == 0 or name.len > 15) return error.BadName;
    const fd = c.open("/dev/net/tun", .{ .ACCMODE = .RDWR, .CLOEXEC = true });
    if (fd < 0) return error.TunUnavailable;
    errdefer _ = c.close(fd);
    // struct ifreq: name[16], then a union whose first member is the flags
    var ifr: [40]u8 = @splat(0);
    @memcpy(ifr[0..name.len], name);
    std.mem.writeInt(u16, ifr[16..18], IFF_TUN | IFF_NO_PI, .little);
    if (c.ioctl(fd, @bitCast(TUNSETIFF), &ifr) != 0) {
        return if (c.errno(@as(c_int, -1)) == .PERM) error.NeedsAdministrator else error.TunSetupFailed;
    }
    return fd;
}

pub const Options = struct {
    mtu: u16 = 1500,
    /// keep the device (and so the capture) when the service goes away
    hold: bool = true,
    /// send IPv6 into the device too (to be carried or refused there)
    ipv6: bool = true,
};

/// What `up` set up, for the service to run on.
pub const Lease = struct {
    fd: c.fd_t,
    /// the physical interface our own sockets must stay on
    bind: [16:0]u8 = @splat(0),
    /// the network's resolvers; they are routed into the device, and
    /// reached by us through `bind`
    dns: [4][4]u8 = undefined,
    dns_len: usize = 0,

    pub fn bindName(l: *const Lease) []const u8 {
        return std.mem.sliceTo(&l.bind, 0);
    }
};

/// Create (or take over) the device and capture the traffic with it.
pub fn up(io: std.Io, gpa: std.mem.Allocator, o: Options) !Lease {
    if (comptime builtin.os.tag != .linux) return error.Unsupported;
    // before our routes exist: where the real default route goes
    var lease: Lease = .{ .fd = -1 };
    const def = try defaultInterface(io, gpa);
    @memcpy(lease.bind[0..def.len], def.slice());
    lease.dns_len = resolvers(io, gpa, &lease.dns);

    loosenReversePath(def.slice());

    const fd = try openTun(device);
    errdefer _ = c.close(fd);
    // the user owns it: the service, which runs without capabilities, can
    // take it over again and let it go (`remove`)
    _ = c.ioctl(fd, @bitCast(TUNSETOWNER), @as(c_ulong, c.getuid()));
    if (c.ioctl(fd, @bitCast(TUNSETPERSIST), @as(c_ulong, @intFromBool(o.hold))) != 0) return error.TunSetupFailed;

    const s = c.socket(c.AF.INET, c.SOCK.DGRAM | c.SOCK.CLOEXEC, 0);
    if (s < 0) return error.SocketFailed;
    defer _ = c.close(s);
    var ifr: Ifreq = .{};
    @memcpy(ifr.name[0..device.len], device);
    ifr.u = .{ .addr = .{ .addr = tun_addr } };
    if (c.ioctl(s, @bitCast(SIOCSIFADDR), &ifr) != 0) return error.AddressFailed;
    ifr.u = .{ .addr = .{ .addr = tun_mask } };
    if (c.ioctl(s, @bitCast(SIOCSIFNETMASK), &ifr) != 0) return error.AddressFailed;
    ifr.u = .{ .pad = @splat(0) };
    ifr.u.mtu = std.math.clamp(o.mtu, 1280, 9000);
    _ = c.ioctl(s, @bitCast(SIOCSIFMTU), &ifr);
    ifr.u = .{ .pad = @splat(0) };
    if (c.ioctl(s, @bitCast(SIOCGIFFLAGS), &ifr) != 0) return error.AddressFailed;
    ifr.u.flags |= IFF_UP | IFF_RUNNING;
    if (c.ioctl(s, @bitCast(SIOCSIFFLAGS), &ifr) != 0) return error.AddressFailed;

    // everything, in two halves: more specific than the real default route,
    // which stays where it is for our own sockets
    try addRoute4(s, .{ 0, 0, 0, 0 }, .{ 128, 0, 0, 0 }, false);
    try addRoute4(s, .{ 128, 0, 0, 0 }, .{ 128, 0, 0, 0 }, false);
    // the resolvers, even on the local network: name lookups must reach
    // the tunnel's own DNS, which hands out the fake addresses
    for (lease.dns[0..lease.dns_len]) |ip| addRoute4(s, ip, .{ 255, 255, 255, 255 }, true) catch |err|
        log.warn("resolver {d}.{d}.{d}.{d} is not captured: {t}", .{ ip[0], ip[1], ip[2], ip[3], err });
    if (o.ipv6) captureIpv6(s) catch |err| log.warn("IPv6 is not captured: {t}", .{err});

    lease.fd = fd;
    return lease;
}

/// Let the traffic go: the device and its routes disappear. For a device
/// left behind by a service that is gone, and for the clean stop.
pub fn remove() void {
    if (comptime builtin.os.tag != .linux) return;
    const fd = openTun(device) catch return;
    _ = c.ioctl(fd, @bitCast(TUNSETPERSIST), @as(c_ulong, 0));
    _ = c.close(fd);
}

/// Stop holding: the device goes when its descriptor is closed.
pub fn release(fd: c.fd_t) void {
    if (comptime builtin.os.tag != .linux) return;
    _ = c.ioctl(fd, @bitCast(TUNSETPERSIST), @as(c_ulong, 0));
}

/// With the strict reverse-path filter (the default on many systems) the
/// kernel drops the answers to our own sockets: they arrive on the physical
/// interface from addresses that, by the routing table, live behind the
/// device. The loose mode accepts a source that is reachable at all. Only
/// the physical interface is changed (the stricter of "all" and the
/// interface's own value does not apply: the kernel takes the larger).
fn loosenReversePath(iface: []const u8) void {
    var path_buf: [96]u8 = undefined;
    const path = std.fmt.bufPrint(path_buf[0 .. path_buf.len - 1], "/proc/sys/net/ipv4/conf/{s}/rp_filter", .{iface}) catch return;
    path_buf[path.len] = 0;
    const fd = c.open(@ptrCast(path.ptr), .{ .ACCMODE = .RDWR, .CLOEXEC = true });
    if (fd < 0) return;
    defer _ = c.close(fd);
    var cur: [8]u8 = undefined;
    const n = c.read(fd, &cur, cur.len);
    if (n <= 0 or cur[0] != '1') return;
    if (c.pwrite(fd, "2\n", 2, 0) != 2) log.warn("the reverse-path filter of {s} stays strict: direct connections may not work", .{iface});
}

fn addRoute4(s: c.fd_t, dst: [4]u8, mask: [4]u8, host: bool) !void {
    var rt: Rtentry = .{
        .dst = .{ .addr = dst },
        .genmask = .{ .addr = mask },
        .flags = RTF_UP | (if (host) RTF_HOST else 0),
        .dev = device,
    };
    if (c.ioctl(s, @bitCast(SIOCADDRT), &rt) != 0) {
        // there already: a device taken over from a service that went away
        if (c.errno(@as(c_int, -1)) == .EXIST) return;
        return error.RouteFailed;
    }
}

fn captureIpv6(s4: c.fd_t) !void {
    var ifr: Ifreq = .{};
    @memcpy(ifr.name[0..device.len], device);
    if (c.ioctl(s4, @bitCast(SIOCGIFINDEX), &ifr) != 0) return error.NoIndex;
    const index = ifr.u.index;
    const s = c.socket(c.AF.INET6, c.SOCK.DGRAM | c.SOCK.CLOEXEC, 0);
    if (s < 0) return error.SocketFailed;
    defer _ = c.close(s);
    var a: In6Ifreq = .{ .addr = tun_addr6, .prefixlen = 126, .ifindex = index };
    if (c.ioctl(s, @bitCast(SIOCSIFADDR), &a) != 0 and c.errno(@as(c_int, -1)) != .EXIST) return error.AddressFailed;
    for ([_]u8{ 0x00, 0x80 }) |first| {
        var rt: In6Rtmsg = .{ .dst_len = 1, .ifindex = index };
        rt.dst[0] = first;
        if (c.ioctl(s, @bitCast(SIOCADDRT), &rt) != 0 and c.errno(@as(c_int, -1)) != .EXIST) return error.RouteFailed;
    }
}

const Name = struct {
    buf: [16]u8 = @splat(0),
    len: usize = 0,
    fn slice(n: *const Name) []const u8 {
        return n.buf[0..n.len];
    }
};

/// The interface of the default route with the lowest metric, not ours.
fn defaultInterface(io: std.Io, gpa: std.mem.Allocator) !Name {
    _ = io;
    const text = readAll(gpa, "/proc/net/route") orelse return error.NoDefaultRoute;
    defer gpa.free(text);
    return parseDefault(text) orelse error.NoDefaultRoute;
}

/// A whole small file, read until it ends: files in /proc say they are
/// empty, so nothing that sizes its buffer by the file's length works.
fn readAll(gpa: std.mem.Allocator, path: [*:0]const u8) ?[]u8 {
    const fd = c.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    if (fd < 0) return null;
    defer _ = c.close(fd);
    var out: std.ArrayList(u8) = .empty;
    var buf: [4096]u8 = undefined;
    while (out.items.len < 1 << 20) {
        const n = c.read(fd, &buf, buf.len);
        if (n < 0) {
            if (c.errno(n) == .INTR) continue;
            out.deinit(gpa);
            return null;
        }
        if (n == 0) break;
        out.appendSlice(gpa, buf[0..@intCast(n)]) catch {
            out.deinit(gpa);
            return null;
        };
    }
    return out.toOwnedSlice(gpa) catch {
        out.deinit(gpa);
        return null;
    };
}

fn parseDefault(text: []const u8) ?Name {
    var best: ?Name = null;
    var best_metric: u32 = std.math.maxInt(u32);
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    _ = lines.next(); // the header
    while (lines.next()) |line| {
        var f = std.mem.tokenizeAny(u8, line, " \t");
        const iface = f.next() orelse continue;
        const dst = f.next() orelse continue;
        _ = f.next(); // gateway
        const flags = std.fmt.parseInt(u16, f.next() orelse continue, 16) catch continue;
        _ = f.next(); // refcnt
        _ = f.next(); // use
        const metric = std.fmt.parseInt(u32, f.next() orelse continue, 10) catch continue;
        const mask = f.next() orelse continue;
        if (!std.mem.eql(u8, dst, "00000000") or !std.mem.eql(u8, mask, "00000000")) continue;
        if (flags & RTF_UP == 0 or iface.len > 15 or std.mem.eql(u8, iface, device)) continue;
        if (metric >= best_metric) continue;
        best_metric = metric;
        var n: Name = .{ .len = iface.len };
        @memcpy(n.buf[0..iface.len], iface);
        best = n;
    }
    return best;
}

/// IPv4 resolvers of the network. With systemd-resolved, resolv.conf names
/// only its local stub; the real ones are in its own file.
fn resolvers(io: std.Io, gpa: std.mem.Allocator, out: *[4][4]u8) usize {
    var n: usize = 0;
    _ = io;
    for ([_][*:0]const u8{ "/run/systemd/resolve/resolv.conf", "/etc/resolv.conf" }) |path| {
        const text = readAll(gpa, path) orelse continue;
        defer gpa.free(text);
        n = parseResolvers(text, out);
        if (n > 0) break;
    }
    return n;
}

fn parseResolvers(text: []const u8, out: *[4][4]u8) usize {
    var n: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        var f = std.mem.tokenizeAny(u8, raw, " \t");
        if (!std.mem.eql(u8, f.next() orelse continue, "nameserver")) continue;
        const ip = std.Io.net.Ip4Address.parse(f.next() orelse continue, 0) catch continue;
        // a local stub (127.0.0.53) is not a resolver of the network, and
        // our own fake range would loop
        if (ip.bytes[0] == 127 or (ip.bytes[0] == 198 and ip.bytes[1] & 0xfe == 18)) continue;
        if (n == out.len) break;
        out[n] = ip.bytes;
        n += 1;
    }
    return n;
}

test "the default route with the lowest metric that is not ours" {
    const table =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" ++
        "blackwall0\t00000000\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0\n" ++
        "wlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" ++
        "eth0\t00000000\t0205A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" ++
        "eth0\t0005A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
    try std.testing.expectEqualStrings("eth0", parseDefault(table).?.slice());
    try std.testing.expect(parseDefault("Iface\tDestination\n") == null);
    // only our own default route: there is no way out
    try std.testing.expect(parseDefault("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" ++
        "blackwall0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\n") == null);
}

test "resolvers of the network, without local stubs and our own range" {
    var out: [4][4]u8 = undefined;
    const n = parseResolvers(
        \\# Generated by something
        \\search lan
        \\nameserver 127.0.0.53
        \\nameserver 192.168.5.2
        \\nameserver 198.18.0.2
        \\nameserver fe80::1
        \\nameserver 1.1.1.1
    , &out);
    try std.testing.expectEqual(2, n);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 5, 2 }, &out[0]);
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 1, 1 }, &out[1]);
}

test "the kernel structures have the sizes the ioctls expect" {
    if (builtin.os.tag != .linux or @sizeOf(usize) != 8) return error.SkipZigTest;
    try std.testing.expectEqual(40, @sizeOf(Ifreq));
    try std.testing.expectEqual(120, @sizeOf(Rtentry));
    try std.testing.expectEqual(24, @sizeOf(In6Ifreq));
    try std.testing.expectEqual(80, @sizeOf(In6Rtmsg));
}
