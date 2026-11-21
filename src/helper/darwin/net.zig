//! macOS network control for the root helper: the utun device, its MTU and
//! addresses, interface routes into it, the physical default route, and the
//! capture routes of other VPNs. Raw ioctls and route-socket messages only;
//! nothing shells out to ifconfig or route.
//!
//! Changing anything (openUtun, setMtu, addAddress*, addRoute, deleteRoute)
//! needs root. defaultRoute and foreignCaptures only read and work as any user.
//!
//! Addresses are 16 bytes: IPv4 as v4-mapped (::ffff:a.b.c.d), IPv6 as is.
//! A prefix length counts bits within the family: 0..32 or 0..128.

const std = @import("std");
const builtin = @import("builtin");
const c = std.c;

pub const Addr = [16]u8;

pub const Error = error{
    NotPermitted,
    SocketFailed,
    ControlNotFound,
    ConnectFailed,
    NoSuchInterface,
    InvalidPrefix,
    /// the kernel refused the value (MTU out of range, bad address)
    InvalidValue,
    IoctlFailed,
    /// a route for exactly this prefix exists; it may be another VPN's
    RouteExists,
    RouteNotFound,
    /// the route points into another interface than the one given
    ForeignRoute,
    /// the interface has no address of the route's family yet
    NoAddress,
    RouteWriteFailed,
    RouteReadFailed,
    Timeout,
    SysctlFailed,
};

const native = builtin.cpu.arch.endian();

// <sys/sys_domain.h>, <sys/kern_control.h>, <net/if_utun.h>
const AF_SYSTEM = 32;
const SYSPROTO_CONTROL = 2;
const AF_SYS_CONTROL = 2;
const CTLIOCGINFO: u32 = 0xc0644e03;
const UTUN_CONTROL_NAME = "com.apple.net.utun_control";
const UTUN_OPT_IFNAME = 2;
// <sys/sockio.h>, <netinet6/in6_var.h>, <netinet6/nd6.h>
const SIOCSIFMTU: u32 = 0x80206934;
const SIOCAIFADDR: u32 = 0x8040691a;
const SIOCAIFADDR_IN6: u32 = 0x8080691a;
const IN6_IFF_NODAD = 0x20;
const ND6_INFINITE_LIFETIME: u32 = 0xffffffff;
// <net/route.h>, <sys/sysctl.h>
const RTM_VERSION = 5;
const RTM_ADD = 1;
const RTM_DELETE = 2;
const RTM_GET = 4;
const RTF_UP = 0x1;
const RTF_GATEWAY = 0x2;
const RTF_STATIC = 0x800;
const RTF_IFSCOPE = 0x1000000;
const RTA_DST = 0x1;
const RTA_GATEWAY = 0x2;
const RTA_NETMASK = 0x4;
const RTAX_DST = 0;
const RTAX_GATEWAY = 1;
const RTAX_NETMASK = 2;
const RTAX_MAX = 8;
const CTL_NET = 4;
const NET_RT_DUMP = 1;

const CtlInfo = extern struct { ctl_id: u32 = 0, ctl_name: [96]u8 };
const SockaddrCtl = extern struct {
    len: u8 = 32,
    family: u8 = AF_SYSTEM,
    sysaddr: u16 = AF_SYS_CONTROL,
    id: u32,
    unit: u32,
    reserved: [5]u32 = @splat(0),
};
const IfreqMtu = extern struct { name: [16]u8, mtu: i32, pad: [12]u8 = @splat(0) };
const SockaddrIn = extern struct { len: u8 = 16, family: u8 = c.AF.INET, port: u16 = 0, addr: [4]u8, zero: [8]u8 = @splat(0) };
const SockaddrIn6 = extern struct { len: u8 = 28, family: u8 = c.AF.INET6, port: u16 = 0, flowinfo: u32 = 0, addr: [16]u8, scope_id: u32 = 0 };
const SockaddrDl = extern struct { len: u8 = 20, family: u8 = c.AF.LINK, index: u16, type: u8 = 0, nlen: u8 = 0, alen: u8 = 0, slen: u8 = 0, data: [12]u8 = @splat(0) };
const IfAliasReq = extern struct { name: [16]u8, addr: SockaddrIn, dst: SockaddrIn, mask: SockaddrIn };
const In6AddrLifetime = extern struct { expire: i64 = 0, preferred: i64 = 0, vltime: u32 = ND6_INFINITE_LIFETIME, pltime: u32 = ND6_INFINITE_LIFETIME };
const In6AliasReq = extern struct {
    name: [16]u8,
    addr: SockaddrIn6,
    dst: SockaddrIn6,
    prefixmask: SockaddrIn6,
    flags: i32 = IN6_IFF_NODAD,
    lifetime: In6AddrLifetime = .{},
};
const RtMsghdr = extern struct {
    msglen: u16,
    version: u8 = RTM_VERSION,
    type: u8,
    index: u16 = 0,
    flags: i32,
    addrs: i32,
    pid: i32 = 0,
    seq: i32,
    err: i32 = 0,
    use: i32 = 0,
    inits: u32 = 0,
    rmx: [14]u32 = @splat(0),
};

comptime {
    std.debug.assert(@sizeOf(CtlInfo) == 100 and @sizeOf(SockaddrCtl) == 32 and @sizeOf(IfreqMtu) == 32);
    std.debug.assert(@sizeOf(SockaddrDl) == 20 and @sizeOf(IfAliasReq) == 64);
    std.debug.assert(@sizeOf(In6AliasReq) == 128 and @offsetOf(In6AliasReq, "flags") == 100 and @offsetOf(In6AliasReq, "lifetime") == 104);
    std.debug.assert(@sizeOf(RtMsghdr) == 92 and @offsetOf(RtMsghdr, "flags") == 8 and @offsetOf(RtMsghdr, "rmx") == 36);
}

extern "c" fn if_indextoname(ifindex: c_uint, ifname: [*]u8) ?[*:0]u8;

fn lastErrno() c.E {
    return c.errno(@as(c_int, -1));
}

fn mapV4(a: [4]u8) Addr {
    return .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff } ++ a;
}

pub fn isV4(a: Addr) bool {
    return std.mem.eql(u8, a[0..12], &[12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff });
}

// ---------------------------------------------------------------- utun

/// An open utun control socket. The interface lives exactly as long as this
/// socket (all its copies), so the helper keeps one for the whole session.
pub const Utun = struct {
    fd: c.fd_t,
    name: [16:0]u8,

    pub fn ifname(u: *const Utun) []const u8 {
        return std.mem.sliceTo(&u.name, 0);
    }

    pub fn close(u: Utun) void {
        _ = c.close(u.fd);
    }
};

/// A new utun at the first free unit: never a fixed one, since the system
/// holds utun0-4 and other VPNs take more.
pub fn openUtun() Error!Utun {
    const fd = c.socket(AF_SYSTEM, c.SOCK.DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) return error.SocketFailed;
    errdefer _ = c.close(fd);
    _ = c.fcntl(fd, c.F.SETFD, @as(c_int, c.FD_CLOEXEC));
    // the control id is assigned at boot, so it is looked up every time
    var info: CtlInfo = .{ .ctl_name = @splat(0) };
    @memcpy(info.ctl_name[0..UTUN_CONTROL_NAME.len], UTUN_CONTROL_NAME);
    if (c.ioctl(fd, @bitCast(CTLIOCGINFO), &info) != 0) return error.ControlNotFound;
    // the kernel checks connect()'s length argument (not sc_len) against 32
    const sa: SockaddrCtl = .{ .id = info.ctl_id, .unit = 0 };
    if (c.connect(fd, @ptrCast(&sa), @sizeOf(SockaddrCtl)) != 0) return switch (lastErrno()) {
        .PERM, .ACCES => error.NotPermitted,
        else => error.ConnectFailed,
    };
    var u: Utun = .{ .fd = fd, .name = @splat(0) };
    var len: c.socklen_t = 16;
    if (c.getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, &u.name, &len) != 0) return error.ConnectFailed;
    return u;
}

// ---------------------------------------------------------------- interface

/// The kernel stops at the first NUL, so "utun9\x00x" would name utun9.
fn validName(name: []const u8) bool {
    return name.len > 0 and name.len < 16 and std.mem.indexOfScalar(u8, name, 0) == null;
}

fn ifreqName(name: []const u8) Error![16]u8 {
    if (!validName(name)) return error.NoSuchInterface;
    var n: [16]u8 = @splat(0);
    @memcpy(n[0..name.len], name);
    return n;
}

/// Interface ioctls go through any datagram socket of the right family.
fn ifIoctl(family: c_uint, req: u32, arg: *anyopaque) Error!void {
    const s = c.socket(family, c.SOCK.DGRAM, 0);
    if (s < 0) return error.SocketFailed;
    defer _ = c.close(s);
    if (c.ioctl(s, @bitCast(req), arg) == 0) return;
    return switch (lastErrno()) {
        .PERM, .ACCES => error.NotPermitted,
        .NXIO, .NODEV => error.NoSuchInterface,
        .INVAL, .DESTADDRREQ, .ADDRNOTAVAIL => error.InvalidValue,
        else => error.IoctlFailed,
    };
}

pub fn setMtu(name: []const u8, mtu: u16) Error!void {
    var req: IfreqMtu = .{ .name = try ifreqName(name), .mtu = mtu };
    try ifIoctl(c.AF.INET, SIOCSIFMTU, &req);
}

/// utun is point-to-point, and the kernel refuses an IPv4 address there
/// without a destination (EDESTADDRREQ). `dest` == `local` is what sing-tun
/// does and works.
pub fn addAddress4(name: []const u8, local: [4]u8, dest: [4]u8) Error!void {
    var req: IfAliasReq = .{
        .name = try ifreqName(name),
        .addr = .{ .addr = local },
        .dst = .{ .addr = dest },
        .mask = .{ .addr = .{ 255, 255, 255, 255 } },
    };
    try ifIoctl(c.AF.INET, SIOCAIFADDR, &req);
}

/// No destination: on a point-to-point link the kernel takes one only with
/// a /128, and a shorter prefix (e.g. /126) needs none. No DAD, never expires.
pub fn addAddress6(name: []const u8, addr: [16]u8, prefix_len: u8) Error!void {
    if (prefix_len > 128) return error.InvalidPrefix;
    var req: In6AliasReq = .{
        .name = try ifreqName(name),
        .addr = .{ .addr = addr },
        .dst = std.mem.zeroes(SockaddrIn6),
        .prefixmask = .{ .addr = prefixMask(16, prefix_len) },
    };
    try ifIoctl(c.AF.INET6, SIOCAIFADDR_IN6, &req);
}

pub fn ifIndex(name: []const u8) ?u32 {
    if (!validName(name)) return null;
    var z: [16:0]u8 = @splat(0);
    @memcpy(z[0..name.len], name);
    const idx = c.if_nametoindex(&z);
    return if (idx > 0) @intCast(idx) else null;
}

fn ifNameOf(index: u32) ?[16:0]u8 {
    var n: [16:0]u8 = @splat(0);
    return if (if_indextoname(index, &n) != null) n else null;
}

// ---------------------------------------------------------------- route messages

/// One route as the kernel reports it.
const Route = struct {
    flags: u32,
    index: u16,
    dst: Addr,
    prefix_len: u8,
    /// IP gateway; null for interface routes (AF_LINK gateway) and none
    gateway: ?Addr,
};

fn prefixMask(comptime n: usize, len: u8) [n]u8 {
    var m: [n]u8 = @splat(0);
    var left = len;
    for (&m) |*b| {
        const take = @min(left, 8);
        b.* = @truncate(@as(u16, 0xff00) >> @intCast(take));
        left -= take;
    }
    return m;
}

fn maskOf(v4: bool, prefix_len: u8) Addr {
    return if (v4) mapV4(prefixMask(4, prefix_len)) else prefixMask(16, prefix_len);
}

fn checkPrefix(dst: Addr, prefix_len: u8) Error!void {
    if (prefix_len > @as(u8, if (isV4(dst)) 32 else 128)) return error.InvalidPrefix;
}

/// dst with the host bits cleared, as the kernel stores it.
fn network(dst: Addr, prefix_len: u8) Addr {
    const v4 = isV4(dst);
    const m = maskOf(v4, prefix_len);
    const start: usize = if (v4) 12 else 0;
    var d = dst;
    for (d[start..], m[start..]) |*b, mb| b.* &= mb;
    return d;
}

/// Sockaddrs in route messages are padded to 4 bytes; an empty one still takes 4.
fn roundup(len: usize) usize {
    return if (len == 0) 4 else (len + 3) & ~@as(usize, 3);
}

fn put(buf: []u8, off: usize, bytes: []const u8) usize {
    @memcpy(buf[off..][0..bytes.len], bytes);
    return off + roundup(bytes.len);
}

fn putIp(buf: []u8, off: usize, a: Addr, v4: bool) usize {
    if (v4) return put(buf, off, std.mem.asBytes(&SockaddrIn{ .addr = a[12..16].* }));
    return put(buf, off, std.mem.asBytes(&SockaddrIn6{ .addr = a }));
}

const max_msg = 1024;

/// A route message with DST, NETMASK and, when `gw_index` is set, an AF_LINK
/// GATEWAY naming the interface itself (what `route add -interface` sends:
/// an interface route, RTF_GATEWAY clear). Returns the message length.
fn buildRoute(buf: *[max_msg]u8, kind: u8, seq: i32, dst: Addr, prefix_len: u8, gw_index: ?u16) usize {
    @memset(buf, 0);
    const v4 = isV4(dst);
    var addrs: i32 = RTA_DST | RTA_NETMASK;
    var off = putIp(buf, @sizeOf(RtMsghdr), network(dst, prefix_len), v4);
    if (gw_index) |i| {
        off = put(buf, off, std.mem.asBytes(&SockaddrDl{ .index = i }));
        addrs |= RTA_GATEWAY;
    }
    off = putIp(buf, off, maskOf(v4, prefix_len), v4);
    const hdr: RtMsghdr = .{ .msglen = @intCast(off), .type = kind, .flags = RTF_UP | RTF_STATIC, .addrs = addrs, .seq = seq };
    @memcpy(buf[0..@sizeOf(RtMsghdr)], std.mem.asBytes(&hdr));
    return off;
}

fn header(msg: []const u8) ?RtMsghdr {
    if (msg.len < @sizeOf(RtMsghdr)) return null;
    const hdr = std.mem.bytesToValue(RtMsghdr, msg[0..@sizeOf(RtMsghdr)]);
    if (hdr.version != RTM_VERSION or hdr.msglen < @sizeOf(RtMsghdr) or hdr.msglen > msg.len) return null;
    return hdr;
}

/// An IP address out of a sockaddr_in / sockaddr_in6; null for other families.
fn ipOf(sa: []const u8) ?Addr {
    if (sa.len < 2) return null;
    return switch (sa[1]) {
        c.AF.INET => if (sa.len >= 8) mapV4(sa[4..8].*) else null,
        c.AF.INET6 => if (sa.len >= 24) sa[8..24].* else null,
        else => null,
    };
}

/// Netmasks come back as compact radix keys: sa_len covers only the bytes up
/// to the last non-zero one (5 for 128.0.0.0/1, 0 for /0) and the family byte
/// is unreliable, so the destination's family decides where the mask starts.
fn prefixOf(sa: []const u8, v4: bool) u8 {
    const start: usize = if (v4) 4 else 8;
    const width: usize = if (v4) 4 else 16;
    if (sa.len <= start) return 0;
    var n: u8 = 0;
    for (sa[start..@min(sa.len, start + width)]) |b| {
        n += @clz(~b);
        if (b != 0xff) break;
    }
    return n;
}

/// Parses an RTM_* route message; null for malformed ones and non-IP routes.
fn parseRoute(msg: []const u8) ?Route {
    const hdr = header(msg) orelse return null;
    var sas: [RTAX_MAX]?[]const u8 = @splat(null);
    var off: usize = @sizeOf(RtMsghdr);
    for (&sas, 0..) |*sa, i| {
        if (hdr.addrs & (@as(i32, 1) << @intCast(i)) == 0) continue;
        if (off >= hdr.msglen) return null;
        const len = msg[off];
        if (off + len > hdr.msglen) return null;
        sa.* = msg[off..][0..len];
        off += roundup(len);
    }
    const dst_sa = sas[RTAX_DST] orelse return null;
    const dst = ipOf(dst_sa) orelse return null;
    const v4 = dst_sa[1] == c.AF.INET;
    // an IPv6 route inside ::ffff:0:0/96 has no place in Addr: it would read as IPv4
    if (!v4 and isV4(dst)) return null;
    return .{
        .flags = @bitCast(hdr.flags),
        .index = hdr.index,
        .dst = dst,
        .prefix_len = if (sas[RTAX_NETMASK]) |m| prefixOf(m, v4) else if (v4) 32 else 128,
        .gateway = if (sas[RTAX_GATEWAY]) |g| ipOf(g) else null,
    };
}

// ---------------------------------------------------------------- route socket

var seq_counter: std.atomic.Value(i32) = .init(0);

fn nextSeq() i32 {
    return seq_counter.fetchAdd(1, .monotonic) + 1;
}

/// Writes need a socket created by root; RTM_GET works for anyone. The write
/// right sticks to the socket, not the caller, so it must never reach a
/// child process (close-on-exec).
fn routeSocket() Error!c.fd_t {
    const fd = c.socket(c.AF.ROUTE, c.SOCK.RAW, 0);
    if (fd < 0) return error.SocketFailed;
    _ = c.fcntl(fd, c.F.SETFD, @as(c_int, c.FD_CLOEXEC));
    return fd;
}

fn writeRoute(fd: c.fd_t, msg: []const u8) Error!void {
    const rc = c.write(fd, msg.ptr, msg.len);
    if (rc == msg.len) return;
    if (rc >= 0) return error.RouteWriteFailed;
    return switch (lastErrno()) {
        .EXIST => error.RouteExists,
        .SRCH => error.RouteNotFound,
        .PERM, .ACCES => error.NotPermitted,
        .NETUNREACH => error.NoAddress,
        else => error.RouteWriteFailed,
    };
}

fn waitReadable(fd: c.fd_t, ms: c_int) bool {
    var fds = [1]c.pollfd{.{ .fd = fd, .events = c.POLL.IN, .revents = 0 }};
    while (true) {
        const rc = c.poll(&fds, 1, ms);
        if (rc < 0 and lastErrno() == .INTR) continue;
        return rc > 0;
    }
}

/// Route sockets see every routing message on the system; ours is the
/// RTM_GET carrying our pid and sequence number.
fn readReply(fd: c.fd_t, buf: *[max_msg]u8, seq: i32) Error!Route {
    const pid = c.getpid();
    while (true) {
        if (!waitReadable(fd, 1000)) return error.Timeout;
        const n = c.read(fd, buf, buf.len);
        if (n < 0) {
            if (lastErrno() == .INTR) continue;
            return error.RouteReadFailed;
        }
        const msg = buf[0..@intCast(n)];
        const hdr = header(msg) orelse continue;
        if (hdr.type != RTM_GET or hdr.pid != pid or hdr.seq != seq) continue;
        return parseRoute(msg) orelse error.RouteReadFailed;
    }
}

/// The route the kernel holds for exactly dst/prefix_len. Asked with a mask,
/// the kernel answers with the default route when no such entry exists, so
/// the reply's own destination and mask are checked before it is believed.
fn getRoute(dst: Addr, prefix_len: u8) Error!Route {
    try checkPrefix(dst, prefix_len);
    const fd = try routeSocket();
    defer _ = c.close(fd);
    var buf: [max_msg]u8 align(4) = undefined;
    const seq = nextSeq();
    try writeRoute(fd, buf[0..buildRoute(&buf, RTM_GET, seq, dst, prefix_len, null)]);
    const r = try readReply(fd, &buf, seq);
    const want = network(dst, prefix_len);
    if (r.prefix_len != prefix_len or !std.mem.eql(u8, &r.dst, &want)) return error.RouteNotFound;
    return r;
}

fn changeRoute(kind: u8, dst: Addr, prefix_len: u8, ifindex: u32) Error!void {
    const fd = try routeSocket();
    defer _ = c.close(fd);
    var buf: [max_msg]u8 align(4) = undefined;
    const idx = std.math.cast(u16, ifindex) orelse return error.NoSuchInterface;
    try writeRoute(fd, buf[0..buildRoute(&buf, kind, nextSeq(), dst, prefix_len, idx)]);
}

/// Points dst/prefix_len into `ifname` as an interface route. The interface
/// needs an address of the same family first (IPv6 routes need an IPv6
/// address), else error.NoAddress. An existing route is never replaced: it
/// may belong to another VPN, so error.RouteExists goes to the caller.
pub fn addRoute(dst: Addr, prefix_len: u8, ifname: []const u8) Error!void {
    try checkPrefix(dst, prefix_len);
    const idx = ifIndex(ifname) orelse return error.NoSuchInterface;
    try changeRoute(RTM_ADD, dst, prefix_len, idx);
}

/// Removes dst/prefix_len only while it still points into `ifname`, so a
/// route someone else installed for the same prefix is left alone.
pub fn deleteRoute(dst: Addr, prefix_len: u8, ifname: []const u8) Error!void {
    const idx = ifIndex(ifname) orelse return error.NoSuchInterface;
    const r = try getRoute(dst, prefix_len);
    if (r.index != idx) return error.ForeignRoute;
    try changeRoute(RTM_DELETE, dst, prefix_len, idx);
}

// ---------------------------------------------------------------- default route

pub const DefaultRoute = struct {
    ifindex: u32,
    ifname: [16:0]u8,
    /// null when the default is an interface route (no router)
    gateway4: ?[4]u8,
};

/// The IPv4 0.0.0.0/0 route. Asked with an explicit /0 mask, so the capture
/// routes of this or another VPN (0/1, 1/8 .. 128/1) never answer instead.
pub fn defaultRoute() Error!DefaultRoute {
    const r = try getRoute(mapV4(.{ 0, 0, 0, 0 }), 0);
    return .{
        .ifindex = r.index,
        .ifname = ifNameOf(r.index) orelse return error.NoSuchInterface,
        .gateway4 = gateway4(r),
    };
}

fn gateway4(r: Route) ?[4]u8 {
    if (r.flags & RTF_GATEWAY == 0) return null;
    const g = r.gateway orelse return null;
    return if (isV4(g)) g[12..16].* else null;
}

// ---------------------------------------------------------------- other VPNs

pub const Capture = struct {
    ifname: [16:0]u8,
    dst: Addr,
    prefix_len: u8,
};

/// Routes through another tunnel that take over large parts of the address
/// space, such as Happ's sing-box with 1/8 .. 128/1 on utun5. Their longer
/// prefixes would beat our 0/1, so the helper warns or refuses instead of
/// fighting over routes. Caller frees the slice.
pub fn foreignCaptures(gpa: std.mem.Allocator, own_ifname: ?[]const u8) (Error || std.mem.Allocator.Error)![]Capture {
    const table = try dumpRoutes(gpa);
    defer gpa.free(table);
    var out: std.ArrayList(Capture) = .empty;
    errdefer out.deinit(gpa);
    var off: usize = 0;
    while (off + 2 <= table.len) {
        const len = std.mem.readInt(u16, table[off..][0..2], native);
        if (len == 0 or off + len > table.len) break;
        const msg = table[off..][0..len];
        off += len;
        const r = parseRoute(msg) orelse continue;
        if (!isCapture(r)) continue;
        const name = ifNameOf(r.index) orelse continue;
        const s = std.mem.sliceTo(&name, 0);
        if (!isTunnel(s)) continue;
        if (own_ifname) |own| if (std.mem.eql(u8, s, own)) continue;
        try out.append(gpa, .{ .ifname = name, .dst = r.dst, .prefix_len = r.prefix_len });
    }
    return out.toOwnedSlice(gpa);
}

/// An unscoped unicast route of /8 or shorter. Scoped routes (RTF_IFSCOPE,
/// like the system utun0-4 IPv6 defaults) serve only sockets bound to that
/// interface and capture nothing.
fn isCapture(r: Route) bool {
    if (r.flags & RTF_UP == 0 or r.flags & RTF_IFSCOPE != 0 or r.prefix_len > 8) return false;
    const multicast = if (isV4(r.dst)) r.dst[12] >= 224 else r.dst[0] == 0xff;
    return !multicast;
}

fn isTunnel(name: []const u8) bool {
    for ([_][]const u8{ "utun", "ipsec", "ppp", "tun", "tap" }) |p| {
        if (std.mem.startsWith(u8, name, p)) return true;
    }
    return false;
}

/// The whole routing table as a run of route messages (NET_RT_DUMP).
fn dumpRoutes(gpa: std.mem.Allocator) (Error || std.mem.Allocator.Error)![]u8 {
    var mib = [6]c_int{ CTL_NET, c.AF.ROUTE, 0, 0, NET_RT_DUMP, 0 };
    for (0..3) |_| {
        var size: usize = 0;
        if (c.sysctl(&mib, mib.len, null, &size, null, 0) != 0) return error.SysctlFailed;
        size += size / 4 + 1024; // the table may grow between the two calls
        const buf = try gpa.alloc(u8, size);
        if (c.sysctl(&mib, mib.len, buf.ptr, &size, null, 0) == 0) return gpa.realloc(buf, size) catch |e| {
            gpa.free(buf);
            return e;
        };
        gpa.free(buf);
        if (lastErrno() != .NOMEM) return error.SysctlFailed;
    }
    return error.SysctlFailed;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn isRoot() bool {
    return c.geteuid() == 0;
}

test "interface route message for 0.0.0.0/1" {
    var buf: [max_msg]u8 align(4) = undefined;
    const n = buildRoute(&buf, RTM_ADD, 7, mapV4(.{ 0, 0, 0, 0 }), 1, 23);
    try testing.expectEqual(92 + 16 + 20 + 16, n);
    const hdr = header(buf[0..n]).?;
    try testing.expectEqual(RTM_ADD, hdr.type);
    try testing.expectEqual(RTA_DST | RTA_GATEWAY | RTA_NETMASK, hdr.addrs);
    try testing.expectEqual(RTF_UP | RTF_STATIC, hdr.flags);
    try testing.expectEqual(7, hdr.seq);
    try testing.expectEqualSlices(u8, &.{ 16, c.AF.INET, 0, 0, 0, 0, 0, 0 }, buf[92..100]);
    try testing.expectEqualSlices(u8, &.{ 20, c.AF.LINK, 23, 0 }, buf[108..112]);
    try testing.expectEqualSlices(u8, &.{ 16, c.AF.INET, 0, 0, 0x80, 0, 0, 0 }, buf[128..136]);
    const r = parseRoute(buf[0..n]).?;
    try testing.expectEqual(1, r.prefix_len);
    try testing.expectEqual(mapV4(.{ 0, 0, 0, 0 }), r.dst);
    try testing.expectEqual(null, r.gateway);
}

test "IPv6 route messages and host bits" {
    var buf: [max_msg]u8 align(4) = undefined;
    var dst: Addr = @splat(0);
    dst[0] = 0x80;
    dst[15] = 1; // host bits are cleared
    const n = buildRoute(&buf, RTM_DELETE, 1, dst, 1, 30);
    try testing.expectEqual(92 + 28 + 20 + 28, n);
    const r = parseRoute(buf[0..n]).?;
    try testing.expectEqual(1, r.prefix_len);
    try testing.expectEqual(0x80, r.dst[0]);
    try testing.expectEqual(0, r.dst[15]);

    const m = buildRoute(&buf, RTM_GET, 2, mapV4(.{ 10, 1, 2, 3 }), 8, null);
    try testing.expectEqual(92 + 16 + 16, m);
    const g = parseRoute(buf[0..m]).?;
    try testing.expectEqual(mapV4(.{ 10, 0, 0, 0 }), g.dst);
    try testing.expectEqual(8, g.prefix_len);
}

fn appendSa(buf: []u8, off: *usize, sa: []const u8) void {
    off.* = put(buf, off.*, sa);
}

fn testMessage(buf: *[max_msg]u8, addrs: i32, flags: u32, index: u16, sas: []const []const u8) []const u8 {
    @memset(buf, 0);
    var off: usize = @sizeOf(RtMsghdr);
    for (sas) |sa| appendSa(buf, &off, sa);
    const hdr: RtMsghdr = .{ .msglen = @intCast(off), .type = RTM_GET, .index = index, .flags = @bitCast(flags), .addrs = addrs, .seq = 1 };
    @memcpy(buf[0..@sizeOf(RtMsghdr)], std.mem.asBytes(&hdr));
    return buf[0..off];
}

test "RTM_GET reply for the default route (layout seen on macOS 26)" {
    var buf: [max_msg]u8 align(4) = undefined;
    // DST, GATEWAY, NETMASK (sa_len 0), IFP (sockaddr_dl), IFA
    const msg = testMessage(&buf, 0x37, 0x40010843, 14, &.{
        std.mem.asBytes(&SockaddrIn{ .addr = .{ 0, 0, 0, 0 } }),
        std.mem.asBytes(&SockaddrIn{ .addr = .{ 192, 168, 0, 1 } }),
        &.{},
        std.mem.asBytes(&SockaddrDl{ .index = 14 }),
        std.mem.asBytes(&SockaddrIn{ .addr = .{ 192, 168, 0, 233 } }),
    });
    try testing.expectEqual(92 + 16 + 16 + 4 + 20 + 16, msg.len);
    const r = parseRoute(msg).?;
    try testing.expectEqual(0, r.prefix_len);
    try testing.expectEqual(14, r.index);
    try testing.expectEqual([4]u8{ 192, 168, 0, 1 }, gateway4(r).?);
}

test "compact radix netmasks" {
    var buf: [max_msg]u8 align(4) = undefined;
    const gw = std.mem.asBytes(&SockaddrIn{ .addr = .{ 172, 18, 0, 1 } });
    const happ = testMessage(&buf, 0x7, 0x10843, 23, &.{
        std.mem.asBytes(&SockaddrIn{ .addr = .{ 128, 0, 0, 0 } }), gw, &.{ 5, 0xff, 0, 0, 0x80 },
    });
    const r = parseRoute(happ).?;
    try testing.expectEqual(1, r.prefix_len);
    try testing.expect(isCapture(r));

    const eight = parseRoute(testMessage(&buf, 0x7, 0x10843, 23, &.{
        std.mem.asBytes(&SockaddrIn{ .addr = .{ 1, 0, 0, 0 } }), gw, &.{ 5, 0xff, 0, 0, 0xff },
    })).?;
    try testing.expectEqual(8, eight.prefix_len);

    var v6: Addr = @splat(0);
    v6[0] = 0x80;
    const six = parseRoute(testMessage(&buf, 0x5, 0x803, 23, &.{
        std.mem.asBytes(&SockaddrIn6{ .addr = v6 }), &.{ 9, 0xff, 0, 0, 0, 0, 0, 0, 0x80 },
    })).?;
    try testing.expectEqual(1, six.prefix_len);

    // a host route has no netmask
    const host = parseRoute(testMessage(&buf, 0x1, 0x5, 1, &.{
        std.mem.asBytes(&SockaddrIn{ .addr = .{ 127, 0, 0, 1 } }),
    })).?;
    try testing.expectEqual(32, host.prefix_len);
}

test "malformed route messages" {
    var buf: [max_msg]u8 align(4) = undefined;
    const msg = testMessage(&buf, 0x5, 0x1, 1, &.{
        std.mem.asBytes(&SockaddrIn{ .addr = .{ 10, 0, 0, 0 } }), &.{ 5, 0xff, 0, 0, 0xff },
    });
    try testing.expect(parseRoute(msg[0 .. msg.len - 1]) == null);
    // a sockaddr running past msglen
    buf[92] = 200;
    try testing.expect(parseRoute(msg) == null);
    try testing.expect(parseRoute(buf[0..10]) == null);

    // an IPv6 ::ffff:0:0/96 route must not pass for an IPv4 one
    const mapped = testMessage(&buf, 0x5, 0x803, 1, &.{
        std.mem.asBytes(&SockaddrIn6{ .addr = mapV4(.{ 0, 0, 0, 0 }) }),
        std.mem.asBytes(&SockaddrIn6{ .addr = prefixMask(16, 96) }),
    });
    try testing.expect(parseRoute(mapped) == null);
}

test "interface names with an inner NUL are refused" {
    try testing.expect(validName("utun9") and !validName("") and !validName("utun9\x00en0"));
    try testing.expectEqual(null, ifIndex("lo0\x00"));
    try testing.expectError(error.NoSuchInterface, setMtu("lo0\x00", 1500));
}

test "what counts as a capture" {
    const base: Route = .{ .flags = RTF_UP | RTF_GATEWAY, .index = 1, .dst = mapV4(.{ 0, 0, 0, 0 }), .prefix_len = 0, .gateway = null };
    try testing.expect(isCapture(base));
    var r = base;
    r.flags |= RTF_IFSCOPE;
    try testing.expect(!isCapture(r));
    r = base;
    r.prefix_len = 16;
    try testing.expect(!isCapture(r));
    r = base;
    r.dst = mapV4(.{ 224, 0, 0, 0 });
    r.prefix_len = 4;
    try testing.expect(!isCapture(r));
    r = base;
    r.dst = @splat(0);
    r.dst[0] = 0xff;
    r.prefix_len = 8;
    try testing.expect(!isCapture(r));
    try testing.expect(isTunnel("utun5") and isTunnel("ipsec0") and isTunnel("ppp0"));
    try testing.expect(!isTunnel("en0") and !isTunnel("lo0") and !isTunnel("bridge0"));
}

test "prefix masks" {
    try testing.expectEqual([4]u8{ 0, 0, 0, 0 }, prefixMask(4, 0));
    try testing.expectEqual([4]u8{ 0x80, 0, 0, 0 }, prefixMask(4, 1));
    try testing.expectEqual([4]u8{ 255, 255, 240, 0 }, prefixMask(4, 20));
    try testing.expectEqual([4]u8{ 255, 255, 255, 255 }, prefixMask(4, 32));
    try testing.expectError(error.InvalidPrefix, checkPrefix(mapV4(.{ 1, 2, 3, 4 }), 33));
    try checkPrefix(@splat(0), 128);
}

test "default route of this machine (no root needed)" {
    // a machine without a network has none: nothing to check
    const d = defaultRoute() catch |err| if (err == error.RouteNotFound) return error.SkipZigTest else return err;
    const name = std.mem.sliceTo(&d.ifname, 0);
    try testing.expect(name.len > 0);
    try testing.expectEqual(d.ifindex, ifIndex(name).?);
}

test "a missing exact route is not mistaken for the default" {
    try testing.expectError(error.RouteNotFound, getRoute(mapV4(.{ 198, 51, 100, 0 }), 24));
}

test "foreign tunnel captures on this machine" {
    const caps = try foreignCaptures(testing.allocator, null);
    defer testing.allocator.free(caps);
    for (caps) |cap| {
        try testing.expect(cap.prefix_len <= 8);
        try testing.expect(isTunnel(std.mem.sliceTo(&cap.ifname, 0)));
    }
    // naming the tunnel as our own hides its routes
    if (caps.len > 0) {
        const own = std.mem.sliceTo(&caps[0].ifname, 0);
        const rest = try foreignCaptures(testing.allocator, own);
        defer testing.allocator.free(rest);
        for (rest) |cap| try testing.expect(!std.mem.eql(u8, std.mem.sliceTo(&cap.ifname, 0), own));
    }
}

test "privileged calls fail cleanly without root" {
    // as root these would really change the system
    if (isRoot()) return error.SkipZigTest;
    try testing.expectError(error.NotPermitted, openUtun());
    try testing.expectError(error.NotPermitted, addRoute(mapV4(.{ 198, 51, 100, 0 }), 24, "lo0"));
    try testing.expectError(error.NotPermitted, setMtu("lo0", 16384));
    try testing.expectError(error.NoSuchInterface, addRoute(mapV4(.{ 198, 51, 100, 0 }), 24, "nosuchif0"));
    try testing.expectError(error.RouteNotFound, deleteRoute(mapV4(.{ 198, 51, 100, 0 }), 24, "lo0"));
}
