//! Socket calls std.Io does not offer: binding a socket to one interface
//! (so the service's own traffic never loops back into its TUN), connect
//! with a timeout, and UDP request/response with a timeout.
//!
//! Sockets made here are plain file descriptors; a TCP one is wrapped into
//! `std.Io.net.Stream` and used with the normal readers and writers.

const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const net = std.Io.net;
const packet = @import("ipstack/packet.zig");

pub const Addr = packet.Addr;

/// Windows has no TUN data plane yet: these calls exist there but refuse.
pub const supported = builtin.os.tag != .windows;

/// How outbound sockets leave the machine.
pub const Bind = union(enum) {
    /// normal routing
    none,
    /// macOS: IP_BOUND_IF / IPV6_BOUND_IF with this interface index
    index: u32,
    /// Linux: SO_BINDTODEVICE with this interface name (needs CAP_NET_RAW)
    name: [16:0]u8,

    pub fn interface(name: []const u8) Bind {
        if (comptime !supported) return .none;
        if (builtin.os.tag == .linux) {
            var n: [16:0]u8 = @splat(0);
            @memcpy(n[0..@min(name.len, 15)], name[0..@min(name.len, 15)]);
            return .{ .name = n };
        }
        var z: [32:0]u8 = @splat(0);
        @memcpy(z[0..@min(name.len, 31)], name[0..@min(name.len, 31)]);
        const idx = c.if_nametoindex(&z);
        return if (idx > 0) .{ .index = @intCast(idx) } else .none;
    }
};

pub const Error = error{
    SocketFailed,
    BindFailed,
    ConnectionRefused,
    NetworkUnreachable,
    HostUnreachable,
    Timeout,
    ConnectFailed,
    SendFailed,
    RecvFailed,
};

const Sockaddr = extern union {
    in: c.sockaddr.in,
    in6: c.sockaddr.in6,
    any: c.sockaddr,
};

fn sockaddr(addr: *const Addr, port: u16) struct { Sockaddr, c.socklen_t, u32 } {
    if (packet.isV4(addr)) {
        return .{
            .{ .in = .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(addr[12..16].*) } },
            @sizeOf(c.sockaddr.in),
            c.AF.INET,
        };
    }
    return .{
        .{ .in6 = .{ .port = std.mem.nativeToBig(u16, port), .flowinfo = 0, .addr = addr.*, .scope_id = 0 } },
        @sizeOf(c.sockaddr.in6),
        c.AF.INET6,
    };
}

pub fn closeFd(fd: c.fd_t) void {
    if (comptime !supported) return;
    _ = c.close(fd);
}

fn applyBind(fd: c.fd_t, family: u32, bind: Bind) Error!void {
    if (comptime !supported) return error.BindFailed;
    switch (bind) {
        .none => {},
        .index => |idx| {
            if (builtin.os.tag.isDarwin()) {
                const v: u32 = idx;
                const rc = if (family == c.AF.INET)
                    c.setsockopt(fd, c.IPPROTO.IP, c.IP.BOUND_IF, &v, @sizeOf(u32))
                else
                    c.setsockopt(fd, c.IPPROTO.IPV6, c.IPV6.BOUND_IF, &v, @sizeOf(u32));
                if (rc != 0) return error.BindFailed;
            }
        },
        .name => |n| {
            if (builtin.os.tag == .linux) {
                const len: c.socklen_t = @intCast(std.mem.indexOfScalar(u8, &n, 0) orelse n.len);
                if (c.setsockopt(fd, c.SOL.SOCKET, c.SO.BINDTODEVICE, &n, len) != 0) return error.BindFailed;
            }
        },
    }
}

fn setNonblocking(fd: c.fd_t, on: bool) void {
    if (comptime !supported) return;
    const flags = c.fcntl(fd, c.F.GETFL);
    if (flags < 0) return;
    const nb: c_int = @bitCast(@as(u32, @bitCast(c.O{ .NONBLOCK = true })));
    _ = c.fcntl(fd, c.F.SETFL, if (on) flags | nb else flags & ~nb);
}

/// The stack size to ask for a thread whose own frames need `want` bytes.
///
/// glibc carves a thread's static TLS block (and its own bookkeeping) out
/// of the very mapping it is given as the stack, and refuses to create the
/// thread (EINVAL) when the size asked for does not hold both. So there
/// what glibc itself needs is added on top; everywhere else `want` is what
/// gets asked for. Only pages that are touched cost memory.
pub fn stackSize(want: usize) usize {
    if (comptime !(builtin.os.tag == .linux and builtin.abi.isGnu() and builtin.link_libc)) return want;
    const S = struct {
        var extra: std.atomic.Value(usize) = .init(0);
    };
    var e = S.extra.load(.monotonic);
    if (e == 0) {
        // glibc tells how much it needs, through a symbol made for runtimes
        // that size their own stacks (it is not in the headers)
        const Min = *const fn (?*const anyopaque) callconv(.c) usize;
        e = if (c.dlsym(null, "__pthread_get_minstack")) |f| @as(Min, @ptrCast(@alignCast(f)))(null) else 0;
        // unknown, or implausible: a margin that covers any TLS seen in practice
        if (e < 16 * 1024 or e > 16 * 1024 * 1024) e = 256 * 1024;
        S.extra.store(e, .monotonic);
    }
    return want + e;
}

/// Wait until `fd` is readable (or writable); false on timeout.
pub fn waitFd(fd: c.fd_t, for_write: bool, ms: i32) bool {
    if (comptime !supported) return false;
    var fds = [1]c.pollfd{.{ .fd = fd, .events = if (for_write) c.POLL.OUT else c.POLL.IN, .revents = 0 }};
    while (true) {
        const rc = c.poll(&fds, 1, ms);
        if (rc < 0 and c.errno(rc) == .INTR) continue;
        return rc > 0;
    }
}

/// Reads a socket like `net.Stream.Reader`, except that a read gives up
/// once `deadline_ms` (awake clock; 0 = never) has passed. A server that
/// accepts a connection and then says nothing would otherwise hold its
/// flow, and the flow's socket, forever.
pub const SockReader = struct {
    fd: c.fd_t,
    io: std.Io,
    deadline_ms: i64 = 0,
    timed_out: bool = false,
    interface: std.Io.Reader,

    pub fn init(fd: c.fd_t, io: std.Io, buffer: []u8) SockReader {
        return .{ .fd = fd, .io = io, .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 } };
    }

    /// The peer has `ms` from now for everything read until `noDeadline`.
    pub fn setDeadline(r: *SockReader, ms: i64) void {
        r.deadline_ms = std.Io.Clock.awake.now(r.io).toMilliseconds() + ms;
    }

    pub fn noDeadline(r: *SockReader) void {
        r.deadline_ms = 0;
    }

    fn stream(io_r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const r: *SockReader = @alignCast(@fieldParentPtr("interface", io_r));
        if (comptime !supported) return error.ReadFailed;
        const dest = limit.slice(try w.writableSliceGreedy(1));
        while (true) {
            if (r.deadline_ms != 0) {
                const left = r.deadline_ms - std.Io.Clock.awake.now(r.io).toMilliseconds();
                if (left <= 0 or !waitFd(r.fd, false, @intCast(@min(left, std.math.maxInt(i32))))) {
                    r.timed_out = true;
                    return error.ReadFailed;
                }
            }
            const n = c.recv(r.fd, dest.ptr, dest.len, 0);
            if (n < 0) {
                if (c.errno(n) == .INTR) continue;
                return error.ReadFailed;
            }
            if (n == 0) return error.EndOfStream;
            w.advance(@intCast(n));
            return @intCast(n);
        }
    }
};

extern "c" fn getpeereid(fd: c.fd_t, uid: *c.uid_t, gid: *c.gid_t) c_int;

/// User id of the process at the other end of a Unix socket.
pub fn peerUid(fd: c.fd_t) ?u32 {
    if (comptime !supported) return null;
    if (builtin.os.tag == .linux) {
        const ucred = extern struct { pid: i32, uid: u32, gid: u32 };
        var cred: ucred = undefined;
        var len: c.socklen_t = @sizeOf(ucred);
        if (c.getsockopt(fd, c.SOL.SOCKET, c.SO.PEERCRED, &cred, &len) != 0) return null;
        return cred.uid;
    }
    var uid: c.uid_t = undefined;
    var gid: c.gid_t = undefined;
    if (getpeereid(fd, &uid, &gid) != 0) return null;
    return uid;
}

/// TCP connection to `addr` leaving through `bind`, within `timeout_ms`.
/// On Windows through std.Io.net (AFD), which has the timeout itself; the
/// service there keeps its own traffic off the tunnel by routes, not by
/// binding sockets, so `bind` is not needed.
pub fn connectTcp(io: std.Io, addr: *const Addr, port: u16, bind: Bind, timeout_ms: i32) Error!net.Stream {
    if (comptime builtin.os.tag == .windows) {
        return toIpAddress(addr, port).connect(io, .{
            .mode = .stream,
            .timeout = .{ .duration = .{ .raw = .fromMilliseconds(timeout_ms), .clock = .awake } },
        }) catch |err| switch (err) {
            error.ConnectionRefused => error.ConnectionRefused,
            error.NetworkUnreachable => error.NetworkUnreachable,
            error.HostUnreachable => error.HostUnreachable,
            error.Timeout => error.Timeout,
            else => error.ConnectFailed,
        };
    }
    const sa, const len, const family = sockaddr(addr, port);
    const fd = c.socket(family, c.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    errdefer closeFd(fd);
    try applyBind(fd, family, bind);
    if (builtin.os.tag.isDarwin()) {
        const one: c_int = 1;
        _ = c.setsockopt(fd, c.SOL.SOCKET, c.SO.NOSIGPIPE, &one, @sizeOf(c_int));
    }
    setNonblocking(fd, true);
    if (c.connect(fd, &sa.any, len) != 0) {
        switch (c.errno(@as(c_int, -1))) {
            .INPROGRESS, .INTR => {},
            else => |e| return mapConnectErrno(e),
        }
        if (!waitFd(fd, true, timeout_ms)) return error.Timeout;
        var err: c_int = 0;
        var elen: c.socklen_t = @sizeOf(c_int);
        if (c.getsockopt(fd, c.SOL.SOCKET, c.SO.ERROR, &err, &elen) != 0) return error.ConnectFailed;
        if (err != 0) return mapConnectErrno(@enumFromInt(err));
    }
    setNonblocking(fd, false);
    const one: c_int = 1;
    _ = c.setsockopt(fd, c.IPPROTO.TCP, c.TCP.NODELAY, &one, @sizeOf(c_int));
    return .{ .socket = .{ .handle = fd, .address = toIpAddress(addr, port) } };
}

fn mapConnectErrno(e: c.E) Error {
    return switch (e) {
        .CONNREFUSED => error.ConnectionRefused,
        .NETUNREACH, .NETDOWN => error.NetworkUnreachable,
        .HOSTUNREACH, .HOSTDOWN => error.HostUnreachable,
        .TIMEDOUT => error.Timeout,
        else => error.ConnectFailed,
    };
}

pub fn toIpAddress(addr: *const Addr, port: u16) net.IpAddress {
    if (packet.isV4(addr)) return .{ .ip4 = .{ .bytes = addr[12..16].*, .port = port } };
    return .{ .ip6 = .{ .bytes = addr.*, .port = port } };
}

pub fn fromIpAddress(a: net.IpAddress) struct { Addr, u16 } {
    return switch (a) {
        .ip4 => |v| .{ packet.v4(v.bytes), v.port },
        .ip6 => |v| .{ v.bytes, v.port },
    };
}

/// One UDP socket aimed at a single peer.
pub const Udp = if (builtin.os.tag == .windows) WinUdp else PosixUdp;

/// Windows: a std.Io.net datagram socket and the peer it sends to.
const WinUdp = struct {
    io: std.Io,
    sock: net.Socket,
    peer: net.IpAddress,

    pub fn open(io: std.Io, peer: *const Addr, port: u16, bind: Bind) Error!WinUdp {
        _ = bind;
        const to = toIpAddress(peer, port);
        const any: net.IpAddress = switch (to) {
            .ip4 => .{ .ip4 = .unspecified(0) },
            .ip6 => .{ .ip6 = .unspecified(0) },
        };
        const sock = any.bind(io, .{ .mode = .dgram }) catch return error.SocketFailed;
        return .{ .io = io, .sock = sock, .peer = to };
    }

    pub fn close(u: WinUdp) void {
        u.sock.close(u.io);
    }

    pub fn send(u: WinUdp, data: []const u8) Error!void {
        u.sock.send(u.io, &u.peer, data) catch return error.SendFailed;
    }

    /// Next datagram from the peer, or Timeout.
    pub fn recv(u: WinUdp, buf: []u8, timeout_ms: i32) Error!usize {
        const deadline = std.Io.Clock.awake.now(u.io).toMilliseconds() + timeout_ms;
        while (true) {
            const left = deadline - std.Io.Clock.awake.now(u.io).toMilliseconds();
            if (left <= 0) return error.Timeout;
            const msg = u.sock.receiveTimeout(u.io, buf, .{ .duration = .{ .raw = .fromMilliseconds(left), .clock = .awake } }) catch |err| switch (err) {
                error.Timeout => return error.Timeout,
                else => return error.RecvFailed,
            };
            // an unconnected socket hears anyone: keep only the peer's answers
            if (msg.from.eql(&u.peer)) return msg.data.len;
        }
    }
};

const PosixUdp = struct {
    fd: c.fd_t,

    pub fn open(io: std.Io, peer: *const Addr, port: u16, bind: Bind) Error!PosixUdp {
        _ = io;
        if (comptime !supported) return error.SocketFailed;
        const sa, const len, const family = sockaddr(peer, port);
        const fd = c.socket(family, c.SOCK.DGRAM, 0);
        if (fd < 0) return error.SocketFailed;
        errdefer closeFd(fd);
        try applyBind(fd, family, bind);
        if (c.connect(fd, &sa.any, len) != 0) return error.ConnectFailed;
        return .{ .fd = fd };
    }

    pub fn close(u: PosixUdp) void {
        closeFd(u.fd);
    }

    pub fn send(u: PosixUdp, data: []const u8) Error!void {
        if (comptime !supported) return error.SendFailed;
        const rc = c.send(u.fd, data.ptr, data.len, 0);
        if (rc < 0) return error.SendFailed;
    }

    /// Next datagram, or Timeout.
    pub fn recv(u: PosixUdp, buf: []u8, timeout_ms: i32) Error!usize {
        if (comptime !supported) return error.RecvFailed;
        if (!waitFd(u.fd, false, timeout_ms)) return error.Timeout;
        if (comptime !supported) return error.RecvFailed;
        const rc = c.recv(u.fd, buf.ptr, buf.len, 0);
        if (rc < 0) return error.RecvFailed;
        return @intCast(rc);
    }
};

test "connect with timeout to a closed and an open port" {
    const io = std.testing.io;
    const lo = packet.v4(.{ 127, 0, 0, 1 });
    // an open port
    const listen_addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();
    const s = try connectTcp(io, &lo, port, .none, 1000);
    s.close(io);
    // a closed one (the listener's port after closing the listener is racy; use port 1)
    try std.testing.expectError(error.ConnectionRefused, connectTcp(io, &lo, 1, .none, 1000));
}

test "udp request and reply over loopback" {
    const io = std.testing.io;
    const lo = packet.v4(.{ 127, 0, 0, 1 });
    // echo peer: a bound UDP socket
    const here: net.IpAddress = .{ .ip4 = .loopback(0) };
    const srv = try here.bind(io, .{ .mode = .dgram });
    defer srv.close(io);
    const port = srv.address.getPort();

    const u = try Udp.open(io, &lo, port, .none);
    defer u.close();
    try u.send("ping");
    var buf: [16]u8 = undefined;
    const got = try srv.receiveTimeout(io, &buf, .{ .duration = .{ .raw = .fromMilliseconds(2000), .clock = .awake } });
    try std.testing.expectEqualStrings("ping", got.data);
    try srv.send(io, &got.from, "pong");
    const m = try u.recv(&buf, 2000);
    try std.testing.expectEqualStrings("pong", buf[0..m]);
    try std.testing.expectError(error.Timeout, u.recv(&buf, 10));
}
