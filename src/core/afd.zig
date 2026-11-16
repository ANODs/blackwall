//! Windows sockets through the Ancillary Function Driver (\Device\Afd), the
//! way std.Io.net makes them there, for what std does not offer yet: connect
//! with a timeout, waiting until a socket is readable or writable, and
//! keeping a socket on one interface (IP_UNICAST_IF).
//!
//! The handles are the same kind std opens (asynchronous AFD endpoints), so
//! a socket made here is read, written and closed by std.Io.net as usual.
//! Each request here waits on its own event instead of an APC, which is
//! what lets it give up after a time.

const std = @import("std");
const builtin = @import("builtin");
const w = std.os.windows;
const ntdll = w.ntdll;
const net = std.Io.net;

pub const Handle = w.HANDLE;

pub const Error = error{
    SocketFailed,
    BindFailed,
    ConnectionRefused,
    NetworkUnreachable,
    HostUnreachable,
    Timeout,
    ConnectFailed,
    RecvFailed,
};

const Result = struct { status: w.NTSTATUS, info: usize };

/// One request to the driver, waited for at most `timeout_ms` (null:
/// without end). On timeout the request is cancelled and Timeout returned.
fn call(h: Handle, code: w.CTL_CODE, in: []const u8, out: []u8, timeout_ms: ?u32) error{ SocketFailed, Timeout }!Result {
    var ev: Handle = undefined;
    // EVENT_ALL_ACCESS
    if (ntdll.NtCreateEvent(&ev, @bitCast(@as(u32, 0x1F0003)), null, .Notification, .FALSE) != .SUCCESS) return error.SocketFailed;
    defer w.CloseHandle(ev);
    var iosb: w.IO_STATUS_BLOCK = .{ .u = .{ .Status = .PENDING }, .Information = 0 };
    const rc = ntdll.NtDeviceIoControlFile(
        h,
        ev,
        null,
        null,
        &iosb,
        code,
        if (in.len > 0) in.ptr else null,
        @intCast(in.len),
        if (out.len > 0) out.ptr else null,
        @intCast(out.len),
    );
    if (rc != .PENDING) return .{ .status = rc, .info = iosb.Information };
    var timeout: w.LARGE_INTEGER = if (timeout_ms) |ms| -@as(i64, ms) * 10_000 else 0;
    _ = ntdll.NtWaitForSingleObject(ev, .FALSE, if (timeout_ms != null) &timeout else null);
    if (@atomicLoad(w.NTSTATUS, &iosb.u.Status, .acquire) == .PENDING) {
        // still running: cancel, and wait for the driver to let go of iosb
        var cancel: w.IO_STATUS_BLOCK = undefined;
        _ = ntdll.NtCancelIoFileEx(h, &iosb, &cancel);
        _ = ntdll.NtWaitForSingleObject(ev, .FALSE, null);
        if (iosb.u.Status == .CANCELLED) return error.Timeout;
    }
    return .{ .status = iosb.u.Status, .info = iosb.Information };
}

pub const Mode = enum { tcp, udp };

/// A new socket, as std.Io.net opens one.
pub fn open(fam: u16, mode: Mode) Error!Handle {
    var h: Handle = undefined;
    var iosb: w.IO_STATUS_BLOCK = undefined;
    const rc = ntdll.NtCreateFile(
        &h,
        .{
            .STANDARD = .{ .RIGHTS = .{ .WRITE_DAC = true }, .SYNCHRONIZE = true },
            .GENERIC = .{ .WRITE = true, .READ = true },
        },
        &.{ .ObjectName = @constCast(&w.UNICODE_STRING.init(w.AFD.DEVICE_NAME ++ .{ '\\', 'E', 'n', 'd', 'p', 'o', 'i', 'n', 't' })) },
        &iosb,
        null,
        .{},
        .{ .READ = true, .WRITE = true },
        .OPEN_IF,
        .{ .IO = .ASYNCHRONOUS },
        &w.AFD.OPEN_PACKET.FULL_EA_INFORMATION{ .Value = .{
            .EndpointType = .{ .CONNECTIONLESS = mode == .udp, .MESSAGEMODE = mode == .udp },
            .GroupID = 0,
            .AddressFamily = fam,
            .SocketType = if (mode == .tcp) 1 else 2, // SOCK_STREAM, SOCK_DGRAM
            .Protocol = if (mode == .tcp) 6 else 17, // IPPROTO_TCP, IPPROTO_UDP
            .TransportDeviceNameLength = 0,
            .TransportDeviceName = undefined,
        } },
        @sizeOf(w.AFD.OPEN_PACKET.FULL_EA_INFORMATION),
    );
    if (rc != .SUCCESS) return error.SocketFailed;
    return h;
}

pub fn close(h: Handle) void {
    w.CloseHandle(h);
}

const Posix = std.Io.Threaded.PosixAddress;

fn family(a: *const net.IpAddress) u16 {
    return switch (a.*) {
        .ip4 => 2, // AF_INET
        .ip6 => 23, // AF_INET6
    };
}

/// Binds to the unspecified address of the family: the system picks the port.
fn bindAny(h: Handle, fam: u16) Error!net.IpAddress {
    const any: net.IpAddress = if (fam == 2) .{ .ip4 = .unspecified(0) } else .{ .ip6 = .unspecified(0) };
    const Storage = extern struct { info: w.AFD.BIND_INFO, addr: Posix };
    var s: Storage = .{ .info = .{ .Mode = .Active }, .addr = undefined };
    const len = std.Io.Threaded.addressToPosix(&any, &s.addr);
    const r = call(h, w.IOCTL.AFD.BIND, @as([]const u8, @ptrCast(&s))[0 .. @offsetOf(Storage, "addr") + len], @as([]u8, @ptrCast(&s.addr))[0..len], null) catch return error.BindFailed;
    if (r.status != .SUCCESS) return error.BindFailed;
    return std.Io.Threaded.addressFromPosix(&s.addr);
}

/// Set (or, with `get`, read) a socket option of the transport (IP_TTL and
/// the like): the value is a 32-bit integer.
pub fn intOption(h: Handle, level: i32, name: u32, value: *u32, get: bool) Error!void {
    const info: w.AFD.SOCKOPT_INFO = .{ .mode = if (get) .get else .set, .level = level, .optname = name, .optval = value, .optlen = @sizeOf(u32) };
    const r = call(h, w.IOCTL.AFD.SOCKOPT, @ptrCast(&info), &.{}, null) catch return error.BindFailed;
    if (r.status != .SUCCESS) return error.BindFailed;
}

/// Sends this socket's packets out of interface `index` only, whatever
/// the routes say (IP_UNICAST_IF / IPV6_UNICAST_IF).
pub fn unicastIf(h: Handle, fam: u16, index: u32) Error!void {
    // IPv4 takes the index in network byte order, IPv6 in host order
    var v: u32 = if (fam == 2) std.mem.nativeToBig(u32, index) else index;
    const info: w.AFD.SOCKOPT_INFO = .{
        .mode = .set,
        .level = if (fam == 2) 0 else 41, // IPPROTO_IP, IPPROTO_IPV6
        .optname = 31, // IP_UNICAST_IF, IPV6_UNICAST_IF
        .optval = &v,
        .optlen = @sizeOf(u32),
    };
    const r = call(h, w.IOCTL.AFD.SOCKOPT, @ptrCast(&info), &.{}, null) catch return error.BindFailed;
    if (r.status != .SUCCESS) return error.BindFailed;
}

/// A TCP connection to `to`, within `timeout_ms`; out of interface
/// `index` when it is not 0.
pub fn connectTcp(to: net.IpAddress, index: u32, timeout_ms: u32) Error!net.Stream {
    const fam = family(&to);
    const h = try open(fam, .tcp);
    errdefer close(h);
    if (index != 0) try unicastIf(h, fam, index);
    _ = try bindAny(h, fam);
    const Storage = extern struct { reserved: [3]usize = @splat(0), addr: Posix };
    var s: Storage = .{ .addr = undefined };
    const len = std.Io.Threaded.addressToPosix(&to, &s.addr);
    const r = call(h, w.IOCTL.AFD.CONNECT, @as([]const u8, @ptrCast(&s))[0 .. @offsetOf(Storage, "addr") + len], &.{}, timeout_ms) catch |err| return switch (err) {
        error.Timeout => error.Timeout,
        error.SocketFailed => error.SocketFailed,
    };
    switch (r.status) {
        .SUCCESS => {},
        .CONNECTION_REFUSED => return error.ConnectionRefused,
        .NETWORK_UNREACHABLE => return error.NetworkUnreachable,
        .HOST_UNREACHABLE => return error.HostUnreachable,
        .IO_TIMEOUT => return error.Timeout,
        else => return error.ConnectFailed,
    }
    noDelay(h);
    return .{ .socket = .{ .handle = h, .address = to } };
}

fn noDelay(h: Handle) void {
    var one: u32 = 1;
    const info: w.AFD.SOCKOPT_INFO = .{ .mode = .set, .level = 6, .optname = 1, .optval = &one, .optlen = @sizeOf(u32) }; // IPPROTO_TCP, TCP_NODELAY
    _ = call(h, w.IOCTL.AFD.SOCKOPT, @ptrCast(&info), &.{}, null) catch {};
}

/// A UDP socket bound to an unspecified address, out of interface `index`
/// when it is not 0. Sent and received through std.Io.net.
pub fn openUdp(fam_of: net.IpAddress, index: u32) Error!net.Socket {
    const fam = family(&fam_of);
    const h = try open(fam, .udp);
    errdefer close(h);
    if (index != 0) try unicastIf(h, fam, index);
    const bound = try bindAny(h, fam);
    return .{ .handle = h, .address = bound };
}

const PollHandle = extern struct { handle: Handle, events: u32, status: w.NTSTATUS };
const PollInfo = extern struct { timeout: i64, count: u32, exclusive: u32, handles: [1]PollHandle };

const poll_receive = 0x0001;
const poll_send = 0x0004;
const poll_disconnect = 0x0008;
const poll_abort = 0x0010;
const poll_local_close = 0x0020;
const poll_accept = 0x0080;
const poll_connect_fail = 0x0100;

/// Waits until `h` is readable (or writable), at most `ms` (negative:
/// without end); false on timeout. A closed or failed socket counts as
/// ready, so the read or write that follows reports it.
pub fn wait(h: Handle, for_write: bool, ms: i32) bool {
    const events: u32 = if (for_write)
        poll_send | poll_abort | poll_local_close | poll_connect_fail
    else
        poll_receive | poll_disconnect | poll_abort | poll_local_close | poll_accept;
    var info: PollInfo = .{
        // the driver's own timeout (relative, in 100 ns); "without end" as
        // far in the future as it goes
        .timeout = if (ms < 0) std.math.maxInt(i64) else -@as(i64, ms) * 10_000,
        .count = 1,
        .exclusive = 0,
        .handles = .{.{ .handle = h, .events = events, .status = .SUCCESS }},
    };
    // the event wait is only a guard should the driver's timer not fire
    const guard: ?u32 = if (ms < 0) null else @as(u32, @intCast(ms)) + 1000;
    const r = call(h, w.IOCTL.AFD.POLL, @ptrCast(&info), @ptrCast(&info), guard) catch return false;
    return switch (r.status) {
        .SUCCESS => info.count > 0 and info.handles[0].events != 0,
        .TIMEOUT => false,
        else => true,
    };
}

/// Whether a connected TCP socket has data waiting (true) or has ended or
/// been reset (false); read nothing. Call once it is readable.
pub fn peekData(h: Handle) bool {
    var one: [1]u8 = undefined;
    var bufs = [1]w.AFD.WSABUF(.@"var"){.{ .len = 1, .buf = &one }};
    const info: w.AFD.RECV_INFO = .{
        .BufferArray = &bufs,
        .BufferCount = 1,
        .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
        .TdiFlags = .{ .NORMAL = true, .PEEK = true },
    };
    const r = call(h, w.IOCTL.AFD.RECEIVE, @ptrCast(&info), &.{}, 1000) catch return false;
    return r.status == .SUCCESS and r.info > 0;
}

/// Bytes from a connected TCP socket; 0 at its end.
pub fn recv(h: Handle, buf: []u8) Error!usize {
    var bufs = [1]w.AFD.WSABUF(.@"var"){.{ .len = @intCast(@min(buf.len, std.math.maxInt(u32))), .buf = buf.ptr }};
    const info: w.AFD.RECV_INFO = .{
        .BufferArray = &bufs,
        .BufferCount = 1,
        .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
        .TdiFlags = .{ .NORMAL = true },
    };
    const r = call(h, w.IOCTL.AFD.RECEIVE, @ptrCast(&info), &.{}, null) catch return error.RecvFailed;
    return switch (r.status) {
        .SUCCESS => r.info,
        .REMOTE_DISCONNECT, .LOCAL_DISCONNECT => 0,
        else => error.RecvFailed,
    };
}

test "connect with a timeout, wait for data, read it" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    const io = std.testing.io;
    const here: net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try here.listen(io, .{});
    defer server.deinit(io);
    const s = try connectTcp(server.socket.address, 0, 2000);
    defer s.close(io);
    const peer = try server.accept(io);
    defer peer.close(io);
    // nothing sent yet
    try std.testing.expect(!wait(s.socket.handle, false, 50));
    try std.testing.expect(wait(s.socket.handle, true, 50));
    var wb: [64]u8 = undefined;
    var pw = peer.writer(io, &wb);
    try pw.interface.writeAll("hello");
    try pw.interface.flush();
    try std.testing.expect(wait(s.socket.handle, false, 2000));
    var buf: [16]u8 = undefined;
    const n = try recv(s.socket.handle, &buf);
    try std.testing.expectEqualStrings("hello", buf[0..n]);
    // std reads and writes the same handle
    var sw = s.writer(io, &wb);
    try sw.interface.writeAll("back");
    try sw.interface.flush();
    var rb: [64]u8 = undefined;
    var pr = peer.reader(io, &rb);
    try std.testing.expectEqualStrings("back", try pr.interface.take(4));
    // the end of the stream
    peer.shutdown(io, .send) catch {};
    try std.testing.expect(wait(s.socket.handle, false, 2000));
    try std.testing.expectEqual(@as(usize, 0), try recv(s.socket.handle, &buf));
}

test "refused, and a connect that runs out of time" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    try std.testing.expectError(error.ConnectionRefused, connectTcp(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1 } }, 0, 5000));
    // TEST-NET-1 drops everything; nothing answers within 300 ms
    const t0 = std.Io.Clock.awake.now(std.testing.io).toMilliseconds();
    const r = connectTcp(.{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 443 } }, 0, 300);
    const took = std.Io.Clock.awake.now(std.testing.io).toMilliseconds() - t0;
    if (r) |s| s.close(std.testing.io) else |_| {}
    try std.testing.expect(took < 3000);
}

test "a socket kept on the loopback interface" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    const io = std.testing.io;
    const here: net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try here.listen(io, .{});
    defer server.deinit(io);
    // interface 1 is the loopback pseudo-interface on Windows
    const s = try connectTcp(server.socket.address, 1, 2000);
    s.close(io);
}

test "udp through a socket opened here" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    const io = std.testing.io;
    const here: net.IpAddress = .{ .ip4 = .loopback(0) };
    const srv = try here.bind(io, .{ .mode = .dgram });
    defer srv.close(io);
    const u = try openUdp(srv.address, 0);
    defer u.close(io);
    try u.send(io, &srv.address, "ping");
    try std.testing.expect(wait(srv.handle, false, 2000));
    var buf: [16]u8 = undefined;
    const got = try srv.receive(io, &buf);
    try std.testing.expectEqualStrings("ping", got.data);
    try std.testing.expect(!wait(u.handle, false, 50));
}
