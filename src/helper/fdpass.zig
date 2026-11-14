//! Passing a file descriptor over a connected Unix stream socket
//! (SCM_RIGHTS). The root helper hands the utun to the unprivileged data
//! plane this way and keeps its own copy, so the interface outlives a crash
//! of the data plane and traffic fails closed instead of leaking.

const std = @import("std");
const builtin = @import("builtin");
const c = std.c;

pub const Error = error{ EmptyPayload, SendFailed, RecvFailed, ConnectionClosed, ControlTruncated };

const SCM_RIGHTS = 1;
const native = builtin.cpu.arch.endian();
/// A dead peer must not kill the (root) sender with SIGPIPE: Linux takes a
/// send flag, macOS a socket option (see noSigpipe).
const send_flags: u32 = if (builtin.os.tag == .linux) c.MSG.NOSIGNAL else 0;
/// The most descriptors one message can carry: XNU keeps them as pointers in
/// one 2 KiB cluster (254), Linux caps them at SCM_MAX_FD (253). XNU installs
/// every descriptor of a message before it copies the control data out, so a
/// smaller buffer would truncate it and leave the rest open here, unseen.
const max_fds = 254;

const cmsg_hdr_len = std.mem.alignForward(usize, @sizeOf(c.cmsghdr), c.cmsg_align);

fn cmsgSpace(n: usize) usize {
    return std.mem.alignForward(usize, cmsg_hdr_len + n * @sizeOf(c.fd_t), c.cmsg_align);
}

const Control = [cmsgSpace(max_fds)]u8;

/// Sends `payload` with `fd` attached to its first byte. The payload must not
/// be empty: a descriptor cannot travel without data on a stream socket.
pub fn sendFd(sock: c.fd_t, fd: c.fd_t, payload: []const u8) Error!void {
    return sendFds(sock, &.{fd}, payload);
}

fn sendFds(sock: c.fd_t, fds: []const c.fd_t, payload: []const u8) Error!void {
    if (payload.len == 0) return error.EmptyPayload;
    std.debug.assert(fds.len > 0 and fds.len <= max_fds);
    var control: Control align(@alignOf(c.cmsghdr)) = @splat(0);
    const hdr: *c.cmsghdr = @ptrCast(&control);
    hdr.* = .{ .len = @intCast(cmsg_hdr_len + fds.len * @sizeOf(c.fd_t)), .level = c.SOL.SOCKET, .type = SCM_RIGHTS };
    @memcpy(control[cmsg_hdr_len..][0 .. fds.len * @sizeOf(c.fd_t)], std.mem.sliceAsBytes(fds));

    noSigpipe(sock);
    var iov = [1]c.iovec_const{.{ .base = payload.ptr, .len = payload.len }};
    const msg: c.msghdr_const = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = @intCast(cmsgSpace(fds.len)),
        .flags = 0,
    };
    const sent: usize = while (true) {
        const rc = c.sendmsg(sock, &msg, send_flags);
        if (rc >= 0) break @intCast(rc);
        if (c.errno(rc) != .INTR) return error.SendFailed;
    };
    // the descriptors went with the first byte; the rest is plain data
    try writeAll(sock, payload[sent..]);
}

/// Sends all of `data` without a descriptor. A dead peer is an error, never
/// SIGPIPE.
pub fn sendAll(sock: c.fd_t, data: []const u8) Error!void {
    noSigpipe(sock);
    try writeAll(sock, data);
}

fn noSigpipe(sock: c.fd_t) void {
    if (!builtin.os.tag.isDarwin()) return;
    const one: c_int = 1;
    _ = c.setsockopt(sock, c.SOL.SOCKET, c.SO.NOSIGPIPE, &one, @sizeOf(c_int));
}

fn writeAll(sock: c.fd_t, data: []const u8) Error!void {
    var rest = data;
    while (rest.len > 0) {
        const rc = c.send(sock, rest.ptr, rest.len, send_flags);
        if (rc < 0) {
            if (c.errno(rc) == .INTR) continue;
            return error.SendFailed;
        }
        rest = rest[@intCast(rc)..];
    }
}

pub const Received = struct { len: usize, fd: ?c.fd_t };

/// Reads data into `buf` and takes the first descriptor that came with it,
/// marked close-on-exec. A stream may split or merge sends, so the caller
/// frames its payload itself.
pub fn recvFd(sock: c.fd_t, buf: []u8) Error!Received {
    var control: Control align(@alignOf(c.cmsghdr)) = @splat(0);
    var iov = [1]c.iovec{.{ .base = buf.ptr, .len = buf.len }};
    var msg: c.msghdr = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };
    const n: usize = while (true) {
        const rc = c.recvmsg(sock, &msg, 0);
        if (rc >= 0) break @intCast(rc);
        if (c.errno(rc) != .INTR) return error.RecvFailed;
    };
    const fd = takeFds(control[0..@min(msg.controllen, control.len)]);
    if (msg.flags & c.MSG.CTRUNC != 0) {
        if (fd) |f| _ = c.close(f);
        return error.ControlTruncated;
    }
    if (n == 0 and fd == null) return error.ConnectionClosed;
    return .{ .len = n, .fd = fd };
}

/// The first descriptor, close-on-exec; any others are closed so a peer
/// cannot leak descriptors into this process. A message cut off at the end
/// of the buffer (MSG_CTRUNC) still installed the descriptors it shows.
fn takeFds(control: []const u8) ?c.fd_t {
    var kept: ?c.fd_t = null;
    var off: usize = 0;
    while (off + cmsg_hdr_len <= control.len) {
        const hdr = std.mem.bytesToValue(c.cmsghdr, control[off..][0..@sizeOf(c.cmsghdr)]);
        const len: usize = @intCast(hdr.len);
        if (len < cmsg_hdr_len) break;
        const stop = off +| len;
        const end = @min(stop, control.len);
        if (hdr.level == c.SOL.SOCKET and hdr.type == SCM_RIGHTS) {
            const data = control[off + cmsg_hdr_len .. end];
            var i: usize = 0;
            while (i + @sizeOf(c.fd_t) <= data.len) : (i += @sizeOf(c.fd_t)) {
                const fd = std.mem.readInt(c.fd_t, data[i..][0..@sizeOf(c.fd_t)], native);
                if (kept == null) {
                    _ = c.fcntl(fd, c.F.SETFD, @as(c_int, c.FD_CLOEXEC));
                    kept = fd;
                } else _ = c.close(fd);
            }
        }
        if (end < stop) break; // cut off: nothing follows
        off += std.mem.alignForward(usize, len, c.cmsg_align);
    }
    return kept;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn socketPair() ![2]c.fd_t {
    var sv: [2]c.fd_t = undefined;
    if (c.socketpair(c.AF.UNIX, c.SOCK.STREAM, 0, &sv) != 0) return error.SocketPairFailed;
    return sv;
}

fn closeAll(fds: []const c.fd_t) void {
    for (fds) |fd| _ = c.close(fd);
}

fn pipePair() ![2]c.fd_t {
    var p: [2]c.fd_t = undefined;
    if (c.pipe(&p) != 0) return error.PipeFailed;
    return p;
}

test "a pipe passed over a socketpair carries data" {
    const sv = try socketPair();
    defer closeAll(&sv);
    const p = try pipePair();
    defer _ = c.close(p[1]);

    try sendFd(sv[0], p[0], "utun9");
    _ = c.close(p[0]); // the receiver's copy keeps the pipe open

    var buf: [16]u8 = undefined;
    const got = try recvFd(sv[1], &buf);
    try testing.expectEqualStrings("utun9", buf[0..got.len]);
    const fd = got.fd orelse return error.NoFd;
    defer _ = c.close(fd);
    try testing.expect(c.fcntl(fd, c.F.GETFD) & c.FD_CLOEXEC != 0);

    try testing.expectEqual(4, c.write(p[1], "ping", 4));
    var r: [4]u8 = undefined;
    try testing.expectEqual(4, c.read(fd, &r, r.len));
    try testing.expectEqualStrings("ping", &r);
}

test "extra descriptors are closed on receive" {
    const sv = try socketPair();
    defer closeAll(&sv);
    const p = try pipePair();

    // the write end travels as the unwanted second descriptor
    try sendFds(sv[0], &.{ p[0], p[1] }, "x");
    _ = c.close(p[0]);
    _ = c.close(p[1]);

    var buf: [4]u8 = undefined;
    const got = try recvFd(sv[1], &buf);
    const fd = got.fd orelse return error.NoFd;
    defer _ = c.close(fd);
    // end-of-file proves no write end is left open anywhere
    var fds = [1]c.pollfd{.{ .fd = fd, .events = c.POLL.IN, .revents = 0 }};
    try testing.expectEqual(1, c.poll(&fds, 1, 1000));
    try testing.expectEqual(0, c.read(fd, &buf, buf.len));
}

/// Whether every write end of the pipe is closed: its read end sees EOF.
fn writersGone(read_end: c.fd_t) !bool {
    var fds = [1]c.pollfd{.{ .fd = read_end, .events = c.POLL.IN, .revents = 0 }};
    if (c.poll(&fds, 1, 1000) != 1) return false;
    var b: [1]u8 = undefined;
    return c.read(read_end, &b, 1) == 0;
}

test "a peer sending many descriptors leaks none of them" {
    const sv = try socketPair();
    defer closeAll(&sv);
    const p = try pipePair();
    defer _ = c.close(p[0]);

    // far more than one: a buffer sized for a few would be truncated and
    // leave the rest open in this process
    var many: [100]c.fd_t = undefined;
    @memset(&many, p[1]);
    try sendFds(sv[0], &many, "x");
    _ = c.close(p[1]);

    var buf: [4]u8 = undefined;
    const got = try recvFd(sv[1], &buf);
    _ = c.close(got.fd orelse return error.NoFd);
    try testing.expect(try writersGone(p[0]));
}

test "descriptors of a cut-off control message are closed too" {
    const p = try pipePair();
    defer _ = c.close(p[0]);
    const extra = [2]c.fd_t{ c.dup(p[1]), c.dup(p[1]) };
    _ = c.close(p[1]);

    // the header promises four descriptors, the buffer holds two of them
    var control: Control align(@alignOf(c.cmsghdr)) = @splat(0);
    const hdr: *c.cmsghdr = @ptrCast(&control);
    hdr.* = .{ .len = @intCast(cmsg_hdr_len + 4 * @sizeOf(c.fd_t)), .level = c.SOL.SOCKET, .type = SCM_RIGHTS };
    @memcpy(control[cmsg_hdr_len..][0 .. 2 * @sizeOf(c.fd_t)], std.mem.sliceAsBytes(&extra));
    const kept = takeFds(control[0 .. cmsg_hdr_len + 2 * @sizeOf(c.fd_t)]) orelse return error.NoFd;
    try testing.expectEqual(extra[0], kept);
    _ = c.close(kept);
    try testing.expect(try writersGone(p[0]));
}

test "plain data, an empty payload and a closed peer" {
    const sv = try socketPair();
    defer _ = c.close(sv[1]);
    try testing.expectError(error.EmptyPayload, sendFd(sv[0], 0, ""));

    try testing.expectEqual(2, c.write(sv[0], "hi", 2));
    var buf: [4]u8 = undefined;
    const got = try recvFd(sv[1], &buf);
    try testing.expectEqual(2, got.len);
    try testing.expectEqual(null, got.fd);

    _ = c.close(sv[0]);
    try testing.expectError(error.ConnectionClosed, recvFd(sv[1], &buf));
}

test "sending to a peer that is gone fails instead of raising SIGPIPE" {
    const sv = try socketPair();
    defer _ = c.close(sv[0]);
    try sendAll(sv[0], "hello");
    _ = c.close(sv[1]);
    try testing.expectError(error.SendFailed, sendAll(sv[0], "again"));
}
