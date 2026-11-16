//! The line protocol between the window and the background service.
//!
//! One request per connection over a Unix socket that only the owner can
//! open: the client sends a JSON object with a "cmd" field and a newline,
//! the service answers with one JSON line and closes.
//!
//!   {"cmd":"status"}   -> Status
//!   {"cmd":"reload"}   -> {"ok":true}   re-read config.json
//!   {"cmd":"stop"}     -> {"ok":true}   shut down and release the TUN
//!   {"cmd":"suspend"}  -> {"ok":true}   shut down but leave the helper's
//!                                        capture to the kill switch (restarts)
//!   {"cmd":"ping","host":"h","port":443} -> {"ms":42} or {"ms":null}
//!                                        TCP connect time from the real
//!                                        address, past the TUN

const std = @import("std");
const sys = @import("sys.zig");
const Io = std.Io;
const c = std.c;

pub const socket_name = "service.sock";

/// Where the service listens: in the configuration folder, or — when that
/// path is too long for a Unix socket (104 bytes on macOS) — at a short
/// per-user path in /tmp. Clients check who listens there (`call`).
pub fn socketPath(buf: []u8, config_dir: []const u8) []const u8 {
    if (config_dir.len + 1 + socket_name.len <= 100) {
        if (std.fmt.bufPrint(buf, "{s}/" ++ socket_name, .{config_dir})) |p| return p else |_| {}
    }
    const uid = if (comptime sys.supported) c.geteuid() else 0;
    return std.fmt.bufPrint(buf, "/tmp/blackwall-{d}.sock", .{uid}) catch "";
}
/// Why the service could not start: an error name, for conflicts followed
/// by the interfaces of the other VPN ("Conflict utun5 utun6").
pub const error_name = "service.error";
pub const log_name = "service.log";

/// Bumped whenever Status or the commands change incompatibly.
pub const version: u32 = 1;

pub const AppStatus = struct {
    id: []const u8 = "",
    down: u64 = 0,
    up: u64 = 0,
    active: u32 = 0,
};

/// Every field has a default: a window must still recognise (and restart)
/// a service of another release whose status lacks or adds fields.
pub const Status = struct {
    version: u32 = version,
    /// the service's process, so a window that did not start it can tell
    /// when it is gone
    pid: i32 = 0,
    /// release of the service binary (a window of another release restarts it)
    build: []const u8 = "",
    tun: bool = false,
    socks_port: u16 = 0,
    down: u64 = 0,
    up: u64 = 0,
    active: u32 = 0,
    failed: u32 = 0,
    /// connections that moved past the outer TLS layer (Vision direct)
    direct: u32 = 0,
    /// the last connection fault since the previous status ("none" if none)
    fault: []const u8 = "none",
    /// servers in the configuration this build cannot carry
    skipped: usize = 0,
    /// id of the server the main route uses right now (a reserve server
    /// when the main one stopped working); 0 when there is none
    server: u32 = 0,
    /// how often that server changed since the service started
    switches: u32 = 0,
    /// the VPN is off; the service only holds the applications with a rule
    standby: bool = false,
    apps: []const AppStatus = &.{},
};

pub const Request = struct {
    cmd: []const u8,
    /// "ping"
    host: []const u8 = "",
    port: u16 = 0,
};

pub const PingReply = struct { ms: ?u32 = null };

pub const CallError = error{ Unsupported, Timeout, ReadFailed, WriteFailed, ReplyTooLong, WrongPeer } ||
    std.Io.net.UnixAddress.InitError || std.Io.net.UnixAddress.ConnectError || std.mem.Allocator.Error;

const max_reply = 1 << 20;

/// Send one command and return the response line (allocated, without the
/// newline). Gives up after `timeout_ms`, so a stuck peer never freezes the
/// caller. Only a peer running as this user or as root is talked to. Also
/// used for the root helper's socket.
pub fn call(gpa: std.mem.Allocator, io: Io, socket_path: []const u8, cmd: []const u8, timeout_ms: i64) CallError![]u8 {
    var req_buf: [96]u8 = undefined;
    const req = std.fmt.bufPrint(&req_buf, "{{\"cmd\":\"{s}\"}}\n", .{cmd}) catch return error.WriteFailed;
    return request(gpa, io, socket_path, req, timeout_ms);
}

/// `call` with a whole request line (JSON object and newline) of the caller's.
pub fn request(gpa: std.mem.Allocator, io: Io, socket_path: []const u8, req: []const u8, timeout_ms: i64) CallError![]u8 {
    if (comptime @import("builtin").os.tag == .windows) return requestWindows(gpa, io, socket_path, req, timeout_ms);
    if (comptime !sys.supported) return error.Unsupported;
    const addr = try std.Io.net.UnixAddress.init(socket_path);
    const s = try addr.connect(io);
    defer s.close(io);
    const fd = s.socket.handle;
    const peer = sys.peerUid(fd) orelse return error.WrongPeer;
    if (peer != c.geteuid() and peer != 0) return error.WrongPeer;
    if (@import("builtin").os.tag.isDarwin()) {
        const one: c_int = 1;
        _ = c.setsockopt(fd, c.SOL.SOCKET, c.SO.NOSIGPIPE, &one, @sizeOf(c_int));
    }
    var off: usize = 0;
    while (off < req.len) {
        const n = c.write(fd, req[off..].ptr, req.len - off);
        if (n < 0 and c.errno(n) == .INTR) continue;
        if (n <= 0) return error.WriteFailed;
        off += @intCast(n);
    }

    const start = Io.Clock.awake.now(io);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var buf: [4096]u8 = undefined;
    while (std.mem.indexOfScalar(u8, out.items, '\n') == null) {
        const left = timeout_ms - start.untilNow(io, .awake).toMilliseconds();
        if (left <= 0 or !sys.waitFd(fd, false, @intCast(@min(left, std.math.maxInt(i32))))) return error.Timeout;
        const n = c.read(fd, &buf, buf.len);
        if (n == 0) break;
        if (n < 0) {
            if (c.errno(n) == .INTR) continue;
            return error.ReadFailed;
        }
        if (out.items.len + @as(usize, @intCast(n)) > max_reply) return error.ReplyTooLong;
        try out.appendSlice(gpa, buf[0..@intCast(n)]);
    }
    out.shrinkRetainingCapacity(std.mem.indexOfScalar(u8, out.items, '\n') orelse out.items.len);
    return out.toOwnedSlice(gpa);
}

/// Windows: the same over an AF_UNIX socket (std.Io.net, AFD). Who may
/// connect is decided by the folder the socket file is in (the user's
/// profile), so there is no peer to check.
fn requestWindows(gpa: std.mem.Allocator, io: Io, socket_path: []const u8, req: []const u8, timeout_ms: i64) CallError![]u8 {
    const afd = @import("afd.zig");
    const addr = try std.Io.net.UnixAddress.init(socket_path);
    const s = try addr.connect(io);
    defer s.close(io);
    var wb: [256]u8 = undefined;
    var w = s.writer(io, &wb);
    w.interface.writeAll(req) catch return error.WriteFailed;
    w.interface.flush() catch return error.WriteFailed;

    const start = Io.Clock.awake.now(io);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var buf: [4096]u8 = undefined;
    while (std.mem.indexOfScalar(u8, out.items, '\n') == null) {
        const left = timeout_ms - start.untilNow(io, .awake).toMilliseconds();
        if (left <= 0 or !afd.wait(s.socket.handle, false, @intCast(@min(left, std.math.maxInt(i32))))) return error.Timeout;
        const n = afd.recv(s.socket.handle, &buf) catch return error.ReadFailed;
        if (n == 0) break;
        if (out.items.len + n > max_reply) return error.ReplyTooLong;
        try out.appendSlice(gpa, buf[0..n]);
    }
    out.shrinkRetainingCapacity(std.mem.indexOfScalar(u8, out.items, '\n') orelse out.items.len);
    return out.toOwnedSlice(gpa);
}

test "socket path falls back to /tmp when the folder path is too long" {
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("/Users/a/Library/Application Support/BLACKWALL/service.sock", socketPath(&buf, "/Users/a/Library/Application Support/BLACKWALL"));
    const long = "/private/tmp/claude-501/a-rather-long-scratch-directory-name/8c639711-a540-4344-8ec2-eb9a04170d16/linktest";
    try std.testing.expect(std.mem.startsWith(u8, socketPath(&buf, long), "/tmp/blackwall-"));
}

test "call: one line back, timeout on a silent peer" {
    if (comptime !sys.supported) return error.SkipZigTest;
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var dir_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&dir_buf, "/tmp/bw-ipc-{d}.sock", .{c.getpid()});
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};
    const addr = try std.Io.net.UnixAddress.init(path);
    var server = try addr.listen(io, .{});
    defer server.deinit(io);

    const Peer = struct {
        fn serve(srv: *std.Io.net.Server, answer: bool) void {
            const conn = srv.accept(std.testing.io) catch return;
            defer conn.close(std.testing.io);
            var b: [128]u8 = undefined;
            _ = c.read(conn.socket.handle, &b, b.len);
            if (answer) {
                const reply = "{\"ok\":true}\nrest";
                _ = c.write(conn.socket.handle, reply, reply.len);
            } else {
                std.Io.sleep(std.testing.io, .fromMilliseconds(300), .awake) catch {};
            }
        }
    };
    {
        const t = try std.Thread.spawn(.{}, Peer.serve, .{ &server, true });
        defer t.join();
        const line = try call(gpa, io, path, "status", 2000);
        defer gpa.free(line);
        try std.testing.expectEqualStrings("{\"ok\":true}", line);
    }
    {
        const t = try std.Thread.spawn(.{}, Peer.serve, .{ &server, false });
        defer t.join();
        try std.testing.expectError(error.Timeout, call(gpa, io, path, "status", 50));
    }
}
