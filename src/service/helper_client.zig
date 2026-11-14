//! The service's side of the root helper protocol (macOS): ask for the
//! TUN, give it back.

const std = @import("std");
const core = @import("core");
const fdpass = @import("fdpass");

const proto = core.helper_ipc;
const c = std.c;
const Io = std.Io;

pub const Lease = struct {
    fd: c.fd_t,
    ifname: [16]u8 = @splat(0),
    bind_index: u32,
    dns: [8][4]u8 = undefined,
    dns_len: usize = 0,

    pub fn upstream(l: *const Lease) []const [4]u8 {
        return l.dns[0..l.dns_len];
    }
};

pub const UpError = error{ HelperMissing, Conflict, HelperRefused, BadReply } || std.mem.Allocator.Error;

/// Names of the other VPN interfaces after error.Conflict.
pub var conflict_names: [4][16]u8 = undefined;
pub var conflict_count: usize = 0;

fn call(gpa: std.mem.Allocator, io: Io, req: proto.Request, want_fd: bool) !struct { std.json.Parsed(proto.Reply), ?c.fd_t } {
    const addr = std.Io.net.UnixAddress.init(proto.socket_path) catch return error.HelperMissing;
    const s = addr.connect(io) catch return error.HelperMissing;
    defer s.close(io);
    const text = try std.json.Stringify.valueAlloc(gpa, req, .{});
    defer gpa.free(text);
    const line = try std.mem.concat(gpa, u8, &.{ text, "\n" });
    defer gpa.free(line);
    var off: usize = 0;
    while (off < line.len) {
        const n = c.write(s.socket.handle, line[off..].ptr, line.len - off);
        if (n <= 0) return error.HelperRefused;
        off += @intCast(n);
    }
    var buf: [16 * 1024]u8 = undefined;
    var len: usize = 0;
    var fd: ?c.fd_t = null;
    while (std.mem.indexOfScalar(u8, buf[0..len], '\n') == null) {
        if (len == buf.len) return error.BadReply;
        const got = fdpass.recvFd(s.socket.handle, buf[len..]) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return error.BadReply,
        };
        if (got.fd) |f| {
            if (fd != null or !want_fd) _ = c.close(f) else fd = f;
        }
        len += got.len;
    }
    errdefer if (fd) |f| {
        _ = c.close(f);
    };
    const end = std.mem.indexOfScalar(u8, buf[0..len], '\n') orelse len;
    const parsed = std.json.parseFromSlice(proto.Reply, gpa, buf[0..end], .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch return error.BadReply;
    return .{ parsed, fd };
}

pub fn up(gpa: std.mem.Allocator, io: Io, req: proto.Request) UpError!Lease {
    const parsed, const fd = call(gpa, io, req, true) catch |err| return switch (err) {
        error.HelperMissing => error.HelperMissing,
        error.OutOfMemory => error.OutOfMemory,
        else => error.BadReply,
    };
    defer parsed.deinit();
    const r = parsed.value;
    if (!r.ok) {
        if (fd) |f| _ = c.close(f);
        if (std.mem.eql(u8, r.@"error", "conflict")) {
            conflict_count = 0;
            for (r.conflicts) |name| {
                if (conflict_count == conflict_names.len) break;
                conflict_names[conflict_count] = @splat(0);
                @memcpy(conflict_names[conflict_count][0..@min(name.len, 15)], name[0..@min(name.len, 15)]);
                conflict_count += 1;
            }
            return error.Conflict;
        }
        return error.HelperRefused;
    }
    var lease: Lease = .{ .fd = fd orelse return error.BadReply, .bind_index = r.bind_index };
    @memcpy(lease.ifname[0..@min(r.ifname.len, 15)], r.ifname[0..@min(r.ifname.len, 15)]);
    for (r.dns) |text| {
        if (lease.dns_len == lease.dns.len) break;
        const ip = std.Io.net.Ip4Address.parse(text, 0) catch continue;
        lease.dns[lease.dns_len] = ip.bytes;
        lease.dns_len += 1;
    }
    return lease;
}

/// Ask the helper to take everything down (routes, DNS, kill switch, utun).
pub fn down(gpa: std.mem.Allocator, io: Io) void {
    const parsed, const fd = call(gpa, io, .{ .cmd = "down" }, false) catch return;
    if (fd) |f| _ = c.close(f);
    parsed.deinit();
}

/// Tell the strict kill switch about new server addresses.
pub fn servers(gpa: std.mem.Allocator, io: Io, list: []const []const u8) void {
    const parsed, const fd = call(gpa, io, .{ .cmd = "servers", .servers = list }, false) catch return;
    if (fd) |f| _ = c.close(f);
    parsed.deinit();
}

/// Whether the helper is installed and answering.
pub fn present(gpa: std.mem.Allocator, io: Io) bool {
    const parsed, const fd = call(gpa, io, .{ .cmd = "status" }, false) catch return false;
    if (fd) |f| _ = c.close(f);
    defer parsed.deinit();
    return parsed.value.ok;
}
