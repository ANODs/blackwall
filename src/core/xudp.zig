//! XUDP: UDP over one VLESS connection (command 0x03, Mux.Cool frames on
//! session 0). Every datagram carries its destination, so one connection
//! serves one application socket and any number of peers ("full cone"),
//! the way Xray and sing-box clients carry UDP.
//!
//! Frame: [u16 meta_len][meta][u16 data_len][data]
//!   meta = u16 session id (0), u8 status, u8 option, then for UDP frames
//!          u8 network (2), u16 port, u8 address type, address
//!   status 1 New, 2 Keep, 3 End, 4 KeepAlive; option bit 0 = data follows,
//!   bit 1 = error. Address types as in the VLESS header: 1 IPv4, 2 domain,
//!   3 IPv6.

const std = @import("std");

pub const max_payload = 7526; // Xray's own writer drops anything larger
pub const max_meta = 512;

pub const Address = union(enum) {
    ip4: [4]u8,
    ip6: [16]u8,
    domain: []const u8,

    pub fn eql(a: Address, b: Address) bool {
        return switch (a) {
            .ip4 => |x| b == .ip4 and std.mem.eql(u8, &x, &b.ip4),
            .ip6 => |x| b == .ip6 and std.mem.eql(u8, &x, &b.ip6),
            .domain => |x| b == .domain and std.ascii.eqlIgnoreCase(x, b.domain),
        };
    }

    fn len(a: Address) usize {
        return switch (a) {
            .ip4 => 4,
            .ip6 => 16,
            .domain => |d| 1 + d.len,
        };
    }
};

/// The VLESS request header for XUDP (no address after the command).
pub fn header(buf: *[1 + 16 + 1 + 18 + 1]u8, uuid: [16]u8, vision: bool) []const u8 {
    buf[0] = 0;
    buf[1..17].* = uuid;
    if (vision) {
        buf[17..37].* = .{ 18, 0x0a, 16 } ++ "xtls-rprx-vision".* ++ .{0x03};
        return buf[0..37];
    }
    buf[17] = 0;
    buf[18] = 0x03;
    return buf[0..19];
}

/// Encode one datagram frame (New for the first datagram of the session,
/// Keep afterwards). Returns the frame length, or null if it cannot be sent.
pub fn encode(out: []u8, first: bool, port: u16, addr: Address, payload: []const u8) ?usize {
    if (payload.len > max_payload) return null;
    if (addr == .domain and (addr.domain.len == 0 or addr.domain.len > 255)) return null;
    const meta_len = 4 + 1 + 2 + 1 + addr.len();
    const total = 2 + meta_len + 2 + payload.len;
    if (out.len < total or meta_len > max_meta) return null;
    std.mem.writeInt(u16, out[0..2], @intCast(meta_len), .big);
    out[2..9].* = .{ 0, 0, if (first) 1 else 2, 1, 2, 0, 0 };
    std.mem.writeInt(u16, out[7..9], port, .big);
    var i: usize = 9;
    switch (addr) {
        .ip4 => |a| {
            out[i] = 1;
            out[i + 1 ..][0..4].* = a;
            i += 5;
        },
        .ip6 => |a| {
            out[i] = 3;
            out[i + 1 ..][0..16].* = a;
            i += 17;
        },
        .domain => |d| {
            out[i] = 2;
            out[i + 1] = @intCast(d.len);
            @memcpy(out[i + 2 ..][0..d.len], d);
            i += 2 + d.len;
        },
    }
    std.mem.writeInt(u16, out[i..][0..2], @intCast(payload.len), .big);
    @memcpy(out[i + 2 ..][0..payload.len], payload);
    return total;
}

/// The frame that ends the session.
pub const end_frame = [_]u8{ 0, 4, 0, 0, 3, 0 };

pub const Event = union(enum) {
    /// a datagram for the application; `from` is the reply's source if the
    /// server named it (else it came from the session's destination)
    data: struct { from: ?struct { port: u16, addr: Address }, payload: []const u8 },
    /// the server ended the session
    end,
};

/// Incremental parser for the server's frames.
pub const Reader = struct {
    buf: []u8,
    len: usize = 0,
    /// length of the frame returned last; dropped on the next call
    done: usize = 0,

    /// Append bytes from the connection (invalidates the last event).
    /// False if they do not fit: a frame larger than the buffer means a
    /// broken stream.
    pub fn push(r: *Reader, bytes: []const u8) bool {
        r.drop();
        if (r.buf.len - r.len < bytes.len) return false;
        @memcpy(r.buf[r.len..][0..bytes.len], bytes);
        r.len += bytes.len;
        return true;
    }

    /// Next complete event; null when more bytes are needed. Slices point
    /// into the buffer and stay valid until the next `next` or `push`.
    pub fn next(r: *Reader) error{BadFrame}!?Event {
        r.drop();
        while (true) {
            if (r.len < 2) return null;
            const meta_len = std.mem.readInt(u16, r.buf[0..2], .big);
            if (meta_len < 4) return .end;
            if (meta_len > max_meta) return error.BadFrame;
            if (r.len < 2 + meta_len) return null;
            const meta = r.buf[2..][0..meta_len];
            const status = meta[2];
            const option = meta[3];
            var frame_len: usize = 2 + meta_len;
            var payload: []const u8 = &.{};
            if (option & 1 != 0) {
                if (r.len < frame_len + 2) return null;
                const dl = std.mem.readInt(u16, r.buf[frame_len..][0..2], .big);
                if (r.len < frame_len + 2 + dl) return null;
                payload = r.buf[frame_len + 2 ..][0..dl];
                frame_len += 2 + dl;
            }
            if (option & 2 != 0 or status == 3 or status == 1) {
                r.consume(frame_len);
                return .end;
            }
            if (status == 4 or payload.len == 0) {
                r.consume(frame_len);
                continue;
            }
            if (status != 2) return error.BadFrame;
            var from: ?Address = null;
            var port: u16 = 0;
            if (meta_len > 4 and meta[4] == 2) {
                if (meta_len < 9) return error.BadFrame;
                port = std.mem.readInt(u16, meta[5..7], .big);
                from = switch (meta[7]) {
                    1 => if (meta_len >= 12) .{ .ip4 = meta[8..12].* } else return error.BadFrame,
                    3 => if (meta_len >= 24) .{ .ip6 = meta[8..24].* } else return error.BadFrame,
                    2 => blk: {
                        const n = meta[8];
                        if (n == 0 or meta_len < 9 + @as(usize, n)) return error.BadFrame;
                        break :blk .{ .domain = meta[9..][0..n] };
                    },
                    else => return error.BadFrame,
                };
            }
            r.done = frame_len;
            return .{ .data = .{
                .from = if (from) |a| .{ .port = port, .addr = a } else null,
                .payload = payload,
            } };
        }
    }

    fn drop(r: *Reader) void {
        if (r.done == 0) return;
        r.consume(r.done);
        r.done = 0;
    }

    fn consume(r: *Reader, n: usize) void {
        std.mem.copyForwards(u8, r.buf[0 .. r.len - n], r.buf[n..r.len]);
        r.len -= n;
    }
};

test "header shapes" {
    var b: [37]u8 = undefined;
    const v = header(&b, @splat(7), true);
    try std.testing.expectEqual(37, v.len);
    try std.testing.expectEqualSlices(u8, &.{ 18, 0x0a, 16 }, v[17..20]);
    try std.testing.expectEqual(0x03, v[36]);
    const p = header(&b, @splat(7), false);
    try std.testing.expectEqualSlices(u8, &.{ 0, 3 }, p[17..19]);
}

test "encode matches the documented XUDP New frame" {
    var out: [64]u8 = undefined;
    const n = encode(&out, true, 53, .{ .ip4 = .{ 1, 1, 1, 1 } }, "q").?;
    try std.testing.expectEqualSlices(u8, &.{ 0, 0x0c, 0, 0, 1, 1, 2, 0, 53, 1, 1, 1, 1, 1, 0, 1, 'q' }, out[0..n]);
    const k = encode(&out, false, 443, .{ .domain = "a.io" }, "xy").?;
    try std.testing.expectEqualSlices(u8, &.{ 0, 13, 0, 0, 2, 1, 2, 1, 0xbb, 2, 4, 'a', '.', 'i', 'o', 0, 2, 'x', 'y' }, out[0..k]);
    var big: [max_payload + 1]u8 = undefined;
    try std.testing.expect(encode(&out, false, 1, .{ .ip4 = @splat(0) }, &big) == null);
}

test "reader: replies with and without source, keepalive, split input, end" {
    var store: [8192]u8 = undefined;
    var r: Reader = .{ .buf = &store };
    // Keep with an IPv4 source, sent in two pieces
    const keep = [_]u8{ 0, 12, 0, 0, 2, 1, 2, 0x0d, 0x96, 1, 9, 9, 9, 9, 0, 3, 'a', 'b', 'c' };
    try std.testing.expect(r.push(keep[0..7]));
    try std.testing.expect((try r.next()) == null);
    try std.testing.expect(r.push(keep[7..]));
    const ev = (try r.next()).?.data;
    try std.testing.expectEqualStrings("abc", ev.payload);
    try std.testing.expectEqual(3478, ev.from.?.port);
    try std.testing.expect(ev.from.?.addr.eql(.{ .ip4 = .{ 9, 9, 9, 9 } }));
    // KeepAlive is skipped, a Keep without address follows
    try std.testing.expect(r.push(&.{ 0, 4, 0, 0, 4, 0 }));
    try std.testing.expect(r.push(&.{ 0, 4, 0, 0, 2, 1, 0, 2, 'h', 'i' }));
    const ev2 = (try r.next()).?.data;
    try std.testing.expectEqualStrings("hi", ev2.payload);
    try std.testing.expect(ev2.from == null);
    // domain source
    try std.testing.expect(r.push(&.{ 0, 12, 0, 0, 2, 1, 2, 0, 80, 2, 3, 'x', '.', 'y', 0, 1, '!' }));
    const ev3 = (try r.next()).?.data;
    try std.testing.expectEqualStrings("x.y", ev3.from.?.addr.domain);
    try std.testing.expectEqualStrings("!", ev3.payload);
    try std.testing.expect(r.push(&end_frame));
    try std.testing.expect((try r.next()).? == .end);
}

test "reader: many frames buffered at once keep their payloads" {
    var store: [4096]u8 = undefined;
    var r: Reader = .{ .buf = &store };
    var frames: [600]u8 = undefined;
    var n: usize = 0;
    for (0..20) |i| {
        const f = [_]u8{ 0, 4, 0, 0, 2, 1, 0, 2, 'a' + @as(u8, @intCast(i)), 'z' };
        @memcpy(frames[n..][0..f.len], &f);
        n += f.len;
    }
    try std.testing.expect(r.push(frames[0..n]));
    for (0..20) |i| {
        const ev = (try r.next()).?.data;
        try std.testing.expectEqual('a' + @as(u8, @intCast(i)), ev.payload[0]);
    }
    try std.testing.expect((try r.next()) == null);
}
