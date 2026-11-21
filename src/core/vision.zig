//! XTLS Vision framing (flow "xtls-rprx-vision").
//!
//! While the inner connection is being set up, every write is wrapped in a
//! frame with random padding so the TLS-in-TLS handshake does not show its
//! shape. Once the inner connection is TLS 1.3 and starts sending
//! application data, either side may end padding with the "direct" command
//! and from then on send the inner records raw on the TCP socket: the outer
//! TLS layer stops encrypting, so bulk traffic is encrypted only once.
//!
//! Frame: [uuid, first frame only] command u8, content_len u16,
//! padding_len u16, content, padding.

const std = @import("std");

pub const Command = enum(u8) { pad = 0, end = 1, direct = 2 };

pub const max_content = 8192 - 21;
pub const max_frame = 16 + 5 + max_content;

/// State both directions look at: the downlink learns what the inner
/// server speaks, the uplink acts on it.
pub const Traffic = struct {
    server_tls: std.atomic.Value(bool) = .init(false),
    enable_direct: std.atomic.Value(bool) = .init(false),
};

pub const Padder = struct {
    uuid: ?[16]u8,

    pub fn init(uuid: [16]u8) Padder {
        return .{ .uuid = uuid };
    }

    /// Write one frame into `out` (at least `max_frame` bytes) and return
    /// its length. `long` pads short content up to roughly a full packet.
    pub fn frame(p: *Padder, out: []u8, content: []const u8, command: Command, long: bool, rand: std.Random) usize {
        std.debug.assert(content.len <= max_content and out.len >= max_frame);
        var pad: usize = if (content.len < 900 and long)
            rand.uintLessThan(usize, 500) + 900 - content.len
        else
            rand.uintLessThan(usize, 256);
        pad = @min(pad, max_content - content.len);
        var n: usize = 0;
        if (p.uuid) |u| {
            out[0..16].* = u;
            n = 16;
            p.uuid = null;
        }
        out[n] = @backingInt(command);
        std.mem.writeInt(u16, out[n + 1 ..][0..2], @intCast(content.len), .big);
        std.mem.writeInt(u16, out[n + 3 ..][0..2], @intCast(pad), .big);
        n += 5;
        @memcpy(out[n..][0..content.len], content);
        n += content.len;
        @memset(out[n..][0..pad], 0);
        return n + pad;
    }
};

pub const Unpadder = struct {
    uuid: [16]u8,
    state: enum { initial, header, body, passthrough } = .initial,
    matched: u8 = 0,
    hdr: [5]u8 = undefined,
    hdr_len: u8 = 0,
    command: u8 = 0,
    content_left: u16 = 0,
    padding_left: u16 = 0,

    pub fn init(uuid: [16]u8) Unpadder {
        return .{ .uuid = uuid };
    }

    pub const Result = struct {
        /// bytes of the input that were processed
        consumed: usize,
        /// the peer switched to raw TCP after these bytes
        direct: bool,
    };

    /// Process `in`, handing content to `sink.content(bytes)`.
    pub fn feed(u: *Unpadder, in: []const u8, sink: anytype) !Result {
        var i: usize = 0;
        while (i < in.len) {
            switch (u.state) {
                .passthrough => {
                    try sink.content(in[i..]);
                    i = in.len;
                },
                .initial => {
                    // the stream is padded only if it opens with our uuid
                    const n = @min(16 - u.matched, in.len - i);
                    if (!std.mem.eql(u8, in[i..][0..n], u.uuid[u.matched..][0..n])) {
                        if (u.matched > 0) try sink.content(u.uuid[0..u.matched]);
                        u.state = .passthrough;
                        continue;
                    }
                    u.matched += @intCast(n);
                    i += n;
                    if (u.matched == 16) u.state = .header;
                },
                .header => {
                    u.hdr[u.hdr_len] = in[i];
                    u.hdr_len += 1;
                    i += 1;
                    if (u.hdr_len == 5) {
                        u.command = u.hdr[0];
                        u.content_left = std.mem.readInt(u16, u.hdr[1..3], .big);
                        u.padding_left = std.mem.readInt(u16, u.hdr[3..5], .big);
                        u.hdr_len = 0;
                        u.state = .body;
                    }
                },
                .body => {
                    if (u.content_left > 0) {
                        const n: u16 = @intCast(@min(u.content_left, in.len - i));
                        try sink.content(in[i..][0..n]);
                        i += n;
                        u.content_left -= n;
                    } else {
                        const n: u16 = @intCast(@min(u.padding_left, in.len - i));
                        i += n;
                        u.padding_left -= n;
                    }
                },
            }
            if (u.state == .body and u.content_left == 0 and u.padding_left == 0) {
                switch (u.command) {
                    0 => u.state = .header,
                    2 => {
                        u.state = .passthrough;
                        return .{ .consumed = i, .direct = true };
                    },
                    else => u.state = .passthrough,
                }
            }
        }
        return .{ .consumed = i, .direct = false };
    }
};

/// Watches the first downlink packets for the inner ServerHello: TLS 1.3
/// with an AEAD that the direct mode can carry enables it.
pub const ServerHelloFilter = struct {
    left: u8 = 8,
    remaining: i32 = 0,
    cipher: u16 = 0,

    pub fn feed(f: *ServerHelloFilter, piece: []const u8, t: *Traffic) void {
        if (f.left == 0 or piece.len == 0) return;
        f.left -= 1;
        if (piece.len >= 6 and std.mem.eql(u8, piece[0..3], &.{ 0x16, 0x03, 0x03 }) and piece[5] == 0x02) {
            f.remaining = (@as(i32, piece[3]) << 8 | piece[4]) + 5;
            t.server_tls.store(true, .release);
            if (piece.len >= 79 and f.remaining >= 79) {
                const sid: usize = piece[43];
                if (piece.len >= 44 + sid + 2) f.cipher = std.mem.readInt(u16, piece[44 + sid ..][0..2], .big);
            }
        }
        if (f.remaining > 0) {
            const end: usize = @intCast(@min(f.remaining, @as(i32, @intCast(@min(piece.len, std.math.maxInt(i32))))));
            f.remaining -= @intCast(@min(piece.len, std.math.maxInt(i32)));
            if (std.mem.indexOf(u8, piece[0..end], &.{ 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 }) != null) {
                // TLS_AES_128_CCM_8_SHA256 (0x1305) is the one suite excluded
                if (f.cipher >= 0x1301 and f.cipher <= 0x1304) t.enable_direct.store(true, .release);
                f.left = 0;
            } else if (f.remaining <= 0) {
                f.left = 0;
            }
        }
    }
};

/// True when `b` is one or more complete TLS application data records.
pub fn isAppDataRecords(b: []const u8) bool {
    var i: usize = 0;
    while (i < b.len) {
        if (b.len - i < 5 or !std.mem.eql(u8, b[i..][0..3], &.{ 0x17, 0x03, 0x03 })) return false;
        i += 5 + std.mem.readInt(u16, b[i + 3 ..][0..2], .big);
    }
    return i == b.len and b.len > 0;
}

pub fn isRecordHeader(h: []const u8) bool {
    return h.len >= 5 and h[0] >= 0x14 and h[0] <= 0x17 and h[1] == 0x03 and h[2] <= 0x04;
}

pub fn isClientHello(b: []const u8) bool {
    return b.len >= 6 and b[0] == 0x16 and b[1] == 0x03 and b[5] == 0x01;
}

const Collect = struct {
    buf: std.ArrayList(u8) = .empty,
    fn content(c: *Collect, bytes: []const u8) !void {
        try c.buf.appendSlice(std.testing.allocator, bytes);
    }
};

test "padding round trip, byte by byte, across commands" {
    var prng: std.Random.DefaultPrng = .init(1);
    const uuid: [16]u8 = @splat(0x5a);
    var p: Padder = .init(uuid);
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(std.testing.allocator);
    var frame: [max_frame]u8 = undefined;
    const parts = [_]struct { []const u8, Command, bool }{
        .{ "", .pad, true },
        .{ "client hello", .pad, true },
        .{ "finished", .end, false },
    };
    for (parts) |part| {
        const n = p.frame(&frame, part[0], part[1], part[2], prng.random());
        try wire.appendSlice(std.testing.allocator, frame[0..n]);
    }
    try wire.appendSlice(std.testing.allocator, "raw tail");

    var out: Collect = .{};
    defer out.buf.deinit(std.testing.allocator);
    var u: Unpadder = .init(uuid);
    for (wire.items) |b| {
        const r = try u.feed(&.{b}, &out);
        try std.testing.expect(!r.direct);
        try std.testing.expectEqual(1, r.consumed);
    }
    try std.testing.expectEqualStrings("client hellofinishedraw tail", out.buf.items);
}

test "direct command stops at the frame boundary" {
    var prng: std.Random.DefaultPrng = .init(2);
    const uuid: [16]u8 = @splat(1);
    var p: Padder = .init(uuid);
    var frame: [max_frame]u8 = undefined;
    var wire: [2 * max_frame]u8 = undefined;
    const n = p.frame(&frame, "app data", .direct, false, prng.random());
    @memcpy(wire[0..n], frame[0..n]);
    @memcpy(wire[n..][0..3], "RAW");

    var out: Collect = .{};
    defer out.buf.deinit(std.testing.allocator);
    var u: Unpadder = .init(uuid);
    const r = try u.feed(wire[0 .. n + 3], &out);
    try std.testing.expect(r.direct);
    try std.testing.expectEqual(n, r.consumed);
    try std.testing.expectEqualStrings("app data", out.buf.items);
}

test "unpadded stream passes through" {
    var out: Collect = .{};
    defer out.buf.deinit(std.testing.allocator);
    var u: Unpadder = .init(@splat(9));
    _ = try u.feed(&.{ 9, 9, 9 }, &out); // looks like the uuid at first
    _ = try u.feed("HTTP/1.1 200 OK", &out);
    try std.testing.expectEqualStrings("\x09\x09\x09HTTP/1.1 200 OK", out.buf.items);
}

test "server hello filter enables direct only for TLS 1.3 AEAD" {
    var sh: [120]u8 = @splat(0);
    sh[0..6].* = .{ 0x16, 0x03, 0x03, 0x00, 115, 0x02 };
    sh[43] = 32;
    sh[76..78].* = .{ 0x13, 0x01 };
    sh[100..106].* = .{ 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };
    var t: Traffic = .{};
    var f: ServerHelloFilter = .{};
    f.feed(&sh, &t);
    try std.testing.expect(t.enable_direct.load(.acquire));

    sh[76..78].* = .{ 0x13, 0x05 };
    var t2: Traffic = .{};
    var f2: ServerHelloFilter = .{};
    f2.feed(&sh, &t2);
    try std.testing.expect(t2.server_tls.load(.acquire));
    try std.testing.expect(!t2.enable_direct.load(.acquire));
}

test "record helpers" {
    try std.testing.expect(isAppDataRecords(&.{ 0x17, 3, 3, 0, 1, 0xaa, 0x17, 3, 3, 0, 0 }));
    try std.testing.expect(!isAppDataRecords(&.{ 0x17, 3, 3, 0, 2, 0xaa }));
    try std.testing.expect(!isAppDataRecords(&.{ 0x14, 3, 3, 0, 1, 1 }));
    try std.testing.expect(isClientHello(&.{ 0x16, 3, 1, 2, 0, 1 }));
}
