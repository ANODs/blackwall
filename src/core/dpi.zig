//! The "DPI bypass" route: a direct connection whose first bytes (a TLS
//! ClientHello, an HTTP request) leave in a shape that a middlebox
//! matching the site's name in one packet does not recognise, while the
//! server still reads the same request. Everything here is done from our
//! own socket: no raw sockets, no administrator, no fake packets.
//!
//!   records    the ClientHello split into two TLS records in the middle
//!              of the server name, sent in one write
//!   segments   the same two records, each in its own TCP segment
//!   disorder   the first segment sent with TTL 1 (it dies at the first
//!              router; the kernel sends it again later), so the second
//!              arrives first
//!
//! Plain HTTP goes as it is: what reads its Host on the way (an ISP's
//! filter, a server's sniffing) takes half a name for the whole one and
//! breaks the request, so cutting it costs more than it saves. Which way
//! gets a TLS connection through is learned per host: a refusal
//! (a reset, or silence) before the server answered moves on to the next
//! with the same bytes; the one that worked is tried first next time.

const std = @import("std");
const Io = std.Io;
const sni = @import("sni.zig");

pub const Strategy = enum(u8) {
    records,
    segments,
    disorder,

    pub const count = 3;
};

/// How long the server has to say anything once the first bytes are out.
pub const answer_ms = 2500;

/// A first flight, cut where the name is: the whole ClientHello record.
pub const Hello = struct {
    bytes: []const u8,
    /// where to cut: the middle of the name
    cut: usize,
};

pub fn hello(first: []const u8) ?Hello {
    const k, const need = sni.kind(first);
    if (k != .tls or first.len < need) return null;
    const f = sni.serverName(first[0..need]) orelse return null;
    return .{ .bytes = first[0..need], .cut = f.offset + f.name.len / 2 };
}

/// The ClientHello as two records cut at `h.cut`: the first record's
/// bytes, then the second's, in `out`. Same handshake, other framing.
pub fn splitRecords(h: Hello, out: []u8) struct { []const u8, []const u8 } {
    std.debug.assert(h.cut > 5 and h.cut < h.bytes.len and out.len >= h.bytes.len + 5);
    const body = h.bytes[5..];
    const at = h.cut - 5;
    const one = out[0 .. 5 + at];
    one[0..3].* = h.bytes[0..3].*;
    std.mem.writeInt(u16, one[3..5], @intCast(at), .big);
    @memcpy(one[5..], body[0..at]);
    const two = out[one.len..][0 .. 5 + body.len - at];
    two[0..3].* = h.bytes[0..3].*;
    std.mem.writeInt(u16, two[3..5], @intCast(body.len - at), .big);
    @memcpy(two[5..], body[at..]);
    return .{ one, two };
}

/// What to send, in order, each part its own segment when asked; and
/// whether the first goes with a TTL of 1.
pub const Plan = struct {
    parts: [2][]const u8,
    /// one write for both
    together: bool,
    low_ttl_first: bool,
};

pub fn plan(h: Hello, s: Strategy, buf: []u8) Plan {
    const one, const two = splitRecords(h, buf);
    return switch (s) {
        .records => .{ .parts = .{ one, two }, .together = true, .low_ttl_first = false },
        .segments => .{ .parts = .{ one, two }, .together = false, .low_ttl_first = false },
        .disorder => .{ .parts = .{ one, two }, .together = false, .low_ttl_first = true },
    };
}

/// What worked for which host, the last 64 of them.
pub const Memory = struct {
    mutex: Io.Mutex = .init,
    hosts: [64]u64 = @splat(0),
    strategy: [64]Strategy = @splat(.records),
    next: usize = 0,

    fn key(host: []const u8) u64 {
        var h = std.hash.Wyhash.init(0x5eed);
        for (host) |c| h.update(&.{std.ascii.toLower(c)});
        return h.final() | 1;
    }

    pub fn get(m: *Memory, io: Io, host: []const u8) ?Strategy {
        const k = key(host);
        m.mutex.lockUncancelable(io);
        defer m.mutex.unlock(io);
        for (m.hosts, 0..) |hk, i| if (hk == k) return m.strategy[i];
        return null;
    }

    pub fn put(m: *Memory, io: Io, host: []const u8, s: Strategy) void {
        const k = key(host);
        m.mutex.lockUncancelable(io);
        defer m.mutex.unlock(io);
        for (m.hosts, 0..) |hk, i| if (hk == k) {
            m.strategy[i] = s;
            return;
        };
        m.hosts[m.next] = k;
        m.strategy[m.next] = s;
        m.next = (m.next + 1) % m.hosts.len;
    }
};

pub var memory: Memory = .{};

/// One strategy for every host, for tests (blackwall-proxy dpi:<name>).
pub var force: ?Strategy = null;

test "a ClientHello in two records: the same handshake bytes" {
    var hb: [512]u8 = undefined;
    const ch = sni.testHello(&hb, "blocked.example.com");
    const h = hello(ch).?;
    // the cut falls inside the name
    const f = sni.serverName(ch).?;
    try std.testing.expect(h.cut > f.offset and h.cut < f.offset + f.name.len);
    var out: [600]u8 = undefined;
    const one, const two = splitRecords(h, &out);
    // two records, each a header and part of the handshake
    try std.testing.expectEqual(@as(u8, 0x16), one[0]);
    try std.testing.expectEqual(@as(u8, 0x16), two[0]);
    try std.testing.expectEqual(one.len - 5, std.mem.readInt(u16, one[3..5], .big));
    try std.testing.expectEqual(two.len - 5, std.mem.readInt(u16, two[3..5], .big));
    var joined: [600]u8 = undefined;
    @memcpy(joined[0 .. one.len - 5], one[5..]);
    @memcpy(joined[one.len - 5 ..][0 .. two.len - 5], two[5..]);
    try std.testing.expectEqualSlices(u8, ch[5..], joined[0 .. one.len - 5 + two.len - 5]);
    // neither record holds the whole name
    try std.testing.expect(std.mem.indexOf(u8, one, "blocked.example.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, two, "blocked.example.com") == null);
}

test "every plan sends the request whole; HTTP is left alone" {
    var hb: [512]u8 = undefined;
    const ch = sni.testHello(&hb, "x.example");
    var buf: [600]u8 = undefined;
    inline for (.{ Strategy.records, Strategy.segments, Strategy.disorder }) |s| {
        const p = plan(hello(ch).?, s, &buf);
        try std.testing.expectEqual(s == .records, p.together);
        try std.testing.expectEqual(s == .disorder, p.low_ttl_first);
        try std.testing.expectEqual(ch.len + 5, p.parts[0].len + p.parts[1].len);
    }
    try std.testing.expect(hello("GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n") == null);
    // not a request we know: nothing to cut
    try std.testing.expect(hello("SSH-2.0-x\r\n") == null);
}

test "what worked is remembered per host" {
    var m: Memory = .{};
    const io = std.testing.io;
    try std.testing.expect(m.get(io, "a.example") == null);
    m.put(io, "a.example", .disorder);
    m.put(io, "B.example", .segments);
    try std.testing.expectEqual(Strategy.disorder, m.get(io, "A.EXAMPLE").?);
    try std.testing.expectEqual(Strategy.segments, m.get(io, "b.example").?);
    m.put(io, "a.example", .records);
    try std.testing.expectEqual(Strategy.records, m.get(io, "a.example").?);
}
