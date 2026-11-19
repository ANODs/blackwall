//! IPv4 / IPv6 packets carrying TCP or UDP: parsing what the TUN delivers
//! and building what we send back. Addresses are 16 bytes everywhere; IPv4
//! uses the IPv4-mapped form (::ffff:a.b.c.d) so one type serves both.

const std = @import("std");

pub const Addr = [16]u8;

const v4_prefix = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

pub fn v4(a: [4]u8) Addr {
    return v4_prefix ++ a;
}

pub fn isV4(a: *const Addr) bool {
    return std.mem.eql(u8, a[0..12], &v4_prefix);
}

pub const Endpoint = struct {
    addr: Addr,
    port: u16,

    pub fn eql(a: Endpoint, b: Endpoint) bool {
        return a.port == b.port and std.mem.eql(u8, &a.addr, &b.addr);
    }

    pub fn format(e: Endpoint, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (isV4(&e.addr)) {
            try w.print("{d}.{d}.{d}.{d}:{d}", .{ e.addr[12], e.addr[13], e.addr[14], e.addr[15], e.port });
        } else {
            try w.writeByte('[');
            var i: usize = 0;
            while (i < 16) : (i += 2) {
                if (i > 0) try w.writeByte(':');
                try w.print("{x}", .{std.mem.readInt(u16, e.addr[i..][0..2], .big)});
            }
            try w.print("]:{d}", .{e.port});
        }
    }
};

pub const proto_icmp: u8 = 1;
pub const proto_tcp: u8 = 6;
pub const proto_udp: u8 = 17;
pub const proto_icmpv6: u8 = 58;

pub const Ip = struct {
    v6: bool,
    src: Addr,
    dst: Addr,
    proto: u8,
    /// transport header and payload
    l4: []const u8,
};

/// Returns null for anything we do not handle: fragments, malformed
/// headers, IPv6 extension headers other than the skippable ones.
pub fn parseIp(pkt: []const u8) ?Ip {
    if (pkt.len < 1) return null;
    switch (pkt[0] >> 4) {
        4 => {
            if (pkt.len < 20) return null;
            const ihl: usize = @as(usize, pkt[0] & 0x0f) * 4;
            const total = std.mem.readInt(u16, pkt[2..4], .big);
            if (ihl < 20 or total < ihl or total > pkt.len) return null;
            const frag = std.mem.readInt(u16, pkt[6..8], .big);
            if (frag & 0x3fff != 0) return null; // MF set or offset != 0
            return .{
                .v6 = false,
                .src = v4(pkt[12..16].*),
                .dst = v4(pkt[16..20].*),
                .proto = pkt[9],
                .l4 = pkt[ihl..total],
            };
        },
        6 => {
            if (pkt.len < 40) return null;
            const payload_len = std.mem.readInt(u16, pkt[4..6], .big);
            if (40 + @as(usize, payload_len) > pkt.len) return null;
            var next = pkt[6];
            var off: usize = 40;
            const end: usize = 40 + @as(usize, payload_len);
            while (true) {
                switch (next) {
                    0, 43, 60 => { // hop-by-hop, routing, destination options
                        if (end - off < 8) return null;
                        const len = (@as(usize, pkt[off + 1]) + 1) * 8;
                        if (end - off < len) return null;
                        next = pkt[off];
                        off += len;
                    },
                    else => break,
                }
            }
            if (next == 44 or next == 50 or next == 51 or next == 59) return null; // fragment, ESP, AH, none
            const src: Addr = pkt[8..24].*;
            const dst: Addr = pkt[24..40].*;
            // IPv4-mapped addresses never appear on the wire, and here they
            // would pass for IPv4: replies would get the other header size
            if (isV4(&src) or isV4(&dst)) return null;
            return .{
                .v6 = true,
                .src = src,
                .dst = dst,
                .proto = next,
                .l4 = pkt[off..end],
            };
        },
        else => return null,
    }
}

pub const Flags = packed struct(u8) {
    fin: bool = false,
    syn: bool = false,
    rst: bool = false,
    psh: bool = false,
    ack: bool = false,
    urg: bool = false,
    ece: bool = false,
    cwr: bool = false,
};

pub const Tcp = struct {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: Flags,
    window: u16,
    /// MSS option, only looked for on SYN
    mss: ?u16,
    payload: []const u8,
};

pub fn parseTcp(l4: []const u8) ?Tcp {
    if (l4.len < 20) return null;
    const off: usize = @as(usize, l4[12] >> 4) * 4;
    if (off < 20 or off > l4.len) return null;
    const flags: Flags = @bitCast(l4[13]);
    var mss: ?u16 = null;
    if (flags.syn) {
        var i: usize = 20;
        while (i < off) {
            const kind = l4[i];
            if (kind == 0) break;
            if (kind == 1) {
                i += 1;
                continue;
            }
            if (i + 1 >= off) break;
            const len = l4[i + 1];
            if (len < 2 or i + len > off) break;
            if (kind == 2 and len == 4) mss = std.mem.readInt(u16, l4[i + 2 ..][0..2], .big);
            i += len;
        }
    }
    return .{
        .src_port = std.mem.readInt(u16, l4[0..2], .big),
        .dst_port = std.mem.readInt(u16, l4[2..4], .big),
        .seq = std.mem.readInt(u32, l4[4..8], .big),
        .ack = std.mem.readInt(u32, l4[8..12], .big),
        .flags = flags,
        .window = std.mem.readInt(u16, l4[14..16], .big),
        .mss = mss,
        .payload = l4[off..],
    };
}

pub const Udp = struct {
    src_port: u16,
    dst_port: u16,
    payload: []const u8,
};

pub fn parseUdp(l4: []const u8) ?Udp {
    if (l4.len < 8) return null;
    const len = std.mem.readInt(u16, l4[4..6], .big);
    if (len < 8 or len > l4.len) return null;
    return .{
        .src_port = std.mem.readInt(u16, l4[0..2], .big),
        .dst_port = std.mem.readInt(u16, l4[2..4], .big),
        .payload = l4[8..len],
    };
}

// ---------------------------------------------------------------- checksums

/// Ones' complement sum of `data` added to `acc` (not folded).
pub fn sum(acc: u64, data: []const u8) u64 {
    var s = acc;
    var i: usize = 0;
    while (i + 8 <= data.len) : (i += 8) {
        s += std.mem.readInt(u32, data[i..][0..4], .big);
        s += std.mem.readInt(u32, data[i + 4 ..][0..4], .big);
    }
    while (i + 2 <= data.len) : (i += 2) s += std.mem.readInt(u16, data[i..][0..2], .big);
    if (i < data.len) s += @as(u64, data[i]) << 8;
    return s;
}

pub fn fold(acc: u64) u16 {
    var s = acc;
    while (s >> 16 != 0) s = (s & 0xffff) + (s >> 16);
    return ~@as(u16, @truncate(s));
}

fn pseudo(src: *const Addr, dst: *const Addr, proto: u8, len: usize) u64 {
    var s: u64 = 0;
    if (isV4(src)) {
        s = sum(s, src[12..16]);
        s = sum(s, dst[12..16]);
    } else {
        s = sum(s, src);
        s = sum(s, dst);
    }
    return s + proto + len;
}

/// Verify the transport checksum of a parsed packet.
pub fn transportChecksumOk(ip: Ip) bool {
    return fold(sum(pseudo(&ip.src, &ip.dst, ip.proto, ip.l4.len), ip.l4)) == 0;
}

// ---------------------------------------------------------------- building

/// Room needed in front of the transport header.
pub fn ipHeaderLen(addr: *const Addr) usize {
    return if (isV4(addr)) 20 else 40;
}

fn writeIpHeader(out: []u8, src: *const Addr, dst: *const Addr, proto: u8, l4_len: usize) usize {
    if (isV4(src)) {
        const total = 20 + l4_len;
        out[0..12].* = .{ 0x45, 0, @intCast(total >> 8), @truncate(total), 0, 0, 0x40, 0, 64, proto, 0, 0 };
        out[12..16].* = src[12..16].*;
        out[16..20].* = dst[12..16].*;
        std.mem.writeInt(u16, out[10..12], fold(sum(0, out[0..20])), .big);
        return 20;
    }
    out[0..4].* = .{ 0x60, 0, 0, 0 };
    std.mem.writeInt(u16, out[4..6], @intCast(l4_len), .big);
    out[6] = proto;
    out[7] = 64;
    out[8..24].* = src.*;
    out[24..40].* = dst.*;
    return 40;
}

pub const TcpOut = struct {
    seq: u32,
    ack: u32,
    flags: Flags,
    window: u16,
    /// MSS option to include (SYN segments)
    mss: ?u16 = null,
    payload: []const u8 = &.{},
};

/// Longest IP and TCP header we build: IPv6 and the MSS option.
pub const tcp_headers_max = 40 + 24;

/// The IP and TCP headers of a segment that carries `payload_len` bytes
/// (`seg.payload` is not used), its TCP checksum left to `finishTcp`.
/// `out` takes `tcp_headers_max`; returns the headers' length.
pub fn tcpHeaders(out: []u8, src: Endpoint, dst: Endpoint, seg: TcpOut, payload_len: usize) usize {
    const ip_len = ipHeaderLen(&src.addr);
    const opt_len: usize = if (seg.mss != null) 4 else 0;
    const hdr_len = 20 + opt_len;
    const t = out[ip_len..][0..hdr_len];
    std.mem.writeInt(u16, t[0..2], src.port, .big);
    std.mem.writeInt(u16, t[2..4], dst.port, .big);
    std.mem.writeInt(u32, t[4..8], seg.seq, .big);
    std.mem.writeInt(u32, t[8..12], seg.ack, .big);
    t[12] = @intCast((hdr_len / 4) << 4);
    t[13] = @bitCast(seg.flags);
    std.mem.writeInt(u16, t[14..16], seg.window, .big);
    t[16..20].* = .{ 0, 0, 0, 0 }; // checksum, urgent pointer
    if (seg.mss) |m| {
        t[20..22].* = .{ 2, 4 };
        std.mem.writeInt(u16, t[22..24], m, .big);
    }
    _ = writeIpHeader(out, &src.addr, &dst.addr, proto_tcp, hdr_len + payload_len);
    return ip_len + hdr_len;
}

/// Fill in the TCP checksum of `headers` (from `tcpHeaders`) for a
/// payload sent as `payload`, in pieces of any length.
pub fn finishTcp(headers: []u8, payload: []const []const u8) void {
    const v6 = headers[0] >> 4 == 6;
    const ip_len: usize = if (v6) 40 else 20;
    const t = headers[ip_len..];
    var len = t.len;
    for (payload) |p| len += p.len;
    var acc: u64 = proto_tcp + len;
    acc = if (v6) sum(acc, headers[8..40]) else sum(acc, headers[12..20]);
    acc = sum(acc, t);
    // the TCP header is 20 or 24 bytes, so the payload starts even
    var odd = false;
    for (payload) |p| {
        acc = if (odd) acc + @byteSwap(foldRaw(sum(0, p))) else sum(acc, p);
        odd = odd != (p.len % 2 == 1);
    }
    std.mem.writeInt(u16, t[16..18], fold(acc), .big);
}

/// The 16-bit ones' complement sum, not complemented.
fn foldRaw(acc: u64) u16 {
    return ~fold(acc);
}

/// Build an IP packet with a TCP segment into `out`; returns its length.
pub fn writeTcp(out: []u8, src: Endpoint, dst: Endpoint, seg: TcpOut) usize {
    const n = tcpHeaders(out, src, dst, seg, seg.payload.len);
    @memcpy(out[n..][0..seg.payload.len], seg.payload);
    finishTcp(out[0..n], &.{out[n..][0..seg.payload.len]});
    return n + seg.payload.len;
}

/// Build an IP packet with a UDP datagram into `out`; returns its length.
pub fn writeUdp(out: []u8, src: Endpoint, dst: Endpoint, payload: []const u8) usize {
    const ip_len = ipHeaderLen(&src.addr);
    const l4_len = 8 + payload.len;
    const u = out[ip_len..][0..l4_len];
    std.mem.writeInt(u16, u[0..2], src.port, .big);
    std.mem.writeInt(u16, u[2..4], dst.port, .big);
    std.mem.writeInt(u16, u[4..6], @intCast(l4_len), .big);
    u[6..8].* = .{ 0, 0 };
    @memcpy(u[8..], payload);
    var c = fold(sum(pseudo(&src.addr, &dst.addr, proto_udp, l4_len), u));
    if (c == 0) c = 0xffff;
    std.mem.writeInt(u16, u[6..8], c, .big);
    _ = writeIpHeader(out, &src.addr, &dst.addr, proto_udp, l4_len);
    return ip_len + l4_len;
}

// ---------------------------------------------------------------- tests

test "IPv4 TCP round trip with MSS option" {
    var buf: [128]u8 = undefined;
    const a: Endpoint = .{ .addr = v4(.{ 10, 0, 0, 2 }), .port = 51000 };
    const b: Endpoint = .{ .addr = v4(.{ 93, 184, 216, 34 }), .port = 443 };
    const n = writeTcp(&buf, a, b, .{ .seq = 1000, .ack = 0, .flags = .{ .syn = true }, .window = 65535, .mss = 1460 });
    try std.testing.expectEqual(20 + 24, n);
    const ip = parseIp(buf[0..n]).?;
    try std.testing.expect(!ip.v6);
    try std.testing.expect(transportChecksumOk(ip));
    try std.testing.expectEqual(proto_tcp, ip.proto);
    try std.testing.expectEqualSlices(u8, &a.addr, &ip.src);
    const t = parseTcp(ip.l4).?;
    try std.testing.expect(t.flags.syn and !t.flags.ack);
    try std.testing.expectEqual(1460, t.mss.?);
    try std.testing.expectEqual(1000, t.seq);
    // header checksum folds to zero
    try std.testing.expectEqual(0, fold(sum(0, buf[0..20])));
}

test "IPv6 UDP round trip, extension header skipped" {
    var buf: [256]u8 = undefined;
    var a: Endpoint = .{ .addr = @splat(0), .port = 5353 };
    a.addr[0] = 0xfd;
    a.addr[15] = 2;
    var b = a;
    b.addr[15] = 1;
    b.port = 53;
    const n = writeUdp(&buf, a, b, "query");
    const ip = parseIp(buf[0..n]).?;
    try std.testing.expect(ip.v6 and transportChecksumOk(ip));
    const u = parseUdp(ip.l4).?;
    try std.testing.expectEqualStrings("query", u.payload);

    // insert an 8-byte hop-by-hop header in front of UDP
    var ext: [256]u8 = undefined;
    @memcpy(ext[0..40], buf[0..40]);
    ext[6] = 0; // next header: hop-by-hop
    std.mem.writeInt(u16, ext[4..6], @intCast(n - 40 + 8), .big);
    ext[40..48].* = .{ proto_udp, 0, 1, 4, 0, 0, 0, 0 };
    @memcpy(ext[48 .. 48 + n - 40], buf[40..n]);
    const ip2 = parseIp(ext[0 .. n + 8]).?;
    try std.testing.expectEqual(proto_udp, ip2.proto);
    try std.testing.expectEqualStrings("query", parseUdp(ip2.l4).?.payload);
}

test "TCP checksum over a payload in pieces, odd lengths included" {
    var data: [301]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 151 +% 7);
    const a: Endpoint = .{ .addr = v4(.{ 10, 0, 0, 2 }), .port = 51000 };
    var b6: Endpoint = .{ .addr = @splat(0), .port = 443 };
    b6.addr[0] = 0xfd;
    b6.addr[15] = 1;
    var a6 = b6;
    a6.addr[15] = 2;
    a6.port = 40000;
    for ([_][2]Endpoint{ .{ a, .{ .addr = v4(.{ 93, 184, 216, 34 }), .port = 443 } }, .{ a6, b6 } }) |ends| {
        for ([_]usize{ 0, 1, 2, 3, 150, 151, 299, 300, 301 }) |cut| {
            for ([_]usize{ 301, 300, 1, 0 }) |len| {
                const first = data[0..@min(cut, len)];
                const second = data[first.len..len];
                const seg: TcpOut = .{ .seq = 5, .ack = 9, .flags = .{ .ack = true, .psh = true }, .window = 1000, .payload = data[0..len] };
                var whole: [tcp_headers_max + 301]u8 = undefined;
                const n = writeTcp(&whole, ends[0], ends[1], seg);
                var hdr: [tcp_headers_max]u8 = undefined;
                const h = tcpHeaders(&hdr, ends[0], ends[1], seg, len);
                finishTcp(hdr[0..h], &.{ first, second });
                try std.testing.expectEqualSlices(u8, whole[0..h], hdr[0..h]);
                try std.testing.expect(transportChecksumOk(parseIp(whole[0..n]).?));
            }
        }
    }
}

test "fragments and garbage are refused" {
    var buf: [64]u8 = undefined;
    const a: Endpoint = .{ .addr = v4(.{ 1, 2, 3, 4 }), .port = 1 };
    const n = writeUdp(&buf, a, a, "x");
    buf[6] = 0x20; // MF
    try std.testing.expect(parseIp(buf[0..n]) == null);
    try std.testing.expect(parseIp(&.{0x45}) == null);
    try std.testing.expect(parseIp(&.{ 0x70, 0, 0, 0 }) == null);
}

test "IPv6 packets with an IPv4-mapped address are refused" {
    var buf: [128]u8 = undefined;
    var a: Endpoint = .{ .addr = @splat(0), .port = 40000 };
    a.addr[0] = 0xfd;
    a.addr[15] = 5;
    var b = a;
    b.addr[15] = 1;
    b.port = 443;
    const n = writeTcp(&buf, a, b, .{ .seq = 10, .ack = 0, .flags = .{ .syn = true }, .window = 65535, .mss = 1460 });
    try std.testing.expect(parseIp(buf[0..n]) != null);
    // the same IPv6 header naming ::ffff:10.0.0.1 as source, then as destination
    const mapped = v4(.{ 10, 0, 0, 1 });
    var bad = buf;
    bad[8..24].* = mapped;
    try std.testing.expect(parseIp(bad[0..n]) == null);
    bad = buf;
    bad[24..40].* = mapped;
    try std.testing.expect(parseIp(bad[0..n]) == null);
}

test "endpoint formatting" {
    var buf: [64]u8 = undefined;
    const e: Endpoint = .{ .addr = v4(.{ 198, 18, 0, 1 }), .port = 53 };
    try std.testing.expectEqualStrings("198.18.0.1:53", try std.fmt.bufPrint(&buf, "{f}", .{e}));
}
