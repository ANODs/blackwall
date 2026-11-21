//! Trojan outbound: the request that opens a TCP stream or a UDP
//! association, the UDP packet framing, and the trojan:// link.
//!
//! The request is the hex SHA-224 of the password, CRLF, a command, the
//! destination as SOCKS5 writes it, CRLF. After it the stream is raw both
//! ways: the server answers with no header of its own, so a wrong password
//! only shows as the server's camouflage site answering (Xray hands what it
//! does not recognise to its fallback) or as the connection closing.
//!
//! Xray takes a connection for Trojan only if its first read holds at least
//! 58 bytes with '\r' at offset 56: the header has to open the first TLS
//! record. Like the VLESS header it should leave together with the first
//! data, or alone after a short wait so server-first protocols do not stall.
//!
//! Trojan always runs inside TLS here (ordinary TLS checked against the
//! system roots, or REALITY): over plain TCP anyone on the path could read
//! the password hash and replay it.

const std = @import("std");
const Io = std.Io;
const outbound = @import("outbound.zig");
const tls13 = @import("tls13.zig");

const Target = outbound.Target;
const Text = outbound.Text;

pub const Command = enum(u8) { connect = 1, udp = 3 };

/// Longest SOCKS5-style address: type, length, a 255-byte name, port.
pub const address_max = 1 + 1 + 255 + 2;
pub const header_max = 56 + 2 + 1 + address_max + 2;

/// Xray and trojan-go refuse UDP payloads longer than this. Xray's own
/// writer is tighter still: it builds address, length and payload in one
/// 8192-byte buffer, and a datagram that does not fit (a reply above about
/// 8170 bytes) ends the whole association instead of being dropped.
pub const udp_max_payload = 8192;

/// The credential a request starts with: hex SHA-224 of the password.
pub fn passwordKey(password: []const u8) [56]u8 {
    var digest: [28]u8 = undefined;
    std.crypto.hash.sha2.Sha224.hash(password, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// Request header for `cmd` to `t`. For a UDP association `t` is the first
/// packet's destination; every packet then names its own (`writePacket`).
pub fn requestHeader(buf: *[header_max]u8, key: *const [56]u8, cmd: Command, t: *const Target) []const u8 {
    var w: Io.Writer = .fixed(buf);
    w.writeAll(key) catch unreachable;
    w.writeAll("\r\n") catch unreachable;
    w.writeByte(@backingInt(cmd)) catch unreachable;
    writeAddress(&w, t) catch unreachable;
    w.writeAll("\r\n") catch unreachable;
    return w.buffered();
}

/// Destination as SOCKS5 writes it: 1 IPv4, 3 name, 4 IPv6, then the port.
pub fn writeAddress(w: *Io.Writer, t: *const Target) Io.Writer.Error!void {
    switch (t.kind) {
        .ip4 => try w.writeByte(1),
        .domain => try w.writeAll(&.{ 3, t.len }),
        .ip6 => try w.writeByte(4),
    }
    try w.writeAll(t.addr());
    try w.writeInt(u16, t.port, .big);
}

pub fn readAddress(r: *Io.Reader) (Io.Reader.Error || error{BadAddress})!Target {
    var t: Target = switch (try r.takeByte()) {
        1 => .{ .kind = .ip4, .len = 4, .port = 0 },
        3 => .{ .kind = .domain, .len = try r.takeByte(), .port = 0 },
        4 => .{ .kind = .ip6, .len = 16, .port = 0 },
        else => return error.BadAddress,
    };
    try r.readSliceAll(t.bytes[0..t.len]);
    t.port = try r.takeInt(u16, .big);
    return t;
}

// ---------------------------------------------------------------- UDP (command 3)

/// One datagram of a UDP association, in either direction: address, length,
/// CRLF, payload. Every packet names its peer, so one association carries
/// several destinations.
pub fn writePacket(w: *Io.Writer, to: *const Target, payload: []const u8) (Io.Writer.Error || error{PacketTooLarge})!void {
    if (payload.len > udp_max_payload) return error.PacketTooLarge;
    try writeAddress(w, to);
    try w.writeInt(u16, @intCast(payload.len), .big);
    try w.writeAll("\r\n");
    try w.writeAll(payload);
}

pub const Packet = struct {
    /// who sent it (downlink) or where it goes (uplink)
    peer: Target,
    payload: []u8,
};

/// The next datagram; its payload lands in `buf`.
pub fn readPacket(r: *Io.Reader, buf: *[udp_max_payload]u8) (Io.Reader.Error || error{ BadAddress, BadPacket })!Packet {
    const peer = try readAddress(r);
    const len = try r.takeInt(u16, .big);
    if (len > udp_max_payload) return error.BadPacket;
    if (!std.mem.eql(u8, try r.takeArray(2), "\r\n")) return error.BadPacket;
    try r.readSliceAll(buf[0..len]);
    return .{ .peer = peer, .payload = buf[0..len] };
}

// ---------------------------------------------------------------- link

/// A Trojan server as a link describes it. Slices point into the link and
/// the host passed to `fromLink`. Exactly one of `tls` and `reality` is set.
pub const Trojan = struct {
    host: []const u8,
    port: u16,
    key: [56]u8,
    reality: ?outbound.Reality = null,
    tls: ?outbound.Tls = null,
    transport: Transport = .raw,
};

/// What the TLS stream carries: Trojan itself, or a transport around it.
/// The dialer's own types: one dialer serves every protocol.
pub const Transport = outbound.Transport;
pub const Http = outbound.Http;
pub const Grpc = outbound.Grpc;
pub const Xhttp = outbound.Xhttp;

pub const LinkError = error{
    NotTrojan,
    BadPassword,
    UnsupportedTransport,
    UnsupportedSecurity,
    UnsupportedFlow,
    BadRealityKey,
};

/// What of a `trojan://password@host:port?...` link this build can carry.
/// `host` and `port` are the server's, already taken from the link.
/// Parameters as Xray's share links and v2rayN write them: security
/// (default tls), sni (or the older peer), alpn, type (tcp, ws,
/// httpupgrade, grpc, xhttp) with path, host, serviceName, authority, mode
/// and extra, and pbk / sid for REALITY. fp is ignored (the ClientHello is always Chrome's);
/// so is allowInsecure: certificates are always checked.
pub fn fromLink(link: []const u8, host: []const u8, port: u16) LinkError!Trojan {
    const prefix = "trojan://";
    if (!std.ascii.startsWithIgnoreCase(link, prefix)) return error.NotTrojan;
    const rest = link[prefix.len..];
    // The password ends at the last '@' before the query, so one written
    // without escaping its '@' or '/' still parses.
    const auth_end = std.mem.findAny(u8, rest, "?#") orelse rest.len;
    const at = std.mem.findScalarLast(u8, rest[0..auth_end], '@') orelse return error.BadPassword;
    if (at == 0) return error.BadPassword;

    var query: []const u8 = "";
    if (std.mem.findScalar(u8, rest, '?')) |q| {
        const end = std.mem.findScalarPos(u8, rest, q, '#') orelse rest.len;
        query = rest[q + 1 .. end];
    }
    var p: struct {
        security: []const u8 = "",
        sni: []const u8 = "",
        peer: []const u8 = "",
        alpn: []const u8 = "",
        type: []const u8 = "",
        header_type: []const u8 = "",
        path: []const u8 = "",
        host: []const u8 = "",
        service_name: []const u8 = "",
        authority: []const u8 = "",
        mode: []const u8 = "",
        flow: []const u8 = "",
        pbk: []const u8 = "",
        sid: []const u8 = "",
        extra: []const u8 = "",
    } = .{};
    var it = std.mem.tokenizeScalar(u8, query, '&');
    while (it.next()) |kv| {
        const eq = std.mem.findScalar(u8, kv, '=') orelse continue;
        const k = kv[0..eq];
        const v = kv[eq + 1 ..];
        const fields = .{
            .{ "security", &p.security },   .{ "sni", &p.sni },   .{ "peer", &p.peer },
            .{ "alpn", &p.alpn },           .{ "type", &p.type }, .{ "headerType", &p.header_type },
            .{ "path", &p.path },           .{ "host", &p.host }, .{ "serviceName", &p.service_name },
            .{ "authority", &p.authority }, .{ "mode", &p.mode }, .{ "flow", &p.flow },
            .{ "pbk", &p.pbk },             .{ "sid", &p.sid },   .{ "extra", &p.extra },
        };
        inline for (fields) |f| if (std.mem.eql(u8, k, f[0])) {
            f[1].* = v;
        };
    }

    var out: Trojan = .{ .host = host, .port = port, .key = encodedPasswordKey(rest[0..at]) };
    if (p.flow.len > 0) return error.UnsupportedFlow; // Vision is VLESS only

    const is = struct {
        fn is(a: []const u8, b: []const u8) bool {
            return std.ascii.eqlIgnoreCase(a, b);
        }
    }.is;
    if (p.type.len == 0 or is(p.type, "tcp") or is(p.type, "raw")) {
        // the HTTP/1.1 disguise of raw TCP is not carried
        if (p.header_type.len > 0 and !is(p.header_type, "none")) return error.UnsupportedTransport;
        out.transport = .raw;
    } else if (is(p.type, "ws") or is(p.type, "httpupgrade")) {
        var h: Http = .{};
        if (!setDecoded(&h.path, if (p.path.len > 0) p.path else "/")) return error.UnsupportedTransport;
        if (h.path.len == 0 or h.path.buf[0] != '/') return error.UnsupportedTransport;
        const name = if (p.host.len > 0) p.host else if (p.sni.len > 0) p.sni else host;
        if (!setDecoded(&h.host, name)) return error.UnsupportedTransport;
        out.transport = if (is(p.type, "ws")) .{ .ws = h } else .{ .httpupgrade = h };
    } else if (is(p.type, "grpc")) {
        var g: Grpc = .{};
        if (!setDecoded(&g.service_name, p.service_name)) return error.UnsupportedTransport;
        if (!setDecoded(&g.authority, p.authority)) return error.UnsupportedTransport;
        if (p.mode.len > 0 and !is(p.mode, "gun") and !is(p.mode, "multi")) return error.UnsupportedTransport;
        g.multi = is(p.mode, "multi");
        out.transport = .{ .grpc = g };
    } else if (is(p.type, "xhttp") or is(p.type, "splithttp")) {
        // which modes and extras can be carried is the dialer's to say
        var x: Xhttp = .{};
        if (!setDecoded(&x.path, p.path) or !setDecoded(&x.mode, p.mode) or !setDecoded(&x.extra, p.extra)) return error.UnsupportedTransport;
        const name = if (p.host.len > 0) p.host else if (p.sni.len > 0) p.sni else host;
        if (!setDecoded(&x.host, name)) return error.UnsupportedTransport;
        out.transport = .{ .xhttp = x };
    } else return error.UnsupportedTransport;

    const sni = if (p.sni.len > 0) p.sni else p.peer;
    if (p.security.len == 0 or is(p.security, "tls")) {
        var t: outbound.Tls = .{};
        // the certificate is checked against this name: sni, else the Host
        // a CDN routes by, else the address
        const name = if (sni.len > 0) sni else if (p.host.len > 0) p.host else host;
        if (!setDecoded(&t.server_name, name)) return error.UnsupportedSecurity;
        const has_h2 = std.mem.find(u8, p.alpn, "h2") != null;
        const has_h11 = std.mem.find(u8, p.alpn, "http") != null;
        t.alpn = switch (out.transport) {
            // WebSocket and HTTPUpgrade need HTTP/1.1; gRPC and XHTTP run on HTTP/2
            .ws, .httpupgrade => .http11,
            .grpc, .xhttp => .h2,
            .raw => if (has_h11 and !has_h2) .http11 else if (has_h2 and !has_h11) .h2 else .h2_http11,
        };
        out.tls = t;
    } else if (is(p.security, "reality")) {
        out.reality = .{
            .server_name = if (sni.len > 0) sni else host,
            .public_key = decodeKey(p.pbk) orelse return error.BadRealityKey,
            .short_id = decodeShortId(p.sid) orelse return error.BadRealityKey,
        };
    } else return error.UnsupportedSecurity; // "none" included: see the top
    return out;
}

/// SHA-224 of the percent-decoded password, decoded on the fly.
fn encodedPasswordKey(raw: []const u8) [56]u8 {
    var h: std.crypto.hash.sha2.Sha224 = .init(.{});
    var i: usize = 0;
    while (i < raw.len) {
        const b, const n = decodedAt(raw, i);
        h.update(&.{b});
        i += n;
    }
    return std.fmt.bytesToHex(h.finalResult(), .lower);
}

/// The byte at `raw[i]` after percent-decoding, and how many bytes it took.
/// A '%' not followed by two hex digits stands for itself, as in links.
fn decodedAt(raw: []const u8, i: usize) struct { u8, usize } {
    if (raw[i] == '%' and i + 2 < raw.len) {
        if (std.fmt.parseInt(u8, raw[i + 1 .. i + 3], 16)) |b| return .{ b, 3 } else |_| {}
    }
    return .{ raw[i], 1 };
}

/// Percent-decoded into a outbound.Text; false if it does not fit.
fn setDecoded(t: anytype, raw: []const u8) bool {
    var n: usize = 0;
    var i: usize = 0;
    while (i < raw.len) : (n += 1) {
        if (n == t.buf.len) return false;
        const b, const k = decodedAt(raw, i);
        t.buf[n] = b;
        i += k;
    }
    t.len = @intCast(n);
    return true;
}

/// X25519 public key as links write it: base64, URL alphabet, unpadded
/// (standard alphabet and padding tolerated).
fn decodeKey(text: []const u8) ?[32]u8 {
    var clean: [64]u8 = undefined;
    var n: usize = 0;
    for (text) |c| {
        if (c == '=') continue;
        if (n == clean.len) return null;
        clean[n] = switch (c) {
            '+' => '-',
            '/' => '_',
            else => c,
        };
        n += 1;
    }
    const dec = std.base64.url_safe_no_pad.Decoder;
    if ((dec.calcSizeForSlice(clean[0..n]) catch return null) != 32) return null;
    var key: [32]u8 = undefined;
    dec.decode(&key, clean[0..n]) catch return null;
    return key;
}

fn decodeShortId(text: []const u8) ?[8]u8 {
    var id: [8]u8 = @splat(0);
    if (text.len > 16 or text.len % 2 != 0) return null;
    _ = std.fmt.hexToBytes(id[0 .. text.len / 2], text) catch return null;
    return id;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "password key is hex SHA-224" {
    // FIPS 180-4 examples
    try testing.expectEqualStrings("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", &passwordKey(""));
    try testing.expectEqualStrings("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", &passwordKey("abc"));
    // a link escapes what a userinfo cannot hold
    try testing.expectEqualSlices(u8, &passwordKey("p@ss:w/rd%"), &encodedPasswordKey("p%40ss%3Aw%2Frd%"));
}

test "request header layout" {
    const key = passwordKey("secret");
    var buf: [header_max]u8 = undefined;
    const name = Target.fromDomain("example.com", 80);
    const h = requestHeader(&buf, &key, .connect, &name);
    try testing.expectEqual(56 + 2 + 1 + 1 + 1 + 11 + 2 + 2, h.len);
    try testing.expectEqualSlices(u8, &key, h[0..56]);
    try testing.expectEqualSlices(u8, "\r\n\x01\x03\x0bexample.com\x00\x50\r\n", h[56..]);

    var v4: Target = .{ .kind = .ip4, .len = 4, .port = 443 };
    v4.bytes[0..4].* = .{ 1, 2, 3, 4 };
    try testing.expectEqualSlices(u8, "\x03\x01\x01\x02\x03\x04\x01\xbb\r\n", requestHeader(&buf, &key, .udp, &v4)[58..]);

    var v6: Target = .{ .kind = .ip6, .len = 16, .port = 53 };
    v6.bytes[0..16].* = @splat(0xfe);
    const h6 = requestHeader(&buf, &key, .connect, &v6);
    try testing.expectEqual(header_max - address_max + 1 + 16 + 2, h6.len);
    try testing.expectEqual(4, h6[59]);

    // the longest name fits
    var long: [255]u8 = @splat('a');
    const lt = Target.fromDomain(&long, 1);
    try testing.expectEqual(header_max, requestHeader(&buf, &key, .connect, &lt).len);
}

test "udp packets round trip and match Xray's framing" {
    var buf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    var dns: Target = .{ .kind = .ip4, .len = 4, .port = 53 };
    dns.bytes[0..4].* = .{ 8, 8, 4, 4 };
    try writePacket(&w, &dns, "query");
    try writePacket(&w, &Target.fromDomain("example.com", 443), "");
    try testing.expectEqualSlices(u8, "\x01\x08\x08\x04\x04\x00\x35\x00\x05\r\nquery", w.buffered()[0..16]);

    var r: Io.Reader = .fixed(w.buffered());
    var payload: [udp_max_payload]u8 = undefined;
    const a = try readPacket(&r, &payload);
    try testing.expectEqual(.ip4, a.peer.kind);
    try testing.expectEqual(53, a.peer.port);
    try testing.expectEqualStrings("query", a.payload);
    const b = try readPacket(&r, &payload);
    try testing.expectEqualStrings("example.com", b.peer.addr());
    try testing.expectEqual(0, b.payload.len);
    try testing.expectError(error.EndOfStream, readPacket(&r, &payload));

    const big: [udp_max_payload + 1]u8 = @splat(0);
    try testing.expectError(error.PacketTooLarge, writePacket(&w, &dns, &big));
    var bad: Io.Reader = .fixed("\x01\x08\x08\x04\x04\x00\x35\x20\x01\r\n");
    try testing.expectError(error.BadPacket, readPacket(&bad, &payload));
    var no_crlf: Io.Reader = .fixed("\x01\x08\x08\x04\x04\x00\x35\x00\x01xxy");
    try testing.expectError(error.BadPacket, readPacket(&no_crlf, &payload));
    var bad_type: Io.Reader = .fixed("\x02\x08\x08\x04\x04\x00\x35\x00\x01\r\ny");
    try testing.expectError(error.BadAddress, readPacket(&bad_type, &payload));
}

test "trojan links" {
    // plain: TLS by default, the certificate name is the address
    const plain = try fromLink("trojan://secret@h.example:443#name", "h.example", 443);
    try testing.expectEqualSlices(u8, &passwordKey("secret"), &plain.key);
    try testing.expectEqualStrings("h.example", plain.tls.?.server_name.slice());
    try testing.expectEqual(tls13.Alpn.h2_http11, plain.tls.?.alpn);
    try testing.expect(plain.reality == null and plain.transport == .raw);

    // escaped password, sni, alpn narrowed, the extras Xray writes ignored
    const tcp = try fromLink("trojan://p%40ss%23w@1.2.3.4:8443?security=tls&sni=s.example&alpn=http%2F1.1&fp=chrome&type=tcp&headerType=none&allowInsecure=0#x", "1.2.3.4", 8443);
    try testing.expectEqualSlices(u8, &passwordKey("p@ss#w"), &tcp.key);
    try testing.expectEqualStrings("s.example", tcp.tls.?.server_name.slice());
    try testing.expectEqual(tls13.Alpn.http11, tcp.tls.?.alpn);
    // the older trojan-go spelling of the server name
    const peer = try fromLink("trojan://pw@1.2.3.4:443?peer=old.example", "1.2.3.4", 443);
    try testing.expectEqualStrings("old.example", peer.tls.?.server_name.slice());
    // a raw '@' in the password: the last one before the query separates
    const raw_at = try fromLink("trojan://a@b@h:1?security=tls", "h", 1);
    try testing.expectEqualSlices(u8, &passwordKey("a@b"), &raw_at.key);

    // WebSocket behind a CDN: Host and path as given, HTTP/1.1 only
    const cdn = try fromLink("trojan://pw@104.16.1.1:443?type=ws&security=tls&host=cdn.example&sni=edge.example&path=%2Ftj%3Fed%3D2048#y", "104.16.1.1", 443);
    try testing.expectEqualStrings("/tj?ed=2048", cdn.transport.ws.path.slice());
    try testing.expectEqualStrings("cdn.example", cdn.transport.ws.host.slice());
    try testing.expectEqualStrings("edge.example", cdn.tls.?.server_name.slice());
    try testing.expectEqual(tls13.Alpn.http11, cdn.tls.?.alpn);
    const hu = try fromLink("trojan://pw@h:443?type=httpupgrade&host=u.example", "h", 443);
    try testing.expectEqualStrings("/", hu.transport.httpupgrade.path.slice());
    try testing.expectEqualStrings("u.example", hu.tls.?.server_name.slice());

    // gRPC: HTTP/2 whatever the link says
    const grpc = try fromLink("trojan://pw@h:443?type=grpc&serviceName=tun%2Fsub&mode=multi&authority=a.example&alpn=http%2F1.1&sni=g.example", "h", 443);
    try testing.expectEqualStrings("tun/sub", grpc.transport.grpc.service_name.slice());
    try testing.expectEqualStrings("a.example", grpc.transport.grpc.authority.slice());
    try testing.expect(grpc.transport.grpc.multi);
    try testing.expectEqual(tls13.Alpn.h2, grpc.tls.?.alpn);
    try testing.expect(!(try fromLink("trojan://pw@h:443?type=grpc&serviceName=x", "h", 443)).transport.grpc.multi);

    // REALITY
    const re = try fromLink("trojan://pw@h:443?security=reality&sni=www.example.com&pbk=jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8&sid=ab12&fp=chrome", "h", 443);
    try testing.expect(re.tls == null);
    try testing.expectEqualStrings("www.example.com", re.reality.?.server_name);
    try testing.expectEqual(0x8c, re.reality.?.public_key[0]);
    try testing.expectEqualSlices(u8, &.{ 0xab, 0x12, 0, 0, 0, 0, 0, 0 }, &re.reality.?.short_id);

    try testing.expectError(error.NotTrojan, fromLink("vless://pw@h:1", "h", 1));
    try testing.expectError(error.BadPassword, fromLink("trojan://@h:1", "h", 1));
    try testing.expectError(error.BadPassword, fromLink("trojan://h:1?sni=a@b", "h", 1));
    try testing.expectError(error.UnsupportedSecurity, fromLink("trojan://pw@h:1?security=none", "h", 1));
    try testing.expectError(error.UnsupportedSecurity, fromLink("trojan://pw@h:1?security=xtls", "h", 1));
    try testing.expectError(error.UnsupportedFlow, fromLink("trojan://pw@h:1?flow=xtls-rprx-vision", "h", 1));
    // XHTTP: HTTP/2, the Host from sni when the link names none
    const xh = try fromLink("trojan://pw@h:443?type=xhttp&path=%2Fx&mode=stream-one&sni=x.example&extra=%7B%22a%22%3A1%7D", "h", 443);
    try testing.expectEqualStrings("/x", xh.transport.xhttp.path.slice());
    try testing.expectEqualStrings("stream-one", xh.transport.xhttp.mode.slice());
    try testing.expectEqualStrings("x.example", xh.transport.xhttp.host.slice());
    try testing.expectEqualStrings("{\"a\":1}", xh.transport.xhttp.extra.slice());
    try testing.expectEqual(tls13.Alpn.h2, xh.tls.?.alpn);
    try testing.expectError(error.UnsupportedTransport, fromLink("trojan://pw@h:1?type=kcp", "h", 1));
    try testing.expectError(error.UnsupportedTransport, fromLink("trojan://pw@h:1?type=tcp&headerType=http", "h", 1));
    try testing.expectError(error.UnsupportedTransport, fromLink("trojan://pw@h:1?type=grpc&mode=tun", "h", 1));
    try testing.expectError(error.UnsupportedTransport, fromLink("trojan://pw@h:1?type=ws&path=nope", "h", 1));
    try testing.expectError(error.BadRealityKey, fromLink("trojan://pw@h:1?security=reality&pbk=short", "h", 1));
}
