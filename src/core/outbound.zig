//! What a server is: the outbound a share link describes, with its
//! security (REALITY, TLS, none) and transport (raw, WebSocket, HTTPUpgrade,
//! gRPC, XHTTP), and the destination of a flow. No I/O here: proxy.zig
//! dials these, and the protocol files (trojan.zig, vmess.zig,
//! shadowsocks.zig) take their shared pieces from here.

const std = @import("std");
const tls13 = @import("tls13.zig");
const xhttp = @import("xhttp.zig");
const trojan = @import("trojan.zig");
const shadowsocks = @import("shadowsocks.zig");
const vmess = @import("vmess.zig");
const packet = @import("ipstack/packet.zig");

pub const Reality = struct {
    server_name: []const u8,
    public_key: [32]u8,
    short_id: [8]u8 = @splat(0),
};

/// A short string kept inside the struct, so outbounds copy by value.
pub fn Text(comptime cap: usize) type {
    return struct {
        buf: [cap]u8 = undefined,
        len: std.math.IntFittingRange(0, cap) = 0,

        const Self = @This();

        pub fn slice(t: *const Self) []const u8 {
            return t.buf[0..t.len];
        }

        /// Percent-decoded (as link parameters are); false if it does not fit.
        pub fn setDecoded(t: *Self, raw: []const u8) bool {
            var n: usize = 0;
            var i: usize = 0;
            while (i < raw.len) : (n += 1) {
                if (n == cap) return false;
                if (raw[i] == '%' and i + 2 < raw.len) {
                    if (std.fmt.parseInt(u8, raw[i + 1 .. i + 3], 16)) |b| {
                        t.buf[n] = b;
                        i += 3;
                        continue;
                    } else |_| {}
                }
                t.buf[n] = raw[i];
                i += 1;
            }
            t.len = @intCast(n);
            return true;
        }
    };
}

/// Ordinary TLS around the transport (security=tls).
pub const Tls = struct {
    server_name: Text(255) = .{},
    alpn: tls13.Alpn = .h2_http11,
};

/// An HTTP/1.1 upgrade: WebSocket and HTTPUpgrade ask for the same things.
pub const Http = struct {
    path: Text(512) = .{},
    /// Host header; a CDN routes by it
    host: Text(255) = .{},
};

pub const Grpc = struct {
    service_name: Text(255) = .{},
    /// :authority, when the link names one
    authority: Text(255) = .{},
    /// mode=multi (TunMulti), else "gun"
    multi: bool = false,
};

pub const Xhttp = struct {
    path: Text(512) = .{},
    /// :authority; a CDN routes by it
    host: Text(255) = .{},
    /// empty, auto, stream-one, stream-up or packet-up, as the link has it
    mode: Text(16) = .{},
    /// The link's `extra`, decoded: a JSON object of more settings. Kept by
    /// value like the rest, so one that does not fit is not carried.
    extra: Text(1024) = .{},
};

/// What the (TLS) stream carries: the protocol itself, or a transport with
/// the protocol inside. The same for every protocol.
pub const Transport = union(enum) {
    raw,
    /// WebSocket binary frames
    ws: Http,
    /// WebSocket's upgrade without its framing
    httpupgrade: Http,
    /// one gRPC call over HTTP/2
    grpc: Grpc,
    /// one HTTP/2 POST, the bodies being the two directions (stream-one)
    xhttp: Xhttp,
};

pub const Vless = struct {
    host: []const u8,
    port: u16,
    uuid: [16]u8,
    /// flow xtls-rprx-vision
    vision: bool = false,
    reality: ?Reality = null,
    tls: ?Tls = null,
    transport: Transport = .raw,
};

const raw_transport: Transport = .raw;

/// How the connection to a server is built, whatever protocol speaks on it.
pub const Via = struct {
    host: []const u8,
    port: u16,
    reality: ?Reality = null,
    tls: ?*const Tls = null,
    transport: *const Transport = &raw_transport,
};

pub const Outbound = union(enum) {
    direct,
    block,
    /// direct, with the first bytes shaped past DPI (dpi.zig)
    dpi,
    vless: Vless,
    trojan: trojan.Trojan,
    shadowsocks: shadowsocks.Shadowsocks,
    vmess: vmess.Vmess,

    /// Null for the outbounds that use no server.
    pub fn via(o: *const Outbound) ?Via {
        return switch (o.*) {
            .direct, .block, .dpi => null,
            .shadowsocks => |*s| .{ .host = s.host, .port = s.port },
            inline .vless, .trojan, .vmess => |*s| .{
                .host = s.host,
                .port = s.port,
                .reality = s.reality,
                .tls = if (s.tls) |*t| t else null,
                .transport = &s.transport,
            },
        };
    }

    /// The server's address, for the outbounds that have one.
    pub fn host(o: *const Outbound) ?[]const u8 {
        return if (o.via()) |v| v.host else null;
    }

    /// The same server: address, port and account (not how it is reached).
    pub fn sameServer(a: *const Outbound, b: *const Outbound) bool {
        if (std.meta.activeTag(a.*) != std.meta.activeTag(b.*)) return false;
        const va = a.via() orelse return true;
        const vb = b.via().?;
        if (va.port != vb.port or !std.mem.eql(u8, va.host, vb.host)) return false;
        return switch (a.*) {
            .direct, .block, .dpi => true,
            .vless => |*v| std.mem.eql(u8, &v.uuid, &b.vless.uuid),
            .trojan => |*t| std.mem.eql(u8, &t.key, &b.trojan.key),
            .shadowsocks => |*s| s.method == b.shadowsocks.method and std.mem.eql(u8, &s.key, &b.shadowsocks.key),
            .vmess => |*v| std.mem.eql(u8, &v.user.cmd_key, &b.vmess.user.cmd_key),
        };
    }

    /// The strings an outbound points to rather than holds.
    fn strings(o: *Outbound) ?struct { host: *[]const u8, sni: ?*[]const u8 } {
        switch (o.*) {
            .direct, .block, .dpi => return null,
            inline else => |*s| {
                const has_reality = comptime @hasField(@TypeOf(s.*), "reality");
                return .{
                    .host = &s.host,
                    .sni = if (has_reality) (if (s.reality) |*re| &re.server_name else null) else null,
                };
            },
        }
    }

    /// A copy whose strings are allocated from `a`.
    pub fn dupe(o: Outbound, a: std.mem.Allocator) std.mem.Allocator.Error!Outbound {
        var out = o;
        if (out.strings()) |s| {
            s.host.* = try a.dupe(u8, s.host.*);
            if (s.sni) |sni| sni.* = try a.dupe(u8, sni.*);
        }
        return out;
    }
};

pub const LinkError = error{
    /// not a link of a protocol this build speaks
    UnsupportedProtocol,
    /// the link does not parse (a vmess:// body, an ss:// userinfo)
    BadLink,
    /// VLESS, VMess: the id is no UUID
    BadUuid,
    /// Trojan, Shadowsocks: no password, or a 2022 key of the wrong length
    BadPassword,
    /// Shadowsocks: a cipher that is not carried
    UnsupportedMethod,
    /// Shadowsocks: SIP003 plugins are separate programs
    UnsupportedPlugin,
    UnsupportedTransport,
    UnsupportedSecurity,
    UnsupportedFlow,
    BadRealityKey,
};

/// What of a share link this build can actually carry: vless://, trojan://,
/// ss:// or vmess://. `host` and `port` are the server's, already taken from
/// the link (sublink.zig); slices in the result point into `link` and `host`.
/// Whether this build can carry a server (model.Server): a group when it
/// can carry any of its servers.
pub fn carries(sv: anytype) bool {
    if (sv.members.len == 0) return if (outboundFromLink(sv.link, sv.host, sv.port)) |_| true else |_| false;
    for (sv.members) |m| {
        if (outboundFromLink(m.link, m.host, m.port)) |_| return true else |_| {}
    }
    return false;
}

pub fn outboundFromLink(link: []const u8, host: []const u8, port: u16) LinkError!Outbound {
    const scheme = link[0 .. std.mem.indexOf(u8, link, "://") orelse return error.UnsupportedProtocol];
    const is = std.ascii.eqlIgnoreCase;
    const ob: Outbound = if (is(scheme, "vless"))
        .{ .vless = try vlessFromLink(link, host, port) }
    else if (is(scheme, "trojan"))
        .{ .trojan = trojan.fromLink(link, host, port) catch |err| return switch (err) {
            error.NotTrojan => error.UnsupportedProtocol,
            else => |e| e,
        } }
    else if (is(scheme, "ss"))
        .{ .shadowsocks = shadowsocks.fromLink(link, host, port) catch |err| return switch (err) {
            error.NotShadowsocks => error.UnsupportedProtocol,
            error.BadUserInfo => error.BadLink,
            else => |e| e,
        } }
    else if (is(scheme, "vmess"))
        .{ .vmess = vmess.fromLink(link, host, port) catch |err| return switch (err) {
            error.NotVmess => error.UnsupportedProtocol,
            error.BadId => error.BadUuid,
            else => |e| e,
        } }
    else
        return error.UnsupportedProtocol;

    // XHTTP: only what Xray's own client would send as stream-one (so "auto"
    // only inside REALITY), and settings in `extra` it would itself take
    const v = ob.via().?;
    switch (v.transport.*) {
        .xhttp => |*x| xhttp.check(xhttpOptions(x, &v)) catch return error.UnsupportedTransport,
        else => {},
    }
    return ob;
}

pub fn xhttpOptions(x: *const Xhttp, v: *const Via) xhttp.Options {
    return .{
        .path = x.path.slice(),
        .host = x.host.slice(),
        .mode = x.mode.slice(),
        .extra = x.extra.slice(),
        .reality = v.reality != null,
    };
}

/// What of a `vless://` link this build can carry. Parameters as Xray's
/// share links write them: security (none, tls, reality) with sni, alpn, pbk
/// and sid; type (tcp, ws, httpupgrade, grpc, xhttp) with path, host,
/// serviceName, authority, mode and extra; flow. fp is ignored (the
/// ClientHello is always Chrome's), so is allowInsecure: certificates are
/// always checked.
pub fn vlessFromLink(link: []const u8, host: []const u8, port: u16) LinkError!Vless {
    const prefix = "vless://";
    if (!std.ascii.startsWithIgnoreCase(link, prefix)) return error.UnsupportedProtocol;
    const rest = link[prefix.len..];
    const at = std.mem.indexOfScalar(u8, rest, '@') orelse return error.BadUuid;
    const uuid = parseUuid(rest[0..at]) orelse return error.BadUuid;

    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, '?')) |q| {
        const end = std.mem.indexOfScalarPos(u8, rest, q, '#') orelse rest.len;
        query = rest[q + 1 .. end];
    }
    var p: struct {
        security: []const u8 = "",
        encryption: []const u8 = "",
        type: []const u8 = "",
        header_type: []const u8 = "",
        flow: []const u8 = "",
        sni: []const u8 = "",
        pbk: []const u8 = "",
        sid: []const u8 = "",
        path: []const u8 = "",
        host: []const u8 = "",
        alpn: []const u8 = "",
        service_name: []const u8 = "",
        authority: []const u8 = "",
        mode: []const u8 = "",
        extra: []const u8 = "",
    } = .{};
    var it = std.mem.tokenizeScalar(u8, query, '&');
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        const fields = .{
            .{ "security", &p.security },      .{ "encryption", &p.encryption }, .{ "type", &p.type },
            .{ "headerType", &p.header_type }, .{ "flow", &p.flow },             .{ "sni", &p.sni },
            .{ "pbk", &p.pbk },                .{ "sid", &p.sid },               .{ "path", &p.path },
            .{ "host", &p.host },              .{ "alpn", &p.alpn },             .{ "serviceName", &p.service_name },
            .{ "authority", &p.authority },    .{ "mode", &p.mode },             .{ "extra", &p.extra },
        };
        inline for (fields) |f| if (std.mem.eql(u8, kv[0..eq], f[0])) {
            f[1].* = kv[eq + 1 ..];
        };
    }
    const is = std.ascii.eqlIgnoreCase;

    // VLESS's own encryption layer (ML-KEM) is not spoken
    if (p.encryption.len > 0 and !is(p.encryption, "none")) return error.UnsupportedSecurity;

    var out: Vless = .{ .host = host, .port = port, .uuid = uuid };
    // the Host a CDN routes by: as the link says, else its sni, else the address
    const route_host = if (p.host.len > 0) p.host else if (p.sni.len > 0) p.sni else host;
    if (p.type.len == 0 or is(p.type, "tcp") or is(p.type, "raw")) {
        // the HTTP/1.1 disguise of raw TCP is not carried
        if (p.header_type.len > 0 and !is(p.header_type, "none")) return error.UnsupportedTransport;
    } else if (is(p.type, "ws") or is(p.type, "httpupgrade")) {
        var h: Http = .{};
        if (!h.path.setDecoded(if (p.path.len > 0) p.path else "/")) return error.UnsupportedTransport;
        if (h.path.len == 0 or h.path.buf[0] != '/') return error.UnsupportedTransport;
        if (!h.host.setDecoded(route_host)) return error.UnsupportedTransport;
        out.transport = if (is(p.type, "ws")) .{ .ws = h } else .{ .httpupgrade = h };
    } else if (is(p.type, "grpc")) {
        var g: Grpc = .{};
        if (!g.service_name.setDecoded(p.service_name) or !g.authority.setDecoded(p.authority)) return error.UnsupportedTransport;
        if (p.mode.len > 0 and !is(p.mode, "gun") and !is(p.mode, "multi")) return error.UnsupportedTransport;
        g.multi = is(p.mode, "multi");
        out.transport = .{ .grpc = g };
    } else if (is(p.type, "xhttp") or is(p.type, "splithttp")) {
        var x: Xhttp = .{};
        if (!x.path.setDecoded(p.path) or !x.mode.setDecoded(p.mode) or !x.extra.setDecoded(p.extra)) return error.UnsupportedTransport;
        if (!x.host.setDecoded(route_host)) return error.UnsupportedTransport;
        out.transport = .{ .xhttp = x };
    } else return error.UnsupportedTransport;

    if (p.flow.len > 0) {
        if (!std.mem.startsWith(u8, p.flow, "xtls-rprx-vision")) return error.UnsupportedFlow;
        // Vision splices raw TCP; it has no place inside a transport
        if (out.transport != .raw) return error.UnsupportedFlow;
        out.vision = true;
    }
    if (p.security.len == 0 or is(p.security, "none")) {
        if (out.vision) return error.UnsupportedFlow; // Vision rides on an outer TLS layer
    } else if (is(p.security, "reality")) {
        out.reality = .{
            .server_name = if (p.sni.len > 0) p.sni else host,
            .public_key = decodeKey(p.pbk) orelse return error.BadRealityKey,
            .short_id = decodeShortId(p.sid) orelse return error.BadRealityKey,
        };
    } else if (is(p.security, "tls")) {
        if (out.vision) return error.UnsupportedFlow; // Vision over plain TLS: not carried
        var t: Tls = .{};
        // the certificate is checked against this name: sni, else the Host
        // the CDN routes by, else the address
        const name = if (p.sni.len > 0) p.sni else if (p.host.len > 0) p.host else host;
        if (!t.server_name.setDecoded(name)) return error.UnsupportedSecurity;
        const has_h2 = std.mem.indexOf(u8, p.alpn, "h2") != null;
        const has_h11 = std.mem.indexOf(u8, p.alpn, "http") != null;
        t.alpn = switch (out.transport) {
            // WebSocket and HTTPUpgrade need HTTP/1.1; gRPC and XHTTP run on HTTP/2
            .ws, .httpupgrade => .http11,
            .grpc, .xhttp => .h2,
            // a link may narrow the offer
            .raw => if (has_h11 and !has_h2) .http11 else if (has_h2 and !has_h11) .h2 else .h2_http11,
        };
        out.tls = t;
    } else return error.UnsupportedSecurity;
    return out;
}

pub fn parseUuid(text: []const u8) ?[16]u8 {
    var out: [16]u8 = undefined;
    var n: usize = 0;
    var hi: ?u8 = null;
    for (text) |c| {
        if (c == '-') continue;
        const d = std.fmt.charToDigit(c, 16) catch return null;
        if (hi) |h| {
            if (n == 16) return null;
            out[n] = h << 4 | d;
            n += 1;
            hi = null;
        } else hi = d;
    }
    return if (n == 16 and hi == null) out else null;
}

/// X25519 public key as written in links: base64, URL alphabet, unpadded
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
    const size = dec.calcSizeForSlice(clean[0..n]) catch return null;
    if (size != 32) return null;
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

pub const Target = struct {
    kind: enum { ip4, ip6, domain },
    bytes: [255]u8 = undefined,
    len: u8,
    port: u16,

    pub fn addr(t: *const Target) []const u8 {
        return t.bytes[0..t.len];
    }

    pub fn fromEndpoint(e: packet.Endpoint) Target {
        var t: Target = undefined;
        if (packet.isV4(&e.addr)) {
            t = .{ .kind = .ip4, .len = 4, .port = e.port };
            @memcpy(t.bytes[0..4], e.addr[12..16]);
        } else {
            t = .{ .kind = .ip6, .len = 16, .port = e.port };
            @memcpy(t.bytes[0..16], &e.addr);
        }
        return t;
    }

    pub fn fromDomain(name: []const u8, port: u16) Target {
        var t: Target = .{ .kind = .domain, .len = @intCast(@min(name.len, 255)), .port = port };
        @memcpy(t.bytes[0..t.len], name[0..t.len]);
        return t;
    }
};

/// An outbound with its strings copied in, safe to pass to another thread
/// and to keep after the configuration it came from is gone.
pub const Snapshot = struct {
    outbound: Outbound,
    host: [255]u8 = undefined,
    host_len: u8 = 0,
    sni: [255]u8 = undefined,
    sni_len: u8 = 0,

    pub fn of(o: Outbound) Snapshot {
        var s: Snapshot = .{ .outbound = o };
        if (s.outbound.strings()) |p| {
            s.host_len = @intCast(@min(p.host.len, s.host.len));
            @memcpy(s.host[0..s.host_len], p.host.*[0..s.host_len]);
            if (p.sni) |sni| {
                s.sni_len = @intCast(@min(sni.len, s.sni.len));
                @memcpy(s.sni[0..s.sni_len], sni.*[0..s.sni_len]);
            }
        }
        return s;
    }

    /// The outbound with its strings pointing into this snapshot.
    pub fn get(s: *const Snapshot) Outbound {
        var o = s.outbound;
        if (o.strings()) |p| {
            p.host.* = s.host[0..s.host_len];
            if (p.sni) |sni| sni.* = s.sni[0..s.sni_len];
        }
        return o;
    }
};

test "uuid and link capability" {
    const u = parseUuid("11111111-2222-3333-4444-555555555555").?;
    try std.testing.expectEqual(0x11, u[0]);
    try std.testing.expectEqual(0x55, u[15]);
    try std.testing.expect(parseUuid("1111") == null);

    const plain = try vlessFromLink("vless://11111111-2222-3333-4444-555555555555@h:1?type=tcp&security=none#x", "h", 1);
    try std.testing.expect(plain.reality == null and !plain.vision);

    const re = try vlessFromLink(
        "vless://11111111-2222-3333-4444-555555555555@h:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.example.com&fp=chrome&pbk=jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8&sid=ab12#x",
        "h",
        443,
    );
    try std.testing.expect(re.vision);
    try std.testing.expectEqualStrings("www.example.com", re.reality.?.server_name);
    try std.testing.expectEqual(0x8c, re.reality.?.public_key[0]);
    try std.testing.expectEqualSlices(u8, &.{ 0xab, 0x12, 0, 0, 0, 0, 0, 0 }, &re.reality.?.short_id);

    try std.testing.expectError(error.BadRealityKey, vlessFromLink("vless://11111111-2222-3333-4444-555555555555@h:1?security=reality&pbk=short", "h", 1));
    try std.testing.expectError(error.UnsupportedSecurity, vlessFromLink("vless://11111111-2222-3333-4444-555555555555@h:1?security=xtls", "h", 1));
    try std.testing.expectError(error.UnsupportedTransport, vlessFromLink("vless://11111111-2222-3333-4444-555555555555@h:1?type=kcp", "h", 1));
    try std.testing.expectError(error.UnsupportedTransport, vlessFromLink("vless://11111111-2222-3333-4444-555555555555@h:1?type=tcp&headerType=http", "h", 1));
    // VLESS's own encryption is not spoken: better refused than sent in the clear
    try std.testing.expectError(error.UnsupportedSecurity, vlessFromLink("vless://11111111-2222-3333-4444-555555555555@h:1?encryption=mlkem768x25519plus.native.0rtt.abc", "h", 1));

    // WebSocket inside TLS behind a CDN: SNI, Host and path as the link says
    const cdn = try vlessFromLink("vless://11111111-2222-3333-4444-555555555555@104.16.1.1:443?type=ws&security=tls&encryption=none&alpn=http%2F1.1&host=cdn.example&sni=edge.example&path=%2Fstream%2Fx%3Fed%3D2048&fp=chrome#y", "104.16.1.1", 443);
    try std.testing.expectEqualStrings("edge.example", cdn.tls.?.server_name.slice());
    try std.testing.expectEqual(tls13.Alpn.http11, cdn.tls.?.alpn);
    try std.testing.expectEqualStrings("/stream/x?ed=2048", cdn.transport.ws.path.slice());
    try std.testing.expectEqualStrings("cdn.example", cdn.transport.ws.host.slice());
    // defaults: path "/", the Host and the certificate name from sni
    const bare = try vlessFromLink("vless://11111111-2222-3333-4444-555555555555@h:443?type=ws&security=tls&sni=s.example", "h", 443);
    try std.testing.expectEqualStrings("/", bare.transport.ws.path.slice());
    try std.testing.expectEqualStrings("s.example", bare.transport.ws.host.slice());
    try std.testing.expectError(error.UnsupportedFlow, vlessFromLink("vless://11111111-2222-3333-4444-555555555555@h:443?type=ws&security=tls&flow=xtls-rprx-vision", "h", 443));
    try std.testing.expectError(error.UnsupportedFlow, vlessFromLink("vless://11111111-2222-3333-4444-555555555555@h:1?flow=xtls-rprx-vision", "h", 1));
    try std.testing.expectError(error.UnsupportedProtocol, vlessFromLink("trojan://p@h:1", "h", 1));

    // HTTPUpgrade: WebSocket's parameters and HTTP/1.1
    const hu = try vlessFromLink("vless://11111111-2222-3333-4444-555555555555@h:443?type=httpupgrade&security=tls&host=u.example&path=%2Fup%3Fed%3D2048", "h", 443);
    try std.testing.expectEqualStrings("/up?ed=2048", hu.transport.httpupgrade.path.slice());
    try std.testing.expectEqualStrings("u.example", hu.transport.httpupgrade.host.slice());
    try std.testing.expectEqual(tls13.Alpn.http11, hu.tls.?.alpn);
    // gRPC and XHTTP: HTTP/2, whatever the link's alpn says
    const g = try vlessFromLink("vless://11111111-2222-3333-4444-555555555555@h:443?type=grpc&security=tls&serviceName=tun%2Fsub&mode=multi&authority=a.example&alpn=http%2F1.1&sni=g.example", "h", 443);
    try std.testing.expectEqualStrings("tun/sub", g.transport.grpc.service_name.slice());
    try std.testing.expectEqualStrings("a.example", g.transport.grpc.authority.slice());
    try std.testing.expect(g.transport.grpc.multi);
    try std.testing.expectEqual(tls13.Alpn.h2, g.tls.?.alpn);
    try std.testing.expectError(error.UnsupportedTransport, vlessFromLink("vless://11111111-2222-3333-4444-555555555555@h:1?type=grpc&mode=tun", "h", 1));
    const xh = try vlessFromLink("vless://11111111-2222-3333-4444-555555555555@h:443?type=xhttp&security=reality&sni=www.example.com&pbk=jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8&path=%2Fx&mode=auto&extra=%7B%22xPaddingBytes%22%3A%22100-200%22%7D", "h", 443);
    try std.testing.expectEqualStrings("/x", xh.transport.xhttp.path.slice());
    try std.testing.expectEqualStrings("www.example.com", xh.transport.xhttp.host.slice());
    try std.testing.expectEqualStrings("{\"xPaddingBytes\":\"100-200\"}", xh.transport.xhttp.extra.slice());
    try std.testing.expectError(error.UnsupportedFlow, vlessFromLink("vless://11111111-2222-3333-4444-555555555555@h:443?type=xhttp&security=reality&pbk=jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8&flow=xtls-rprx-vision", "h", 443));
}

test "a link of any protocol becomes an outbound, or says what it lacks" {
    const t = std.testing;
    const uuid = "11111111-2222-3333-4444-555555555555";
    const pbk = "jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8";

    try t.expect((try outboundFromLink("vless://" ++ uuid ++ "@h:443?security=reality&flow=xtls-rprx-vision&pbk=" ++ pbk, "h", 443)).vless.vision);
    try t.expect((try outboundFromLink("VLESS://" ++ uuid ++ "@h:443?type=grpc&security=tls", "h", 443)).vless.transport == .grpc);

    const tj = try outboundFromLink("trojan://pw@h:443?type=ws&host=cdn.example&path=%2Ft", "h", 443);
    try t.expectEqualStrings("cdn.example", tj.trojan.transport.ws.host.slice());
    try t.expectEqual(tls13.Alpn.http11, tj.via().?.tls.?.alpn);
    try t.expect((try outboundFromLink("trojan://pw@h:443?security=reality&type=grpc&pbk=" ++ pbk, "h", 443)).via().?.reality != null);
    try t.expectError(error.UnsupportedSecurity, outboundFromLink("trojan://pw@h:443?security=none", "h", 443));
    try t.expectError(error.BadPassword, outboundFromLink("trojan://@h:443", "h", 443));
    try t.expectError(error.UnsupportedFlow, outboundFromLink("trojan://pw@h:443?flow=xtls-rprx-vision", "h", 443));

    // aes-256-gcm:pw
    const ss = try outboundFromLink("ss://YWVzLTI1Ni1nY206cHc@h:8388#x", "h", 8388);
    try t.expectEqual(shadowsocks.Method.aes_256_gcm, ss.shadowsocks.method);
    try t.expect(ss.via().?.tls == null and ss.via().?.transport.* == .raw);
    try t.expectError(error.UnsupportedMethod, outboundFromLink("ss://rc4-md5:pw@h:8388", "h", 8388));
    try t.expectError(error.UnsupportedPlugin, outboundFromLink("ss://YWVzLTI1Ni1nY206cHc@h:8388?plugin=obfs-local%3Bobfs%3Dhttp", "h", 8388));
    try t.expectError(error.BadLink, outboundFromLink("ss://@h:8388", "h", 8388));

    const vm = try outboundFromLink("vmess://" ++ uuid ++ "@h:443?type=httpupgrade&security=tls&path=%2Fv", "h", 443);
    try t.expectEqualStrings("/v", vm.vmess.transport.httpupgrade.path.slice());
    // {"v":"2","add":"h","port":"80","id":"<uuid>","net":"ws","path":"/w"}
    const vj = try outboundFromLink("vmess://eyJ2IjoiMiIsImFkZCI6ImgiLCJwb3J0IjoiODAiLCJpZCI6IjExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NSIsIm5ldCI6IndzIiwicGF0aCI6Ii93In0=", "h", 80);
    try t.expectEqualStrings("/w", vj.vmess.transport.ws.path.slice());
    try t.expect(vj.via().?.tls == null);
    try t.expectError(error.BadUuid, outboundFromLink("vmess://nope-nope-nope-nope-nope-nope-nope-nope@h:443", "h", 443));
    try t.expectError(error.BadLink, outboundFromLink("vmess://eyJ2IjoiMiJ9eA", "h", 443));

    // XHTTP is carried as stream-one: named so, or "auto" inside REALITY
    const x = "?type=xhttp&path=%2Fx";
    try t.expect((try outboundFromLink("vless://" ++ uuid ++ "@h:443" ++ x ++ "&security=reality&pbk=" ++ pbk, "h", 443)).vless.transport == .xhttp);
    try t.expect((try outboundFromLink("vless://" ++ uuid ++ "@h:443" ++ x ++ "&security=tls&mode=stream-one", "h", 443)).vless.transport == .xhttp);
    try t.expect((try outboundFromLink("trojan://pw@h:443" ++ x ++ "&mode=stream-one", "h", 443)).trojan.transport == .xhttp);
    try t.expectError(error.UnsupportedTransport, outboundFromLink("vless://" ++ uuid ++ "@h:443" ++ x ++ "&security=tls", "h", 443));
    try t.expectError(error.UnsupportedTransport, outboundFromLink("vless://" ++ uuid ++ "@h:443" ++ x ++ "&mode=packet-up&security=reality&pbk=" ++ pbk, "h", 443));
    try t.expectError(error.UnsupportedTransport, outboundFromLink("vmess://" ++ uuid ++ "@h:443" ++ x ++ "&security=tls&mode=stream-up", "h", 443));

    for ([_][]const u8{ "hysteria2://pw@h:443", "tuic://u:p@h:443", "wireguard://k@h:51820", "no link at all" }) |l|
        try t.expectError(error.UnsupportedProtocol, outboundFromLink(l, "h", 443));
}

test "an outbound of any kind keeps its strings in a snapshot and in a copy" {
    const t = std.testing;
    const pbk = "jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8";
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const links = [_][]const u8{
        "vless://11111111-2222-3333-4444-555555555555@a.example:443?security=reality&sni=sni.example&pbk=" ++ pbk,
        "trojan://pw@a.example:443?security=reality&sni=sni.example&pbk=" ++ pbk,
        "vmess://11111111-2222-3333-4444-555555555555@a.example:443?security=reality&sni=sni.example&pbk=" ++ pbk,
        "ss://YWVzLTI1Ni1nY206cHc@a.example:443",
    };
    for (links) |link| {
        var host_buf: [16]u8 = undefined;
        var link_buf: [256]u8 = undefined;
        const host = try std.fmt.bufPrint(&host_buf, "a.example", .{});
        const ob = try outboundFromLink(try std.fmt.bufPrint(&link_buf, "{s}", .{link}), host, 443);
        const snap: Snapshot = .of(ob);
        const copy = try ob.dupe(arena.allocator());
        // what the link and the host were read from goes away
        @memset(&host_buf, 'x');
        @memset(&link_buf, 'x');
        for ([_]Outbound{ snap.get(), copy }) |o| {
            const v = o.via().?;
            try t.expectEqualStrings("a.example", v.host);
            try t.expectEqual(443, v.port);
            if (o != .shadowsocks) try t.expectEqualStrings("sni.example", v.reality.?.server_name);
            try t.expect(o.sameServer(&copy));
        }
    }
    // the same address with another account, or another protocol, is another server
    const a = try outboundFromLink("trojan://pw@a.example:443", "a.example", 443);
    const b = try outboundFromLink("trojan://other@a.example:443", "a.example", 443);
    const c = try outboundFromLink("ss://YWVzLTI1Ni1nY206cHc@a.example:443", "a.example", 443);
    try t.expect(a.sameServer(&a) and !a.sameServer(&b) and !a.sameServer(&c));
    const direct: Outbound = .direct;
    try t.expect(direct.via() == null and direct.host() == null and direct.sameServer(&direct) and !direct.sameServer(&a));
}
