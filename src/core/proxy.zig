//! Outbounds, and the local SOCKS5 inbound.
//!
//! A flow has a local side (an application on the SOCKS port, or a TCP
//! connection terminated by the TUN stack) and goes out direct, blocked, or
//! through a server: VLESS, Trojan, VMess or Shadowsocks. The connection to
//! a server is built in layers, TCP -> TLS or REALITY (or neither) -> a
//! transport (none, WebSocket, HTTPUpgrade, gRPC, XHTTP) -> the protocol,
//! and every protocol takes every layer it allows (Shadowsocks: plain TCP
//! only; Trojan: never without TLS).
//!
//! VLESS on raw TCP may use the Vision flow: once the inner connection is
//! TLS 1.3 both directions switch to raw TCP, so bulk traffic is encrypted
//! only once. That path works on the TLS records themselves and is the one
//! case that puts nothing between them and the protocol.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const net = Io.net;
const tls13 = @import("tls13.zig");
const ws = @import("ws.zig");
const httpupgrade = @import("httpupgrade.zig");
const grpc = @import("grpc.zig");
const xhttp = @import("xhttp.zig");
const trojan = @import("trojan.zig");
const shadowsocks = @import("shadowsocks.zig");
const vmess = @import("vmess.zig");
const vision = @import("vision.zig");
const sys = @import("sys.zig");
const packet = @import("ipstack/packet.zig");
const tcp = @import("ipstack/stack.zig");
const dns = @import("ipstack/dns.zig");

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
    vless: Vless,
    trojan: trojan.Trojan,
    shadowsocks: shadowsocks.Shadowsocks,
    vmess: vmess.Vmess,

    /// Null for the outbounds that use no server.
    pub fn via(o: *const Outbound) ?Via {
        return switch (o.*) {
            .direct, .block => null,
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
            .direct, .block => true,
            .vless => |*v| std.mem.eql(u8, &v.uuid, &b.vless.uuid),
            .trojan => |*t| std.mem.eql(u8, &t.key, &b.trojan.key),
            .shadowsocks => |*s| s.method == b.shadowsocks.method and std.mem.eql(u8, &s.key, &b.shadowsocks.key),
            .vmess => |*v| std.mem.eql(u8, &v.user.cmd_key, &b.vmess.user.cmd_key),
        };
    }

    /// The strings an outbound points to rather than holds.
    fn strings(o: *Outbound) ?struct { host: *[]const u8, sni: ?*[]const u8 } {
        switch (o.*) {
            .direct, .block => return null,
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

fn xhttpOptions(x: *const Xhttp, v: *const Via) xhttp.Options {
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

pub const vless_header_max = 1 + 16 + 1 + 18 + 1 + 2 + 1 + 1 + 255;

/// VLESS request header for a TCP stream to `t`.
pub fn vlessHeader(buf: *[vless_header_max]u8, uuid: [16]u8, t: *const Target, flow_vision: bool) []const u8 {
    var w: Io.Writer = .fixed(buf);
    w.writeByte(0) catch unreachable; // version
    w.writeAll(&uuid) catch unreachable;
    if (flow_vision) {
        // addons (protobuf): field 1, flow
        const flow = "xtls-rprx-vision";
        w.writeAll(&.{ 2 + flow.len, 0x0a, flow.len }) catch unreachable;
        w.writeAll(flow) catch unreachable;
    } else {
        w.writeByte(0) catch unreachable;
    }
    w.writeByte(1) catch unreachable; // command: TCP
    w.writeInt(u16, t.port, .big) catch unreachable;
    switch (t.kind) {
        .ip4 => w.writeByte(1) catch unreachable,
        .domain => {
            w.writeByte(2) catch unreachable;
            w.writeByte(t.len) catch unreachable;
        },
        .ip6 => w.writeByte(3) catch unreachable,
    }
    w.writeAll(t.addr()) catch unreachable;
    return w.buffered();
}

/// Why connections fail, for the interface. Only failures on the way to the
/// server are recorded; a client closing early is not a fault.
pub const Fault = enum(u8) { none, unreachable_server, handshake, reality_rejected };

/// Byte and connection counters. A flow may feed several (global, per app).
pub const Meter = struct {
    down: std.atomic.Value(u64) = .init(0),
    up: std.atomic.Value(u64) = .init(0),
    active: std.atomic.Value(u32) = .init(0),
    failed: std.atomic.Value(u32) = .init(0),
    /// connections whose bulk traffic left the outer TLS layer (Vision)
    direct_up: std.atomic.Value(u32) = .init(0),
    direct_down: std.atomic.Value(u32) = .init(0),
    fault: std.atomic.Value(Fault) = .init(.none),
};

var dial_log_ms: std.atomic.Value(i64) = .init(0);
var dial_log_skipped: std.atomic.Value(u32) = .init(0);

/// Why a server could not be reached, in the log: at most one line every
/// few seconds, with the number of failures left out in between.
fn noteDialFailure(io: Io, host: []const u8, err: anyerror, http_status: ?u16) void {
    const now = Io.Clock.awake.now(io).toMilliseconds();
    const last = dial_log_ms.load(.monotonic);
    if (last != 0 and now - last < 5000) {
        _ = dial_log_skipped.fetchAdd(1, .monotonic);
        return;
    }
    if (dial_log_ms.cmpxchgStrong(last, now, .monotonic, .monotonic) != null) return;
    const more = dial_log_skipped.swap(0, .monotonic);
    if (http_status) |st|
        std.log.scoped(.proxy).warn("server {s}: {t}, HTTP {d} (+{d} more failures)", .{ host, err, st, more })
    else
        std.log.scoped(.proxy).warn("server {s}: {t} (+{d} more failures)", .{ host, err, more });
}

/// A server that accepted the connection finishes the TLS and transport
/// handshakes within this time, or the dial fails.
pub const handshake_timeout_ms = 10_000;

/// Stack of a thread that dials a server. The TLS handshake (its ML-KEM key
/// pair above all) goes about 175 KiB deep in a release build and 260 KiB
/// in a debug one, under the thread's own buffers. Only pages that are
/// touched cost memory.
pub const dial_stack_size = 512 * 1024;

/// How outbound connections are made.
pub const Dialer = struct {
    /// keep our own sockets off the TUN
    bind: sys.Bind = .none,
    /// resolve names here instead of through the system (whose DNS points
    /// at our own fake-IP server while the TUN is up)
    resolver: ?*dns.Resolver = null,
    timeout_ms: i32 = 10_000,

    pub fn connect(d: *const Dialer, io: Io, host: []const u8, port: u16) !net.Stream {
        if (net.IpAddress.parse(host, port)) |ip| {
            const a, _ = sys.fromIpAddress(ip);
            return d.connectAddr(io, &a, port);
        } else |_| {}
        if (d.resolver) |r| {
            const a = try r.resolve(host);
            return d.connectAddr(io, &a, port);
        }
        const name = try net.HostName.init(host);
        return name.connect(io, port, .{ .mode = .stream });
    }

    pub fn connectAddr(d: *const Dialer, io: Io, a: *const packet.Addr, port: u16) !net.Stream {
        if (d.bind == .none) return sys.toIpAddress(a, port).connect(io, .{ .mode = .stream });
        return sys.connectTcp(a, port, d.bind, d.timeout_ms);
    }

    pub fn connectTarget(d: *const Dialer, io: Io, t: *const Target) !net.Stream {
        return switch (t.kind) {
            .domain => d.connect(io, t.addr(), t.port),
            .ip4 => d.connectAddr(io, &packet.v4(t.bytes[0..4].*), t.port),
            .ip6 => d.connectAddr(io, t.bytes[0..16], t.port),
        };
    }
};

/// A connection to a server, dialed, through its TLS or REALITY handshake
/// and with its transport open: ready for the protocol's request. It holds
/// the buffers of the socket and of the TLS records, so it must stay at one
/// address once `Flow.dial` has filled it.
pub const Upstream = struct {
    stream: net.Stream,
    ur: if (sys.supported) sys.SockReader else net.Stream.Reader,
    uw: net.Stream.Writer,
    rr: tls13.RecordReader,
    rw: tls13.RecordWriter,
    tls: bool,
    urb: [tls13.min_read_buffer]u8,
    uwb: [4096]u8,
    /// What runs inside the stream: a transport, a protocol's own cipher,
    /// or only the TLS records as a byte stream. On the heap with its
    /// buffers; VLESS on the raw stream has none.
    layer: ?*Layer = null,
    /// HTTP status of a transport request the server refused, for the log
    layer_status: u16 = 0,

    /// The download ended badly while the upload may still be running:
    /// make sure the upload notices. Over HTTP/2 it may be waiting for
    /// flow-control credit that only the download thread could have
    /// delivered, and would wait forever.
    fn abandon(u: *Upstream, io: Io) void {
        if (u.layer) |l| l.goodbye();
        u.stream.shutdown(io, .both) catch {};
    }

    /// How long the server may stay silent after the upload ended.
    fn lingerMs(u: *const Upstream) u32 {
        const l = u.layer orelse return linger_ms;
        return if (l.transport == .ws) linger_unsignalled_ms else linger_ms;
    }

    pub fn close(u: *Upstream, io: Io) void {
        if (u.layer) |l| {
            l.goodbye();
            l.destroy();
            u.layer = null;
        }
        u.stream.close(io);
    }

    /// Where the protocol's bytes come from and go to when something sits
    /// between it and the TLS records or the socket; the caller handles
    /// those itself otherwise.
    pub fn transportReader(u: *Upstream) ?*Io.Reader {
        return if (u.layer) |l| l.r else null;
    }
    pub fn transportWriter(u: *Upstream) ?*Io.Writer {
        return if (u.layer) |l| l.w else null;
    }

    /// The application's data, once `attach` put the protocol's cipher (if
    /// it has one) on the stream.
    fn reader(u: *Upstream) *Io.Reader {
        const l = u.layer.?;
        return switch (l.cipher) {
            .none => l.r,
            inline else => |c| &c.reader,
        };
    }
    fn writer(u: *Upstream) *Io.Writer {
        const l = u.layer.?;
        return switch (l.cipher) {
            .none => l.w,
            inline else => |c| &c.writer,
        };
    }

    /// VMess and Shadowsocks seal the stream themselves: put their cipher
    /// on it, with the request for `target` (which leaves with the first
    /// flush). No I/O. The other protocols need nothing here.
    fn attach(u: *Upstream, io: Io, ob: *const Outbound, target: *const Target) !void {
        const l = u.layer orelse return;
        const p = Plan.of(ob, &ob.via().?, u.tls).?;
        switch (ob.*) {
            .vmess => |*v| {
                const c = l.make(vmess.Conn);
                c.* = .init(io, v.user, v.security, l.r, l.w, l.take(p.cr), l.take(p.cw));
                l.cipher = .{ .vmess = c };
                try c.writeRequest(.{
                    .address = switch (target.kind) {
                        .ip4 => .{ .ip4 = target.bytes[0..4].* },
                        .ip6 => .{ .ip6 = target.bytes[0..16].* },
                        .domain => .{ .domain = target.addr() },
                    },
                    .port = target.port,
                });
            },
            .shadowsocks => |*s| {
                const c = l.make(shadowsocks.Conn);
                c.* = .init(io, s, target, l.r, l.w, l.take(p.cr), l.take(p.cw));
                l.cipher = .{ .shadowsocks = c };
            },
            else => {},
        }
    }

    /// The application finished sending: tell the server so, leaving the
    /// download open, where the layers have a way to say it.
    fn endUpload(u: *Upstream, io: Io) void {
        if (u.layer) |l| {
            switch (l.cipher) {
                // the empty chunk that ends our direction
                .vmess => |c| c.end() catch {},
                .none, .shadowsocks => {},
            }
            switch (l.transport) {
                // WebSocket has no half-close, and Xray takes a TCP one for
                // an abnormal end and drops the download with it: say
                // nothing, the server's own timers end the flow
                .ws => return,
                // END_STREAM; the connection itself has to stay, it still
                // answers the server's PINGs and returns flow-control credit
                .grpc => |c| return c.closeWrite() catch {},
                .xhttp => |c| return c.closeWrite() catch {},
                // a byte stream on the records: only this thread writes them
                .none, .httpupgrade => if (u.tls) u.rw.closeNotify() catch {},
            }
        }
        u.stream.shutdown(io, .send) catch {};
    }

    /// Why the server turned the connection down, when that shows only
    /// after the dial: gRPC and XHTTP send their request without waiting
    /// for the answer, as do WebSocket and HTTPUpgrade with early data, and
    /// a cipher's key is first tested by the server's first bytes. Null
    /// when nothing of the kind happened: a destination the server could
    /// not reach is not its fault. For the thread that reads the
    /// connection, once it has ended.
    fn refusal(u: *Upstream) ?anyerror {
        const l = u.layer orelse return null;
        switch (l.transport) {
            .none => {},
            .ws => |c| if (c.err) |e| switch (e) {
                error.WsUpgradeRefused, error.WsBadHandshake => {
                    u.layer_status = c.status;
                    return e;
                },
                else => {},
            },
            .httpupgrade => |c| if (c.err) |e| {
                u.layer_status = c.status;
                return e;
            },
            .grpc => |c| if (c.read_err) |e| switch (e) {
                error.GrpcRefused, error.GrpcNotGrpc => {
                    u.layer_status = c.status;
                    return e;
                },
                // 12, unimplemented: a wrong service name or mode
                error.GrpcStatus => if (c.grpc_status == 12) return e,
                else => {},
            },
            .xhttp => |c| if (c.read_err) |e| if (e == error.XhttpRejected) {
                u.layer_status = c.status;
                return e;
            },
        }
        switch (l.cipher) {
            .none => {},
            // (no answer at all is also what an unreachable destination gives)
            .vmess => |c| if (c.err) |e| if (e == error.VmessBadResponse) return e,
            .shadowsocks => |c| if (c.err) |e| switch (e) {
                error.SsAuthFailed, error.SsBadResponse, error.SsClockSkew => return e,
                else => {},
            },
        }
        return null;
    }
};

/// Buffer sizes of a connection's layer. What a buffer is for decides its
/// size: one a copy loop reads from holds a TLS record's worth, one that
/// only passes bytes on to a buffer above it stays small.
const Plan = struct {
    /// TLS records as a byte stream
    sr: usize = 0,
    sw: usize = 0,
    /// the transport
    tr: usize = 0,
    tw: usize = 0,
    /// the protocol's cipher
    cr: usize = 0,
    cw: usize = 0,
    /// the transport's and the cipher's own state
    state: usize = 0,

    /// Room for a `T` wherever in the block it comes: buffers of any
    /// length may lie before it, so it may have to move up to be aligned.
    fn room(comptime T: type) usize {
        return @sizeOf(T) + Layer.block_align;
    }

    /// Null: nothing sits between the protocol and the stream.
    fn of(ob: *const Outbound, v: *const Via, tls: bool) ?Plan {
        var p: Plan = .{};
        switch (ob.*) {
            .vmess => {
                p.cr = vmess.read_buffer_len;
                p.cw = vmess.write_buffer_len;
                p.state = room(vmess.Conn);
            },
            .shadowsocks => |*s| {
                p.cr = shadowsocks.readBufferLen(s.method);
                p.cw = shadowsocks.write_buffer_len;
                p.state = room(shadowsocks.Conn);
            },
            else => {},
        }
        const cipher = p.cr != 0;
        // a cipher opens chunks in its own buffer: below it nothing is copied from
        const top: usize = if (cipher) 512 else 16 * 1024;
        switch (v.transport.*) {
            .raw => {
                // VLESS works on the records (Vision) or the socket itself
                if (ob.* == .vless) return null;
                if (tls) p.sr = top;
            },
            .ws => {
                if (tls) {
                    p.sr = 16 * 1024;
                    p.sw = 4096;
                }
                p.tr = top;
                // a frame is at most one TLS record
                p.tw = 16 * 1024;
                p.state += room(ws.Conn);
            },
            .httpupgrade => {
                // the answer is read from here line by line, then data passes through
                if (tls) p.sr = 4096;
                p.tr = top;
                p.state += room(httpupgrade.Conn);
            },
            .grpc => {
                // HTTP/2 takes frame headers from here; payload goes past it
                if (tls) p.sr = 64;
                p.tr = top;
                // a message, its DATA frame and that frame's TLS record: one each
                p.tw = 16 * 1024 - 18;
                p.state += room(grpc.Conn);
            },
            .xhttp => {
                if (tls) p.sr = 64;
                p.tr = top;
                // room for a request header to leave with the first data
                p.tw = 4096;
                p.state += room(xhttp.Conn);
            },
        }
        return p;
    }

    /// The buffers alone.
    fn buffers(p: Plan) usize {
        return p.sr + p.sw + p.tr + p.tw + p.cr + p.cw;
    }

    fn total(p: Plan) usize {
        return p.buffers() + p.state;
    }
};

/// What a connection carries inside its stream, from the bottom up: the
/// TLS records as a byte stream, a transport, a protocol's cipher. One
/// allocation: this, then the state of those that are there and their
/// buffers (see `Plan`), so a connection pays for what it uses only.
const Layer = struct {
    block: []align(block_align) u8,
    used: usize,
    sr: tls13.StreamReader = undefined,
    sw: tls13.StreamWriter = undefined,
    transport: union(enum) {
        none,
        ws: *ws.Conn,
        httpupgrade: *httpupgrade.Conn,
        grpc: *grpc.Conn,
        xhttp: *xhttp.Conn,
    } = .none,
    cipher: union(enum) {
        none,
        vmess: *vmess.Conn,
        shadowsocks: *shadowsocks.Conn,
    } = .none,
    /// the protocol's bytes: the transport, else the TLS stream, else the socket
    r: *Io.Reader = undefined,
    w: *Io.Writer = undefined,

    const block_align = 16;

    fn create(p: Plan) !*Layer {
        const head = @sizeOf(Layer);
        const block = try std.heap.c_allocator.alignedAlloc(u8, .fromByteUnits(block_align), head + p.total());
        const l: *Layer = @ptrCast(block.ptr);
        l.* = .{ .block = block, .used = head };
        return l;
    }

    fn destroy(l: *Layer) void {
        std.heap.c_allocator.free(l.block);
    }

    fn take(l: *Layer, n: usize) []u8 {
        // the plan and what is taken by it are written in two places: a
        // mismatch must never become a write past the block
        if (n > l.block.len - l.used) @panic("connection layer: plan too small");
        const s = l.block[l.used..][0..n];
        l.used += n;
        return s;
    }

    /// Room for a `T`, not initialized.
    fn make(l: *Layer, comptime T: type) *T {
        comptime std.debug.assert(@alignOf(T) <= block_align);
        const at = std.mem.alignForward(usize, l.used, block_align);
        _ = l.take(at - l.used);
        return @ptrCast(@alignCast(l.take(@sizeOf(T)).ptr));
    }

    /// Tell the server the connection is over, where the transport has a
    /// word for it; not waited for. Twice does no harm.
    fn goodbye(l: *Layer) void {
        switch (l.transport) {
            .none, .httpupgrade => {},
            inline else => |c| c.close(),
        }
    }
};

/// The application's side of a flow.
pub const Local = struct {
    r: *Io.Reader,
    w: *Io.Writer,
    end: union(enum) {
        /// a SOCKS5 client: answers are SOCKS replies
        socks: net.Stream,
        /// a connection terminated by the TUN stack
        tun: *tcp.Conn,
    },

    /// The outbound is ready: tell the application it is connected.
    pub fn ready(l: *Local) !void {
        switch (l.end) {
            .socks => try reply(l.w, 0),
            .tun => |c| try c.accept(),
        }
    }

    /// The flow cannot be served (`code` is the SOCKS reply code).
    pub fn refuse(l: *Local, code: u8) void {
        switch (l.end) {
            .socks => reply(l.w, code) catch {},
            .tun => |c| c.reject(),
        }
    }

    pub fn waitReadable(l: *Local, ms: u32) bool {
        if (l.r.buffered().len > 0) return true;
        return switch (l.end) {
            .socks => |s| if (builtin.os.tag == .windows) false else sys.waitFd(s.socket.handle, false, @intCast(ms)),
            .tun => |c| c.waitReadable(ms),
        };
    }

    /// The remote side finished: close ours and stop reading.
    pub fn closeBoth(l: *Local, io: Io) void {
        l.w.flush() catch {};
        switch (l.end) {
            .socks => |s| s.shutdown(io, .both) catch {},
            .tun => |c| {
                c.closeWrite();
                c.shutdownRead();
            },
        }
    }

    /// The remote side failed: reset ours.
    pub fn reset(l: *Local, io: Io) void {
        switch (l.end) {
            .socks => |s| s.shutdown(io, .both) catch {},
            .tun => |c| c.abort(),
        }
    }
};

/// Everything a flow needs besides its two ends.
pub const Flow = struct {
    io: Io,
    dialer: Dialer = .{},
    meters: [3]?*Meter = .{ null, null, null },
    /// set when whoever runs the flows shuts down: flows end at once
    stop: ?*const std.atomic.Value(bool) = null,

    pub fn up(f: *const Flow, n: usize) void {
        for (f.meters) |m| if (m) |mm| {
            _ = mm.up.fetchAdd(n, .monotonic);
        };
    }
    pub fn down(f: *const Flow, n: usize) void {
        for (f.meters) |m| if (m) |mm| {
            _ = mm.down.fetchAdd(n, .monotonic);
        };
    }
    fn fault(f: *const Flow, what: Fault) void {
        for (f.meters) |m| if (m) |mm| mm.fault.store(what, .monotonic);
    }
    fn up_fault(f: *const Flow) Fault {
        for (f.meters) |m| if (m) |mm| return mm.fault.load(.monotonic);
        return .none;
    }

    pub fn mark(f: *const Flow, comptime field: []const u8) void {
        for (f.meters) |m| if (m) |mm| {
            _ = @field(mm, field).fetchAdd(1, .monotonic);
        };
    }

    /// Carry one connection from `local` to `target` through `ob`.
    pub fn run(f: *const Flow, local: *Local, target: *const Target, ob: *const Outbound) !void {
        f.mark("active");
        defer for (f.meters) |m| if (m) |mm| {
            _ = mm.active.fetchSub(1, .monotonic);
        };
        errdefer f.mark("failed");
        switch (ob.*) {
            .block => {
                local.refuse(2);
                return error.Blocked;
            },
            .direct => {
                const upstream = f.dialer.connectTarget(f.io, target) catch |err| {
                    local.refuse(if (err == error.ConnectionRefused) 5 else 4);
                    return err;
                };
                defer upstream.close(f.io);
                try local.ready();
                try f.relayPlain(local, upstream);
            },
            .vless => try f.runVless(ob, local, target),
            .trojan, .shadowsocks, .vmess => try f.runStream(ob, local, target),
        }
    }

    fn relayPlain(f: *const Flow, local: *Local, upstream: net.Stream) !void {
        var urb: [16 * 1024]u8 = undefined;
        var uwb: [4096]u8 = undefined;
        var ur = upstream.reader(f.io, &urb);
        var uw = upstream.writer(f.io, &uwb);
        var bk: Back = .{};
        const back = try std.Thread.spawn(.{ .stack_size = sys.stackSize(64 * 1024) }, relayBack, .{ f, &ur.interface, local, &bk });
        if (f.pumpCounted(local.r, &uw.interface, .up)) {
            upstream.shutdown(f.io, .send) catch {};
            f.linger(&bk, upstream, linger_ms);
        } else |_| {
            upstream.shutdown(f.io, .both) catch {};
        }
        back.join();
    }

    fn relayBack(f: *const Flow, from: *Io.Reader, local: *Local, bk: *Back) void {
        defer bk.finish(f.io);
        if (f.pumpBack(from, local.w, bk)) local.closeBoth(f.io) else |_| local.reset(f.io);
    }

    fn pumpBack(f: *const Flow, from: *Io.Reader, to: *Io.Writer, bk: *Back) !void {
        while (true) {
            const chunk = from.peekGreedy(1) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            try to.writeAll(chunk);
            try to.flush();
            f.down(chunk.len);
            _ = bk.chunks.fetchAdd(1, .monotonic);
            from.toss(chunk.len);
        }
        try to.flush();
    }

    /// The application finished sending; the other end gets to finish too,
    /// but not forever. A server that keeps a half-closed connection open
    /// and silent would hold its two threads and its socket for good (and
    /// a shutdown would wait for them): once nothing has come for
    /// `linger_ms`, or the owner of the flows is stopping, the connection
    /// is closed, which ends the thread reading it.
    fn linger(f: *const Flow, bk: *Back, upstream: net.Stream, limit_ms: u32) void {
        var seen = bk.chunks.load(.monotonic);
        var quiet_ms: u32 = 0;
        bk.mutex.lockUncancelable(f.io);
        defer bk.mutex.unlock(f.io);
        while (!bk.done) {
            // woken the moment the other direction ends
            bk.cond.waitTimeout(f.io, &bk.mutex, .{ .duration = .{ .raw = .fromMilliseconds(linger_step_ms), .clock = .awake } }) catch {};
            if (bk.done) return;
            const now = bk.chunks.load(.monotonic);
            if (now != seen) {
                seen = now;
                quiet_ms = 0;
            } else quiet_ms += linger_step_ms;
            const stopping = if (f.stop) |st| st.load(.acquire) else false;
            if (quiet_ms >= limit_ms or stopping) {
                upstream.shutdown(f.io, .both) catch {};
                return;
            }
        }
    }

    fn pumpCounted(f: *const Flow, from: *Io.Reader, to: *Io.Writer, dir: enum { up, down }) !void {
        while (true) {
            const chunk = from.peekGreedy(1) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            try to.writeAll(chunk);
            try to.flush();
            if (dir == .up) f.up(chunk.len) else f.down(chunk.len);
            from.toss(chunk.len);
        }
        try to.flush();
    }

    /// Connect to the server of `ob`, run the TLS or REALITY handshake if
    /// it has one, and open its transport. The protocol's request is the
    /// caller's to send.
    pub fn dial(f: *const Flow, ob: *const Outbound, u: *Upstream) !void {
        const v = ob.via() orelse return error.NoServer;
        f.dialInner(ob, &v, u) catch |err| {
            noteDialFailure(f.io, v.host, err, if (u.layer_status != 0) u.layer_status else null);
            return err;
        };
    }

    fn dialInner(f: *const Flow, ob: *const Outbound, v: *const Via, u: *Upstream) !void {
        const io = f.io;
        u.layer = null;
        u.layer_status = 0;
        u.stream = f.dialer.connect(io, v.host, v.port) catch |err| {
            f.fault(.unreachable_server);
            return err;
        };
        errdefer u.stream.close(io);
        if (comptime sys.supported) {
            u.ur = .init(u.stream.socket.handle, io, &u.urb);
            // the handshakes below must finish in time; data may idle forever
            u.ur.setDeadline(handshake_timeout_ms);
        } else {
            u.ur = u.stream.reader(io, &u.urb);
        }
        defer if (comptime sys.supported) u.ur.noDeadline();
        u.uw = u.stream.writer(io, &u.uwb);
        u.tls = v.reality != null or v.tls != null;
        if (v.reality) |re| {
            _ = tls13.handshake(io, &u.ur.interface, &u.uw.interface, .{
                .server_name = re.server_name,
                .reality = .{ .public_key = re.public_key, .short_id = re.short_id },
            }, &u.rr, &u.rw) catch |err| {
                f.fault(if (err == error.RealityAuthFailed) .reality_rejected else .handshake);
                return err;
            };
        } else if (v.tls) |t| {
            const roots = tls13.systemRoots(io) catch |err| {
                f.fault(.handshake);
                return err;
            };
            _ = tls13.handshake(io, &u.ur.interface, &u.uw.interface, .{
                .server_name = t.server_name.slice(),
                .roots = roots,
                .alpn = t.alpn,
            }, &u.rr, &u.rw) catch |err| {
                f.fault(.handshake);
                return err;
            };
        }

        try f.openLayer(ob, v, u);
    }

    /// What runs inside the stream, if anything does. A function of its
    /// own so that its frame is not under the TLS handshake's, the deepest
    /// part of a dial: flow threads have small stacks.
    fn openLayer(f: *const Flow, ob: *const Outbound, v: *const Via, u: *Upstream) !void {
        const io = f.io;
        const p = Plan.of(ob, v, u.tls) orelse return;
        const l = try Layer.create(p);
        errdefer l.destroy();
        var r: *Io.Reader = &u.ur.interface;
        var w: *Io.Writer = &u.uw.interface;
        if (u.tls) {
            l.sr = .init(&u.rr, l.take(p.sr));
            l.sw = .init(&u.rw, l.take(p.sw));
            r = &l.sr.interface;
            w = &l.sw.interface;
        }
        switch (v.transport.*) {
            .raw => {},
            .ws => |*h| {
                const c = l.make(ws.Conn);
                c.* = .init(io, r, w, l.take(p.tr), l.take(p.tw));
                l.transport = .{ .ws = c };
                c.handshake(.{ .path = h.path.slice(), .host = h.host.slice() }) catch |err| {
                    u.layer_status = c.status;
                    f.fault(.handshake);
                    return err;
                };
                r = &c.reader;
                w = &c.writer;
            },
            .httpupgrade => |*h| {
                const c = l.make(httpupgrade.Conn);
                c.* = .init(io, r, w, l.take(p.tr));
                l.transport = .{ .httpupgrade = c };
                c.handshake(.{ .path = h.path.slice(), .host = h.host.slice(), .tls = u.tls }) catch |err| {
                    u.layer_status = c.status;
                    f.fault(.handshake);
                    return err;
                };
                r = &c.reader;
                w = c.writer();
            },
            // gRPC and XHTTP send their request without waiting for the
            // answer, as Xray does: a refusal shows on the first read
            .grpc => |*g| {
                const c = l.make(grpc.Conn);
                var ab: [264]u8 = undefined;
                c.open(io, r, w, l.take(p.tr), l.take(p.tw), .{
                    .service_name = g.service_name.slice(),
                    .authority = grpc.authority(&ab, g.authority.slice(), if (v.tls) |t| t.server_name.slice() else "", v.reality != null, v.host, v.port),
                    .mode = if (g.multi) .multi else .gun,
                }) catch |err| {
                    f.fault(.handshake);
                    return err;
                };
                l.transport = .{ .grpc = c };
                r = c.reader();
                w = c.writer();
            },
            .xhttp => |*x| {
                const c = l.make(xhttp.Conn);
                c.open(io, r, w, l.take(p.tr), l.take(p.tw), xhttpOptions(x, v)) catch |err| {
                    f.fault(.handshake);
                    return err;
                };
                l.transport = .{ .xhttp = c };
                r = c.reader();
                w = c.writer();
            },
        }
        l.r = r;
        l.w = w;
        u.layer = l;
    }

    /// SOCKS reply code for a dial that failed.
    fn refuseCode(f: *const Flow, err: anyerror) u8 {
        return switch (err) {
            error.ConnectionRefused => 5,
            error.RealityAuthFailed => 1,
            else => if (up_fault(f) == .handshake or up_fault(f) == .reality_rejected) 1 else 4,
        };
    }

    /// A connection that ended without a byte from the server: if the
    /// server turned it down (`Upstream.refusal`), that is a handshake that
    /// failed, for the server's health and for the log.
    fn noteRefusal(f: *const Flow, u: *Upstream, host: []const u8) void {
        const err = u.refusal() orelse return;
        f.fault(.handshake);
        noteDialFailure(f.io, host, err, if (u.layer_status != 0) u.layer_status else null);
    }

    fn runVless(f: *const Flow, ob: *const Outbound, local: *Local, target: *const Target) !void {
        const io = f.io;
        const v = &ob.vless;
        var conn: Upstream = undefined;
        f.dial(ob, &conn) catch |err| {
            local.refuse(f.refuseCode(err));
            return err;
        };
        defer conn.close(io);
        const upstream = conn.stream;
        const ur = &conn.ur;
        const uw = &conn.uw;
        const rr = &conn.rr;
        const rw = &conn.rw;
        try local.ready();

        // inside a transport, VLESS reads and writes the transport's stream;
        // otherwise the TLS records (Vision needs them) or the socket
        const t_r = conn.transportReader();
        const t_w = conn.transportWriter();
        var traffic: vision.Traffic = .{};
        var bk: Back = .{};
        var dl: Downlink = .{
            .flow = f,
            .conn = &conn,
            .host = v.host,
            .tls = if (conn.tls and t_r == null) rr else null,
            .raw = t_r orelse &ur.interface,
            .local = local,
            .uuid = v.uuid,
            .vision = v.vision,
            .traffic = &traffic,
            .back = &bk,
        };
        const back = try std.Thread.spawn(.{ .stack_size = sys.stackSize(128 * 1024) }, Downlink.run, .{&dl});
        const tls_w: ?*tls13.RecordWriter = if (conn.tls and t_w == null) rw else null;
        if (f.uplink(v, local, t_w orelse &uw.interface, tls_w, &traffic, target)) {
            conn.endUpload(io);
            f.linger(&bk, upstream, conn.lingerMs());
        } else |_| {
            upstream.shutdown(io, .both) catch {};
        }
        back.join();
    }

    /// Trojan, VMess, Shadowsocks: after the request the application's data
    /// goes as it is, inside the protocol's cipher if it has one.
    fn runStream(f: *const Flow, ob: *const Outbound, local: *Local, target: *const Target) !void {
        const io = f.io;
        var conn: Upstream = undefined;
        f.dial(ob, &conn) catch |err| {
            local.refuse(f.refuseCode(err));
            return err;
        };
        defer conn.close(io);
        conn.attach(io, ob, target) catch |err| {
            local.refuse(1);
            return err;
        };
        try local.ready();

        var bk: Back = .{};
        var sb: StreamBack = .{ .flow = f, .conn = &conn, .host = ob.host().?, .local = local, .back = &bk };
        const back = try std.Thread.spawn(.{ .stack_size = sys.stackSize(128 * 1024) }, StreamBack.run, .{&sb});
        if (f.uplinkStream(ob, &conn, local, target)) {
            conn.endUpload(io);
            f.linger(&bk, conn.stream, conn.lingerMs());
        } else |_| {
            conn.stream.shutdown(io, .both) catch {};
        }
        back.join();
    }

    fn uplinkStream(f: *const Flow, ob: *const Outbound, conn: *Upstream, local: *Local, target: *const Target) !void {
        const w = conn.writer();
        switch (ob.*) {
            // Xray takes a connection for Trojan only if its first read
            // starts with the whole header: nothing may be flushed before it
            .trojan => |*t| {
                var hb: [trojan.header_max]u8 = undefined;
                try w.writeAll(trojan.requestHeader(&hb, &t.key, .connect, target));
            },
            // the ciphers hold their request until the first flush
            else => {},
        }
        // the request leaves with the first data, or alone after a short
        // wait so server-first protocols are not stuck
        if (!local.waitReadable(500)) try w.flush();
        return f.pumpCounted(local.r, w, .up);
    }

    fn uplink(
        f: *const Flow,
        v: *const Vless,
        local: *Local,
        raw: *Io.Writer,
        tls_w: ?*tls13.RecordWriter,
        traffic: *vision.Traffic,
        target: *const Target,
    ) !void {
        const cr = local.r;
        var hb: [vless_header_max]u8 = undefined;
        const header = vlessHeader(&hb, v.uuid, target, v.vision);

        if (!v.vision) {
            // the header leaves with the first data, or alone after a short
            // wait so server-first protocols are not stuck
            if (tls_w) |t| try t.write(header) else try raw.writeAll(header);
            if (!local.waitReadable(500)) {
                if (tls_w) |t| try t.flush() else try raw.flush();
            }
            return if (tls_w) |t| f.pumpTls(cr, t) else f.pumpCounted(cr, raw, .up);
        }

        const rw = tls_w.?;
        var seed: [8]u8 = undefined;
        f.io.random(&seed);
        var prng: std.Random.DefaultPrng = .init(std.mem.readInt(u64, &seed, .little));
        const rand = prng.random();
        var padder: vision.Padder = .init(v.uuid);
        try rw.write(header);

        var frames: u32 = 0;
        var tracking = false; // the inner stream is TLS, cut it at record boundaries
        var first = true;
        while (true) {
            var chunk: []const u8 = &.{};
            if (first) {
                if (local.waitReadable(500)) chunk = cr.peekGreedy(1) catch |err| switch (err) {
                    error.EndOfStream => &.{},
                    else => return err,
                };
                if (vision.isClientHello(chunk)) {
                    tracking = true;
                    chunk = try completeRecords(cr);
                }
            } else {
                chunk = (if (tracking) completeRecords(cr) else cr.peekGreedy(1)) catch |err| switch (err) {
                    error.EndOfStream => return rw.closeNotify(),
                    else => return err,
                };
            }

            var command: vision.Command = .pad;
            if (tracking and vision.isAppDataRecords(chunk)) {
                command = if (traffic.enable_direct.load(.acquire)) .direct else .end;
            } else if (frames >= 63 or (!tracking and !traffic.server_tls.load(.acquire) and frames >= 7)) {
                command = .end;
            }
            const long = first or tracking or traffic.server_tls.load(.acquire);

            var rest = chunk;
            while (true) {
                const piece = rest[0..@min(rest.len, vision.max_content)];
                rest = rest[piece.len..];
                const space = try rw.writable(vision.max_frame);
                rw.advance(padder.frame(space, piece, if (rest.len == 0) command else .pad, long, rand));
                frames += 1;
                if (rest.len == 0) break;
            }
            try rw.flush();
            cr.toss(chunk.len);
            f.up(chunk.len);
            first = false;

            switch (command) {
                .pad => {},
                .end => return f.pumpTls(cr, rw),
                .direct => {
                    f.mark("direct_up");
                    return f.pumpCounted(cr, raw, .up);
                },
            }
        }
    }

    fn pumpTls(f: *const Flow, from: *Io.Reader, rw: *tls13.RecordWriter) !void {
        while (true) {
            const chunk = from.peekGreedy(1) catch |err| switch (err) {
                error.EndOfStream => return rw.closeNotify(),
                else => return err,
            };
            try rw.write(chunk);
            try rw.flush();
            f.up(chunk.len);
            from.toss(chunk.len);
        }
    }
};

/// The reverse direction of a flow, as the thread waiting for it sees it.
const Back = struct {
    mutex: Io.Mutex = .init,
    cond: Io.Condition = .init,
    done: bool = false,
    /// grows with every piece of data that arrived
    chunks: std.atomic.Value(u32) = .init(0),

    fn finish(b: *Back, io: Io) void {
        b.mutex.lockUncancelable(io);
        b.done = true;
        b.mutex.unlock(io);
        b.cond.broadcast(io);
    }
};

/// How long the other end may stay silent after the application finished
/// sending (Xray's default for this is 5 s of its 300 s idle time).
const linger_ms = 30_000;
/// The same for a transport that cannot tell the server the upload is over
/// (WebSocket has no half-close): the destination never learns that the
/// application is done and usually just stays open, so waiting long only
/// keeps finished flows around. Xray gives this case one second.
const linger_unsignalled_ms = 4000;
const linger_step_ms = 200;

/// The downlink of a flow whose protocol leaves the application's data on
/// the connection's reader as it is.
const StreamBack = struct {
    flow: *const Flow,
    conn: *Upstream,
    host: []const u8,
    local: *Local,
    back: *Back,

    fn run(s: *StreamBack) void {
        const f = s.flow;
        defer s.back.finish(f.io);
        const ended = if (f.pumpBack(s.conn.reader(), s.local.w, s.back)) true else |_| false;
        if (s.back.chunks.load(.monotonic) == 0) f.noteRefusal(s.conn, s.host);
        if (!ended) s.conn.abandon(f.io);
        if (ended) s.local.closeBoth(f.io) else s.local.reset(f.io);
    }
};

const Downlink = struct {
    flow: *const Flow,
    conn: *Upstream,
    host: []const u8,
    tls: ?*tls13.RecordReader,
    raw: *Io.Reader,
    local: *Local,
    uuid: [16]u8,
    vision: bool,
    traffic: *vision.Traffic,
    back: *Back,
    filter: vision.ServerHelloFilter = .{},

    /// Content for the application (also the sink of the unpadder).
    pub fn content(d: *Downlink, bytes: []const u8) Io.Writer.Error!void {
        if (bytes.len == 0) return;
        if (d.vision) d.filter.feed(bytes, d.traffic);
        try d.local.w.writeAll(bytes);
        d.flow.down(bytes.len);
        _ = d.back.chunks.fetchAdd(1, .monotonic);
    }

    fn run(d: *Downlink) void {
        defer d.back.finish(d.flow.io);
        const ended = if (d.loop()) true else |_| false;
        if (d.back.chunks.load(.monotonic) == 0) d.flow.noteRefusal(d.conn, d.host);
        if (!ended) d.conn.abandon(d.flow.io);
        if (ended) d.local.closeBoth(d.flow.io) else d.local.reset(d.flow.io);
    }

    fn loop(d: *Downlink) !void {
        var header: ResponseHeader = .{};
        var unpad: vision.Unpadder = .init(d.uuid);
        var use_tls = d.tls != null;
        while (true) {
            var raw_len: usize = 0;
            const data: []const u8 = if (use_tls)
                (try d.tls.?.next()) orelse return
            else blk: {
                const chunk = d.raw.peekGreedy(1) catch |err| switch (err) {
                    error.EndOfStream => return,
                    else => return err,
                };
                raw_len = chunk.len;
                break :blk chunk;
            };
            const body = try header.strip(data);
            if (d.vision) {
                const res = try unpad.feed(body, d);
                if (res.direct) {
                    // the rest of this record (normally empty), then raw TCP;
                    // bytes already read past the record stay in `raw`
                    try d.content(body[res.consumed..]);
                    use_tls = false;
                    d.flow.mark("direct_down");
                }
            } else {
                try d.content(body);
            }
            try d.local.w.flush();
            d.raw.toss(raw_len);
        }
    }
};

pub const ResponseHeader = struct {
    state: enum { version, addons_len, addons, done } = .version,
    left: u8 = 0,

    pub fn strip(h: *ResponseHeader, d: []const u8) error{BadVlessResponse}![]const u8 {
        var i: usize = 0;
        while (h.state != .done and i < d.len) {
            switch (h.state) {
                .version => {
                    if (d[i] != 0) return error.BadVlessResponse;
                    i += 1;
                    h.state = .addons_len;
                },
                .addons_len => {
                    h.left = d[i];
                    i += 1;
                    h.state = if (h.left == 0) .done else .addons;
                },
                .addons => {
                    const n: u8 = @intCast(@min(h.left, d.len - i));
                    i += n;
                    h.left -= n;
                    if (h.left == 0) h.state = .done;
                },
                .done => unreachable,
            }
        }
        return d[i..];
    }
};

/// Whole TLS records at the front of `cr`, waiting for the first to complete.
fn completeRecords(cr: *Io.Reader) Io.Reader.Error![]const u8 {
    const head = try cr.peek(5);
    if (!vision.isRecordHeader(head)) return cr.peekGreedy(1);
    var total: usize = 5 + std.mem.readInt(u16, head[3..5], .big);
    if (total > cr.buffer.len) return cr.peekGreedy(1);
    _ = try cr.peek(total);
    const buffered = cr.buffered();
    while (buffered.len - total >= 5 and vision.isRecordHeader(buffered[total..])) {
        const next = total + 5 + std.mem.readInt(u16, buffered[total + 3 ..][0..2], .big);
        if (next > buffered.len) break;
        total = next;
    }
    return buffered[0..total];
}

// ---------------------------------------------------------------- outbound snapshot

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

// ---------------------------------------------------------------- SOCKS5 inbound

pub const Proxy = struct {
    io: Io,
    port: u16 = 0,
    outbound: Outbound = .direct,
    dialer: Dialer = .{},
    meter: Meter = .{},
    /// a second meter fed by every flow (for example the service totals)
    extra: ?*Meter = null,

    server: ?net.Server = null,
    running: std.atomic.Value(bool) = .init(false),
    accept_thread: ?std.Thread = null,
    /// connections being served; `stop` waits for them, since each of
    /// their threads still uses this Proxy
    handlers: std.atomic.Value(u32) = .init(0),
    /// tells flows that only wait for a server to finish to give up
    stopping: std.atomic.Value(bool) = .init(false),

    pub fn setOutbound(p: *Proxy, o: Outbound) void {
        std.debug.assert(!p.running.load(.acquire));
        p.outbound = o;
    }

    /// Listen on 127.0.0.1:`port` (0 = any free port, see `p.port` after).
    /// Strings in the outbound are copied, the caller's may go away.
    pub fn start(p: *Proxy, port: u16) !void {
        if (p.running.load(.acquire)) return;
        const address: net.IpAddress = .{ .ip4 = .loopback(port) };
        var server = try address.listen(p.io, .{ .reuse_address = true });
        errdefer server.deinit(p.io);
        p.port = server.socket.address.getPort();
        p.server = server;
        p.meter.fault.store(.none, .monotonic);
        p.stopping.store(false, .release);
        p.running.store(true, .release);
        p.accept_thread = try std.Thread.spawn(.{}, acceptLoop, .{ p, Snapshot.of(p.outbound) });
    }

    pub fn stop(p: *Proxy) void {
        if (!p.running.swap(false, .acq_rel)) return;
        // wake the blocked accept with a throwaway connection
        const address: net.IpAddress = .{ .ip4 = .loopback(p.port) };
        if (address.connect(p.io, .{ .mode = .stream })) |s| s.close(p.io) else |_| {}
        if (p.accept_thread) |t| t.join();
        p.accept_thread = null;
        if (p.server) |*s| s.deinit(p.io);
        p.server = null;
        // let the connections in flight end: a few seconds for those whose
        // application is still there, the rest is left to the process
        p.stopping.store(true, .release);
        var waited_ms: u32 = 0;
        while (p.handlers.load(.acquire) > 0 and waited_ms < 5000) : (waited_ms += 2) {
            p.io.sleep(.fromMilliseconds(2), .awake) catch {};
        }
    }

    fn acceptLoop(p: *Proxy, snap: Snapshot) void {
        while (p.running.load(.acquire)) {
            const client = p.server.?.accept(p.io) catch continue;
            if (!p.running.load(.acquire)) {
                client.close(p.io);
                break;
            }
            _ = p.handlers.fetchAdd(1, .acq_rel);
            const t = std.Thread.spawn(.{ .stack_size = sys.stackSize(dial_stack_size) }, handle, .{ p, client, snap }) catch {
                _ = p.handlers.fetchSub(1, .acq_rel);
                client.close(p.io);
                continue;
            };
            t.detach();
        }
    }

    fn handle(p: *Proxy, client: net.Stream, snap: Snapshot) void {
        // last: nothing of `p` is touched after the count goes down
        defer _ = p.handlers.fetchSub(1, .acq_rel);
        const io = p.io;
        defer client.close(io);
        p.serve(client, &snap) catch {};
    }

    fn serve(p: *Proxy, client: net.Stream, snap: *const Snapshot) !void {
        const io = p.io;
        var crb: [tls13.min_read_buffer]u8 = undefined;
        var cwb: [4096]u8 = undefined;
        var cr = client.reader(io, &crb);
        var cw = client.writer(io, &cwb);
        var local: Local = .{ .r = &cr.interface, .w = &cw.interface, .end = .{ .socks = client } };
        const target = try socksRequest(local.r, local.w);
        const flow: Flow = .{ .io = io, .dialer = p.dialer, .meters = .{ &p.meter, p.extra, null }, .stop = &p.stopping };
        const ob = snap.get();
        try flow.run(&local, &target, &ob);
    }
};

fn socksRequest(r: *Io.Reader, w: *Io.Writer) !Target {
    // greeting: VER NMETHODS METHODS...
    if (try r.takeByte() != 5) return error.NotSocks5;
    const nmethods = try r.takeByte();
    _ = try r.take(nmethods);
    try w.writeAll(&.{ 5, 0 }); // no authentication
    try w.flush();

    // request: VER CMD RSV ATYP ADDR PORT
    const head = (try r.takeArray(4)).*;
    if (head[0] != 5) return error.NotSocks5;
    var target: Target = undefined;
    switch (head[3]) {
        1 => {
            target = .{ .kind = .ip4, .len = 4, .port = 0 };
            @memcpy(target.bytes[0..4], try r.take(4));
        },
        3 => {
            const n = try r.takeByte();
            target = .{ .kind = .domain, .len = n, .port = 0 };
            @memcpy(target.bytes[0..n], try r.take(n));
        },
        4 => {
            target = .{ .kind = .ip6, .len = 16, .port = 0 };
            @memcpy(target.bytes[0..16], try r.take(16));
        },
        else => {
            try reply(w, 8);
            return error.BadAddress;
        },
    }
    target.port = std.mem.readInt(u16, try r.takeArray(2), .big);
    if (head[1] != 1) { // only CONNECT
        try reply(w, 7);
        return error.UnsupportedCommand;
    }
    return target;
}

fn reply(w: *Io.Writer, code: u8) !void {
    try w.writeAll(&.{ 5, code, 0, 1, 0, 0, 0, 0, 0, 0 });
    try w.flush();
}

/// Copy until the source ends.
fn pump(from: *Io.Reader, to: *Io.Writer) !void {
    while (true) {
        const chunk = from.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        try to.writeAll(chunk);
        try to.flush();
        from.toss(chunk.len);
    }
    try to.flush();
}

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

test "a connection's layer: only what the protocol and the transport need" {
    const t = std.testing;
    const uuid = "11111111-2222-3333-4444-555555555555";
    const total = struct {
        fn of(link: []const u8) !?usize {
            const ob = try outboundFromLink(link, "h", 443);
            const v = ob.via().?;
            const p = Plan.of(&ob, &v, v.tls != null or v.reality != null) orelse return null;
            return p.buffers();
        }
    }.of;
    // VLESS on the stream itself has no layer at all
    try t.expectEqual(null, try total("vless://" ++ uuid ++ "@h:443?security=tls"));
    try t.expectEqual(null, try total("vless://" ++ uuid ++ "@h:443"));
    // WebSocket inside TLS as it always was
    try t.expectEqual(52 * 1024, (try total("vless://" ++ uuid ++ "@h:443?type=ws&security=tls")).?);
    // Trojan: the TLS stream the copy loop reads from
    try t.expectEqual(16 * 1024, (try total("trojan://pw@h:443")).?);
    // gRPC: a message buffer each way
    try t.expect((try total("trojan://pw@h:443?type=grpc")).? < 33 * 1024);
    // a cipher brings its own buffers, and what is below it shrinks
    try t.expect((try total("vmess://" ++ uuid ++ "@h:443?security=tls")).? < 26 * 1024);
    try t.expect((try total("ss://YWVzLTI1Ni1nY206cHc@h:443")).? < 36 * 1024);
    // the layer itself is small: a transport's state comes only with the transport
    try t.expect(@sizeOf(Layer) < 256);

    // the block holds everything a dial takes from it, in the dial's order,
    // wherever alignment puts the transport's and the cipher's state
    const kinds = [_][]const u8{ "vless://" ++ uuid, "trojan://pw", "vmess://" ++ uuid, "ss://YWVzLTI1Ni1nY206cHc", "ss://2022-blake3-aes-256-gcm:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D" };
    const transports = [_][]const u8{ "tcp", "ws", "httpupgrade", "grpc", "xhttp&mode=stream-one" };
    const securities = [_][]const u8{ "none", "tls" };
    var carved: usize = 0;
    for (kinds) |kind| for (transports) |tr| for (securities) |sec| {
        var buf: [256]u8 = undefined;
        const link = try std.fmt.bufPrint(&buf, "{s}@h:443?type={s}&security={s}", .{ kind, tr, sec });
        const ob = outboundFromLink(link, "h", 443) catch continue; // Trojan without TLS, Shadowsocks in a transport
        const v = ob.via().?;
        const tls = v.tls != null;
        const p = Plan.of(&ob, &v, tls) orelse continue;
        const l = try Layer.create(p);
        defer l.destroy();
        if (tls) _ = .{ l.take(p.sr), l.take(p.sw) };
        switch (v.transport.*) {
            .raw => {},
            .ws => _ = l.make(ws.Conn),
            .httpupgrade => _ = l.make(httpupgrade.Conn),
            .grpc => _ = l.make(grpc.Conn),
            .xhttp => _ = l.make(xhttp.Conn),
        }
        _ = .{ l.take(p.tr), l.take(p.tw) };
        switch (ob) {
            .vmess => _ = l.make(vmess.Conn),
            .shadowsocks => _ = l.make(shadowsocks.Conn),
            else => {},
        }
        _ = .{ l.take(p.cr), l.take(p.cw) };
        try t.expect(l.used <= l.block.len and l.block.len - l.used < 3 * Layer.block_align);
        carved += 1;
    };
    try t.expectEqual(5 * 2 + 5 + 5 * 2 + 2 - 2, carved);
}

test "vless header layout" {
    var t: Target = .{ .kind = .domain, .len = 11, .port = 443 };
    @memcpy(t.bytes[0..11], "example.com");
    var buf: [vless_header_max]u8 = undefined;
    const h = vlessHeader(&buf, @splat(0xAB), &t, false);
    try std.testing.expectEqual(1 + 16 + 1 + 1 + 2 + 1 + 1 + 11, h.len);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 0x01, 0xBB, 2, 11 }, h[17..23]);
    try std.testing.expectEqualStrings("example.com", h[23..]);

    const hv = vlessHeader(&buf, @splat(0xAB), &t, true);
    try std.testing.expectEqualSlices(u8, &.{ 18, 0x0a, 16 }, hv[17..20]);
    try std.testing.expectEqualStrings("xtls-rprx-vision", hv[20..36]);
    try std.testing.expectEqual(1, hv[36]);
}

// ---------------------------------------------------------------- loopback tests

const TestPeer = struct {
    server: net.Server,
    port: u16,
    thread: std.Thread = undefined,
    /// when set, expect a VLESS request with this UUID before echoing
    vless_uuid: ?[16]u8 = null,
    header_ok: bool = false,
    /// answer an HTTP/1.1 upgrade request first, as an HTTPUpgrade server
    upgrade: bool = false,
    upgrade_ok: bool = false,

    fn init(io: Io) !TestPeer {
        const address: net.IpAddress = .{ .ip4 = .loopback(0) };
        const server = try address.listen(io, .{ .reuse_address = true });
        return .{ .server = server, .port = server.socket.address.getPort() };
    }

    fn run(peer: *TestPeer, io: Io) void {
        const s = peer.server.accept(io) catch return;
        defer s.close(io);
        var rb: [4096]u8 = undefined;
        var wb: [4096]u8 = undefined;
        var r = s.reader(io, &rb);
        var w = s.writer(io, &wb);
        if (peer.upgrade) {
            var first = true;
            while (true) {
                const line = r.interface.takeDelimiterInclusive('\n') catch return;
                if (first) peer.upgrade_ok = std.mem.eql(u8, line, "GET /up HTTP/1.1\r\n");
                first = false;
                if (line.len == 2) break;
            }
            w.interface.writeAll("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n") catch return;
            w.interface.flush() catch return;
        }
        if (peer.vless_uuid) |uuid| {
            const h = (r.interface.takeArray(1 + 16 + 1 + 1 + 2 + 1) catch return).*;
            const addr_ok = h[21] == 1 and std.mem.eql(u8, r.interface.take(4) catch return, &.{ 10, 9, 8, 7 });
            peer.header_ok = h[0] == 0 and std.mem.eql(u8, h[1..17], &uuid) and h[17] == 0 and h[18] == 1 and
                std.mem.readInt(u16, h[19..21], .big) == 4242 and addr_ok;
            w.interface.writeAll(&.{ 0, 0 }) catch return;
        }
        pump(&r.interface, &w.interface) catch {};
    }
};

fn socksRoundTrip(io: Io, proxy_port: u16, dest: [4]u8, dest_port: u16, payload: []const u8) !void {
    const address: net.IpAddress = .{ .ip4 = .loopback(proxy_port) };
    const s = try address.connect(io, .{ .mode = .stream });
    defer s.close(io);
    var rb: [4096]u8 = undefined;
    var wb: [4096]u8 = undefined;
    var r = s.reader(io, &rb);
    var w = s.writer(io, &wb);
    try w.interface.writeAll(&.{ 5, 1, 0 });
    try w.interface.flush();
    try std.testing.expectEqualSlices(u8, &.{ 5, 0 }, try r.interface.takeArray(2));
    try w.interface.writeAll(&.{ 5, 1, 0, 1 });
    try w.interface.writeAll(&dest);
    try w.interface.writeInt(u16, dest_port, .big);
    try w.interface.flush();
    const rep = try r.interface.takeArray(10);
    if (rep[1] != 0) return error.Refused;
    try w.interface.writeAll(payload);
    try w.interface.flush();
    try std.testing.expectEqualStrings(payload, try r.interface.take(payload.len));
}

test "socks5 -> direct carries bytes and counts them" {
    const io = std.testing.io;
    var peer: TestPeer = try .init(io);
    defer peer.server.deinit(io);
    peer.thread = try std.Thread.spawn(.{}, TestPeer.run, .{ &peer, io });

    var p: Proxy = .{ .io = io };
    try p.start(0);
    defer p.stop();
    try socksRoundTrip(io, p.port, .{ 127, 0, 0, 1 }, peer.port, "hello through direct");
    peer.thread.join();
    try std.testing.expectEqual(20, p.meter.up.load(.monotonic));
    try std.testing.expectEqual(20, p.meter.down.load(.monotonic));
}

test "socks5 -> vless sends a valid request and strips the response header" {
    const io = std.testing.io;
    var peer: TestPeer = try .init(io);
    defer peer.server.deinit(io);
    const uuid = parseUuid("11111111-2222-3333-4444-555555555555").?;
    peer.vless_uuid = uuid;
    peer.thread = try std.Thread.spawn(.{}, TestPeer.run, .{ &peer, io });

    var p: Proxy = .{ .io = io };
    p.setOutbound(.{ .vless = .{ .host = "127.0.0.1", .port = peer.port, .uuid = uuid } });
    try p.start(0);
    defer p.stop();
    // the destination only travels inside the VLESS header
    try socksRoundTrip(io, p.port, .{ 10, 9, 8, 7 }, 4242, "hello through vless");
    peer.thread.join();
    try std.testing.expect(peer.header_ok);
    try std.testing.expectEqual(19, p.meter.down.load(.monotonic));
}

test "socks5 -> vless inside HTTPUpgrade: the transport's layer carries the flow" {
    const io = std.testing.io;
    var peer: TestPeer = try .init(io);
    defer peer.server.deinit(io);
    const uuid = parseUuid("11111111-2222-3333-4444-555555555555").?;
    peer.vless_uuid = uuid;
    peer.upgrade = true;
    peer.thread = try std.Thread.spawn(.{}, TestPeer.run, .{ &peer, io });

    var link_buf: [128]u8 = undefined;
    const link = try std.fmt.bufPrint(&link_buf, "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:{d}?type=httpupgrade&path=%2Fup&host=up.example", .{peer.port});
    var p: Proxy = .{ .io = io };
    p.setOutbound(try outboundFromLink(link, "127.0.0.1", peer.port));
    try p.start(0);
    defer p.stop();
    try socksRoundTrip(io, p.port, .{ 10, 9, 8, 7 }, 4242, "hello through httpupgrade");
    peer.thread.join();
    try std.testing.expect(peer.upgrade_ok and peer.header_ok);
    try std.testing.expectEqual(25, p.meter.down.load(.monotonic));
    try std.testing.expectEqual(Fault.none, p.meter.fault.load(.monotonic));
}

test "socks5 -> block refuses the connection" {
    const io = std.testing.io;
    var p: Proxy = .{ .io = io };
    p.setOutbound(.block);
    try p.start(0);
    defer p.stop();
    try std.testing.expectError(error.Refused, socksRoundTrip(io, p.port, .{ 127, 0, 0, 1 }, 9, "x"));
}

test "a TUN connection relayed direct to a loopback server" {
    // application <-> stack (emulated kernel) <-> Flow(direct) <-> echo server
    const io = std.testing.io;
    var peer: TestPeer = try .init(io);
    defer peer.server.deinit(io);
    peer.thread = try std.Thread.spawn(.{}, TestPeer.run, .{ &peer, io });

    const App = struct {
        gpa: std.mem.Allocator,
        mutex: Io.Mutex = .init,
        out: std.ArrayList([]u8) = .empty,
        conn: ?*tcp.Conn = null,
        fn write(ctx: *anyopaque, pkt: []const u8) void {
            const a: *@This() = @ptrCast(@alignCast(ctx));
            a.mutex.lockUncancelable(std.testing.io);
            defer a.mutex.unlock(std.testing.io);
            a.out.append(a.gpa, a.gpa.dupe(u8, pkt) catch unreachable) catch unreachable;
        }
        fn onTcp(ctx: *anyopaque, c: *tcp.Conn) bool {
            const a: *@This() = @ptrCast(@alignCast(ctx));
            a.conn = c;
            return true;
        }
        fn onUdp(_: *anyopaque, _: packet.Endpoint, _: packet.Endpoint, _: []const u8) void {}
        fn take(a: *@This()) ?[]u8 {
            a.mutex.lockUncancelable(std.testing.io);
            defer a.mutex.unlock(std.testing.io);
            if (a.out.items.len == 0) return null;
            return a.out.orderedRemove(0);
        }
    };
    var app: App = .{ .gpa = std.testing.allocator };
    defer {
        for (app.out.items) |b| app.gpa.free(b);
        app.out.deinit(app.gpa);
    }
    const stack = try tcp.Stack.create(std.testing.allocator, io, .{}, .{ .ctx = &app, .write = App.write }, .{ .ctx = &app, .tcp = App.onTcp, .udp = App.onUdp });
    defer stack.destroy();

    const me: packet.Endpoint = .{ .addr = packet.v4(.{ 198, 18, 0, 1 }), .port = 40000 };
    const there: packet.Endpoint = .{ .addr = packet.v4(.{ 127, 0, 0, 1 }), .port = peer.port };
    var pkt: [2048]u8 = undefined;
    stack.input(pkt[0..packet.writeTcp(&pkt, me, there, .{ .seq = 1, .ack = 0, .flags = .{ .syn = true }, .window = 65535, .mss = 1400 })]);

    const Worker = struct {
        fn run(c: *tcp.Conn, port: u16) void {
            var rb: [tls13.min_read_buffer]u8 = undefined;
            var wb: [4096]u8 = undefined;
            var r: tcp.Reader = .init(c, &rb);
            var w: tcp.Writer = .init(c, &wb);
            var local: Local = .{ .r = &r.interface, .w = &w.interface, .end = .{ .tun = c } };
            var meter: Meter = .{};
            const flow: Flow = .{ .io = std.testing.io, .meters = .{ &meter, null, null } };
            const target = Target.fromEndpoint(.{ .addr = packet.v4(.{ 127, 0, 0, 1 }), .port = port });
            const ob: Outbound = .direct;
            flow.run(&local, &target, &ob) catch {};
            c.release();
        }
    };
    const th = try std.Thread.spawn(.{}, Worker.run, .{ app.conn.?, peer.port });

    // wait for the SYN-ACK, then complete the handshake and send data + FIN
    const synack = while (true) {
        if (app.take()) |b| break b;
        std.Thread.yield() catch {};
    };
    defer app.gpa.free(synack);
    const sa = packet.parseTcp(packet.parseIp(synack).?.l4).?;
    try std.testing.expect(sa.flags.syn and sa.flags.ack);
    stack.input(pkt[0..packet.writeTcp(&pkt, me, there, .{ .seq = 2, .ack = sa.seq +% 1, .flags = .{ .ack = true }, .window = 65535 })]);
    stack.input(pkt[0..packet.writeTcp(&pkt, me, there, .{ .seq = 2, .ack = sa.seq +% 1, .flags = .{ .ack = true, .psh = true, .fin = true }, .window = 65535, .payload = "ping over tun" })]);
    stack.flush();

    // collect the echo until the stack's FIN
    var echoed: std.ArrayList(u8) = .empty;
    defer echoed.deinit(std.testing.allocator);
    var got_fin = false;
    var ack_to = sa.seq +% 1;
    while (!got_fin) {
        const b = app.take() orelse {
            std.Thread.yield() catch {};
            continue;
        };
        defer app.gpa.free(b);
        const t = packet.parseTcp(packet.parseIp(b).?.l4).?;
        try echoed.appendSlice(std.testing.allocator, t.payload);
        ack_to = t.seq +% @as(u32, @intCast(t.payload.len)) +% @intFromBool(t.flags.fin);
        if (t.flags.fin) got_fin = true;
        stack.input(pkt[0..packet.writeTcp(&pkt, me, there, .{ .seq = 16, .ack = ack_to, .flags = .{ .ack = true }, .window = 65535 })]);
    }
    th.join();
    peer.thread.join();
    try std.testing.expectEqualStrings("ping over tun", echoed.items);
    stack.abortAll();
    _ = stack.tick();
}
