//! Outbounds, and the local SOCKS5 inbound.
//!
//! A flow has a local side (an application on the SOCKS port, or a TCP
//! connection terminated by the TUN stack) and goes out direct, blocked,
//! or over VLESS: on raw TCP (optionally REALITY and the Vision flow), or
//! inside WebSocket, both optionally inside TLS. With Vision, once the inner
//! connection is TLS 1.3 both directions switch to raw TCP, so bulk traffic
//! is encrypted only once.
//! Not yet: XHTTP / gRPC transports.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const net = Io.net;
const tls13 = @import("tls13.zig");
const ws = @import("ws.zig");
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
        fn setDecoded(t: *Self, raw: []const u8) bool {
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

pub const Transport = union(enum) {
    /// VLESS straight on the (TLS) stream
    raw,
    /// VLESS in WebSocket binary frames
    ws: struct {
        path: Text(512) = .{},
        /// Host header; a CDN routes by it
        host: Text(255) = .{},
    },
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

pub const Outbound = union(enum) {
    direct,
    block,
    vless: Vless,
};

pub const LinkError = error{
    NotVless,
    BadUuid,
    UnsupportedTransport,
    UnsupportedSecurity,
    UnsupportedFlow,
    BadRealityKey,
};

/// What of a `vless://` link this build can actually carry. Slices in the
/// result point into `link` and `host`.
pub fn vlessFromLink(link: []const u8, host: []const u8, port: u16) LinkError!Vless {
    const prefix = "vless://";
    if (!std.ascii.startsWithIgnoreCase(link, prefix)) return error.NotVless;
    const rest = link[prefix.len..];
    const at = std.mem.indexOfScalar(u8, rest, '@') orelse return error.BadUuid;
    const uuid = parseUuid(rest[0..at]) orelse return error.BadUuid;

    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, '?')) |q| {
        const end = std.mem.indexOfScalarPos(u8, rest, q, '#') orelse rest.len;
        query = rest[q + 1 .. end];
    }
    var security: []const u8 = "";
    var transport: []const u8 = "";
    var flow: []const u8 = "";
    var sni: []const u8 = "";
    var pbk: []const u8 = "";
    var sid: []const u8 = "";
    var path: []const u8 = "";
    var host_header: []const u8 = "";
    var alpn: []const u8 = "";
    var it = std.mem.tokenizeScalar(u8, query, '&');
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        const k = kv[0..eq];
        const v = kv[eq + 1 ..];
        if (std.mem.eql(u8, k, "security")) security = v;
        if (std.mem.eql(u8, k, "type")) transport = v;
        if (std.mem.eql(u8, k, "flow")) flow = v;
        if (std.mem.eql(u8, k, "sni")) sni = v;
        if (std.mem.eql(u8, k, "pbk")) pbk = v;
        if (std.mem.eql(u8, k, "sid")) sid = v;
        if (std.mem.eql(u8, k, "path")) path = v;
        if (std.mem.eql(u8, k, "host")) host_header = v;
        if (std.mem.eql(u8, k, "alpn")) alpn = v;
    }

    var out: Vless = .{ .host = host, .port = port, .uuid = uuid };
    if (transport.len == 0 or std.mem.eql(u8, transport, "tcp") or std.mem.eql(u8, transport, "raw")) {
        out.transport = .raw;
    } else if (std.mem.eql(u8, transport, "ws")) {
        out.transport = .{ .ws = .{} };
        const w = &out.transport.ws;
        if (!w.path.setDecoded(if (path.len > 0) path else "/")) return error.UnsupportedTransport;
        if (w.path.len == 0 or w.path.buf[0] != '/') return error.UnsupportedTransport;
        const h = if (host_header.len > 0) host_header else if (sni.len > 0) sni else host;
        if (!w.host.setDecoded(h)) return error.UnsupportedTransport;
    } else return error.UnsupportedTransport;

    if (flow.len > 0) {
        if (!std.mem.startsWith(u8, flow, "xtls-rprx-vision")) return error.UnsupportedFlow;
        // Vision splices raw TCP; it has no place inside WebSocket
        if (out.transport != .raw) return error.UnsupportedFlow;
        out.vision = true;
    }
    if (security.len == 0 or std.mem.eql(u8, security, "none")) {
        if (out.vision) return error.UnsupportedFlow; // Vision rides on an outer TLS layer
    } else if (std.mem.eql(u8, security, "reality")) {
        out.reality = .{
            .server_name = if (sni.len > 0) sni else host,
            .public_key = decodeKey(pbk) orelse return error.BadRealityKey,
            .short_id = decodeShortId(sid) orelse return error.BadRealityKey,
        };
    } else if (std.mem.eql(u8, security, "tls")) {
        if (out.vision) return error.UnsupportedFlow; // Vision over plain TLS: not carried
        var t: Tls = .{};
        // the certificate is checked against this name: sni, else the Host
        // the CDN routes by, else the address
        const name = if (sni.len > 0) sni else if (host_header.len > 0) host_header else host;
        if (!t.server_name.setDecoded(name)) return error.UnsupportedSecurity;
        // WebSocket needs HTTP/1.1; a link may narrow the offer further
        const has_h2 = std.mem.indexOf(u8, alpn, "h2") != null;
        const has_h11 = std.mem.indexOf(u8, alpn, "http") != null;
        t.alpn = if (out.transport == .ws or (has_h11 and !has_h2)) .http11 else if (has_h2 and !has_h11) .h2 else .h2_http11;
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

/// A connection to a VLESS server, dialed and (with REALITY) through the
/// TLS handshake, ready for a request header. It holds its own buffers, so
/// it must stay at one address once `dialVless` has filled it.
pub const Upstream = struct {
    stream: net.Stream,
    ur: if (sys.supported) sys.SockReader else net.Stream.Reader,
    uw: net.Stream.Writer,
    rr: tls13.RecordReader,
    rw: tls13.RecordWriter,
    tls: bool,
    urb: [tls13.min_read_buffer]u8,
    uwb: [4096]u8,
    /// a transport inside the stream (WebSocket); its buffers live on the heap
    layer: ?*Layer = null,
    /// HTTP status of a transport upgrade the server refused, for the log
    layer_status: u16 = 0,

    pub fn close(u: *Upstream, io: Io) void {
        if (u.layer) |l| {
            l.ws.close();
            std.heap.c_allocator.destroy(l);
            u.layer = null;
        }
        u.stream.close(io);
    }

    /// Where VLESS bytes go and come from: the transport if there is one,
    /// else the TLS records or the socket (the caller handles those).
    fn transportReader(u: *Upstream) ?*Io.Reader {
        return if (u.layer) |l| &l.ws.reader else null;
    }
    fn transportWriter(u: *Upstream) ?*Io.Writer {
        return if (u.layer) |l| &l.ws.writer else null;
    }
};

/// A WebSocket inside TLS (or on the socket).
const Layer = struct {
    sr: tls13.StreamReader,
    sw: tls13.StreamWriter,
    ws: ws.Conn,
    srb: [16 * 1024]u8,
    swb: [4096]u8,
    rb: [16 * 1024]u8,
    wb: [16 * 1024]u8,
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
            .vless => |v| try f.runVless(v, local, target),
        }
    }

    fn relayPlain(f: *const Flow, local: *Local, upstream: net.Stream) !void {
        var urb: [16 * 1024]u8 = undefined;
        var uwb: [4096]u8 = undefined;
        var ur = upstream.reader(f.io, &urb);
        var uw = upstream.writer(f.io, &uwb);
        var bk: Back = .{};
        const back = try std.Thread.spawn(.{ .stack_size = 64 * 1024 }, relayBack, .{ f, &ur.interface, local, &bk });
        if (f.pumpCounted(local.r, &uw.interface, .up)) {
            upstream.shutdown(f.io, .send) catch {};
            f.linger(&bk, upstream);
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
    fn linger(f: *const Flow, bk: *Back, upstream: net.Stream) void {
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
            if (quiet_ms >= linger_ms or stopping) {
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

    /// Connect to the server of `v`, run the TLS or REALITY handshake if it
    /// has one, and open its transport.
    pub fn dialVless(f: *const Flow, v: Vless, u: *Upstream) !void {
        f.dialVlessInner(v, u) catch |err| {
            noteDialFailure(f.io, v.host, err, if (u.layer_status != 0) u.layer_status else null);
            return err;
        };
    }

    fn dialVlessInner(f: *const Flow, v: Vless, u: *Upstream) !void {
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
        switch (v.transport) {
            .raw => {},
            .ws => |w| {
                const l = try std.heap.c_allocator.create(Layer);
                errdefer std.heap.c_allocator.destroy(l);
                var below_r: *Io.Reader = &u.ur.interface;
                var below_w: *Io.Writer = &u.uw.interface;
                if (u.tls) {
                    l.sr = .init(&u.rr, &l.srb);
                    l.sw = .init(&u.rw, &l.swb);
                    below_r = &l.sr.interface;
                    below_w = &l.sw.interface;
                }
                l.ws = .init(io, below_r, below_w, &l.rb, &l.wb);
                l.ws.handshake(.{ .path = w.path.slice(), .host = w.host.slice() }) catch |err| {
                    u.layer_status = l.ws.status;
                    f.fault(.handshake);
                    return err;
                };
                u.layer = l;
            },
        }
    }

    fn runVless(f: *const Flow, v: Vless, local: *Local, target: *const Target) !void {
        const io = f.io;
        var conn: Upstream = undefined;
        f.dialVless(v, &conn) catch |err| {
            local.refuse(switch (err) {
                error.ConnectionRefused => 5,
                error.RealityAuthFailed => 1,
                else => if (up_fault(f) == .handshake or up_fault(f) == .reality_rejected) 1 else 4,
            });
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
            .tls = if (conn.tls and t_r == null) rr else null,
            .raw = t_r orelse &ur.interface,
            .local = local,
            .uuid = v.uuid,
            .vision = v.vision,
            .traffic = &traffic,
            .back = &bk,
        };
        const back = try std.Thread.spawn(.{ .stack_size = 128 * 1024 }, Downlink.run, .{&dl});
        const tls_w: ?*tls13.RecordWriter = if (conn.tls and t_w == null) rw else null;
        if (f.uplink(v, local, t_w orelse &uw.interface, tls_w, &traffic, target)) {
            upstream.shutdown(io, .send) catch {};
            f.linger(&bk, upstream);
        } else |_| {
            upstream.shutdown(io, .both) catch {};
        }
        back.join();
    }

    fn uplink(
        f: *const Flow,
        v: Vless,
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
const linger_step_ms = 200;

const Downlink = struct {
    flow: *const Flow,
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
        if (d.loop()) d.local.closeBoth(d.flow.io) else |_| d.local.reset(d.flow.io);
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
        if (o == .vless) {
            s.host_len = @intCast(@min(o.vless.host.len, s.host.len));
            @memcpy(s.host[0..s.host_len], o.vless.host[0..s.host_len]);
            if (o.vless.reality) |re| {
                s.sni_len = @intCast(@min(re.server_name.len, s.sni.len));
                @memcpy(s.sni[0..s.sni_len], re.server_name[0..s.sni_len]);
            }
        }
        return s;
    }

    /// The outbound with its strings pointing into this snapshot.
    pub fn get(s: *const Snapshot) Outbound {
        return switch (s.outbound) {
            .vless => |vv| blk: {
                var v = vv;
                v.host = s.host[0..s.host_len];
                if (v.reality) |*re| re.server_name = s.sni[0..s.sni_len];
                break :blk .{ .vless = v };
            },
            else => s.outbound,
        };
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
    }

    fn acceptLoop(p: *Proxy, snap: Snapshot) void {
        while (p.running.load(.acquire)) {
            const client = p.server.?.accept(p.io) catch continue;
            if (!p.running.load(.acquire)) {
                client.close(p.io);
                break;
            }
            const t = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, handle, .{ p, client, snap }) catch {
                client.close(p.io);
                continue;
            };
            t.detach();
        }
    }

    fn handle(p: *Proxy, client: net.Stream, snap: Snapshot) void {
        defer client.close(p.io);
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
        const flow: Flow = .{ .io = io, .dialer = p.dialer, .meters = .{ &p.meter, p.extra, null } };
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
    try std.testing.expectError(error.UnsupportedTransport, vlessFromLink("vless://11111111-2222-3333-4444-555555555555@h:1?type=grpc", "h", 1));

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
    try std.testing.expectError(error.NotVless, vlessFromLink("trojan://p@h:1", "h", 1));
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
