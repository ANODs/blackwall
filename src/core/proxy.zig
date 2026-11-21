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
const sniff = @import("sni.zig");
const dpi = @import("dpi.zig");
const packet = @import("ipstack/packet.zig");
const tcp = @import("ipstack/stack.zig");
const dns = @import("ipstack/dns.zig");

const outbound = @import("outbound.zig");
// What a server is (outbound.zig), under the names the rest of the code uses.
pub const Reality = outbound.Reality;
pub const Text = outbound.Text;
pub const Tls = outbound.Tls;
pub const Http = outbound.Http;
pub const Grpc = outbound.Grpc;
pub const Xhttp = outbound.Xhttp;
pub const Transport = outbound.Transport;
pub const Vless = outbound.Vless;
pub const Via = outbound.Via;
pub const Outbound = outbound.Outbound;
pub const LinkError = outbound.LinkError;
pub const Target = outbound.Target;
pub const Snapshot = outbound.Snapshot;
pub const carries = outbound.carries;
pub const outboundFromLink = outbound.outboundFromLink;
pub const vlessFromLink = outbound.vlessFromLink;
pub const parseUuid = outbound.parseUuid;
const xhttpOptions = outbound.xhttpOptions;

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
/// `os_status`: on Windows, the NTSTATUS a failed read ended with (0: none).
fn noteDialFailure(io: Io, host: []const u8, err: anyerror, http_status: ?u16, os_status: u32) void {
    const now = Io.Clock.awake.now(io).toMilliseconds();
    const last = dial_log_ms.load(.monotonic);
    if (last != 0 and now - last < 5000) {
        _ = dial_log_skipped.fetchAdd(1, .monotonic);
        return;
    }
    if (dial_log_ms.cmpxchgStrong(last, now, .monotonic, .monotonic) != null) return;
    const more = dial_log_skipped.swap(0, .monotonic);
    if (os_status != 0)
        std.log.scoped(.proxy).warn("server {s}: {t}, status 0x{x:0>8} (+{d} more failures)", .{ host, err, os_status, more })
    else if (http_status) |st|
        std.log.scoped(.proxy).warn("server {s}: {t}, HTTP {d} (+{d} more failures)", .{ host, err, st, more })
    else
        std.log.scoped(.proxy).warn("server {s}: {t} (+{d} more failures)", .{ host, err, more });
}

/// A server that accepted the connection finishes the TLS and transport
/// handshakes within this time, or the dial fails.
pub const handshake_timeout_ms = 10_000;

/// A transport request answered with 5xx came from a front that is up but
/// could not reach its backend at that moment (502 Bad Gateway, 503, 504,
/// a CDN's 52x). Some servers do that now and then, and a new connection
/// a moment later usually gets through. Xray dials again after any
/// failure, up to five times with waits of 0.2, 0.4, 0.8 and 1.6 s, so its
/// users never see those answers; we wait the same way, but for this case
/// only. Any other failure ends the dial at once: a server that is down or
/// turns us away is found out (and the reserve taken) without delay. With
/// early data the answer comes after the dial, the application's first
/// bytes already in the request: such a refusal still fails the flow.
const redial_attempts = 5;
const redial_first_ms = 200;

fn redialable(err: anyerror, http_status: u16) bool {
    return switch (err) {
        error.WsUpgradeRefused, error.HttpUpgradeRefused => http_status >= 500 and http_status <= 599,
        else => false,
    };
}

/// Stack of a thread that dials a server. The TLS handshake (its ML-KEM key
/// pair above all) goes about 175 KiB deep in a release build and 260 KiB
/// in a debug one, under the thread's own buffers. Only pages that are
/// touched cost memory.
pub const dial_stack_size = 512 * 1024;

/// How outbound connections are made.
/// Unbound sockets also connect with a deadline.
const plain_timed = builtin.abi.isAndroid();

pub const Dialer = struct {
    /// keep our own sockets off the TUN
    bind: sys.Bind = .none,
    /// resolve names here instead of through the system (whose DNS points
    /// at our own fake-IP server while the TUN is up)
    resolver: ?*dns.Resolver = null,
    timeout_ms: i32 = 10_000,

    /// The address of `host` (an IP, or a name), resolved the way
    /// `connect` would: through `resolver` when there is one.
    pub fn resolve(d: *const Dialer, io: Io, host: []const u8) !packet.Addr {
        if (net.IpAddress.parse(host, 0)) |ip| {
            const a, _ = sys.fromIpAddress(ip);
            return a;
        } else |_| {}
        if (d.resolver) |r| return r.resolve(host);
        const name = try net.HostName.init(host);
        var results: [16]net.HostName.LookupResult = undefined;
        var q: Io.Queue(net.HostName.LookupResult) = .init(&results);
        try name.lookup(io, &q, .{ .port = 0 });
        while (q.getOne(io)) |res| switch (res) {
            .address => |ip| {
                const a, _ = sys.fromIpAddress(ip);
                return a;
            },
            .canonical_name => {},
        } else |_| {}
        return error.UnknownHostName;
    }

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
        // Android leaves our package out of the VPN, so nothing is bound
        // there; the connect must still give up in time
        if (d.bind == .none and !plain_timed) return sys.toIpAddress(a, port).connect(io, .{ .mode = .stream });
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
    ur: sys.SockReader,
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
    /// Why the last attempt to dial failed. The meters get it only when
    /// `Flow.dial` gives up: a redial that works is no fault to report.
    fault: Fault = .none,

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
    pub fn reader(u: *Upstream) *Io.Reader {
        const l = u.layer.?;
        return switch (l.cipher) {
            .none => l.r,
            inline else => |c| &c.reader,
        };
    }
    pub fn writer(u: *Upstream) *Io.Writer {
        const l = u.layer.?;
        return switch (l.cipher) {
            .none => l.w,
            inline else => |c| &c.writer,
        };
    }

    /// VMess opened for UDP: its cipher with a mux request, whose frames
    /// (XUDP) name each datagram's peer. Nothing leaves until a flush.
    pub fn attachMux(u: *Upstream, io: Io, ob: *const Outbound) !void {
        const v = &ob.vmess;
        const l = u.layer orelse return error.NoLayer;
        const p = Plan.of(ob, &ob.via().?, u.tls).?;
        const c = l.make(vmess.Conn);
        c.* = .init(io, v.user, v.security, l.r, l.w, l.take(p.cr), l.take(p.cw));
        l.cipher = .{ .vmess = c };
        try c.writeRequest(.{ .command = .mux });
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
    /// told already (the tunnel may accept before it dials, to read the
    /// name the application asks for)
    accepted: bool = false,

    /// The outbound is ready: tell the application it is connected.
    pub fn ready(l: *Local) !void {
        if (l.accepted) return;
        l.accepted = true;
        switch (l.end) {
            .socks => try socksReply(l.w, 0),
            .tun => |c| try c.accept(),
        }
    }

    /// The flow cannot be served (`code` is the SOCKS reply code).
    pub fn refuse(l: *Local, code: u8) void {
        switch (l.end) {
            .socks => socksReply(l.w, code) catch {},
            .tun => |c| c.reject(),
        }
    }

    pub fn waitReadable(l: *Local, ms: u32) bool {
        if (l.r.buffered().len > 0) return true;
        return switch (l.end) {
            .socks => |s| sys.waitFd(s.socket.handle, false, @intCast(ms)),
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
            .dpi => try f.runDpi(local, target),
            .vless => try f.runVless(ob, local, target),
            .trojan, .shadowsocks, .vmess => try f.runStream(ob, local, target),
        }
    }

    /// Direct, with the first flight shaped past DPI (dpi.zig): the
    /// application is told it is connected first, its ClientHello (or HTTP
    /// request) is read, and sent in the way that worked for this host
    /// before, else in each way in turn until the server answers.
    fn runDpi(f: *const Flow, local: *Local, target: *const Target) !void {
        try local.ready();
        const first = firstFlight(local);
        const h = dpi.hello(first) orelse return f.dpiPlain(local, target);
        var name_buf: [255]u8 = undefined;
        const host = if (target.kind == .domain) target.addr() else blk: {
            const found = sniff.find(h.bytes) orelse break :blk target.addr();
            const n = @min(found.name.len, name_buf.len);
            @memcpy(name_buf[0..n], found.name[0..n]);
            break :blk name_buf[0..n];
        };
        const known = dpi.force orelse dpi.memory.get(f.io, host);
        var s: dpi.Strategy = known orelse .records;
        var buf: [tls13.min_read_buffer + 16]u8 = undefined;
        var tried: usize = 0;
        while (tried < dpi.Strategy.count) : (tried += 1) {
            const upstream = f.dialer.connectTarget(f.io, target) catch |err| {
                local.reset(f.io);
                return err;
            };
            if (f.sendShaped(upstream, target, dpi.plan(h, s, &buf))) {
                if (sys.waitFd(upstream.socket.handle, false, dpi.answer_ms) and sys.hasData(upstream.socket.handle)) {
                    if (known != s) dpi.memory.put(f.io, host, s);
                    local.r.toss(h.bytes.len);
                    f.up(h.bytes.len);
                    defer upstream.close(f.io);
                    return f.relayPlain(local, upstream);
                }
            } else |_| {}
            upstream.close(f.io);
            s = @fromBackingInt(@intCast((@backingInt(s) + 1) % dpi.Strategy.count));
        }
        f.fault(.unreachable_server);
        local.reset(f.io);
        return error.DpiRefused;
    }

    /// Nothing to shape (another protocol, or nothing said in time): a
    /// plain direct connection, which carries what was read.
    fn dpiPlain(f: *const Flow, local: *Local, target: *const Target) !void {
        const upstream = f.dialer.connectTarget(f.io, target) catch |err| {
            local.reset(f.io);
            return err;
        };
        defer upstream.close(f.io);
        return f.relayPlain(local, upstream);
    }

    /// The application's first bytes, as much as makes a ClientHello or a
    /// request head, read but left in `local.r`; whatever came within
    /// `first_flight_ms` otherwise.
    fn firstFlight(local: *Local) []const u8 {
        const r = local.r;
        var waited: u32 = 0;
        while (true) {
            const have = r.buffered();
            const k, const need = sniff.kind(have);
            switch (k) {
                .tls => if (have.len >= need or need > r.buffer.len) return have,
                .http => if (std.mem.indexOf(u8, have, "\r\n\r\n") != null or have.len == r.buffer.len) return have,
                .other => return have,
                .incomplete => {},
            }
            if (waited >= first_flight_ms) return have;
            if (!local.waitReadable(50)) {
                waited += 50;
                continue;
            }
            r.fillMore() catch return r.buffered();
        }
    }

    const first_flight_ms = 400;

    /// The plan's parts on their way: together, or each its own segment,
    /// the first with a TTL of 1 when asked (it dies on the way and the
    /// kernel sends it again, after the second).
    fn sendShaped(f: *const Flow, upstream: net.Stream, target: *const Target, p: dpi.Plan) !void {
        var wb: [4096]u8 = undefined;
        var w = upstream.writer(f.io, &wb);
        const fd = upstream.socket.handle;
        if (p.together) {
            try w.interface.writeAll(p.parts[0]);
            try w.interface.writeAll(p.parts[1]);
            return w.interface.flush();
        }
        const v6 = target.kind == .ip6 or (target.kind == .domain and upstream.socket.address == .ip6);
        const normal = if (p.low_ttl_first) sys.ttl(fd, v6) else null;
        if (normal != null) _ = sys.setTtl(fd, v6, 1);
        try w.interface.writeAll(p.parts[0]);
        try w.interface.flush();
        if (normal) |t| {
            // let the segment leave with the low TTL before it is restored
            f.io.sleep(.fromMilliseconds(5), .awake) catch {};
            _ = sys.setTtl(fd, v6, t);
        } else f.io.sleep(.fromMilliseconds(2), .awake) catch {};
        try w.interface.writeAll(p.parts[1]);
        try w.interface.flush();
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
            if (quiet_ms >= limit_ms or f.stopping()) {
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
    /// caller's to send. A transport request answered with 5xx is dialed
    /// again (see `redialable`); the application waits meanwhile.
    pub fn dial(f: *const Flow, ob: *const Outbound, u: *Upstream) !void {
        const v = ob.via() orelse return error.NoServer;
        var wait_ms: u32 = redial_first_ms;
        var attempt: u32 = 1;
        while (true) : (attempt += 1) {
            // set by the reader, which a dial that fails to connect never makes
            u.ur.os_status = 0;
            f.dialInner(ob, &v, u) catch |err| {
                if (attempt < redial_attempts and redialable(err, u.layer_status) and f.pause(wait_ms)) {
                    wait_ms *= 2;
                    continue;
                }
                if (u.fault != .none) f.fault(u.fault);
                noteDialFailure(f.io, v.host, err, if (u.layer_status != 0) u.layer_status else null, u.ur.os_status);
                return err;
            };
            return;
        }
    }

    /// Sleep `ms`, or less if whoever runs the flows is stopping: false then.
    fn pause(f: *const Flow, ms: u32) bool {
        var left = ms;
        while (left > 0) {
            if (f.stopping()) return false;
            const step = @min(left, linger_step_ms);
            f.io.sleep(.fromMilliseconds(step), .awake) catch return false;
            left -= step;
        }
        return !f.stopping();
    }

    fn stopping(f: *const Flow) bool {
        return if (f.stop) |st| st.load(.acquire) else false;
    }

    fn dialInner(f: *const Flow, ob: *const Outbound, v: *const Via, u: *Upstream) !void {
        const io = f.io;
        u.layer = null;
        u.layer_status = 0;
        u.fault = .none;
        u.stream = f.dialer.connect(io, v.host, v.port) catch |err| {
            u.fault = .unreachable_server;
            return err;
        };
        errdefer u.stream.close(io);
        u.ur = .init(u.stream.socket.handle, io, &u.urb);
        // the handshakes below must finish in time; data may idle forever
        u.ur.setDeadline(handshake_timeout_ms);
        defer u.ur.noDeadline();
        u.uw = u.stream.writer(io, &u.uwb);
        u.tls = v.reality != null or v.tls != null;
        if (v.reality) |re| {
            _ = tls13.handshake(io, &u.ur.interface, &u.uw.interface, .{
                .server_name = re.server_name,
                .reality = .{ .public_key = re.public_key, .short_id = re.short_id },
            }, &u.rr, &u.rw) catch |err| {
                u.fault = if (err == error.RealityAuthFailed) .reality_rejected else .handshake;
                return err;
            };
        } else if (v.tls) |t| {
            const roots = tls13.systemRoots(io) catch |err| {
                u.fault = .handshake;
                return err;
            };
            _ = tls13.handshake(io, &u.ur.interface, &u.uw.interface, .{
                .server_name = t.server_name.slice(),
                .roots = roots,
                .alpn = t.alpn,
            }, &u.rr, &u.rw) catch |err| {
                u.fault = .handshake;
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
                    u.fault = .handshake;
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
                    u.fault = .handshake;
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
                    u.fault = .handshake;
                    return err;
                };
                l.transport = .{ .grpc = c };
                r = c.reader();
                w = c.writer();
            },
            .xhttp => |*x| {
                const c = l.make(xhttp.Conn);
                c.open(io, r, w, l.take(p.tr), l.take(p.tw), xhttpOptions(x, v)) catch |err| {
                    u.fault = .handshake;
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
        noteDialFailure(f.io, host, err, if (u.layer_status != 0) u.layer_status else null, u.ur.os_status);
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

// ---------------------------------------------------------------- SOCKS5

/// The local SOCKS5 inbound (socks.zig).
pub const Proxy = @import("socks.zig").Proxy;

/// A SOCKS5 answer with `code` (0: the connection is there).
pub fn socksReply(w: *Io.Writer, code: u8) !void {
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

/// A relay counts a chunk after passing it on, so the client can have the
/// bytes a moment before the counter does.
fn expectCount(want: u64, counter: *const std.atomic.Value(u64)) !void {
    for (0..300) |_| {
        if (counter.load(.monotonic) == want) return;
        std.testing.io.sleep(.fromMilliseconds(10), .awake) catch {};
    }
    try std.testing.expectEqual(want, counter.load(.monotonic));
}

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
    try expectCount(20, &p.meter.up);
    try expectCount(20, &p.meter.down);
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
    try expectCount(19, &p.meter.down);
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
    try expectCount(25, &p.meter.down);
    try std.testing.expectEqual(Fault.none, p.meter.fault.load(.monotonic));
}

test "only a transport request answered with 5xx is dialed again" {
    try std.testing.expect(redialable(error.WsUpgradeRefused, 502));
    try std.testing.expect(redialable(error.WsUpgradeRefused, 503));
    try std.testing.expect(redialable(error.HttpUpgradeRefused, 504));
    try std.testing.expect(redialable(error.WsUpgradeRefused, 522));
    // a wrong path or Host, a refused Host/SNI pair: the same every time
    try std.testing.expect(!redialable(error.WsUpgradeRefused, 404));
    try std.testing.expect(!redialable(error.HttpUpgradeRefused, 403));
    try std.testing.expect(!redialable(error.WsBadHandshake, 0));
    // a server that is down or turns us away is found out at once
    try std.testing.expect(!redialable(error.ConnectionRefused, 0));
    try std.testing.expect(!redialable(error.ReadFailed, 0));
    try std.testing.expect(!redialable(error.TlsCertificateUntrusted, 0));
    try std.testing.expect(!redialable(error.RealityAuthFailed, 0));
}

/// A WebSocket front whose backend is away now and then: the first
/// `refuse` upgrades get `status` and the connection is closed; then, if
/// `serve`, one connection is upgraded, its VLESS request checked and the
/// data after it echoed back.
const FlakyWsPeer = struct {
    server: net.Server,
    thread: std.Thread = undefined,
    refuse: u8,
    status: []const u8 = "502 Bad Gateway",
    serve: bool = true,
    uuid: [16]u8,
    accepted: u8 = 0,
    echoed: bool = false,

    const payload = "hello through ws";

    fn init(io: Io, refuse: u8, uuid: [16]u8) !FlakyWsPeer {
        const address: net.IpAddress = .{ .ip4 = .loopback(0) };
        return .{ .server = try address.listen(io, .{ .reuse_address = true }), .refuse = refuse, .uuid = uuid };
    }

    fn port(peer: *const FlakyWsPeer) u16 {
        return peer.server.socket.address.getPort();
    }

    fn run(peer: *FlakyWsPeer, io: Io) void {
        for (0..peer.refuse + @intFromBool(peer.serve)) |i| {
            const s = peer.server.accept(io) catch return;
            defer s.close(io);
            peer.accepted += 1;
            peer.answer(io, s, i < peer.refuse) catch return;
        }
    }

    fn answer(peer: *FlakyWsPeer, io: Io, s: net.Stream, refuse: bool) !void {
        var rb: [4096]u8 = undefined;
        var wb: [4096]u8 = undefined;
        var r = s.reader(io, &rb);
        var w = s.writer(io, &wb);
        var key: [24]u8 = @splat(0);
        while (true) {
            const line = try r.interface.takeDelimiterInclusive('\n');
            const name = "Sec-WebSocket-Key: ";
            if (std.mem.startsWith(u8, line, name) and line.len >= name.len + 24) key = line[name.len..][0..24].*;
            if (line.len == 2) break;
        }
        if (refuse) {
            try w.interface.print("HTTP/1.1 {s}\r\nContent-Length: 0\r\n\r\n", .{peer.status});
            return w.interface.flush();
        }
        var sha = std.crypto.hash.Sha1.init(.{});
        sha.update(&key);
        sha.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        var accept: [28]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&accept, &sha.finalResult());
        try w.interface.print("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{&accept});
        try w.interface.flush();

        // the VLESS request (26 bytes for an IPv4 destination) and the
        // data, in as many masked frames as the client chose
        var got: [26 + payload.len]u8 = undefined;
        var n: usize = 0;
        while (n < got.len) {
            const h = (try r.interface.takeArray(2)).*;
            if (h[1] & 0x80 == 0 or h[1] & 0x7f > 125) return error.TestUnexpectedResult;
            const mask = (try r.interface.takeArray(4)).*;
            const len = h[1] & 0x7f;
            if (n + len > got.len) return error.TestUnexpectedResult;
            for (try r.interface.take(len), 0..) |b, j| got[n + j] = b ^ mask[j & 3];
            n += len;
        }
        if (got[0] != 0 or !std.mem.eql(u8, got[1..17], &peer.uuid) or !std.mem.eql(u8, got[26..], payload))
            return error.TestUnexpectedResult;
        // the response header, the data, and a normal close
        try w.interface.writeAll(&.{ 0x82, 2 + payload.len, 0, 0 });
        try w.interface.writeAll(payload);
        try w.interface.writeAll(&.{ 0x88, 2, 0x03, 0xe8 });
        try w.interface.flush();
        peer.echoed = true;
    }
};

test "socks5 -> vless over WebSocket: a front that answers 502 is dialed again" {
    const io = std.testing.io;
    const uuid = parseUuid("11111111-2222-3333-4444-555555555555").?;
    var peer: FlakyWsPeer = try .init(io, 2, uuid);
    defer peer.server.deinit(io);
    peer.thread = try std.Thread.spawn(.{}, FlakyWsPeer.run, .{ &peer, io });

    var link_buf: [160]u8 = undefined;
    const link = try std.fmt.bufPrint(&link_buf, "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:{d}?type=ws&path=%2Fws&host=ws.example", .{peer.port()});
    var p: Proxy = .{ .io = io };
    p.setOutbound(try outboundFromLink(link, "127.0.0.1", peer.port()));
    try p.start(0);
    defer p.stop();
    try socksRoundTrip(io, p.port, .{ 10, 9, 8, 7 }, 4242, FlakyWsPeer.payload);
    peer.thread.join();
    try std.testing.expectEqual(3, peer.accepted);
    try std.testing.expect(peer.echoed);
    // the flow worked: nothing failed, nothing for the window to report
    try std.testing.expectEqual(0, p.meter.failed.load(.monotonic));
    try std.testing.expectEqual(Fault.none, p.meter.fault.load(.monotonic));
}

test "socks5 -> vless over WebSocket: a 404 is not dialed again" {
    const io = std.testing.io;
    const uuid = parseUuid("11111111-2222-3333-4444-555555555555").?;
    var peer: FlakyWsPeer = try .init(io, 1, uuid);
    defer peer.server.deinit(io);
    peer.status = "404 Not Found";
    peer.serve = false;
    peer.thread = try std.Thread.spawn(.{}, FlakyWsPeer.run, .{ &peer, io });

    var link_buf: [160]u8 = undefined;
    const link = try std.fmt.bufPrint(&link_buf, "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:{d}?type=ws&path=%2Fws&host=ws.example", .{peer.port()});
    var p: Proxy = .{ .io = io };
    p.setOutbound(try outboundFromLink(link, "127.0.0.1", peer.port()));
    try p.start(0);
    defer p.stop();
    try std.testing.expectError(error.Refused, socksRoundTrip(io, p.port, .{ 10, 9, 8, 7 }, 4242, FlakyWsPeer.payload));
    peer.thread.join();
    // the refusal came once the dial had given up: no other connection waits
    try std.testing.expectEqual(1, peer.accepted);
    try std.testing.expect(!sys.waitFd(peer.server.socket.handle, false, 0));
    try std.testing.expectEqual(Fault.handshake, p.meter.fault.load(.monotonic));
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
