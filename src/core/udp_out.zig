//! UDP through a server: one application socket's datagrams, to any number
//! of peers, over one connection (or, for Shadowsocks, one UDP socket).
//!
//!   VLESS        XUDP frames (xudp.zig) after a request with command 3,
//!                inside Vision padding for the first few when it is on
//!   VMess        XUDP frames in a connection opened with command mux
//!   Trojan       a UDP association (command 3): address, length, CRLF,
//!                payload per datagram (trojan.zig)
//!   Shadowsocks  datagrams sealed one by one to the server's UDP port
//!                (shadowsocks.Udp)
//!
//! One thread sends while another receives; `close` from either (or a
//! third) ends both.

const std = @import("std");
const Io = std.Io;
const proxy = @import("proxy.zig");
const xudp = @import("xudp.zig");
const vision = @import("vision.zig");
const trojan = @import("trojan.zig");
const shadowsocks = @import("shadowsocks.zig");
const sys = @import("sys.zig");
const packet = @import("ipstack/packet.zig");

const Target = proxy.Target;

pub const Peer = struct {
    addr: xudp.Address,
    port: u16,

    pub fn target(p: Peer) Target {
        return switch (p.addr) {
            .ip4 => |a| Target.fromEndpoint(.{ .addr = packet.v4(a), .port = p.port }),
            .ip6 => |a| Target.fromEndpoint(.{ .addr = a, .port = p.port }),
            .domain => |d| Target.fromDomain(d, p.port),
        };
    }

    /// A peer naming the address in `t`, which it points into.
    pub fn of(t: *const Target) Peer {
        return .{ .port = t.port, .addr = switch (t.kind) {
            .ip4 => .{ .ip4 = t.bytes[0..4].* },
            .ip6 => .{ .ip6 = t.bytes[0..16].* },
            .domain => .{ .domain = t.addr() },
        } };
    }
};

pub const Datagram = struct {
    /// who sent it, when the protocol says (XUDP may leave it out)
    from: ?Peer,
    payload: []const u8,
};

/// The most a datagram may carry here: XUDP's limit, which Xray's own
/// writer keeps to; the others take more but gain nothing from it.
pub const max_payload = xudp.max_payload;

pub const Kind = enum { vless, vmess, trojan, shadowsocks };

pub fn kindOf(ob: *const proxy.Outbound) ?Kind {
    return switch (ob.*) {
        .vless => .vless,
        .vmess => .vmess,
        .trojan => .trojan,
        .shadowsocks => .shadowsocks,
        .direct, .block => null,
    };
}

pub const Conn = struct {
    io: Io,
    ob: proxy.Outbound,
    kind: Kind,
    up: proxy.Upstream = undefined,
    /// the stream (or the socket) is open: `close` must undo it
    connected: std.atomic.Value(bool) = .init(false),
    closed: std.atomic.Value(bool) = .init(false),

    // sending
    first: bool = true,
    padding: bool = false,
    padder: vision.Padder = undefined,
    frames: u32 = 0,
    prng: std.Random.DefaultPrng = undefined,
    /// an XUDP frame, or a sealed Shadowsocks packet
    sbuf: [max_payload + 600]u8 = undefined,

    // receiving
    header: proxy.ResponseHeader = .{},
    unpad: vision.Unpadder = undefined,
    /// XUDP frames as they come, a Trojan packet, or a Shadowsocks one
    rbuf: [16 * 1024]u8 = undefined,
    reader: xudp.Reader = undefined,
    from: Target = undefined,

    // Shadowsocks
    sock: ?sys.Udp = null,
    ss: shadowsocks.Udp = undefined,

    comptime {
        std.debug.assert(max_payload + shadowsocks.Udp.overhead_max <= @sizeOf(@FieldType(Conn, "sbuf")));
    }

    pub fn init(io: Io, ob: proxy.Outbound) ?Conn {
        const kind = kindOf(&ob) orelse return null;
        return .{ .io = io, .ob = ob, .kind = kind };
    }

    /// Connect to the server and say what the connection is for. Nothing
    /// that names a peer leaves before the first `send`.
    pub fn open(c: *Conn, f: *const proxy.Flow) !void {
        var seed: [8]u8 = undefined;
        c.io.random(&seed);
        c.prng = .init(std.mem.readInt(u64, &seed, .little));
        c.reader = .{ .buf = &c.rbuf };
        switch (c.kind) {
            .shadowsocks => {
                const s = &c.ob.shadowsocks;
                c.ss = try shadowsocks.Udp.init(c.io, s);
                const addr = try f.dialer.resolve(c.io, s.host);
                c.sock = try sys.Udp.open(c.io, &addr, s.port, f.dialer.bind);
                c.connected.store(true, .release);
            },
            else => {
                try f.dial(&c.ob, &c.up);
                c.connected.store(true, .release);
                switch (c.kind) {
                    .vless => {
                        c.padding = c.ob.vless.vision;
                        c.padder = .init(c.ob.vless.uuid);
                        c.unpad = .init(c.ob.vless.uuid);
                    },
                    .vmess => try c.up.attachMux(c.io, &c.ob),
                    else => {},
                }
            },
        }
    }

    /// Send one datagram to `to`. One thread at a time.
    pub fn send(c: *Conn, to: Peer, payload: []const u8) !void {
        if (payload.len > max_payload) return error.PacketTooLarge;
        switch (c.kind) {
            .vless, .vmess => {
                const len = xudp.encode(&c.sbuf, c.first, to.port, to.addr, payload) orelse return error.PacketTooLarge;
                if (c.first and c.kind == .vless) {
                    var hb: [37]u8 = undefined;
                    try c.writeVless(xudp.header(&hb, c.ob.vless.uuid, c.ob.vless.vision), true);
                }
                if (c.kind == .vless) try c.writeVless(c.sbuf[0..len], false) else try c.up.writer().writeAll(c.sbuf[0..len]);
                try c.flush();
            },
            .trojan => {
                const t = to.target();
                const w = c.up.writer();
                // the header opens the first record, together with the first packet
                if (c.first) {
                    var hb: [trojan.header_max]u8 = undefined;
                    try w.writeAll(trojan.requestHeader(&hb, &c.ob.trojan.key, .udp, &t));
                }
                try trojan.writePacket(w, &t, payload);
                try w.flush();
            },
            .shadowsocks => {
                const t = to.target();
                const pkt = try c.ss.seal(c.io, &c.sbuf, &t, payload);
                try c.sock.?.send(pkt);
            },
        }
        c.first = false;
    }

    /// The end of what we send, where the protocol has a way to say it.
    pub fn finish(c: *Conn) void {
        if (c.first) return;
        switch (c.kind) {
            .vless => {
                c.writeVless(&xudp.end_frame, false) catch return;
                c.flush() catch {};
            },
            .vmess => {
                c.up.writer().writeAll(&xudp.end_frame) catch return;
                c.flush() catch {};
            },
            .trojan, .shadowsocks => {},
        }
    }

    /// Write to a VLESS server: the header in the clear, frames inside
    /// Vision padding for the first few, then plain.
    fn writeVless(c: *Conn, bytes: []const u8, is_header: bool) !void {
        // inside a transport: its stream (Vision does not run there)
        if (c.up.transportWriter()) |w| return w.writeAll(bytes);
        if (!c.up.tls) return c.up.uw.interface.writeAll(bytes);
        const rw = &c.up.rw;
        if (is_header or !c.padding) return rw.write(bytes);
        const cmd: vision.Command = if (c.frames >= 7) .end else .pad;
        const space = try rw.writable(vision.max_frame);
        rw.advance(c.padder.frame(space, bytes, cmd, false, c.prng.random()));
        c.frames += 1;
        if (cmd == .end) c.padding = false;
    }

    fn flush(c: *Conn) !void {
        if (c.kind == .vmess) return c.up.writer().flush();
        if (c.up.transportWriter()) |w| return w.flush();
        if (c.up.tls) return c.up.rw.flush();
        return c.up.uw.interface.flush();
    }

    const Sink = struct {
        r: *xudp.Reader,
        pub fn content(k: *Sink, bytes: []const u8) error{Overflow}!void {
            if (!k.r.push(bytes)) return error.Overflow;
        }
    };

    /// The next datagram from the server; null when the server ended the
    /// session, or (Shadowsocks, which has no end) after `wait_ms` with
    /// none. One thread at a time; what it returns lasts until the next call.
    pub fn recv(c: *Conn, wait_ms: i32) !?Datagram {
        switch (c.kind) {
            .shadowsocks => {
                while (!c.closed.load(.acquire)) {
                    const n = c.sock.?.recv(&c.rbuf, wait_ms) catch |err| switch (err) {
                        error.Timeout => return null,
                        else => return err,
                    };
                    // a packet that does not open is someone else's or a replay
                    const d = c.ss.open(c.io, c.rbuf[0..n]) catch continue;
                    c.from = d.from;
                    return .{ .from = Peer.of(&c.from), .payload = d.payload };
                }
                return error.Closed;
            },
            .trojan => {
                const p = trojan.readPacket(c.up.reader(), c.rbuf[0..trojan.udp_max_payload]) catch |err| switch (err) {
                    error.EndOfStream => return null,
                    else => return err,
                };
                c.from = p.peer;
                return .{ .from = Peer.of(&c.from), .payload = p.payload };
            },
            .vless, .vmess => while (true) {
                if (try c.reader.next()) |ev| switch (ev) {
                    .end => return null,
                    .data => |d| return .{ .from = if (d.from) |fr| .{ .addr = fr.addr, .port = fr.port } else null, .payload = d.payload },
                };
                try c.fill();
            },
        }
    }

    /// More XUDP frames from the stream.
    fn fill(c: *Conn) !void {
        var sink: Sink = .{ .r = &c.reader };
        if (c.kind == .vmess) {
            const r = c.up.reader();
            const chunk = r.peekGreedy(1) catch |err| return if (err == error.EndOfStream) error.EndOfStream else err;
            try sink.content(chunk);
            r.toss(chunk.len);
            return;
        }
        var raw_len: usize = 0;
        // inside a transport: its stream; else the records or the socket
        const raw = c.up.transportReader() orelse &c.up.ur.interface;
        const data: []const u8 = if (c.up.tls and raw == &c.up.ur.interface)
            (try c.up.rr.next()) orelse return error.EndOfStream
        else blk: {
            const chunk = try raw.peekGreedy(1);
            raw_len = chunk.len;
            break :blk chunk;
        };
        const body = try c.header.strip(data);
        if (c.ob.vless.vision) _ = try c.unpad.feed(body, &sink) else try sink.content(body);
        if (raw_len > 0) raw.toss(raw_len);
    }

    /// End the session: a thread in `recv` returns soon after.
    pub fn close(c: *Conn) void {
        if (c.closed.swap(true, .acq_rel)) return;
        if (!c.connected.load(.acquire)) return;
        if (c.kind != .shadowsocks) c.up.stream.shutdown(c.io, .both) catch {};
    }

    /// Free what `open` made, once no thread uses the connection.
    pub fn deinit(c: *Conn) void {
        if (!c.connected.load(.acquire)) return;
        if (c.sock) |s| s.close() else c.up.close(c.io);
        if (c.kind == .shadowsocks) c.ss.deinit();
    }
};
