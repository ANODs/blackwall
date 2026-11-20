//! Userspace TCP/UDP endpoint behind a TUN device (the "tun2socks" role).
//!
//! Every TCP connection an application opens through the TUN is terminated
//! here: we play the server side, and a worker thread relays the bytes to an
//! outbound. Packet input, timers and connection state sit behind one mutex;
//! workers block on a per-connection condition.
//!
//! Deliberately small, because the peer is the local kernel a fraction of a
//! millisecond away:
//! - no window scaling (we never offer it, so windows stay below 64 KiB),
//!   no SACK, no timestamps;
//! - in-order receive only: a TUN does not reorder, and anything out of
//!   order is dropped and recovered by the kernel's retransmission;
//! - go-back-N retransmission with a 200 ms minimum timeout;
//! - the SYN is answered only after the worker has picked a route and
//!   reached the outbound, so a failing route shows up as a refused
//!   connection instead of a connection that dies after opening.

const std = @import("std");
const Io = std.Io;
const packet = @import("packet.zig");
const Endpoint = packet.Endpoint;

pub const Key = struct {
    /// the application's end (source of packets read from the TUN)
    app: Endpoint,
    /// where the application wanted to go
    remote: Endpoint,
};

const KeyContext = struct {
    pub fn hash(_: KeyContext, k: Key) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(&k.app.addr);
        h.update(&k.remote.addr);
        h.update(std.mem.asBytes(&k.app.port));
        h.update(std.mem.asBytes(&k.remote.port));
        return h.final();
    }
    pub fn eql(_: KeyContext, a: Key, b: Key) bool {
        return a.app.eql(b.app) and a.remote.eql(b.remote);
    }
};

pub const Output = struct {
    ctx: *anyopaque,
    /// Write one IP packet to the TUN. Must be safe to call from several
    /// threads at once (a plain write(2) per packet is).
    write: *const fn (ctx: *anyopaque, pkt: []const u8) void,
};

pub const Handler = struct {
    ctx: *anyopaque,
    /// A new TCP flow (SYN) arrived. Called with the stack locked: only
    /// record the connection and hand it to a worker, which must then call
    /// `accept` or `reject`, and finally `release`. Return false to refuse
    /// at once (the stack answers with RST and forgets the flow).
    tcp: *const fn (ctx: *anyopaque, conn: *Conn) bool,
    /// A UDP datagram arrived. Called without the lock held.
    udp: *const fn (ctx: *anyopaque, src: Endpoint, dst: Endpoint, payload: []const u8) void,
};

pub const Config = struct {
    mtu: u16 = 1500,
    max_conns: u32 = 4096,
    /// receive buffer per connection, also the largest window we advertise
    rx_buf: u32 = 32 * 1024,
    /// send buffer per connection (data waiting for the application's ACK)
    tx_buf: u32 = 32 * 1024,
};

pub const Stats = struct {
    packets_in: u64 = 0,
    packets_out: u64 = 0,
    dropped: u64 = 0,
    resets_sent: u64 = 0,
    retransmits: u64 = 0,
    /// nanoseconds `input` waited for the lock (diagnostics)
    input_lock_ns: u64 = 0,
};

const ns_per_ms = std.time.ns_per_ms;
const rto_min_ms = 200;
const rto_max_ms = 30_000;
const max_retries = 8;
const persist_min_ms = 200;
const persist_max_ms = 5_000;
const linger_ms = 2_000;
const pending_timeout_ms = 30_000;
const fin_wait_timeout_ms = 60_000;
const idle_timeout_ms = 2 * 60 * 60 * 1000;
/// Floor for the MSS a SYN announces (Linux uses 48). Zero would never
/// advance trySend, and a few bytes would turn every window into a flood
/// of tiny packets, all written under the stack lock.
const min_peer_mss = 64;
/// The TUN carries IPv6, whose links are at least this large (the helper
/// clamps the utun the same way); it keeps every segment size positive.
const min_mtu = 1280;

fn seqLt(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) < 0;
}
fn seqLe(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) <= 0;
}

/// Byte ring with a power-of-two capacity.
const Ring = struct {
    buf: []u8 = &.{},
    head: usize = 0,
    len: usize = 0,

    fn free(r: *const Ring) usize {
        return r.buf.len - r.len;
    }

    fn write(r: *Ring, data: []const u8) usize {
        const n = @min(data.len, r.free());
        const mask = r.buf.len - 1;
        const start = (r.head + r.len) & mask;
        const first = @min(n, r.buf.len - start);
        @memcpy(r.buf[start..][0..first], data[0..first]);
        @memcpy(r.buf[0 .. n - first], data[first..n]);
        r.len += n;
        return n;
    }

    /// Copy `out.len` bytes starting `offset` bytes after the head.
    fn copyAt(r: *const Ring, offset: usize, out: []u8) void {
        std.debug.assert(offset + out.len <= r.len);
        const mask = r.buf.len - 1;
        const start = (r.head + offset) & mask;
        const first = @min(out.len, r.buf.len - start);
        @memcpy(out[0..first], r.buf[start..][0..first]);
        @memcpy(out[first..], r.buf[0 .. out.len - first]);
    }

    fn consume(r: *Ring, n: usize) void {
        std.debug.assert(n <= r.len);
        r.head = (r.head + n) & (r.buf.len - 1);
        r.len -= n;
        if (r.len == 0) r.head = 0;
    }
};

pub const State = enum {
    /// SYN seen, waiting for the worker to accept or reject
    pending,
    syn_received,
    established,
    close_wait,
    last_ack,
    fin_wait_1,
    fin_wait_2,
    closing,
    time_wait,
    closed,
};

pub const Error = error{ ConnectionReset, ConnectionTimedOut, ConnectionRefused, Closed, OutOfMemory };

pub const Conn = struct {
    stack: *Stack,
    key: Key,
    state: State = .pending,

    cond: Io.Condition = .init,
    /// a worker still holds this connection
    attached: bool = true,
    /// gone from the protocol's point of view; freed once detached
    dead: bool = false,
    in_ack_list: bool = false,
    failure: ?Error = null,

    // receive side: application -> us
    irs: u32,
    rcv_nxt: u32,
    rx: Ring = .{},
    rx_eof: bool = false,
    /// the worker stopped reading: further data is acknowledged and dropped
    rx_closed: bool = false,
    /// right edge of the window we last advertised
    adv_edge: u32 = 0,
    ack_due: bool = false,

    // send side: us -> application
    iss: u32 = 0,
    snd_una: u32 = 0,
    snd_nxt: u32 = 0,
    snd_wnd: u32,
    snd_wl1: u32 = 0,
    snd_wl2: u32 = 0,
    /// unacknowledged and unsent bytes, starting at snd_una
    tx: Ring = .{},
    fin_queued: bool = false,
    /// sequence number of our FIN once it has been sent
    fin_seq: ?u32 = null,
    fin_acked: bool = false,
    peer_mss: u16,
    dup_acks: u8 = 0,

    // timers, absolute nanoseconds on the awake clock (0 = off)
    rto_at: i96 = 0,
    rto_ms: u32 = rto_min_ms,
    retries: u8 = 0,
    persist_at: i96 = 0,
    persist_ms: u32 = persist_min_ms,
    deadline: i96 = 0,

    pub fn local(c: *const Conn) Endpoint {
        return c.key.app;
    }
    pub fn remote(c: *const Conn) Endpoint {
        return c.key.remote;
    }

    // ------------------------------------------------------------ worker API

    /// Complete the handshake (SYN-ACK). Blocks until the application
    /// acknowledges it, so the caller knows the flow is really open.
    pub fn accept(c: *Conn) Error!void {
        const s = c.stack;
        s.lock();
        defer s.unlock();
        if (c.state != .pending) return c.failure orelse error.Closed;
        c.rx.buf = s.gpa.alloc(u8, s.cfg.rx_buf) catch {
            c.abortLocked(error.OutOfMemory, true);
            return error.OutOfMemory;
        };
        c.tx.buf = s.gpa.alloc(u8, s.cfg.tx_buf) catch {
            c.abortLocked(error.OutOfMemory, true);
            return error.OutOfMemory;
        };
        var isn: [4]u8 = undefined;
        s.io.random(&isn);
        c.iss = std.mem.readInt(u32, &isn, .little);
        c.snd_una = c.iss;
        c.snd_nxt = c.iss +% 1;
        c.state = .syn_received;
        c.sendSynAck();
        c.rto_at = s.now() + @as(i96, c.rto_ms) * ns_per_ms;
        while (c.state == .syn_received) c.cond.waitUncancelable(s.io, &s.mutex);
        if (c.failure) |f| return f;
    }

    /// Refuse the flow (RST), as a closed port would.
    pub fn reject(c: *Conn) void {
        const s = c.stack;
        s.lock();
        defer s.unlock();
        if (c.state != .pending) return;
        s.sendRst(c.key, 0, c.rcv_nxt, true);
        c.failure = error.ConnectionRefused;
        c.state = .closed;
        c.dead = true;
    }

    /// Copy received bytes into `dest` (several slices); blocks until there
    /// is something to read. End of stream is error.EndOfStream.
    pub fn recv(c: *Conn, dest: []const []u8) (Error || error{EndOfStream})!usize {
        const s = c.stack;
        s.lock();
        defer s.unlock();
        while (c.rx.len == 0) {
            if (c.failure) |f| return f;
            if (c.rx_eof or c.rx_closed) return error.EndOfStream;
            c.cond.waitUncancelable(s.io, &s.mutex);
        }
        var n: usize = 0;
        for (dest) |d| {
            const k = @min(d.len, c.rx.len);
            if (k == 0) break;
            c.rx.copyAt(0, d[0..k]);
            c.rx.consume(k);
            n += k;
        }
        c.maybeWindowUpdate();
        return n;
    }

    /// Wait up to `ms` for data (or the end of the stream) to be readable.
    pub fn waitReadable(c: *Conn, ms: u32) bool {
        const s = c.stack;
        s.lock();
        defer s.unlock();
        const deadline = s.now() + @as(i96, ms) * ns_per_ms;
        while (c.rx.len == 0 and !c.rx_eof and c.failure == null and !c.rx_closed) {
            const left = deadline - s.now();
            if (left <= 0) return false;
            c.cond.waitTimeout(s.io, &s.mutex, .{ .duration = .{
                .raw = .fromNanoseconds(left),
                .clock = .awake,
            } }) catch {};
        }
        return true;
    }

    /// Queue `data` for the application; blocks while the send buffer is full.
    pub fn send(c: *Conn, data: []const u8) Error!void {
        const s = c.stack;
        s.lock();
        defer s.unlock();
        var rest = data;
        while (rest.len > 0) {
            if (c.failure) |f| return f;
            if (c.fin_queued or c.state == .closed) return error.Closed;
            const n = c.tx.write(rest);
            rest = rest[n..];
            if (n > 0) c.trySend();
            if (rest.len > 0) c.cond.waitUncancelable(s.io, &s.mutex);
        }
    }

    /// No more data from our side: FIN after everything queued.
    pub fn closeWrite(c: *Conn) void {
        const s = c.stack;
        s.lock();
        defer s.unlock();
        if (c.fin_queued or c.state == .closed or c.state == .pending) return;
        c.fin_queued = true;
        c.trySend();
    }

    /// Stop reading: buffered and future data is acknowledged and dropped.
    pub fn shutdownRead(c: *Conn) void {
        const s = c.stack;
        s.lock();
        defer s.unlock();
        c.rx_closed = true;
        if (c.rx.len > 0) {
            c.rx.consume(c.rx.len);
            c.maybeWindowUpdate();
        }
        c.cond.broadcast(s.io);
    }

    /// Reset the connection (RST to the application).
    pub fn abort(c: *Conn) void {
        const s = c.stack;
        s.lock();
        defer s.unlock();
        if (c.state == .closed) return;
        c.abortLocked(error.ConnectionReset, true);
    }

    /// The worker is done with this connection; the stack frees it once
    /// the protocol is finished (or right away if it already is).
    pub fn release(c: *Conn) void {
        const s = c.stack;
        s.lock();
        defer s.unlock();
        c.attached = false;
        c.rx_closed = true;
        if (c.rx.len > 0) c.rx.consume(c.rx.len);
        switch (c.state) {
            .pending => {
                s.sendRst(c.key, 0, c.rcv_nxt, true);
                c.state = .closed;
                c.dead = true;
            },
            // still talking: let the close handshake finish on its own
            .syn_received, .established, .close_wait => if (!c.fin_queued) {
                c.fin_queued = true;
                c.trySend();
            },
            .closed => c.dead = true,
            else => {},
        }
    }

    // ------------------------------------------------------------ protocol (stack locked)

    fn now(c: *const Conn) i96 {
        return c.stack.now();
    }

    /// Largest payload per segment. The header size comes from key.remote,
    /// the source address of everything we send (packet.writeTcp).
    fn mss(c: *const Conn) usize {
        const ip_len: usize = packet.ipHeaderLen(&c.key.remote.addr);
        const own: usize = c.stack.cfg.mtu - ip_len - 20;
        return @min(own, c.peer_mss);
    }

    fn window(c: *const Conn) u16 {
        if (c.rx_closed) return @intCast(@min(c.stack.cfg.rx_buf, 65535));
        return @intCast(@min(c.rx.free(), 65535));
    }

    fn emit(c: *Conn, seq: u32, flags: packet.Flags, payload: []const u8, mss_opt: ?u16) void {
        var f = flags;
        f.ack = flags.ack or c.state != .pending;
        const wnd = c.window();
        c.adv_edge = c.rcv_nxt +% wnd;
        c.ack_due = false;
        c.stack.writeTcp(c.key.remote, c.key.app, .{
            .seq = seq,
            .ack = c.rcv_nxt,
            .flags = f,
            .window = wnd,
            .mss = mss_opt,
            .payload = payload,
        });
    }

    fn sendSynAck(c: *Conn) void {
        const own: u16 = @intCast(c.stack.cfg.mtu - packet.ipHeaderLen(&c.key.remote.addr) - 20);
        c.emit(c.iss, .{ .syn = true, .ack = true }, &.{}, own);
    }

    fn sendAck(c: *Conn) void {
        c.emit(c.snd_nxt, .{ .ack = true }, &.{}, null);
    }

    fn finInFlight(c: *const Conn) bool {
        const f = c.fin_seq orelse return false;
        return c.snd_nxt == f +% 1;
    }

    fn trySend(c: *Conn) void {
        switch (c.state) {
            .established, .close_wait, .fin_wait_1, .last_ack, .closing => {},
            else => return,
        }
        const s = c.stack;
        const seg_buf = s.segbuf;
        while (true) {
            const in_flight: usize = c.snd_nxt -% c.snd_una;
            const fin_out = c.finInFlight();
            const data_in_flight = if (fin_out) c.tx.len else @min(in_flight, c.tx.len);
            const unsent = c.tx.len - data_in_flight;
            if (unsent > 0) {
                const room: usize = if (c.snd_wnd > in_flight) c.snd_wnd - in_flight else 0;
                if (room == 0) {
                    if (c.rto_at == 0 and c.persist_at == 0)
                        c.persist_at = c.now() + @as(i96, c.persist_ms) * ns_per_ms;
                    break;
                }
                const n = @min(unsent, room, c.mss());
                c.tx.copyAt(data_in_flight, seg_buf[0..n]);
                const last = n == unsent;
                c.emit(c.snd_nxt, .{ .ack = true, .psh = last }, seg_buf[0..n], null);
                c.snd_nxt +%= @intCast(n);
                if (c.rto_at == 0) c.rto_at = c.now() + @as(i96, c.rto_ms) * ns_per_ms;
                continue;
            }
            if (c.fin_queued and !fin_out) {
                c.fin_seq = c.snd_nxt;
                c.emit(c.snd_nxt, .{ .fin = true, .ack = true }, &.{}, null);
                c.snd_nxt +%= 1;
                switch (c.state) {
                    .established => c.state = .fin_wait_1,
                    .close_wait => c.state = .last_ack,
                    else => {},
                }
                if (c.rto_at == 0) c.rto_at = c.now() + @as(i96, c.rto_ms) * ns_per_ms;
            }
            break;
        }
    }

    fn maybeWindowUpdate(c: *Conn) void {
        switch (c.state) {
            .established, .fin_wait_1, .fin_wait_2 => {},
            else => return,
        }
        const edge = c.rcv_nxt +% c.window();
        const grow = edge -% c.adv_edge;
        if (seqLt(c.adv_edge, edge) and grow >= @min(c.mss(), c.stack.cfg.rx_buf / 2)) c.sendAck();
    }

    fn abortLocked(c: *Conn, why: Error, send_rst: bool) void {
        if (send_rst and c.state != .pending and c.state != .closed)
            c.stack.sendRst(c.key, c.snd_nxt, c.rcv_nxt, true);
        if (send_rst and c.state == .pending)
            c.stack.sendRst(c.key, 0, c.rcv_nxt, true);
        c.failure = why;
        c.state = .closed;
        c.dead = true;
        c.rto_at = 0;
        c.persist_at = 0;
        c.cond.broadcast(c.stack.io);
    }

    fn enterTimeWait(c: *Conn) void {
        c.state = .time_wait;
        c.rto_at = 0;
        c.deadline = c.now() + linger_ms * ns_per_ms;
    }

    fn inWindow(c: *const Conn, seq: u32) bool {
        const wnd: u32 = @max(c.window(), 1);
        return seqLe(c.rcv_nxt, seq) and seqLt(seq, c.rcv_nxt +% wnd);
    }

    fn segment(c: *Conn, t: packet.Tcp) void {
        const s = c.stack;
        if (c.state == .pending or c.state == .closed) return;
        defer c.refreshDeadline();

        if (t.flags.rst) {
            // only a reset aimed at our window counts (blind resets are ignored)
            if (c.state == .syn_received or c.inWindow(t.seq) or t.seq == c.rcv_nxt)
                c.abortLocked(error.ConnectionReset, false);
            return;
        }
        if (t.flags.syn) {
            if (c.state == .syn_received and t.seq == c.irs) c.sendSynAck() else c.sendAck();
            return;
        }
        if (!t.flags.ack) return;

        if (c.state == .syn_received) {
            if (t.ack != c.iss +% 1) {
                s.sendRst(c.key, t.ack, 0, false);
                return;
            }
            c.state = .established;
            c.snd_una = t.ack;
            c.snd_wnd = t.window;
            c.snd_wl1 = t.seq;
            c.snd_wl2 = t.ack;
            c.rto_at = 0;
            c.retries = 0;
            c.rto_ms = rto_min_ms;
            c.cond.broadcast(s.io);
        } else {
            if (seqLt(c.snd_nxt, t.ack)) {
                // acknowledges data we never sent
                c.queueAck();
                return;
            }
            if (seqLt(c.snd_una, t.ack)) {
                const advanced: usize = t.ack -% c.snd_una;
                c.tx.consume(@min(advanced, c.tx.len));
                if (c.fin_seq) |f| {
                    if (t.ack == f +% 1) c.fin_acked = true;
                }
                c.snd_una = t.ack;
                c.dup_acks = 0;
                c.retries = 0;
                c.rto_ms = rto_min_ms;
                c.rto_at = if (c.snd_una != c.snd_nxt) c.now() + @as(i96, c.rto_ms) * ns_per_ms else 0;
                c.cond.broadcast(s.io);
            } else if (t.ack == c.snd_una and t.payload.len == 0 and !t.flags.fin and
                t.window == c.snd_wnd and c.snd_una != c.snd_nxt)
            {
                // saturating: the go-back-N resend keeps snd_una behind
                // snd_nxt, so a long run of duplicates keeps counting
                c.dup_acks +|= 1;
                if (c.dup_acks == 3) {
                    s.stats.retransmits += 1;
                    c.snd_nxt = c.snd_una;
                    c.rto_at = 0;
                }
            }
            if (seqLt(c.snd_wl1, t.seq) or (c.snd_wl1 == t.seq and seqLe(c.snd_wl2, t.ack))) {
                c.snd_wnd = t.window;
                c.snd_wl1 = t.seq;
                c.snd_wl2 = t.ack;
                if (c.snd_wnd > 0) {
                    c.persist_at = 0;
                    c.persist_ms = persist_min_ms;
                }
            }
            if (c.fin_acked) switch (c.state) {
                .fin_wait_1 => c.state = .fin_wait_2,
                .closing => c.enterTimeWait(),
                .last_ack => {
                    c.state = .closed;
                    c.dead = true;
                    c.rto_at = 0;
                    c.cond.broadcast(s.io);
                    return;
                },
                else => {},
            };
        }

        if (t.payload.len > 0 or t.flags.fin) {
            c.receive(t);
        } else if (!c.inWindow(t.seq)) {
            // an unacceptable segment gets an ACK (RFC 9293 3.10.7.4):
            // keepalive and Linux zero-window probes are empty with
            // seq = rcv_nxt - 1, and the sender gives up without an answer
            c.queueAck();
        }
        c.trySend();
    }

    fn refreshDeadline(c: *Conn) void {
        c.deadline = switch (c.state) {
            .pending, .closed => c.deadline,
            .time_wait => c.deadline, // set once on entry, not extended
            .fin_wait_2 => c.now() + fin_wait_timeout_ms * ns_per_ms,
            else => c.now() + idle_timeout_ms * ns_per_ms,
        };
    }

    fn queueAck(c: *Conn) void {
        c.ack_due = true;
        if (!c.in_ack_list) {
            c.stack.ack_list.append(c.stack.gpa, c) catch {
                c.sendAck();
                return;
            };
            c.in_ack_list = true;
        }
    }

    fn receive(c: *Conn, t: packet.Tcp) void {
        const s = c.stack;
        switch (c.state) {
            .established, .fin_wait_1, .fin_wait_2 => {},
            else => {
                // the peer already finished; a repeated FIN or stray data gets an ACK
                c.queueAck();
                return;
            },
        }
        var seq = t.seq;
        var data = t.payload;
        if (seqLt(seq, c.rcv_nxt)) {
            const dup: usize = c.rcv_nxt -% seq;
            if (dup > data.len or (dup == data.len and !t.flags.fin)) {
                c.queueAck(); // old segment or 1-byte keepalive probe
                return;
            }
            data = data[dup..];
            seq = c.rcv_nxt;
        }
        if (seq != c.rcv_nxt) {
            c.queueAck(); // out of order: duplicate ACK, the peer retransmits
            return;
        }
        var taken: usize = 0;
        if (data.len > 0) {
            taken = if (c.rx_closed) data.len else c.rx.write(data);
            c.rcv_nxt +%= @intCast(taken);
            if (taken > 0) c.cond.broadcast(s.io);
            c.queueAck();
        }
        if (t.flags.fin and taken == data.len) {
            c.rcv_nxt +%= 1;
            c.rx_eof = true;
            c.queueAck();
            switch (c.state) {
                .established => c.state = .close_wait,
                .fin_wait_1 => c.state = .closing,
                .fin_wait_2 => c.enterTimeWait(),
                else => {},
            }
            c.cond.broadcast(s.io);
        }
    }

    fn timers(c: *Conn, now_ns: i96) void {
        const s = c.stack;
        if (c.deadline != 0 and now_ns >= c.deadline) {
            switch (c.state) {
                .time_wait => {
                    c.state = .closed;
                    c.dead = true;
                    c.cond.broadcast(s.io);
                },
                else => c.abortLocked(error.ConnectionTimedOut, true),
            }
            return;
        }
        if (c.rto_at != 0 and now_ns >= c.rto_at) {
            c.retries += 1;
            if (c.retries > max_retries) {
                c.abortLocked(error.ConnectionTimedOut, true);
                return;
            }
            s.stats.retransmits += 1;
            c.rto_ms = @min(c.rto_ms * 2, rto_max_ms);
            if (c.state == .syn_received) {
                c.sendSynAck();
            } else {
                c.snd_nxt = c.snd_una;
                c.rto_at = 0;
                c.trySend();
            }
            c.rto_at = now_ns + @as(i96, c.rto_ms) * ns_per_ms;
        }
        if (c.persist_at != 0 and now_ns >= c.persist_at) {
            // zero-window probe: an old sequence number makes the peer answer
            // with its current window
            c.emit(c.snd_una -% 1, .{ .ack = true }, &.{}, null);
            c.persist_ms = @min(c.persist_ms * 2, persist_max_ms);
            c.persist_at = now_ns + @as(i96, c.persist_ms) * ns_per_ms;
        }
    }

    fn nextDeadline(c: *const Conn) i96 {
        var d: i96 = std.math.maxInt(i96);
        inline for (.{ c.deadline, c.rto_at, c.persist_at }) |t| {
            if (t != 0) d = @min(d, t);
        }
        return d;
    }
};

pub const Stack = struct {
    gpa: std.mem.Allocator,
    io: Io,
    cfg: Config,
    out: Output,
    handler: Handler,
    mutex: Io.Mutex = .init,
    conns: std.HashMapUnmanaged(Key, *Conn, KeyContext, 80) = .empty,
    ack_list: std.ArrayList(*Conn) = .empty,
    /// packet scratch for TCP output, used under the mutex
    scratch: []u8,
    /// payload scratch for data segments, used under the mutex
    segbuf: []u8,
    /// packet scratch for UDP output, used under `udp_mutex`. Not on the
    /// caller's stack: DNS forwarders and UDP readers run on small stacks.
    udp_buf: []u8,
    udp_mutex: Io.Mutex = .init,
    /// fixed clock for tests
    test_now: ?i96 = null,
    stats: Stats = .{},

    pub fn create(gpa: std.mem.Allocator, io: Io, config: Config, out: Output, handler: Handler) !*Stack {
        var cfg = config;
        std.debug.assert(std.math.isPowerOfTwo(cfg.rx_buf) and std.math.isPowerOfTwo(cfg.tx_buf));
        cfg.mtu = @max(cfg.mtu, min_mtu);
        const s = try gpa.create(Stack);
        errdefer gpa.destroy(s);
        const scratch = try gpa.alloc(u8, cfg.mtu);
        errdefer gpa.free(scratch);
        const segbuf = try gpa.alloc(u8, cfg.mtu);
        errdefer gpa.free(segbuf);
        s.* = .{
            .gpa = gpa,
            .io = io,
            .cfg = cfg,
            .out = out,
            .handler = handler,
            .scratch = scratch,
            .segbuf = segbuf,
            .udp_buf = try gpa.alloc(u8, cfg.mtu),
        };
        return s;
    }

    /// Reset every connection; blocked workers wake up with ConnectionReset.
    pub fn abortAll(s: *Stack) void {
        s.lock();
        defer s.unlock();
        var it = s.conns.valueIterator();
        while (it.next()) |c| {
            if (c.*.state != .closed) c.*.abortLocked(error.ConnectionReset, true);
        }
    }

    /// Reset the connection with this key, if it is still there. Unlike
    /// `Conn.abort` this needs no pointer that has to stay valid: whoever
    /// remembers flows to end them later remembers their keys.
    pub fn abortKey(s: *Stack, key: Key) void {
        s.lock();
        defer s.unlock();
        const c = s.conns.get(key) orelse return;
        if (c.state != .closed) c.abortLocked(error.ConnectionReset, true);
    }

    /// Connections still held by a worker.
    pub fn attachedCount(s: *Stack) usize {
        s.lock();
        defer s.unlock();
        var n: usize = 0;
        var it = s.conns.valueIterator();
        while (it.next()) |c| n += @intFromBool(c.*.attached);
        return n;
    }

    /// Free the stack. Call `abortAll` first and wait until no worker holds
    /// a connection (`attachedCount() == 0`).
    pub fn destroy(s: *Stack) void {
        s.lock();
        var it = s.conns.valueIterator();
        while (it.next()) |cp| {
            const c = cp.*;
            if (c.rx.buf.len > 0) s.gpa.free(c.rx.buf);
            if (c.tx.buf.len > 0) s.gpa.free(c.tx.buf);
            s.gpa.destroy(c);
        }
        s.conns.deinit(s.gpa);
        s.ack_list.deinit(s.gpa);
        s.unlock();
        s.gpa.free(s.scratch);
        s.gpa.free(s.segbuf);
        s.gpa.free(s.udp_buf);
        s.gpa.destroy(s);
    }

    /// Diagnostics: how long `input` waited for the lock since the last call.
    pub fn takeInputLockNs(s: *Stack) u64 {
        s.lock();
        defer s.unlock();
        const v = s.stats.input_lock_ns;
        s.stats.input_lock_ns = 0;
        return v;
    }

    fn lock(s: *Stack) void {
        s.mutex.lockUncancelable(s.io);
    }
    fn unlock(s: *Stack) void {
        s.mutex.unlock(s.io);
    }

    pub fn now(s: *const Stack) i96 {
        return s.test_now orelse Io.Clock.awake.now(s.io).nanoseconds;
    }

    /// Feed one packet read from the TUN.
    pub fn input(s: *Stack, pkt: []const u8) void {
        const ip = packet.parseIp(pkt) orelse return;
        switch (ip.proto) {
            packet.proto_tcp => {
                const t = packet.parseTcp(ip.l4) orelse return;
                const w0 = Io.Clock.awake.now(s.io).toNanoseconds();
                s.lock();
                defer s.unlock();
                s.stats.input_lock_ns += @intCast(Io.Clock.awake.now(s.io).toNanoseconds() - w0);
                s.stats.packets_in += 1;
                s.tcpInput(ip, t);
            },
            packet.proto_udp => {
                const u = packet.parseUdp(ip.l4) orelse return;
                s.handler.udp(s.handler.ctx, .{ .addr = ip.src, .port = u.src_port }, .{ .addr = ip.dst, .port = u.dst_port }, u.payload);
            },
            else => {},
        }
    }

    /// Send the acknowledgements collected while processing a batch of input.
    pub fn flush(s: *Stack) void {
        s.lock();
        defer s.unlock();
        for (s.ack_list.items) |c| {
            c.in_ack_list = false;
            if (c.ack_due and !c.dead) c.sendAck();
        }
        s.ack_list.clearRetainingCapacity();
    }

    /// Run timers and free finished connections. Returns how long the caller
    /// may sleep before calling again (milliseconds).
    pub fn tick(s: *Stack) u32 {
        s.lock();
        defer s.unlock();
        const t = s.now();
        var next: i96 = t + 60 * std.time.ns_per_s;
        var gone: std.ArrayList(*Conn) = .empty;
        defer gone.deinit(s.gpa);
        var it = s.conns.valueIterator();
        while (it.next()) |cp| {
            const c = cp.*;
            if (!c.dead) c.timers(t);
            if (c.dead) {
                // no timers left: a stale deadline of a connection its
                // worker still holds must not make us wake every millisecond
                if (!c.attached) gone.append(s.gpa, c) catch {};
                continue;
            }
            next = @min(next, c.nextDeadline());
        }
        for (gone.items) |c| s.freeConn(c);
        const wait = @max(next - t, 0);
        return @intCast(@min(@divTrunc(wait, ns_per_ms) + 1, 60_000));
    }

    pub fn connectionCount(s: *Stack) usize {
        s.lock();
        defer s.unlock();
        return s.conns.count();
    }

    fn freeConn(s: *Stack, c: *Conn) void {
        // freed in the middle of an input batch (a new SYN reusing the
        // tuple): flush must not find it
        if (c.in_ack_list) {
            const i = std.mem.indexOfScalar(*Conn, s.ack_list.items, c).?;
            _ = s.ack_list.swapRemove(i);
        }
        _ = s.conns.remove(c.key);
        if (c.rx.buf.len > 0) s.gpa.free(c.rx.buf);
        if (c.tx.buf.len > 0) s.gpa.free(c.tx.buf);
        s.gpa.destroy(c);
    }

    fn tcpInput(s: *Stack, ip: packet.Ip, t: packet.Tcp) void {
        const key: Key = .{
            .app = .{ .addr = ip.src, .port = t.src_port },
            .remote = .{ .addr = ip.dst, .port = t.dst_port },
        };
        if (s.conns.get(key)) |c| {
            if (c.dead) {
                // a new SYN may reuse the tuple of a connection in its last moments
                if (t.flags.syn and !t.flags.ack and !c.attached) {
                    s.freeConn(c);
                    s.newConn(key, t);
                } else if (!t.flags.rst) s.sendRstFor(key, t);
                return;
            }
            c.segment(t);
            return;
        }
        if (t.flags.rst) return;
        if (t.flags.syn and !t.flags.ack) return s.newConn(key, t);
        s.sendRstFor(key, t);
    }

    fn newConn(s: *Stack, key: Key, t: packet.Tcp) void {
        if (s.conns.count() >= s.cfg.max_conns) return s.sendRst(key, 0, t.seq +% 1, true);
        const c = s.gpa.create(Conn) catch return s.sendRst(key, 0, t.seq +% 1, true);
        c.* = .{
            .stack = s,
            .key = key,
            .irs = t.seq,
            .rcv_nxt = t.seq +% 1,
            .snd_wnd = t.window,
            .peer_mss = @max(t.mss orelse 536, min_peer_mss),
            .deadline = s.now() + pending_timeout_ms * ns_per_ms,
        };
        s.conns.put(s.gpa, key, c) catch {
            s.gpa.destroy(c);
            return s.sendRst(key, 0, t.seq +% 1, true);
        };
        if (!s.handler.tcp(s.handler.ctx, c)) {
            s.sendRst(key, 0, c.rcv_nxt, true);
            c.state = .closed;
            c.dead = true;
            c.attached = false;
        }
    }

    /// RST in answer to a segment that belongs to no connection (RFC 9293 3.10.7.1).
    fn sendRstFor(s: *Stack, key: Key, t: packet.Tcp) void {
        if (t.flags.ack) {
            s.sendRst(key, t.ack, 0, false);
        } else {
            var len: u32 = @intCast(t.payload.len);
            if (t.flags.syn) len += 1;
            if (t.flags.fin) len += 1;
            s.sendRst(key, 0, t.seq +% len, true);
        }
    }

    fn sendRst(s: *Stack, key: Key, seq: u32, ack: u32, with_ack: bool) void {
        s.stats.resets_sent += 1;
        s.writeTcp(key.remote, key.app, .{
            .seq = seq,
            .ack = if (with_ack) ack else 0,
            .flags = .{ .rst = true, .ack = with_ack },
            .window = 0,
        });
    }

    fn writeTcp(s: *Stack, src: Endpoint, dst: Endpoint, seg: packet.TcpOut) void {
        const n = packet.writeTcp(s.scratch, src, dst, seg);
        s.stats.packets_out += 1;
        s.out.write(s.out.ctx, s.scratch[0..n]);
    }

    /// Send a UDP datagram to the application. Thread-safe; takes only
    /// `udp_mutex`, never the stack lock, and needs little stack.
    pub fn sendUdp(s: *Stack, src: Endpoint, dst: Endpoint, payload: []const u8) void {
        // larger than the TUN takes; fragmenting is not worth it
        if (packet.ipHeaderLen(&src.addr) + 8 + payload.len > s.udp_buf.len) return;
        s.udp_mutex.lockUncancelable(s.io);
        defer s.udp_mutex.unlock(s.io);
        const n = packet.writeUdp(s.udp_buf, src, dst, payload);
        s.out.write(s.out.ctx, s.udp_buf[0..n]);
    }
};

// ---------------------------------------------------------------- Io adapters

/// `std.Io.Reader` over a connection, for code written against readers.
pub const Reader = struct {
    conn: *Conn,
    interface: Io.Reader,
    err: ?Error = null,

    pub fn init(conn: *Conn, buffer: []u8) Reader {
        return .{
            .conn = conn,
            .interface = .{
                .vtable = &.{ .stream = stream, .readVec = readVec },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn stream(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const dest = limit.slice(try io_w.writableSliceGreedy(1));
        var data: [1][]u8 = .{dest};
        const n = try readVec(io_r, &data);
        io_w.advance(n);
        return n;
    }

    fn readVec(io_r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const r: *Reader = @alignCast(@fieldParentPtr("interface", io_r));
        var iovecs: [8][]u8 = undefined;
        const dest_n, const data_size = try io_r.writableVector(&iovecs, data);
        const n = r.conn.recv(iovecs[0..dest_n]) catch |err| switch (err) {
            error.EndOfStream => return error.EndOfStream,
            else => |e| {
                r.err = e;
                return error.ReadFailed;
            },
        };
        if (n > data_size) {
            io_r.end += n - data_size;
            return data_size;
        }
        return n;
    }
};

/// `std.Io.Writer` over a connection.
pub const Writer = struct {
    conn: *Conn,
    interface: Io.Writer,
    err: ?Error = null,

    pub fn init(conn: *Conn, buffer: []u8) Writer {
        return .{
            .conn = conn,
            .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buffer },
        };
    }

    fn drain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const w: *Writer = @alignCast(@fieldParentPtr("interface", io_w));
        var n: usize = io_w.end;
        w.conn.send(io_w.buffered()) catch |e| return w.fail(e);
        for (data[0 .. data.len - 1]) |d| {
            w.conn.send(d) catch |e| return w.fail(e);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            w.conn.send(last) catch |e| return w.fail(e);
            n += last.len;
        }
        return io_w.consume(n);
    }

    fn fail(w: *Writer, e: Error) error{WriteFailed} {
        w.err = e;
        return error.WriteFailed;
    }
};

// ---------------------------------------------------------------- tests

const Harness = struct {
    gpa: std.mem.Allocator,
    stack: *Stack = undefined,
    mutex: Io.Mutex = .init,
    out: std.ArrayList([]u8) = .empty,
    conns: std.ArrayList(*Conn) = .empty,
    refuse: bool = false,
    app: Endpoint = .{ .addr = packet.v4(.{ 198, 18, 0, 1 }), .port = 50000 },
    remote: Endpoint = .{ .addr = packet.v4(.{ 93, 184, 216, 34 }), .port = 443 },

    const Seg = struct { t: packet.Tcp, buf: []u8 };

    fn init(h: *Harness, cfg: Config) !void {
        h.stack = try Stack.create(h.gpa, std.testing.io, cfg, .{ .ctx = h, .write = capture }, .{ .ctx = h, .tcp = onTcp, .udp = onUdp });
        h.stack.test_now = 1_000 * std.time.ns_per_s;
    }

    fn deinit(h: *Harness) void {
        h.stack.abortAll();
        for (h.conns.items) |c| c.release();
        _ = h.stack.tick();
        h.stack.destroy();
        for (h.out.items) |b| h.gpa.free(b);
        h.out.deinit(h.gpa);
        h.conns.deinit(h.gpa);
    }

    fn capture(ctx: *anyopaque, pkt: []const u8) void {
        const h: *Harness = @ptrCast(@alignCast(ctx));
        h.mutex.lockUncancelable(std.testing.io);
        defer h.mutex.unlock(std.testing.io);
        h.out.append(h.gpa, h.gpa.dupe(u8, pkt) catch unreachable) catch unreachable;
    }

    fn onTcp(ctx: *anyopaque, conn: *Conn) bool {
        const h: *Harness = @ptrCast(@alignCast(ctx));
        if (h.refuse) return false;
        h.conns.append(h.gpa, conn) catch return false;
        return true;
    }

    fn onUdp(_: *anyopaque, _: Endpoint, _: Endpoint, _: []const u8) void {}

    /// One packet of a device batch; `flush` ends the batch.
    fn input(h: *Harness, seg: packet.TcpOut) void {
        var buf: [2048]u8 = undefined;
        const n = packet.writeTcp(&buf, h.app, h.remote, seg);
        h.stack.input(buf[0..n]);
    }

    /// What the application's kernel would send.
    fn send(h: *Harness, seg: packet.TcpOut) void {
        h.input(seg);
        h.stack.flush();
    }

    /// Next packet the stack sent towards the application.
    fn next(h: *Harness) ?packet.Tcp {
        h.mutex.lockUncancelable(std.testing.io);
        defer h.mutex.unlock(std.testing.io);
        if (h.out.items.len == 0) return null;
        const b = h.out.orderedRemove(0);
        const ip = packet.parseIp(b).?;
        std.debug.assert(packet.transportChecksumOk(ip));
        std.debug.assert(std.mem.eql(u8, &ip.dst, &h.app.addr));
        const t = packet.parseTcp(ip.l4).?;
        // keep the payload alive for the caller: leak into the arena of `out`
        h.out.append(h.gpa, b) catch unreachable;
        _ = h.out.pop();
        h.keep(b);
        return t;
    }

    var kept: std.ArrayList([]u8) = .empty;
    fn keep(h: *Harness, b: []u8) void {
        kept.append(h.gpa, b) catch unreachable;
    }
    fn freeKept(h: *Harness) void {
        for (kept.items) |b| h.gpa.free(b);
        kept.clearAndFree(h.gpa);
    }

    fn pending(h: *Harness) usize {
        h.mutex.lockUncancelable(std.testing.io);
        defer h.mutex.unlock(std.testing.io);
        return h.out.items.len;
    }

    fn advance(h: *Harness, ms: u64) void {
        h.stack.test_now.? += @as(i96, ms) * std.time.ns_per_ms;
        _ = h.stack.tick();
    }

    /// SYN, accept in a worker thread, ACK: returns the established conn and our ISS.
    fn open(h: *Harness, isn: u32) !struct { *Conn, u32 } {
        return h.openMss(isn, 1460);
    }

    /// `open` with the MSS option the SYN carries.
    fn openMss(h: *Harness, isn: u32, mss: ?u16) !struct { *Conn, u32 } {
        h.send(.{ .seq = isn, .ack = 0, .flags = .{ .syn = true }, .window = 65535, .mss = mss });
        try std.testing.expectEqual(1, h.conns.items.len);
        const c = h.conns.items[h.conns.items.len - 1];
        try std.testing.expectEqual(0, h.pending()); // nothing until the worker decides
        const T = struct {
            fn run(conn: *Conn, result: *?Error) void {
                conn.accept() catch |e| {
                    result.* = e;
                };
            }
        };
        var result: ?Error = null;
        const th = try std.Thread.spawn(.{}, T.run, .{ c, &result });
        var synack: ?packet.Tcp = null;
        while (synack == null) {
            synack = h.next();
            if (synack == null) std.Thread.yield() catch {};
        }
        const sa = synack.?;
        try std.testing.expect(sa.flags.syn and sa.flags.ack);
        try std.testing.expectEqual(isn +% 1, sa.ack);
        try std.testing.expectEqual(h.stack.cfg.mtu - 40, sa.mss.?);
        h.send(.{ .seq = isn +% 1, .ack = sa.seq +% 1, .flags = .{ .ack = true }, .window = 65535 });
        th.join();
        try std.testing.expect(result == null);
        try std.testing.expectEqual(State.established, c.state);
        return .{ c, sa.seq };
    }
};

fn testHarness(cfg: Config) !*Harness {
    const h = try std.testing.allocator.create(Harness);
    h.* = .{ .gpa = std.testing.allocator };
    try h.init(cfg);
    return h;
}

fn freeHarness(h: *Harness) void {
    h.deinit();
    h.freeKept();
    std.testing.allocator.destroy(h);
}

test "handshake, data both ways, orderly close initiated by the app" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    const c, const iss = try h.open(1000);

    h.send(.{ .seq = 1001, .ack = iss +% 1, .flags = .{ .ack = true, .psh = true }, .window = 65535, .payload = "hello" });
    const ack = h.next().?;
    try std.testing.expectEqual(1006, ack.ack);
    var buf: [16]u8 = undefined;
    try std.testing.expectEqual(5, try c.recv(&.{&buf}));
    try std.testing.expectEqualStrings("hello", buf[0..5]);

    try c.send("world");
    const data = h.next().?;
    try std.testing.expectEqualStrings("world", data.payload);
    try std.testing.expectEqual(iss +% 1, data.seq);
    try std.testing.expectEqual(1006, data.ack);
    h.send(.{ .seq = 1006, .ack = iss +% 6, .flags = .{ .ack = true }, .window = 65535 });

    h.send(.{ .seq = 1006, .ack = iss +% 6, .flags = .{ .ack = true, .fin = true }, .window = 65535 });
    try std.testing.expectEqual(1007, h.next().?.ack);
    try std.testing.expectError(error.EndOfStream, c.recv(&.{&buf}));
    try std.testing.expectEqual(State.close_wait, c.state);

    c.closeWrite();
    const fin = h.next().?;
    try std.testing.expect(fin.flags.fin);
    try std.testing.expectEqual(iss +% 6, fin.seq);
    try std.testing.expectEqual(State.last_ack, c.state);
    h.send(.{ .seq = 1007, .ack = iss +% 7, .flags = .{ .ack = true }, .window = 65535 });
    try std.testing.expectEqual(State.closed, c.state);
    c.release();
    h.conns.clearRetainingCapacity();
    h.advance(1);
    try std.testing.expectEqual(0, h.stack.connectionCount());
}

test "we close first: FIN_WAIT, TIME_WAIT, then gone" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    const c, const iss = try h.open(7);
    c.closeWrite();
    const fin = h.next().?;
    try std.testing.expect(fin.flags.fin);
    h.send(.{ .seq = 8, .ack = iss +% 2, .flags = .{ .ack = true }, .window = 65535 });
    try std.testing.expectEqual(State.fin_wait_2, c.state);
    h.send(.{ .seq = 8, .ack = iss +% 2, .flags = .{ .ack = true, .fin = true }, .window = 65535 });
    try std.testing.expectEqual(9, h.next().?.ack);
    try std.testing.expectEqual(State.time_wait, c.state);
    // a retransmitted FIN is acknowledged again
    h.send(.{ .seq = 8, .ack = iss +% 2, .flags = .{ .ack = true, .fin = true }, .window = 65535 });
    try std.testing.expectEqual(9, h.next().?.ack);
    c.release();
    h.conns.clearRetainingCapacity();
    h.advance(linger_ms + 1);
    try std.testing.expectEqual(0, h.stack.connectionCount());
}

test "out of order segment is dropped and duplicate-acked" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    const c, const iss = try h.open(100);
    h.send(.{ .seq = 106, .ack = iss +% 1, .flags = .{ .ack = true }, .window = 65535, .payload = "later" });
    try std.testing.expectEqual(101, h.next().?.ack);
    h.send(.{ .seq = 101, .ack = iss +% 1, .flags = .{ .ack = true }, .window = 65535, .payload = "first" });
    try std.testing.expectEqual(106, h.next().?.ack);
    // the retransmission overlapping old data is trimmed
    h.send(.{ .seq = 103, .ack = iss +% 1, .flags = .{ .ack = true }, .window = 65535, .payload = "rstlater" });
    try std.testing.expectEqual(111, h.next().?.ack);
    var buf: [32]u8 = undefined;
    const n = try c.recv(&.{&buf});
    try std.testing.expectEqualStrings("firstlater", buf[0..n]);
}

test "retransmission timeout, then go-back-N resend" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    const c, const iss = try h.open(1);
    try c.send("abc");
    try std.testing.expectEqualStrings("abc", h.next().?.payload);
    h.advance(rto_min_ms - 1);
    try std.testing.expectEqual(0, h.pending());
    h.advance(2);
    const again = h.next().?;
    try std.testing.expectEqualStrings("abc", again.payload);
    try std.testing.expectEqual(iss +% 1, again.seq);
    // backoff doubled: nothing at the old interval
    h.advance(rto_min_ms + 1);
    try std.testing.expectEqual(0, h.pending());
    h.send(.{ .seq = 2, .ack = iss +% 4, .flags = .{ .ack = true }, .window = 65535 });
    h.advance(10_000);
    try std.testing.expectEqual(0, h.pending());
}

test "three duplicate ACKs trigger fast retransmit" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    const c, const iss = try h.open(1);
    var big: [3000]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @truncate(i);
    try c.send(&big);
    var sent: usize = 0;
    while (h.next()) |seg| sent += seg.payload.len;
    try std.testing.expectEqual(3000, sent);
    // the first segment was "lost": three duplicate ACKs for iss+1
    for (0..3) |_| h.send(.{ .seq = 2, .ack = iss +% 1, .flags = .{ .ack = true }, .window = 65535 });
    const re = h.next().?;
    try std.testing.expectEqual(iss +% 1, re.seq);
    try std.testing.expectEqualSlices(u8, big[0..re.payload.len], re.payload);
}

test "zero window: persist probe, then the window opens" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    const c, const iss = try h.open(1);
    h.send(.{ .seq = 2, .ack = iss +% 1, .flags = .{ .ack = true }, .window = 0 });
    try c.send("blocked");
    try std.testing.expectEqual(0, h.pending());
    h.advance(persist_min_ms + 1);
    const probe = h.next().?;
    try std.testing.expectEqual(iss, probe.seq);
    try std.testing.expectEqual(0, probe.payload.len);
    h.send(.{ .seq = 2, .ack = iss +% 1, .flags = .{ .ack = true }, .window = 4096 });
    try std.testing.expectEqualStrings("blocked", h.next().?.payload);
}

test "receive window shrinks and reopens with a window update" {
    const h = try testHarness(.{ .rx_buf = 4096 });
    defer freeHarness(h);
    const c, const iss = try h.open(1);
    var chunk: [1024]u8 = @splat('x');
    var seq: u32 = 2;
    for (0..4) |_| {
        h.send(.{ .seq = seq, .ack = iss +% 1, .flags = .{ .ack = true }, .window = 65535, .payload = &chunk });
        seq += 1024;
    }
    var last: packet.Tcp = undefined;
    while (h.next()) |a| last = a;
    try std.testing.expectEqual(0, last.window);
    // more data while the window is closed is not accepted
    h.send(.{ .seq = seq, .ack = iss +% 1, .flags = .{ .ack = true }, .window = 65535, .payload = "y" });
    try std.testing.expectEqual(seq, h.next().?.ack);
    var buf: [4096]u8 = undefined;
    try std.testing.expectEqual(4096, try c.recv(&.{&buf}));
    const upd = h.next().?;
    try std.testing.expectEqual(4096, upd.window);
}

test "RST from the application wakes the worker with ConnectionReset" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    const c, const iss = try h.open(50);
    h.send(.{ .seq = 51, .ack = iss +% 1, .flags = .{ .rst = true, .ack = true }, .window = 0 });
    var buf: [4]u8 = undefined;
    try std.testing.expectError(error.ConnectionReset, c.recv(&.{&buf}));
    try std.testing.expectError(error.ConnectionReset, c.send("x"));
}

test "blind RST outside the window is ignored" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    const c, const iss = try h.open(50);
    h.send(.{ .seq = 50 +% 100_000, .ack = iss +% 1, .flags = .{ .rst = true }, .window = 0 });
    try std.testing.expectEqual(State.established, c.state);
}

test "rejected and refused flows get RST" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    h.send(.{ .seq = 900, .ack = 0, .flags = .{ .syn = true }, .window = 65535 });
    const c = h.conns.items[0];
    c.reject();
    const rst = h.next().?;
    try std.testing.expect(rst.flags.rst and rst.flags.ack);
    try std.testing.expectEqual(901, rst.ack);
    c.release();
    h.conns.clearRetainingCapacity();

    h.refuse = true;
    h.app.port += 1;
    h.send(.{ .seq = 5, .ack = 0, .flags = .{ .syn = true }, .window = 65535 });
    try std.testing.expect(h.next().?.flags.rst);

    // a stray ACK for an unknown flow: RST with seq = its ack
    h.app.port += 1;
    h.send(.{ .seq = 77, .ack = 12345, .flags = .{ .ack = true }, .window = 65535 });
    const stray = h.next().?;
    try std.testing.expect(stray.flags.rst and !stray.flags.ack);
    try std.testing.expectEqual(12345, stray.seq);
    h.advance(1);
    try std.testing.expectEqual(0, h.stack.connectionCount());
}

test "lost SYN-ACK is retransmitted and a repeated SYN is answered" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    h.send(.{ .seq = 10, .ack = 0, .flags = .{ .syn = true }, .window = 65535, .mss = 1200 });
    const c = h.conns.items[0];
    const T = struct {
        fn run(conn: *Conn) void {
            conn.accept() catch {};
        }
    };
    const th = try std.Thread.spawn(.{}, T.run, .{c});
    while (h.pending() == 0) std.Thread.yield() catch {};
    const first = h.next().?;
    h.advance(rto_min_ms + 1);
    const second = h.next().?;
    try std.testing.expect(second.flags.syn and second.seq == first.seq);
    h.send(.{ .seq = 10, .ack = 0, .flags = .{ .syn = true }, .window = 65535, .mss = 1200 });
    try std.testing.expect(h.next().?.flags.syn);
    h.send(.{ .seq = 11, .ack = first.seq +% 1, .flags = .{ .ack = true }, .window = 65535 });
    th.join();
    try std.testing.expectEqual(State.established, c.state);
    // the peer's MSS bounds our segments
    var big: [3000]u8 = @splat(1);
    try c.send(&big);
    try std.testing.expectEqual(1200, h.next().?.payload.len);
}

test "unanswered data times out after max retries" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    const c, _ = try h.open(1);
    try c.send("lost");
    var ms: u32 = rto_min_ms;
    for (0..max_retries + 1) |_| {
        h.advance(ms + 1);
        ms = @min(ms * 2, rto_max_ms);
    }
    try std.testing.expectEqual(State.closed, c.state);
    var buf: [4]u8 = undefined;
    try std.testing.expectError(error.ConnectionTimedOut, c.recv(&.{&buf}));
}

test "Io adapters: reader and writer over a connection" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    const c, const iss = try h.open(1);
    h.send(.{ .seq = 2, .ack = iss +% 1, .flags = .{ .ack = true, .fin = true }, .window = 65535, .payload = "line one\nline two\n" });
    var rb: [64]u8 = undefined;
    var r: Reader = .init(c, &rb);
    try std.testing.expectEqualStrings("line one", try r.interface.takeDelimiterExclusive('\n'));
    r.interface.toss(1);
    try std.testing.expectEqualStrings("line two", try r.interface.takeDelimiterExclusive('\n'));
    r.interface.toss(1);
    try std.testing.expectError(error.EndOfStream, r.interface.peekByte());

    var wb: [8]u8 = undefined;
    var w: Writer = .init(c, &wb);
    try w.interface.writeAll("a fairly long reply that overflows the buffer");
    try w.interface.flush();
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(std.testing.allocator);
    while (h.next()) |seg| try got.appendSlice(std.testing.allocator, seg.payload);
    try std.testing.expectEqualStrings("a fairly long reply that overflows the buffer", got.items);
}

test "waitReadable times out and wakes on data" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    h.stack.test_now = null; // real clock for the timed wait
    const c, const iss = try h.open(1);
    try std.testing.expect(!c.waitReadable(20));
    h.send(.{ .seq = 2, .ack = iss +% 1, .flags = .{ .ack = true }, .window = 65535, .payload = "x" });
    try std.testing.expect(c.waitReadable(20));
}

test "an MSS of 0 and a tiny MTU still leave room for data" {
    const h = try testHarness(.{ .mtu = 40 });
    defer freeHarness(h);
    try std.testing.expectEqual(min_mtu, h.stack.cfg.mtu);
    const c, const iss = try h.openMss(77, 0);
    try std.testing.expectEqual(min_peer_mss, c.mss());
    // sending used to spin forever on empty segments, under the stack lock
    try c.send("hello");
    try std.testing.expectEqualStrings("hello", h.next().?.payload);
    try std.testing.expectEqual(0, h.pending());
    h.send(.{ .seq = 78, .ack = iss +% 6, .flags = .{ .ack = true }, .window = 65535 });
    var big: [200]u8 = @splat(1);
    try c.send(&big);
    try std.testing.expectEqual(min_peer_mss, h.next().?.payload.len);
}

test "a SYN reusing the tuple of a connection that waits for its ACK" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    const c, const iss = try h.open(5000);
    c.closeWrite();
    _ = h.next().?; // our FIN
    h.send(.{ .seq = 5001, .ack = iss +% 2, .flags = .{ .ack = true }, .window = 65535 });
    try std.testing.expectEqual(State.fin_wait_2, c.state);
    c.release();
    h.conns.clearRetainingCapacity();
    // one device batch: data (an ACK is due), RST, then a SYN from the same port
    h.input(.{ .seq = 5001, .ack = iss +% 2, .flags = .{ .ack = true }, .window = 65535, .payload = "x" });
    h.input(.{ .seq = 5002, .ack = 0, .flags = .{ .rst = true }, .window = 0 });
    h.input(.{ .seq = 9000, .ack = 0, .flags = .{ .syn = true }, .window = 65535, .mss = 1460 });
    // the old connection is gone, and with it its due ACK
    try std.testing.expectEqual(0, h.stack.ack_list.items.len);
    h.stack.flush();
    try std.testing.expectEqual(0, h.pending());
    try std.testing.expectEqual(1, h.stack.connectionCount());
    try std.testing.expectEqual(State.pending, h.conns.items[0].state);
}

test "keepalive and zero-window probes without data are acknowledged" {
    const h = try testHarness(.{ .rx_buf = 4096 });
    defer freeHarness(h);
    _, const iss = try h.open(1000);
    // an ordinary ACK needs no answer
    h.send(.{ .seq = 1001, .ack = iss +% 1, .flags = .{ .ack = true }, .window = 65535 });
    try std.testing.expectEqual(0, h.pending());
    // keepalive: empty, one below what we expect
    h.send(.{ .seq = 1000, .ack = iss +% 1, .flags = .{ .ack = true }, .window = 65535 });
    try std.testing.expectEqual(1001, h.next().?.ack);
    try std.testing.expectEqual(0, h.pending());
    // our window fills up; a Linux zero-window probe has the same shape
    var chunk: [1024]u8 = @splat('x');
    var seq: u32 = 1001;
    for (0..4) |_| {
        h.send(.{ .seq = seq, .ack = iss +% 1, .flags = .{ .ack = true }, .window = 65535, .payload = &chunk });
        seq += 1024;
    }
    while (h.next()) |_| {}
    h.send(.{ .seq = seq - 1, .ack = iss +% 1, .flags = .{ .ack = true }, .window = 65535 });
    const ack = h.next().?;
    try std.testing.expectEqual(seq, ack.ack);
    try std.testing.expectEqual(0, ack.window);
}

test "a long run of duplicate ACKs resends once and does not overflow" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    const c, const iss = try h.open(1);
    try c.send("data");
    while (h.next()) |_| {}
    for (0..300) |_| h.send(.{ .seq = 2, .ack = iss +% 1, .flags = .{ .ack = true }, .window = 65535 });
    try std.testing.expectEqualStrings("data", h.next().?.payload);
    try std.testing.expectEqual(0, h.pending());
    try std.testing.expectEqual(1, h.stack.stats.retransmits);
}

test "a dead connection still held by its worker lets tick sleep" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    h.send(.{ .seq = 1, .ack = 0, .flags = .{ .syn = true }, .window = 65535 });
    const c = h.conns.items[0];
    // the worker is still dialing when the flow times out
    h.advance(pending_timeout_ms + 1);
    try std.testing.expect(c.dead and c.attached);
    try std.testing.expectEqual(60_000, h.stack.tick());
}

test "an IPv6 SYN from an IPv4-mapped address opens nothing" {
    const h = try testHarness(.{});
    defer freeHarness(h);
    var src: Endpoint = .{ .addr = @splat(0), .port = 40000 };
    src.addr[0] = 0xfd;
    src.addr[15] = 5;
    var dst: Endpoint = .{ .addr = @splat(0), .port = 443 };
    dst.addr[0] = 0x20;
    dst.addr[1] = 0x01;
    dst.addr[15] = 1;
    var buf: [128]u8 = undefined;
    const n = packet.writeTcp(&buf, src, dst, .{ .seq = 10, .ack = 0, .flags = .{ .syn = true }, .window = 65535, .mss = 1460 });
    buf[8..24].* = packet.v4(.{ 10, 0, 0, 1 }); // its replies would get an IPv4-sized header budget
    h.stack.input(buf[0..n]);
    h.stack.flush();
    try std.testing.expectEqual(0, h.conns.items.len);
    try std.testing.expectEqual(0, h.pending());
}

test "sendUdp fits on the small stack of a DNS forwarding thread" {
    const T = struct {
        var bytes: std.atomic.Value(usize) = .init(0);
        fn write(_: *anyopaque, pkt: []const u8) void {
            _ = bytes.fetchAdd(pkt.len, .monotonic);
        }
        fn onTcp(_: *anyopaque, _: *Conn) bool {
            return false;
        }
        fn onUdp(_: *anyopaque, _: Endpoint, _: Endpoint, _: []const u8) void {}
        const from: Endpoint = .{ .addr = packet.v4(.{ 198, 18, 0, 2 }), .port = 53 };
        const to: Endpoint = .{ .addr = packet.v4(.{ 198, 18, 0, 1 }), .port = 5353 };
        /// the shape of a forwarder: its own reply buffer, then sendUdp
        fn reply(s: *Stack) void {
            var resp: [1472]u8 = @splat(0x42);
            s.sendUdp(from, to, &resp);
        }
    };
    var ctx: u8 = 0;
    const s = try Stack.create(std.testing.allocator, std.testing.io, .{}, .{ .ctx = &ctx, .write = T.write }, .{ .ctx = &ctx, .tcp = T.onTcp, .udp = T.onUdp });
    defer s.destroy();
    // half of the 64 KiB that sendUdp once put on its caller's stack
    const th = try std.Thread.spawn(.{ .stack_size = @import("../sys.zig").stackSize(32 * 1024) }, T.reply, .{s});
    th.join();
    try std.testing.expectEqual(1500, T.bytes.load(.monotonic));
    // one byte more than the MTU takes is dropped
    var big: [1473]u8 = @splat(0);
    s.sendUdp(T.from, T.to, &big);
    try std.testing.expectEqual(1500, T.bytes.load(.monotonic));
}
