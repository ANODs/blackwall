//! WebSocket client (RFC 6455): the VLESS transport behind CDNs, shaped like
//! Xray's (gorilla/websocket) client. One HTTP/1.1 upgrade with the headers
//! Xray sends, then every flush of `writer` leaves as masked binary frames,
//! and the payloads of the server's data frames, whatever their boundaries,
//! make up `reader`.
//!
//! Runs over any std.Io.Reader/Writer pair, normally the decrypted TLS
//! stream. One thread reads while another writes, and every write to the
//! stream below happens under `mutex`: the writer's frames as well as the
//! pongs and the close reply the reader owes. The reader never waits for that
//! lock: while the writer holds it, the reply is left to the writer, which
//! sends it before letting go. So a writer stuck on a full socket cannot stop
//! the downlink, which would deadlock a flow whose server stops reading until
//! we read.
//!
//! Memory: a frame is built in place in the caller's write buffer (room for
//! its header is kept in front of the payload, the mask goes on in place),
//! and payloads are read straight from the stream below; nothing is staged.
//!
//! Early data (`ed=N` in the path's query): the upgrade waits for the first
//! flush, and when those bytes (the VLESS header and the start of the data)
//! fit in N they travel in Sec-WebSocket-Protocol instead of a frame, saving
//! the round trip of the upgrade, as in Xray.

const std = @import("std");
const Io = std.Io;

pub const Options = struct {
    /// The link's path, percent-decoded once. As in Xray, a missing leading
    /// '/' is added and `ed=N` in its query sets the early-data budget
    /// without being sent.
    path: []const u8,
    /// Host header, without a port: the link's host, else its sni, else the
    /// server address.
    host: []const u8,
};

pub const Error = error{
    /// The server answered the upgrade with another status, kept in
    /// `status`. From Xray 404 means a wrong path or Host; behind a CDN 403
    /// or 421 mean it refuses the Host/SNI pair, 52x that it cannot reach
    /// the server.
    WsUpgradeRefused,
    /// No HTTP/1.1 101 answer with Upgrade, Connection and the right
    /// Sec-WebSocket-Accept: not a WebSocket server (or ALPN chose h2).
    WsBadHandshake,
    /// The server sent a frame RFC 6455 forbids (it was told: close 1002).
    WsProtocolError,
    /// The server closed with a code other than 1000 or none (`close_code`).
    WsClosedAbnormally,
    /// The stream below ended without a close frame (what gorilla calls 1006).
    WsTruncated,
    /// A Host or path that cannot go into a request.
    WsBadOptions,
};

pub const HandshakeError = Error || error{ ReadFailed, WriteFailed };

/// Largest frame header: 2 bytes, a 64-bit length and the mask key. The
/// write buffer keeps this much room in front of the payload. With a 16 KiB
/// write buffer a frame is at most 16384 bytes: one TLS record.
const head_room = 14;
/// Early data put in the request at most, whatever `ed` says. Xray never
/// sends more (its first write is one 8 KiB buffer), and its server takes
/// 8 KiB of headers plus 4 KiB of slack, which this fits in base64.
const max_early = 8192;
/// An answer to the upgrade longer than this is not one.
const max_answer = 16 * 1024;
/// Reading before the upgrade, how long to wait for the first flush (which
/// carries early data) before upgrading without it. VLESS flushes its header
/// within half a second; missing that, the writer has given up.
const first_write_wait: Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } };

const Opcode = enum(u4) { continuation = 0, text = 1, binary = 2, close = 8, ping = 9, pong = 10 };

pub const Conn = struct {
    io: Io,
    /// the stream below
    r: *Io.Reader,
    w: *Io.Writer,
    /// the payload: what the server sends, and what we send
    reader: Io.Reader,
    writer: Io.Writer,
    /// Why `reader` or `writer` failed, if the stream below did not.
    err: ?Error = null,
    /// HTTP status of the answer to the upgrade
    status: u16 = 0,
    /// close code the server sent (1005: none given), 0 while it has not
    close_code: u16 = 0,

    /// Guards `w`, `upgraded` and `closed`.
    mutex: Io.Mutex = .init,
    /// Set once the upgrade is over: done, failed, or called off by `close`.
    settled: Io.Event = .unset,
    upgraded: bool = false,
    /// A close frame went out (no frame may follow it), or the connection
    /// was closed before the upgrade.
    closed: bool = false,
    /// early-data budget; nonzero while the upgrade waits for the first flush
    early: u32 = 0,
    /// Sec-WebSocket-Key, for checking the answer
    key: [24]u8 = undefined,

    /// Replies the reader owes, sent by whoever holds `mutex`. The reader
    /// fills `pong` only while `owe_pong` is false.
    owe_pong: std.atomic.Value(bool) = .init(false),
    owe_close: std.atomic.Value(bool) = .init(false),
    pong: [125]u8 = undefined,
    pong_len: u8 = 0,
    close_reply: [2]u8 = undefined,
    close_reply_len: u8 = 0,

    // the reading thread's own
    rstate: enum { open, eof, failed } = .open,
    /// payload left in the current data frame
    left: u64 = 0,
    /// inside a fragmented message (its last frame has not come)
    in_message: bool = false,

    /// `rbuf` buffers `reader` (any size); `wbuf` must be larger than
    /// `head_room` and bounds the frames we send (16 KiB: one TLS record
    /// each). The interfaces point back into the result: keep it at one
    /// address.
    pub fn init(io: Io, r: *Io.Reader, w: *Io.Writer, rbuf: []u8, wbuf: []u8) Conn {
        std.debug.assert(rbuf.len > 0 and wbuf.len > head_room);
        return .{
            .io = io,
            .r = r,
            .w = w,
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = rbuf, .seek = 0, .end = 0 },
            .writer = .{ .vtable = &.{ .drain = drain, .flush = flush }, .buffer = wbuf[head_room..] },
        };
    }

    /// Send the upgrade request and check the answer, before any other use.
    /// With early data only the start of the request goes into `w`: the
    /// first flush of `writer` finishes it, and a refused upgrade then shows
    /// as a failed write (with `err` and `status` set).
    pub fn handshake(c: *Conn, opts: Options) HandshakeError!void {
        if (!validHost(opts.host)) return c.fail(error.WsBadOptions);
        var raw: [16]u8 = undefined;
        c.io.random(&raw);
        _ = std.base64.standard.Encoder.encode(&c.key, &raw);
        const chrome = chromeMajor(Io.Clock.real.now(c.io).toSeconds());
        const ed = writeRequestHead(c.w, opts.path, opts.host, &c.key, chrome) catch |e| switch (e) {
            error.WriteFailed => return error.WriteFailed,
            else => |bad| return c.fail(bad),
        };
        c.early = @min(ed, max_early);
        if (c.early == 0) try c.upgrade("");
    }

    /// End the connection from our side: close 1000, sent once and not
    /// waited for (the caller closes the stream below next). Before the
    /// upgrade nothing goes out, and a reader waiting for it gets the end.
    /// WebSocket has no half-close: this ends the server's direction too, so
    /// it is not for when only our sending is over (nor is a TCP shutdown of
    /// the stream below, which Xray takes as an abnormal close, 1006).
    pub fn close(c: *Conn) void {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        if (!c.settled.isSet()) {
            c.closed = true;
            c.settled.set(c.io);
            return;
        }
        if (!c.upgraded or c.closed) return;
        c.closed = true;
        var f: [head_room + 2]u8 = undefined;
        f[head_room..].* = .{ 0x03, 0xe8 };
        c.w.writeAll(c.seal(.close, f[head_room..])) catch return;
        c.w.flush() catch {};
    }

    fn fail(c: *Conn, e: Error) Error {
        c.err = e;
        return e;
    }

    /// Finish the request (`early` rides in Sec-WebSocket-Protocol, which
    /// sorts between the key and the version), send it, check the answer.
    /// Runs once: from `handshake`, or under `mutex` from the first flush.
    fn upgrade(c: *Conn, early: []const u8) HandshakeError!void {
        defer c.settled.set(c.io);
        const w = c.w;
        if (early.len > 0) {
            try w.writeAll("Sec-WebSocket-Protocol: ");
            try writeBase64Url(w, early);
            try w.writeAll("\r\n");
        }
        try w.writeAll("Sec-WebSocket-Version: 13\r\nUpgrade: websocket\r\n\r\n");
        try w.flush();
        try c.readAnswer();
        c.upgraded = true;
    }

    /// The answer up to its empty line; the frames behind it stay in `r`.
    /// Checked as gorilla does: status 101, Upgrade lists "websocket",
    /// Connection lists "upgrade", and Sec-WebSocket-Accept is right.
    /// Anything else in it (a CDN adds plenty) does not matter.
    fn readAnswer(c: *Conn) HandshakeError!void {
        var buf: [256]u8 = undefined;
        var budget: usize = max_answer;
        // "HTTP/1.1 101 Switching Protocols"
        const status = try c.answerLine(&buf, &budget);
        if (status.len < 12 or !std.mem.startsWith(u8, status, "HTTP/1.") or status[8] != ' ')
            return c.fail(error.WsBadHandshake);
        c.status = std.fmt.parseInt(u16, status[9..12], 10) catch return c.fail(error.WsBadHandshake);
        if (c.status != 101) return c.fail(error.WsUpgradeRefused);

        var expect: [28]u8 = undefined;
        acceptFor(&c.key, &expect);
        var upgrade_ok = false;
        var connection_ok = false;
        var accept_ok = false;
        while (true) {
            const line = try c.answerLine(&buf, &budget);
            if (line.len == 0) break;
            const colon = std.mem.findScalar(u8, line, ':') orelse continue;
            const name = line[0..colon];
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(name, "upgrade")) {
                upgrade_ok = upgrade_ok or hasToken(value, "websocket");
            } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
                connection_ok = connection_ok or hasToken(value, "upgrade");
            } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-accept")) {
                accept_ok = accept_ok or std.mem.eql(u8, value, &expect);
            }
        }
        if (!upgrade_ok or !connection_ok or !accept_ok) return c.fail(error.WsBadHandshake);
    }

    /// The next line of the answer without its CRLF. What of a long line
    /// does not fit `buf` is skipped: no header we check is that long.
    fn answerLine(c: *Conn, buf: []u8, budget: *usize) HandshakeError![]const u8 {
        var n: usize = 0;
        while (true) {
            const chunk = c.r.peekGreedy(1) catch |e| switch (e) {
                error.EndOfStream => return c.fail(error.WsBadHandshake),
                error.ReadFailed => return error.ReadFailed,
            };
            const nl = std.mem.findScalar(u8, chunk, '\n');
            const take = if (nl) |i| i + 1 else chunk.len;
            if (take > budget.*) return c.fail(error.WsBadHandshake);
            budget.* -= take;
            const k = @min(take, buf.len - n);
            @memcpy(buf[n..][0..k], chunk[0..k]);
            n += k;
            c.r.toss(take);
            if (nl != null) return std.mem.trimEnd(u8, buf[0..n], "\r\n");
        }
    }

    // ------------------------------------------------------------ writing

    /// Put a final, masked frame header for `payload` into the `head_room`
    /// bytes in front of it, which the caller owns, mask the payload in
    /// place and return the whole frame. Called with `mutex` held.
    fn seal(c: *Conn, op: Opcode, payload: []u8) []u8 {
        var key: [4]u8 = undefined;
        c.io.random(&key);
        mask(payload, key);
        var h: [head_room]u8 = undefined;
        h[0] = 0x80 | @as(u8, @backingInt(op));
        var n: usize = 2;
        switch (payload.len) {
            0...125 => h[1] = 0x80 | @as(u8, @intCast(payload.len)),
            126...0xffff => {
                h[1] = 0x80 | 126;
                std.mem.writeInt(u16, h[2..4], @intCast(payload.len), .big);
                n = 4;
            },
            else => {
                h[1] = 0x80 | 127;
                std.mem.writeInt(u64, h[2..10], payload.len, .big);
                n = 10;
            },
        }
        h[n..][0..4].* = key;
        n += 4;
        const start = payload.ptr - n;
        @memcpy(start[0..n], h[0..n]);
        return start[0 .. n + payload.len];
    }

    /// What `writer` holds leaves as one frame, or as the early data of an
    /// upgrade that waits for it.
    fn sendBuffered(c: *Conn) Io.Writer.Error!void {
        const wr = &c.writer;
        if (wr.end == 0 and c.settled.isSet()) return;
        c.mutex.lockUncancelable(c.io);
        defer c.release();
        if (!c.settled.isSet()) {
            if (wr.end == 0) return; // nothing to carry yet: keep waiting
            // all of the first write fits, or none of it goes early (Xray)
            const first = wr.buffered();
            const early = first.len <= c.early;
            c.upgrade(if (early) first else "") catch return error.WriteFailed;
            if (early) {
                wr.end = 0;
                return;
            }
        }
        if (!c.upgraded or c.closed) return error.WriteFailed;
        const n = wr.end;
        wr.end = 0;
        if (n > 0) try c.w.writeAll(c.seal(.binary, wr.buffer[0..n]));
        try c.writeOwed();
        try c.w.flush();
    }

    /// Unlock, then send any reply the reader left while we held the lock.
    fn release(c: *Conn) void {
        c.mutex.unlock(c.io);
        c.payOwed();
    }

    /// Send the replies the reader owes if the lock is free; while it is
    /// not, its holder sends them before letting go (see `release`).
    fn payOwed(c: *Conn) void {
        while (c.owe_pong.load(.seq_cst) or c.owe_close.load(.seq_cst)) {
            if (!c.mutex.tryLock()) return;
            const sent = if (c.writeOwed()) |_| (if (c.w.flush()) |_| true else |_| false) else |_| false;
            c.mutex.unlock(c.io);
            if (!sent) return;
        }
    }

    /// The reader's pending replies; `mutex` is held.
    fn writeOwed(c: *Conn) Io.Writer.Error!void {
        var f: [head_room + 125]u8 = undefined;
        if (c.owe_pong.load(.acquire)) {
            const p = f[head_room..][0..c.pong_len];
            @memcpy(p, c.pong[0..c.pong_len]);
            c.owe_pong.store(false, .release); // `pong` is the reader's again
            if (c.upgraded and !c.closed) try c.w.writeAll(c.seal(.pong, p));
        }
        if (c.owe_close.load(.acquire)) {
            c.owe_close.store(false, .release);
            if (c.upgraded and !c.closed) {
                c.closed = true;
                const p = f[head_room..][0..c.close_reply_len];
                @memcpy(p, c.close_reply[0..c.close_reply_len]);
                try c.w.writeAll(c.seal(.close, p));
            }
        }
    }

    fn drain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const c: *Conn = @alignCast(@fieldParentPtr("writer", io_w));
        // top the buffer up and send it whole, so frames are as large as it
        var n: usize = 0;
        fill: for (data, 0..) |d, i| {
            if (d.len == 0) continue;
            for (0..if (i == data.len - 1) splat else 1) |_| {
                const k = @min(d.len, io_w.buffer.len - io_w.end);
                @memcpy(io_w.buffer[io_w.end..][0..k], d[0..k]);
                io_w.end += k;
                n += k;
                if (k < d.len) break :fill;
            }
        }
        try c.sendBuffered();
        return n;
    }

    fn flush(io_w: *Io.Writer) Io.Writer.Error!void {
        const c: *Conn = @alignCast(@fieldParentPtr("writer", io_w));
        return c.sendBuffered();
    }

    // ------------------------------------------------------------ reading

    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const c: *Conn = @alignCast(@fieldParentPtr("reader", io_r));
        switch (c.rstate) {
            .open => {},
            .eof => return error.EndOfStream,
            .failed => return error.ReadFailed,
        }
        if (!c.settled.isSet()) c.awaitUpgrade();
        if (!c.upgraded) {
            // closed before the upgrade is an end, a failed upgrade an error
            c.rstate = if (c.closed and c.err == null) .eof else .failed;
            return if (c.rstate == .eof) error.EndOfStream else error.ReadFailed;
        }
        while (c.left == 0) c.nextFrame() catch |e| {
            c.rstate = if (e == error.EndOfStream) .eof else .failed;
            return e;
        };
        const n = c.r.stream(w, limit.min(.limited64(c.left))) catch |e| switch (e) {
            error.EndOfStream => {
                c.rstate = .failed;
                return c.readFailed(error.WsTruncated);
            },
            error.ReadFailed => {
                c.rstate = .failed;
                return error.ReadFailed;
            },
            error.WriteFailed => return error.WriteFailed,
        };
        c.left -= n;
        return n;
    }

    /// The upgrade waits for the first flush (early data). That normally
    /// comes within half a second; if it has not come within a second the
    /// writer gave up, and we upgrade without early data rather than wait
    /// forever. While the lock is busy the writer is upgrading: wait for it.
    fn awaitUpgrade(c: *Conn) void {
        c.settled.waitTimeout(c.io, first_write_wait) catch {};
        if (!c.settled.isSet() and c.mutex.tryLock()) {
            if (!c.settled.isSet()) c.upgrade("") catch {};
            c.release();
        }
        c.settled.waitUncancelable(c.io);
    }

    fn readFailed(c: *Conn, e: Error) error{ReadFailed} {
        c.err = e;
        return error.ReadFailed;
    }

    /// Exactly `buf.len` bytes from below. Through `stream`, so the TLS
    /// record behind a frame header is not first copied into the buffer of
    /// the reader below.
    fn below(c: *Conn, buf: []u8) error{ReadFailed}!void {
        var w: Io.Writer = .fixed(buf);
        c.r.streamExact(&w, buf.len) catch |e| switch (e) {
            error.EndOfStream => return c.readFailed(error.WsTruncated),
            error.ReadFailed => return error.ReadFailed,
            error.WriteFailed => unreachable,
        };
    }

    /// Read frame headers until a data frame with payload begins, answering
    /// control frames on the way. Text frames are data too (as in Xray), and
    /// message boundaries mean nothing: a CDN may cut frames anew. Strict
    /// like gorilla: no extension bits, no masked or unknown frames, control
    /// frames short and whole, continuations only inside a message.
    /// EndOfStream: the server closed normally.
    fn nextFrame(c: *Conn) error{ EndOfStream, ReadFailed }!void {
        var h: [8]u8 = undefined;
        try c.below(h[0..2]);
        const fin = h[0] & 0x80 != 0;
        const op = std.enums.fromInt(Opcode, h[0] & 0x0f) orelse return c.protocolError();
        if (h[0] & 0x70 != 0 or h[1] & 0x80 != 0) return c.protocolError();
        var len: u64 = h[1] & 0x7f;
        if (len == 126) {
            try c.below(h[0..2]);
            len = std.mem.readInt(u16, h[0..2], .big);
        } else if (len == 127) {
            try c.below(h[0..8]);
            len = std.mem.readInt(u64, h[0..8], .big);
            if (len >> 63 != 0) return c.protocolError();
        }
        switch (op) {
            .continuation, .text, .binary => {
                if ((op == .continuation) != c.in_message) return c.protocolError();
                c.in_message = !fin;
                c.left = len;
            },
            .close, .ping, .pong => {
                if (!fin or len > 125) return c.protocolError();
                var p: [125]u8 = undefined;
                const payload = p[0..@intCast(len)];
                try c.below(payload);
                switch (op) {
                    .ping => c.owePong(payload),
                    .close => return c.closeReceived(payload),
                    else => {},
                }
            },
        }
    }

    /// The server closes: reply with its code and no reason (as gorilla
    /// does) and end the stream. Only 1000 and "no code" are a normal end;
    /// Xray reports any other code as an error.
    fn closeReceived(c: *Conn, p: []const u8) error{ EndOfStream, ReadFailed } {
        if (p.len == 1) return c.protocolError();
        c.close_code = 1005;
        if (p.len >= 2) {
            c.close_code = std.mem.readInt(u16, p[0..2], .big);
            if (!validCloseCode(c.close_code) or !std.unicode.utf8ValidateSlice(p[2..]))
                return c.protocolError();
        }
        c.oweClose(p[0..@min(p.len, 2)]);
        if (c.close_code == 1000 or c.close_code == 1005) return error.EndOfStream;
        return c.readFailed(error.WsClosedAbnormally);
    }

    fn protocolError(c: *Conn) error{ReadFailed} {
        c.oweClose(&.{ 0x03, 0xea }); // 1002
        return c.readFailed(error.WsProtocolError);
    }

    fn owePong(c: *Conn, payload: []const u8) void {
        // a pong still owed answers this ping as well (RFC 6455 5.5.3)
        if (!c.owe_pong.load(.acquire)) {
            @memcpy(c.pong[0..payload.len], payload);
            c.pong_len = @intCast(payload.len);
            c.owe_pong.store(true, .seq_cst);
        }
        c.payOwed();
    }

    /// Only one close is ever owed: the reader stops after it.
    fn oweClose(c: *Conn, payload: []const u8) void {
        @memcpy(c.close_reply[0..payload.len], payload);
        c.close_reply_len = @intCast(payload.len);
        c.owe_close.store(true, .seq_cst);
        c.payOwed();
    }
};

/// Close codes a server may send (gorilla's list): the IANA ones in use and
/// the 3000-4999 range for applications.
fn validCloseCode(code: u16) bool {
    return switch (code) {
        1000...1003, 1007...1013, 3000...4999 => true,
        else => false,
    };
}

fn mask(bytes: []u8, key: [4]u8) void {
    const len = std.simd.suggestVectorLength(u8) orelse 16;
    const V = @Vector(len, u8);
    var pattern: [len]u8 = undefined;
    for (&pattern, 0..) |*b, j| b.* = key[j & 3];
    const k: V = pattern;
    var i: usize = 0;
    while (i + len <= bytes.len) : (i += len) {
        const v: V = bytes[i..][0..len].*;
        bytes[i..][0..len].* = v ^ k;
    }
    // `i` is a multiple of 4: the key lines up again
    for (bytes[i..], 0..) |*b, j| b.* ^= key[j & 3];
}

fn acceptFor(key: *const [24]u8, out: *[28]u8) void {
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(key);
    sha.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    _ = std.base64.standard.Encoder.encode(out, &sha.finalResult());
}

/// Whether a comma-separated header value lists `token`, in any case.
fn hasToken(value: []const u8, token: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, value, ',');
    while (it.next()) |t| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, t, " \t"), token)) return true;
    }
    return false;
}

/// A Host value is one token: no spaces, controls or line breaks.
fn validHost(host: []const u8) bool {
    if (host.len == 0) return false;
    for (host) |b| if (b <= ' ' or b >= 0x7f) return false;
    return true;
}

fn writeBase64Url(w: *Io.Writer, bytes: []const u8) Io.Writer.Error!void {
    const enc = std.base64.url_safe_no_pad.Encoder;
    var out: [1024]u8 = undefined;
    var rest = bytes;
    while (rest.len > 0) {
        const n = @min(rest.len, 768); // a multiple of 3: no padding mid-way
        try w.writeAll(enc.encode(&out, rest[0..n]));
        rest = rest[n..];
    }
}

// ---------------------------------------------------------------- the request

/// The request up to Sec-WebSocket-Key, as Xray writes it: Go puts Host and
/// User-Agent first and sorts the rest by name; the names and values are
/// Xray's Chrome disguise (common/utils/browser.go) plus gorilla's own.
/// Returns the early-data budget the path asks for.
fn writeRequestHead(w: *Io.Writer, path: []const u8, host: []const u8, key: *const [24]u8, chrome: u32) (Error || Io.Writer.Error)!u32 {
    try w.writeAll("GET ");
    const ed = try writeTarget(w, path);
    try w.print(" HTTP/1.1\r\nHost: {s}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) " ++
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{d}.0.0.0 Safari/537.36\r\n" ++
        "Accept: */*\r\nAccept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\n" ++
        "Connection: Upgrade\r\nDNT: 1\r\nPragma: no-cache\r\nSec-CH-UA: ", .{ host, chrome });
    try writeBrands(w, chrome);
    try w.print("\r\nSec-CH-UA-Mobile: ?0\r\nSec-CH-UA-Platform: \"Windows\"\r\nSec-Fetch-Dest: empty\r\n" ++
        "Sec-Fetch-Mode: websocket\r\nSec-Fetch-Site: same-origin\r\nSec-WebSocket-Key: {s}\r\n", .{key});
    return ed;
}

/// Write the request target for a link's path; return the early-data budget
/// its query asks for. As Xray: a leading '/' is added if missing, and when
/// the query has `ed` with a value, `ed` leaves it and the rest is sorted by
/// name (Go re-encodes it so; values here keep their spelling). Otherwise
/// the query goes as it is. Bytes a request line cannot carry are
/// percent-encoded and a fragment is dropped, as Go does.
fn writeTarget(w: *Io.Writer, path: []const u8) (Error || Io.Writer.Error)!u32 {
    const whole = path[0 .. std.mem.findScalar(u8, path, '#') orelse path.len];
    const q = std.mem.findScalar(u8, whole, '?');
    const p = whole[0 .. q orelse whole.len];
    if (p.len == 0 or p[0] != '/') try w.writeByte('/');
    try writeEscaped(w, p);
    const query = whole[(q orelse return 0) + 1 ..];

    var pairs: [32][]const u8 = undefined;
    var n: usize = 0;
    var ed: ?[]const u8 = null;
    var it = std.mem.tokenizeScalar(u8, query, '&');
    while (it.next()) |kv| {
        const eq = std.mem.findScalar(u8, kv, '=');
        if (std.mem.eql(u8, kv[0 .. eq orelse kv.len], "ed")) {
            if (ed == null) ed = if (eq) |i| kv[i + 1 ..] else "";
            continue;
        }
        if (n == pairs.len) return error.WsBadOptions;
        pairs[n] = kv;
        n += 1;
    }
    const budget = ed orelse "";
    if (budget.len == 0) { // Xray leaves such a query alone
        try w.writeByte('?');
        try writeEscaped(w, query);
        return 0;
    }
    std.sort.insertion([]const u8, pairs[0..n], {}, nameLess);
    for (pairs[0..n], 0..) |kv, i| {
        try w.writeByte(if (i == 0) '?' else '&');
        try writeEscaped(w, kv);
        if (std.mem.findScalar(u8, kv, '=') == null) try w.writeByte('=');
    }
    return earlyBudget(budget);
}

fn nameLess(_: void, a: []const u8, b: []const u8) bool {
    const an = a[0 .. std.mem.findScalar(u8, a, '=') orelse a.len];
    const bn = b[0 .. std.mem.findScalar(u8, b, '=') orelse b.len];
    return std.mem.lessThan(u8, an, bn);
}

/// `ed` as Xray reads it (Atoi, then uint32): not a number is 0, a negative
/// one wraps around to a huge budget. Capped to what we put in a request.
fn earlyBudget(text: []const u8) u32 {
    const n = std.fmt.parseInt(i64, text, 10) catch |e| return switch (e) {
        error.Overflow => max_early,
        error.InvalidCharacter => 0,
    };
    const wrapped: u32 = @truncate(@as(u64, @bitCast(n)));
    return @min(wrapped, max_early);
}

/// RFC 3986 characters a request target carries as they are (unreserved,
/// sub-delims, ':', '@', '/', '?', '[', ']' and '%' of escapes already
/// there); any other byte goes percent-encoded.
fn writeEscaped(w: *Io.Writer, s: []const u8) Io.Writer.Error!void {
    for (s) |b| {
        if (std.ascii.isAlphanumeric(b) or std.mem.findScalar(u8, "-._~!$&'()*+,;=:@/?[]%", b) != null) {
            try w.writeByte(b);
        } else {
            try w.print("%{X:0>2}", .{b});
        }
    }
}

/// Chrome's major version as Xray derives it from the date: 144 on
/// 2026-01-13, one more every 35 days after a 35-day lag. Xray adds a
/// random lag of up to 105 days, fixed per machine; we add none and claim
/// the newest version, which most Chrome installations run.
fn chromeMajor(now_s: i64) u32 {
    const days = @divFloor(now_s, 86400) - 20466; // 2026-01-13
    return 144 + @as(u32, @intCast(@max(0, @divTrunc(days - 35, 35))));
}

/// Sec-CH-UA for Chrome `v` the way Chromium greases it (seeded by the
/// version): a made-up brand, Chromium and Google Chrome, in an order that
/// depends on the version.
fn writeBrands(w: *Io.Writer, v: u32) Io.Writer.Error!void {
    const grease = " (:-./);=?_";
    const grease_versions = [_][]const u8{ "8", "99", "24" };
    const orders = [6][3]u2{ .{ 0, 1, 2 }, .{ 0, 2, 1 }, .{ 1, 0, 2 }, .{ 1, 2, 0 }, .{ 2, 0, 1 }, .{ 2, 1, 0 } };
    // brand i goes to place order[i]
    var at: [3]u2 = undefined;
    for (orders[v % 6], 0..) |place, i| at[place] = @intCast(i);
    for (at, 0..) |brand, i| {
        if (i > 0) try w.writeAll(", ");
        switch (brand) {
            0 => try w.print("\"Not{c}A{c}Brand\";v=\"{s}\"", .{ grease[v % 11], grease[(v + 1) % 11], grease_versions[v % 3] }),
            1 => try w.print("\"Chromium\";v=\"{d}\"", .{v}),
            else => try w.print("\"Google Chrome\";v=\"{d}\"", .{v}),
        }
    }
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

/// A client frame as the server sees it, unmasked in place.
const Seen = struct { op: u8, fin: bool, payload: []u8 };

/// Take the next client frame off the front of `bytes`; it must be masked.
fn takeClientFrame(bytes: *[]u8) !Seen {
    const b = bytes.*;
    if (b.len < 2) return error.TestUnexpectedResult;
    try testing.expect(b[1] & 0x80 != 0);
    var len: usize = b[1] & 0x7f;
    var i: usize = 2;
    if (len == 126) {
        len = std.mem.readInt(u16, b[2..4], .big);
        i = 4;
    } else if (len == 127) {
        len = @intCast(std.mem.readInt(u64, b[2..10], .big));
        i = 10;
    }
    const key = b[i..][0..4].*;
    i += 4;
    const p = b[i..][0..len];
    for (p, 0..) |*x, j| x.* ^= key[j & 3];
    bytes.* = b[i + len ..];
    return .{ .op = b[0] & 0x0f, .fin = b[0] & 0x80 != 0, .payload = p };
}

/// A server frame (never masked).
fn putFrame(w: *Io.Writer, b0: u8, payload: []const u8) !void {
    if (payload.len < 126) {
        try w.writeAll(&.{ b0, @intCast(payload.len) });
    } else if (payload.len <= 0xffff) {
        try w.writeAll(&.{ b0, 126 });
        try w.writeInt(u16, @intCast(payload.len), .big);
    } else {
        try w.writeAll(&.{ b0, 127 });
        try w.writeInt(u64, payload.len, .big);
    }
    try w.writeAll(payload);
}

fn headerValue(req: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, req, "\r\n");
    while (it.next()) |line| {
        if (line.len > name.len + 1 and std.mem.startsWith(u8, line, name) and line[name.len] == ':')
            return std.mem.trim(u8, line[name.len + 1 ..], " ");
    }
    return null;
}

/// In-process server for tests on one thread. What the client writes lands
/// in `up`; its first read finds the request complete and gets `answer`
/// (with ACCEPT standing for the right Sec-WebSocket-Accept) and `frames`.
const Script = struct {
    up_buf: [96 * 1024]u8 = undefined,
    up: Io.Writer = undefined,
    down_buf: [96 * 1024]u8 = undefined,
    down: Io.Reader = undefined,
    answer: []const u8 = ok_answer,
    frames: []const u8 = "",
    answered: bool = false,
    rbuf: [64]u8 = undefined,
    wbuf: [256]u8 = undefined,
    c: Conn = undefined,

    const ok_answer = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ACCEPT\r\n\r\n";

    fn init(s: *Script) void {
        s.up = .fixed(&s.up_buf);
        s.down = .{ .vtable = &.{ .stream = respond }, .buffer = &s.down_buf, .seek = 0, .end = 0 };
        s.c = .init(testing.io, &s.down, &s.up, &s.rbuf, &s.wbuf);
    }

    fn respond(r: *Io.Reader, _: *Io.Writer, _: Io.Limit) Io.Reader.StreamError!usize {
        const s: *Script = @alignCast(@fieldParentPtr("down", r));
        if (s.answered) return error.EndOfStream;
        s.answered = true;
        var accept: [28]u8 = undefined;
        const key = headerValue(s.up.buffered(), "Sec-WebSocket-Key") orelse return error.EndOfStream;
        acceptFor(key[0..24], &accept);
        const n = std.mem.replace(u8, s.answer, "ACCEPT", &accept, r.buffer);
        const len = s.answer.len + n * (accept.len - "ACCEPT".len);
        @memcpy(r.buffer[len..][0..s.frames.len], s.frames);
        r.end = len + s.frames.len;
        return 0;
    }

    /// Everything the client sent after its request.
    fn framesUp(s: *Script) []u8 {
        const all = s.up.buffered();
        return all[std.mem.find(u8, all, "\r\n\r\n").? + 4 ..];
    }
};

test "the request is Xray's, byte for byte" {
    var buf: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    try testing.expectEqual(@as(u32, 0), try writeRequestHead(&w, "/ws", "ws.blackwall.test", key, 151));
    try w.writeAll("Sec-WebSocket-Version: 13\r\nUpgrade: websocket\r\n\r\n");
    // captured from Xray 26.11.9 on this machine (only the key differs)
    const xray = "GET /ws HTTP/1.1\r\nHost: ws.blackwall.test\r\n" ++
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36\r\n" ++
        "Accept: */*\r\nAccept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nConnection: Upgrade\r\nDNT: 1\r\nPragma: no-cache\r\n" ++
        "Sec-CH-UA: \"Not=A?Brand\";v=\"99\", \"Google Chrome\";v=\"151\", \"Chromium\";v=\"151\"\r\n" ++
        "Sec-CH-UA-Mobile: ?0\r\nSec-CH-UA-Platform: \"Windows\"\r\nSec-Fetch-Dest: empty\r\nSec-Fetch-Mode: websocket\r\nSec-Fetch-Site: same-origin\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nUpgrade: websocket\r\n\r\n";
    try testing.expectEqualStrings(xray, w.buffered());
    try testing.expectEqual(@as(usize, 590), w.buffered().len);
}

test "Chrome version and client hints follow the date" {
    try testing.expectEqual(@as(u32, 151), chromeMajor(1_794_614_400)); // 2026-11-14
    try testing.expectEqual(@as(u32, 144), chromeMajor(1_768_262_400)); // 2026-01-13
    try testing.expectEqual(@as(u32, 144), chromeMajor(0)); // a clock that is off
    var buf: [128]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeBrands(&w, 144); // places {0,1,2}
    try testing.expectEqualStrings("\"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"144\", \"Google Chrome\";v=\"144\"", w.buffered());
    w.end = 0;
    try writeBrands(&w, 147); // places {1,2,0}: the made-up brand second, Chromium third
    try testing.expectEqualStrings("\"Google Chrome\";v=\"147\", \"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"147\"", w.buffered());
}

test "paths: leading slash, early data taken out, the rest sorted" {
    const cases = [_]struct { in: []const u8, out: []const u8, ed: u32 }{
        .{ .in = "", .out = "/", .ed = 0 },
        .{ .in = "ws", .out = "/ws", .ed = 0 },
        .{ .in = "/ws?ed=2048", .out = "/ws", .ed = 2048 },
        .{ .in = "/a?z=1&ed=9&b=2", .out = "/a?b=2&z=1", .ed = 9 },
        .{ .in = "/a?z=1&b", .out = "/a?z=1&b", .ed = 0 },
        .{ .in = "/a?b&ed=1", .out = "/a?b=", .ed = 1 },
        .{ .in = "/ws?ed=", .out = "/ws?ed=", .ed = 0 },
        .{ .in = "/ws?ed=abc", .out = "/ws", .ed = 0 },
        .{ .in = "/ws?ed=-1", .out = "/ws", .ed = max_early },
        .{ .in = "/ws?", .out = "/ws?", .ed = 0 },
        .{ .in = "/a b\r\n\"x\"#frag", .out = "/a%20b%0D%0A%22x%22", .ed = 0 },
        .{ .in = "/assets/v2/0ab~_.-", .out = "/assets/v2/0ab~_.-", .ed = 0 },
    };
    for (cases) |t| {
        var buf: [128]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        const ed = try writeTarget(&w, t.in);
        try testing.expectEqualStrings(t.out, w.buffered());
        try testing.expectEqual(t.ed, ed);
    }
    try testing.expect(!validHost("a b"));
    try testing.expect(!validHost("a\r\nX: y"));
    try testing.expect(!validHost(""));
    try testing.expect(validHost("[2001:db8::1]"));
}

test "upgrade, then frames down: fragments, pings, text, every length form" {
    var s: Script = .{};
    var big: [70000]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @truncate(i *% 7);
    var frames_buf: [80 * 1024]u8 = undefined;
    var f: Io.Writer = .fixed(&frames_buf);
    try putFrame(&f, 0x82, "hello "); // binary
    try putFrame(&f, 0x89, "p1"); // ping
    try putFrame(&f, 0x01, "wor"); // text, unfinished
    try putFrame(&f, 0x89, "p2"); // control frames may come inside a message
    try putFrame(&f, 0x8a, "ignored"); // pong
    try putFrame(&f, 0x80, "ld"); // continuation, final
    try putFrame(&f, 0x82, big[0..300]); // 16-bit length
    try putFrame(&f, 0x82, &big); // 64-bit length
    try putFrame(&f, 0x82, ""); // empty frames are skipped
    try putFrame(&f, 0x88, &.{ 0x03, 0xe8 }); // close 1000
    s.frames = f.buffered();
    s.init();
    try s.c.handshake(.{ .path = "/ws", .host = "ws.blackwall.test" });
    try testing.expectEqual(@as(u16, 101), s.c.status);

    var got_buf: [80 * 1024]u8 = undefined;
    var got: Io.Writer = .fixed(&got_buf);
    _ = try s.c.reader.streamRemaining(&got);
    try testing.expect(std.mem.startsWith(u8, got.buffered(), "hello world"));
    try testing.expectEqualSlices(u8, big[0..300], got.buffered()[11..][0..300]);
    try testing.expectEqualSlices(u8, &big, got.buffered()[311..]);
    try testing.expectEqual(@as(u16, 1000), s.c.close_code);
    try testing.expectError(error.EndOfStream, s.c.reader.takeByte()); // and it stays ended

    // up: a pong per ping, then the close reply with the server's code
    var up = s.framesUp();
    const p1 = try takeClientFrame(&up);
    try testing.expectEqual(@as(u8, 0xa), p1.op);
    try testing.expectEqualStrings("p1", p1.payload);
    const p2 = try takeClientFrame(&up);
    try testing.expectEqualStrings("p2", p2.payload);
    const bye = try takeClientFrame(&up);
    try testing.expectEqual(@as(u8, 0x8), bye.op);
    try testing.expectEqualSlices(u8, &.{ 0x03, 0xe8 }, bye.payload);
    try testing.expectEqual(@as(usize, 0), up.len);
    // after the close, nothing more goes out: no data, no second close
    const sent = s.up.end;
    try s.c.writer.writeAll("late");
    try testing.expectError(error.WriteFailed, s.c.writer.flush());
    s.c.close();
    try testing.expectEqual(sent, s.up.end);
}

test "frames up: one masked binary frame per flush, header room used in place" {
    var s: Script = .{};
    s.init();
    try s.c.handshake(.{ .path = "/ws", .host = "h" });
    try s.c.writer.writeAll("abc");
    try s.c.writer.flush();
    var big: [1000]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @truncate(i);
    try s.c.writer.writeAll(&big); // larger than the 242-byte buffer: full frames
    try s.c.writer.flush();
    s.c.close();

    var up = s.framesUp();
    const first = try takeClientFrame(&up);
    try testing.expectEqual(@as(u8, 0x2), first.op);
    try testing.expect(first.fin);
    try testing.expectEqualStrings("abc", first.payload);
    var all: [1000]u8 = undefined;
    var n: usize = 0;
    while (true) {
        const fr = try takeClientFrame(&up);
        if (fr.op == 0x8) {
            try testing.expectEqualSlices(u8, &.{ 0x03, 0xe8 }, fr.payload);
            break;
        }
        try testing.expectEqual(@as(u8, 0x2), fr.op);
        try testing.expect(fr.payload.len <= 256 - head_room);
        @memcpy(all[n..][0..fr.payload.len], fr.payload);
        n += fr.payload.len;
    }
    try testing.expectEqualSlices(u8, &big, all[0..n]);
    try testing.expectEqual(@as(usize, 0), up.len);
}

test "early data rides in the request; too much of it goes as a frame" {
    {
        var s: Script = .{};
        s.init();
        try s.c.handshake(.{ .path = "/ws?ed=2048", .host = "h" });
        try testing.expect(!s.answered); // nothing goes out before the first flush
        try s.c.writer.writeAll("vless header and data");
        try s.c.writer.flush();
        const req = s.up.buffered();
        try testing.expect(std.mem.startsWith(u8, req, "GET /ws HTTP/1.1\r\n"));
        var b64: [64]u8 = undefined;
        const want = std.base64.url_safe_no_pad.Encoder.encode(&b64, "vless header and data");
        try testing.expectEqualStrings(want, headerValue(req, "Sec-WebSocket-Protocol").?);
        try testing.expectEqual(@as(usize, 0), s.framesUp().len); // not sent again as a frame
        try s.c.writer.writeAll("more");
        try s.c.writer.flush();
        var up = s.framesUp();
        try testing.expectEqualStrings("more", (try takeClientFrame(&up)).payload);
    }
    {
        var s: Script = .{};
        s.init();
        try s.c.handshake(.{ .path = "/ws?ed=8", .host = "h" });
        try s.c.writer.writeAll("nine bytes");
        try s.c.writer.flush();
        try testing.expect(headerValue(s.up.buffered(), "Sec-WebSocket-Protocol") == null);
        var up = s.framesUp();
        try testing.expectEqualStrings("nine bytes", (try takeClientFrame(&up)).payload);
    }
}

test "refused and broken upgrades" {
    const answers = [_]struct { answer: []const u8, err: Error, status: u16 }{
        .{ .answer = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", .err = error.WsUpgradeRefused, .status = 404 },
        .{ .answer = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n", .err = error.WsBadHandshake, .status = 101 },
        .{ .answer = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ACCEPT\r\n\r\n", .err = error.WsBadHandshake, .status = 101 },
        // h2 chosen by ALPN: the server opens with SETTINGS
        .{ .answer = "\x00\x00\x12\x04\x00\x00\x00\x00\x00", .err = error.WsBadHandshake, .status = 0 },
        .{ .answer = "HTTP/1.1 101 Switching", .err = error.WsBadHandshake, .status = 0 },
        .{ .answer = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n", .err = error.WsBadHandshake, .status = 101 },
    };
    for (answers) |t| {
        var s: Script = .{ .answer = t.answer };
        s.init();
        try testing.expectError(t.err, s.c.handshake(.{ .path = "/ws", .host = "h" }));
        try testing.expectEqual(t.err, s.c.err.?);
        try testing.expectEqual(t.status, s.c.status);
        try testing.expectError(error.ReadFailed, s.c.reader.takeByte());
    }
    // what a CDN adds: long lines, lists and other spellings
    var s: Script = .{ .answer = "HTTP/1.1 101 Switching Protocols\r\nDate: x\r\nconnection: keep-alive, UPGRADE\r\n" ++
        "Report-To: {\"endpoints\":[{\"url\":\"https:\\/\\/a.example\\/report\\/v4?s=" ++ @as([400]u8, @splat('x')) ++ "\"}]}\r\n" ++
        "upgrade: WebSocket\r\nsec-websocket-accept:ACCEPT\r\nServer: cloudflare\r\n\r\n" };
    s.init();
    try s.c.handshake(.{ .path = "/ws", .host = "h" });
}

test "bad frames from the server fail the stream and are answered with 1002" {
    const bad = [_][]const u8{
        &.{ 0x82, 0x81, 1, 2, 3, 4, 'x' }, // masked
        &.{ 0xc2, 0x01, 'x' }, // RSV1 without an extension
        &.{ 0x80, 0x01, 'x' }, // continuation of nothing
        &.{ 0x02, 0x01, 'x', 0x82, 0x01, 'y' }, // new message inside one
        &.{ 0x83, 0x00 }, // reserved opcode
        &.{ 0x09, 0x00 }, // fragmented ping
        &.{ 0x88, 0x01, 0x03 }, // close with half a code
        &.{ 0x88, 0x02, 0x03, 0xed }, // 1005 must not be sent
        &.{ 0x88, 0x04, 0x03, 0xe8, 0xff, 0xfe }, // reason not UTF-8
    };
    for (bad) |frames| {
        var s: Script = .{ .frames = frames };
        s.init();
        try s.c.handshake(.{ .path = "/ws", .host = "h" });
        var sink: [16]u8 = undefined;
        var w: Io.Writer = .fixed(&sink);
        try testing.expectError(error.ReadFailed, s.c.reader.streamRemaining(&w));
        try testing.expectEqual(error.WsProtocolError, s.c.err.?);
        var up = s.framesUp();
        const bye = try takeClientFrame(&up);
        try testing.expectEqual(@as(u8, 0x8), bye.op);
        try testing.expectEqualSlices(u8, &.{ 0x03, 0xea }, bye.payload);
    }
}

test "how the stream ends: close codes and truncation" {
    const ends = [_]struct { frames: []const u8, err: ?Error, code: u16 }{
        .{ .frames = &.{ 0x82, 0x01, 'x', 0x88, 0x00 }, .err = null, .code = 1005 },
        .{ .frames = &.{ 0x82, 0x01, 'x', 0x88, 0x06, 0x03, 0xe9, 'b', 'y', 'e', '!' }, .err = error.WsClosedAbnormally, .code = 1001 },
        .{ .frames = &.{ 0x82, 0x01, 'x' }, .err = error.WsTruncated, .code = 0 },
        .{ .frames = &.{ 0x82, 0x05, 'x' }, .err = error.WsTruncated, .code = 0 },
        .{ .frames = &.{ 0x82, 0x01, 'x', 0x82, 0x7e, 0x01 }, .err = error.WsTruncated, .code = 0 },
    };
    for (ends) |t| {
        var s: Script = .{ .frames = t.frames };
        s.init();
        try s.c.handshake(.{ .path = "/ws", .host = "h" });
        var sink: [16]u8 = undefined;
        var w: Io.Writer = .fixed(&sink);
        if (t.err) |e| {
            try testing.expectError(error.ReadFailed, s.c.reader.streamRemaining(&w));
            try testing.expectEqual(e, s.c.err.?);
        } else {
            try testing.expectEqual(@as(usize, 1), try s.c.reader.streamRemaining(&w));
        }
        try testing.expectEqual(t.code, s.c.close_code);
        try testing.expectEqual('x', sink[0]);
    }
}

test "a reply owed while the writer holds the lock goes out when it lets go" {
    var s: Script = .{ .frames = &.{ 0x89, 0x02, 'h', 'i', 0x82, 0x01, 'x' } };
    s.init();
    try s.c.handshake(.{ .path = "/ws", .host = "h" });
    s.c.mutex.lockUncancelable(testing.io); // as if a frame were going out
    try testing.expectEqual('x', try s.c.reader.takeByte());
    try testing.expectEqual(@as(usize, 0), s.framesUp().len);
    s.c.release();
    var up = s.framesUp();
    const pong = try takeClientFrame(&up);
    try testing.expectEqual(@as(u8, 0xa), pong.op);
    try testing.expectEqualStrings("hi", pong.payload);
}

/// The server side of the threaded tests: a loopback listener whose one
/// connection is handed to `serve` on its own thread.
const Peer = struct {
    server: Io.net.Server = undefined,
    thread: std.Thread = undefined,
    failed: bool = false,

    const Serve = *const fn (Io.net.Stream) anyerror!void;

    fn start(p: *Peer, serve: Serve) !void {
        const address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        p.server = try address.listen(testing.io, .{ .reuse_address = true });
        p.thread = try std.Thread.spawn(.{}, run, .{ p, serve });
    }

    fn run(p: *Peer, serve: Serve) void {
        const conn = p.server.accept(testing.io) catch {
            p.failed = true;
            return;
        };
        defer conn.close(testing.io);
        serve(conn) catch {
            p.failed = true;
        };
    }

    fn connect(p: *Peer) !Io.net.Stream {
        const address: Io.net.IpAddress = .{ .ip4 = .loopback(p.server.socket.address.getPort()) };
        return address.connect(testing.io, .{ .mode = .stream });
    }

    fn finish(p: *Peer) !void {
        p.thread.join();
        p.server.deinit(testing.io);
        try testing.expect(!p.failed);
    }

    /// Read the request, check it, answer 101; returns the request's
    /// Sec-WebSocket-Protocol (early data), decoded into `ed`.
    fn accept(r: *Io.Reader, w: *Io.Writer, ed: []u8) ![]u8 {
        var req_buf: [2048]u8 = undefined;
        var n: usize = 0;
        while (std.mem.find(u8, req_buf[0..n], "\r\n\r\n") == null) {
            req_buf[n] = try r.takeByte();
            n += 1;
        }
        const req = req_buf[0..n];
        try testing.expect(std.mem.startsWith(u8, req, "GET /ws HTTP/1.1\r\nHost: ws.blackwall.test\r\n"));
        var accept_buf: [28]u8 = undefined;
        acceptFor(headerValue(req, "Sec-WebSocket-Key").?[0..24], &accept_buf);
        try w.print("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{&accept_buf});
        try w.flush();
        const proto = headerValue(req, "Sec-WebSocket-Protocol") orelse return ed[0..0];
        const len = try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(proto);
        try std.base64.url_safe_no_pad.Decoder.decode(ed[0..len], proto);
        return ed[0..len];
    }

    /// The next client frame off a socket, unmasked into `buf`.
    fn readFrame(r: *Io.Reader, buf: []u8) !Seen {
        const h = (try r.takeArray(2)).*;
        try testing.expect(h[1] & 0x80 != 0);
        var len: usize = h[1] & 0x7f;
        if (len == 126) len = try r.takeInt(u16, .big) else if (len == 127) len = @intCast(try r.takeInt(u64, .big));
        const key = (try r.takeArray(4)).*;
        try r.readSliceAll(buf[0..len]);
        for (buf[0..len], 0..) |*x, j| x.* ^= key[j & 3];
        return .{ .op = h[0] & 0x0f, .fin = h[0] & 0x80 != 0, .payload = buf[0..len] };
    }
};

/// Bytes of a test pattern, the same on both sides.
fn testByte(i: usize) u8 {
    return @truncate((i *% 2654435761) >> 13);
}

const bulk = 3 * 1024 * 1024;

/// Server of the threaded test: pings while data streams both ways, then
/// closes once it has all of ours.
fn serveBulk(conn: Io.net.Stream) !void {
    var rb: [16 * 1024]u8 = undefined;
    var wb: [16 * 1024]u8 = undefined;
    var sr = conn.reader(testing.io, &rb);
    var sw = conn.writer(testing.io, &wb);
    var ed: [64]u8 = undefined;
    _ = try Peer.accept(&sr.interface, &sw.interface, &ed);

    // our own writer thread: a ping between every chunk of downlink
    const Down = struct {
        w: *Io.Writer,
        mutex: *Io.Mutex,
        err: bool = false,
        fn run(d: *@This()) void {
            d.send() catch {
                d.err = true;
            };
        }
        fn send(d: *@This()) !void {
            var chunk: [5000]u8 = undefined;
            var sent: usize = 0;
            var pings: u8 = 0;
            while (sent < bulk) : (pings +%= 1) {
                const n = @min(chunk.len, bulk - sent);
                for (chunk[0..n], sent..) |*b, i| b.* = testByte(i);
                d.mutex.lockUncancelable(testing.io);
                defer d.mutex.unlock(testing.io);
                try putFrame(d.w, 0x82, chunk[0..n]);
                try putFrame(d.w, 0x89, &.{pings});
                try d.w.flush();
                sent += n;
            }
        }
    };
    var mutex: Io.Mutex = .init;
    var down: Down = .{ .w = &sw.interface, .mutex = &mutex };
    const t = try std.Thread.spawn(.{}, Down.run, .{&down});

    var buf: [64 * 1024]u8 = undefined;
    var got: usize = 0;
    var pongs: usize = 0;
    while (got < bulk) {
        const f = try Peer.readFrame(&sr.interface, &buf);
        switch (f.op) {
            0x2 => {
                for (f.payload, got..) |b, i| if (b != testByte(i)) return error.TestUnexpectedResult;
                got += f.payload.len;
            },
            0xa => pongs += 1,
            else => return error.TestUnexpectedResult,
        }
    }
    t.join();
    try testing.expect(!down.err);
    {
        mutex.lockUncancelable(testing.io);
        defer mutex.unlock(testing.io);
        try putFrame(&sw.interface, 0x88, &.{ 0x03, 0xe8 });
        try sw.interface.flush();
    }
    // pongs still in flight, then the close reply
    while (true) {
        const f = try Peer.readFrame(&sr.interface, &buf);
        if (f.op == 0xa) {
            pongs += 1;
            continue;
        }
        try testing.expectEqual(@as(u8, 0x8), f.op);
        try testing.expectEqualSlices(u8, &.{ 0x03, 0xe8 }, f.payload);
        break;
    }
    try testing.expect(pongs > 0);
}

test "a reading and a writing thread over a socket, pinged all along" {
    var peer: Peer = .{};
    try peer.start(serveBulk);
    const stream_ = try peer.connect();
    defer stream_.close(testing.io);
    var urb: [16 * 1024]u8 = undefined;
    var uwb: [4096]u8 = undefined;
    var ur = stream_.reader(testing.io, &urb);
    var uw = stream_.writer(testing.io, &uwb);
    var rbuf: [16 * 1024]u8 = undefined;
    var wbuf: [16 * 1024]u8 = undefined;
    var c: Conn = .init(testing.io, &ur.interface, &uw.interface, &rbuf, &wbuf);
    try c.handshake(.{ .path = "/ws", .host = "ws.blackwall.test" });

    const Reading = struct {
        fn run(conn: *Conn, total: *usize, ok: *bool) void {
            while (true) {
                const chunk = conn.reader.peekGreedy(1) catch |e| {
                    ok.* = e == error.EndOfStream;
                    return;
                };
                for (chunk, total.*..) |b, i| if (b != testByte(i)) return;
                total.* += chunk.len;
                conn.reader.toss(chunk.len);
            }
        }
    };
    var total: usize = 0;
    var ok = false;
    const t = try std.Thread.spawn(.{}, Reading.run, .{ &c, &total, &ok });

    var chunk: [7000]u8 = undefined;
    var sent: usize = 0;
    while (sent < bulk) {
        const n = @min(chunk.len, bulk - sent);
        for (chunk[0..n], sent..) |*b, i| b.* = testByte(i);
        try c.writer.writeAll(chunk[0..n]);
        try c.writer.flush();
        sent += n;
    }
    t.join();
    try testing.expect(ok);
    try testing.expectEqual(@as(usize, bulk), total);
    try testing.expectEqual(@as(u16, 1000), c.close_code);
    c.close(); // already answered: nothing more goes out
    try peer.finish();
}

/// Server for the early-data test: the first bytes come in the request.
fn serveEarly(conn: Io.net.Stream) !void {
    var rb: [4096]u8 = undefined;
    var wb: [4096]u8 = undefined;
    var sr = conn.reader(testing.io, &rb);
    var sw = conn.writer(testing.io, &wb);
    var ed: [64]u8 = undefined;
    const first = try Peer.accept(&sr.interface, &sw.interface, &ed);
    try testing.expectEqualStrings("header+request", first);
    try putFrame(&sw.interface, 0x82, "answer");
    try putFrame(&sw.interface, 0x88, &.{ 0x03, 0xe8 });
    try sw.interface.flush();
    var buf: [256]u8 = undefined;
    const bye = try Peer.readFrame(&sr.interface, &buf);
    try testing.expectEqual(@as(u8, 0x8), bye.op);
}

test "early data: the reader waits for the first write to upgrade" {
    var peer: Peer = .{};
    try peer.start(serveEarly);
    const stream_ = try peer.connect();
    defer stream_.close(testing.io);
    var urb: [4096]u8 = undefined;
    var uwb: [4096]u8 = undefined;
    var ur = stream_.reader(testing.io, &urb);
    var uw = stream_.writer(testing.io, &uwb);
    var rbuf: [256]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var c: Conn = .init(testing.io, &ur.interface, &uw.interface, &rbuf, &wbuf);
    try c.handshake(.{ .path = "/ws?ed=2048", .host = "ws.blackwall.test" });

    const Reading = struct {
        fn run(conn: *Conn, out: *[16]u8, len: *usize) void {
            var w: Io.Writer = .fixed(out);
            len.* = conn.reader.streamRemaining(&w) catch 99;
        }
    };
    var out: [16]u8 = undefined;
    var len: usize = 0;
    const t = try std.Thread.spawn(.{}, Reading.run, .{ &c, &out, &len });
    try Io.sleep(testing.io, .fromMilliseconds(100), .awake); // the reader is waiting by now
    try c.writer.writeAll("header+request");
    try c.writer.flush();
    t.join();
    try testing.expectEqualStrings("answer", out[0..len]);
    try peer.finish();
}

/// Server for the test where no write comes: upgrade without early data.
fn serveSilent(conn: Io.net.Stream) !void {
    var rb: [4096]u8 = undefined;
    var wb: [4096]u8 = undefined;
    var sr = conn.reader(testing.io, &rb);
    var sw = conn.writer(testing.io, &wb);
    var ed: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), (try Peer.accept(&sr.interface, &sw.interface, &ed)).len);
    try putFrame(&sw.interface, 0x88, &.{ 0x03, 0xe8 });
    try sw.interface.flush();
}

test "early data: without a first write the reader upgrades by itself" {
    var peer: Peer = .{};
    try peer.start(serveSilent);
    const stream_ = try peer.connect();
    defer stream_.close(testing.io);
    var urb: [4096]u8 = undefined;
    var uwb: [4096]u8 = undefined;
    var ur = stream_.reader(testing.io, &urb);
    var uw = stream_.writer(testing.io, &uwb);
    var rbuf: [256]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var c: Conn = .init(testing.io, &ur.interface, &uw.interface, &rbuf, &wbuf);
    try c.handshake(.{ .path = "/ws?ed=2048", .host = "ws.blackwall.test" });
    try testing.expectError(error.EndOfStream, c.reader.takeByte());
    try testing.expect(c.upgraded);
    try peer.finish();
}

test "closing before an early-data upgrade lets the reader go" {
    var s: Script = .{};
    s.init();
    try s.c.handshake(.{ .path = "/ws?ed=100", .host = "h" });
    s.c.close();
    try testing.expectError(error.EndOfStream, s.c.reader.takeByte());
    try testing.expectError(error.WriteFailed, s.c.writer.writeAll(&@as([300]u8, @splat(0x78))));
    try testing.expect(!s.answered);
}
