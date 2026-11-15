//! HTTP/2 client (RFC 9113) for one long-lived bidirectional request per
//! connection, the shape the gRPC and XHTTP transports use, over any
//! std.Io.Reader/Writer pair (the decrypted TLS stream).
//!
//! Threads: one thread reads (the response, `reader()`) while another writes
//! (the request body, `writer()`). Every frame goes out under `mutex`, the
//! writer's DATA as well as the reader's SETTINGS and PING acknowledgments
//! and window updates. The writer hears of new flow-control credit only
//! through the reader, so the response must keep being read while a body
//! goes out (a tunnel pumps both directions anyway).
//!
//! Use: `init`, `start` with the request head, then `response` and
//! `reader` on the reading thread, `writer` and `closeWrite` on the writing
//! one; `close`, then closing the transport, ends it all.
//!
//! Memory: no frame is buffered. DATA payloads go from the TLS reader to the
//! caller and from the caller to the TLS writer; header blocks are decoded
//! as they arrive. A connection is 6.5 KiB, mostly the HPACK context
//! (4.8 KiB) and room for 1 KiB of response header fields.

const std = @import("std");
const Io = std.Io;
const hpack = @import("hpack.zig");

pub const Field = hpack.Field;

pub const Error = error{
    /// The peer broke the protocol; it got a GOAWAY saying so.
    ProtocolError,
    FlowControlError,
    FrameSizeError,
    /// The response headers do not decode (HPACK).
    CompressionError,
    /// A response header block longer than `max_block`, or request headers
    /// longer than one frame.
    HeadersTooLarge,
    /// The peer reset the stream; `peer_code` says why.
    StreamReset,
    /// The peer is going away without having processed the stream (GOAWAY):
    /// it is safe to retry on a new connection.
    Refused,
    /// The transport ended in the middle of the stream.
    ConnectionClosed,
    /// The request body was already ended, the connection was closed, or
    /// the response is over and nobody reads window updates any more.
    Closed,
    /// The underlying reader or writer failed; it has the details.
    ReadFailed,
    WriteFailed,
};

pub const Options = struct {
    /// Our receive window, for the stream and the connection alike, at
    /// least 65535. Large by default: unread data waits in the socket, not
    /// here, and TCP paces a lone stream anyway, so a small window would
    /// only add round trips.
    window: u31 = 1 << 30,
};

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Our SETTINGS_MAX_FRAME_SIZE: the default, as nothing is gained by more
/// when payloads are streamed and not buffered.
const max_frame = 16384;
/// Header block bytes we accept across HEADERS and CONTINUATION frames.
const max_block = 64 * 1024;
const initial_window = 65535;
const max_window = 0x7fff_ffff;

const Type = enum(u8) {
    data = 0,
    headers = 1,
    priority = 2,
    rst_stream = 3,
    settings = 4,
    push_promise = 5,
    ping = 6,
    goaway = 7,
    window_update = 8,
    continuation = 9,
    _,
};

const end_stream = 0x1;
const ack = 0x1;
const end_headers = 0x4;
const padded = 0x8;
const priority = 0x20;

const code_no_error = 0x0;
const code_protocol = 0x1;
const code_flow_control = 0x3;
const code_frame_size = 0x6;
const code_cancel = 0x8;
const code_compression = 0x9;
const code_calm = 0xb;

const Header = struct { len: u32, type: Type, flags: u8, stream: u31 };

fn writeHeader(w: *Io.Writer, len: usize, t: Type, flags: u8, stream: u31) Io.Writer.Error!void {
    var h: [9]u8 = undefined;
    std.mem.writeInt(u24, h[0..3], @intCast(len), .big);
    h[3] = @backingInt(t);
    h[4] = flags;
    std.mem.writeInt(u32, h[5..9], stream, .big);
    try w.writeAll(&h);
}

pub const Conn = struct {
    io: Io,
    in: *Io.Reader,
    out: *Io.Writer,
    window: u31,

    /// Guards `out` and the fields from here to `dead`.
    mutex: Io.Mutex = .init,
    /// Wakes a writer waiting for flow-control credit.
    cond: Io.Condition = .init,
    send_conn: i64 = initial_window,
    send_stream: i64 = initial_window,
    peer_initial: u32 = initial_window,
    peer_max_frame: u32 = 16384,
    /// The preface went out: frames may follow.
    started: bool = false,
    /// END_STREAM sent / received.
    local_done: bool = false,
    remote_done: bool = false,
    /// `out` failed once and is not written again.
    out_failed: bool = false,
    /// The stream is over for the writer: reset, refused, failed or closed.
    dead: ?Error = null,

    // reading thread only
    /// Code of the RST_STREAM or GOAWAY the peer sent, if any.
    peer_code: ?u32 = null,
    /// Why `reader()` or `response()` failed.
    read_err: ?Error = null,
    got_settings: bool = false,
    status: u16 = 0,
    /// The DATA frame being read: payload and padding left, END_STREAM.
    data_left: u32 = 0,
    pad_left: u32 = 0,
    data_end: bool = false,
    /// What the peer may still send; the stream and connection windows
    /// move together, as all DATA is on our one stream.
    recv_window: i64,
    /// Consumed, not yet returned with WINDOW_UPDATE.
    unacked: u32 = 0,
    decoder: hpack.Decoder(4096) = .{},
    head_buf: [1024]u8 = undefined,
    head_fields: [16]Field = undefined,
    list: hpack.List,
    /// `list` holds the response head, then the trailers.
    head_len: usize = 0,
    body_in: Io.Reader,

    // writing thread only
    /// Why `writer()` or `closeWrite()` failed.
    write_err: ?Error = null,
    body_out: Io.Writer,

    /// `in` needs a buffer of at least 9 bytes. `read_buffer` and
    /// `write_buffer` back `reader()` and `writer()` and may be empty: an
    /// unbuffered side moves payload between the caller and the transport
    /// without a copy of its own. The connection must stay in place.
    pub fn init(c: *Conn, io: Io, in: *Io.Reader, out: *Io.Writer, read_buffer: []u8, write_buffer: []u8, options: Options) void {
        std.debug.assert(options.window >= initial_window);
        c.* = .{
            .io = io,
            .in = in,
            .out = out,
            .window = options.window,
            .recv_window = options.window,
            .list = undefined,
            .body_in = .{ .vtable = &.{ .stream = bodyStream }, .buffer = read_buffer, .seek = 0, .end = 0 },
            .body_out = .{ .vtable = &.{ .drain = bodyDrain, .flush = bodyFlush }, .buffer = write_buffer },
        };
        c.list = .init(&c.head_buf, &c.head_fields);
    }

    /// Send the connection preface and the request head. `request` holds
    /// the pseudo-header fields first (:method, :scheme, :authority, :path)
    /// and lowercase names, in the order they should go on the wire. The
    /// body follows through `writer()`. Call once, before the threads start.
    pub fn start(c: *Conn, request: []const Field) Error!void {
        var len: usize = 0;
        for (request) |f| len += hpack.fieldLen(f);
        // one HEADERS frame within the peer's initial SETTINGS_MAX_FRAME_SIZE
        if (len > 16384) return error.HeadersTooLarge;
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        c.started = true;
        c.startLocked(request, len) catch {
            c.broke();
            return error.WriteFailed;
        };
    }

    fn startLocked(c: *Conn, request: []const Field, len: usize) Io.Writer.Error!void {
        const w = c.out;
        try w.writeAll(preface);
        var s: [12]u8 = undefined;
        std.mem.writeInt(u16, s[0..2], 0x2, .big); // ENABLE_PUSH
        std.mem.writeInt(u32, s[2..6], 0, .big);
        std.mem.writeInt(u16, s[6..8], 0x4, .big); // INITIAL_WINDOW_SIZE
        std.mem.writeInt(u32, s[8..12], c.window, .big);
        try writeHeader(w, s.len, .settings, 0, 0);
        try w.writeAll(&s);
        if (c.window > initial_window) {
            var inc: [4]u8 = undefined;
            std.mem.writeInt(u32, &inc, c.window - initial_window, .big);
            try writeHeader(w, 4, .window_update, 0, 0);
            try w.writeAll(&inc);
        }
        try writeHeader(w, len, .headers, end_headers, 1);
        for (request) |f| try hpack.writeField(w, f);
        try w.flush();
    }

    /// Wait for the final response head, skipping 1xx ones, and return its
    /// status. Reading thread.
    pub fn response(c: *Conn) Error!u16 {
        while (c.status == 0) {
            if (c.read_err) |e| return e;
            c.readFrame() catch |e| return c.fail(e);
        }
        return c.status;
    }

    /// The response head (`:status` first), once `response()` returned.
    /// Fields beyond the space kept for them are left out.
    pub fn headers(c: *const Conn) []const Field {
        return c.list.fields[0..c.head_len];
    }

    /// The trailers, once `reader()` reached the end.
    pub fn trailers(c: *const Conn) []const Field {
        return c.list.fields[c.head_len..c.list.len];
    }

    /// The response body; it ends with the stream. Reading thread.
    pub fn reader(c: *Conn) *Io.Reader {
        return &c.body_in;
    }

    /// The request body; `flush` sends what is buffered. Writing thread.
    pub fn writer(c: *Conn) *Io.Writer {
        return &c.body_out;
    }

    /// End the request body after what is buffered (END_STREAM).
    pub fn closeWrite(c: *Conn) Io.Writer.Error!void {
        try c.send(c.body_out.buffered(), true, true);
        c.body_out.end = 0;
    }

    /// End the connection from any thread: reset the stream unless both
    /// sides finished it, say GOAWAY, and stop a writer waiting for credit.
    /// A reader blocked in the transport wakes when the caller closes the
    /// transport next. If a writer is stuck in the transport right now the
    /// goodbye is skipped rather than waited for: closing the transport
    /// frees that writer too.
    pub fn close(c: *Conn) void {
        var tries: u8 = 0;
        while (!c.mutex.tryLock()) : (tries += 1) {
            if (tries == 100) return;
            std.Thread.yield() catch {};
        }
        defer c.mutex.unlock(c.io);
        if (c.dead == null) {
            if (c.started) {
                if (!(c.local_done and c.remote_done)) c.putU32(.rst_stream, 1, code_cancel) catch {};
                c.goAway(code_no_error) catch {};
                c.flushOut() catch {};
            }
            c.dead = error.Closed;
        }
        c.cond.broadcast(c.io);
    }

    // ------------------------------------------------------------ sending

    /// One frame to `out`; the caller holds `mutex`.
    fn put(c: *Conn, t: Type, flags: u8, stream: u31, payload: []const u8) error{WriteFailed}!void {
        if (c.out_failed) return error.WriteFailed;
        errdefer c.broke();
        try writeHeader(c.out, payload.len, t, flags, stream);
        try c.out.writeAll(payload);
    }

    fn putU32(c: *Conn, t: Type, stream: u31, v: u32) error{WriteFailed}!void {
        var p: [4]u8 = undefined;
        std.mem.writeInt(u32, &p, v, .big);
        return c.put(t, 0, stream, &p);
    }

    fn goAway(c: *Conn, code: u32) error{WriteFailed}!void {
        var p: [8]u8 = undefined;
        std.mem.writeInt(u32, p[0..4], 0, .big); // we processed no stream of the peer
        std.mem.writeInt(u32, p[4..8], code, .big);
        return c.put(.goaway, 0, 0, &p);
    }

    fn flushOut(c: *Conn) error{WriteFailed}!void {
        if (c.out_failed) return error.WriteFailed;
        c.out.flush() catch {
            c.broke();
            return error.WriteFailed;
        };
    }

    /// `out` failed: nobody writes it again and the writer stops.
    fn broke(c: *Conn) void {
        c.out_failed = true;
        if (c.dead == null) c.dead = error.WriteFailed;
        c.cond.broadcast(c.io);
    }

    fn failWrite(c: *Conn, e: Error) error{WriteFailed} {
        if (c.write_err == null) c.write_err = e;
        return error.WriteFailed;
    }

    /// Send `bytes` as DATA, ending the stream with them if `end`, then
    /// flush `out` if `flush`.
    fn send(c: *Conn, bytes: []const u8, end: bool, flush: bool) Io.Writer.Error!void {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        if ((bytes.len > 0 or end) and c.local_done) return c.failWrite(error.Closed);
        var rest = bytes;
        while (rest.len > 0) {
            const n = try c.sendable(rest.len);
            const flags: u8 = if (end and n == rest.len) end_stream else 0;
            c.put(.data, flags, 1, rest[0..n]) catch return c.failWrite(error.WriteFailed);
            c.send_conn -= @intCast(n);
            c.send_stream -= @intCast(n);
            rest = rest[n..];
        }
        if (end) {
            if (bytes.len == 0) {
                if (c.dead) |e| return c.failWrite(e);
                c.put(.data, end_stream, 1, "") catch return c.failWrite(error.WriteFailed);
            }
            c.local_done = true;
        }
        if (flush) c.flushOut() catch return c.failWrite(error.WriteFailed);
    }

    /// DATA bytes that may go out now, at least one: waits for the peer to
    /// open its windows. The caller holds `mutex`.
    fn sendable(c: *Conn, want: usize) error{WriteFailed}!usize {
        while (true) {
            if (c.dead) |e| return c.failWrite(e);
            const room = @min(c.send_conn, c.send_stream);
            if (room > 0) return @min(want, @as(usize, @intCast(room)), c.peer_max_frame);
            // credit arrives through the reader, which stops with the response
            if (c.remote_done) return c.failWrite(error.Closed);
            // and the peer grants it only for data that reached it
            c.flushOut() catch return c.failWrite(error.WriteFailed);
            c.cond.waitUncancelable(c.io, &c.mutex);
        }
    }

    fn bodyDrain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const c: *Conn = @alignCast(@fieldParentPtr("body_out", w));
        if (w.end > 0) try c.send(w.buffered(), false, false);
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try c.send(d, false, false);
            n += d.len;
        }
        const pattern = data[data.len - 1];
        if (splat == 0 or pattern.len == 0) return n;
        // a repeated pattern (splatByteAll and the like) goes out as copies:
        // in the emptied buffer, or without one in a stack chunk, not as a
        // frame per copy
        var chunk: [256]u8 = undefined;
        const buffered = w.buffer.len >= pattern.len;
        const room: []u8 = if (buffered) w.buffer else &chunk;
        const k = @min(splat, room.len / pattern.len);
        if (splat == 1 or k <= 1) {
            try c.send(pattern, false, false);
            return n + pattern.len;
        }
        for (0..k) |i| @memcpy(room[i * pattern.len ..][0..pattern.len], pattern);
        if (buffered) w.end = k * pattern.len else try c.send(room[0 .. k * pattern.len], false, false);
        return n + k * pattern.len;
    }

    fn bodyFlush(w: *Io.Writer) Io.Writer.Error!void {
        const c: *Conn = @alignCast(@fieldParentPtr("body_out", w));
        try c.send(w.buffered(), false, true);
        w.end = 0;
    }

    // ------------------------------------------------------------ receiving

    /// Record the reader's first error and return it.
    fn fail(c: *Conn, e: Error) Error {
        c.record(e);
        return c.read_err.?;
    }

    /// Record the reader's first error, tell the peer of a protocol error
    /// (GOAWAY), and stop the writer.
    fn record(c: *Conn, e: Error) void {
        if (c.read_err != null) return;
        c.read_err = e;
        const code: ?u32 = switch (e) {
            error.ProtocolError => code_protocol,
            error.FlowControlError => code_flow_control,
            error.FrameSizeError => code_frame_size,
            error.CompressionError => code_compression,
            error.HeadersTooLarge => code_calm,
            else => null,
        };
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        if (c.dead == null) {
            if (code) |k| {
                c.goAway(k) catch {};
                c.flushOut() catch {};
            }
            c.dead = e;
        }
        c.cond.broadcast(c.io);
    }

    fn bodyStream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const c: *Conn = @alignCast(@fieldParentPtr("body_in", r));
        if (c.read_err != null) return error.ReadFailed;
        if (c.data_left == 0) {
            while (c.data_left == 0 and !c.remote_done) c.readFrame() catch |e| {
                c.record(e);
                return error.ReadFailed;
            };
            if (c.data_left == 0) return error.EndOfStream;
        }
        const n = c.in.stream(w, limit.min(.limited(c.data_left))) catch |e| {
            c.record(switch (e) {
                error.WriteFailed => return error.WriteFailed,
                error.EndOfStream => error.ConnectionClosed,
                error.ReadFailed => error.ReadFailed,
            });
            return error.ReadFailed;
        };
        c.data_left -= @intCast(n);
        // a failure here shows on the next call; these bytes are good
        c.consumed(n) catch |e| c.record(e);
        return n;
    }

    /// `n` payload bytes went to the caller: finish the frame when it is
    /// done and return credit once half the window is used up.
    fn consumed(c: *Conn, n: usize) Error!void {
        if (c.data_left == 0) {
            try c.skip(c.pad_left);
            c.pad_left = 0;
            if (c.data_end) return c.endStream();
        }
        return c.credit(n);
    }

    fn credit(c: *Conn, n: usize) Error!void {
        c.unacked += @intCast(n);
        if (c.unacked < c.window / 2 or c.remote_done) return;
        const inc = c.unacked;
        c.unacked = 0;
        c.recv_window += inc;
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        try c.putU32(.window_update, 0, inc);
        try c.putU32(.window_update, 1, inc);
        try c.flushOut();
    }

    fn endStream(c: *Conn) void {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        c.remote_done = true;
        c.cond.broadcast(c.io);
    }

    fn get(c: *Conn, comptime n: usize) Error!*[n]u8 {
        return c.in.takeArray(n) catch |e| switch (e) {
            error.EndOfStream => error.ConnectionClosed,
            error.ReadFailed => error.ReadFailed,
        };
    }

    fn skip(c: *Conn, n: usize) Error!void {
        c.in.discardAll(n) catch |e| return switch (e) {
            error.EndOfStream => error.ConnectionClosed,
            error.ReadFailed => error.ReadFailed,
        };
    }

    fn frameHeader(c: *Conn) Error!Header {
        const b = try c.get(9);
        const h: Header = .{
            .len = std.mem.readInt(u24, b[0..3], .big),
            .type = @fromBackingInt(b[3]),
            .flags = b[4],
            .stream = @truncate(std.mem.readInt(u32, b[5..9], .big)),
        };
        if (h.len > max_frame) return error.FrameSizeError;
        return h;
    }

    /// One frame. DATA only sets up `data_left` for the body reader.
    fn readFrame(c: *Conn) Error!void {
        const h = try c.frameHeader();
        // 3.4: the server's preface is a SETTINGS frame
        if (!c.got_settings and (h.type != .settings or h.flags & ack != 0)) return error.ProtocolError;
        switch (h.type) {
            .data => try c.onData(h),
            .headers => try c.onHeaders(h),
            .priority => {
                if (h.stream == 0) return error.ProtocolError;
                if (h.len != 5) return error.FrameSizeError;
                try c.skip(5);
            },
            .rst_stream => {
                if (h.stream == 0) return error.ProtocolError;
                if (h.len != 4) return error.FrameSizeError;
                const code = std.mem.readInt(u32, try c.get(4), .big);
                if (h.stream != 1) return error.ProtocolError; // an idle stream
                c.peer_code = code;
                return error.StreamReset;
            },
            .settings => try c.onSettings(h),
            .push_promise => return error.ProtocolError, // we disabled push
            .ping => {
                if (h.stream != 0) return error.ProtocolError;
                if (h.len != 8) return error.FrameSizeError;
                const payload = (try c.get(8)).*;
                if (h.flags & ack != 0) return; // we send none
                c.mutex.lockUncancelable(c.io);
                defer c.mutex.unlock(c.io);
                try c.put(.ping, ack, 0, &payload);
                try c.flushOut();
            },
            .goaway => {
                if (h.stream != 0) return error.ProtocolError;
                if (h.len < 8) return error.FrameSizeError;
                const p = try c.get(8);
                const last = std.mem.readInt(u32, p[0..4], .big) & max_window;
                c.peer_code = std.mem.readInt(u32, p[4..8], .big);
                try c.skip(h.len - 8); // debug data
                // a stream the peer took on may still complete
                if (last < 1) return error.Refused;
            },
            .window_update => try c.onWindowUpdate(h),
            .continuation => return error.ProtocolError, // only right after HEADERS
            _ => try c.skip(h.len), // 5.5: unknown types are ignored
        }
    }

    fn onData(c: *Conn, h: Header) Error!void {
        // DATA belongs to our stream, after the response head
        if (h.stream != 1 or c.status == 0) return error.ProtocolError;
        // 6.9.1: the whole payload counts, padding included
        if (h.len > c.recv_window) return error.FlowControlError;
        c.recv_window -= h.len;
        var len = h.len;
        var pad: u32 = 0;
        if (h.flags & padded != 0) {
            if (len == 0) return error.FrameSizeError;
            pad = (try c.get(1))[0];
            len -= 1;
            if (pad > len) return error.ProtocolError;
            len -= pad;
        }
        c.data_left = len;
        c.pad_left = pad;
        c.data_end = h.flags & end_stream != 0;
        // padding is consumed as soon as it is read
        try c.credit(h.len - len);
        if (len == 0) try c.consumed(0);
    }

    fn onHeaders(c: *Conn, h: Header) Error!void {
        if (h.stream != 1) return error.ProtocolError;
        var len = h.len;
        var pad: u32 = 0;
        if (h.flags & padded != 0) {
            if (len < 1) return error.FrameSizeError;
            pad = (try c.get(1))[0];
            len -= 1;
        }
        if (h.flags & priority != 0) {
            if (len < 5) return error.FrameSizeError;
            try c.skip(5);
            len -= 5;
        }
        if (pad > len) return error.ProtocolError;

        var buf: [256]u8 = undefined;
        var block: Block = .{
            .c = c,
            .frag = len - pad,
            .pad = pad,
            .last = h.flags & end_headers != 0,
            .budget = max_block - h.len,
            .interface = .{ .vtable = &.{ .stream = Block.stream }, .buffer = &buf, .seek = 0, .end = 0 },
        };
        const mark_len = c.list.len;
        const mark_used = c.list.used;
        c.decoder.decode(&block.interface, &c.list) catch |e| return switch (e) {
            error.ReadFailed => block.err orelse error.ReadFailed,
            else => error.CompressionError,
        };
        const fields = c.list.fields[mark_len..c.list.len];
        const ends = h.flags & end_stream != 0;
        if (c.status == 0) {
            // 8.3.2: the head starts with :status, the only pseudo-header
            const status = if (fields.len > 0 and std.mem.eql(u8, fields[0].name, ":status"))
                parseStatus(fields[0].value) orelse return error.ProtocolError
            else
                return error.ProtocolError;
            for (fields[1..]) |f| if (std.mem.startsWith(u8, f.name, ":")) return error.ProtocolError;
            if (status < 200) {
                // interim (1xx): forgotten, the final head follows
                if (ends) return error.ProtocolError;
                c.list.len = mark_len;
                c.list.used = mark_used;
                return;
            }
            c.status = status;
            c.head_len = c.list.len;
        } else {
            // trailers (8.1) end the stream and carry no pseudo-headers
            if (!ends) return error.ProtocolError;
            for (fields) |f| if (std.mem.startsWith(u8, f.name, ":")) return error.ProtocolError;
        }
        if (ends) c.endStream();
    }

    fn onSettings(c: *Conn, h: Header) Error!void {
        if (h.stream != 0) return error.ProtocolError;
        if (h.flags & ack != 0) {
            if (h.len != 0) return error.FrameSizeError;
            return; // ours are in effect
        }
        if (h.len % 6 != 0) return error.FrameSizeError;
        c.got_settings = true;
        var left = h.len;
        while (left > 0) : (left -= 6) {
            const s = try c.get(6);
            const id = std.mem.readInt(u16, s[0..2], .big);
            const v = std.mem.readInt(u32, s[2..6], .big);
            switch (id) {
                0x2 => if (v != 0) return error.ProtocolError, // a server may not enable push
                0x4 => {
                    if (v > max_window) return error.FlowControlError;
                    c.mutex.lockUncancelable(c.io);
                    defer c.mutex.unlock(c.io);
                    // 6.9.2: open streams move by the difference
                    c.send_stream += @as(i64, v) - c.peer_initial;
                    c.peer_initial = v;
                    if (c.send_stream > max_window) return error.FlowControlError;
                    c.cond.broadcast(c.io);
                },
                0x5 => {
                    if (v < 16384 or v > 16777215) return error.ProtocolError;
                    c.mutex.lockUncancelable(c.io);
                    defer c.mutex.unlock(c.io);
                    c.peer_max_frame = v;
                },
                // header table size (our encoder never indexes), stream
                // limits, header list size and unknown ones change nothing
                else => {},
            }
        }
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        try c.put(.settings, ack, 0, "");
        try c.flushOut();
    }

    fn onWindowUpdate(c: *Conn, h: Header) Error!void {
        if (h.len != 4) return error.FrameSizeError;
        const inc = std.mem.readInt(u32, try c.get(4), .big) & max_window;
        if (h.stream > 1 or inc == 0) return error.ProtocolError;
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        const w = if (h.stream == 0) &c.send_conn else &c.send_stream;
        w.* += inc;
        if (w.* > max_window) return error.FlowControlError;
        c.cond.broadcast(c.io);
    }
};

fn parseStatus(s: []const u8) ?u16 {
    if (s.len != 3) return null;
    var v: u16 = 0;
    for (s) |d| {
        if (d < '0' or d > '9') return null;
        v = v * 10 + (d - '0');
    }
    return if (v >= 100) v else null;
}

/// A header block, from a HEADERS frame on through its CONTINUATION
/// frames, as one stream that ends where the block does.
const Block = struct {
    c: *Conn,
    interface: Io.Reader,
    /// fragment bytes left in the current frame, then its padding
    frag: u32,
    pad: u32,
    /// the current frame has END_HEADERS
    last: bool,
    budget: u32,
    err: ?Error = null,

    fn fail(b: *Block, e: Error) error{ReadFailed} {
        b.err = e;
        return error.ReadFailed;
    }

    fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const b: *Block = @alignCast(@fieldParentPtr("interface", r));
        while (b.frag == 0) {
            if (b.pad > 0) {
                b.c.skip(b.pad) catch |e| return b.fail(e);
                b.pad = 0;
            }
            if (b.last) return error.EndOfStream;
            // 6.10: nothing may come between the frames of a block
            const h = b.c.frameHeader() catch |e| return b.fail(e);
            if (h.type != .continuation or h.stream != 1) return b.fail(error.ProtocolError);
            if (h.len > b.budget) return b.fail(error.HeadersTooLarge);
            b.budget -= h.len;
            b.frag = h.len;
            b.last = h.flags & end_headers != 0;
        }
        const n = b.c.in.stream(w, limit.min(.limited(b.frag))) catch |e| return switch (e) {
            error.WriteFailed => error.WriteFailed,
            error.EndOfStream => b.fail(error.ConnectionClosed),
            error.ReadFailed => b.fail(error.ReadFailed),
        };
        b.frag -= @intCast(n);
        return n;
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn frame(w: *Io.Writer, t: Type, flags: u8, stream: u31, payload: []const u8) !void {
    try writeHeader(w, payload.len, t, flags, stream);
    try w.writeAll(payload);
}

fn settingsFrame(w: *Io.Writer, pairs: []const [2]u32) !void {
    try writeHeader(w, pairs.len * 6, .settings, 0, 0);
    for (pairs) |p| {
        var s: [6]u8 = undefined;
        std.mem.writeInt(u16, s[0..2], @intCast(p[0]), .big);
        std.mem.writeInt(u32, s[2..6], p[1], .big);
        try w.writeAll(&s);
    }
}

fn u32Frame(w: *Io.Writer, t: Type, stream: u31, v: u32) !void {
    var p: [4]u8 = undefined;
    std.mem.writeInt(u32, &p, v, .big);
    try frame(w, t, 0, stream, &p);
}

/// Header block of `fields` as our encoder writes it.
fn encodeBlock(buf: []u8, fields: []const Field) []const u8 {
    var w: Io.Writer = .fixed(buf);
    for (fields) |f| hpack.writeField(&w, f) catch unreachable;
    return w.buffered();
}

const Sent = struct { h: Header, payload: []const u8 };

/// The frames a client wrote, after the preface.
fn sentFrames(out: []const u8, list: []Sent) ![]Sent {
    try testing.expect(std.mem.startsWith(u8, out, preface));
    var rest = out[preface.len..];
    var n: usize = 0;
    while (rest.len >= 9) : (n += 1) {
        const len = std.mem.readInt(u24, rest[0..3], .big);
        list[n] = .{
            .h = .{ .len = len, .type = @fromBackingInt(rest[3]), .flags = rest[4], .stream = @truncate(std.mem.readInt(u32, rest[5..9], .big)) },
            .payload = rest[9..][0..len],
        };
        rest = rest[9 + len ..];
    }
    try testing.expectEqual(0, rest.len);
    return list[0..n];
}

const test_request = [_]Field{
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":authority", .value = "example.com" },
    .{ .name = ":path", .value = "/svc/Tun" },
    .{ .name = "content-type", .value = "application/grpc" },
    .{ .name = "te", .value = "trailers" },
};

/// A client reading a scripted server and writing into `out`.
const Scripted = struct {
    in: Io.Reader,
    out: Io.Writer,
    c: Conn,

    fn init(s: *Scripted, script: []const u8, out: []u8, options: Options) !void {
        s.in = .fixed(script);
        s.out = .fixed(out);
        s.c.init(testing.io, &s.in, &s.out, &.{}, &.{}, options);
        try s.c.start(&test_request);
    }

    /// The frames the client sent after its request head.
    fn replies(s: *Scripted, list: []Sent) ![]Sent {
        const all = try sentFrames(s.out.buffered(), list);
        var i: usize = 0;
        while (all[i].h.type != .headers) i += 1;
        return all[i + 1 ..];
    }
};

test "request head: preface, settings, window, one HEADERS frame" {
    var out: [512]u8 = undefined;
    var s: Scripted = undefined;
    try s.init("", &out, .{});
    var list: [8]Sent = undefined;
    const f = try sentFrames(s.out.buffered(), &list);
    try testing.expectEqual(3, f.len);
    try testing.expectEqual(Type.settings, f[0].h.type);
    try testing.expectEqualSlices(u8, &.{ 0, 2, 0, 0, 0, 0, 0, 4, 0x40, 0, 0, 0 }, f[0].payload);
    try testing.expectEqual(Type.window_update, f[1].h.type);
    try testing.expectEqual((1 << 30) - 65535, std.mem.readInt(u32, f[1].payload[0..4], .big));
    try testing.expectEqual(Type.headers, f[2].h.type);
    try testing.expectEqual(end_headers, f[2].h.flags);
    try testing.expectEqual(1, f[2].h.stream);
    var src: Io.Reader = .fixed(f[2].payload);
    var buf: [256]u8 = undefined;
    var fields: [8]Field = undefined;
    var got: hpack.List = .init(&buf, &fields);
    var d: hpack.Decoder(4096) = .{};
    try d.decode(&src, &got);
    try testing.expectEqual(test_request.len, got.len);
    for (test_request, got.slice()) |want, have| {
        try testing.expectEqualStrings(want.name, have.name);
        try testing.expectEqualStrings(want.value, have.value);
    }
    // the empty transport ends before the server's preface
    try testing.expectError(error.ConnectionClosed, s.c.response());
}

test "response through CONTINUATION, padding, priority, an interim head, trailers, PING" {
    var sb: [8192]u8 = undefined;
    var sw: Io.Writer = .fixed(&sb);
    try settingsFrame(&sw, &.{ .{ 0x5, 20000 }, .{ 0x3, 100 }, .{ 0x99, 7 } });
    try frame(&sw, .settings, ack, 0, "");
    try frame(&sw, .ping, 0, 0, "12345678");
    try frame(&sw, @fromBackingInt(0xfa), 0, 0, "an extension frame"); // ignored
    var hb: [2048]u8 = undefined;
    try frame(&sw, .headers, end_headers, 1, encodeBlock(&hb, &.{
        .{ .name = ":status", .value = "103" },
        .{ .name = "link", .value = "</a.css>; rel=preload" },
    }));
    // the head: :status 200 and content-type from our encoder, then the
    // rest of RFC 7541 C.6.1 (Huffman, into the dynamic table), then a
    // field too long to keep; split over HEADERS (padded, with priority)
    // and two CONTINUATION frames
    var w: Io.Writer = .fixed(&hb);
    try hpack.writeField(&w, .{ .name = ":status", .value = "200" });
    try hpack.writeField(&w, .{ .name = "content-type", .value = "application/grpc" });
    const c61 = "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3";
    var c61b: [c61.len / 2]u8 = undefined;
    try w.writeAll((try std.fmt.hexToBytes(&c61b, c61))[4..]);
    const long: [1100]u8 = @splat('v');
    try hpack.writeField(&w, .{ .name = "x-long", .value = &long });
    const head = w.buffered();
    var first: [1 + 5 + 30 + 3]u8 = undefined;
    first[0] = 3; // pad length
    first[1..6].* = .{ 0x80, 0, 0, 3, 15 }; // exclusive, depends on 3, weight 16
    @memcpy(first[6..36], head[0..30]);
    @memset(first[36..], 0);
    try frame(&sw, .headers, padded | priority, 1, &first);
    try frame(&sw, .continuation, 0, 1, head[30..100]);
    try frame(&sw, .continuation, end_headers, 1, head[100..]);
    // body: padded, plain, empty
    var d1: [1 + 6 + 10]u8 = undefined;
    d1[0] = 10;
    @memcpy(d1[1..7], "hello ");
    @memset(d1[7..], 0);
    try frame(&sw, .data, padded, 1, &d1);
    try frame(&sw, .data, 0, 1, "world");
    try frame(&sw, .data, 0, 1, "");
    // trailers, one of them from the dynamic table (62: location)
    var tb: [64]u8 = undefined;
    var tw: Io.Writer = .fixed(&tb);
    try hpack.writeField(&tw, .{ .name = "grpc-status", .value = "0" });
    try tw.writeByte(0x80 | 62);
    try frame(&sw, .headers, end_headers | end_stream, 1, tw.buffered());

    var out: [1024]u8 = undefined;
    var s: Scripted = undefined;
    try s.init(sw.buffered(), &out, .{});
    const c = &s.c;
    try testing.expectEqual(200, try c.response());
    try testing.expectEqual(20000, c.peer_max_frame);
    const hs = c.headers();
    try testing.expectEqual(5, hs.len);
    try testing.expectEqualStrings(":status", hs[0].name);
    try testing.expectEqualStrings("application/grpc", hs[1].value);
    try testing.expectEqualStrings("private", hs[2].value);
    try testing.expectEqualStrings("https://www.example.com", hs[4].value);
    try testing.expectEqual(1, c.list.dropped); // x-long

    var body: [64]u8 = undefined;
    var bw: Io.Writer = .fixed(&body);
    _ = try c.reader().streamRemaining(&bw);
    try testing.expectEqualStrings("hello world", bw.buffered());
    const tr = c.trailers();
    try testing.expectEqual(2, tr.len);
    try testing.expectEqualStrings("0", tr[0].value);
    try testing.expectEqualStrings("location", tr[1].name);

    // the client acknowledged the SETTINGS and the PING, and said nothing else
    var list: [8]Sent = undefined;
    const r = try s.replies(&list);
    try testing.expectEqual(2, r.len);
    try testing.expectEqual(Type.settings, r[0].h.type);
    try testing.expectEqual(ack, r[0].h.flags);
    try testing.expectEqual(Type.ping, r[1].h.type);
    try testing.expectEqual(ack, r[1].h.flags);
    try testing.expectEqualStrings("12345678", r[1].payload);
    try testing.expect(c.remote_done and c.read_err == null);
}

/// Run the client against `script` and expect it to fail with `want`, from
/// `response()` or from the body, having sent a GOAWAY with `goaway`.
fn expectFailure(script: []const u8, want: Error, goaway: ?u32) !void {
    var out: [1024]u8 = undefined;
    var s: Scripted = undefined;
    try s.init(script, &out, .{ .window = 65535 });
    const got = got: {
        _ = s.c.response() catch |e| break :got e;
        var sink: [256]u8 = undefined;
        var w: Io.Writer = .fixed(&sink);
        _ = s.c.reader().streamRemaining(&w) catch break :got s.c.read_err.?;
        return error.TestExpectedError;
    };
    try testing.expectEqual(want, got);
    var list: [8]Sent = undefined;
    var sent: ?u32 = null;
    for (try s.replies(&list)) |f| if (f.h.type == .goaway) {
        try testing.expectEqual(0, std.mem.readInt(u32, f.payload[0..4], .big));
        sent = std.mem.readInt(u32, f.payload[4..8], .big);
    };
    try testing.expectEqual(goaway, sent);
    // the writer is stopped too
    try testing.expectError(error.WriteFailed, s.c.writer().writeAll("x"));
    try testing.expectEqual(want, s.c.write_err.?);
}

test "peer errors end the stream; protocol errors get a GOAWAY" {
    var b: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&b);
    var okb: [16]u8 = undefined;
    const ok_head = encodeBlock(&okb, &.{.{ .name = ":status", .value = "200" }});
    var hb: [64]u8 = undefined;

    // 3.4: the server's preface must be SETTINGS
    try frame(&w, .ping, 0, 0, "12345678");
    try expectFailure(w.buffered(), error.ProtocolError, code_protocol);

    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try writeHeader(&w, max_frame + 1, .data, 0, 1);
    try expectFailure(w.buffered(), error.FrameSizeError, code_frame_size);

    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try frame(&w, .data, 0, 1, "x"); // before the head
    try expectFailure(w.buffered(), error.ProtocolError, code_protocol);

    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try frame(&w, .headers, 0, 1, ok_head[0..1]);
    try frame(&w, .ping, 0, 0, "12345678"); // inside a header block
    try expectFailure(w.buffered(), error.ProtocolError, code_protocol);

    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try frame(&w, .headers, 0, 1, ok_head[0..1]);
    try frame(&w, .continuation, end_headers, 3, ok_head[1..]);
    try expectFailure(w.buffered(), error.ProtocolError, code_protocol);

    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try frame(&w, .headers, end_headers, 1, ok_head);
    try frame(&w, .data, padded, 1, &.{ 4, 0, 0, 0 }); // 4 bytes of padding in 4
    try expectFailure(w.buffered(), error.ProtocolError, code_protocol);

    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try frame(&w, .headers, end_headers, 1, &.{0x80}); // HPACK index 0
    try expectFailure(w.buffered(), error.CompressionError, code_compression);

    w = .fixed(&b);
    try settingsFrame(&w, &.{.{ 0x2, 1 }}); // push enabled by a server
    try expectFailure(w.buffered(), error.ProtocolError, code_protocol);

    w = .fixed(&b);
    try settingsFrame(&w, &.{.{ 0x4, 0x8000_0000 }});
    try expectFailure(w.buffered(), error.FlowControlError, code_flow_control);

    w = .fixed(&b);
    try settingsFrame(&w, &.{.{ 0x5, 100 }});
    try expectFailure(w.buffered(), error.ProtocolError, code_protocol);

    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try u32Frame(&w, .window_update, 0, 0);
    try expectFailure(w.buffered(), error.ProtocolError, code_protocol);

    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try u32Frame(&w, .window_update, 0, max_window); // 65535 + 2^31-1
    try expectFailure(w.buffered(), error.FlowControlError, code_flow_control);

    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try u32Frame(&w, .push_promise, 1, 2);
    try expectFailure(w.buffered(), error.ProtocolError, code_protocol);

    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try frame(&w, .headers, end_headers, 1, encodeBlock(&hb, &.{.{ .name = ":status", .value = "2x0" }}));
    try expectFailure(w.buffered(), error.ProtocolError, code_protocol);

    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try frame(&w, .headers, end_headers | end_stream, 1, encodeBlock(&hb, &.{.{ .name = ":status", .value = "100" }}));
    try expectFailure(w.buffered(), error.ProtocolError, code_protocol);

    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try frame(&w, .headers, end_headers, 1, ok_head);
    try frame(&w, .headers, end_headers, 1, encodeBlock(&hb, &.{.{ .name = "grpc-status", .value = "0" }}));
    try expectFailure(w.buffered(), error.ProtocolError, code_protocol); // trailers that do not end the stream

    // the peer's own endings: no GOAWAY from us
    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try u32Frame(&w, .rst_stream, 1, 7);
    try expectFailure(w.buffered(), error.StreamReset, null);

    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try frame(&w, .goaway, 0, 0, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 'b', 'y', 'e' });
    try expectFailure(w.buffered(), error.Refused, null);

    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try frame(&w, .headers, end_headers, 1, ok_head);
    try writeHeader(&w, 10, .data, 0, 1);
    try w.writeAll("abc"); // the transport ends inside the frame
    try expectFailure(w.buffered(), error.ConnectionClosed, null);
}

test "GOAWAY that spares our stream, a CONTINUATION flood, a window overrun" {
    var b: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&b);
    var hb: [64]u8 = undefined;
    const ok_head = encodeBlock(&hb, &.{.{ .name = ":status", .value = "200" }});

    // GOAWAY with last stream 1: the stream still completes
    try settingsFrame(&w, &.{});
    try frame(&w, .goaway, 0, 0, &.{ 0, 0, 0, 1, 0, 0, 0, 0 });
    try frame(&w, .headers, end_headers, 1, ok_head);
    try frame(&w, .data, end_stream, 1, "last");
    var out: [1024]u8 = undefined;
    var s: Scripted = undefined;
    try s.init(w.buffered(), &out, .{});
    try testing.expectEqual(200, try s.c.response());
    var body: [16]u8 = undefined;
    try testing.expectEqual(4, try s.c.reader().readSliceShort(&body));
    try testing.expectEqualStrings("last", body[0..4]);
    try testing.expectEqual(0, s.c.peer_code);

    // endless CONTINUATION frames of valid fields
    var big: Io.Writer.Allocating = .init(testing.allocator);
    defer big.deinit();
    try settingsFrame(&big.writer, &.{});
    const chunk: [max_frame]u8 = @splat(0x82); // ":method: GET", over and over
    try frame(&big.writer, .headers, 0, 1, &chunk);
    for (0..4) |_| try frame(&big.writer, .continuation, 0, 1, &chunk);
    try expectFailure(big.written(), error.HeadersTooLarge, code_calm);

    // more DATA than the window we gave
    w = .fixed(&b);
    try settingsFrame(&w, &.{});
    try frame(&w, .headers, end_headers, 1, ok_head);
    try frame(&w, .data, 0, 1, &@as([100]u8, @splat('d')));
    try s.init(w.buffered(), &out, .{});
    try testing.expectEqual(200, try s.c.response());
    s.c.recv_window = 99;
    try testing.expectError(error.ReadFailed, s.c.reader().readSliceShort(&body));
    try testing.expectEqual(error.FlowControlError, s.c.read_err.?);
}

fn pipe() ![2]Io.File {
    const fds = try std.Io.Threaded.pipe2(.{});
    return .{
        .{ .handle = fds[0], .flags = .{ .nonblocking = false } },
        .{ .handle = fds[1], .flags = .{ .nonblocking = false } },
    };
}

fn upByte(i: usize) u8 {
    return @truncate(i *% 13 +% 1);
}

fn downByte(i: usize) u8 {
    return @truncate((i *% 7 +% 3) ^ (i >> 9));
}

/// A server for the duplex test. Like a real one it reads and writes on
/// separate threads, and the reading thread never writes, so it never
/// stops reading because the client does not read.
const DuplexPeer = struct {
    io: Io,
    from: *Io.Reader,
    to: *Io.Writer,
    down_total: usize,
    up_total: usize,

    mutex: Io.Mutex = .init,
    cond: Io.Condition = .init,
    // from the reading thread to the writing one
    credit: u32 = 0,
    raise: bool = false,
    conn_window: i64 = 65535,
    stream_window: i64 = 65535,
    up_done: bool = false,
    stop: bool = false,
    err: ?anyerror = null,

    // reading thread only: the client's windows as we granted them
    up_len: usize = 0,
    up_stream: i64 = 1000,
    up_conn: i64 = 65535,
    raised: bool = false,
    acks: u8 = 0,
    pinged: bool = false,
    largest: usize = 0,

    fn fail(p: *DuplexPeer, e: anyerror) void {
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        if (p.err == null) p.err = e;
        p.stop = true;
        p.cond.broadcast(p.io);
    }

    fn header(p: *DuplexPeer) !Header {
        const b = try p.from.takeArray(9);
        return .{
            .len = std.mem.readInt(u24, b[0..3], .big),
            .type = @fromBackingInt(b[3]),
            .flags = b[4],
            .stream = @truncate(std.mem.readInt(u32, b[5..9], .big)),
        };
    }

    fn run(p: *DuplexPeer) void {
        p.read() catch |e| p.fail(e);
    }

    fn read(p: *DuplexPeer) !void {
        if (!std.mem.eql(u8, try p.from.takeArray(preface.len), preface)) return error.BadPreface;
        var h = try p.header();
        if (h.type != .settings) return error.NoSettings;
        try p.from.discardAll(h.len);
        h = try p.header(); // window 65535: no WINDOW_UPDATE comes first
        if (h.type != .headers or h.flags != end_headers) return error.NoHead;
        try p.from.discardAll(h.len);
        const writer_thread = try std.Thread.spawn(.{}, DuplexPeer.writeLoop, .{p});
        defer writer_thread.join();
        var buf: [max_frame]u8 = undefined;
        while (true) {
            h = p.header() catch |e| switch (e) {
                error.EndOfStream => break,
                else => return e,
            };
            if (h.len > buf.len) return error.FrameTooLarge;
            const payload = buf[0..h.len];
            try p.from.readSliceAll(payload);
            switch (h.type) {
                .data => {
                    if (h.stream != 1) return error.BadStream;
                    p.up_stream -= h.len;
                    p.up_conn -= h.len;
                    if (p.up_stream < 0 or p.up_conn < 0) return error.WindowOverrun;
                    for (payload, p.up_len..) |byte, i| if (byte != upByte(i)) return error.BadUpload;
                    p.up_len += h.len;
                    p.largest = @max(p.largest, h.len);
                    // credit straight back, and once raise the stream window
                    p.up_stream += h.len;
                    p.up_conn += h.len;
                    const raise = !p.raised and p.up_len >= 5000;
                    if (raise) {
                        p.raised = true;
                        p.up_stream += 3000 - 1000;
                    }
                    p.mutex.lockUncancelable(p.io);
                    defer p.mutex.unlock(p.io);
                    p.credit += h.len;
                    p.raise = p.raise or raise;
                    if (h.flags & end_stream != 0) p.up_done = true;
                    p.cond.broadcast(p.io);
                },
                .window_update => {
                    const inc = std.mem.readInt(u32, payload[0..4], .big);
                    p.mutex.lockUncancelable(p.io);
                    defer p.mutex.unlock(p.io);
                    if (h.stream == 0) p.conn_window += inc else p.stream_window += inc;
                    p.cond.broadcast(p.io);
                },
                .settings => {
                    if (h.flags & ack == 0) return error.SecondSettings;
                    p.acks += 1;
                },
                .ping => {
                    if (h.flags & ack == 0 or !std.mem.eql(u8, payload, "pingpong")) return error.BadPing;
                    p.pinged = true;
                },
                else => return error.UnexpectedFrame,
            }
        }
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        p.stop = true;
        p.cond.broadcast(p.io);
    }

    fn writeLoop(p: *DuplexPeer) void {
        p.write() catch |e| p.fail(e);
    }

    fn write(p: *DuplexPeer) !void {
        const w = p.to;
        try settingsFrame(w, &.{ .{ 0x4, 1000 }, .{ 0x5, 16384 } });
        try frame(w, .ping, 0, 0, "pingpong");
        var hb: [32]u8 = undefined;
        try frame(w, .headers, end_headers, 1, encodeBlock(&hb, &.{.{ .name = ":status", .value = "200" }}));
        try w.flush();
        var data: [max_frame]u8 = undefined;
        var sent: usize = 0;
        var frames: usize = 0;
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        while (!p.stop) {
            const window = @min(p.conn_window, p.stream_window);
            const more = sent < p.down_total and window > 0;
            const finish = p.up_done and sent == p.down_total;
            if (p.credit == 0 and !p.raise and !more and !finish) {
                p.cond.waitUncancelable(p.io, &p.mutex);
                continue;
            }
            const credit = p.credit;
            p.credit = 0;
            const raise = p.raise;
            p.raise = false;
            var n: usize = 0;
            var pad: usize = 0;
            if (more) {
                // every third frame padded: padding uses up window too
                pad = if (frames % 3 == 0 and window > 64) 7 else 0;
                const extra: usize = if (pad > 0) 1 + pad else 0;
                n = @min(p.down_total - sent, max_frame - extra, @as(usize, @intCast(window)) - extra);
                p.conn_window -= @intCast(n + extra);
                p.stream_window -= @intCast(n + extra);
            }
            p.mutex.unlock(p.io);
            defer p.mutex.lockUncancelable(p.io);
            if (credit > 0) {
                try u32Frame(w, .window_update, 1, credit);
                try u32Frame(w, .window_update, 0, credit);
            }
            if (raise) try settingsFrame(w, &.{.{ 0x4, 3000 }});
            if (n > 0) {
                for (data[0..n], sent..) |*b, i| b.* = downByte(i);
                if (pad > 0) {
                    try writeHeader(w, 1 + n + pad, .data, padded, 1);
                    try w.writeByte(@intCast(pad));
                    try w.writeAll(data[0..n]);
                    try w.splatByteAll(0, pad);
                } else try frame(w, .data, 0, 1, data[0..n]);
                sent += n;
                frames += 1;
            }
            if (finish) {
                try frame(w, .headers, end_headers | end_stream, 1, encodeBlock(&hb, &.{.{ .name = "grpc-status", .value = "0" }}));
                try w.flush();
                return;
            }
            try w.flush();
        }
    }
};

test "full duplex: both bodies at once under small windows, a SETTINGS change, PING" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest; // POSIX sockets and pipes
    const io = testing.io;
    const c2s = try pipe();
    const s2c = try pipe();
    var buffers: [4][16 * 1024]u8 = undefined;
    var cr = s2c[0].readerStreaming(io, &buffers[0]);
    var cw = c2s[1].writerStreaming(io, &buffers[1]);
    var pr = c2s[0].readerStreaming(io, &buffers[2]);
    var pw = s2c[1].writerStreaming(io, &buffers[3]);
    defer for ([_]Io.File{ s2c[0], s2c[1], c2s[0] }) |f| f.close(io);

    var peer: DuplexPeer = .{ .io = io, .from = &pr.interface, .to = &pw.interface, .down_total = 1 << 20, .up_total = 300_000 };
    const peer_thread = try std.Thread.spawn(.{}, DuplexPeer.run, .{&peer});

    var c: Conn = undefined;
    var rbuf: [4096]u8 = undefined;
    var wbuf: [2048]u8 = undefined;
    c.init(io, &cr.interface, &cw.interface, &rbuf, &wbuf, .{ .window = 65535 });
    try c.start(&test_request);
    // the head comes after the server's SETTINGS (stream window 1000), so
    // the upload starts with that in effect
    try testing.expectEqual(200, try c.response());

    const Up = struct {
        fn run(conn: *Conn, total: usize) void {
            upload(conn, total) catch {};
        }
        fn upload(conn: *Conn, total: usize) !void {
            const sizes = [_]usize{ 1, 999, 4096, 16384, 40000, 7, 30000 };
            var chunk: [40000]u8 = undefined;
            var sent: usize = 0;
            var k: usize = 0;
            while (sent < total) : (k += 1) {
                const n = @min(sizes[k % sizes.len], total - sent);
                for (chunk[0..n], sent..) |*b, i| b.* = upByte(i);
                try conn.writer().writeAll(chunk[0..n]);
                if (k % 3 == 0) try conn.writer().flush();
                sent += n;
            }
            try conn.closeWrite();
        }
    };
    const up_thread = try std.Thread.spawn(.{}, Up.run, .{ &c, peer.up_total });

    var got: usize = 0;
    var rb: [5000]u8 = undefined;
    while (true) {
        const n = try c.reader().readSliceShort(&rb);
        for (rb[0..n], got..) |b, i| if (b != downByte(i)) return error.BadDownload;
        got += n;
        if (n < rb.len) break;
    }
    up_thread.join();
    c2s[1].close(io); // the peer's reader sees the end
    peer_thread.join();

    try testing.expectEqual(null, peer.err);
    try testing.expectEqual(null, c.read_err);
    try testing.expectEqual(null, c.write_err);
    try testing.expectEqual(1 << 20, got);
    try testing.expectEqual(peer.up_total, peer.up_len);
    try testing.expectEqualStrings("0", c.trailers()[0].value);
    try testing.expectEqual(2, peer.acks);
    try testing.expect(peer.pinged);
    // the stream window was at most 3000, so no frame was larger
    try testing.expect(peer.largest <= 3000);
}

test "a writer waiting for credit is released by close, a reset, or the end of the response" {
    var hb: [16]u8 = undefined;
    const ok_head = encodeBlock(&hb, &.{.{ .name = ":status", .value = "200" }});
    const Writer = struct {
        fn run(c: *Conn) void {
            c.writer().writeAll("x") catch return;
            c.writer().flush() catch return;
        }
    };
    for ([_]Error{ error.Closed, error.StreamReset, error.Closed }, 0..) |want, case| {
        var b: [256]u8 = undefined;
        var w: Io.Writer = .fixed(&b);
        try settingsFrame(&w, &.{.{ 0x4, 0 }}); // no credit for the stream
        try frame(&w, .headers, end_headers | @as(u8, if (case == 2) end_stream else 0), 1, ok_head);
        if (case == 1) try u32Frame(&w, .rst_stream, 1, 2);
        var out: [512]u8 = undefined;
        var s: Scripted = undefined;
        try s.init(w.buffered(), &out, .{});
        var wbuf: [64]u8 = undefined;
        s.c.body_out.buffer = &wbuf;
        try testing.expectEqual(200, try s.c.response());
        const t = try std.Thread.spawn(.{}, Writer.run, .{&s.c});
        switch (case) {
            0 => s.c.close(),
            1 => try testing.expectError(error.ReadFailed, s.c.reader().discardRemaining()),
            else => _ = try s.c.reader().discardRemaining(),
        }
        t.join();
        try testing.expectEqual(want, s.c.write_err.?);
        if (case == 0) {
            // RST_STREAM(CANCEL) and GOAWAY(NO_ERROR) went out
            var list: [8]Sent = undefined;
            const r = try s.replies(&list);
            try testing.expectEqual(Type.rst_stream, r[1].h.type);
            try testing.expectEqual(code_cancel, std.mem.readInt(u32, r[1].payload[0..4], .big));
            try testing.expectEqual(Type.goaway, r[2].h.type);
            try testing.expectEqual(code_no_error, std.mem.readInt(u32, r[2].payload[4..8], .big));
        }
    }
}

test "memory per connection" {
    // HPACK context and header storage dominate; no frame buffers
    try testing.expect(@sizeOf(Conn) < 7 * 1024);
}

test "an unbuffered writer sends a repeated pattern in few frames" {
    var b: [64]u8 = undefined;
    var w: Io.Writer = .fixed(&b);
    try settingsFrame(&w, &.{});
    var out: [2048]u8 = undefined;
    var s: Scripted = undefined;
    try s.init(w.buffered(), &out, .{});
    try s.c.writer().splatByteAll('z', 600);
    try s.c.writer().print("{d}", .{42});
    try s.c.closeWrite();
    var list: [16]Sent = undefined;
    const f = try s.replies(&list);
    try testing.expectEqual(5, f.len); // 256 + 256 + 88, "42", END_STREAM
    var total: usize = 0;
    for (f[0..3]) |d| {
        try testing.expectEqual(Type.data, d.h.type);
        for (d.payload) |byte| try testing.expectEqual('z', byte);
        total += d.payload.len;
    }
    try testing.expectEqual(600, total);
    try testing.expectEqualStrings("42", f[3].payload);
    try testing.expectEqual(end_stream, f[4].h.flags);
    try testing.expectError(error.WriteFailed, s.c.writer().writeAll("late"));
    try testing.expectEqual(error.Closed, s.c.write_err.?);
}
