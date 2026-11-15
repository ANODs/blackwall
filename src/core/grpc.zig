//! gRPC (type=grpc): Xray's "gun" transport, spoken the way Xray's client
//! (grpc-go) speaks it (Xray-core v26.11.9, transport/internet/grpc). One
//! bidirectional streaming call over HTTP/2: POST /<serviceName>/Tun, or
//! /TunMulti in multi mode, both ways a stream of gRPC messages, each a
//! 5-byte prefix (not compressed, length) and a protobuf message whose
//! field 1 carries the bytes: `Hunk { bytes data = 1; }`, or
//! `MultiHunk { repeated bytes data = 1; }` in multi mode.
//!
//! A one-element MultiHunk is byte for byte a Hunk, so both modes send the
//! same messages, one per flush, and differ only in the path; the reader
//! takes every field 1 of a message in order, which covers both.
//!
//! Like Xray: no round trip before data (the request head and the first
//! message may leave together), `:scheme http` even inside TLS (Xray does
//! TLS itself and gives grpc-go insecure credentials), Xray's Chrome
//! user-agent without grpc-go's suffix. Unlike Xray, one connection carries
//! one call: Xray multiplexes all calls to a server over one connection.
//!
//! Threads as in h2.zig: `reader()` on one, `writer()` and `closeWrite()` on
//! another, `close()` from either. Keep reading while uploading: credit
//! for the upload arrives through the reader. End the upload with
//! `closeWrite`, never by shutting the socket: the connection still has to
//! answer the server's SETTINGS and PINGs for the download to go on.
//!
//! Memory: the h2 connection (6.5 KiB) and the caller's two buffers. A
//! message is sealed in place: the write buffer keeps room for the prefix
//! and the field header in front of the payload, so nothing is staged.

const std = @import("std");
const Io = std.Io;
const h2 = @import("h2.zig");
const browser = @import("httpupgrade.zig");

const Field = h2.Field;

pub const Mode = enum {
    /// Tun: a Hunk per message
    gun,
    /// TunMulti: MultiHunk, several pieces per message
    multi,
};

pub const Error = h2.Error || error{
    /// A service name or authority that cannot go into a request.
    GrpcBadOptions,
    /// The HTTP status was not 200, kept in `status`: a CDN or web server
    /// in front refuses (404: wrong path there, 502: no way to the server).
    GrpcRefused,
    /// 200, but not application/grpc: something other than a gRPC server
    /// answers on that path.
    GrpcNotGrpc,
    /// The call ended with a gRPC status other than OK, kept in
    /// `grpc_status`. From Xray 12 (unimplemented) means a wrong
    /// serviceName or mode.
    GrpcStatus,
    /// A message that is not a Hunk: a compressed one (never asked for),
    /// or protobuf that does not parse.
    GrpcBadMessage,
    /// The stream ended inside a message.
    GrpcTruncated,
};

pub const Options = struct {
    /// The link's serviceName, percent-decoded once. One that starts with
    /// '/' is a custom path, "/<service path>/<Tun name>[|<TunMulti name>]".
    service_name: []const u8 = "",
    /// `:authority`, as `authority` picks it.
    authority: []const u8,
    mode: Mode = .gun,
};

/// Payload bytes a message may carry: its field length stays a varint of
/// at most 3 bytes.
const max_payload = (1 << 21) - 1;
/// Room kept in front of the payload: the gRPC prefix (5), the tag of
/// field 1 (1) and its length (3).
const head_room = 5 + 1 + 3;
/// Request paths longer than this are not real ones.
const max_path = 2048;

/// The `:authority` Xray's client sends: the link's `authority`, else the
/// sni of plain TLS (`tls_sni`, empty otherwise), else a server address
/// that is a name, unless REALITY is on, else address:port as grpc-go makes
/// it from its dial target. Slices point into the arguments or `buf`.
pub fn authority(buf: *[264]u8, link_authority: []const u8, tls_sni: []const u8, reality: bool, host: []const u8, port: u16) []const u8 {
    if (link_authority.len > 0) return link_authority;
    if (tls_sni.len > 0) return tls_sni;
    const bare = std.mem.trim(u8, host, "[]");
    const ip = if (Io.net.IpAddress.parse(bare, port)) |_| true else |_| false;
    if (!reality and !ip) return host;
    var w: Io.Writer = .fixed(buf);
    const v6 = std.mem.findScalar(u8, bare, ':') != null;
    w.print("{s}{s}{s}:{d}", .{ if (v6) "[" else "", bare, if (v6) "]" else "", port }) catch return host;
    return w.buffered();
}

pub const Conn = struct {
    h2: h2.Conn,
    body_in: Io.Reader,
    body_out: Io.Writer,
    /// HTTP status of the response, once `reader()` has seen it
    status: u16 = 0,
    /// grpc-status the call ended with, once it did
    grpc_status: ?u32 = null,
    /// Why `reader()` failed: one of ours, or the h2 error.
    read_err: ?Error = null,

    // reading thread only
    rstate: enum { head, open, eof, failed } = .head,
    /// bytes left of the current message, and of its field 1 being read
    msg_left: u32 = 0,
    data_left: u32 = 0,
    /// h2's read buffer: only message and field headers pass through it
    small: [16]u8 = undefined,

    /// Send the HTTP/2 preface and the request head into `out`, the stream
    /// inside TLS (or the socket), and flush it. It does not wait for the
    /// answer: data may follow at once, and the outcome shows on the first
    /// read. `read_buffer` backs `reader()` (any size); `write_buffer`
    /// bounds the messages sent and must be larger than 9 bytes (16 KiB - 18
    /// puts each in one DATA frame and that in one TLS record). `in` needs
    /// a buffer of at least 9 bytes; a small one saves a copy, as payload
    /// then goes straight from TLS records to `read_buffer`. The connection
    /// must stay in place afterwards.
    pub fn open(g: *Conn, io: Io, in: *Io.Reader, out: *Io.Writer, read_buffer: []u8, write_buffer: []u8, o: Options) Error!void {
        std.debug.assert(read_buffer.len > 0 and write_buffer.len > head_room);
        g.* = .{
            .h2 = undefined,
            .body_in = .{ .vtable = &.{ .stream = bodyStream }, .buffer = read_buffer, .seek = 0, .end = 0 },
            .body_out = .{
                .vtable = &.{ .drain = bodyDrain, .flush = bodyFlush },
                .buffer = write_buffer[head_room..][0..@min(write_buffer.len - head_room, max_payload)],
            },
        };
        g.h2.init(io, in, out, &g.small, &.{}, .{});
        var path_buf: [max_path]u8 = undefined;
        var pw: Io.Writer = .fixed(&path_buf);
        writePath(&pw, o.service_name, o.mode) catch return error.GrpcBadOptions;
        if (!validValue(o.authority)) return error.GrpcBadOptions;
        var ua_buf: [160]u8 = undefined;
        var uw: Io.Writer = .fixed(&ua_buf);
        browser.writeUserAgent(&uw, browser.chromeMajor(Io.Clock.real.now(io).toSeconds())) catch unreachable;
        // grpc-go's order (http2_client.go createHeaderFields)
        try g.h2.start(&.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = pw.buffered() },
            .{ .name = ":authority", .value = o.authority },
            .{ .name = "content-type", .value = "application/grpc" },
            .{ .name = "user-agent", .value = uw.buffered() },
            .{ .name = "te", .value = "trailers" },
        });
    }

    /// The download. The first read waits for the response head and fails
    /// unless it is a 200 from a gRPC server (`read_err`, `status`); the
    /// end of the call is the end of the stream when its status is OK.
    /// Reading thread.
    pub fn reader(g: *Conn) *Io.Reader {
        return &g.body_in;
    }

    /// The upload; each flush sends what is buffered as one message.
    /// Failures leave their cause in `g.h2.write_err`. Writing thread.
    pub fn writer(g: *Conn) *Io.Writer {
        return &g.body_out;
    }

    /// End the upload after what is buffered (END_STREAM, as grpc-go's
    /// CloseSend). Xray's server passes the end on to the destination; the
    /// download goes on until the destination closes. Writing thread.
    pub fn closeWrite(g: *Conn) Io.Writer.Error!void {
        try g.sendBuffered(false);
        try g.h2.closeWrite();
    }

    /// End the call from any thread (RST_STREAM CANCEL, as grpc-go when the
    /// local side goes away) and say GOAWAY, as the connection carried only
    /// this call. Then close the transport: that wakes a reader blocked in
    /// it.
    pub fn close(g: *Conn) void {
        g.h2.close();
    }

    // ------------------------------------------------------------ writing

    /// What `body_out` holds leaves as one message, sealed in place: the
    /// prefix and field header go into the room in front of the buffer.
    fn sendBuffered(g: *Conn, flush: bool) Io.Writer.Error!void {
        const wr = &g.body_out;
        const n = wr.end;
        wr.end = 0;
        const hw = g.h2.writer();
        if (n > 0) {
            var h: [head_room]u8 = undefined;
            var k: usize = 6;
            var v: usize = n;
            while (v >= 0x80) : (v >>= 7) {
                h[k] = @as(u8, @truncate(v)) | 0x80;
                k += 1;
            }
            h[k] = @intCast(v);
            k += 1;
            h[0] = 0; // not compressed
            std.mem.writeInt(u32, h[1..5], @intCast(k - 5 + n), .big);
            h[5] = 0x0a; // field 1, length-delimited
            const start = wr.buffer.ptr - k;
            @memcpy(start[0..k], h[0..k]);
            try hw.writeAll(start[0 .. k + n]);
        }
        if (flush) try hw.flush();
    }

    fn bodyDrain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const g: *Conn = @alignCast(@fieldParentPtr("body_out", w));
        // top the buffer up and send it whole, so messages are as large as it
        var n: usize = 0;
        fill: for (data, 0..) |d, i| {
            if (d.len == 0) continue;
            for (0..if (i == data.len - 1) splat else 1) |_| {
                const k = @min(d.len, w.buffer.len - w.end);
                @memcpy(w.buffer[w.end..][0..k], d[0..k]);
                w.end += k;
                n += k;
                if (k < d.len) break :fill;
            }
        }
        try g.sendBuffered(true);
        return n;
    }

    fn bodyFlush(w: *Io.Writer) Io.Writer.Error!void {
        const g: *Conn = @alignCast(@fieldParentPtr("body_out", w));
        return g.sendBuffered(true);
    }

    // ------------------------------------------------------------ reading

    fn failRead(g: *Conn, e: Error) error{ReadFailed} {
        if (g.read_err == null) g.read_err = e;
        g.rstate = .failed;
        return error.ReadFailed;
    }

    /// The h2 connection failed; it knows why.
    fn h2Failed(g: *Conn) error{ReadFailed} {
        return g.failRead(g.h2.read_err orelse error.ReadFailed);
    }

    fn bodyStream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const g: *Conn = @alignCast(@fieldParentPtr("body_in", r));
        switch (g.rstate) {
            .head => try g.awaitHead(),
            .open => {},
            .eof => return error.EndOfStream,
            .failed => return error.ReadFailed,
        }
        while (g.data_left == 0) try g.nextData();
        const n = g.h2.reader().stream(w, limit.min(.limited(g.data_left))) catch |e| switch (e) {
            error.EndOfStream => return g.failRead(error.GrpcTruncated),
            error.ReadFailed => return g.h2Failed(),
            error.WriteFailed => return error.WriteFailed,
        };
        g.data_left -= @intCast(n);
        g.msg_left -= @intCast(n);
        return n;
    }

    /// The response head, as grpc-go checks it: 200 and a gRPC content
    /// type. A head that ends the call (Trailers-Only, Xray's answer to an
    /// unknown service) shows its status at the end of the body.
    fn awaitHead(g: *Conn) error{ReadFailed}!void {
        g.status = g.h2.response() catch return g.h2Failed();
        if (g.status != 200) return g.failRead(error.GrpcRefused);
        // a head too long for h2's field space (a CDN's) may have lost the
        // content type: then the messages have to speak for themselves
        const ct = header(g.h2.headers(), "content-type") orelse
            if (g.h2.list.dropped > 0) "application/grpc" else "";
        const grpc = std.mem.startsWith(u8, ct, "application/grpc") and
            (ct.len == 16 or ct[16] == '+' or ct[16] == ';');
        if (!grpc) return g.failRead(error.GrpcNotGrpc);
        g.rstate = .open;
    }

    /// Read message and field headers until bytes of a field 1 come, and
    /// skip any other field (protobuf: unknown fields are ignored). Every
    /// field 1 counts: a MultiHunk has one per piece, a Hunk one. At the
    /// end of the stream, between messages, the call's status decides.
    fn nextData(g: *Conn) error{ ReadFailed, EndOfStream }!void {
        const hr = g.h2.reader();
        while (true) {
            if (g.msg_left == 0) {
                const prefix = hr.takeArray(5) catch |e| switch (e) {
                    error.EndOfStream => {
                        if (hr.bufferedLen() > 0) return g.failRead(error.GrpcTruncated);
                        return g.ended();
                    },
                    error.ReadFailed => return g.h2Failed(),
                };
                if (prefix[0] != 0) return g.failRead(error.GrpcBadMessage);
                g.msg_left = std.mem.readInt(u32, prefix[1..5], .big);
                continue;
            }
            const tag = try g.varint();
            if (tag >> 3 == 0) return g.failRead(error.GrpcBadMessage);
            switch (tag & 7) {
                0 => _ = try g.varint(),
                1 => try g.skip(8),
                2 => {
                    const len = try g.varint();
                    if (len > g.msg_left) return g.failRead(error.GrpcBadMessage);
                    if (tag >> 3 == 1) {
                        g.data_left = @intCast(len);
                        if (len > 0) return;
                    } else try g.skip(len);
                },
                5 => try g.skip(4),
                else => return g.failRead(error.GrpcBadMessage), // groups: not proto3
            }
        }
    }

    /// The stream ended where a message would begin: the end of the call,
    /// good if its status is OK. A missing status passes too: the data is
    /// whole, and a proxy in between may drop trailers.
    fn ended(g: *Conn) error{ ReadFailed, EndOfStream } {
        const text = header(g.h2.trailers(), "grpc-status") orelse header(g.h2.headers(), "grpc-status") orelse "0";
        const code = std.fmt.parseInt(u32, text, 10) catch return g.failRead(error.GrpcBadMessage);
        g.grpc_status = code;
        if (code != 0) return g.failRead(error.GrpcStatus);
        g.rstate = .eof;
        return error.EndOfStream;
    }

    /// A varint inside the current message.
    fn varint(g: *Conn) error{ReadFailed}!u64 {
        const hr = g.h2.reader();
        var v: u64 = 0;
        var shift: u7 = 0;
        while (shift < 64) : (shift += 7) {
            if (g.msg_left == 0) return g.failRead(error.GrpcBadMessage);
            const b = hr.takeByte() catch |e| return switch (e) {
                error.EndOfStream => g.failRead(error.GrpcTruncated),
                error.ReadFailed => g.h2Failed(),
            };
            g.msg_left -= 1;
            v |= @as(u64, b & 0x7f) << @intCast(shift);
            if (b < 0x80) return v;
        }
        return g.failRead(error.GrpcBadMessage);
    }

    fn skip(g: *Conn, n: u64) error{ReadFailed}!void {
        if (n > g.msg_left) return g.failRead(error.GrpcBadMessage);
        g.h2.reader().discardAll(@intCast(n)) catch |e| return switch (e) {
            error.EndOfStream => g.failRead(error.GrpcTruncated),
            error.ReadFailed => g.h2Failed(),
        };
        g.msg_left -= @intCast(n);
    }
};

fn header(fields: []const Field, name: []const u8) ?[]const u8 {
    for (fields) |f| if (std.mem.eql(u8, f.name, name)) return f.value;
    return null;
}

/// A header value we send: no controls or line breaks, no spaces.
fn validValue(v: []const u8) bool {
    if (v.len == 0) return false;
    for (v) |b| if (b <= ' ' or b >= 0x7f) return false;
    return true;
}

/// The request path for a service name, as Xray builds it (grpc/config.go).
/// A plain name is one path segment: "/<name>/Tun". One that starts with
/// '/' is split at its last '/': what comes before is the service path,
/// escaped segment by segment; what follows names the stream, "Tun|Multi"
/// naming each mode's apart and a single name serving both.
fn writePath(w: *Io.Writer, name: []const u8, mode: Mode) Io.Writer.Error!void {
    try w.writeByte('/');
    if (name.len == 0 or name[0] != '/') {
        try writeSegment(w, name);
        return w.writeAll(if (mode == .gun) "/Tun" else "/TunMulti");
    }
    const last = std.mem.findScalarLast(u8, name, '/').?;
    var it = std.mem.splitScalar(u8, name[1..@max(last, 1)], '/');
    var first = true;
    while (it.next()) |segment| : (first = false) {
        if (!first) try w.writeByte('/');
        try writeSegment(w, segment);
    }
    try w.writeByte('/');
    var names = std.mem.splitScalar(u8, name[last + 1 ..], '|');
    const tun = names.first();
    try writeSegment(w, if (mode == .gun) tun else names.next() orelse tun);
}

/// Go's url.PathEscape: letters, digits, "-._~" and "$&+:=@" stay; any
/// other byte goes percent-encoded.
fn writeSegment(w: *Io.Writer, s: []const u8) Io.Writer.Error!void {
    for (s) |b| {
        if (std.ascii.isAlphanumeric(b) or std.mem.findScalar(u8, "-._~$&+:=@", b) != null) {
            try w.writeByte(b);
        } else {
            try w.print("%{X:0>2}", .{b});
        }
    }
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const hpack = @import("hpack.zig");

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const t_data = 0;
const t_headers = 1;
const t_rst_stream = 3;
const t_settings = 4;
const t_goaway = 7;
const t_window_update = 8;
const f_end_stream = 0x1;
const f_end_headers = 0x4;

fn frame(w: *Io.Writer, t: u8, flags: u8, stream: u32, payload: []const u8) !void {
    var h: [9]u8 = undefined;
    std.mem.writeInt(u24, h[0..3], @intCast(payload.len), .big);
    h[3] = t;
    h[4] = flags;
    std.mem.writeInt(u32, h[5..9], stream, .big);
    try w.writeAll(&h);
    try w.writeAll(payload);
}

fn headersFrame(w: *Io.Writer, end: bool, fields: []const Field) !void {
    var buf: [512]u8 = undefined;
    var bw: Io.Writer = .fixed(&buf);
    for (fields) |f| try hpack.writeField(&bw, f);
    try frame(w, t_headers, f_end_headers | @as(u8, if (end) f_end_stream else 0), 1, bw.buffered());
}

/// What Xray's server answers with, and ends a call with.
const ok_head = [_]Field{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = "application/grpc" } };
const ok_trailers = [_]Field{ .{ .name = "grpc-status", .value = "0" }, .{ .name = "grpc-message", .value = "" } };

/// A gRPC message with a field 1 per piece: a Hunk, or a MultiHunk.
fn message(w: *Io.Writer, pieces: []const []const u8) !void {
    var len: usize = 0;
    for (pieces) |p| {
        var v = p.len;
        len += 2 + p.len;
        while (v >= 0x80) : (v >>= 7) len += 1;
    }
    try w.writeByte(0);
    try w.writeInt(u32, @intCast(len), .big);
    for (pieces) |p| {
        try w.writeByte(0x0a);
        try w.writeUleb128(p.len);
        try w.writeAll(p);
    }
}

fn repeat(comptime s: []const u8, comptime n: usize) *const [s.len * n]u8 {
    comptime {
        var all: [s.len * n]u8 = undefined;
        for (0..n) |i| @memcpy(all[i * s.len ..][0..s.len], s);
        const done = all;
        return &done;
    }
}

const Sent = struct { type: u8, flags: u8, stream: u32, payload: []const u8 };

/// The frames a client wrote, after the preface.
fn sentFrames(out: []const u8, list: []Sent) ![]Sent {
    try testing.expect(std.mem.startsWith(u8, out, preface));
    var rest = out[preface.len..];
    var n: usize = 0;
    while (rest.len >= 9) : (n += 1) {
        const len = std.mem.readInt(u24, rest[0..3], .big);
        list[n] = .{ .type = rest[3], .flags = rest[4], .stream = std.mem.readInt(u32, rest[5..9], .big), .payload = rest[9..][0..len] };
        rest = rest[9 + len ..];
    }
    try testing.expectEqual(0, rest.len);
    return list[0..n];
}

/// The upload in `bytes`, the DATA payloads joined, read as Xray's server
/// reads it: every message exactly one field 1 (grpc-go would take more,
/// but we never send more). Returns the payload and the message count.
fn hunks(bytes: []const u8, into: []u8) !struct { []const u8, usize } {
    var r: Io.Reader = .fixed(bytes);
    var n: usize = 0;
    var count: usize = 0;
    while (r.seek < bytes.len) : (count += 1) {
        try testing.expectEqual(0, try r.takeByte());
        const len = try r.takeInt(u32, .big);
        const before = r.seek;
        try testing.expectEqual(0x0a, try r.takeByte());
        const k = try r.takeLeb128(u32);
        try testing.expect(k > 0); // nothing sends empty messages
        try r.readSliceAll(into[n..][0..k]);
        n += k;
        try testing.expectEqual(len, r.seek - before);
    }
    return .{ into[0..n], count };
}

/// A client reading a scripted server and writing into `out`.
const Scripted = struct {
    in: Io.Reader,
    out: Io.Writer,
    g: Conn,
    rbuf: [64]u8,
    wbuf: [head_room + 300]u8,

    fn open(s: *Scripted, script: []const u8, out: []u8, o: Options) !void {
        s.in = .fixed(script);
        s.out = .fixed(out);
        try s.g.open(testing.io, &s.in, &s.out, &s.rbuf, &s.wbuf, o);
    }

    /// Everything the download gives, and how it ended.
    fn download(s: *Scripted, buf: []u8) !struct { []const u8, ?Error } {
        var w: Io.Writer = .fixed(buf);
        _ = s.g.reader().streamRemaining(&w) catch |e| switch (e) {
            error.ReadFailed => return .{ w.buffered(), s.g.read_err.? },
            error.WriteFailed => return e,
        };
        return .{ w.buffered(), null };
    }
};

const test_options: Options = .{ .service_name = "svc", .authority = "127.0.0.1:27312" };

test "the call is Xray's: request head, a Hunk per flush, END_STREAM" {
    var sb: [256]u8 = undefined;
    var sw: Io.Writer = .fixed(&sb);
    try frame(&sw, t_settings, 0, 0, "");
    try headersFrame(&sw, false, &ok_head);
    var mb: [64]u8 = undefined;
    var mw: Io.Writer = .fixed(&mb);
    try message(&mw, &.{"pong"});
    try frame(&sw, t_data, 0, 1, mw.buffered());
    try headersFrame(&sw, true, &ok_trailers);

    var out: [1024]u8 = undefined;
    var s: Scripted = undefined;
    try s.open(sw.buffered(), &out, test_options);
    const w = s.g.writer();
    try w.writeAll("hello");
    try w.flush();
    try w.flush(); // nothing buffered: no empty message
    try w.writeAll("again");
    try s.g.closeWrite();
    var db: [64]u8 = undefined;
    const got, const err = try s.download(&db);
    try testing.expectEqual(null, err);
    try testing.expectEqualStrings("pong", got);
    try testing.expectEqual(200, s.g.status);
    try testing.expectEqual(0, s.g.grpc_status.?);
    try testing.expectError(error.EndOfStream, s.g.reader().takeByte());

    var list: [16]Sent = undefined;
    const sent = try sentFrames(s.out.buffered(), &list);
    // as captured from Xray 26.11.9's client: the head leaves before the
    // server's SETTINGS are seen, the fields in this order
    try testing.expectEqual(t_settings, sent[0].type);
    try testing.expectEqual(t_window_update, sent[1].type);
    try testing.expectEqual(t_headers, sent[2].type);
    try testing.expectEqual(f_end_headers, sent[2].flags);
    var block: Io.Reader = .fixed(sent[2].payload);
    var dec: hpack.Decoder(4096) = .{};
    var fb: [512]u8 = undefined;
    var fields: [16]Field = undefined;
    var fl: hpack.List = .init(&fb, &fields);
    try dec.decode(&block, &fl);
    var ua_buf: [160]u8 = undefined;
    var uw: Io.Writer = .fixed(&ua_buf);
    try browser.writeUserAgent(&uw, browser.chromeMajor(Io.Clock.real.now(testing.io).toSeconds()));
    const want = [_]Field{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/svc/Tun" },
        .{ .name = ":authority", .value = "127.0.0.1:27312" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "user-agent", .value = uw.buffered() },
        .{ .name = "te", .value = "trailers" },
    };
    try testing.expectEqual(want.len, fl.len);
    for (want, fl.slice()) |a, b| {
        try testing.expectEqualStrings(a.name, b.name);
        try testing.expectEqualStrings(a.value, b.value);
    }
    try testing.expect(std.mem.startsWith(u8, uw.buffered(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"));
    // one message, one DATA frame: 00, length, tag 0a, length, bytes
    try testing.expectEqual(t_data, sent[3].type);
    try testing.expectEqual(0, sent[3].flags);
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x00\x07\x0a\x05hello", sent[3].payload);
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x00\x07\x0a\x05again", sent[4].payload);
    // grpc-go's CloseSend: an empty DATA frame with END_STREAM
    try testing.expectEqual(t_data, sent[5].type);
    try testing.expectEqual(f_end_stream, sent[5].flags);
    try testing.expectEqual(0, sent[5].payload.len);
    // then the reader's SETTINGS acknowledgment
    try testing.expectEqual(t_settings, sent[6].type);
    try testing.expectEqual(7, sent.len);
    // writing after the end fails
    try w.writeAll("x");
    try testing.expectError(error.WriteFailed, w.flush());
    try testing.expectEqual(error.Closed, s.g.h2.write_err.?);
}

test "paths as Xray builds them from serviceName" {
    const cases = [_]struct { []const u8, Mode, []const u8 }{
        .{ "svc", .gun, "/svc/Tun" },
        .{ "svc", .multi, "/svc/TunMulti" },
        .{ "", .gun, "//Tun" },
        // a plain name is one segment: its slashes are escaped
        .{ "a/b c", .gun, "/a%2Fb%20c/Tun" },
        .{ "GunService", .multi, "/GunService/TunMulti" },
        .{ "я?", .gun, "/%D1%8F%3F/Tun" },
        // custom paths: the last segment names the stream
        .{ "/my/sample/path1", .gun, "/my/sample/path1" },
        .{ "/my/sample/path1", .multi, "/my/sample/path1" },
        .{ "/my/sample/path1|path2", .gun, "/my/sample/path1" },
        .{ "/my/sample/path1|path2", .multi, "/my/sample/path2" },
        .{ "/my path/T un", .gun, "/my%20path/T%20un" },
        .{ "/Tun", .gun, "//Tun" },
        .{ "/", .multi, "//" },
    };
    for (cases) |c| {
        var buf: [64]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        try writePath(&w, c[0], c[1]);
        try testing.expectEqualStrings(c[2], w.buffered());
    }
    // too long for a request, or an authority that cannot go into one
    var out: [4096]u8 = undefined;
    var s: Scripted = undefined;
    try testing.expectError(error.GrpcBadOptions, s.open("", &out, .{ .service_name = &@as([3000]u8, @splat('x')), .authority = "a" }));
    try testing.expectError(error.GrpcBadOptions, s.open("", &out, .{ .authority = "" }));
    try testing.expectError(error.GrpcBadOptions, s.open("", &out, .{ .authority = "a b" }));
    try testing.expectError(error.GrpcBadOptions, s.open("", &out, .{ .authority = "a\r\nx: y" }));
}

test "authority as Xray picks it" {
    var buf: [264]u8 = undefined;
    // the link's own, then the sni of plain TLS
    try testing.expectEqualStrings("a.example", authority(&buf, "a.example", "sni.example", false, "h.example", 443));
    try testing.expectEqualStrings("sni.example", authority(&buf, "", "sni.example", false, "198.51.100.7", 443));
    // no TLS: a name goes as it is, an address with its port
    try testing.expectEqualStrings("h.example", authority(&buf, "", "", false, "h.example", 2053));
    try testing.expectEqualStrings("198.51.100.7:2053", authority(&buf, "", "", false, "198.51.100.7", 2053));
    try testing.expectEqualStrings("[2001:db8::7]:443", authority(&buf, "", "", false, "2001:db8::7", 443));
    try testing.expectEqualStrings("[2001:db8::7]:443", authority(&buf, "", "", false, "[2001:db8::7]", 443));
    // REALITY: never the server's name alone
    try testing.expectEqualStrings("h.example:443", authority(&buf, "", "", true, "h.example", 443));
    try testing.expectEqualStrings("198.51.100.7:443", authority(&buf, "", "", true, "198.51.100.7", 443));
}

test "download: Hunks and MultiHunks, split anywhere, unknown fields skipped" {
    // the messages
    var mb: [2048]u8 = undefined;
    var mw: Io.Writer = .fixed(&mb);
    try message(&mw, &.{"one"});
    try message(&mw, &.{ "two", "", "three" }); // a MultiHunk, one piece empty
    try message(&mw, &.{}); // an empty message
    const long = comptime repeat("0123456789abcdef", 20); // a two-byte length
    try message(&mw, &.{ long, "four" });
    // fields a later Xray might add, of every wire type, around field 1
    try mw.writeAll("\x00\x00\x00\x00\x1c" ++ "\x10\x96\x01" ++ "\x19" ++ @as([8]u8, @splat(0)) ++ "\x0a\x04five" ++
        "\x25" ++ @as([4]u8, @splat(0)) ++ "\x2a\x03xyz");
    const messages = mw.buffered();
    const want = "one" ++ "two" ++ "three" ++ long ++ "four" ++ "five";

    // in DATA frames of every small size, so every header gets split
    for ([_]usize{ 1, 2, 3, 5, 7, 400, 16384 }) |step| {
        var sb: [16 * 1024]u8 = undefined;
        var sw: Io.Writer = .fixed(&sb);
        try frame(&sw, t_settings, 0, 0, "");
        try headersFrame(&sw, false, &ok_head);
        var rest: []const u8 = messages;
        while (rest.len > 0) {
            const n = @min(step, rest.len);
            try frame(&sw, t_data, 0, 1, rest[0..n]);
            rest = rest[n..];
            if (step == 3) try frame(&sw, t_data, 0, 1, ""); // empty frames between
        }
        // Xray's server ends with trailers; a proxy may end with DATA
        if (step % 2 == 0) try frame(&sw, t_data, f_end_stream, 1, "") else try headersFrame(&sw, true, &ok_trailers);

        var out: [16 * 1024]u8 = undefined;
        var s: Scripted = undefined;
        try s.open(sw.buffered(), &out, test_options);
        var db: [1024]u8 = undefined;
        const got, const err = try s.download(&db);
        try testing.expectEqual(null, err);
        try testing.expectEqualStrings(want, got);
        try testing.expectEqual(0, s.g.grpc_status.?);
    }
}

test "upload: a message per buffer, lengths of one to three bytes, sealed in place" {
    var sb: [64]u8 = undefined;
    var sw: Io.Writer = .fixed(&sb);
    try frame(&sw, t_settings, 0, 0, "");
    var out: [80 * 1024]u8 = undefined;
    var in: Io.Reader = .fixed(sw.buffered());
    var ow: Io.Writer = .fixed(&out);
    var g: Conn = undefined;
    var rbuf: [16]u8 = undefined;
    var wbuf: [head_room + 20000]u8 = undefined;
    try g.open(testing.io, &in, &ow, &rbuf, &wbuf, .{ .authority = "h.example", .mode = .multi });
    const w = g.writer();
    var data: [50000]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    // 1, 127 (the last one-byte length), 128, then past the 16384 a
    // two-byte length holds, then more than the buffer: split
    var at: usize = 0;
    for ([_]usize{ 1, 127, 128, 17000, 30000 }) |n| {
        try w.writeAll(data[at..][0..n]);
        try w.flush();
        at += n;
    }
    // unflushed bytes leave with closeWrite, the last frame ending the stream
    try w.writeAll(data[at..][0..10]);
    at += 10;
    try g.closeWrite();

    var list: [32]Sent = undefined;
    const sent = try sentFrames(ow.buffered(), &list);
    var joined: [64 * 1024]u8 = undefined;
    var n: usize = 0;
    var sizes: [16]usize = undefined;
    var count: usize = 0;
    try testing.expectEqual(t_headers, sent[2].type);
    for (sent[3..]) |f| {
        try testing.expectEqual(t_data, f.type);
        @memcpy(joined[n..][0..f.payload.len], f.payload);
        n += f.payload.len;
        sizes[count] = f.payload.len;
        count += 1;
    }
    try testing.expectEqual(f_end_stream, sent[sent.len - 1].flags);
    // the peer's frame size bounds a DATA frame, so the 17000 and the two
    // parts of the 30000 take two frames each
    try testing.expectEqualSlices(usize, &.{ 7 + 1, 7 + 127, 8 + 128, 16384, 9 + 17000 - 16384, 16384, 9 + 20000 - 16384, 8 + 10000, 7 + 10, 0 }, sizes[0..count]);
    var payload: [50000]u8 = undefined;
    const got, const messages = try hunks(joined[0..n], &payload);
    try testing.expectEqual(7, messages);
    try testing.expectEqualSlices(u8, data[0..at], got);
    // the head room took the headers: the buffer starts where it did
    try testing.expectEqual(@intFromPtr(&wbuf) + head_room, @intFromPtr(w.buffer.ptr));
    try testing.expectEqual(20000, w.buffer.len);
}

test "refusals and broken streams say what happened" {
    const Case = struct {
        head: []const Field,
        /// DATA after the head, then how the stream ends
        body: []const u8 = "",
        end: union(enum) { trailers: []const Field, data, reset: u32, cut, none } = .none,
        want: Error,
        got: []const u8 = "",
        status: u16 = 200,
        grpc_status: ?u32 = null,
    };
    const cases = [_]Case{
        // a CDN or web server in front
        .{ .head = &.{ .{ .name = ":status", .value = "404" }, .{ .name = "content-type", .value = "text/html" } }, .body = "<html>", .want = error.GrpcRefused, .status = 404 },
        .{ .head = &.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = "text/html" } }, .body = "<html>", .want = error.GrpcNotGrpc },
        .{ .head = &.{.{ .name = ":status", .value = "200" }}, .want = error.GrpcNotGrpc },
        .{ .head = &.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = "application/grpcweb" } }, .want = error.GrpcNotGrpc },
        // Xray's answer to a wrong serviceName or mode: Trailers-Only
        .{
            .head = &.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = "application/grpc" }, .{ .name = "grpc-status", .value = "12" }, .{ .name = "grpc-message", .value = "unknown service svc" } },
            .end = .none,
            .want = error.GrpcStatus,
            .grpc_status = 12,
        },
        // an error after data: the data first
        .{ .head = &ok_head, .body = "\x00\x00\x00\x00\x04\x0a\x02ok", .end = .{ .trailers = &.{.{ .name = "grpc-status", .value = "14" }} }, .want = error.GrpcStatus, .got = "ok", .grpc_status = 14 },
        .{ .head = &ok_head, .end = .{ .trailers = &.{.{ .name = "grpc-status", .value = "x" }} }, .want = error.GrpcBadMessage },
        // a compressed message, which we never asked for
        .{ .head = &ok_head, .body = "\x01\x00\x00\x00\x04\x0a\x02ok", .end = .data, .want = error.GrpcBadMessage },
        // a field longer than its message, field number 0, a group
        .{ .head = &ok_head, .body = "\x00\x00\x00\x00\x04\x0a\x03ok", .end = .data, .want = error.GrpcBadMessage },
        .{ .head = &ok_head, .body = "\x00\x00\x00\x00\x02\x02\x00", .end = .data, .want = error.GrpcBadMessage },
        .{ .head = &ok_head, .body = "\x00\x00\x00\x00\x02\x0b\x0c", .end = .data, .want = error.GrpcBadMessage },
        // a varint that the message cuts, or that never ends
        .{ .head = &ok_head, .body = "\x00\x00\x00\x00\x02\x0a\x80", .end = .data, .want = error.GrpcBadMessage },
        .{ .head = &ok_head, .body = "\x00\x00\x00\x00\x0c\x0a" ++ @as([11]u8, @splat(0xff)), .end = .data, .want = error.GrpcBadMessage },
        // the stream ends inside a prefix, a header, the bytes
        .{ .head = &ok_head, .body = "\x00\x00\x00", .end = .data, .want = error.GrpcTruncated },
        .{ .head = &ok_head, .body = "\x00\x00\x00\x00\x04\x0a", .end = .data, .want = error.GrpcTruncated },
        .{ .head = &ok_head, .body = "\x00\x00\x00\x00\x04\x0a\x02o", .end = .{ .trailers = &ok_trailers }, .want = error.GrpcTruncated, .got = "o" },
        // the server resets the stream, or the connection breaks
        .{ .head = &ok_head, .body = "\x00\x00\x00\x00\x04\x0a\x02ok", .end = .{ .reset = 2 }, .want = error.StreamReset, .got = "ok" },
        .{ .head = &ok_head, .body = "\x00\x00\x00\x00\x04\x0a\x02ok", .end = .cut, .want = error.ConnectionClosed, .got = "ok" },
    };
    for (cases) |c| {
        var sb: [512]u8 = undefined;
        var sw: Io.Writer = .fixed(&sb);
        try frame(&sw, t_settings, 0, 0, "");
        try headersFrame(&sw, c.end == .none, c.head);
        if (c.body.len > 0) try frame(&sw, t_data, 0, 1, c.body);
        switch (c.end) {
            .trailers => |t| try headersFrame(&sw, true, t),
            .data => try frame(&sw, t_data, f_end_stream, 1, ""),
            .reset => |code| {
                var p: [4]u8 = undefined;
                std.mem.writeInt(u32, &p, code, .big);
                try frame(&sw, t_rst_stream, 0, 1, &p);
            },
            .cut, .none => {},
        }
        var out: [1024]u8 = undefined;
        var s: Scripted = undefined;
        try s.open(sw.buffered(), &out, test_options);
        var db: [64]u8 = undefined;
        const got, const err = try s.download(&db);
        try testing.expectEqual(c.want, err.?);
        try testing.expectEqualStrings(c.got, got);
        try testing.expectEqual(c.status, s.g.status);
        try testing.expectEqual(c.grpc_status, s.g.grpc_status);
        // and it stays failed
        try testing.expectError(error.ReadFailed, s.g.reader().takeByte());
        try testing.expectEqual(c.want, s.g.read_err.?);
    }
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
    return @truncate(i *% 7 +% 3);
}

/// A gRPC server for one call, the way grpc-go's behaves: a small stream
/// window that it reopens as it reads, messages that span DATA frames, and
/// trailers once both directions are done.
const Peer = struct {
    io: Io,
    from: *Io.Reader,
    to: *Io.Writer,
    multi: bool,
    down_total: usize,
    /// Guards `to` and `up_done`.
    mutex: Io.Mutex = .init,
    cond: Io.Condition = .init,
    up_done: bool = false,
    /// The upload's DATA payloads, joined.
    up: std.ArrayList(u8) = .empty,
    path: [64]u8 = undefined,
    path_len: usize = 0,
    acks: usize = 0,
    err: ?anyerror = null,

    fn run(p: *Peer) void {
        p.read() catch |e| {
            p.err = e;
        };
    }

    fn read(p: *Peer) !void {
        if (!std.mem.eql(u8, try p.from.takeArray(preface.len), preface)) return error.BadPreface;
        var down_thread: ?std.Thread = null;
        defer if (down_thread) |t| t.join();
        var buf: [16384]u8 = undefined;
        while (true) {
            const h = p.from.takeArray(9) catch |e| switch (e) {
                error.EndOfStream => return,
                else => return e,
            };
            const len = std.mem.readInt(u24, h[0..3], .big);
            const t = h[3];
            const flags = h[4];
            if (len > buf.len) return error.FrameTooLarge;
            const payload = buf[0..len];
            try p.from.readSliceAll(payload);
            switch (t) {
                t_headers => {
                    var block: Io.Reader = .fixed(payload);
                    var dec: hpack.Decoder(4096) = .{};
                    var fb: [512]u8 = undefined;
                    var fields: [16]Field = undefined;
                    var list: hpack.List = .init(&fb, &fields);
                    try dec.decode(&block, &list);
                    const path = list.get(":path") orelse return error.NoPath;
                    @memcpy(p.path[0..path.len], path);
                    p.path_len = path.len;
                    {
                        p.mutex.lockUncancelable(p.io);
                        defer p.mutex.unlock(p.io);
                        // a stream window of 3000: uploads wait for credit
                        try frame(p.to, t_settings, 0, 0, "\x00\x04\x00\x00\x0b\xb8");
                        try frame(p.to, t_settings, 1, 0, "");
                        try headersFrame(p.to, false, &ok_head);
                        try p.to.flush();
                    }
                    down_thread = try std.Thread.spawn(.{}, Peer.downLoop, .{p});
                },
                t_data => {
                    try p.up.appendSlice(testing.allocator, payload);
                    p.mutex.lockUncancelable(p.io);
                    defer p.mutex.unlock(p.io);
                    if (len > 0) {
                        var inc: [4]u8 = undefined;
                        std.mem.writeInt(u32, &inc, len, .big);
                        try frame(p.to, t_window_update, 0, 0, &inc);
                        try frame(p.to, t_window_update, 0, 1, &inc);
                        try p.to.flush();
                    }
                    if (flags & f_end_stream != 0) {
                        p.up_done = true;
                        p.cond.broadcast(p.io);
                    }
                },
                t_settings => if (flags & 1 != 0) {
                    p.acks += 1;
                },
                t_window_update, t_goaway => {},
                else => return error.UnexpectedFrame,
            }
        }
    }

    fn downLoop(p: *Peer) void {
        p.down() catch |e| {
            p.err = e;
        };
    }

    fn down(p: *Peer) !void {
        // messages of odd sizes, in multi mode of several pieces, cut into
        // DATA frames without regard to their bounds
        var stage: [40000]u8 = undefined;
        var sent: usize = 0;
        var k: usize = 0;
        const sizes = [_]usize{ 1, 300, 5000, 127, 128, 20000, 16384, 2 };
        while (sent < p.down_total) : (k += 1) {
            var mw: Io.Writer = .fixed(&stage);
            var pieces: [3][]const u8 = undefined;
            var data: [20000 * 3]u8 = undefined;
            var n: usize = 0;
            const count: usize = if (p.multi) 1 + k % 3 else 1;
            for (pieces[0..count], 0..) |*piece, i| {
                const want = @min(sizes[(k + i) % sizes.len] / count + 1, p.down_total - sent - n);
                for (data[n..][0..want], sent + n..) |*b, j| b.* = downByte(j);
                piece.* = data[n..][0..want];
                n += want;
            }
            try message(&mw, pieces[0..count]);
            sent += n;
            var rest = mw.buffered();
            p.mutex.lockUncancelable(p.io);
            defer p.mutex.unlock(p.io);
            while (rest.len > 0) {
                const m = @min(rest.len, 16384 - k % 5 * 1000);
                try frame(p.to, t_data, 0, 1, rest[0..m]);
                rest = rest[m..];
            }
            try p.to.flush();
        }
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        while (!p.up_done) p.cond.waitUncancelable(p.io, &p.mutex);
        try headersFrame(p.to, true, &ok_trailers);
        try p.to.flush();
    }
};

test "a reading and a writing thread against a gRPC server, both modes" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest; // POSIX sockets and pipes
    const io = testing.io;
    for ([_]Mode{ .gun, .multi }) |mode| {
        const c2s = try pipe();
        const s2c = try pipe();
        var buffers: [4][16 * 1024]u8 = undefined;
        var cr = s2c[0].readerStreaming(io, &buffers[0]);
        var cw = c2s[1].writerStreaming(io, &buffers[1]);
        var pr = c2s[0].readerStreaming(io, &buffers[2]);
        var pw = s2c[1].writerStreaming(io, &buffers[3]);
        defer for ([_]Io.File{ s2c[0], s2c[1], c2s[0] }) |f| f.close(io);

        const up_total = 200_000;
        var peer: Peer = .{ .io = io, .from = &pr.interface, .to = &pw.interface, .multi = mode == .multi, .down_total = 700_000 };
        defer peer.up.deinit(testing.allocator);
        const peer_thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});

        var g: Conn = undefined;
        var rbuf: [4096]u8 = undefined;
        var wbuf: [16384 - 18]u8 = undefined;
        try g.open(io, &cr.interface, &cw.interface, &rbuf, &wbuf, .{ .service_name = "svc", .authority = "h.example", .mode = mode });

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
        const up_thread = try std.Thread.spawn(.{}, Up.run, .{ &g, up_total });

        var got: usize = 0;
        var rb: [5000]u8 = undefined;
        while (true) {
            const n = try g.reader().readSliceShort(&rb);
            for (rb[0..n], got..) |b, i| if (b != downByte(i)) return error.BadDownload;
            got += n;
            if (n < rb.len) break;
        }
        up_thread.join();
        g.close();
        cw.interface.flush() catch {};
        c2s[1].close(io); // the peer's reader sees the end
        peer_thread.join();

        try testing.expectEqual(null, peer.err);
        try testing.expectEqual(null, g.read_err);
        try testing.expectEqual(null, g.h2.write_err);
        try testing.expectEqual(peer.down_total, got);
        try testing.expectEqual(0, g.grpc_status.?);
        try testing.expectEqualStrings(if (mode == .gun) "/svc/Tun" else "/svc/TunMulti", peer.path[0..peer.path_len]);
        const payload = try testing.allocator.alloc(u8, up_total);
        defer testing.allocator.free(payload);
        const up, const messages = try hunks(peer.up.items, payload);
        try testing.expectEqual(up_total, up.len);
        for (up, 0..) |b, i| if (b != upByte(i)) return error.BadUpload;
        // full buffers and the flushed rests, nothing smaller
        try testing.expect(messages >= up_total / (wbuf.len - head_room) and messages < 40);
        try testing.expectEqual(1, peer.acks);
    }
}

test "memory per call" {
    // the h2 connection and little else
    try testing.expect(@sizeOf(Conn) <= @sizeOf(h2.Conn) + 256);
}
