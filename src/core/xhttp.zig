//! XHTTP client transport (Xray's "splithttp") in stream-one mode, spoken
//! the way Xray's own client speaks it over REALITY (Xray-core v26.11.9,
//! transport/internet/splithttp): HTTP/2 with prior knowledge, since REALITY
//! negotiates no ALPN, and one POST stream per connection whose request
//! body is the upload and whose response body is the download, both raw
//! VLESS bytes. Nothing frames them: DATA frame boundaries mean nothing, and
//! no gRPC length prefix follows despite the content type.
//!
//! The server checks the path prefix, the Host if it is configured with
//! one, and the padding length in the Referer (100..1000 by default). The
//! rest of the request is what Xray adds to look like Chrome running
//! fetch(), and it goes out the same: that header set, the Chrome version
//! Xray derives from the date, its GREASE brand, a random header order.
//!
//! Threads as in h2.zig: `reader()` on one, `writer()` and `closeWrite()` on
//! another, `close()` from either. Keep reading while uploading: flow-control
//! credit arrives through the reader.
//!
//! Memory: the h2 connection (6.5 KiB) and the caller's two buffers. The
//! request head is built on the stack in `open` and not kept.

const std = @import("std");
const Io = std.Io;
const h2 = @import("h2.zig");

const Field = h2.Field;
const Allocator = std.mem.Allocator;

pub const Error = h2.Error || error{
    /// Not stream-one: packet-up, stream-up, or auto where Xray would pick
    /// one of those (without REALITY, or with downloadSettings).
    XhttpBadMode,
    /// `extra` is not a JSON object of XHTTP settings, or holds one that
    /// Xray itself refuses for stream-one (a Host header, GET, ...).
    XhttpBadExtra,
    /// The server's status was not 200: 404 for a wrong path or Host, 400
    /// for padding outside its range or a server that takes packet-up only.
    XhttpRejected,
};

pub const Options = struct {
    /// The link's `path`, percent-decoded. A `?query` in it stays on
    /// `:path`; the part before it gets the '/' Xray puts at its end.
    path: []const u8 = "",
    /// `:authority` and the host in the Referer: the link's `host`, else
    /// the REALITY or TLS server name, else the server address. Sent as
    /// given; Xray adds no port.
    host: []const u8,
    /// The link's `mode`: empty, auto, stream-one, stream-up or packet-up.
    mode: []const u8 = "",
    /// The link's `extra`, percent-decoded: a JSON object of more XHTTP
    /// settings (padding, headers, method), or empty.
    extra: []const u8 = "",
    /// The stream runs inside REALITY: only then does Xray's auto mean
    /// stream-one.
    reality: bool = true,
};

/// Whether `o` makes a request this transport can send, the same check as
/// `open` without any I/O: for links, when they are parsed.
pub fn check(o: Options) Error!void {
    var prng: std.Random.DefaultPrng = .init(0);
    var scratch: [scratch_len]u8 = undefined;
    var head: Head = .{};
    try build(o, .{ .rand = prng.random(), .now = 0, .longest = true }, &scratch, &head);
}

pub const Conn = struct {
    h2: h2.Conn,
    body_in: Io.Reader,
    /// The response status, once `reader()` has seen it.
    status: u16 = 0,
    /// Why `reader()` failed: XhttpRejected, or the h2 error.
    read_err: ?Error = null,

    /// Send the HTTP/2 preface and the request head into `out`, the stream
    /// inside TLS or REALITY, and flush it. It does not wait for the answer:
    /// as with Xray the upload may follow at once, and the status shows on
    /// the first read. `read_buffer` backs `reader()` and `write_buffer`
    /// `writer()`; either may be empty. `in` needs a buffer of at least 9
    /// bytes. The connection must stay in place afterwards.
    pub fn open(x: *Conn, io: Io, in: *Io.Reader, out: *Io.Writer, read_buffer: []u8, write_buffer: []u8, o: Options) Error!void {
        x.* = .{
            .h2 = undefined,
            .body_in = .{ .vtable = &.{ .stream = bodyStream }, .buffer = read_buffer, .seek = 0, .end = 0 },
        };
        // h2 hands the body over unbuffered; `body_in` buffers it once
        x.h2.init(io, in, out, &.{}, write_buffer, .{});
        var seed: [8]u8 = undefined;
        io.random(&seed);
        var prng: std.Random.DefaultPrng = .init(std.mem.readInt(u64, &seed, .little));
        var scratch: [scratch_len]u8 = undefined;
        var head: Head = .{};
        try build(o, .{ .rand = prng.random(), .now = Io.Clock.real.now(io).toSeconds() }, &scratch, &head);
        try x.h2.start(head.slice());
    }

    /// The download. The first read waits for the response head and fails
    /// unless it is 200 (`read_err`, `status`). Reading thread.
    pub fn reader(x: *Conn) *Io.Reader {
        return &x.body_in;
    }

    /// The upload; `flush` sends what is buffered. Failures leave their
    /// cause in `x.h2.write_err`. Writing thread.
    pub fn writer(x: *Conn) *Io.Writer {
        return x.h2.writer();
    }

    /// End the upload after what is buffered (END_STREAM). The server passes
    /// the end on to the destination and ends the download about a second
    /// later (its downlinkOnly policy). Writing thread.
    pub fn closeWrite(x: *Conn) Io.Writer.Error!void {
        return x.h2.closeWrite();
    }

    /// End the stream from any thread, as Xray's client does when the local
    /// side goes away (RST_STREAM CANCEL), and say GOAWAY, as the connection
    /// carried only this stream. Then close the transport: that wakes a
    /// reader blocked in it.
    pub fn close(x: *Conn) void {
        x.h2.close();
    }

    fn failRead(x: *Conn, e: Error) error{ReadFailed} {
        if (x.read_err == null) x.read_err = e;
        return error.ReadFailed;
    }

    fn bodyStream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const x: *Conn = @alignCast(@fieldParentPtr("body_in", r));
        if (x.read_err != null) return error.ReadFailed;
        if (x.status == 0) {
            // Xray's client takes nothing but 200; the server sends it
            // before it reads any of the body
            x.status = x.h2.response() catch |e| return x.failRead(e);
            if (x.status != 200) return x.failRead(error.XhttpRejected);
        }
        return x.h2.reader().stream(w, limit) catch |e| switch (e) {
            error.ReadFailed => x.failRead(x.h2.read_err orelse error.ReadFailed),
            else => |err| err,
        };
    }
};

// ------------------------------------------------------------ the request

/// Room for the request head while it is built: padding up to `max_padding`
/// next to a long path, user agent, brand list and the extra JSON's strings.
const scratch_len = 12 * 1024;
/// Padding beyond this cannot pass any server's header limit (8 KiB by
/// default), so a range reaching past it is refused, not truncated.
const max_padding = 8192;
/// Fields of the head: 4 pseudo-headers, 17 of Xray's, the custom ones.
const max_fields = 40;
const max_custom = 16;

const Env = struct {
    rand: std.Random,
    /// Unix seconds, for the Chrome version.
    now: i64,
    /// The longest padding of the range instead of a random one.
    longest: bool = false,
};

/// The request head being built: pseudo-headers first, then the rest.
const Head = struct {
    fields: [max_fields]Field = undefined,
    len: usize = 0,

    fn slice(h: *const Head) []const Field {
        return h.fields[0..h.len];
    }

    fn find(h: *Head, name: []const u8) ?*Field {
        for (h.fields[0..h.len]) |*f| if (std.mem.eql(u8, f.name, name)) return f;
        return null;
    }

    fn add(h: *Head, name: []const u8, value: []const u8) Error!void {
        if (h.len == max_fields) return error.HeadersTooLarge;
        h.fields[h.len] = .{ .name = name, .value = value };
        h.len += 1;
    }

    /// Go's Header.Set: this value in place of all before it.
    fn set(h: *Head, name: []const u8, value: []const u8) Error!void {
        var n: usize = 0;
        for (h.fields[0..h.len]) |f| if (!std.mem.eql(u8, f.name, name)) {
            h.fields[n] = f;
            n += 1;
        };
        h.len = n;
        try h.add(name, value);
    }

    /// Set unless a non-empty value is there (Go: `if h.Get(k) == ""`).
    fn setDefault(h: *Head, name: []const u8, value: []const u8) Error!void {
        if (h.find(name)) |f| if (f.value.len > 0) return;
        try h.set(name, value);
    }
};

const Mode = enum { auto, packet_up, stream_up, stream_one };

fn parseMode(name: []const u8) ?Mode {
    if (name.len == 0) return .auto;
    const names = [_]struct { []const u8, Mode }{
        .{ "auto", .auto },
        .{ "packet-up", .packet_up },
        .{ "stream-up", .stream_up },
        .{ "stream-one", .stream_one },
    };
    for (names) |n| if (std.mem.eql(u8, name, n[0])) return n[1];
    return null;
}

/// FillStreamRequest (config.go), GetRequestHeader and Go's HTTP/2
/// transport, in that order: custom headers, Chrome's, the padding, the
/// content type, a random order, `accept-encoding` last.
fn build(o: Options, env: Env, scratch: []u8, head: *Head) Error!void {
    var fba: std.heap.FixedBufferAllocator = .init(scratch);
    const a = fba.allocator();
    return buildIn(a, o, env, head) catch |e| switch (e) {
        error.OutOfMemory => error.HeadersTooLarge,
        else => |err| err,
    };
}

fn buildIn(a: Allocator, o: Options, env: Env, head: *Head) (Error || Allocator.Error)!void {
    const mode = parseMode(o.mode) orelse return error.XhttpBadMode;
    var e: Extra = .{};
    const json = std.mem.trim(u8, o.extra, " \t\r\n");
    if (json.len > 0 and !std.mem.eql(u8, json, "null")) parseExtra(a, json, &e) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.HeadersTooLarge => error.HeadersTooLarge,
        else => error.XhttpBadExtra,
    };
    // dialer.go: auto is stream-one over REALITY, unless the download goes
    // elsewhere (stream-up); packet-up otherwise
    const effective: Mode = if (mode != .auto) mode else if (!o.reality) .packet_up else if (e.download) .stream_up else .stream_one;
    if (effective != .stream_one) return error.XhttpBadMode;
    if (mode == .stream_one and e.download) return error.XhttpBadExtra;

    const q = std.mem.indexOfScalar(u8, o.path, '?');
    const path = try escapePath(a, o.path[0 .. q orelse o.path.len], e.slash);
    const query = if (q) |i| o.path[i + 1 ..] else "";
    const n = padLen(e, env);
    var target: []const u8 = path;
    if (query.len > 0) target = try print(a, "{s}?{s}", .{ path, query });
    if (e.obfs and e.placement == .query) {
        // Go re-encodes the query sorted by key; the server only looks the key up
        target = try padded(a, "{s}{s}{s}=", .{ target, if (query.len > 0) "&" else "?", e.key }, n);
    }

    // Go's HTTP/2 order, then the header map in random order
    try head.add(":authority", o.host);
    try head.add(":method", e.method);
    try head.add(":path", target);
    try head.add(":scheme", "https");
    for (e.headers[0..e.n_headers]) |f| try head.add(f.name, f.value);
    // browser.go: no User-Agent, or the name of a browser, means Chrome's
    // headers (other browsers' sets are not reproduced); a literal one
    // stands alone
    const ua = head.find("user-agent");
    if (ua == null or isPreset(ua.?.value)) try chromeFetch(a, head, chromeMajor(env.now));
    if (!e.obfs) {
        try head.set("referer", try padded(a, "https://{s}{s}?x_padding=", .{ o.host, path }, n));
    } else switch (e.placement) {
        .query_in_header => try head.set(e.header, try padded(a, "https://{s}{s}?{s}=", .{ o.host, path, e.key }, n)),
        .header => try head.set(e.header, try padded(a, "", .{}, n)),
        .cookie => try head.add("cookie", try padded(a, "{s}=", .{e.key}, n)),
        .query => {},
    }
    if (e.grpc) try head.set("content-type", "application/grpc");
    env.rand.shuffle(Field, head.fields[4..head.len]);
    // added by Go's transport unless the request asks for an encoding or a range
    if (head.find("accept-encoding") == null and head.find("range") == null) try head.add("accept-encoding", "gzip");
}

/// Xray's RandBetween over the padding range: [from, to), or `from` when
/// that holds a single value.
fn padLen(e: Extra, env: Env) usize {
    if (e.pad_to - e.pad_from <= 1) return e.pad_from;
    if (env.longest) return e.pad_to - 1;
    return env.rand.intRangeLessThan(u32, e.pad_from, e.pad_to);
}

/// `fmt` with `args`, sized exactly: allocPrint would grow a buffer.
fn print(a: Allocator, comptime fmt: []const u8, args: anytype) Allocator.Error![]const u8 {
    return padded(a, fmt, args, 0);
}

/// `fmt` with `args`, then `n` padding characters, as one string. 'X' has
/// an 8-bit Huffman code, so the padding is as long on the wire under any
/// HPACK encoder, and passes a server that measures "tokenish" padding by
/// its Huffman length too.
fn padded(a: Allocator, comptime fmt: []const u8, args: anytype, n: usize) Allocator.Error![]const u8 {
    const len = std.fmt.count(fmt, args);
    const s = try a.alloc(u8, len + n);
    _ = std.fmt.bufPrint(s, fmt, args) catch unreachable;
    @memset(s[len..], 'X');
    return s;
}

/// The path as Go puts it on the wire (url.URL.EscapedPath of
/// GetNormalizedPath): a '/' first, with `slash` one last as well, and
/// everything but unreserved characters and `$&+,/:;=@` percent-encoded.
fn escapePath(a: Allocator, raw: []const u8, slash: bool) Allocator.Error![]const u8 {
    const buf = try a.alloc(u8, 3 * raw.len + 2);
    var w: Io.Writer = .fixed(buf);
    if (raw.len == 0 or raw[0] != '/') w.writeByte('/') catch unreachable;
    std.Uri.Component.percentEncode(&w, raw, keepInPath) catch unreachable;
    if (slash and buf[w.end - 1] != '/') w.writeByte('/') catch unreachable;
    return w.buffered();
}

fn keepInPath(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, "-_.~$&+,/:;=@", c) != null;
}

fn isPreset(ua: []const u8) bool {
    for ([_][]const u8{ "chrome", "firefox", "safari", "edge", "curl", "golang" }) |p| {
        if (std.mem.eql(u8, ua, p)) return true;
    }
    return false;
}

/// applyMasqueradedHeaders(header, "chrome", "fetch") from browser.go.
fn chromeFetch(a: Allocator, head: *Head, v: u32) (Error || Allocator.Error)!void {
    try head.set("sec-ch-ua", try chromeBrands(a, v));
    try head.set("sec-ch-ua-mobile", "?0");
    try head.set("sec-ch-ua-platform", "\"Windows\"");
    try head.set("dnt", "1");
    try head.set("user-agent", try print(a, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{d}.0.0.0 Safari/537.36", .{v}));
    try head.set("accept-language", "en-US,en;q=0.9");
    try head.set("sec-fetch-mode", "cors");
    try head.set("sec-fetch-dest", "empty");
    try head.set("sec-fetch-site", "same-origin");
    try head.setDefault("priority", "u=1, i");
    try head.setDefault("cache-control", "no-cache");
    try head.setDefault("pragma", "no-cache");
    try head.setDefault("accept", "*/*");
}

/// Chromium's GREASEd brand list for major version `v`, which also seeds
/// it (getGreasedChUa in browser.go).
fn chromeBrands(a: Allocator, v: u32) Allocator.Error![]const u8 {
    const na = " (:-./);=?_";
    const vna = [_][]const u8{ "8", "99", "24" };
    const orders = [6][3]u2{ .{ 0, 1, 2 }, .{ 0, 2, 1 }, .{ 1, 0, 2 }, .{ 1, 2, 0 }, .{ 2, 0, 1 }, .{ 2, 1, 0 } };
    const grease = try print(a, "\"Not{c}A{c}Brand\";v=\"{s}\"", .{ na[v % na.len], na[(v + 1) % na.len], vna[v % vna.len] });
    const chromium = try print(a, "\"Chromium\";v=\"{d}\"", .{v});
    const chrome = try print(a, "\"Google Chrome\";v=\"{d}\"", .{v});
    var placed: [3][]const u8 = undefined;
    for (orders[v % orders.len], [_][]const u8{ grease, chromium, chrome }) |at, brand| placed[at] = brand;
    return print(a, "{s}, {s}, {s}", .{ placed[0], placed[1], placed[2] });
}

/// Chrome's major version as Xray derives it from the date (ChromeVersion
/// in browser.go): 144 came out on 2026-01-13, one more every 35 days,
/// each taken to reach users 35 days later. Xray adds a lag of up to 105
/// days, fixed per machine; like the other transports here we add none and
/// claim the newest, which most Chrome installations run. Below 144 only
/// for a clock that is wrong anyway.
fn chromeMajor(now: i64) u32 {
    const days = @divFloor(now, std.time.s_per_day) - 20466;
    return 144 + @as(u32, @intCast(@max(0, @divTrunc(days - 35, 35))));
}

// ------------------------------------------------------------ extra

const Placement = enum { query_in_header, header, cookie, query };

/// What of a link's `extra` (Xray's SplitHTTPConfig as JSON) shapes a
/// stream-one request, with Xray's defaults. Strings point into the JSON or
/// the scratch.
const Extra = struct {
    pad_from: u32 = 100,
    pad_to: u32 = 1000,
    /// xPaddingObfsMode: the padding goes where `placement` says
    obfs: bool = false,
    placement: Placement = .query_in_header,
    key: []const u8 = "x_padding",
    /// lowercase, as HTTP/2 wants names
    header: []const u8 = "x-padding",
    method: []const u8 = "POST",
    grpc: bool = true,
    /// The session id or the sequence number would go into the path, so it
    /// ends with '/'. Both are absent in stream-one; the slash stays.
    slash: bool = true,
    /// downloadSettings: the download comes from elsewhere (stream-up)
    download: bool = false,
    headers: [max_custom]Field = undefined,
    n_headers: usize = 0,
};

const Scanner = std.json.Scanner;

/// Read the fields of `json` that matter here, with Go's case-insensitive
/// key match; refuse what Xray's config builder refuses.
fn parseExtra(a: Allocator, json: []const u8, e: *Extra) !void {
    var s: Scanner = .initCompleteInput(a, json);
    if (try s.next() != .object_begin) return error.XhttpBadExtra;
    var session_in_path = true;
    var seq_in_path = true;
    while (true) {
        const tok = try s.nextAlloc(a, .alloc_if_needed);
        if (tok == .object_end) break;
        const key = text(tok) orelse return error.XhttpBadExtra;
        if (is(key, "headers")) {
            try parseHeaders(a, &s, e);
        } else if (is(key, "xPaddingBytes")) {
            try parsePadding(a, &s, e);
        } else if (is(key, "xPaddingObfsMode")) {
            if (try boolean(&s)) |v| e.obfs = v;
        } else if (is(key, "xPaddingKey")) {
            const v = try string(a, &s) orelse "";
            if (v.len > 0) e.key = v;
        } else if (is(key, "xPaddingHeader")) {
            const v = try string(a, &s) orelse "";
            if (v.len > 0 and !isToken(v)) return error.XhttpBadExtra;
            if (v.len > 0) e.header = try lowerName(a, v);
        } else if (is(key, "xPaddingPlacement")) {
            const v = try string(a, &s) orelse "";
            const names = [_]struct { []const u8, Placement }{
                .{ "", .query_in_header },
                .{ "queryInHeader", .query_in_header },
                .{ "header", .header },
                .{ "cookie", .cookie },
                .{ "query", .query },
            };
            e.placement = for (names) |n| {
                if (std.mem.eql(u8, v, n[0])) break n[1];
            } else return error.XhttpBadExtra;
        } else if (is(key, "xPaddingMethod")) {
            // tokenish padding is checked by its Huffman length, which our
            // X's meet as well
            const v = try string(a, &s) orelse "";
            if (!oneOf(v, &.{ "", "repeat-x", "tokenish" })) return error.XhttpBadExtra;
        } else if (is(key, "uplinkHTTPMethod")) {
            const v = try string(a, &s) orelse "";
            if (v.len > 0) {
                if (!isToken(v)) return error.XhttpBadExtra;
                const up = std.ascii.upperString(try a.alloc(u8, v.len), v);
                // GET carries no body: packet-up only
                if (std.mem.eql(u8, up, "GET")) return error.XhttpBadExtra;
                e.method = up;
            }
        } else if (is(key, "noGRPCHeader")) {
            if (try boolean(&s)) |v| e.grpc = !v;
        } else if (is(key, "sessionIDPlacement")) {
            session_in_path = try placedInPath(a, &s);
        } else if (is(key, "seqPlacement")) {
            seq_in_path = try placedInPath(a, &s);
        } else if (is(key, "uplinkDataPlacement")) {
            // cookies and headers carry data in packet-up only
            const v = try string(a, &s) orelse "";
            if (!oneOf(v, &.{ "", "auto", "body" })) return error.XhttpBadExtra;
        } else if (is(key, "downloadSettings")) {
            if (try s.peekNextTokenType() == .null) {
                _ = try s.next();
            } else {
                try s.skipValue();
                e.download = true;
            }
        } else try s.skipValue();
    }
    if (try s.next() != .end_of_document) return error.XhttpBadExtra;
    e.slash = session_in_path or seq_in_path;
}

fn is(key: []const u8, name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(key, name);
}

fn oneOf(v: []const u8, names: []const []const u8) bool {
    for (names) |n| if (std.mem.eql(u8, v, n)) return true;
    return false;
}

fn text(tok: std.json.Token) ?[]const u8 {
    return switch (tok) {
        .string => |v| v,
        .allocated_string => |v| v,
        else => null,
    };
}

/// A string value; null for JSON null, which Go leaves the field alone for.
fn string(a: Allocator, s: *Scanner) !?[]const u8 {
    const tok = try s.nextAlloc(a, .alloc_if_needed);
    if (tok == .null) return null;
    return text(tok) orelse error.XhttpBadExtra;
}

fn boolean(s: *Scanner) !?bool {
    return switch (try s.next()) {
        .true => true,
        .false => false,
        .null => null,
        else => error.XhttpBadExtra,
    };
}

fn placedInPath(a: Allocator, s: *Scanner) !bool {
    const v = try string(a, s) orelse "";
    if (!oneOf(v, &.{ "", "path", "cookie", "header", "query" })) return error.XhttpBadExtra;
    return v.len == 0 or std.mem.eql(u8, v, "path");
}

/// xPaddingBytes (Int32Range): a number, or a string "n" or "from-to", in
/// either order; 0 means the default, anything else must be positive.
fn parsePadding(a: Allocator, s: *Scanner, e: *Extra) !void {
    const tok = try s.nextAlloc(a, .alloc_if_needed);
    const r: [2]i64 = switch (tok) {
        .number => |v| .{ try std.fmt.parseInt(i32, v, 10), try std.fmt.parseInt(i32, v, 10) },
        .allocated_number => |v| .{ try std.fmt.parseInt(i32, v, 10), try std.fmt.parseInt(i32, v, 10) },
        .null => .{ 0, 0 },
        else => try parseRange(text(tok) orelse return error.XhttpBadExtra),
    };
    const from = @min(r[0], r[1]);
    const to = @max(r[0], r[1]);
    if (from == 0 and to == 0) return;
    if (from <= 0 or to > max_padding) return error.XhttpBadExtra;
    e.pad_from = @intCast(from);
    e.pad_to = @intCast(to);
}

/// ParseRangeString (infra/conf/common.go): "n", "from-to", "" for 0, with
/// a sign allowed on each number.
fn parseRange(v: []const u8) ![2]i64 {
    if (v.len == 0) return .{ 0, 0 };
    if (std.fmt.parseInt(i32, v, 10)) |n| return .{ n, n } else |_| {}
    // the dash between the numbers is the second one when the first is a sign
    const dash = std.mem.indexOfScalarPos(u8, v, @intFromBool(v[0] == '-'), '-') orelse return error.XhttpBadExtra;
    return .{ try std.fmt.parseInt(i32, v[0..dash], 10), try std.fmt.parseInt(i32, v[dash + 1 ..], 10) };
}

/// headers: an object of strings. Names become lowercase; Host is refused
/// as Xray refuses it, and fields HTTP/2 forbids are left out as Go does.
fn parseHeaders(a: Allocator, s: *Scanner, e: *Extra) !void {
    switch (try s.next()) {
        .null => return,
        .object_begin => {},
        else => return error.XhttpBadExtra,
    }
    while (true) {
        const tok = try s.nextAlloc(a, .alloc_if_needed);
        if (tok == .object_end) return;
        const raw = text(tok) orelse return error.XhttpBadExtra;
        const value = try string(a, s) orelse return error.XhttpBadExtra;
        if (!isToken(raw)) return error.XhttpBadExtra;
        for (value) |c| if ((c < 0x20 and c != '\t') or c == 0x7f) return error.XhttpBadExtra;
        const name = try lowerName(a, raw);
        if (std.mem.eql(u8, name, "host")) return error.XhttpBadExtra;
        if (oneOf(name, &.{ "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "content-length" })) continue;
        if (std.mem.eql(u8, name, "te") and !std.mem.eql(u8, value, "trailers")) continue;
        if (e.n_headers == max_custom) return error.HeadersTooLarge;
        e.headers[e.n_headers] = .{ .name = name, .value = value };
        e.n_headers += 1;
    }
}

fn lowerName(a: Allocator, name: []const u8) Allocator.Error![]const u8 {
    return std.ascii.lowerString(try a.alloc(u8, name.len), name);
}

/// An HTTP token (RFC 9110 5.6.2): header names and methods.
fn isToken(v: []const u8) bool {
    if (v.len == 0) return false;
    for (v) |c| {
        if (!std.ascii.isAlphanumeric(c) and std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", c) == null) return false;
    }
    return true;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

const hpack = @import("hpack.zig");

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
// frame types and flags (RFC 9113 6)
const t_data = 0x0;
const t_headers = 0x1;
const t_rst_stream = 0x3;
const t_settings = 0x4;
const t_ping = 0x6;
const t_goaway = 0x7;
const t_window_update = 0x8;
const end_stream = 0x1;
const ack = 0x1;
const end_headers = 0x4;

fn frame(w: *Io.Writer, t: u8, flags: u8, stream: u32, payload: []const u8) !void {
    var h: [9]u8 = undefined;
    std.mem.writeInt(u24, h[0..3], @intCast(payload.len), .big);
    h[3] = t;
    h[4] = flags;
    std.mem.writeInt(u32, h[5..9], stream, .big);
    try w.writeAll(&h);
    try w.writeAll(payload);
}

fn u32Frame(w: *Io.Writer, t: u8, stream: u32, v: u32) !void {
    var p: [4]u8 = undefined;
    std.mem.writeInt(u32, &p, v, .big);
    try frame(w, t, 0, stream, &p);
}

fn settingsFrame(w: *Io.Writer, pairs: []const [2]u32) !void {
    var p: [64]u8 = undefined;
    for (pairs, 0..) |pair, i| {
        std.mem.writeInt(u16, p[i * 6 ..][0..2], @intCast(pair[0]), .big);
        std.mem.writeInt(u32, p[i * 6 + 2 ..][0..4], pair[1], .big);
    }
    try frame(w, t_settings, 0, 0, p[0 .. pairs.len * 6]);
}

/// A header block of `fields`, after `first` raw bytes (an indexed field).
fn headBlock(buf: []u8, first: []const u8, fields: []const Field) []const u8 {
    var w: Io.Writer = .fixed(buf);
    w.writeAll(first) catch unreachable;
    for (fields) |f| hpack.writeField(&w, f) catch unreachable;
    return w.buffered();
}

const Sent = struct { type: u8, flags: u8, stream: u32, payload: []const u8 };

/// The frames a client wrote, after the preface.
fn sentFrames(out: []const u8, list: []Sent) ![]Sent {
    try testing.expectStringStartsWith(out, preface);
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

/// A header block as the server decodes it.
const Decoded = struct {
    buf: [16 * 1024]u8 = undefined,
    fields: [64]Field = undefined,
    list: hpack.List = undefined,
    dec: hpack.Decoder(4096) = .{},

    fn decode(d: *Decoded, block: []const u8) ![]const Field {
        d.list = .init(&d.buf, &d.fields);
        var src: Io.Reader = .fixed(block);
        try d.dec.decode(&src, &d.list);
        try testing.expectEqual(0, d.list.dropped);
        return d.list.slice();
    }
};

/// 2026-11-14T05:25:50Z, when Xray was captured sending Chrome 151.
const capture_time = 1794633950;

/// The head `build` makes, with randomness from `seed`.
const Built = struct {
    scratch: [scratch_len]u8 = undefined,
    head: Head = .{},

    fn of(b: *Built, o: Options, seed: u64) Error![]const Field {
        var prng: std.Random.DefaultPrng = .init(seed);
        b.head = .{};
        try build(o, .{ .rand = prng.random(), .now = capture_time }, &b.scratch, &b.head);
        return b.head.slice();
    }
};

fn get(fields: []const Field, name: []const u8) ?[]const u8 {
    for (fields) |f| if (std.mem.eql(u8, f.name, name)) return f.value;
    return null;
}

fn count(fields: []const Field, name: []const u8) usize {
    var n: usize = 0;
    for (fields) |f| n += @intFromBool(std.mem.eql(u8, f.name, name));
    return n;
}

/// `prefix`, then only X's, between `lo` and `hi` of them.
fn expectPadded(value: ?[]const u8, prefix: []const u8, lo: usize, hi: usize) !void {
    const v = value orelse return error.TestExpectedPadding;
    try testing.expectStringStartsWith(v, prefix);
    const pad = v[prefix.len..];
    for (pad) |c| try testing.expectEqual('X', c);
    if (pad.len < lo or pad.len > hi) {
        std.debug.print("padding of {d}, not {d}..{d}\n", .{ pad.len, lo, hi });
        return error.TestUnexpectedPadding;
    }
}

/// What Xray 26.11.9 sent in the capture, Chrome version aside: Go's
/// pseudo-header order, Chrome's fetch() headers in some order, the
/// padding, the content type, accept-encoding last.
fn expectXrayHead(fields: []const Field, host: []const u8, path: []const u8) !void {
    try testing.expectEqualStrings(":authority", fields[0].name);
    try testing.expectEqualStrings(host, fields[0].value);
    try testing.expectEqualStrings(":method", fields[1].name);
    try testing.expectEqualStrings("POST", fields[1].value);
    try testing.expectEqualStrings(":path", fields[2].name);
    try testing.expectEqualStrings(path, fields[2].value);
    try testing.expectEqualStrings(":scheme", fields[3].name);
    try testing.expectEqualStrings("https", fields[3].value);
    const last = fields[fields.len - 1];
    try testing.expectEqualStrings("accept-encoding", last.name);
    try testing.expectEqualStrings("gzip", last.value);
    const fixed = [_][2][]const u8{
        .{ "sec-ch-ua-mobile", "?0" },
        .{ "sec-ch-ua-platform", "\"Windows\"" },
        .{ "dnt", "1" },
        .{ "accept-language", "en-US,en;q=0.9" },
        .{ "sec-fetch-mode", "cors" },
        .{ "sec-fetch-dest", "empty" },
        .{ "sec-fetch-site", "same-origin" },
        .{ "priority", "u=1, i" },
        .{ "cache-control", "no-cache" },
        .{ "pragma", "no-cache" },
        .{ "accept", "*/*" },
        .{ "content-type", "application/grpc" },
    };
    for (fixed) |f| {
        try testing.expectEqual(1, count(fields, f[0]));
        try testing.expectEqualStrings(f[1], get(fields, f[0]).?);
    }
    // the Chrome version agrees between user agent and brands
    const ua = get(fields, "user-agent").?;
    const ua_head = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/";
    try testing.expectStringStartsWith(ua, ua_head);
    try testing.expectStringEndsWith(ua, ".0.0.0 Safari/537.36");
    const v = ua[ua_head.len..std.mem.indexOfScalarPos(u8, ua, ua_head.len, '.').?];
    var want: [64]u8 = undefined;
    const brands = get(fields, "sec-ch-ua").?;
    try testing.expect(std.mem.indexOf(u8, brands, try std.fmt.bufPrint(&want, "\"Chromium\";v=\"{s}\"", .{v})) != null);
    try testing.expect(std.mem.indexOf(u8, brands, try std.fmt.bufPrint(&want, "\"Google Chrome\";v=\"{s}\"", .{v})) != null);
    var referer: [512]u8 = undefined;
    try expectPadded(get(fields, "referer"), try std.fmt.bufPrint(&referer, "https://{s}{s}?x_padding=", .{ host, path }), 100, 999);
    // nothing else, nothing twice
    try testing.expectEqual(4 + fixed.len + 4, fields.len);
    for (fields, 0..) |f, i| {
        try testing.expectEqual(1, count(fields, f.name));
        for (f.name) |c| try testing.expect(!std.ascii.isUpper(c));
        try testing.expectEqual(i < 4, f.name[0] == ':');
    }
}

test "build: Xray's stream-one request, headers in a random order" {
    var b: Built = .{};
    var first: [max_fields][]const u8 = undefined;
    var orders: usize = 0;
    for (0..20) |seed| {
        const fields = try b.of(.{ .host = "www.example.com", .path = "/xhttp" }, seed);
        try expectXrayHead(fields, "www.example.com", "/xhttp/");
        try testing.expectEqualStrings("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36", get(fields, "user-agent").?);
        if (seed == 0) {
            for (fields, 0..) |f, i| first[i] = f.name;
        } else for (fields, 0..) |f, i| {
            if (!std.mem.eql(u8, first[i], f.name)) {
                orders += 1;
                break;
            }
        }
    }
    try testing.expect(orders > 10);
}

test "open: the preface, then one HEADERS frame the server decodes to that request" {
    var in: Io.Reader = .fixed("");
    var out_buf: [8192]u8 = undefined;
    var out: Io.Writer = .fixed(&out_buf);
    var x: Conn = undefined;
    try x.open(testing.io, &in, &out, &.{}, &.{}, .{ .host = "www.example.com", .path = "/xhttp" });
    var list: [8]Sent = undefined;
    const f = try sentFrames(out.buffered(), &list);
    try testing.expectEqual(3, f.len);
    try testing.expectEqual(t_settings, f[0].type);
    try testing.expectEqual(t_window_update, f[1].type);
    try testing.expectEqual(t_headers, f[2].type);
    // END_HEADERS without END_STREAM: the body follows
    try testing.expectEqual(end_headers, f[2].flags);
    try testing.expectEqual(1, f[2].stream);
    var d: Decoded = .{};
    try expectXrayHead(try d.decode(f[2].payload), "www.example.com", "/xhttp/");
    // the transport ends before the server's preface
    var b: [8]u8 = undefined;
    try testing.expectError(error.ReadFailed, x.reader().readSliceShort(&b));
    try testing.expectEqual(error.ConnectionClosed, x.read_err.?);
}

test "the Chrome version and brands follow Xray's calendar" {
    // captured: Chrome 151, `"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`
    try testing.expectEqual(151, chromeMajor(capture_time));
    try testing.expectEqual(144, chromeMajor(20466 * 86400)); // 2026-01-13
    try testing.expectEqual(144, chromeMajor((20466 + 69) * 86400 + 86399));
    try testing.expectEqual(145, chromeMajor((20466 + 70) * 86400));
    try testing.expectEqual(144, chromeMajor(0)); // a clock that is off
    var buf: [512]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    try testing.expectEqualStrings("\"Not=A?Brand\";v=\"99\", \"Google Chrome\";v=\"151\", \"Chromium\";v=\"151\"", try chromeBrands(fba.allocator(), 151));
    try testing.expectEqualStrings("\"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"144\", \"Google Chrome\";v=\"144\"", try chromeBrands(fba.allocator(), 144));
}

test "path: Xray's trailing slash, Go's escaping, the query kept off the Referer" {
    const cases = [_]struct { path: []const u8, extra: []const u8 = "", want: []const u8, referer: []const u8 }{
        .{ .path = "", .want = "/", .referer = "https://h/?x_padding=" },
        .{ .path = "/", .want = "/", .referer = "https://h/?x_padding=" },
        .{ .path = "/xhttp", .want = "/xhttp/", .referer = "https://h/xhttp/?x_padding=" },
        .{ .path = "/xhttp/", .want = "/xhttp/", .referer = "https://h/xhttp/?x_padding=" },
        .{ .path = "xhttp", .want = "/xhttp/", .referer = "https://h/xhttp/?x_padding=" },
        .{ .path = "/xhttp?ed=2560", .want = "/xhttp/?ed=2560", .referer = "https://h/xhttp/?x_padding=" },
        .{ .path = "/p?", .want = "/p/", .referer = "https://h/p/?x_padding=" },
        .{ .path = "/a?b?c", .want = "/a/?b?c", .referer = "https://h/a/?x_padding=" },
        .{ .path = "/a b/\xc3\xbc!", .want = "/a%20b/%C3%BC%21/", .referer = "https://h/a%20b/%C3%BC%21/?x_padding=" },
        .{ .path = "/$&+,:;=@-_.~%", .want = "/$&+,:;=@-_.~%25/", .referer = "https://h/$&+,:;=@-_.~%25/?x_padding=" },
        // neither a session id nor a sequence number would go into the path
        .{ .path = "/xhttp", .extra = "{\"sessionIDPlacement\":\"query\",\"seqPlacement\":\"header\"}", .want = "/xhttp", .referer = "https://h/xhttp?x_padding=" },
        .{ .path = "/xhttp", .extra = "{\"sessionIDPlacement\":\"cookie\"}", .want = "/xhttp/", .referer = "https://h/xhttp/?x_padding=" },
    };
    var b: Built = .{};
    for (cases) |c| {
        const fields = try b.of(.{ .host = "h", .path = c.path, .extra = c.extra }, 1);
        try testing.expectEqualStrings(c.want, get(fields, ":path").?);
        try expectPadded(get(fields, "referer"), c.referer, 100, 999);
    }
}

test "padding: Xray's ranges, as a number or a string" {
    var b: Built = .{};
    var lo: usize = 1000;
    var hi: usize = 0;
    for (0..3000) |seed| {
        const ref = get(try b.of(.{ .host = "h", .path = "/x" }, seed), "referer").?;
        const n = ref.len - "https://h/x/?x_padding=".len;
        lo = @min(lo, n);
        hi = @max(hi, n);
    }
    // RandBetween(100, 1000): 100 to 999
    try testing.expect(lo >= 100 and lo < 105);
    try testing.expect(hi <= 999 and hi > 994);

    const cases = [_]struct { extra: []const u8, lo: usize, hi: usize }{
        .{ .extra = "{\"xPaddingBytes\":\"500\"}", .lo = 500, .hi = 500 },
        .{ .extra = "{\"xPaddingBytes\":300}", .lo = 300, .hi = 300 },
        .{ .extra = "{\"xPaddingBytes\":\"100-101\"}", .lo = 100, .hi = 100 },
        .{ .extra = "{\"xPaddingBytes\":\"200-300\"}", .lo = 200, .hi = 299 },
        .{ .extra = "{\"xPaddingBytes\":\"1000-100\"}", .lo = 100, .hi = 999 },
        .{ .extra = "{\"xPaddingBytes\":\"+5-10\"}", .lo = 5, .hi = 9 },
        .{ .extra = "{\"xPaddingBytes\":\"0\"}", .lo = 100, .hi = 999 },
        .{ .extra = "{\"xPaddingBytes\":\"\"}", .lo = 100, .hi = 999 },
        .{ .extra = "{\"xPaddingBytes\":null}", .lo = 100, .hi = 999 },
        .{ .extra = "{\"XPADDINGBYTES\":\"7000-8192\"}", .lo = 7000, .hi = 8191 },
    };
    for (cases) |c| for (0..50) |seed| {
        try expectPadded(get(try b.of(.{ .host = "h", .path = "/x", .extra = c.extra }, seed), "referer"), "https://h/x/?x_padding=", c.lo, c.hi);
    };
    for ([_][]const u8{
        "{\"xPaddingBytes\":\"0-100\"}",
        "{\"xPaddingBytes\":\"-5\"}",
        "{\"xPaddingBytes\":-5}",
        "{\"xPaddingBytes\":\"-5-10\"}",
        "{\"xPaddingBytes\":\"abc\"}",
        "{\"xPaddingBytes\":\"100-\"}",
        "{\"xPaddingBytes\":\"5-a\"}",
        "{\"xPaddingBytes\":1.5}",
        "{\"xPaddingBytes\":true}",
        "{\"xPaddingBytes\":\"9000-10000\"}",
    }) |extra| try testing.expectError(error.XhttpBadExtra, check(.{ .host = "h", .extra = extra }));
    // the longest padding still fits beside a long path that escapes to thrice its length
    const long: [400]u8 = @splat(0xc3);
    try check(.{ .host = "h", .path = "/" ++ long, .extra = "{\"xPaddingBytes\":\"8000-8192\"}" });
}

test "obfs mode puts the padding where the server then looks" {
    var b: Built = .{};
    var f = try b.of(.{ .host = "h", .path = "/x", .extra = "{\"xPaddingObfsMode\":true}" }, 3);
    try testing.expectEqual(null, get(f, "referer"));
    try expectPadded(get(f, "x-padding"), "https://h/x/?x_padding=", 100, 999);

    f = try b.of(.{ .host = "h", .path = "/x", .extra = "{\"xPaddingObfsMode\":true,\"xPaddingPlacement\":\"header\",\"xPaddingHeader\":\"X-Pad\"}" }, 3);
    try expectPadded(get(f, "x-pad"), "", 100, 999);
    try testing.expectEqual(null, get(f, "referer"));

    f = try b.of(.{ .host = "h", .path = "/x", .extra = "{\"xPaddingObfsMode\":true,\"xPaddingPlacement\":\"cookie\",\"xPaddingKey\":\"pk\",\"xPaddingMethod\":\"tokenish\"}" }, 3);
    try expectPadded(get(f, "cookie"), "pk=", 100, 999);

    f = try b.of(.{ .host = "h", .path = "/x", .extra = "{\"xPaddingObfsMode\":true,\"xPaddingPlacement\":\"query\",\"xPaddingKey\":\"pq\"}" }, 3);
    try expectPadded(get(f, ":path"), "/x/?pq=", 100, 999);
    f = try b.of(.{ .host = "h", .path = "/x?ed=1", .extra = "{\"xPaddingObfsMode\":true,\"xPaddingPlacement\":\"query\"}" }, 3);
    try expectPadded(get(f, ":path"), "/x/?ed=1&x_padding=", 100, 999);

    // without obfs mode the placement settings are checked, then ignored
    f = try b.of(.{ .host = "h", .path = "/x", .extra = "{\"xPaddingObfsMode\":false,\"xPaddingPlacement\":\"header\"}" }, 3);
    try expectPadded(get(f, "referer"), "https://h/x/?x_padding=", 100, 999);
    try testing.expectError(error.XhttpBadExtra, check(.{ .host = "h", .extra = "{\"xPaddingPlacement\":\"body\"}" }));
    try testing.expectError(error.XhttpBadExtra, check(.{ .host = "h", .extra = "{\"xPaddingMethod\":\"random\"}" }));
}

test "extra: custom headers, method and content type, applied as Xray applies them" {
    var b: Built = .{};
    // a literal user agent stands alone, without Chrome's other headers
    var f = try b.of(.{ .host = "h", .path = "/x", .extra = "{\"headers\":{\"User-Agent\":\"MyAgent/1.0\",\"X-Thing\":\"v\\u0041\"}}" }, 4);
    try testing.expectEqualStrings("MyAgent/1.0", get(f, "user-agent").?);
    try testing.expectEqualStrings("vA", get(f, "x-thing").?);
    try testing.expectEqual(null, get(f, "sec-ch-ua"));
    try testing.expectEqual(null, get(f, "sec-fetch-mode"));
    try testing.expectEqualStrings("application/grpc", get(f, "content-type").?);
    try testing.expectEqualStrings("accept-encoding", f[f.len - 1].name);

    // Chrome's set fills in around custom values: some it keeps, some it overrides
    f = try b.of(.{ .host = "h", .path = "/x", .extra = "{\"headers\":{\"Priority\":\"u=0\",\"Accept\":\"a/b\",\"Sec-Fetch-Mode\":\"navigate\",\"User-Agent\":\"chrome\"}}" }, 4);
    try testing.expectEqualStrings("u=0", get(f, "priority").?);
    try testing.expectEqualStrings("a/b", get(f, "accept").?);
    try testing.expectEqualStrings("cors", get(f, "sec-fetch-mode").?);
    try testing.expectStringStartsWith(get(f, "user-agent").?, "Mozilla/5.0 ");
    try testing.expectEqual(1, count(f, "sec-fetch-mode"));

    // the request's own encoding; the gRPC content type over a custom one
    f = try b.of(.{ .host = "h", .path = "/x", .extra = "{\"headers\":{\"Accept-Encoding\":\"br\",\"Content-Type\":\"text/plain\"}}" }, 4);
    try testing.expectEqual(1, count(f, "accept-encoding"));
    try testing.expectEqualStrings("br", get(f, "accept-encoding").?);
    try testing.expectEqual(1, count(f, "content-type"));
    try testing.expectEqualStrings("application/grpc", get(f, "content-type").?);
    f = try b.of(.{ .host = "h", .path = "/x", .extra = "{\"headers\":{\"Content-Type\":\"text/plain\"},\"noGRPCHeader\":true}" }, 4);
    try testing.expectEqualStrings("text/plain", get(f, "content-type").?);
    f = try b.of(.{ .host = "h", .path = "/x", .extra = "{\"NoGrpcHeader\":true}" }, 4);
    try testing.expectEqual(null, get(f, "content-type"));

    // the method, and fields HTTP/2 forbids left out as Go leaves them out
    f = try b.of(.{ .host = "h", .path = "/x", .extra = "{\"uplinkHTTPMethod\":\"put\",\"headers\":{\"Connection\":\"keep-alive\",\"TE\":\"gzip\",\"Content-Length\":\"5\"}}" }, 4);
    try testing.expectEqualStrings("PUT", get(f, ":method").?);
    for ([_][]const u8{ "connection", "te", "content-length" }) |name| try testing.expectEqual(null, get(f, name));

    // settings that matter elsewhere are skipped, whatever their shape
    f = try b.of(.{ .host = "h", .path = "/x", .extra = " {\"xmux\":{\"maxConcurrency\":\"4\"},\"scMaxEachPostBytes\":1000000,\"path\":\"/other\",\"mode\":\"packet-up\",\"x\":[1,{\"a\":null}],\"headers\":null} " }, 4);
    try expectXrayHead(f, "h", "/x/");

    for ([_][]const u8{
        "{\"headers\":{\"Host\":\"x\"}}",
        "{\"headers\":{\"host\":\"x\"}}",
        "{\"headers\":{\"Bad Name\":\"v\"}}",
        "{\"headers\":{\"X\":\"a\\r\\nb\"}}",
        "{\"headers\":{\"X\":1}}",
        "{\"headers\":[]}",
        "{\"uplinkHTTPMethod\":\"get\"}",
        "{\"uplinkHTTPMethod\":\"P OST\"}",
        "{\"uplinkDataPlacement\":\"header\"}",
        "{\"noGRPCHeader\":\"yes\"}",
        "{\"xPaddingKey\":5}",
        "{\"sessionIDPlacement\":\"body\"}",
        "{\"xPaddingHeader\":\"X Pad\"}",
    }) |extra| try testing.expectError(error.XhttpBadExtra, check(.{ .host = "h", .extra = extra }));

    var many: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&many);
    try w.writeAll("{\"headers\":{");
    for (0..max_custom + 1) |i| try w.print("{s}\"X-{d}\":\"v\"", .{ if (i > 0) "," else "", i });
    try w.writeAll("}}");
    try testing.expectError(error.HeadersTooLarge, check(.{ .host = "h", .extra = w.buffered() }));
}

test "modes: stream-one, or auto over REALITY" {
    try check(.{ .host = "h" });
    try check(.{ .host = "h", .mode = "auto" });
    try check(.{ .host = "h", .mode = "stream-one" });
    try check(.{ .host = "h", .mode = "stream-one", .reality = false });
    for ([_]Options{
        .{ .host = "h", .reality = false },
        .{ .host = "h", .mode = "auto", .reality = false },
        .{ .host = "h", .mode = "packet-up" },
        .{ .host = "h", .mode = "stream-up" },
        .{ .host = "h", .mode = "Stream-One" },
        .{ .host = "h", .mode = "one" },
        // the download comes from elsewhere: stream-up
        .{ .host = "h", .extra = "{\"downloadSettings\":{\"address\":\"d\"}}" },
    }) |o| try testing.expectError(error.XhttpBadMode, check(o));
    // ... which Xray refuses to combine with stream-one
    try testing.expectError(error.XhttpBadExtra, check(.{ .host = "h", .mode = "stream-one", .extra = "{\"downloadSettings\":{}}" }));
    try check(.{ .host = "h", .extra = "{\"downloadSettings\":null}" });
    for ([_][]const u8{ "", " ", "null", "{}" }) |extra| try check(.{ .host = "h", .extra = extra });
    for ([_][]const u8{ "[]", "{", "{} x", "{\"a\"}", "1" }) |extra| try testing.expectError(error.XhttpBadExtra, check(.{ .host = "h", .extra = extra }));
}

/// A client over a scripted server: `script` is all the server says, `out`
/// collects what the client says.
const Scripted = struct {
    in: Io.Reader,
    out: Io.Writer,
    x: Conn,
    rbuf: [64]u8 = undefined,
    wbuf: [32]u8 = undefined,

    fn open(s: *Scripted, script: []const u8, out: []u8) !void {
        s.in = .fixed(script);
        s.out = .fixed(out);
        try s.x.open(testing.io, &s.in, &s.out, &s.rbuf, &s.wbuf, .{ .host = "www.example.com", .path = "/xhttp" });
    }

    /// The frames the client sent after its request head.
    fn replies(s: *Scripted, list: []Sent) ![]Sent {
        const all = try sentFrames(s.out.buffered(), list);
        try testing.expectEqual(t_headers, all[2].type);
        return all[3..];
    }
};

/// What Xray's server sends first (the capture): its SETTINGS, the ack of
/// ours, a connection window of 1 MiB.
fn serverPreface(w: *Io.Writer) !void {
    try settingsFrame(w, &.{ .{ 0x5, 1 << 20 }, .{ 0x3, 250 }, .{ 0x6, 8512 }, .{ 0x1, 4096 }, .{ 0x4, 1 << 20 }, .{ 0x9, 1 } });
    try frame(w, t_settings, ack, 0, "");
    try u32Frame(w, t_window_update, 0, 983041);
}

test "stream-one over a scripted server: raw VLESS bytes both ways" {
    var sb: [4096]u8 = undefined;
    var sw: Io.Writer = .fixed(&sb);
    try serverPreface(&sw);
    // the 200 comes as soon as the server has the head, before any body
    var hb: [1024]u8 = undefined;
    const x_padding: [549]u8 = @splat('X');
    try frame(&sw, t_headers, end_headers, 1, headBlock(&hb, &.{0x88}, &.{
        .{ .name = "access-control-allow-origin", .value = "*" },
        .{ .name = "cache-control", .value = "no-store" },
        .{ .name = "content-type", .value = "text/event-stream" },
        .{ .name = "x-accel-buffering", .value = "no" },
        .{ .name = "x-padding", .value = &x_padding },
        .{ .name = "date", .value = "Sat, 14 Nov 2026 05:25:50 GMT" },
    }));
    // the VLESS response header 00 00 rides with the first payload
    try frame(&sw, t_data, 0, 1, "\x00\x00HTTP/1.0 200 OK\r\n\r\n");
    try frame(&sw, t_data, 0, 1, "hello\n");
    // the destination closed: an empty END_STREAM, then the reset of our half
    try frame(&sw, t_data, end_stream, 1, "");
    try u32Frame(&sw, t_rst_stream, 1, 0);

    var out: [4096]u8 = undefined;
    var s: Scripted = undefined;
    try s.open(sw.buffered(), &out);
    const x = &s.x;

    // the VLESS request header and the first payload, as a proxy writes them
    const vless_head = "\x00" ++ "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x00\x01\x96\x4a\x01\x7f\x00\x00\x01";
    const payload = "GET /small.txt HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    try x.writer().writeAll(vless_head);
    try x.writer().writeAll(payload);
    try x.writer().flush();
    try x.closeWrite();

    // read as the proxy's pump does
    var got: [256]u8 = undefined;
    var n: usize = 0;
    while (x.reader().peekGreedy(1)) |chunk| {
        @memcpy(got[n..][0..chunk.len], chunk);
        n += chunk.len;
        x.reader().toss(chunk.len);
    } else |e| try testing.expectEqual(error.EndOfStream, e);
    try testing.expectEqualStrings("\x00\x00HTTP/1.0 200 OK\r\n\r\nhello\n", got[0..n]);
    try testing.expectEqual(200, x.status);
    try testing.expectEqual(null, x.read_err);

    // the upload went out as plain DATA on stream 1, no gRPC prefix, then
    // END_STREAM; reading acknowledged the server's SETTINGS
    var list: [16]Sent = undefined;
    var up: [256]u8 = undefined;
    var up_len: usize = 0;
    var ended = false;
    var acked = false;
    for (try s.replies(&list)) |f| switch (f.type) {
        t_data => {
            try testing.expectEqual(1, f.stream);
            try testing.expect(!ended);
            @memcpy(up[up_len..][0..f.payload.len], f.payload);
            up_len += f.payload.len;
            ended = f.flags & end_stream != 0;
        },
        t_settings => acked = f.flags == ack,
        else => return error.TestUnexpectedFrame,
    };
    try testing.expect(ended and acked);
    try testing.expectEqualStrings(vless_head ++ payload, up[0..up_len]);
}

test "a 404 or 400 fails the download; the stream's own failures pass through" {
    var hb: [64]u8 = undefined;
    for ([_]u16{ 404, 400 }) |code| {
        var sb: [512]u8 = undefined;
        var sw: Io.Writer = .fixed(&sb);
        try serverPreface(&sw);
        var status: [3]u8 = undefined;
        _ = try std.fmt.bufPrint(&status, "{d}", .{code});
        try frame(&sw, t_headers, end_headers | end_stream, 1, headBlock(&hb, "", &.{
            .{ .name = ":status", .value = &status },
            .{ .name = "content-length", .value = "0" },
        }));
        try u32Frame(&sw, t_rst_stream, 1, 0);
        var out: [2048]u8 = undefined;
        var s: Scripted = undefined;
        try s.open(sw.buffered(), &out);
        var b: [8]u8 = undefined;
        try testing.expectError(error.ReadFailed, s.x.reader().readSliceShort(&b));
        try testing.expectEqual(error.XhttpRejected, s.x.read_err.?);
        try testing.expectEqual(code, s.x.status);
        // and stays failed
        try testing.expectError(error.ReadFailed, s.x.reader().readSliceShort(&b));
    }

    // a reset before the head, and a reset in the middle of the body
    for (0..2) |case| {
        var sb: [512]u8 = undefined;
        var sw: Io.Writer = .fixed(&sb);
        try serverPreface(&sw);
        if (case == 1) {
            try frame(&sw, t_headers, end_headers, 1, &.{0x88});
            try frame(&sw, t_data, 0, 1, "\x00\x00abc");
        }
        try u32Frame(&sw, t_rst_stream, 1, 2);
        var out: [2048]u8 = undefined;
        var s: Scripted = undefined;
        try s.open(sw.buffered(), &out);
        var b: [16]u8 = undefined;
        var sink: Io.Writer = .fixed(&b);
        try testing.expectError(error.ReadFailed, s.x.reader().streamRemaining(&sink));
        try testing.expectEqual(error.StreamReset, s.x.read_err.?);
        try testing.expectEqual(2, s.x.h2.peer_code.?);
        try testing.expectEqualStrings(if (case == 1) "\x00\x00abc" else "", sink.buffered());
    }
}

test "close resets the stream and says GOAWAY; the writer stops" {
    var sb: [256]u8 = undefined;
    var sw: Io.Writer = .fixed(&sb);
    try serverPreface(&sw);
    var out: [2048]u8 = undefined;
    var s: Scripted = undefined;
    try s.open(sw.buffered(), &out);
    try s.x.writer().writeAll("\x00abc");
    try s.x.writer().flush();
    s.x.close();
    var list: [8]Sent = undefined;
    const f = try s.replies(&list);
    try testing.expectEqual(3, f.len);
    try testing.expectEqual(t_data, f[0].type);
    try testing.expectEqual(t_rst_stream, f[1].type);
    try testing.expectEqual(1, f[1].stream);
    try testing.expectEqual(0x8, std.mem.readInt(u32, f[1].payload[0..4], .big)); // CANCEL
    try testing.expectEqual(t_goaway, f[2].type);
    try testing.expectEqual(0, std.mem.readInt(u32, f[2].payload[4..8], .big)); // NO_ERROR
    s.x.writer().writeAll("more") catch {};
    try testing.expectError(error.WriteFailed, s.x.writer().flush());
    try testing.expectEqual(error.Closed, s.x.h2.write_err.?);
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

/// An XHTTP server that sends the upload back. Like a real one it reads
/// and writes on separate threads, and the reading thread never writes, so
/// it never stops reading because the client is not reading just then.
const EchoPeer = struct {
    io: Io,
    from: *Io.Reader,
    to: *Io.Writer,
    /// what the client uploaded, to be sent back
    echo: []u8,

    mutex: Io.Mutex = .init,
    cond: Io.Condition = .init,
    // from the reading thread to the writing one
    head_ok: bool = false,
    got: usize = 0,
    credit: u32 = 0,
    up_done: bool = false,
    stop: bool = false,
    err: ?anyerror = null,

    /// Stop; the writing thread tells the client with a GOAWAY, so that a
    /// broken test fails rather than hangs.
    fn fail(p: *EchoPeer, e: anyerror) void {
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        if (p.err == null) p.err = e;
        p.stop = true;
        p.cond.broadcast(p.io);
    }

    fn run(p: *EchoPeer) void {
        const writer_thread = std.Thread.spawn(.{}, writeLoop, .{p}) catch |e| return p.fail(e);
        p.read() catch |e| p.fail(e);
        writer_thread.join();
    }

    fn read(p: *EchoPeer) !void {
        if (!std.mem.eql(u8, try p.from.takeArray(preface.len), preface)) return error.BadPreface;
        var buf: [16384]u8 = undefined;
        var d: Decoded = .{};
        while (true) {
            const h = (try p.from.takeArray(9)).*;
            const len = std.mem.readInt(u24, h[0..3], .big);
            if (h[3] == t_data) {
                // up to the 1 MiB frames our SETTINGS allow, straight into
                // `echo`: only bytes below `got` are the writer's
                if (!p.head_ok or p.got + len > p.echo.len) return error.UnexpectedData;
                try p.from.readSliceAll(p.echo[p.got..][0..len]);
                p.mutex.lockUncancelable(p.io);
                defer p.mutex.unlock(p.io);
                p.got += len;
                p.credit += len;
                p.up_done = h[4] & end_stream != 0;
                p.cond.broadcast(p.io);
                if (p.up_done) return;
                continue;
            }
            if (len > buf.len) return error.FrameTooLarge;
            const payload = buf[0..len];
            try p.from.readSliceAll(payload);
            switch (h[3]) {
                t_settings, t_window_update => {},
                t_headers => {
                    // what the server checks
                    const fields = try d.decode(payload);
                    if (!std.mem.eql(u8, get(fields, ":path").?, "/xhttp/")) return error.BadPath;
                    try expectPadded(get(fields, "referer"), "https://www.example.com/xhttp/?x_padding=", 100, 1000);
                    p.mutex.lockUncancelable(p.io);
                    defer p.mutex.unlock(p.io);
                    p.head_ok = true;
                    p.cond.broadcast(p.io);
                },
                else => return error.UnexpectedFrame,
            }
        }
    }

    fn writeLoop(p: *EchoPeer) void {
        p.write() catch |e| p.fail(e);
    }

    fn write(p: *EchoPeer) !void {
        const w = p.to;
        var started = false;
        var sent: usize = 0;
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        while (true) {
            if (p.stop) {
                try frame(w, t_goaway, 0, 0, &.{ 0, 0, 0, 0, 0, 0, 0, 1 });
                return w.flush();
            }
            const start = p.head_ok and !started;
            const have = p.got;
            const credit = p.credit;
            const done = p.up_done;
            if (!start and credit == 0 and sent == have and !done) {
                p.cond.waitUncancelable(p.io, &p.mutex);
                continue;
            }
            p.credit = 0;
            p.mutex.unlock(p.io);
            defer p.mutex.lockUncancelable(p.io);
            if (start) {
                started = true;
                try serverPreface(w);
                try frame(w, t_headers, end_headers, 1, &.{0x88});
                try frame(w, t_data, 0, 1, "\x00\x00");
            }
            if (credit > 0) {
                try u32Frame(w, t_window_update, 0, credit);
                try u32Frame(w, t_window_update, 1, credit);
            }
            while (sent < have) {
                const n = @min(have - sent, 16384);
                try frame(w, t_data, 0, 1, p.echo[sent..][0..n]);
                sent += n;
            }
            if (done) {
                try frame(w, t_data, end_stream, 1, "");
                try w.flush();
                return;
            }
            try w.flush();
        }
    }
};

const Upload = struct {
    fn run(x: *Conn, total: usize, err: *?anyerror) void {
        upload(x, total) catch |e| {
            err.* = e;
        };
    }

    fn upload(x: *Conn, total: usize) !void {
        const sizes = [_]usize{ 1, 999, 4096, 16384, 40000, 7, 30000 };
        var chunk: [40000]u8 = undefined;
        var sent: usize = 0;
        var k: usize = 0;
        while (sent < total) : (k += 1) {
            const n = @min(sizes[k % sizes.len], total - sent);
            for (chunk[0..n], sent..) |*b, i| b.* = upByte(i);
            try x.writer().writeAll(chunk[0..n]);
            if (k % 3 == 0) try x.writer().flush();
            sent += n;
        }
        try x.closeWrite();
    }
};

test "an echo through a threaded server over pipes, both directions at once" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest; // POSIX sockets and pipes
    const io = testing.io;
    const c2s = try pipe();
    const s2c = try pipe();
    var buffers: [4][16 * 1024]u8 = undefined;
    var cr = s2c[0].readerStreaming(io, &buffers[0]);
    var cw = c2s[1].writerStreaming(io, &buffers[1]);
    var pr = c2s[0].readerStreaming(io, &buffers[2]);
    var pw = s2c[1].writerStreaming(io, &buffers[3]);
    defer for ([_]Io.File{ c2s[0], c2s[1], s2c[0], s2c[1] }) |f| f.close(io);

    const total = 300_000;
    const echo = try testing.allocator.alloc(u8, total);
    defer testing.allocator.free(echo);
    var peer: EchoPeer = .{ .io = io, .from = &pr.interface, .to = &pw.interface, .echo = echo };
    const peer_thread = try std.Thread.spawn(.{}, EchoPeer.run, .{&peer});

    var x: Conn = undefined;
    var rbuf: [4096]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    try x.open(io, &cr.interface, &cw.interface, &rbuf, &wbuf, .{ .host = "www.example.com", .path = "/xhttp" });
    var up_err: ?anyerror = null;
    const up_thread = try std.Thread.spawn(.{}, Upload.run, .{ &x, total, &up_err });

    // read as the proxy pumps: whatever is there, until the end
    const got = try testing.allocator.alloc(u8, total + 2);
    defer testing.allocator.free(got);
    var n: usize = 0;
    while (x.reader().peekGreedy(1)) |chunk| {
        if (n + chunk.len > got.len) return error.TestTooMuchData;
        @memcpy(got[n..][0..chunk.len], chunk);
        n += chunk.len;
        x.reader().toss(chunk.len);
    } else |e| try testing.expectEqual(error.EndOfStream, e);
    up_thread.join();
    peer_thread.join();
    x.close();

    try testing.expectEqual(null, peer.err);
    try testing.expectEqual(null, up_err);
    try testing.expectEqual(null, x.read_err);
    try testing.expectEqual(total + 2, n);
    try testing.expectEqualStrings("\x00\x00", got[0..2]);
    for (got[2..n], 0..) |b, i| if (b != upByte(i)) return error.TestBadEcho;
}

test "memory per connection" {
    // the h2 connection and a reader; the request head lived on the stack
    try testing.expect(@sizeOf(Conn) < @sizeOf(h2.Conn) + 128);
}
