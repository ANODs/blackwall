//! HTTPUpgrade (type=httpupgrade): the VLESS transport that is WebSocket's
//! upgrade without WebSocket's framing, as Xray's client speaks it. One
//! HTTP/1.1 request that asks for `Upgrade: websocket`, a 101 answer, and
//! from then on the connection is a plain byte stream both ways.
//!
//! Runs over any std.Io.Reader/Writer pair, normally the decrypted TLS
//! stream. There is nothing to frame, so the payload is written straight to
//! the writer below (`writer()` returns it) and read through `reader`, which
//! only checks the answer before passing bytes on. No lock: the answer is
//! read either by `handshake` before the flow's threads start, or (early
//! data) by the reading thread, the only one reading below.
//!
//! Early data (`ed=N` in the path's query, any N > 0): the request goes out
//! and the data may follow at once, without waiting for the answer, saving
//! a round trip, as in Xray. Unlike WebSocket nothing rides in the request;
//! the bytes simply come next. Xray's server reads the request through a
//! buffer that it then drops, so data that reaches it in the same read is
//! lost. TLS records keep the two apart (Go reads one record at a time);
//! plain TCP does not, so `ed` is honored only above TLS (`Options.tls`).

const std = @import("std");
const Io = std.Io;

pub const Options = struct {
    /// The link's path, percent-decoded once. As in Xray, `ed=N` leaves its
    /// query (the rest of which is sorted), a missing leading '/' is added,
    /// and the whole is escaped as a path, '?' included.
    path: []const u8,
    /// Host header: the link's host, else its sni, else the server address.
    host: []const u8,
    /// The stream below is TLS (or REALITY); only then does `ed` take effect.
    tls: bool = false,
};

pub const Error = error{
    /// The server closed without a word. Xray's does that when the path or
    /// the Host is wrong.
    HttpUpgradeNoAnswer,
    /// The server answered with another status, kept in `status`: a CDN or
    /// a web server in front (Xray's own never does). 403 or 421 mean the
    /// Host/SNI pair is refused, 52x that the server cannot be reached.
    HttpUpgradeRefused,
    /// No HTTP/1.1 101 answer with Upgrade: websocket and Connection:
    /// upgrade: not an HTTPUpgrade server (or ALPN chose h2).
    HttpUpgradeBadAnswer,
    /// A Host that cannot go into a request.
    HttpUpgradeBadOptions,
};

pub const HandshakeError = Error || error{ ReadFailed, WriteFailed };

/// An answer to the upgrade longer than this is not one.
const max_answer = 16 * 1024;

pub const Conn = struct {
    io: Io,
    /// the stream below; after the answer, the payload itself
    r: *Io.Reader,
    w: *Io.Writer,
    /// What the server sends after its answer.
    reader: Io.Reader,
    /// Why `reader` failed (or `handshake`), if the stream below did not.
    err: ?Error = null,
    /// HTTP status of the answer, 0 until it came
    status: u16 = 0,
    /// The answer was read (or failed): `reader` passes bytes on, or fails.
    answered: bool = false,
    failed: bool = false,

    /// `rbuf` buffers `reader` (any size; 16 KiB suits TLS records). The
    /// stream below needs no larger buffer than it takes to read the
    /// answer line by line. `reader` points back into the result: keep it
    /// at one address.
    pub fn init(io: Io, r: *Io.Reader, w: *Io.Writer, rbuf: []u8) Conn {
        std.debug.assert(rbuf.len > 0);
        return .{
            .io = io,
            .r = r,
            .w = w,
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = rbuf, .seek = 0, .end = 0 },
        };
    }

    /// Send the request and, unless early data is on, check the answer,
    /// before any other use. With early data the answer is checked by the
    /// first read of `reader`, which fails (with `err` and `status` set) if
    /// the server refused.
    pub fn handshake(c: *Conn, opts: Options) HandshakeError!void {
        errdefer {
            c.answered = true;
            c.failed = true;
        }
        if (!validHost(opts.host)) return c.fail(error.HttpUpgradeBadOptions);
        var raw: [16]u8 = undefined;
        c.io.random(&raw);
        var key: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&key, &raw);
        const chrome = chromeMajor(Io.Clock.real.now(c.io).toSeconds());
        const early = try writeRequest(c.w, opts.path, opts.host, &key, chrome);
        // its own flush: TLS puts the request in a record of its own, which
        // is what lets early data follow it
        try c.w.flush();
        if (early and opts.tls) return;
        c.answered = true;
        try c.readAnswer();
    }

    /// Where the payload goes: the stream below, as it is.
    pub fn writer(c: *Conn) *Io.Writer {
        return c.w;
    }

    fn fail(c: *Conn, e: Error) Error {
        c.err = e;
        return e;
    }

    /// The answer up to its empty line; what follows stays in `r`. Checked
    /// like Xray's client does (status 101, Upgrade "websocket", Connection
    /// "upgrade"), but any reason phrase is fine and the headers may be
    /// lists, as a CDN may send them. Xray checks no Sec-WebSocket-Accept.
    fn readAnswer(c: *Conn) HandshakeError!void {
        var buf: [256]u8 = undefined;
        var budget: usize = max_answer;
        _ = c.r.peekByte() catch |e| return switch (e) {
            error.EndOfStream => c.fail(error.HttpUpgradeNoAnswer),
            error.ReadFailed => error.ReadFailed,
        };
        // "HTTP/1.1 101 Switching Protocols"
        const status = try c.answerLine(&buf, &budget);
        if (status.len < 12 or !std.mem.startsWith(u8, status, "HTTP/1.") or status[8] != ' ')
            return c.fail(error.HttpUpgradeBadAnswer);
        c.status = std.fmt.parseInt(u16, status[9..12], 10) catch return c.fail(error.HttpUpgradeBadAnswer);
        if (c.status != 101) return c.fail(error.HttpUpgradeRefused);
        var upgrade_ok = false;
        var connection_ok = false;
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
            }
        }
        if (!upgrade_ok or !connection_ok) return c.fail(error.HttpUpgradeBadAnswer);
    }

    /// The next line of the answer without its CRLF. What of a long line
    /// does not fit `buf` is skipped: no header we check is that long.
    fn answerLine(c: *Conn, buf: []u8, budget: *usize) HandshakeError![]const u8 {
        var n: usize = 0;
        while (true) {
            const chunk = c.r.peekGreedy(1) catch |e| switch (e) {
                error.EndOfStream => return c.fail(error.HttpUpgradeBadAnswer),
                error.ReadFailed => return error.ReadFailed,
            };
            const nl = std.mem.findScalar(u8, chunk, '\n');
            const take = if (nl) |i| i + 1 else chunk.len;
            if (take > budget.*) return c.fail(error.HttpUpgradeBadAnswer);
            budget.* -= take;
            const k = @min(take, buf.len - n);
            @memcpy(buf[n..][0..k], chunk[0..k]);
            n += k;
            c.r.toss(take);
            if (nl != null) return std.mem.trimEnd(u8, buf[0..n], "\r\n");
        }
    }

    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const c: *Conn = @alignCast(@fieldParentPtr("reader", io_r));
        if (!c.answered) {
            c.answered = true;
            c.readAnswer() catch {
                c.failed = true;
            };
        }
        if (c.failed) return error.ReadFailed;
        return c.r.stream(w, limit);
    }
};

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

// ---------------------------------------------------------------- the request

/// The request as Xray's client writes it (Go's http.Request.Write): Host
/// and User-Agent first, the rest sorted by name. The fields are Xray's
/// Chrome disguise (common/utils/browser.go, the "ws" variant) plus the
/// upgrade's own, set through Go's Header.Set and so spelled
/// "Sec-Websocket-Key", unlike gorilla's WebSocket request. Returns whether
/// the path asks for early data.
fn writeRequest(w: *Io.Writer, path: []const u8, host: []const u8, key: *const [24]u8, chrome: u32) Io.Writer.Error!bool {
    try w.writeAll("GET ");
    const early = try writeTarget(w, path);
    try w.print(" HTTP/1.1\r\nHost: {s}\r\nUser-Agent: ", .{host});
    try writeUserAgent(w, chrome);
    try w.writeAll("\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\n" ++
        "Connection: Upgrade\r\nDNT: 1\r\nPragma: no-cache\r\nSec-CH-UA: ");
    try writeBrands(w, chrome);
    try w.print("\r\nSec-CH-UA-Mobile: ?0\r\nSec-CH-UA-Platform: \"Windows\"\r\nSec-Fetch-Dest: empty\r\n" ++
        "Sec-Fetch-Mode: websocket\r\nSec-Fetch-Site: same-origin\r\nSec-Websocket-Key: {s}\r\n" ++
        "Sec-Websocket-Version: 13\r\nUpgrade: websocket\r\n\r\n", .{key});
    return early;
}

/// Write the request target for a link's path; return whether it asks for
/// early data. Xray's config takes `ed` with a value out of the query and
/// sorts what is left by name (values keep their spelling here; Go
/// re-encodes them), a missing leading '/' is added, and the dialer puts
/// the whole string in URL.Path, so it goes escaped as a path: '?', '#' and
/// '%' included.
fn writeTarget(w: *Io.Writer, path: []const u8) Io.Writer.Error!bool {
    const hash = std.mem.findScalar(u8, path, '#') orelse path.len;
    const q = std.mem.findScalar(u8, path[0..hash], '?') orelse hash;
    const query = if (q < hash) path[q + 1 .. hash] else "";
    var ed: ?[]const u8 = null; // the first value, as Go's Get takes it
    var it = std.mem.tokenizeScalar(u8, query, '&');
    while (it.next()) |kv| {
        const eq = std.mem.findScalar(u8, kv, '=');
        if (std.mem.eql(u8, kv[0 .. eq orelse kv.len], "ed")) {
            ed = if (eq) |i| kv[i + 1 ..] else "";
            break;
        }
    }
    if (path.len == 0 or path[0] != '/') try w.writeByte('/');
    const value = ed orelse "";
    if (value.len == 0) { // Xray leaves such a path alone
        try writeEscaped(w, path);
        return false;
    }
    try writeEscaped(w, path[0..q]);
    var pairs: [32][]const u8 = undefined;
    var n: usize = 0;
    it.reset();
    while (it.next()) |kv| {
        const eq = std.mem.findScalar(u8, kv, '=');
        if (std.mem.eql(u8, kv[0 .. eq orelse kv.len], "ed")) continue;
        if (n == pairs.len) break; // a query this long is not a real one
        pairs[n] = kv;
        n += 1;
    }
    std.sort.insertion([]const u8, pairs[0..n], {}, nameLess);
    for (pairs[0..n], 0..) |kv, i| {
        try writeEscaped(w, if (i == 0) "?" else "&");
        try writeEscaped(w, kv);
        if (std.mem.findScalar(u8, kv, '=') == null) try w.writeByte('=');
    }
    try writeEscaped(w, path[hash..]);
    return earlyRequested(value);
}

fn nameLess(_: void, a: []const u8, b: []const u8) bool {
    const an = a[0 .. std.mem.findScalar(u8, a, '=') orelse a.len];
    const bn = b[0 .. std.mem.findScalar(u8, b, '=') orelse b.len];
    return std.mem.lessThan(u8, an, bn);
}

/// `ed` as Xray reads it: Atoi, then uint32, and only zero or not matters.
/// Not a number is 0; out of range Go clamps, which is not 0.
fn earlyRequested(text: []const u8) bool {
    const n = std.fmt.parseInt(i64, text, 10) catch |e| return e == error.Overflow;
    return @as(u32, @truncate(@as(u64, @bitCast(n)))) != 0;
}

/// Go's escaping of a URL path: letters, digits, "-._~" and "$&+,/:;=@"
/// stay; any other byte goes percent-encoded.
fn writeEscaped(w: *Io.Writer, s: []const u8) Io.Writer.Error!void {
    for (s) |b| {
        if (std.ascii.isAlphanumeric(b) or std.mem.findScalar(u8, "-._~$&+,/:;=@", b) != null) {
            try w.writeByte(b);
        } else {
            try w.print("%{X:0>2}", .{b});
        }
    }
}

// ------------------------------------------- the Chrome disguise, shared by
// the HTTP transports (ws.zig keeps its own copy of these two)

/// Chrome's major version as Xray derives it from the date: 144 on
/// 2026-01-13, one more every 35 days after a 35-day lag. Xray adds a
/// random lag of up to 105 days, fixed per machine; we add none and claim
/// the newest version, which most Chrome installations run.
pub fn chromeMajor(now_s: i64) u32 {
    const days = @divFloor(now_s, 86400) - 20466; // 2026-01-13
    return 144 + @as(u32, @intCast(@max(0, @divTrunc(days - 35, 35))));
}

/// Xray's ChromeUA for Chrome `v`.
pub fn writeUserAgent(w: *Io.Writer, v: u32) Io.Writer.Error!void {
    try w.print("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " ++
        "Chrome/{d}.0.0.0 Safari/537.36", .{v});
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

test "the request is Xray's, byte for byte" {
    var buf: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try testing.expect(!try writeRequest(&w, "/hu", "hu.blackwall.test", "E6YUDkPwYe5OBINlwbIRoA==", 151));
    // captured from Xray 26.11.9 on this machine (only the key differs)
    const xray = "GET /hu HTTP/1.1\r\nHost: hu.blackwall.test\r\n" ++
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36\r\n" ++
        "Accept: */*\r\nAccept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nConnection: Upgrade\r\nDNT: 1\r\nPragma: no-cache\r\n" ++
        "Sec-CH-UA: \"Not=A?Brand\";v=\"99\", \"Google Chrome\";v=\"151\", \"Chromium\";v=\"151\"\r\n" ++
        "Sec-CH-UA-Mobile: ?0\r\nSec-CH-UA-Platform: \"Windows\"\r\nSec-Fetch-Dest: empty\r\nSec-Fetch-Mode: websocket\r\nSec-Fetch-Site: same-origin\r\n" ++
        "Sec-Websocket-Key: E6YUDkPwYe5OBINlwbIRoA==\r\nSec-Websocket-Version: 13\r\nUpgrade: websocket\r\n\r\n";
    try testing.expectEqualStrings(xray, w.buffered());
    try testing.expectEqual(@as(usize, 590), w.buffered().len);
}

test "paths: early data taken out, the rest sorted, all escaped as a path" {
    const cases = [_]struct { in: []const u8, out: []const u8, early: bool }{
        .{ .in = "", .out = "/", .early = false },
        .{ .in = "hu", .out = "/hu", .early = false },
        .{ .in = "/hu?ed=2048", .out = "/hu", .early = true },
        // captured from Xray 26.11.9
        .{ .in = "/hu?z=1&b=2&ed=2048", .out = "/hu%3Fb=2&z=1", .early = true },
        .{ .in = "/hu?x=1", .out = "/hu%3Fx=1", .early = false },
        .{ .in = "/hu?ed=", .out = "/hu%3Fed=", .early = false },
        .{ .in = "/hu?ed=abc", .out = "/hu", .early = false },
        .{ .in = "/hu?ed=0", .out = "/hu", .early = false },
        .{ .in = "/hu?ed=-1", .out = "/hu", .early = true },
        .{ .in = "/hu?ed=4294967296", .out = "/hu", .early = false },
        .{ .in = "/hu?ed=99999999999999999999", .out = "/hu", .early = true },
        .{ .in = "/p?b&ed=1", .out = "/p%3Fb=", .early = true },
        .{ .in = "?ed=1", .out = "/", .early = true },
        .{ .in = "/p?ed=1#top", .out = "/p%23top", .early = true },
        .{ .in = "/a b%!*'()[]\"\r\n#f", .out = "/a%20b%25%21%2A%27%28%29%5B%5D%22%0D%0A%23f", .early = false },
        .{ .in = "/v2/$&+,:;=@-._~", .out = "/v2/$&+,:;=@-._~", .early = false },
    };
    for (cases) |t| {
        var buf: [128]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        const early = try writeTarget(&w, t.in);
        try testing.expectEqualStrings(t.out, w.buffered());
        try testing.expectEqual(t.early, early);
    }
    try testing.expect(!validHost("a b"));
    try testing.expect(!validHost("a\r\nX: y"));
    try testing.expect(!validHost(""));
    try testing.expect(validHost("[2001:db8::1]"));
}

test "Chrome version and user agent follow the date" {
    try testing.expectEqual(@as(u32, 151), chromeMajor(1_794_614_400)); // 2026-11-14
    try testing.expectEqual(@as(u32, 144), chromeMajor(1_768_262_400)); // 2026-01-13
    try testing.expectEqual(@as(u32, 144), chromeMajor(0)); // a clock that is off
    var buf: [160]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeUserAgent(&w, 151);
    try testing.expectEqualStrings("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36", w.buffered());
}

/// In-process server for tests on one thread. What the client writes lands
/// in `up`; its first read finds `answer` and `after` (the payload behind
/// it) and notes whether the client had written `before` by then.
const Script = struct {
    up_buf: [4096]u8 = undefined,
    up: Io.Writer = undefined,
    down_buf: [4096]u8 = undefined,
    down: Io.Reader = undefined,
    answer: []const u8 = ok_answer,
    after: []const u8 = "",
    answered: bool = false,
    /// bytes the client had sent past its request when it first read
    sent_first: usize = 0,
    rbuf: [64]u8 = undefined,
    c: Conn = undefined,

    const ok_answer = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\nUpgrade: websocket\r\n\r\n";

    fn init(s: *Script) void {
        s.up = .fixed(&s.up_buf);
        s.down = .{ .vtable = &.{ .stream = respond }, .buffer = &s.down_buf, .seek = 0, .end = 0 };
        s.c = .init(testing.io, &s.down, &s.up, &s.rbuf);
    }

    fn respond(r: *Io.Reader, _: *Io.Writer, _: Io.Limit) Io.Reader.StreamError!usize {
        const s: *Script = @alignCast(@fieldParentPtr("down", r));
        if (s.answered) return error.EndOfStream;
        s.answered = true;
        s.sent_first = s.payloadUp().len;
        @memcpy(r.buffer[0..s.answer.len], s.answer);
        @memcpy(r.buffer[s.answer.len..][0..s.after.len], s.after);
        r.end = s.answer.len + s.after.len;
        return 0;
    }

    /// Everything the client sent after its request.
    fn payloadUp(s: *Script) []u8 {
        const all = s.up.buffered();
        return all[(std.mem.find(u8, all, "\r\n\r\n") orelse return all[all.len..]) + 4 ..];
    }
};

test "upgrade, then the stream as it is both ways" {
    var s: Script = .{ .after = "server speaks first" };
    s.init();
    try s.c.handshake(.{ .path = "/hu", .host = "hu.blackwall.test" });
    try testing.expect(s.answered); // no early data: the answer came first
    try testing.expectEqual(@as(u16, 101), s.c.status);
    try testing.expect(std.mem.startsWith(u8, s.up.buffered(), "GET /hu HTTP/1.1\r\nHost: hu.blackwall.test\r\n"));

    var got: [64]u8 = undefined;
    var gw: Io.Writer = .fixed(&got);
    _ = try s.c.reader.streamRemaining(&gw);
    try testing.expectEqualStrings("server speaks first", gw.buffered());
    try s.c.writer().writeAll("vless header and data");
    try s.c.writer().flush();
    try testing.expectEqualStrings("vless header and data", s.payloadUp());
}

test "early data above TLS: the data goes before the answer, which the reader checks" {
    var s: Script = .{ .after = "reply" };
    s.init();
    try s.c.handshake(.{ .path = "/hu?ed=2560", .host = "h", .tls = true });
    try testing.expect(!s.answered);
    try testing.expect(std.mem.startsWith(u8, s.up.buffered(), "GET /hu HTTP/1.1\r\n"));
    try s.c.writer().writeAll("vless");
    try s.c.writer().flush();
    var got: [16]u8 = undefined;
    const n = try s.c.reader.readSliceShort(&got);
    try testing.expectEqualStrings("reply", got[0..n]);
    try testing.expectEqual(@as(usize, 5), s.sent_first); // written before the answer was read
    try testing.expectEqual(@as(u16, 101), s.c.status);

    // over plain TCP the same path waits for the answer
    var p: Script = .{};
    p.init();
    try p.c.handshake(.{ .path = "/hu?ed=2560", .host = "h" });
    try testing.expect(p.answered);
    try testing.expectEqual(@as(usize, 0), p.sent_first);
}

test "refused and broken answers" {
    const answers = [_]struct { answer: []const u8, err: Error, status: u16 }{
        // Xray's server on a wrong path or Host
        .{ .answer = "", .err = error.HttpUpgradeNoAnswer, .status = 0 },
        .{ .answer = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", .err = error.HttpUpgradeRefused, .status = 404 },
        .{ .answer = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n", .err = error.HttpUpgradeBadAnswer, .status = 101 },
        .{ .answer = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n", .err = error.HttpUpgradeBadAnswer, .status = 101 },
        // h2 chosen by ALPN: the server opens with SETTINGS
        .{ .answer = "\x00\x00\x12\x04\x00\x00\x00\x00\x00", .err = error.HttpUpgradeBadAnswer, .status = 0 },
        .{ .answer = "HTTP/1.1 101 Switching", .err = error.HttpUpgradeBadAnswer, .status = 0 },
        .{ .answer = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n", .err = error.HttpUpgradeBadAnswer, .status = 101 },
    };
    for (answers) |t| {
        var s: Script = .{ .answer = t.answer };
        s.init();
        try testing.expectError(t.err, s.c.handshake(.{ .path = "/hu", .host = "h" }));
        try testing.expectEqual(t.err, s.c.err.?);
        try testing.expectEqual(t.status, s.c.status);
        try testing.expectError(error.ReadFailed, s.c.reader.takeByte());
        // with early data the same shows on the first read
        var e: Script = .{ .answer = t.answer };
        e.init();
        try e.c.handshake(.{ .path = "/hu?ed=1", .host = "h", .tls = true });
        try testing.expectError(error.ReadFailed, e.c.reader.takeByte());
        try testing.expectEqual(t.err, e.c.err.?);
        try testing.expectError(error.ReadFailed, e.c.reader.takeByte());
    }
    // what a CDN adds: long lines, lists, other spellings and reasons
    var s: Script = .{ .answer = "HTTP/1.1 101 Web Socket Protocol Handshake\r\nDate: x\r\nconnection: keep-alive, UPGRADE\r\n" ++
        "Report-To: {\"endpoints\":[{\"url\":\"https:\\/\\/a.example\\/report\\/v4?s=" ++ @as([400]u8, @splat('x')) ++ "\"}]}\r\n" ++
        "upgrade: WebSocket\r\nServer: cloudflare\r\n\r\n", .after = "ok" };
    s.init();
    try s.c.handshake(.{ .path = "/hu", .host = "h" });
    try testing.expectEqual('o', try s.c.reader.takeByte());
    try testing.expectError(error.HttpUpgradeBadOptions, s.c.handshake(.{ .path = "/", .host = "a\r\nb" }));
}

// ------------------------------------------------- over a socket, threaded

fn testByte(i: usize) u8 {
    return @truncate((i *% 2654435761) >> 13);
}

const bulk = 2 * 1024 * 1024;

/// The server side of the threaded test: Xray's hub reduced to its
/// essentials. Checks the request, answers 101 with the first payload in
/// the same write, then streams `bulk` bytes down while it reads `bulk` up.
const Peer = struct {
    server: Io.net.Server = undefined,
    thread: std.Thread = undefined,
    failed: bool = false,

    fn start(p: *Peer) !void {
        const address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        p.server = try address.listen(testing.io, .{ .reuse_address = true });
        p.thread = try std.Thread.spawn(.{}, run, .{p});
    }

    fn run(p: *Peer) void {
        p.serve() catch {
            p.failed = true;
        };
    }

    fn serve(p: *Peer) !void {
        const conn = try p.server.accept(testing.io);
        defer conn.close(testing.io);
        var rb: [16 * 1024]u8 = undefined;
        var wb: [16 * 1024]u8 = undefined;
        var sr = conn.reader(testing.io, &rb);
        var sw = conn.writer(testing.io, &wb);
        var req: [2048]u8 = undefined;
        var n: usize = 0;
        while (std.mem.find(u8, req[0..n], "\r\n\r\n") == null) {
            req[n] = try sr.interface.takeByte();
            n += 1;
        }
        if (!std.mem.startsWith(u8, req[0..n], "GET /hu HTTP/1.1\r\nHost: hu.blackwall.test\r\n")) return error.BadRequest;
        try sw.interface.writeAll(Script.ok_answer);

        const Down = struct {
            fn run(w: *Io.Writer, err: *bool) void {
                send(w) catch {
                    err.* = true;
                };
            }
            fn send(w: *Io.Writer) !void {
                var chunk: [7000]u8 = undefined;
                var sent: usize = 0;
                while (sent < bulk) {
                    const k = @min(chunk.len, bulk - sent);
                    for (chunk[0..k], sent..) |*b, i| b.* = testByte(i);
                    try w.writeAll(chunk[0..k]);
                    try w.flush();
                    sent += k;
                }
            }
        };
        var down_err = false;
        const t = try std.Thread.spawn(.{}, Down.run, .{ &sw.interface, &down_err });
        var got: usize = 0;
        while (got < bulk) {
            const chunk = try sr.interface.peekGreedy(1);
            for (chunk, got..) |b, i| if (b != testByte(i)) return error.BadUpload;
            got += chunk.len;
            sr.interface.toss(chunk.len);
        }
        t.join();
        if (down_err) return error.DownFailed;
        // the client half-closes after its upload: we see the end
        if (sr.interface.peekByte()) |_| return error.TrailingBytes else |e| if (e != error.EndOfStream) return e;
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
};

test "a reading and a writing thread over a socket, early data on" {
    var peer: Peer = .{};
    try peer.start();
    const s = try peer.connect();
    defer s.close(testing.io);
    var urb: [16 * 1024]u8 = undefined;
    var uwb: [4096]u8 = undefined;
    var ur = s.reader(testing.io, &urb);
    var uw = s.writer(testing.io, &uwb);
    var rbuf: [16 * 1024]u8 = undefined;
    var c: Conn = .init(testing.io, &ur.interface, &uw.interface, &rbuf);
    // as if above TLS: the reader thread takes the answer
    try c.handshake(.{ .path = "/hu?ed=2048", .host = "hu.blackwall.test", .tls = true });

    const Reading = struct {
        fn run(conn: *Conn, total: *usize, ok: *bool) void {
            while (total.* < bulk) {
                const chunk = conn.reader.peekGreedy(1) catch return;
                for (chunk, total.*..) |b, i| if (b != testByte(i)) return;
                total.* += chunk.len;
                conn.reader.toss(chunk.len);
            }
            ok.* = true;
        }
    };
    var total: usize = 0;
    var ok = false;
    const t = try std.Thread.spawn(.{}, Reading.run, .{ &c, &total, &ok });
    var chunk: [5000]u8 = undefined;
    var sent: usize = 0;
    while (sent < bulk) {
        const k = @min(chunk.len, bulk - sent);
        for (chunk[0..k], sent..) |*b, i| b.* = testByte(i);
        try c.writer().writeAll(chunk[0..k]);
        try c.writer().flush();
        sent += k;
    }
    try s.shutdown(testing.io, .send);
    t.join();
    try testing.expect(ok);
    try testing.expectEqual(@as(usize, bulk), total);
    try peer.finish();
}
