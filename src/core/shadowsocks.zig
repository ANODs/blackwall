//! Shadowsocks outbound: AEAD (SIP004) and Shadowsocks 2022 (SIP022).
//!
//! `Conn` is a cipher stream over any std.Io.Reader/Writer pair, normally
//! the TCP socket: what is written to `writer` leaves sealed, what the
//! server sends comes out of `reader` opened. The request header leaves
//! with the first flush, together with whatever data is buffered by then
//! (flush with nothing buffered to send it alone, for server-first
//! protocols).
//!
//! AEAD (aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305,
//! xchacha20-ietf-poly1305): each direction starts with a random salt, and
//! the subkey is HKDF-SHA1(key, salt, "ss-subkey") of the key that
//! EVP_BytesToKey (MD5) makes of the password. Then chunks: a sealed 2-byte
//! length and the sealed payload, at most 0x3FFF bytes, each sealed with
//! the next nonce (a little-endian counter from zero). The request is the
//! destination, as SOCKS5 writes it, at the start of the stream.
//!
//! 2022 (2022-blake3-aes-128-gcm, -aes-256-gcm, -chacha20-poly1305): the key
//! is a PSK (base64 in links) and the subkey BLAKE3's derive_key of PSK and
//! salt. The request opens with a sealed fixed header (type 0, timestamp,
//! the length of the next chunk) and a sealed variable header (destination,
//! padding, first data); the answer opens with a fixed header that echoes
//! our salt (checked, as are its type and timestamp) and gives the length
//! of the first payload chunk, which follows without a length chunk of its
//! own. Chunks may hold 0xFFFF bytes. With several PSKs ("iPSK:uPSK", for
//! relays and multi-user servers) an identity header for each PSK but the
//! last tells the server whose key comes next. Xray reads salt and fixed
//! header with one read and resets the connection when they come apart, so
//! the whole request is handed to the stream below in one write.
//!
//! Memory: the writer seals in place inside its buffer, with room for the
//! length chunk and the request header kept in front of the payload; tags
//! travel in the same vectored write. The reader takes as much ciphertext
//! as the socket has into its own buffer (with Xray's 8 KiB chunks, several
//! at a time) and opens every whole chunk there, each payload decrypted
//! straight to the end of the plaintext in front of it, no copy: so one
//! read and one write in the copy loop carry several chunks. That buffer is
//! where the plaintext is read from, and must hold a whole chunk:
//! `readBufferLen`. AES-GCM is aes_gcm.zig's, keyed once per direction.
//!
//! One thread may read while another writes: the directions share nothing
//! that changes after `init`.

const std = @import("std");
const Io = std.Io;
const crypto = std.crypto;
const proxy = @import("proxy.zig");
const aes_gcm = @import("aes_gcm.zig");
/// The SOCKS5 address form, which Shadowsocks shares with Trojan.
const writeAddress = @import("trojan.zig").writeAddress;

const Target = proxy.Target;

const tag_len = 16;
/// a sealed 2-byte length
const len_chunk = 2 + tag_len;
/// 2022 request: type, timestamp, length of the variable header
const fixed_request = 1 + 8 + 2;
const max_padding = 900;
pub const max_identities = 3;
const address_max = 1 + 1 + 255 + 2;
/// Most room the request needs in front of the first data.
const first_room_max = 32 + 16 * max_identities + fixed_request + tag_len + address_max + 2 + max_padding;

/// A write buffer this large seals the first data with the request and
/// then up to 16 KiB per chunk (one TLS-record-sized write each).
pub const write_buffer_len = first_room_max + 16 * 1024;

/// The read buffer holds a whole chunk: 16 KiB for AEAD, 64 KiB for 2022.
/// A smaller one fails (`error.SsBufferTooSmall`) on the first chunk that
/// does not fit; Xray itself never sends more than 8 KiB at once, sing-box
/// and shadowsocks-rust fill chunks to the limit. This is enough for a
/// caller that empties the buffer before asking for more (a copy loop); one
/// that parses with `take(n)` across chunks needs n - 1 bytes on top. It is
/// also the most one read takes from the socket: up to eight of Xray's
/// chunks with 2022.
pub fn readBufferLen(m: Method) usize {
    return m.maxChunk() + tag_len;
}

pub const Method = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,
    xchacha20_poly1305,
    blake3_aes_128_gcm,
    blake3_aes_256_gcm,
    blake3_chacha20_poly1305,

    /// The names links and Xray use, in any case.
    pub fn fromName(name: []const u8) ?Method {
        const names = [_]struct { []const u8, Method }{
            .{ "aes-128-gcm", .aes_128_gcm },
            .{ "aead_aes_128_gcm", .aes_128_gcm },
            .{ "aes-256-gcm", .aes_256_gcm },
            .{ "aead_aes_256_gcm", .aes_256_gcm },
            .{ "chacha20-ietf-poly1305", .chacha20_poly1305 },
            .{ "chacha20-poly1305", .chacha20_poly1305 },
            .{ "aead_chacha20_poly1305", .chacha20_poly1305 },
            .{ "xchacha20-ietf-poly1305", .xchacha20_poly1305 },
            .{ "xchacha20-poly1305", .xchacha20_poly1305 },
            .{ "aead_xchacha20_poly1305", .xchacha20_poly1305 },
            .{ "2022-blake3-aes-128-gcm", .blake3_aes_128_gcm },
            .{ "2022-blake3-aes-256-gcm", .blake3_aes_256_gcm },
            .{ "2022-blake3-chacha20-poly1305", .blake3_chacha20_poly1305 },
        };
        for (names) |n| if (std.ascii.eqlIgnoreCase(name, n[0])) return n[1];
        return null;
    }

    pub fn is2022(m: Method) bool {
        return switch (m) {
            .blake3_aes_128_gcm, .blake3_aes_256_gcm, .blake3_chacha20_poly1305 => true,
            else => false,
        };
    }

    /// Key length, which is also the salt length.
    pub fn keyLen(m: Method) usize {
        return switch (m) {
            .aes_128_gcm, .blake3_aes_128_gcm => 16,
            else => 32,
        };
    }

    /// Largest payload of one chunk.
    pub fn maxChunk(m: Method) usize {
        return if (m.is2022()) 0xffff else 0x3fff;
    }

    /// std's AEAD for the ChaCha methods (the AES ones are aes_gcm.zig's).
    fn Aead(comptime m: Method) type {
        return switch (m) {
            .chacha20_poly1305, .blake3_chacha20_poly1305 => crypto.aead.chacha_poly.ChaCha20Poly1305,
            .xchacha20_poly1305 => crypto.aead.chacha_poly.XChaCha20Poly1305,
            else => unreachable,
        };
    }
};

/// A Shadowsocks server and the keys for it. `host` points to the caller's.
pub const Shadowsocks = struct {
    host: []const u8,
    port: u16,
    method: Method,
    /// AEAD: what EVP_BytesToKey makes of the password; 2022: the user's PSK
    key: [32]u8,
    /// 2022 through a relay or to a multi-user server: the PSKs in front
    /// of the user's, in order, each opening one identity header
    identities: [max_identities][32]u8 = undefined,
    identity_count: u8 = 0,

    /// From a method and a password as Xray takes them. For 2022 the
    /// password is the PSK, or "iPSK:...:uPSK", each base64 (or the raw key).
    pub fn init(method: Method, password: []const u8, host: []const u8, port: u16) LinkError!Shadowsocks {
        var s: Shadowsocks = .{ .host = host, .port = port, .method = method, .key = @splat(0) };
        const n = method.keyLen();
        if (!method.is2022()) {
            if (password.len == 0) return error.BadPassword;
            bytesToKey(password, s.key[0..n]);
            return s;
        }
        var keys: [max_identities + 1][32]u8 = undefined;
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, password, ':');
        while (it.next()) |part| : (count += 1) {
            if (count == keys.len) return error.BadPassword;
            keys[count] = @splat(0);
            if (!parsePsk(part, keys[count][0..n])) return error.BadPassword;
        }
        // identity headers are AES blocks: Xray refuses them with ChaCha too
        if (count > 1 and method == .blake3_chacha20_poly1305) return error.BadPassword;
        s.key = keys[count - 1];
        s.identity_count = @intCast(count - 1);
        @memcpy(s.identities[0 .. count - 1], keys[0 .. count - 1]);
        return s;
    }
};

pub const LinkError = error{
    NotShadowsocks,
    /// no "method:password" where the link should have one
    BadUserInfo,
    UnsupportedMethod,
    /// empty, too long, or a 2022 PSK that is not a key of the method's length
    BadPassword,
    /// SIP003 plugins (obfs, v2ray-plugin, ...) are separate programs
    UnsupportedPlugin,
    UnsupportedTransport,
    UnsupportedSecurity,
};

/// What of an `ss://` link this build can carry. `host` and `port` are the
/// server's, already taken from the link. Forms: SIP002 with the userinfo
/// base64url-encoded ("ss://BASE64(method:password)@host:port") or plain
/// with the password percent-encoded ("ss://method:pass%40word@host:port",
/// which SIP002 asks for with 2022 keys), and the legacy
/// "ss://BASE64(method:password@host:port)". Plugins are refused, as is
/// any transport or security parameter other than plain TCP.
pub fn fromLink(link: []const u8, host: []const u8, port: u16) LinkError!Shadowsocks {
    const prefix = "ss://";
    if (!std.ascii.startsWithIgnoreCase(link, prefix)) return error.NotShadowsocks;
    var rest = link[prefix.len..];
    if (std.mem.findScalar(u8, rest, '#')) |i| rest = rest[0..i];
    if (std.mem.findScalar(u8, rest, '?')) |i| {
        var it = std.mem.tokenizeScalar(u8, rest[i + 1 ..], '&');
        while (it.next()) |kv| {
            const eq = std.mem.findScalar(u8, kv, '=') orelse kv.len;
            const k = kv[0..eq];
            const v = if (eq < kv.len) kv[eq + 1 ..] else "";
            if (std.mem.eql(u8, k, "plugin")) {
                if (v.len > 0) return error.UnsupportedPlugin;
            } else if (std.mem.eql(u8, k, "type")) {
                // what our own subscription parser writes for Xray configs
                if (v.len > 0 and !std.ascii.eqlIgnoreCase(v, "tcp") and !std.ascii.eqlIgnoreCase(v, "raw"))
                    return error.UnsupportedTransport;
            } else if (std.mem.eql(u8, k, "security")) {
                if (v.len > 0 and !std.ascii.eqlIgnoreCase(v, "none")) return error.UnsupportedSecurity;
            }
        }
        rest = rest[0..i];
    }

    var b64: [512]u8 = undefined;
    var pw: [512]u8 = undefined;
    var info: []const u8 = undefined;
    var escaped = false;
    if (std.mem.findScalarLast(u8, rest, '@')) |at| {
        info = rest[0..at];
        if (std.mem.findScalar(u8, info, ':') != null) {
            escaped = true;
        } else if (std.ascii.findIgnoreCase(info, "%3a") != null) {
            info = percentDecode(&pw, info) orelse return error.BadPassword;
        } else {
            // generators that escape the whole link escape the padding too
            const plain = if (std.mem.indexOfScalar(u8, info, '%') != null) percentDecode(&pw, info) orelse return error.BadPassword else info;
            info = decodeBase64(&b64, plain) orelse return error.BadUserInfo;
        }
    } else {
        const all = decodeBase64(&b64, std.mem.trimEnd(u8, rest, "/")) orelse return error.BadUserInfo;
        info = all[0 .. std.mem.findScalarLast(u8, all, '@') orelse return error.BadUserInfo];
    }
    const colon = std.mem.findScalar(u8, info, ':') orelse return error.BadUserInfo;
    const method = Method.fromName(info[0..colon]) orelse return error.UnsupportedMethod;
    var password = info[colon + 1 ..];
    if (escaped) password = percentDecode(&pw, password) orelse return error.BadPassword;
    return .init(method, password, host, port);
}

/// Base64 in either alphabet, padded or not; null if it is not.
fn decodeBase64(out: []u8, text: []const u8) ?[]u8 {
    var clean: [683]u8 = undefined;
    var n: usize = 0;
    for (text) |c| {
        if (c == '=') continue;
        if (n == clean.len) return null;
        clean[n] = switch (c) {
            '-' => '+',
            '_' => '/',
            else => c,
        };
        n += 1;
    }
    const dec = std.base64.standard_no_pad.Decoder;
    const size = dec.calcSizeForSlice(clean[0..n]) catch return null;
    if (size > out.len) return null;
    dec.decode(out[0..size], clean[0..n]) catch return null;
    return out[0..size];
}

fn percentDecode(out: []u8, raw: []const u8) ?[]u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < raw.len) : (n += 1) {
        if (n == out.len) return null;
        out[n] = raw[i];
        i += 1;
        if (raw[i - 1] == '%' and i + 1 < raw.len) {
            if (std.fmt.parseInt(u8, raw[i .. i + 2], 16)) |b| {
                out[n] = b;
                i += 2;
            } else |_| {}
        }
    }
    return out[0..n];
}

/// A 2022 PSK: standard base64 of exactly the key length, else (as Xray
/// allows) the text itself when it has that length.
fn parsePsk(text: []const u8, out: []u8) bool {
    var buf: [64]u8 = undefined;
    if (decodeBase64(&buf, text)) |k| if (k.len == out.len) {
        @memcpy(out, k);
        return true;
    };
    if (text.len != out.len) return false;
    @memcpy(out, text);
    return true;
}

/// OpenSSL's EVP_BytesToKey with MD5 and one round, as every Shadowsocks
/// implementation makes the AEAD key of the password.
fn bytesToKey(password: []const u8, out: []u8) void {
    const Md5 = crypto.hash.Md5;
    var d: [Md5.digest_length]u8 = undefined;
    var i: usize = 0;
    while (i < out.len) : (i += d.len) {
        var h: Md5 = .init(.{});
        if (i > 0) h.update(&d);
        h.update(password);
        h.final(&d);
        const k = @min(d.len, out.len - i);
        @memcpy(out[i..][0..k], d[0..k]);
    }
}

const HkdfSha1 = crypto.kdf.hkdf.Hkdf(crypto.auth.hmac.HmacSha1);

/// BLAKE3 derive_key of the concatenation `a ++ b`.
fn deriveKey(context: []const u8, a: []const u8, b: []const u8, out: []u8) void {
    var h: crypto.hash.Blake3 = .initKdf(context, .{});
    h.update(a);
    h.update(b);
    h.final(out);
}

/// One direction's AEAD: the subkey, with AES its key schedule and powers
/// of H made once (see aes_gcm.zig), and the nonce counter.
const Cipher = struct {
    aead: union {
        aes128: aes_gcm.Aes128Gcm,
        aes256: aes_gcm.Aes256Gcm,
        /// ChaCha20 and XChaCha20, which std's AEADs take as a key
        key: [32]u8,
    } = .{ .key = @splat(0) },
    nonce: [24]u8 = @splat(0),

    fn init(m: Method, key: *const [32]u8, salt: []const u8) Cipher {
        var sub: [32]u8 = @splat(0);
        defer crypto.secureZero(u8, &sub);
        const n = m.keyLen();
        if (m.is2022()) {
            deriveKey("shadowsocks 2022 session subkey", key[0..n], salt, sub[0..n]);
        } else {
            HkdfSha1.expand(sub[0..n], "ss-subkey", HkdfSha1.extract(salt, key[0..n]));
        }
        return .{ .aead = switch (m) {
            .aes_128_gcm, .blake3_aes_128_gcm => .{ .aes128 = .init(sub[0..16].*) },
            .aes_256_gcm, .blake3_aes_256_gcm => .{ .aes256 = .init(sub) },
            else => .{ .key = sub },
        } };
    }

    /// Seal `buf` in place.
    fn seal(c: *Cipher, m: Method, buf: []u8, tag: *[tag_len]u8) void {
        switch (m) {
            .aes_128_gcm, .blake3_aes_128_gcm => c.aead.aes128.encrypt(buf, tag, buf, c.nonce[0..12].*),
            .aes_256_gcm, .blake3_aes_256_gcm => c.aead.aes256.encrypt(buf, tag, buf, c.nonce[0..12].*),
            inline else => |mm| {
                const A = mm.Aead();
                A.encrypt(buf, tag, buf, "", c.nonce[0..A.nonce_length].*, c.aead.key);
            },
        }
        c.next();
    }

    /// Open a chunk (ciphertext, then tag) in place; returns the plaintext.
    fn open(c: *Cipher, m: Method, chunk: []u8) error{SsAuthFailed}![]u8 {
        const n = chunk.len - tag_len;
        try c.openTo(m, chunk[0..n], chunk[0..n], chunk[n..][0..tag_len].*);
        return chunk[0..n];
    }

    /// Open `src` into `dst`, which is `src` itself or starts before it in
    /// the same buffer.
    fn openTo(c: *Cipher, m: Method, dst: []u8, src: []const u8, tag: [tag_len]u8) error{SsAuthFailed}!void {
        (switch (m) {
            .aes_128_gcm, .blake3_aes_128_gcm => c.aead.aes128.decrypt(dst, src, tag, c.nonce[0..12].*),
            .aes_256_gcm, .blake3_aes_256_gcm => c.aead.aes256.decrypt(dst, src, tag, c.nonce[0..12].*),
            inline else => |mm| mm.Aead().decrypt(dst, src, tag, "", c.nonce[0..mm.Aead().nonce_length].*, c.aead.key),
        }) catch return error.SsAuthFailed;
        c.next();
    }

    fn next(c: *Cipher) void {
        for (&c.nonce) |*b| {
            b.* +%= 1;
            if (b.* != 0) break;
        }
    }
};

pub const Error = error{
    /// A chunk did not open: a wrong password or key, a server that is not
    /// Shadowsocks, or a stream changed on the way.
    SsAuthFailed,
    /// 2022: the answer is not to our request (its type, or the salt it echoes).
    SsBadResponse,
    /// 2022: the server's clock is more than 30 s from ours (it refuses our
    /// requests for the same reason).
    SsClockSkew,
    /// A chunk length of zero (2022) or above what the method allows.
    SsBadLength,
    /// A chunk larger than the read buffer.
    SsBufferTooSmall,
    /// The stream ended inside a chunk or a header.
    SsTruncated,
};

pub const Conn = struct {
    io: Io,
    method: Method,
    /// the stream below
    r: *Io.Reader,
    w: *Io.Writer,
    /// what the server sends, opened
    reader: Io.Reader,
    /// what we send; every flush (or full buffer) leaves as one chunk
    writer: Io.Writer,
    /// Why `reader` failed, if the stream below did not.
    err: ?Error = null,

    // fixed after init
    key: [32]u8,
    identities: [max_identities][32]u8,
    identity_count: u8,
    /// our salt, which a 2022 answer echoes
    salt: [32]u8,
    /// the destination in SOCKS5 form, for the request
    addr: [address_max]u8 = undefined,
    addr_len: u16 = 0,

    // the writer's own
    /// the caller's write buffer: `writer.buffer` is its tail, the head is
    /// room for the request (first flush) and length chunks (after)
    wbuf: []u8,
    send: Cipher,
    /// the request has not gone yet
    pending: bool = true,

    // the reader's own
    recv: Cipher = .{},
    rstate: enum { head, chunks, eof, failed } = .head,
    /// ciphertext read but not opened yet: `reader.buffer[raw_start..raw_end]`,
    /// always behind the plaintext (`reader.end <= raw_start`)
    raw_start: usize = 0,
    raw_end: usize = 0,
    /// the length of the payload chunk next in the ciphertext, once known
    /// (its length chunk opened, or the 2022 header gave it)
    next_len: ?u16 = null,
    /// AEAD: the server's empty chunk came, the stream ends after what is open
    ended: bool = false,

    /// `rbuf` holds a whole chunk (see `readBufferLen`); `wbuf` is best
    /// `write_buffer_len` and must exceed the request's room by a byte.
    /// The interfaces point back into the result: keep it at one address.
    pub fn init(io: Io, ss: *const Shadowsocks, target: *const Target, r: *Io.Reader, w: *Io.Writer, rbuf: []u8, wbuf: []u8) Conn {
        var salt: [32]u8 = undefined;
        io.random(&salt);
        return initSalted(io, ss, target, r, w, rbuf, wbuf, salt);
    }

    fn initSalted(io: Io, ss: *const Shadowsocks, target: *const Target, r: *Io.Reader, w: *Io.Writer, rbuf: []u8, wbuf: []u8, salt: [32]u8) Conn {
        const m = ss.method;
        var c: Conn = .{
            .io = io,
            .method = m,
            .r = r,
            .w = w,
            .reader = .{ .vtable = &.{ .stream = stream, .readVec = readVec }, .buffer = rbuf, .seek = 0, .end = 0 },
            .writer = undefined,
            .key = ss.key,
            .identities = ss.identities,
            .identity_count = ss.identity_count,
            .salt = salt,
            .wbuf = wbuf,
            .send = .init(m, &ss.key, salt[0..m.keyLen()]),
        };
        var aw: Io.Writer = .fixed(&c.addr);
        writeAddress(&aw, target) catch unreachable;
        c.addr_len = @intCast(aw.end);
        const room = c.headRoom();
        // the first chunk carries the request too and must stay in bounds
        const first_max = if (m.is2022()) 0xffff - (c.addr_len + 2 + max_padding) else 0x3fff - c.addr_len;
        std.debug.assert(wbuf.len > room);
        c.writer = .{ .vtable = &.{ .drain = drain, .flush = flush }, .buffer = wbuf[room..][0..@min(wbuf.len - room, first_max)] };
        return c;
    }

    /// Room in front of `writer.buffer`: what the first flush puts before
    /// the data. Later chunks use its last `len_chunk` bytes.
    fn headRoom(c: *const Conn) usize {
        const n = c.method.keyLen();
        return if (c.method.is2022())
            n + 16 * @as(usize, c.identity_count) + fixed_request + tag_len + c.addr_len + 2 + max_padding
        else
            n + len_chunk + c.addr_len;
    }

    // ------------------------------------------------------------ writing

    fn drain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const c: *Conn = @alignCast(@fieldParentPtr("writer", io_w));
        // top the buffer up and send it whole, so chunks are as large as it
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
        try c.sendBuffered();
        try c.w.flush();
    }

    /// What `writer` holds leaves as one chunk; the first time, with the
    /// request in front even if nothing is buffered.
    fn sendBuffered(c: *Conn) Io.Writer.Error!void {
        const m = c.method;
        const data = c.writer.buffered();
        const room = c.headRoom();
        if (!c.pending and data.len == 0) return; // an empty chunk ends the stream for Xray
        var tag: [tag_len]u8 = undefined;
        var start = room - len_chunk;
        if (!c.pending) {
            // a length chunk in the last bytes of the room, then the data
            const lc = c.wbuf[start..][0..len_chunk];
            std.mem.writeInt(u16, lc[0..2], @intCast(data.len), .big);
            c.send.seal(m, lc[0..2], lc[2..]);
            c.send.seal(m, data, &tag);
        } else if (!m.is2022()) {
            // salt, length chunk, then destination and data as one chunk
            const a = room - c.addr_len;
            @memcpy(c.wbuf[a..room], c.addr[0..c.addr_len]);
            start = a - len_chunk - m.keyLen();
            @memcpy(c.wbuf[start..][0..m.keyLen()], c.salt[0..m.keyLen()]);
            const lc = c.wbuf[a - len_chunk ..][0..len_chunk];
            std.mem.writeInt(u16, lc[0..2], @intCast(c.addr_len + data.len), .big);
            c.send.seal(m, lc[0..2], lc[2..]);
            c.send.seal(m, c.wbuf[a .. room + data.len], &tag);
        } else {
            start = c.request2022(data.len, &tag);
        }
        c.pending = false;
        c.writer.end = 0;
        var vec = [_][]const u8{ c.wbuf[start .. room + data.len], &tag };
        try c.w.writeVecAll(&vec);
    }

    /// Lay the 2022 request out in front of the `n` bytes of data and seal
    /// it: salt, identity headers, fixed header, then the variable header
    /// (destination, padding, data), whose tag goes to `tag`. Returns where
    /// it starts in `wbuf`.
    fn request2022(c: *Conn, n: usize, tag: *[tag_len]u8) usize {
        const m = c.method;
        const kl = m.keyLen();
        const room = c.headRoom();
        // a request must carry data or padding; pad short ones as Xray does
        var pad: usize = 0;
        if (n < max_padding) {
            var b: [2]u8 = undefined;
            c.io.random(&b);
            pad = 1 + std.mem.readInt(u16, &b, .little) % max_padding;
        }
        const var_start = room - (c.addr_len + 2 + pad);
        @memcpy(c.wbuf[var_start..][0..c.addr_len], c.addr[0..c.addr_len]);
        std.mem.writeInt(u16, c.wbuf[var_start + c.addr_len ..][0..2], @intCast(pad), .big);
        @memset(c.wbuf[room - pad .. room], 0);

        const f = c.wbuf[var_start - (fixed_request + tag_len) .. var_start];
        f[0] = 0; // client stream
        std.mem.writeInt(i64, f[1..9], Io.Clock.real.now(c.io).toSeconds(), .big);
        std.mem.writeInt(u16, f[9..11], @intCast(c.addr_len + 2 + pad + n), .big);
        c.send.seal(m, f[0..fixed_request], f[fixed_request..][0..tag_len]);
        c.send.seal(m, c.wbuf[var_start .. room + n], tag);

        const ids = c.identity_count;
        const start = var_start - (fixed_request + tag_len) - 16 * @as(usize, ids) - kl;
        @memcpy(c.wbuf[start..][0..kl], c.salt[0..kl]);
        for (0..ids) |i| {
            const next = if (i + 1 < ids) &c.identities[i + 1] else &c.key;
            identityHeader(m, c.identities[i][0..kl], c.salt[0..kl], next[0..kl], c.wbuf[start + kl + 16 * i ..][0..16]);
        }
        return start;
    }

    // ------------------------------------------------------------ reading

    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        _ = w;
        _ = limit;
        const c: *Conn = @alignCast(@fieldParentPtr("reader", io_r));
        try c.fillChunk();
        return 0;
    }

    fn readVec(io_r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        _ = data;
        const c: *Conn = @alignCast(@fieldParentPtr("reader", io_r));
        try c.fillChunk();
        return 0;
    }

    /// Open the next chunks into `reader.buffer`, after what is unread.
    fn fillChunk(c: *Conn) Io.Reader.Error!void {
        switch (c.rstate) {
            .eof => return error.EndOfStream,
            .failed => return error.ReadFailed,
            .head, .chunks => {},
        }
        c.nextChunks() catch |e| {
            c.rstate = if (e == error.EndOfStream) .eof else .failed;
            return e;
        };
    }

    /// Every chunk the ciphertext read so far holds whole, opened end to
    /// end behind the unread plaintext; with none whole, read first. One
    /// read takes what the socket has, often several chunks (Xray sends 8
    /// KiB ones), so the bytes cost one read here and one write in the
    /// copy loop above, not two reads and a write per chunk.
    fn nextChunks(c: *Conn) Io.Reader.Error!void {
        if (c.rstate == .head) {
            try c.readHead();
            c.rstate = .chunks;
        }
        while (true) {
            if (try c.openWhole()) return;
            if (c.ended) return error.EndOfStream;
            try c.readRaw();
        }
    }

    /// The server's salt, and with 2022 its fixed header, which gives the
    /// length of the first payload chunk.
    fn readHead(c: *Conn) Io.Reader.Error!void {
        const m = c.method;
        const kl = m.keyLen();
        var salt: [32]u8 = undefined;
        const got = try c.r.readSliceShort(salt[0..kl]);
        if (got == 0) return error.EndOfStream; // closed without a word
        if (got < kl) return c.fail(error.SsTruncated);
        // our own salt back means our own upload reflected at us: with it
        // every chunk we sent would pass as the server's answer
        if (std.mem.eql(u8, salt[0..kl], c.salt[0..kl])) return c.fail(error.SsBadResponse);
        c.recv = .init(m, &c.key, salt[0..kl]);
        if (!m.is2022()) return;

        // type, timestamp, our salt, length of the first payload chunk
        var buf: [1 + 8 + 32 + 2 + tag_len]u8 = undefined;
        const f = buf[0 .. 1 + 8 + kl + 2 + tag_len];
        if (try c.r.readSliceShort(f) < f.len) return c.fail(error.SsTruncated);
        const h = c.recv.open(m, f) catch return c.fail(error.SsAuthFailed);
        if (h[0] != 1 or !std.mem.eql(u8, h[9..][0..kl], c.salt[0..kl])) return c.fail(error.SsBadResponse);
        const skew = @as(i128, Io.Clock.real.now(c.io).toSeconds()) - std.mem.readInt(u64, h[1..9], .big);
        if (skew > 30 or skew < -30) return c.fail(error.SsClockSkew);
        const first = std.mem.readInt(u16, h[9 + kl ..][0..2], .big);
        if (first > 0) c.next_len = first;
    }

    /// Open the chunks that are whole in the ciphertext read so far, each
    /// payload to the end of the plaintext (no copy: the decryption itself
    /// moves it there). True if that added any.
    fn openWhole(c: *Conn) Io.Reader.Error!bool {
        const m = c.method;
        const r = &c.reader;
        const buf = r.buffer;
        var any = false;
        while (!c.ended) {
            const len = c.next_len orelse len: {
                if (c.raw_end - c.raw_start < len_chunk) break;
                const lc = buf[c.raw_start..][0..len_chunk];
                const n = std.mem.readInt(u16, (c.recv.open(m, lc) catch return c.fail(error.SsAuthFailed))[0..2], .big);
                c.raw_start += len_chunk;
                // Xray's own AEAD stream ends with an empty chunk; 2022 has none
                if (n == 0) {
                    if (m.is2022()) return c.fail(error.SsBadLength);
                    c.ended = true;
                    break;
                }
                if (n > m.maxChunk()) return c.fail(error.SsBadLength);
                c.next_len = n;
                break :len n;
            };
            if (c.raw_end - c.raw_start < len + tag_len) break;
            if (r.seek == r.end) {
                r.seek = 0;
                r.end = 0;
            }
            const src = buf[c.raw_start..][0..len];
            c.recv.openTo(m, buf[r.end..][0..len], src, buf[c.raw_start + len ..][0..tag_len].*) catch
                return c.fail(error.SsAuthFailed);
            r.end += len;
            c.raw_start += len + tag_len;
            c.next_len = null;
            any = true;
        }
        if (c.raw_start == c.raw_end) {
            c.raw_start = r.end;
            c.raw_end = r.end;
        }
        return any;
    }

    /// Read more ciphertext behind what is there: what the stream below
    /// has buffered, else one read of as much as it has, into all the room
    /// left. (Not `readVec` with buffered bytes there: after copying them
    /// it reads again, and waits for bytes the server may only send once
    /// these are answered.)
    fn readRaw(c: *Conn) Io.Reader.Error!void {
        const r = &c.reader;
        const buf = r.buffer;
        if (r.seek == r.end and c.raw_start == c.raw_end) {
            r.seek = 0;
            r.end = 0;
            c.raw_start = 0;
            c.raw_end = 0;
        }
        // the rest of the next chunk must fit behind what is read of it
        const need = if (c.next_len) |n| @as(usize, n) + tag_len else len_chunk;
        if (buf.len - c.raw_start < need) {
            // move the unread plaintext to the front, the ciphertext behind it
            const keep = r.end - r.seek;
            const have = c.raw_end - c.raw_start;
            if (keep + need > buf.len) return c.fail(error.SsBufferTooSmall);
            std.mem.copyForwards(u8, buf[0..keep], buf[r.seek..r.end]);
            r.seek = 0;
            r.end = keep;
            std.mem.copyForwards(u8, buf[keep..][0..have], buf[c.raw_start..c.raw_end]);
            c.raw_start = keep;
            c.raw_end = keep + have;
        }
        const room = buf[c.raw_end..];
        const below = c.r.buffered();
        if (below.len > 0) {
            const k = @min(below.len, room.len);
            @memcpy(room[0..k], below[0..k]);
            c.r.toss(k);
            c.raw_end += k;
            return;
        }
        var vec = [_][]u8{room};
        const n = c.r.readVec(&vec) catch |e| switch (e) {
            error.EndOfStream => return if (c.raw_start == c.raw_end and c.next_len == null)
                error.EndOfStream
            else
                c.fail(error.SsTruncated),
            else => |ee| return ee,
        };
        c.raw_end += n;
    }

    fn fail(c: *Conn, e: Error) error{ReadFailed} {
        c.err = e;
        return error.ReadFailed;
    }
};

/// SIP022 identity header: the first 16 bytes of BLAKE3(next PSK), AES
/// encrypted with a key derived from this PSK and the salt.
fn identityHeader(m: Method, psk: []const u8, salt: []const u8, next: []const u8, out: *[16]u8) void {
    var hash: [16]u8 = undefined;
    crypto.hash.Blake3.hash(next, &hash, .{});
    var sub: [32]u8 = undefined;
    deriveKey("shadowsocks 2022 identity subkey", psk, salt, sub[0..psk.len]);
    switch (m) {
        .blake3_aes_128_gcm => crypto.core.aes.Aes128.initEnc(sub[0..16].*).encrypt(out, &hash),
        .blake3_aes_256_gcm => crypto.core.aes.Aes256.initEnc(sub).encrypt(out, &hash),
        else => unreachable, // refused when the keys were parsed
    }
}

// ---------------------------------------------------------------- tests

// ---------------------------------------------------------------- UDP

/// Shadowsocks UDP: every datagram is sealed on its own and goes to the
/// server's UDP port, naming its peer inside, so one socket carries one
/// application socket to any number of peers.
///
///   AEAD:  [salt][sealed: address, payload][tag]; the subkey comes from a
///          new salt in every packet, the nonce is zero.
///   2022 with AES (SIP022): [separate header, one AES block under the
///          PSK: session id 8, packet id 8][sealed body][tag]; the body
///          under the session's subkey (BLAKE3 of the PSK and the session
///          id), its nonce the header's last 12 bytes. Body: type (0 from
///          the client, 1 from the server), timestamp, for the server our
///          session id, padding length and padding, address, payload.
///   2022 with ChaCha: [random nonce 24][XChaCha20-Poly1305 under the PSK
///          of: session id, packet id, then the body as above].
///
/// The server has sessions of its own (one per our session, a new one
/// after a restart); their subkeys and replay windows are kept for the
/// last two seen. Identity headers (relays, multi-user servers) are not
/// carried over UDP here: `Udp.init` refuses such a server.
pub const Udp = struct {
    method: Method,
    key: [32]u8,
    session: [8]u8,
    packet: u64 = 0,
    /// 2022 with AES: ours, made once
    send_aead: ?SessionAead = null,
    servers: [2]?ServerSession = .{ null, null },
    /// which of `servers` goes next
    next_slot: u1 = 0,

    pub const overhead_max = 32 + tag_len + 24 + 1 + 8 + 8 + 2 + address_max;

    const SessionAead = union(enum) {
        aes128: aes_gcm.Aes128Gcm,
        aes256: aes_gcm.Aes256Gcm,

        fn of(m: Method, psk: []const u8, session: []const u8) SessionAead {
            var sub: [32]u8 = undefined;
            defer crypto.secureZero(u8, &sub);
            deriveKey("shadowsocks 2022 session subkey", psk[0..m.keyLen()], session, sub[0..m.keyLen()]);
            return if (m == .blake3_aes_128_gcm) .{ .aes128 = .init(sub[0..16].*) } else .{ .aes256 = .init(sub) };
        }

        fn seal(a: *const SessionAead, buf: []u8, tag: *[tag_len]u8, nonce: [12]u8) void {
            switch (a.*) {
                inline else => |*x| x.encrypt(buf, tag, buf, nonce),
            }
        }

        fn open(a: *const SessionAead, buf: []u8, tag: [tag_len]u8, nonce: [12]u8) error{AuthenticationFailed}!void {
            switch (a.*) {
                inline else => |*x| try x.decrypt(buf, buf, tag, nonce),
            }
        }
    };

    const ServerSession = struct {
        id: [8]u8,
        aead: ?SessionAead,
        window: Window = .{},
    };

    /// Packet ids seen: the highest, and the 64 below it.
    const Window = struct {
        top: u64 = 0,
        bits: u64 = 0,
        any: bool = false,

        fn check(w: *const Window, id: u64) bool {
            if (!w.any or id > w.top) return true;
            const back = w.top - id;
            return back < 64 and w.bits & (@as(u64, 1) << @intCast(back)) == 0;
        }

        fn mark(w: *Window, id: u64) void {
            if (!w.any or id > w.top) {
                const shift = if (w.any) id - w.top else 64;
                w.bits = if (shift >= 64) 0 else w.bits << @intCast(shift);
                w.top = id;
                w.any = true;
            }
            w.bits |= @as(u64, 1) << @intCast(w.top - id);
        }
    };

    pub const InitError = error{UdpNotSupported};

    pub fn init(io: Io, ss: *const Shadowsocks) InitError!Udp {
        if (ss.identity_count > 0) return error.UdpNotSupported;
        var u: Udp = .{ .method = ss.method, .key = ss.key, .session = undefined };
        io.random(&u.session);
        if (u.method == .blake3_aes_128_gcm or u.method == .blake3_aes_256_gcm)
            u.send_aead = .of(u.method, &u.key, &u.session);
        return u;
    }

    pub fn deinit(u: *Udp) void {
        crypto.secureZero(u8, &u.key);
    }

    /// Seal a datagram for `to` into `out`; returns the packet.
    pub fn seal(u: *Udp, io: Io, out: []u8, to: *const Target, payload: []const u8) error{NoSpaceLeft}![]u8 {
        const m = u.method;
        const kl = m.keyLen();
        var w: Io.Writer = .fixed(out);
        switch (m) {
            .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305, .xchacha20_poly1305 => {
                var salt: [32]u8 = undefined;
                io.random(salt[0..kl]);
                w.writeAll(salt[0..kl]) catch return error.NoSpaceLeft;
                const start = w.end;
                writeAddress(&w, to) catch return error.NoSpaceLeft;
                w.writeAll(payload) catch return error.NoSpaceLeft;
                const body = out[start..w.end];
                if (out.len - w.end < tag_len) return error.NoSpaceLeft;
                var c: Cipher = .init(m, &u.key, salt[0..kl]);
                c.seal(m, body, out[w.end..][0..tag_len]);
                return out[0 .. w.end + tag_len];
            },
            .blake3_aes_128_gcm, .blake3_aes_256_gcm => {
                if (out.len < 16) return error.NoSpaceLeft;
                var header: [16]u8 = undefined;
                header[0..8].* = u.session;
                std.mem.writeInt(u64, header[8..16], u.packet, .big);
                u.packet += 1;
                w.end = 16;
                const start = w.end;
                try writeBody(&w, io, null, to, payload);
                if (out.len - w.end < tag_len) return error.NoSpaceLeft;
                u.send_aead.?.seal(out[start..w.end], out[w.end..][0..tag_len], header[4..16].*);
                blockEncrypt(m, &u.key, &header, out[0..16]);
                return out[0 .. w.end + tag_len];
            },
            .blake3_chacha20_poly1305 => {
                var nonce: [24]u8 = undefined;
                io.random(&nonce);
                w.writeAll(&nonce) catch return error.NoSpaceLeft;
                const start = w.end;
                w.writeAll(&u.session) catch return error.NoSpaceLeft;
                w.writeInt(u64, u.packet, .big) catch return error.NoSpaceLeft;
                u.packet += 1;
                try writeBody(&w, io, null, to, payload);
                if (out.len - w.end < tag_len) return error.NoSpaceLeft;
                const body = out[start..w.end];
                crypto.aead.chacha_poly.XChaCha20Poly1305.encrypt(body, out[w.end..][0..tag_len], body, "", nonce, u.key);
                return out[0 .. w.end + tag_len];
            },
        }
    }

    /// type, timestamp, (server: the client's session), padding, address, payload
    fn writeBody(w: *Io.Writer, io: Io, client_session: ?[8]u8, to: *const Target, payload: []const u8) error{NoSpaceLeft}!void {
        w.writeByte(if (client_session == null) 0 else 1) catch return error.NoSpaceLeft;
        w.writeInt(u64, @intCast(@max(0, Io.Clock.real.now(io).toSeconds())), .big) catch return error.NoSpaceLeft;
        if (client_session) |cs| w.writeAll(&cs) catch return error.NoSpaceLeft;
        w.writeInt(u16, 0, .big) catch return error.NoSpaceLeft;
        writeAddress(w, to) catch return error.NoSpaceLeft;
        w.writeAll(payload) catch return error.NoSpaceLeft;
    }

    pub const Datagram = struct { from: Target, payload: []u8 };

    pub const OpenError = error{ SsAuthFailed, SsBadPacket, SsClockSkew, SsReplay };

    /// Open a packet from the server, in place.
    pub fn open(u: *Udp, io: Io, pkt: []u8) OpenError!Datagram {
        const m = u.method;
        const kl = m.keyLen();
        switch (m) {
            .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305, .xchacha20_poly1305 => {
                if (pkt.len < kl + tag_len) return error.SsBadPacket;
                const body = pkt[kl .. pkt.len - tag_len];
                var c: Cipher = .init(m, &u.key, pkt[0..kl]);
                _ = c.open(m, pkt[kl..]) catch return error.SsAuthFailed;
                return parseTail(body);
            },
            .blake3_aes_128_gcm, .blake3_aes_256_gcm => {
                if (pkt.len < 16 + tag_len) return error.SsBadPacket;
                var header: [16]u8 = undefined;
                blockDecrypt(m, &u.key, pkt[0..16], &header);
                const id = std.mem.readInt(u64, header[8..16], .big);
                const s = u.server(header[0..8].*, true);
                if (!s.window.check(id)) return error.SsReplay;
                const body = pkt[16 .. pkt.len - tag_len];
                s.aead.?.open(body, pkt[pkt.len - tag_len ..][0..tag_len].*, header[4..16].*) catch return error.SsAuthFailed;
                const d = try u.parseBody(io, body);
                s.window.mark(id);
                return d;
            },
            .blake3_chacha20_poly1305 => {
                if (pkt.len < 24 + 16 + tag_len) return error.SsBadPacket;
                const body = pkt[24 .. pkt.len - tag_len];
                crypto.aead.chacha_poly.XChaCha20Poly1305.decrypt(body, body, pkt[pkt.len - tag_len ..][0..tag_len].*, "", pkt[0..24].*, u.key) catch
                    return error.SsAuthFailed;
                const id = std.mem.readInt(u64, body[8..16], .big);
                const s = u.server(body[0..8].*, false);
                if (!s.window.check(id)) return error.SsReplay;
                const d = try u.parseBody(io, body[16..]);
                s.window.mark(id);
                return d;
            },
        }
    }

    /// The server session `id`: a known one, or the older slot made over.
    fn server(u: *Udp, id: [8]u8, aes: bool) *ServerSession {
        for (&u.servers) |*slot| if (slot.*) |*s| if (std.mem.eql(u8, &s.id, &id)) return s;
        const slot = &u.servers[u.next_slot];
        u.next_slot +%= 1;
        slot.* = .{ .id = id, .aead = if (aes) SessionAead.of(u.method, &u.key, &id) else null };
        return &slot.*.?;
    }

    fn parseBody(u: *const Udp, io: Io, body: []u8) OpenError!Datagram {
        if (body.len < 1 + 8 + 8 + 2) return error.SsBadPacket;
        if (body[0] != 1) return error.SsBadPacket;
        const skew = @as(i128, Io.Clock.real.now(io).toSeconds()) - std.mem.readInt(u64, body[1..9], .big);
        if (skew > 30 or skew < -30) return error.SsClockSkew;
        // an answer to another client's session is not ours
        if (!std.mem.eql(u8, body[9..17], &u.session)) return error.SsBadPacket;
        const pad = std.mem.readInt(u16, body[17..19], .big);
        if (19 + @as(usize, pad) > body.len) return error.SsBadPacket;
        return parseTail(body[19 + pad ..]);
    }

    /// A SOCKS address, then the payload.
    fn parseTail(b: []u8) OpenError!Datagram {
        var r: Io.Reader = .fixed(b);
        const from = @import("trojan.zig").readAddress(&r) catch return error.SsBadPacket;
        return .{ .from = from, .payload = b[r.seek..] };
    }

    fn blockEncrypt(m: Method, key: *const [32]u8, in: *const [16]u8, out: *[16]u8) void {
        if (m == .blake3_aes_128_gcm) crypto.core.aes.Aes128.initEnc(key[0..16].*).encrypt(out, in) else crypto.core.aes.Aes256.initEnc(key.*).encrypt(out, in);
    }

    fn blockDecrypt(m: Method, key: *const [32]u8, in: *const [16]u8, out: *[16]u8) void {
        if (m == .blake3_aes_128_gcm) crypto.core.aes.Aes128.initDec(key[0..16].*).decrypt(out, in) else crypto.core.aes.Aes256.initDec(key.*).decrypt(out, in);
    }
};

const testing = std.testing;

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "method names and sizes" {
    try testing.expectEqual(.chacha20_poly1305, Method.fromName("CHACHA20-IETF-POLY1305").?);
    try testing.expectEqual(.chacha20_poly1305, Method.fromName("chacha20-poly1305").?);
    try testing.expectEqual(.xchacha20_poly1305, Method.fromName("xchacha20-ietf-poly1305").?);
    try testing.expectEqual(.blake3_aes_256_gcm, Method.fromName("2022-blake3-aes-256-gcm").?);
    try testing.expect(Method.fromName("rc4-md5") == null);
    try testing.expect(Method.fromName("none") == null);
    try testing.expectEqual(16, Method.aes_128_gcm.keyLen());
    try testing.expectEqual(32, Method.blake3_chacha20_poly1305.keyLen());
    try testing.expectEqual(0x3fff + 16, readBufferLen(.aes_256_gcm));
    try testing.expectEqual(0xffff + 16, readBufferLen(.blake3_aes_128_gcm));
}

test "key derivation against independent vectors" {
    // openssl enc -aes-256-cbc -k foobar -nosalt -P -md md5
    var key: [32]u8 = undefined;
    bytesToKey("foobar", &key);
    try testing.expectEqualSlices(u8, &fromHex("3858f62230ac3c915f300c664312c63f568378529614d22ddb49237d2f60bfdf"), &key);
    bytesToKey("foobar", key[0..16]);
    try testing.expectEqualSlices(u8, &fromHex("3858f62230ac3c915f300c664312c63f"), key[0..16]);
    // RFC 5869 test case 4 (HKDF-SHA1)
    var okm: [42]u8 = undefined;
    HkdfSha1.expand(&okm, &fromHex("f0f1f2f3f4f5f6f7f8f9"), HkdfSha1.extract(&fromHex("000102030405060708090a0b0c"), &@as([11]u8, @splat(0x0b))));
    try testing.expectEqualSlices(u8, &fromHex("085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"), &okm);
    // BLAKE3 derive_key, official test vector for an empty input
    var dk: [32]u8 = undefined;
    deriveKey("BLAKE3 2019-12-27 16:29:52 test vectors context", "", "", &dk);
    try testing.expectEqualSlices(u8, &fromHex("2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"), &dk);
}

/// Stream vectors made with Go's crypto/aes, crypto/cipher and
/// x/crypto/chacha20poly1305: password "foobar", salt 00 01 02 ..., chunks
/// "\x03\x0bexample.com\x00\x50GET / HTTP/1.1\r\n" and
/// "Host: example.com\r\n\r\n".
const go_vectors = [_]struct { Method, []const u8 }{
    .{ .aes_128_gcm, "000102030405060708090a0b0c0d0e0ff8511c237690c995d85382877ac822090d613c0fc8a22dda49f5462a585eb764a006b81c0dadbbca471fb4e4ba2585eff4b21576fe522913a018135bdbbabd5c5a48759d8f1b2ad8b78c7322f5e1b7593245a1fdbf613e7f099e712c2ad619590d77ddf6371be00336301355743b0cb85cf7ce5a2115948c" },
    .{ .aes_256_gcm, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f26e3bc3d12580f1ca40c160f7d5f980ef0d7241815b04c2dd91251e282d8589929080d6537ba418a416c0fa94437cde13addd00d17b7a1f1a37a46efe9f1929a489fec077f790cfb55777d32a3a79f8764cdf691caa8b0af58201ac6590eea7b07fe156da1ca89dd5bbbfa4e43c51a7eab4153dd5dd9afa2" },
    .{ .chacha20_poly1305, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f5d884e824e4aa60e49e3eeb0fec3af20f86cac89d42411949fff2de8a5e263a062e62515e9a8c5e81437f00724cb1c6692ac936f49a0c37cbf33967c8e869322a1f8330da63e9d2e1521c95019296d4474135770d94e558b912c694a3432a730c4aadffa154d6cea29eead306b1ac4274f371e020fd28626" },
    .{ .xchacha20_poly1305, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2c01ee4810adf41f6c74556bc5bbd1f04796916634f24e4b4b185dbc9e360a0dad56c7873c610785f4c268591f1e4226f87c25f072dba7c22b1b5b764c9a18ffc9a4daff1356c4efe15987df49816a4fcceb1099389ab8d2a6695e2549e8a92835c0966732edc7788b0e26a9d1423a1833ff7c1f37ab996e" },
};

fn counting() [32]u8 {
    var s: [32]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = @intCast(i);
    return s;
}

test "AEAD streams match an independent implementation both ways" {
    const io = testing.io;
    const target = Target.fromDomain("example.com", 80);
    inline for (go_vectors) |v| {
        const expect = fromHex(v[1]);
        const ss: Shadowsocks = try .init(v[0], "foobar", "h", 1);

        var out: [1024]u8 = undefined;
        var sink: Io.Writer = .fixed(&out);
        var nothing: Io.Reader = .fixed("");
        var rbuf: [64]u8 = undefined;
        var wbuf: [write_buffer_len]u8 = undefined;
        var c: Conn = .initSalted(io, &ss, &target, &nothing, &sink, &rbuf, &wbuf, counting());
        try c.writer.writeAll("GET / HTTP/1.1\r\n");
        try c.writer.flush();
        try c.writer.writeAll("Host: example.com\r\n\r\n");
        try c.writer.flush();
        try c.writer.flush(); // nothing buffered: no chunk
        try testing.expectEqualSlices(u8, &expect, sink.buffered());

        // the answer has the same shape: read it back as if from the server
        var down: Io.Reader = .fixed(&expect);
        var big: [readBufferLen(v[0])]u8 = undefined;
        var d: Conn = .init(io, &ss, &target, &down, &sink, &big, &wbuf);
        var got: [128]u8 = undefined;
        var gw: Io.Writer = .fixed(&got);
        _ = try d.reader.streamRemaining(&gw);
        try testing.expectEqualStrings("\x03\x0bexample.com\x00\x50GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", gw.buffered());

        // a changed byte, a cut stream, a short read buffer
        var bad = expect;
        bad[40] ^= 1;
        var bad_r: Io.Reader = .fixed(&bad);
        var e: Conn = .init(io, &ss, &target, &bad_r, &sink, &big, &wbuf);
        try testing.expectError(error.ReadFailed, e.reader.peekGreedy(1));
        try testing.expectEqual(error.SsAuthFailed, e.err.?);
        try testing.expectError(error.ReadFailed, e.reader.peekGreedy(1)); // and stays failed

        var cut_r: Io.Reader = .fixed(expect[0 .. expect.len - 3]);
        var t: Conn = .init(io, &ss, &target, &cut_r, &sink, &big, &wbuf);
        try testing.expectEqual(31, (try t.reader.peekGreedy(1)).len); // the first chunk is whole
        t.reader.tossBuffered();
        try testing.expectError(error.ReadFailed, t.reader.peekGreedy(1));
        try testing.expectEqual(error.SsTruncated, t.err.?);

        var small_r: Io.Reader = .fixed(&expect);
        var small: [20]u8 = undefined;
        var s: Conn = .init(io, &ss, &target, &small_r, &sink, &small, &wbuf);
        try testing.expectError(error.ReadFailed, s.reader.peekGreedy(1));
        try testing.expectEqual(error.SsBufferTooSmall, s.err.?);
    }
}

test "AEAD: an empty answer, Xray's empty end chunk, long writes split" {
    const io = testing.io;
    const target = Target.fromDomain("example.com", 80);
    const ss: Shadowsocks = try .init(.aes_128_gcm, "pw", "h", 1);
    var sink_buf: [70000]u8 = undefined;
    var sink: Io.Writer = .fixed(&sink_buf);
    var rbuf: [readBufferLen(.aes_128_gcm)]u8 = undefined;
    var wbuf: [write_buffer_len]u8 = undefined;

    var empty: Io.Reader = .fixed("");
    var c: Conn = .init(io, &ss, &target, &empty, &sink, &rbuf, &wbuf);
    try testing.expectError(error.EndOfStream, c.reader.peekGreedy(1));
    try testing.expect(c.err == null);

    // 40000 bytes in one write: chunks of what the buffer holds
    const data: [40000]u8 = @splat('x');
    try c.writer.writeAll(&data);
    try c.writer.flush();
    var server: Io.Reader = .fixed(sink.buffered());
    var rx: Cipher = .init(.aes_128_gcm, &ss.key, (try server.takeArray(16))[0..]);
    var total: usize = 0;
    var chunks: usize = 0;
    while (server.bufferedLen() > 0) : (chunks += 1) {
        var lc = (try server.takeArray(len_chunk)).*;
        const n = std.mem.readInt(u16, (try rx.open(.aes_128_gcm, &lc))[0..2], .big);
        try testing.expect(n <= 0x3fff);
        const p = try rx.open(.aes_128_gcm, try server.take(n + tag_len));
        if (chunks == 0) {
            try testing.expectEqualSlices(u8, c.addr[0..c.addr_len], p[0..c.addr_len]);
            total += p.len - c.addr_len;
        } else total += p.len;
    }
    try testing.expectEqual(data.len, total);
    try testing.expectEqual(3, chunks);

    // the server's stream ends with an empty chunk (Xray's AEAD writer)
    var down_buf: [200]u8 = undefined;
    var down: Io.Writer = .fixed(&down_buf);
    const salt: [16]u8 = @splat(7);
    try down.writeAll(&salt);
    var tx: Cipher = .init(.aes_128_gcm, &ss.key, &salt);
    for ([_][]const u8{ "hi", "" }) |p| {
        var lc: [len_chunk]u8 = undefined;
        std.mem.writeInt(u16, lc[0..2], @intCast(p.len), .big);
        tx.seal(.aes_128_gcm, lc[0..2], lc[2..]);
        try down.writeAll(&lc);
        var body: [2 + tag_len]u8 = undefined;
        @memcpy(body[0..p.len], p);
        tx.seal(.aes_128_gcm, body[0..p.len], body[p.len..][0..tag_len]);
        try down.writeAll(body[0 .. p.len + tag_len]);
    }
    var dr: Io.Reader = .fixed(down.buffered());
    var d: Conn = .init(io, &ss, &target, &dr, &sink, &rbuf, &wbuf);
    try testing.expectEqualStrings("hi", try d.reader.peekGreedy(1));
    d.reader.tossBuffered();
    try testing.expectError(error.EndOfStream, d.reader.peekGreedy(1));
}

/// The server's side of a 2022 request, as the tests check it.
const Request2022 = struct {
    salt: []const u8,
    identities: [max_identities][16]u8 = undefined,
    timestamp: i64,
    target: []const u8,
    padding: usize,
    data: []const u8,
    rx: Cipher,
};

fn openRequest2022(m: Method, user_key: *const [32]u8, ids: usize, wire: []u8) !Request2022 {
    const kl = m.keyLen();
    var q: Request2022 = .{ .salt = wire[0..kl], .timestamp = 0, .target = "", .padding = 0, .data = "", .rx = undefined };
    var at = kl;
    for (0..ids) |i| {
        q.identities[i] = wire[at..][0..16].*;
        at += 16;
    }
    q.rx = .init(m, user_key, q.salt);
    const f = try q.rx.open(m, wire[at..][0 .. fixed_request + tag_len]);
    at += fixed_request + tag_len;
    try testing.expectEqual(0, f[0]);
    q.timestamp = std.mem.readInt(i64, f[1..9], .big);
    const var_len = std.mem.readInt(u16, f[9..11], .big);
    const v = try q.rx.open(m, wire[at..][0 .. var_len + tag_len]);
    try testing.expectEqual(wire.len, at + var_len + tag_len);
    var vr: Io.Reader = .fixed(v);
    const ta = try @import("trojan.zig").readAddress(&vr);
    q.target = v[0 .. v.len - vr.bufferedLen()];
    try testing.expectEqualStrings("example.com", ta.addr());
    q.padding = try vr.takeInt(u16, .big);
    try testing.expect(std.mem.allEqual(u8, try vr.take(q.padding), 0));
    q.data = vr.buffered();
    return q;
}

fn sealedResponse2022(w: *Io.Writer, m: Method, key: *const [32]u8, kind: u8, ts: i64, echo: []const u8, chunks: []const []const u8) !void {
    const kl = m.keyLen();
    const salt: [32]u8 = @splat(0x5a);
    try w.writeAll(salt[0..kl]);
    var tx: Cipher = .init(m, key, salt[0..kl]);
    var buf: [1 + 8 + 32 + 2 + tag_len]u8 = undefined;
    const f = buf[0 .. 1 + 8 + kl + 2];
    f[0] = kind;
    std.mem.writeInt(i64, f[1..9], ts, .big);
    @memcpy(f[9..][0..kl], echo[0..kl]);
    std.mem.writeInt(u16, f[9 + kl ..][0..2], @intCast(chunks[0].len), .big);
    tx.seal(m, f, buf[f.len..][0..tag_len]);
    try w.writeAll(buf[0 .. f.len + tag_len]);
    for (chunks, 0..) |p, i| {
        if (i > 0) {
            var lc: [len_chunk]u8 = undefined;
            std.mem.writeInt(u16, lc[0..2], @intCast(p.len), .big);
            tx.seal(m, lc[0..2], lc[2..]);
            try w.writeAll(&lc);
        } else if (p.len == 0) continue;
        var body: [64]u8 = undefined;
        @memcpy(body[0..p.len], p);
        tx.seal(m, body[0..p.len], body[p.len..][0..tag_len]);
        try w.writeAll(body[0 .. p.len + tag_len]);
    }
}

test "2022: request layout, padding, identity headers" {
    const io = testing.io;
    const target = Target.fromDomain("example.com", 80);
    const k16 = "AAECAwQFBgcICQoLDA0ODw=="; // 00 01 .. 0f
    const k32 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="; // 00 .. 1f
    var wbuf: [write_buffer_len]u8 = undefined;
    var rbuf: [64]u8 = undefined;
    var nothing: Io.Reader = .fixed("");

    inline for (.{ .{ Method.blake3_aes_128_gcm, k16 }, .{ Method.blake3_aes_256_gcm, k32 }, .{ Method.blake3_chacha20_poly1305, k32 } }) |mk| {
        const m = mk[0];
        const ss: Shadowsocks = try .init(m, mk[1], "h", 1);
        try testing.expectEqualSlices(u8, counting()[0..m.keyLen()], ss.key[0..m.keyLen()]);

        // no data yet: the request goes alone, padded
        var out: [4096]u8 = undefined;
        var sink: Io.Writer = .fixed(&out);
        var c: Conn = .init(io, &ss, &target, &nothing, &sink, &rbuf, &wbuf);
        try c.writer.flush();
        const q = try openRequest2022(m, &ss.key, 0, sink.buffered());
        try testing.expectEqualSlices(u8, c.salt[0..m.keyLen()], q.salt);
        try testing.expect(@abs(q.timestamp - Io.Clock.real.now(io).toSeconds()) <= 1);
        try testing.expect(q.padding >= 1 and q.padding <= max_padding);
        try testing.expectEqual(0, q.data.len);

        // then plain chunks
        var rx = q.rx;
        sink.end = 0;
        try c.writer.writeAll("more");
        try c.writer.flush();
        var lc = sink.buffered()[0..len_chunk].*;
        try testing.expectEqual(4, std.mem.readInt(u16, (try rx.open(m, &lc))[0..2], .big));
        try testing.expectEqualStrings("more", try rx.open(m, sink.buffered()[len_chunk..]));

        // the first data rides in the variable header; long data needs no padding
        sink.end = 0;
        var d: Conn = .init(io, &ss, &target, &nothing, &sink, &rbuf, &wbuf);
        const long: [1000]u8 = @splat('q');
        try d.writer.writeAll(&long);
        try d.writer.flush();
        const q2 = try openRequest2022(m, &ss.key, 0, sink.buffered());
        try testing.expectEqual(0, q2.padding);
        try testing.expectEqualSlices(u8, &long, q2.data);
    }

    // a multi-user server's key, then the user's: one identity header
    const ss: Shadowsocks = try .init(.blake3_aes_128_gcm, "MDEyMzQ1Njc4OWFiY2RlZg==:" ++ k16, "h", 1);
    try testing.expectEqual(1, ss.identity_count);
    try testing.expectEqualStrings("0123456789abcdef", ss.identities[0][0..16]);
    var out: [4096]u8 = undefined;
    var sink: Io.Writer = .fixed(&out);
    var c: Conn = .init(io, &ss, &target, &nothing, &sink, &rbuf, &wbuf);
    try c.writer.writeAll("GET");
    try c.writer.flush();
    const q = try openRequest2022(.blake3_aes_128_gcm, &ss.key, 1, sink.buffered());
    try testing.expectEqualStrings("GET", q.data);
    // as the server checks it: decrypt with its own key, compare with BLAKE3(user key)
    var sub: [16]u8 = undefined;
    deriveKey("shadowsocks 2022 identity subkey", "0123456789abcdef", q.salt, &sub);
    var plain: [16]u8 = undefined;
    crypto.core.aes.Aes128.initDec(sub).decrypt(&plain, &q.identities[0]);
    var want: [16]u8 = undefined;
    crypto.hash.Blake3.hash(ss.key[0..16], &want, .{});
    try testing.expectEqualSlices(u8, &want, &plain);
}

test "2022: the answer is checked, then read" {
    const io = testing.io;
    const target = Target.fromDomain("example.com", 80);
    const m = Method.blake3_aes_256_gcm;
    const ss: Shadowsocks = try .init(m, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", "h", 1);
    var wbuf: [write_buffer_len]u8 = undefined;
    var rbuf: [readBufferLen(m)]u8 = undefined;
    var sink_buf: [4096]u8 = undefined;
    var sink: Io.Writer = .fixed(&sink_buf);
    const now = Io.Clock.real.now(io).toSeconds();
    const Case = struct { kind: u8 = 1, skew: i64 = 0, wrong_salt: bool = false, chunks: []const []const u8, expect: ?Error = null, text: []const u8 = "" };
    const cases = [_]Case{
        .{ .chunks = &.{ "HTTP/1.1 200 OK\r\n", "\r\nbody" }, .text = "HTTP/1.1 200 OK\r\n\r\nbody" },
        .{ .chunks = &.{ "", "late" }, .text = "late" }, // the header came before any data
        .{ .skew = 29, .chunks = &.{"ok"}, .text = "ok" },
        .{ .kind = 0, .chunks = &.{"x"}, .expect = error.SsBadResponse },
        .{ .wrong_salt = true, .chunks = &.{"x"}, .expect = error.SsBadResponse },
        .{ .skew = -31, .chunks = &.{"x"}, .expect = error.SsClockSkew },
    };
    for (cases) |cs| {
        var c: Conn = .init(io, &ss, &target, undefined, &sink, &rbuf, &wbuf);
        var resp_buf: [512]u8 = undefined;
        var resp: Io.Writer = .fixed(&resp_buf);
        var echo = c.salt;
        if (cs.wrong_salt) echo[3] ^= 1;
        try sealedResponse2022(&resp, m, &ss.key, cs.kind, now + cs.skew, &echo, cs.chunks);
        var rr: Io.Reader = .fixed(resp.buffered());
        c.r = &rr;
        var got: [128]u8 = undefined;
        var gw: Io.Writer = .fixed(&got);
        if (cs.expect) |e| {
            try testing.expectError(error.ReadFailed, c.reader.streamRemaining(&gw));
            try testing.expectEqual(e, c.err.?);
        } else {
            _ = try c.reader.streamRemaining(&gw);
            try testing.expectEqualStrings(cs.text, gw.buffered());
        }
    }

    // the wrong key: the fixed header does not open
    const other: Shadowsocks = try .init(m, "AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", "h", 1);
    var c: Conn = .init(io, &ss, &target, undefined, &sink, &rbuf, &wbuf);
    var resp_buf: [512]u8 = undefined;
    var resp: Io.Writer = .fixed(&resp_buf);
    try sealedResponse2022(&resp, m, &other.key, 1, now, &c.salt, &.{"x"});
    var rr: Io.Reader = .fixed(resp.buffered());
    c.r = &rr;
    try testing.expectError(error.ReadFailed, c.reader.peekGreedy(1));
    try testing.expectEqual(error.SsAuthFailed, c.err.?);
}

/// A stream below that hands out `parts`, at most one per read, and fails
/// a read past the first `allowed` of them: as a socket would wait there,
/// when the server has nothing more to say until it is answered.
const Parts = struct {
    parts: []const []const u8,
    allowed: usize,
    next: usize = 0,
    at: usize = 0,
    starved: bool = false,
    interface: Io.Reader,

    fn init(parts: []const []const u8, allowed: usize, buf: []u8) Parts {
        return .{ .parts = parts, .allowed = allowed, .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buf, .seek = 0, .end = 0 } };
    }

    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const p: *Parts = @alignCast(@fieldParentPtr("interface", io_r));
        if (p.next == p.allowed) {
            p.starved = true;
            return error.ReadFailed;
        }
        const part = p.parts[p.next][p.at..];
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const n = @min(dest.len, part.len);
        @memcpy(dest[0..n], part[0..n]);
        w.advance(n);
        p.at += n;
        if (p.at == p.parts[p.next].len) {
            p.next += 1;
            p.at = 0;
        }
        return n;
    }
};

test "an answer is given out as soon as it is whole, without waiting for more" {
    const io = testing.io;
    const target = Target.fromDomain("example.com", 80);
    const m = Method.blake3_aes_128_gcm;
    const ss: Shadowsocks = try .init(m, "AAECAwQFBgcICQoLDA0ODw==", "h", 1);
    var wbuf: [write_buffer_len]u8 = undefined;
    var rbuf: [readBufferLen(m)]u8 = undefined;
    var sink_buf: [4096]u8 = undefined;
    var sink: Io.Writer = .fixed(&sink_buf);
    // salt 16, fixed header 43, "server hello" 12 + 16: whole at 87;
    // then a length chunk 18 and "and more" 8 + 16
    const whole = 87;
    // where the reads end: all in one, the salt cut, a byte short, the
    // next length chunk begun
    const cuts = [_][]const usize{ &.{whole}, &.{ 10, whole }, &.{ whole - 1, whole }, &.{100} };
    for (cuts) |ends| {
        var c: Conn = .init(io, &ss, &target, undefined, &sink, &rbuf, &wbuf);
        var resp_buf: [512]u8 = undefined;
        var resp: Io.Writer = .fixed(&resp_buf);
        try sealedResponse2022(&resp, m, &ss.key, 1, Io.Clock.real.now(io).toSeconds(), &c.salt, &.{ "server hello", "and more" });
        const all = resp.buffered();
        var parts: [3][]const u8 = undefined;
        var from: usize = 0;
        for (ends, 0..) |e, i| {
            parts[i] = all[from..e];
            from = e;
        }
        parts[ends.len] = all[from..];
        var pbuf: [4096]u8 = undefined;
        var below: Parts = .init(parts[0 .. ends.len + 1], ends.len, &pbuf);
        c.r = &below.interface;
        try testing.expectEqualStrings("server hello", try c.reader.peekGreedy(1));
        try testing.expect(!below.starved);
        c.reader.tossBuffered();
        below.allowed += 1;
        try testing.expectEqualStrings("and more", try c.reader.peekGreedy(1));
    }
}

/// What a server sends: its salt, with 2022 the fixed header (echoing
/// `echo`, giving the first chunk's length), then the chunks.
fn sealedStream(gpa: std.mem.Allocator, m: Method, key: *const [32]u8, echo: []const u8, chunks: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const kl = m.keyLen();
    const salt: [32]u8 = @splat(0x33);
    try out.appendSlice(gpa, salt[0..kl]);
    var tx: Cipher = .init(m, key, salt[0..kl]);
    var tag: [tag_len]u8 = undefined;
    if (m.is2022()) {
        var f: [1 + 8 + 32 + 2]u8 = undefined;
        const h = f[0 .. 1 + 8 + kl + 2];
        h[0] = 1;
        std.mem.writeInt(i64, h[1..9], Io.Clock.real.now(testing.io).toSeconds(), .big);
        @memcpy(h[9..][0..kl], echo[0..kl]);
        std.mem.writeInt(u16, h[9 + kl ..][0..2], @intCast(chunks[0].len), .big);
        tx.seal(m, h, &tag);
        try out.appendSlice(gpa, h);
        try out.appendSlice(gpa, &tag);
    }
    for (chunks, 0..) |p, i| {
        if (i > 0 or !m.is2022()) {
            var lc: [2]u8 = undefined;
            std.mem.writeInt(u16, &lc, @intCast(p.len), .big);
            tx.seal(m, &lc, &tag);
            try out.appendSlice(gpa, &lc);
            try out.appendSlice(gpa, &tag);
        }
        const at = out.items.len;
        try out.appendSlice(gpa, p);
        tx.seal(m, out.items[at..], &tag);
        try out.appendSlice(gpa, &tag);
    }
    return out.toOwnedSlice(gpa);
}

/// A stream below that gives out `data` in reads of random length.
const Trickle = struct {
    data: []const u8,
    rand: std.Random,
    max: usize,
    interface: Io.Reader,

    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const t: *Trickle = @alignCast(@fieldParentPtr("interface", io_r));
        if (t.data.len == 0) return error.EndOfStream;
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const n = @min(dest.len, t.data.len, t.rand.intRangeAtMost(usize, 1, t.max));
        @memcpy(dest[0..n], t.data[0..n]);
        w.advance(n);
        t.data = t.data[n..];
        return n;
    }
};

test "chunks of any size come out whole, however they are read and taken" {
    const io = testing.io;
    const gpa = testing.allocator;
    const target = Target.fromDomain("example.com", 80);
    var prng: std.Random.DefaultPrng = .init(0xc0ffee);
    const rand = prng.random();
    const plain = try gpa.alloc(u8, 600_000);
    defer gpa.free(plain);
    rand.bytes(plain);
    inline for (.{ Method.blake3_aes_128_gcm, Method.blake3_chacha20_poly1305, Method.aes_256_gcm, Method.chacha20_poly1305 }) |m| {
        const ss: Shadowsocks = try .init(m, if (m == .blake3_aes_128_gcm) "AAECAwQFBgcICQoLDA0ODw==" else if (m.is2022()) "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" else "pw", "h", 1);
        for (0..4) |round| {
            // chunks: tiny, Xray's 8 KiB, or up to the limit
            var chunks: std.ArrayList([]const u8) = .empty;
            defer chunks.deinit(gpa);
            var at: usize = 0;
            while (at < plain.len) {
                const want: usize = switch (rand.uintLessThan(u8, 3)) {
                    0 => rand.intRangeAtMost(usize, 1, 40),
                    1 => 8192,
                    else => rand.intRangeAtMost(usize, 1, m.maxChunk()),
                };
                const n = @min(want, plain.len - at);
                try chunks.append(gpa, plain[at..][0..n]);
                at += n;
            }
            var wbuf: [write_buffer_len]u8 = undefined;
            const rbuf = try gpa.alloc(u8, readBufferLen(m) + 4096);
            defer gpa.free(rbuf);
            var sink_buf: [64]u8 = undefined;
            var sink: Io.Writer = .fixed(&sink_buf);
            var c: Conn = .init(io, &ss, &target, undefined, &sink, rbuf, &wbuf);
            const wire = try sealedStream(gpa, m, &ss.key, &c.salt, chunks.items);
            defer gpa.free(wire);
            var below_buf: [16 * 1024 + 261]u8 = undefined;
            var below: Trickle = .{
                .data = wire,
                .rand = rand,
                .max = if (round % 2 == 0) 100 else 70_000,
                .interface = .{ .vtable = &.{ .stream = Trickle.stream }, .buffer = &below_buf, .seek = 0, .end = 0 },
            };
            c.r = &below.interface;
            // the copy loop's way (all that is there), or a parser's (a few at a time)
            var got: usize = 0;
            while (true) {
                if (rand.boolean()) {
                    const b = c.reader.peekGreedy(1) catch |e| switch (e) {
                        error.EndOfStream => break,
                        else => return e,
                    };
                    const n = rand.intRangeAtMost(usize, 1, b.len);
                    try testing.expectEqualSlices(u8, plain[got..][0..n], b[0..n]);
                    c.reader.toss(n);
                    got += n;
                } else {
                    const n = @min(rand.intRangeAtMost(usize, 1, 4096), plain.len - got);
                    if (n == 0) {
                        try testing.expectError(error.EndOfStream, c.reader.peekGreedy(1));
                        break;
                    }
                    try testing.expectEqualSlices(u8, plain[got..][0..n], try c.reader.take(n));
                    got += n;
                }
            }
            try testing.expectEqual(plain.len, got);
            try testing.expect(c.err == null);
        }
    }
}

test "ss links" {
    const k16 = "AAECAwQFBgcICQoLDA0ODw==";
    // SIP002, base64url userinfo (and a plugin-free path and query)
    const a = try fromLink("ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888/?#Example", "192.168.100.1", 8888);
    try testing.expectEqual(.aes_128_gcm, a.method);
    var k: [32]u8 = undefined;
    bytesToKey("test", k[0..16]);
    try testing.expectEqualSlices(u8, k[0..16], a.key[0..16]);
    // padded standard base64 works too
    const a2 = try fromLink("ss://YWVzLTEyOC1nY206dGVzdA==@h:1", "h", 1);
    try testing.expectEqualSlices(u8, &a.key, &a2.key);
    // plain, the 2022 key percent-encoded as SIP002 asks
    const b = try fromLink("ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw%3D%3D@h:1#n", "h", 1);
    try testing.expectEqualSlices(u8, counting()[0..16], b.key[0..16]);
    // ... or not encoded at all, as our own subscription parser writes it
    const c = try fromLink("ss://2022-blake3-aes-128-gcm:" ++ k16 ++ "@h:1?type=tcp&security=none", "h", 1);
    try testing.expectEqualSlices(u8, &b.key, &c.key);
    // a password with escapes, and with an '@' left as it is
    const d = try fromLink("ss://chacha20-ietf-poly1305:p%40ss%3Aw@h:1", "h", 1);
    bytesToKey("p@ss:w", &k);
    try testing.expectEqualSlices(u8, &k, &d.key);
    const e = try fromLink("ss://aes-256-gcm:p@ss@h:1", "h", 1);
    bytesToKey("p@ss", &k);
    try testing.expectEqualSlices(u8, &k, &e.key);
    // the whole userinfo escaped
    const f = try fromLink("ss://aes-256-gcm%3Ap%40ss@h:1", "h", 1);
    try testing.expectEqualSlices(u8, &k, &f.key);
    // legacy: everything in base64
    const g = try fromLink("ss://YWVzLTI1Ni1nY206cEBzc0BoOjE=#x", "h", 1);
    try testing.expectEqualSlices(u8, &k, &g.key);
    // identities
    const h = try fromLink("ss://2022-blake3-aes-128-gcm:MDEyMzQ1Njc4OWFiY2RlZg%3D%3D%3A" ++ "AAECAwQFBgcICQoLDA0ODw%3D%3D@h:1", "h", 1);
    try testing.expectEqual(1, h.identity_count);
    try testing.expectEqualSlices(u8, &b.key, &h.key);

    try testing.expectError(error.NotShadowsocks, fromLink("trojan://x@h:1", "h", 1));
    try testing.expectError(error.UnsupportedPlugin, fromLink("ss://YWVzLTEyOC1nY206dGVzdA@h:1/?plugin=obfs-local%3Bobfs%3Dhttp", "h", 1));
    try testing.expectError(error.UnsupportedTransport, fromLink("ss://aes-128-gcm:x@h:1?type=ws", "h", 1));
    try testing.expectError(error.UnsupportedSecurity, fromLink("ss://aes-128-gcm:x@h:1?security=tls", "h", 1));
    try testing.expectError(error.UnsupportedMethod, fromLink("ss://rc4-md5:x@h:1", "h", 1));
    try testing.expectError(error.UnsupportedMethod, fromLink("ss://none:x@h:1", "h", 1));
    try testing.expectError(error.BadUserInfo, fromLink("ss://!!!@h:1", "h", 1));
    try testing.expectError(error.BadUserInfo, fromLink("ss://bm9jb2xvbg@h:1", "h", 1)); // "nocolon"
    try testing.expectError(error.BadPassword, fromLink("ss://aes-128-gcm:@h:1", "h", 1));
    try testing.expectError(error.BadPassword, fromLink("ss://2022-blake3-aes-256-gcm:" ++ k16 ++ "@h:1", "h", 1));
    try testing.expectError(error.BadPassword, fromLink("ss://2022-blake3-chacha20-poly1305:" ++ k16 ++ ":" ++ k16 ++ "@h:1", "h", 1));
    // a raw key of the right length is taken as it is (Xray does the same)
    const raw = try fromLink("ss://2022-blake3-aes-128-gcm:0123456789abcdef@h:1", "h", 1);
    try testing.expectEqualStrings("0123456789abcdef", raw.key[0..16]);
}

/// The server's half of Shadowsocks UDP, for the tests: opens a client's
/// packet and seals an answer from `from`.
const TestUdpServer = struct {
    method: Method,
    key: [32]u8,
    session: [8]u8 = @splat(0x5a),
    packet: u64 = 0,

    const Got = struct { to: Target, payload: []u8, client_session: [8]u8 };

    fn openClient(s: *TestUdpServer, pkt: []u8) !Got {
        const m = s.method;
        const kl = m.keyLen();
        switch (m) {
            .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305, .xchacha20_poly1305 => {
                var c: Cipher = .init(m, &s.key, pkt[0..kl]);
                const body = try c.open(m, pkt[kl..]);
                const d = try Udp.parseTail(body);
                return .{ .to = d.from, .payload = d.payload, .client_session = @splat(0) };
            },
            .blake3_aes_128_gcm, .blake3_aes_256_gcm => {
                var header: [16]u8 = undefined;
                Udp.blockDecrypt(m, &s.key, pkt[0..16], &header);
                const aead: Udp.SessionAead = .of(m, &s.key, header[0..8]);
                const body = pkt[16 .. pkt.len - tag_len];
                try aead.open(body, pkt[pkt.len - tag_len ..][0..tag_len].*, header[4..16].*);
                return clientBody(body, header[0..8].*);
            },
            .blake3_chacha20_poly1305 => {
                const body = pkt[24 .. pkt.len - tag_len];
                try crypto.aead.chacha_poly.XChaCha20Poly1305.decrypt(body, body, pkt[pkt.len - tag_len ..][0..tag_len].*, "", pkt[0..24].*, s.key);
                return clientBody(body[16..], body[0..8].*);
            },
        }
    }

    fn clientBody(body: []u8, session: [8]u8) !Got {
        if (body[0] != 0) return error.TestUnexpectedResult;
        const pad = std.mem.readInt(u16, body[9..11], .big);
        const d = try Udp.parseTail(body[11 + pad ..]);
        return .{ .to = d.from, .payload = d.payload, .client_session = session };
    }

    fn sealAnswer(s: *TestUdpServer, io: Io, out: []u8, client_session: [8]u8, from: *const Target, payload: []const u8) ![]u8 {
        const m = s.method;
        const kl = m.keyLen();
        var w: Io.Writer = .fixed(out);
        switch (m) {
            .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305, .xchacha20_poly1305 => {
                const salt: [32]u8 = @splat(0x77);
                try w.writeAll(salt[0..kl]);
                try writeAddress(&w, from);
                try w.writeAll(payload);
                var c: Cipher = .init(m, &s.key, salt[0..kl]);
                c.seal(m, out[kl..w.end], out[w.end..][0..tag_len]);
                return out[0 .. w.end + tag_len];
            },
            .blake3_aes_128_gcm, .blake3_aes_256_gcm => {
                var header: [16]u8 = undefined;
                header[0..8].* = s.session;
                std.mem.writeInt(u64, header[8..16], s.packet, .big);
                s.packet += 1;
                w.end = 16;
                try Udp.writeBody(&w, io, client_session, from, payload);
                const aead: Udp.SessionAead = .of(m, &s.key, &s.session);
                aead.seal(out[16..w.end], out[w.end..][0..tag_len], header[4..16].*);
                Udp.blockEncrypt(m, &s.key, &header, out[0..16]);
                return out[0 .. w.end + tag_len];
            },
            .blake3_chacha20_poly1305 => {
                const nonce: [24]u8 = @splat(0x24);
                try w.writeAll(&nonce);
                try w.writeAll(&s.session);
                try w.writeInt(u64, s.packet, .big);
                s.packet += 1;
                try Udp.writeBody(&w, io, client_session, from, payload);
                const body = out[24..w.end];
                crypto.aead.chacha_poly.XChaCha20Poly1305.encrypt(body, out[w.end..][0..tag_len], body, "", nonce, s.key);
                return out[0 .. w.end + tag_len];
            },
        }
    }
};

test "UDP: every method there and back, replays and strangers refused" {
    const io = testing.io;
    for (std.enums.values(Method)) |m| {
        const password = if (m.is2022()) (if (m.keyLen() == 16) "AAECAwQFBgcICQoLDA0ODw==" else "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=") else "pw";
        const ss: Shadowsocks = try .init(m, password, "h", 1);
        var u: Udp = try .init(io, &ss);
        defer u.deinit();
        var server: TestUdpServer = .{ .method = m, .key = ss.key };
        const to = Target.fromDomain("dns.example", 53);
        var buf: [2048]u8 = undefined;
        for (0..3) |i| {
            const pkt = try u.seal(io, &buf, &to, "query");
            const got = try server.openClient(pkt);
            try testing.expectEqualStrings("dns.example", got.to.addr());
            try testing.expectEqual(53, got.to.port);
            try testing.expectEqualStrings("query", got.payload);
            if (m.is2022()) try testing.expectEqualSlices(u8, &u.session, &got.client_session);

            const from = Target.fromEndpoint(.{ .addr = @import("ipstack/packet.zig").v4(.{ 9, 9, 9, 9 }), .port = 53 });
            var ans_buf: [2048]u8 = undefined;
            const ans = try server.sealAnswer(io, &ans_buf, got.client_session, &from, "answer");
            var copy: [2048]u8 = undefined;
            @memcpy(copy[0..ans.len], ans);
            const d = try u.open(io, ans);
            try testing.expectEqualStrings("answer", d.payload);
            try testing.expectEqualSlices(u8, &.{ 9, 9, 9, 9 }, d.from.addr());
            if (m.is2022()) {
                // the same packet again is a replay
                try testing.expectError(error.SsReplay, u.open(io, copy[0..ans.len]));
            }
            _ = i;
        }
        // a packet sealed under another key
        var other: TestUdpServer = .{ .method = m, .key = @splat(0xee) };
        const from = Target.fromDomain("x.example", 1);
        var ans_buf: [2048]u8 = undefined;
        const bad = try other.sealAnswer(io, &ans_buf, u.session, &from, "nope");
        if (u.open(io, bad)) |_| return error.TestUnexpectedResult else |_| {}
    }
}

test "UDP: a relay's identity headers are not carried" {
    const ss: Shadowsocks = try .init(.blake3_aes_128_gcm, "AAECAwQFBgcICQoLDA0ODw==:AAECAwQFBgcICQoLDA0ODw==", "h", 1);
    try testing.expectError(error.UdpNotSupported, Udp.init(testing.io, &ss));
}
