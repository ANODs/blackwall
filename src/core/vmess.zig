//! VMess client with AEAD headers (alterId 0, all any current server
//! takes), byte for byte as Xray-core 26 sends it: the protocol behind
//! `vmess://` links, still common in subscriptions.
//!
//! A connection starts with the request header (`Conn.writeRequest`): an
//! auth ID (the time, AES-encrypted under a key derived from the UUID) by
//! which the server finds the user, then the header itself, sealed with
//! AES-128-GCM under keys derived from the UUID, the auth ID and a nonce.
//! It carries the body keys, the options, the body cipher and the
//! destination. The server answers with a sealed response header; then
//! each direction is a run of chunks
//!   [length (2, masked)][payload sealed (n + 16)][padding (0..63)]
//! where the masks and padding lengths come from SHAKE128 over the
//! direction's IV, so neither length is plaintext. Security `none` drops
//! the seal and the padding: [length (masked)][payload]. An empty chunk
//! ends a direction. UDP goes as XUDP frames (xudp.zig) in a connection
//! opened with `Command.mux`, as Xray's and sing-box's clients send it.
//!
//! Ciphers: "auto" is AES-128-GCM where AES runs in hardware, else
//! ChaCha20-Poly1305, as in Xray. Xray 26 servers refuse `none` (and
//! `zero`), and Xray 26 clients send "auto" when a config asks for them;
//! `Security.parse` does the same, which every server takes since a
//! server follows the cipher the client names. `none` stays available for
//! servers known to take it (sing-box, v2fly, Xray before 26).
//!
//! Runs over any std.Io.Reader/Writer pair: the socket, the TLS stream or a
//! WebSocket. One thread reads `reader` while another writes `writer`: the
//! two directions share nothing that changes after `init`.
//!
//! Memory: a chunk is sealed in place in the caller's write buffer (room
//! for its length is kept in front of the payload, for its tag and padding
//! behind) and opened in place in the read buffer, which must hold one
//! whole chunk: 16 KiB covers Xray's (8 KiB at most) and sing-box's
//! (15 000-byte payloads). Nothing is allocated.

const std = @import("std");
const Io = std.Io;
const crypto = std.crypto;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const Shake128 = crypto.hash.sha3.Shake128;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = crypto.hash.sha2.Sha256;
const Md5 = crypto.hash.Md5;
const outbound = @import("outbound.zig");

/// The body cipher, by its number in the request header.
pub const Security = enum(u4) {
    aes_128_gcm = 3,
    chacha20_poly1305 = 4,
    /// No body encryption: chunks carry a masked length and the payload.
    /// Only for servers known to take it (Xray 26 refuses it).
    none = 5,

    /// Xray's "auto": AES-128-GCM where AES runs in hardware (decided at
    /// build time here, at run time in Xray), else ChaCha20-Poly1305.
    pub const auto: Security = if (crypto.core.aes.has_hardware_support) .aes_128_gcm else .chacha20_poly1305;

    /// A link's `scy` or a config's `security`, mapped as Xray 26 maps it:
    /// the two ciphers by name, anything else ("auto", "none", "zero", an
    /// empty or unknown name) `auto`.
    pub fn parse(name: []const u8) Security {
        if (std.ascii.eqlIgnoreCase(name, "aes-128-gcm")) return .aes_128_gcm;
        if (std.ascii.eqlIgnoreCase(name, "chacha20-poly1305")) return .chacha20_poly1305;
        return auto;
    }

    /// Request options, as Xray sets them: ChunkStream (1) and ChunkMasking
    /// (4) always, GlobalPadding (8) with a cipher. (AuthenticatedLength,
    /// an experiment off by default, is not offered.)
    fn options(s: Security) u8 {
        return if (s == .none) 0x01 | 0x04 else 0x01 | 0x04 | 0x08;
    }

    /// Largest payload per chunk, as Xray cuts its writes: a chunk with
    /// its length, tag and largest padding fits its 8 KiB buffers; without
    /// a cipher the payload alone gets 8 KiB.
    fn maxPayload(s: Security) usize {
        return if (s == .none) 8192 else 8192 - 2 - tag_len - 64;
    }

    /// Bytes behind a chunk's payload at most: tag and padding.
    fn tail(s: Security) usize {
        return if (s == .none) 0 else tag_len + 63;
    }
};

pub const Command = enum(u8) {
    tcp = 1,
    /// Mux.Cool frames (XUDP for UDP): the frames name their own
    /// destinations, so the header carries none.
    mux = 3,
};

pub const Address = union(enum) {
    ip4: [4]u8,
    ip6: [16]u8,
    domain: []const u8,
};

/// Where the server is to connect.
pub const Request = struct {
    command: Command = .tcp,
    address: Address = .{ .ip4 = @splat(0) },
    port: u16 = 0,
};

pub const Error = error{
    /// The server closed before answering, which is how it refuses a
    /// request: an unknown UUID, a clock more than 120 s off (the auth ID
    /// carries the time), a replayed header, or a cipher it does not take
    /// (Xray 26 and `none`). Also what a destination it cannot reach looks
    /// like. Xray keeps a request it refuses open for up to a minute first
    /// (it reads on, so that a prober learns nothing): time the first read.
    VmessNoResponse,
    /// The response header does not open, or does not echo our byte.
    VmessBadResponse,
    /// A chunk failed authentication or has an impossible length.
    VmessBadChunk,
    /// A chunk larger than the read buffer can take.
    VmessChunkTooLarge,
    /// The stream below ended inside a chunk.
    VmessTruncated,
};

pub const RequestError = Io.Writer.Error || error{
    /// An empty domain, or one longer than 255 bytes.
    VmessBadAddress,
};

const tag_len = 16;

/// Recommended buffer sizes: a write buffer holds Xray's largest chunk; a
/// read buffer the largest any known server sends (sing-box: 15 000-byte
/// payloads plus tag and padding).
pub const write_buffer_len = 2 + 8192;
pub const read_buffer_len = 16 * 1024;

/// Version, body IV and key, response byte, options, padding length and
/// cipher, a reserved byte, command.
const plain_fixed = 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1;
/// plus port, address type, domain length and domain, padding, checksum
const max_plain = plain_fixed + 2 + 1 + 1 + 255 + 15 + 4;
/// auth ID, sealed length, nonce, sealed header
pub const max_request = 16 + 2 + tag_len + 8 + max_plain + tag_len;

// ---------------------------------------------------------------- keys

/// What a user's requests are keyed by, derived once from the UUID.
pub const User = struct {
    /// MD5 of the UUID and a fixed string: the key of all header sealing.
    cmd_key: [16]u8,
    /// AES-128 key of the auth ID.
    auth_key: [16]u8,

    pub fn init(uuid: [16]u8) User {
        var u: User = undefined;
        var h: Md5 = .init(.{});
        h.update(&uuid);
        h.update("c48619fe-8f02-49e0-b9e9-edf763e17e21");
        h.final(&u.cmd_key);
        u.auth_key = kdf16(&u.cmd_key, &.{"AES Auth ID Encryption"});
        return u;
    }
};

/// A connection's own keys, chosen by the client and sent in the request
/// header; the response's keys are their SHA-256.
pub const Session = struct {
    /// request body key and IV
    key: [16]u8,
    iv: [16]u8,
    /// the byte the response header must start with
    v: u8,

    pub fn random(io: Io) Session {
        var raw: [33]u8 = undefined;
        io.random(&raw);
        return .{ .key = raw[0..16].*, .iv = raw[16..32].*, .v = raw[32] };
    }
};

/// VMess's KDF: HMAC-SHA256 keyed "VMess AEAD KDF", wrapped once per
/// `path` element in an HMAC keyed by that element whose hash function is
/// the HMAC below it. That is what Xray's nested hmac.New closures build:
/// the inner and the outer hash of each level are the level below, used
/// as a plain hash. Up to three elements, each at most one block (64
/// bytes), so no key is hashed first.
pub fn kdf(key: []const u8, path: []const []const u8) [32]u8 {
    std.debug.assert(path.len <= 3);
    return kdfLevel(path, &.{key});
}

fn kdf16(key: []const u8, path: []const []const u8) [16]u8 {
    return kdf(key, path)[0..16].*;
}

/// The hash of level `path.len` over the concatenation of `msg`.
fn kdfLevel(path: []const []const u8, msg: []const []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    if (path.len == 0) {
        var h: HmacSha256 = .init("VMess AEAD KDF");
        for (msg) |m| h.update(m);
        h.final(&out);
        return out;
    }
    const below = path[0 .. path.len - 1];
    const k = path[path.len - 1];
    std.debug.assert(k.len <= 64);
    var ipad: [64]u8 = @splat(0x36);
    var opad: [64]u8 = @splat(0x5c);
    for (k, 0..) |b, i| {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    // H(opad || H(ipad || msg)), H being the level below
    var inner_msg: [4][]const u8 = undefined;
    inner_msg[0] = &ipad;
    @memcpy(inner_msg[1..][0..msg.len], msg);
    const inner = kdfLevel(below, inner_msg[0 .. 1 + msg.len]);
    return kdfLevel(below, &.{ &opad, &inner });
}

/// The auth ID: the time and 4 random bytes with their CRC32, one AES-128
/// block under the user's auth key. The server tries each user's key on
/// it, and takes a request only within 120 s of its own clock, and once.
pub fn authId(user: *const User, now: i64, rand: [4]u8) [16]u8 {
    var block: [16]u8 = undefined;
    std.mem.writeInt(i64, block[0..8], now, .big);
    block[8..12].* = rand;
    std.mem.writeInt(u32, block[12..16], std.hash.Crc32.hash(block[0..12]), .big);
    var out: [16]u8 = undefined;
    crypto.core.aes.Aes128.initEnc(user.auth_key).encrypt(&out, &block);
    return out;
}

/// `plain` sealed as the server opens it:
///   auth ID (16) | length sealed (2 + 16) | nonce (8) | header sealed (n + 16)
/// Both seals are AES-128-GCM with the auth ID as associated data, under a
/// key and nonce derived from the user's key, the auth ID and the nonce.
pub fn sealHeader(out: []u8, user: *const User, plain: []const u8, auth_id: [16]u8, nonce: [8]u8) []u8 {
    const total = 16 + 2 + tag_len + 8 + plain.len + tag_len;
    std.debug.assert(out.len >= total and plain.len <= max_plain);
    const ck = &user.cmd_key;
    var len_be: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_be, @intCast(plain.len), .big);
    out[0..16].* = auth_id;
    Aes128Gcm.encrypt(
        out[16..18],
        out[18..34],
        &len_be,
        &auth_id,
        kdf(ck, &.{ "VMess Header AEAD Nonce_Length", &auth_id, &nonce })[0..12].*,
        kdf16(ck, &.{ "VMess Header AEAD Key_Length", &auth_id, &nonce }),
    );
    out[34..42].* = nonce;
    Aes128Gcm.encrypt(
        out[42..][0..plain.len],
        out[42 + plain.len ..][0..tag_len],
        plain,
        &auth_id,
        kdf(ck, &.{ "VMess Header AEAD Nonce", &auth_id, &nonce })[0..12].*,
        kdf16(ck, &.{ "VMess Header AEAD Key", &auth_id, &nonce }),
    );
    return out[0..total];
}

/// The request header before sealing: version 1, the body IV and key, the
/// byte the response must echo, options, padding length (high nibble) and
/// cipher, a reserved zero, the command, the destination (port first; for
/// mux none), random padding, and an FNV-1a checksum of all of it.
pub fn requestPlain(out: *[max_plain]u8, s: *const Session, security: Security, req: Request, padding: []const u8) error{VmessBadAddress}![]u8 {
    std.debug.assert(padding.len < 16);
    var w: Io.Writer = .fixed(out);
    w.writeByte(1) catch unreachable;
    w.writeAll(&s.iv) catch unreachable;
    w.writeAll(&s.key) catch unreachable;
    w.writeAll(&.{ s.v, security.options(), @as(u8, @intCast(padding.len)) << 4 | @backingInt(security), 0, @backingInt(req.command) }) catch unreachable;
    if (req.command != .mux) {
        w.writeInt(u16, req.port, .big) catch unreachable;
        switch (req.address) {
            .ip4 => |a| {
                w.writeByte(1) catch unreachable;
                w.writeAll(&a) catch unreachable;
            },
            .domain => |d| {
                if (d.len == 0 or d.len > 255) return error.VmessBadAddress;
                w.writeAll(&.{ 2, @intCast(d.len) }) catch unreachable;
                w.writeAll(d) catch unreachable;
            },
            .ip6 => |a| {
                w.writeByte(3) catch unreachable;
                w.writeAll(&a) catch unreachable;
            },
        }
    }
    w.writeAll(padding) catch unreachable;
    w.writeInt(u32, std.hash.Fnv1a_32.hash(w.buffered()), .big) catch unreachable;
    return w.buffered();
}

/// One direction of the body: its cipher, the chunk counter in its nonces,
/// and the SHAKE128 stream over its IV that masks each length and, with a
/// cipher, sizes each padding.
const Body = struct {
    security: Security,
    /// AES-128 uses the first half
    key: [32]u8,
    iv: [16]u8,
    count: u16 = 0,
    shake: Shake128,

    fn init(security: Security, key: [16]u8, iv: [16]u8) Body {
        var b: Body = .{ .security = security, .key = undefined, .iv = iv, .shake = .init(.{}) };
        b.shake.update(&iv);
        if (security == .chacha20_poly1305) {
            // ChaCha20 takes 32 bytes: MD5 of the key, then MD5 of that
            Md5.hash(&key, b.key[0..16], .{});
            Md5.hash(b.key[0..16], b.key[16..32], .{});
        } else {
            b.key[0..16].* = key;
        }
        return b;
    }

    const Lengths = struct { pad: u16, mask: u16 };

    /// The next chunk's padding length and length mask, drawn in Xray's
    /// order: padding first.
    fn lengths(b: *Body) Lengths {
        const pad: u16 = if (b.security == .none) 0 else b.draw() % 64;
        return .{ .pad = pad, .mask = b.draw() };
    }

    fn draw(b: *Body) u16 {
        var x: [2]u8 = undefined;
        b.shake.squeeze(&x);
        return std.mem.readInt(u16, &x, .big);
    }

    /// The next chunk's nonce: its number (big endian, wrapping like Xray's
    /// uint16) over the first two bytes of the IV's first twelve.
    fn nonce(b: *Body) [12]u8 {
        var n: [12]u8 = b.iv[0..12].*;
        std.mem.writeInt(u16, n[0..2], b.count, .big);
        b.count +%= 1;
        return n;
    }

    /// Make the `n` payload bytes at `buf[2..]` a chunk, in place: the
    /// length in front, tag and padding behind (`buf` has room for them).
    fn seal(b: *Body, io: Io, buf: []u8, n: usize) []u8 {
        const l = b.lengths();
        if (b.security == .none) {
            std.mem.writeInt(u16, buf[0..2], @as(u16, @intCast(n)) ^ l.mask, .big);
            return buf[0 .. 2 + n];
        }
        const size = n + tag_len + l.pad;
        std.mem.writeInt(u16, buf[0..2], @as(u16, @intCast(size)) ^ l.mask, .big);
        const payload = buf[2..][0..n];
        const tag = buf[2 + n ..][0..tag_len];
        switch (b.security) {
            .none => unreachable,
            .aes_128_gcm => Aes128Gcm.encrypt(payload, tag, payload, "", b.nonce(), b.key[0..16].*),
            .chacha20_poly1305 => ChaCha20Poly1305.encrypt(payload, tag, payload, "", b.nonce(), b.key),
        }
        // in clear on the wire, so from the CSPRNG: it must tell nothing
        io.random(buf[2 + n + tag_len ..][0..l.pad]);
        return buf[0 .. 2 + size];
    }

    /// Open a chunk's payload in place.
    fn open(b: *Body, payload: []u8, tag: *const [tag_len]u8) error{AuthenticationFailed}!void {
        switch (b.security) {
            .none => unreachable,
            .aes_128_gcm => try Aes128Gcm.decrypt(payload, payload, tag.*, "", b.nonce(), b.key[0..16].*),
            .chacha20_poly1305 => try ChaCha20Poly1305.decrypt(payload, payload, tag.*, "", b.nonce(), b.key),
        }
    }
};

// ---------------------------------------------------------------- connection

pub const Conn = struct {
    io: Io,
    /// the stream below
    r: *Io.Reader,
    w: *Io.Writer,
    /// the payload: what the destination sends, and what we send it
    reader: Io.Reader,
    writer: Io.Writer,
    /// Why `reader` failed, if the stream below did not.
    err: ?Error = null,

    user: User,
    security: Security,
    session: Session,
    /// response body key and IV, which also key the response header
    resp_key: [16]u8,
    resp_iv: [16]u8,
    up: Body,
    /// The write buffer: `writer.buffer` with room in front for a chunk's
    /// length and behind for its tag and padding.
    wbuf: []u8,

    // the reading thread's own
    down: Body,
    rstate: enum { header, open, eof, failed } = .header,
    /// security none: payload left in the current chunk
    left: u16 = 0,

    /// `rbuf` buffers `reader` and must hold a whole chunk
    /// (`read_buffer_len`) next to what the caller has not consumed yet: one
    /// who takes all there is each time (peekGreedy, toss) needs no more,
    /// one who asks for n bytes at once n - 1 more. `wbuf` bounds the chunks
    /// we send (`write_buffer_len` for Xray's). The interfaces point back
    /// into the result: keep it at one address.
    pub fn init(io: Io, user: User, security: Security, r: *Io.Reader, w: *Io.Writer, rbuf: []u8, wbuf: []u8) Conn {
        return initSession(io, user, security, .random(io), r, w, rbuf, wbuf);
    }

    pub fn initSession(io: Io, user: User, security: Security, session: Session, r: *Io.Reader, w: *Io.Writer, rbuf: []u8, wbuf: []u8) Conn {
        std.debug.assert(rbuf.len >= 8192 and wbuf.len > 2 + security.tail());
        var resp_key: [32]u8 = undefined;
        var resp_iv: [32]u8 = undefined;
        Sha256.hash(&session.key, &resp_key, .{});
        Sha256.hash(&session.iv, &resp_iv, .{});
        const payload = @min(security.maxPayload(), wbuf.len - 2 - security.tail());
        return .{
            .io = io,
            .r = r,
            .w = w,
            .reader = .{ .vtable = &.{ .stream = stream, .readVec = readVec }, .buffer = rbuf, .seek = 0, .end = 0 },
            .writer = .{ .vtable = &.{ .drain = drain, .flush = flush }, .buffer = wbuf[2..][0..payload] },
            .user = user,
            .security = security,
            .session = session,
            .resp_key = resp_key[0..16].*,
            .resp_iv = resp_iv[0..16].*,
            .up = .init(security, session.key, session.iv),
            .down = .init(security, resp_key[0..16].*, resp_iv[0..16].*),
            .wbuf = wbuf,
        };
    }

    /// Put the sealed request header into the stream below, unflushed: it
    /// leaves with the first chunk, or alone at the first flush (a caller
    /// that waits for data a moment first saves a packet, as Xray waits
    /// 100 ms). Before any other use of `writer`.
    pub fn writeRequest(c: *Conn, req: Request) RequestError!void {
        // padding length and bytes, the auth ID's random part, the nonce
        var rnd: [1 + 15 + 4 + 8]u8 = undefined;
        c.io.random(&rnd);
        var plain_buf: [max_plain]u8 = undefined;
        const plain = try requestPlain(&plain_buf, &c.session, c.security, req, rnd[1..][0 .. rnd[0] % 16]);
        const id = authId(&c.user, Io.Clock.real.now(c.io).toSeconds(), rnd[16..20].*);
        var sealed: [max_request]u8 = undefined;
        try c.w.writeAll(sealHeader(&sealed, &c.user, plain, id, rnd[20..28].*));
    }

    /// Our side is done: what is buffered, then the empty chunk that tells
    /// the server so, flushed. Nothing may be written after it. Xray takes
    /// it as the end of the upload; sing-box does so only without a cipher
    /// (with one it reads Xray's marker as a chunk of nothing and waits
    /// on), so a destination that answers only once we are done is not to
    /// be waited for without a timeout.
    pub fn end(c: *Conn) Io.Writer.Error!void {
        try c.sendBuffered();
        try c.w.writeAll(c.up.seal(c.io, c.wbuf, 0));
        try c.w.flush();
    }

    // ------------------------------------------------------------ writing

    /// What `writer` holds leaves as one chunk (none if it holds nothing:
    /// an empty chunk would end the stream).
    fn sendBuffered(c: *Conn) Io.Writer.Error!void {
        const n = c.writer.end;
        if (n == 0) return;
        c.writer.end = 0;
        try c.w.writeAll(c.up.seal(c.io, c.wbuf, n));
    }

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

    // ------------------------------------------------------------ reading

    // Both put the next chunk's payload into `reader.buffer` and return 0,
    // as the Reader interface allows: a sealed chunk can only be released
    // whole, once its tag is checked, so it is opened where it lands.
    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        _ = w;
        _ = limit;
        const c: *Conn = @alignCast(@fieldParentPtr("reader", io_r));
        try c.fill();
        return 0;
    }

    fn readVec(io_r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        _ = data;
        const c: *Conn = @alignCast(@fieldParentPtr("reader", io_r));
        try c.fill();
        return 0;
    }

    fn fill(c: *Conn) Io.Reader.Error!void {
        switch (c.rstate) {
            .header, .open => {},
            .eof => return error.EndOfStream,
            .failed => return error.ReadFailed,
        }
        c.next() catch |e| switch (e) {
            error.EndOfStream => {
                c.rstate = .eof;
                return error.EndOfStream;
            },
            error.ReadFailed => {
                c.rstate = .failed;
                return error.ReadFailed;
            },
            else => |v| {
                c.rstate = .failed;
                c.err = v;
                return error.ReadFailed;
            },
        };
    }

    fn next(c: *Conn) (Error || Io.Reader.Error)!void {
        if (c.rstate == .header) {
            try c.readResponse();
            c.rstate = .open;
        }
        const r = &c.reader;
        if (c.security == .none) {
            // no tag to wait for: pass on what has come of the chunk
            while (c.left == 0) {
                const raw = try c.takeLength() orelse return error.EndOfStream;
                c.left = raw ^ c.down.lengths().mask;
                if (c.left == 0) return error.EndOfStream; // the empty chunk
            }
            if (!makeRoom(r, 1)) return error.VmessChunkTooLarge;
            const avail = c.r.peekGreedy(1) catch |e| return truncated(e);
            const n = @min(avail.len, c.left, r.buffer.len - r.end);
            @memcpy(r.buffer[r.end..][0..n], avail[0..n]);
            c.r.toss(n);
            r.end += n;
            c.left -= @intCast(n);
            return;
        }
        const raw = try c.takeLength() orelse return error.EndOfStream;
        const l = c.down.lengths();
        const size = raw ^ l.mask;
        const overhead = tag_len + l.pad;
        // the empty chunk: the destination is done (its tag goes unread,
        // as in Xray)
        if (size == overhead) return error.EndOfStream;
        if (size < overhead) return error.VmessBadChunk;
        if (!makeRoom(r, size)) return error.VmessChunkTooLarge;
        const chunk = r.buffer[r.end..][0..size];
        c.r.readSliceAll(chunk) catch |e| return truncated(e);
        const n = size - overhead;
        c.down.open(chunk[0..n], chunk[n..][0..tag_len]) catch return error.VmessBadChunk;
        r.end += n;
    }

    /// The next chunk's length field; null where the stream below ends
    /// between chunks, an end as good as the empty chunk (Xray's server
    /// may leave that out, and its client takes either).
    fn takeLength(c: *Conn) (Error || Io.Reader.Error)!?u16 {
        _ = c.r.peekByte() catch |e| switch (e) {
            error.EndOfStream => return null,
            error.ReadFailed => return error.ReadFailed,
        };
        const b = c.r.takeArray(2) catch |e| return truncated(e);
        return std.mem.readInt(u16, b, .big);
    }

    /// The server's answer ahead of its first chunk: the header's length,
    /// then the header, each sealed with AES-128-GCM under a key and nonce
    /// derived from the response key and IV. The header echoes our byte,
    /// then come options and a command (a dynamic-port switch no current
    /// server sends; ignored, as Xray ignores one it cannot use).
    fn readResponse(c: *Conn) (Error || Io.Reader.Error)!void {
        const sealed_len = c.r.takeArray(2 + tag_len) catch |e| return switch (e) {
            error.EndOfStream => error.VmessNoResponse,
            error.ReadFailed => error.ReadFailed,
        };
        var len_be: [2]u8 = undefined;
        Aes128Gcm.decrypt(
            &len_be,
            sealed_len[0..2],
            sealed_len[2..].*,
            "",
            kdf(&c.resp_iv, &.{"AEAD Resp Header Len IV"})[0..12].*,
            kdf16(&c.resp_key, &.{"AEAD Resp Header Len Key"}),
        ) catch return error.VmessBadResponse;
        const n = std.mem.readInt(u16, &len_be, .big);
        // v, options, command, command length, command
        if (n < 4 or n > 4 + 255) return error.VmessBadResponse;
        var buf: [4 + 255 + tag_len]u8 = undefined;
        c.r.readSliceAll(buf[0 .. n + tag_len]) catch |e| return truncated(e);
        Aes128Gcm.decrypt(
            buf[0..n],
            buf[0..n],
            buf[n..][0..tag_len].*,
            "",
            kdf(&c.resp_iv, &.{"AEAD Resp Header IV"})[0..12].*,
            kdf16(&c.resp_key, &.{"AEAD Resp Header Key"}),
        ) catch return error.VmessBadResponse;
        if (buf[0] != c.session.v) return error.VmessBadResponse;
    }
};

/// Room for `n` more bytes behind the buffered ones, moving those to the
/// front if that makes it.
fn makeRoom(r: *Io.Reader, n: usize) bool {
    if (r.buffer.len - r.end >= n) return true;
    const data = r.buffer[r.seek..r.end];
    @memmove(r.buffer[0..data.len], data);
    r.seek = 0;
    r.end = data.len;
    return r.buffer.len - r.end >= n;
}

fn truncated(e: Io.Reader.Error) (Error || Io.Reader.Error) {
    return switch (e) {
        error.EndOfStream => error.VmessTruncated,
        error.ReadFailed => error.ReadFailed,
    };
}

// ---------------------------------------------------------------- link

/// A VMess server as a link describes it. `host` is the caller's; a REALITY
/// server name points into the link. At most one of
/// `tls` and `reality` is set: VMess seals its own body, so it also runs
/// bare.
pub const Vmess = struct {
    host: []const u8,
    port: u16,
    user: User,
    security: Security = .auto,
    tls: ?outbound.Tls = null,
    reality: ?outbound.Reality = null,
    transport: Transport = .raw,
};

/// What carries the VMess stream: the (TLS) connection itself, or a
/// transport inside it. The dialer's own types: one dialer serves every
/// protocol.
pub const Transport = outbound.Transport;
pub const Http = outbound.Http;
pub const Grpc = outbound.Grpc;
pub const Xhttp = outbound.Xhttp;

pub const LinkError = error{
    NotVmess,
    /// neither base64 of a JSON object nor `id@host:port`, or over `max_link`
    BadLink,
    /// not a UUID, nor a name of 1..30 bytes (which Xray hashes into one)
    BadId,
    UnsupportedTransport,
    UnsupportedSecurity,
    BadRealityKey,
};

/// Longest link taken: its JSON is decoded on the stack.
pub const max_link = 4096;

/// What of a `vmess://` link this build can carry. `host` and `port` are
/// the server's, already taken from the link (`linkSummary` reads them out
/// of the first form). Two forms:
///
/// - v2rayN's, which nearly every subscription uses: base64 of a JSON
///   object {v, ps, add, port, id, aid, scy, net, type, host, path, tls,
///   sni, alpn, fp}, values strings or numbers. `net` is tcp, ws,
///   httpupgrade, grpc (path the service name, type gun or multi, host the
///   authority) or xhttp (type the mode); `tls` is "tls" or empty.
/// - Xray's URL form, `vmess://id@host:port?encryption=..&type=..&security=..`,
///   with the parameters of a vless:// link (so REALITY too).
///
/// `scy` / `encryption` picks the cipher as `Security.parse` does. `aid` is
/// ignored: alterId only ever chose the pre-AEAD header, which no current
/// server takes (and one set to it on the server still takes AEAD). So are
/// `fp` (the ClientHello is always Chrome's) and allowInsecure (certificates
/// are always checked). The HTTP/1.1 disguise of raw TCP (type http), mKCP,
/// QUIC and the retired h2 transport are refused.
pub fn fromLink(link: []const u8, host: []const u8, port: u16) LinkError!Vmess {
    const body = linkBody(link) orelse return error.NotVmess;
    var p: Params = .{};
    if (std.mem.findScalar(u8, body, '@')) |at| {
        p.percent = true;
        p.id = body[0..at];
        var query: []const u8 = "";
        if (std.mem.findScalar(u8, link, '?')) |q| {
            const end = std.mem.findScalarPos(u8, link, q, '#') orelse link.len;
            query = link[q + 1 .. end];
        }
        var it = std.mem.tokenizeScalar(u8, query, '&');
        while (it.next()) |kv| {
            const eq = std.mem.findScalar(u8, kv, '=') orelse continue;
            const fields = .{
                .{ "encryption", &p.scy },      .{ "type", &p.net },            .{ "headerType", &p.header_type },
                .{ "host", &p.host },           .{ "path", &p.path },           .{ "security", &p.tls },
                .{ "sni", &p.sni },             .{ "peer", &p.peer },           .{ "alpn", &p.alpn },
                .{ "serviceName", &p.service }, .{ "authority", &p.authority }, .{ "mode", &p.mode },
                .{ "pbk", &p.pbk },             .{ "sid", &p.sid },             .{ "extra", &p.extra },
            };
            inline for (fields) |f| if (std.mem.eql(u8, kv[0..eq], f[0])) {
                f[1].* = kv[eq + 1 ..];
            };
        }
        return build(&p, host, port);
    }
    var buf: [2 * max_link]u8 = undefined;
    const j = parseJson(body, &buf) orelse return error.BadLink;
    p = .{
        .id = j.id.text,
        .scy = j.scy.text,
        .net = j.net.text,
        .header_type = j.type.text,
        .host = j.host.text,
        .path = j.path.text,
        .tls = j.tls.text,
        .sni = j.sni.text,
        .alpn = j.alpn.text,
    };
    // the JSON has one set of fields for every transport
    if (is(p.net, "grpc")) {
        p.service = p.path;
        p.authority = p.host;
        p.mode = p.header_type;
    } else if (is(p.net, "xhttp") or is(p.net, "splithttp")) {
        p.mode = if (is(p.header_type, "none")) "" else p.header_type;
    }
    return build(&p, host, port);
}

pub const Summary = struct {
    /// the remark ("ps"), as written: may be empty
    name: []const u8,
    host: []const u8,
    port: u16,
    tls: bool,
};

/// For the subscription parser: what a base64-JSON link names its server,
/// and where it is. Null for anything else, the URL form included (it
/// reads as any `scheme://user@host:port#name` link does). Slices point
/// into `buf`, which takes the decoded JSON and its unescaped strings:
/// twice the link's length is always enough; null if it is too small.
pub fn linkSummary(link: []const u8, buf: []u8) ?Summary {
    const body = linkBody(link) orelse return null;
    if (std.mem.findScalar(u8, body, '@') != null) return null;
    const j = parseJson(body, buf) orelse return null;
    if (j.add.text.len == 0) return null;
    return .{
        .name = j.ps.text,
        .host = j.add.text,
        .port = std.fmt.parseInt(u16, j.port.text, 10) catch return null,
        .tls = is(j.tls.text, "tls"),
    };
}

/// What follows "vmess://" up to a query or fragment.
fn linkBody(link: []const u8) ?[]const u8 {
    const prefix = "vmess://";
    if (!std.ascii.startsWithIgnoreCase(link, prefix)) return null;
    const rest = link[prefix.len..];
    return rest[0 .. std.mem.findAny(u8, rest, "?#") orelse rest.len];
}

fn is(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// A link's settings by the names of the URL form, whichever form it had.
const Params = struct {
    id: []const u8 = "",
    scy: []const u8 = "",
    net: []const u8 = "",
    header_type: []const u8 = "",
    host: []const u8 = "",
    path: []const u8 = "",
    tls: []const u8 = "",
    sni: []const u8 = "",
    peer: []const u8 = "",
    alpn: []const u8 = "",
    service: []const u8 = "",
    authority: []const u8 = "",
    mode: []const u8 = "",
    pbk: []const u8 = "",
    sid: []const u8 = "",
    extra: []const u8 = "",
    /// values are percent-encoded (the URL form)
    percent: bool = false,

    /// `raw` into a outbound.Text, decoded if need be; false if it does not fit.
    fn set(p: *const Params, t: anytype, raw: []const u8) bool {
        var n: usize = 0;
        var i: usize = 0;
        while (i < raw.len) : (n += 1) {
            if (n == t.buf.len) return false;
            t.buf[n] = raw[i];
            i += 1;
            // a '%' not followed by two hex digits stands for itself
            if (p.percent and raw[i - 1] == '%' and i + 2 <= raw.len) {
                t.buf[n] = std.fmt.parseInt(u8, raw[i..][0..2], 16) catch continue;
                i += 2;
            }
        }
        t.len = @intCast(n);
        return true;
    }
};

fn build(p: *const Params, host: []const u8, port: u16) LinkError!Vmess {
    var id: outbound.Text(36) = .{};
    if (!p.set(&id, p.id)) return error.BadId;
    var out: Vmess = .{
        .host = host,
        .port = port,
        .user = .init(parseId(id.slice()) orelse return error.BadId),
        .security = .parse(p.scy),
    };

    const sni = if (p.sni.len > 0) p.sni else p.peer;
    if (p.net.len == 0 or is(p.net, "tcp") or is(p.net, "raw")) {
        if (p.header_type.len > 0 and !is(p.header_type, "none")) return error.UnsupportedTransport;
    } else if (is(p.net, "ws") or is(p.net, "httpupgrade")) {
        var h: Http = .{};
        if (!p.set(&h.path, if (p.path.len > 0) p.path else "/")) return error.UnsupportedTransport;
        if (h.path.len == 0 or h.path.buf[0] != '/') return error.UnsupportedTransport;
        if (!p.set(&h.host, if (p.host.len > 0) p.host else if (sni.len > 0) sni else host)) return error.UnsupportedTransport;
        out.transport = if (is(p.net, "ws")) .{ .ws = h } else .{ .httpupgrade = h };
    } else if (is(p.net, "grpc")) {
        var g: Grpc = .{};
        if (!p.set(&g.service_name, p.service) or !p.set(&g.authority, p.authority)) return error.UnsupportedTransport;
        if (p.mode.len > 0 and !is(p.mode, "gun") and !is(p.mode, "multi") and !is(p.mode, "none")) return error.UnsupportedTransport;
        g.multi = is(p.mode, "multi");
        out.transport = .{ .grpc = g };
    } else if (is(p.net, "xhttp") or is(p.net, "splithttp")) {
        // which modes and extras can be carried is the dialer's to say
        var x: Xhttp = .{};
        if (!p.set(&x.path, p.path) or !p.set(&x.mode, p.mode) or !p.set(&x.extra, p.extra)) return error.UnsupportedTransport;
        if (!p.set(&x.host, if (p.host.len > 0) p.host else if (sni.len > 0) sni else host)) return error.UnsupportedTransport;
        out.transport = .{ .xhttp = x };
    } else return error.UnsupportedTransport;

    if (p.tls.len == 0 or is(p.tls, "none")) {
        // bare: the header and the body are sealed all the same
    } else if (is(p.tls, "tls")) {
        var t: outbound.Tls = .{};
        // the certificate is checked against this name: sni, else the Host
        // a CDN routes by, else the address
        if (!p.set(&t.server_name, if (sni.len > 0) sni else if (p.host.len > 0) p.host else host)) return error.UnsupportedSecurity;
        const has_h2 = std.mem.find(u8, p.alpn, "h2") != null;
        const has_h11 = std.mem.find(u8, p.alpn, "http") != null;
        t.alpn = switch (out.transport) {
            // WebSocket and HTTPUpgrade need HTTP/1.1; gRPC and XHTTP run on HTTP/2
            .ws, .httpupgrade => .http11,
            .grpc, .xhttp => .h2,
            .raw => if (has_h11 and !has_h2) .http11 else if (has_h2 and !has_h11) .h2 else .h2_http11,
        };
        out.tls = t;
    } else if (is(p.tls, "reality")) {
        // Only the URL form names the key, so only its `sni`, which lies in
        // the link, is kept here: the JSON form's lies in a buffer that is
        // gone on return, and fails on the key first.
        out.reality = .{
            .server_name = if (sni.len > 0) sni else host,
            .public_key = realityKey(p.pbk) orelse return error.BadRealityKey,
            .short_id = @splat(0),
        };
        if (p.sid.len > 16 or p.sid.len % 2 != 0) return error.BadRealityKey;
        _ = std.fmt.hexToBytes(out.reality.?.short_id[0 .. p.sid.len / 2], p.sid) catch return error.BadRealityKey;
    } else return error.UnsupportedSecurity;
    return out;
}

/// An account's `id` as Xray reads it: a UUID, or a name of up to 30 bytes
/// that stands for the UUID made of its SHA-1 (version 5 over the nil UUID).
fn parseId(text: []const u8) ?[16]u8 {
    if (text.len >= 32 and text.len <= 36) return outbound.parseUuid(text);
    if (text.len == 0 or text.len > 30) return null;
    var h: crypto.hash.Sha1 = .init(.{});
    h.update(&@as([16]u8, @splat(0)));
    h.update(text);
    var d = h.finalResult();
    d[6] = d[6] & 0x0f | 0x50;
    d[8] = d[8] & 0x3f | 0x80;
    return d[0..16].*;
}

/// A REALITY public key as links write it: 32 bytes in base64, either
/// alphabet, padded or not.
fn realityKey(text: []const u8) ?[32]u8 {
    var key: [33]u8 = undefined;
    const got = decodeBase64(&key, text) orelse return null;
    return if (got.len == 32) key[0..32].* else null;
}

/// Base64 as links carry it: either alphabet, padding and line breaks
/// optional. Null on any other byte, or if `out` is too small.
fn decodeBase64(out: []u8, text: []const u8) ?[]u8 {
    var acc: u32 = 0;
    var bits: u5 = 0;
    var n: usize = 0;
    for (text) |c| {
        const v: u32 = switch (c) {
            'A'...'Z' => c - 'A',
            'a'...'z' => c - 'a' + 26,
            '0'...'9' => c - '0' + 52,
            '+', '-' => 62,
            '/', '_' => 63,
            '=', '\r', '\n', ' ' => continue,
            else => return null,
        };
        acc = (acc << 6 | v) & 0xffff;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n == out.len) return null;
            out[n] = @truncate(acc >> bits);
            n += 1;
        }
    }
    return out[0..n];
}

/// A JSON value kept as its text: links write ports and versions as
/// strings or as numbers, and either reads the same here.
const Loose = struct {
    text: []const u8 = "",

    pub fn jsonParse(a: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) std.json.ParseError(@TypeOf(source.*))!Loose {
        return switch (try source.nextAllocMax(a, .alloc_if_needed, options.max_value_len.?)) {
            inline .string, .allocated_string, .number, .allocated_number => |s| .{ .text = s },
            .true => .{ .text = "true" },
            .false, .null => .{},
            else => error.UnexpectedToken,
        };
    }
};

const Json = struct {
    ps: Loose = .{},
    add: Loose = .{},
    port: Loose = .{},
    id: Loose = .{},
    scy: Loose = .{},
    net: Loose = .{},
    type: Loose = .{},
    host: Loose = .{},
    path: Loose = .{},
    tls: Loose = .{},
    sni: Loose = .{},
    alpn: Loose = .{},
};

/// The JSON a link's base64 holds. `buf` takes the decoded text in front
/// and what the parser allocates behind it: strings with escapes, which
/// are no longer than their source. Nothing outlives `buf`.
fn parseJson(b64: []const u8, buf: []u8) ?Json {
    if (b64.len > max_link) return null;
    const text = decodeBase64(buf, b64) orelse return null;
    var fba: std.heap.FixedBufferAllocator = .init(buf[text.len..]);
    return std.json.parseFromSliceLeaky(Json, fba.allocator(), text, .{
        .ignore_unknown_fields = true,
        .duplicate_field_behavior = .use_last,
    }) catch null;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// Vectors from Xray-core's own code (proxy/vmess/aead, common/protocol,
// proxy/vmess/encoding) run on these inputs.
const test_uuid = hex("b831381d63244d53ad4f8cda48b30811");

test "user keys, KDF, auth ID and the sealed header are Xray's" {
    const u: User = .init(test_uuid);
    try testing.expectEqualSlices(u8, &hex("b50d916ac0cec067981af8e5f38a758f"), &u.cmd_key);
    try testing.expectEqualSlices(u8, &hex("1415ba74ca8b3d041a8f583fb4116315"), &u.auth_key);
    try testing.expectEqualSlices(u8, &hex("1e3858c2acb5e5338a1569aac055c295a0c0e2738b2d941c4bf461cdc363efb4"), &kdf(&u.cmd_key, &.{}));
    const id = authId(&u, 1700000000, .{ 1, 2, 3, 4 });
    try testing.expectEqualSlices(u8, &hex("4774fe5cc901ea4f81f2159909767a36"), &id);
    const nonce: [8]u8 = .{ 9, 8, 7, 6, 5, 4, 3, 2 };
    try testing.expectEqualSlices(
        u8,
        &hex("837b22e07a96c156dfbad7865f7bfa3ff89668c3febd1392e9b379bdedb50137"),
        &kdf(&u.cmd_key, &.{ "VMess Header AEAD Key_Length", &id, &nonce }),
    );
    var out: [max_request]u8 = undefined;
    try testing.expectEqualSlices(u8, &hex("4774fe5cc901ea4f81f2159909767a364d51e8e03363f01d922272bd3a6d9e95b6d7" ++
        "0908070605040302daf7c2009afd92334a1a5d19d443ec2415eb72273420902b93566ac82b46610b1adb5abe23f3f31a9e0001f6c5b6"), sealHeader(&out, &u, "vmess request header plaintext", id, nonce));
}

test "body: SHAKE128 lengths, ChaCha20 key, a sealed chunk" {
    var b: Body = .init(.aes_128_gcm, @splat(0x11), @splat(0x22));
    var probe = b;
    try testing.expectEqual(0xccfb, probe.draw());
    try testing.expectEqual(0x8205, probe.draw());
    try testing.expectEqual(0xf24f, probe.draw());

    // padding first (0xccfb % 64 = 59), then the mask
    var buf: [2 + 5 + tag_len + 63]u8 = undefined;
    @memcpy(buf[2..7], "hello");
    const chunk = b.seal(testing.io, &buf, 5);
    try testing.expectEqual(2 + 5 + tag_len + 59, chunk.len);
    try testing.expectEqual((5 + tag_len + 59) ^ 0x8205, std.mem.readInt(u16, chunk[0..2], .big));
    try testing.expectEqualSlices(u8, &hex("f4cf6e664ee131828ffbc973ca642a355fabafca31"), chunk[2..][0 .. 5 + tag_len]);
    try testing.expectEqual(1, b.count);

    const c: Body = .init(.chacha20_poly1305, @splat(0x11), @splat(0x22));
    try testing.expectEqualSlices(u8, &hex("8057b6feaa62d90126274cf9ba31c64299310922acd55ee2a01b34d5cab0196c"), &c.key);

    // none: the mask only, no padding drawn
    var n: Body = .init(.none, @splat(0x11), @splat(0x22));
    @memcpy(buf[2..7], "hello");
    const plain = n.seal(testing.io, &buf, 5);
    try testing.expectEqual(2 + 5, plain.len);
    try testing.expectEqual(5 ^ 0xccfb, std.mem.readInt(u16, plain[0..2], .big));
    try testing.expectEqualStrings("hello", plain[2..]);
}

test "the response header Xray seals opens; one with another byte does not" {
    const response = hex("1ed5e218e618e8c5350363b980c93de5efa06015b5dc7a63f67ab72353ff9aa4f47a9ee044da");
    const session: Session = .{ .key = @splat(0x11), .iv = @splat(0x22), .v = 0x5a };
    var rbuf: [8192]u8 = undefined;
    var wbuf: [write_buffer_len]u8 = undefined;
    var sink: Io.Writer.Discarding = .init(&.{});
    for ([_]u8{ 0x5a, 0x5b }) |v| {
        var below: Io.Reader = .fixed(&response);
        var s = session;
        s.v = v;
        var c: Conn = .initSession(testing.io, .init(test_uuid), .aes_128_gcm, s, &below, &sink.writer, &rbuf, &wbuf);
        if (v == 0x5a) {
            // the header, then the stream ends between chunks: a clean end
            try testing.expectError(error.EndOfStream, c.reader.peekByte());
            try testing.expectEqual(null, c.err);
        } else {
            try testing.expectError(error.ReadFailed, c.reader.peekByte());
            try testing.expectEqual(error.VmessBadResponse, c.err.?);
        }
    }
}

/// The server's side, opening and answering a connection as Xray's does.
const TestServer = struct {
    session: Session,
    security: Security,
    options: u8 = 0,
    command: Command = .tcp,
    port: u16 = 0,
    address: [255]u8 = undefined,
    address_len: usize = 0,
    address_type: u8 = 0,
    padding: usize = 0,
    up: Body,
    down: Body,
    resp_key: [16]u8,
    resp_iv: [16]u8,

    fn init(session: Session, security: Security) TestServer {
        var resp_key: [32]u8 = undefined;
        var resp_iv: [32]u8 = undefined;
        Sha256.hash(&session.key, &resp_key, .{});
        Sha256.hash(&session.iv, &resp_iv, .{});
        return .{
            .session = session,
            .security = security,
            .up = .init(security, session.key, session.iv),
            .down = .init(security, resp_key[0..16].*, resp_iv[0..16].*),
            .resp_key = resp_key[0..16].*,
            .resp_iv = resp_iv[0..16].*,
        };
    }

    fn accept(user: *const User, in: *Io.Reader, now: i64) !TestServer {
        const id = (try in.takeArray(16)).*;
        var block: [16]u8 = undefined;
        crypto.core.aes.Aes128.initDec(user.auth_key).decrypt(&block, &id);
        if (std.mem.readInt(u32, block[12..16], .big) != std.hash.Crc32.hash(block[0..12])) return error.BadAuthId;
        if (@abs(std.mem.readInt(i64, block[0..8], .big) - now) > 120) return error.BadTime;
        const sealed_len = (try in.takeArray(2 + tag_len)).*;
        const nonce = (try in.takeArray(8)).*;
        const ck = &user.cmd_key;
        var len_be: [2]u8 = undefined;
        try Aes128Gcm.decrypt(&len_be, sealed_len[0..2], sealed_len[2..].*, &id, kdf(ck, &.{ "VMess Header AEAD Nonce_Length", &id, &nonce })[0..12].*, kdf16(ck, &.{ "VMess Header AEAD Key_Length", &id, &nonce }));
        const n = std.mem.readInt(u16, &len_be, .big);
        const sealed = try in.take(n + tag_len);
        var plain: [max_plain]u8 = undefined;
        const p = plain[0..n];
        try Aes128Gcm.decrypt(p, sealed[0..n], sealed[n..][0..tag_len].*, &id, kdf(ck, &.{ "VMess Header AEAD Nonce", &id, &nonce })[0..12].*, kdf16(ck, &.{ "VMess Header AEAD Key", &id, &nonce }));
        if (std.mem.readInt(u32, p[n - 4 ..][0..4], .big) != std.hash.Fnv1a_32.hash(p[0 .. n - 4])) return error.BadChecksum;
        if (p[0] != 1 or p[36] != 0) return error.BadHeader;
        const session: Session = .{ .iv = p[1..17].*, .key = p[17..33].*, .v = p[33] };
        const security = std.enums.fromInt(Security, p[35] & 0x0f) orelse return error.BadSecurity;
        var s: TestServer = .init(session, security);
        s.options = p[34];
        s.command = std.enums.fromInt(Command, p[37]) orelse return error.BadCommand;
        s.padding = p[35] >> 4;
        var i: usize = plain_fixed;
        if (s.command != .mux) {
            s.port = std.mem.readInt(u16, p[i..][0..2], .big);
            s.address_type = p[i + 2];
            i += 3;
            s.address_len = switch (s.address_type) {
                1 => 4,
                3 => 16,
                2 => blk: {
                    i += 1;
                    break :blk p[i - 1];
                },
                else => return error.BadAddress,
            };
            @memcpy(s.address[0..s.address_len], p[i..][0..s.address_len]);
            i += s.address_len;
        }
        if (i + s.padding + 4 != n) return error.BadLength;
        return s;
    }

    /// The next chunk's payload, null at the empty chunk.
    fn readChunk(s: *TestServer, in: *Io.Reader, out: []u8) !?[]u8 {
        const raw = std.mem.readInt(u16, try in.takeArray(2), .big);
        const l = s.up.lengths();
        const size = raw ^ l.mask;
        if (s.security == .none) {
            if (size == 0) return null;
            try in.readSliceAll(out[0..size]);
            return out[0..size];
        }
        const n = size - tag_len - l.pad;
        const chunk = try in.take(size);
        @memcpy(out[0..n], chunk[0..n]);
        try s.up.open(out[0..n], chunk[n..][0..tag_len]); // the empty chunk too
        return if (n == 0) null else out[0..n];
    }

    fn writeResponse(s: *TestServer, out: *Io.Writer) !void {
        const plain = [4]u8{ s.session.v, 0, 0, 0 };
        var sealed: [2 + tag_len + 4 + tag_len]u8 = undefined;
        Aes128Gcm.encrypt(sealed[0..2], sealed[2..18], &.{ 0, 4 }, "", kdf(&s.resp_iv, &.{"AEAD Resp Header Len IV"})[0..12].*, kdf16(&s.resp_key, &.{"AEAD Resp Header Len Key"}));
        Aes128Gcm.encrypt(sealed[18..22], sealed[22..38], &plain, "", kdf(&s.resp_iv, &.{"AEAD Resp Header IV"})[0..12].*, kdf16(&s.resp_key, &.{"AEAD Resp Header Key"}));
        try out.writeAll(&sealed);
    }

    fn writeChunk(s: *TestServer, out: *Io.Writer, payload: []const u8) !void {
        var buf: [2 + 16000 + tag_len + 63]u8 = undefined;
        @memcpy(buf[2..][0..payload.len], payload);
        try out.writeAll(s.down.seal(testing.io, &buf, payload.len));
    }
};

fn pattern(buf: []u8, seed: u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i *% 7 +% seed);
}

test "a whole exchange with a server that opens and answers as Xray's" {
    const user: User = .init(test_uuid);
    var up_buf: [64 * 1024]u8 = undefined;
    var down_buf: [64 * 1024]u8 = undefined;
    var got: [64 * 1024]u8 = undefined;
    var rbuf: [read_buffer_len]u8 = undefined;
    var wbuf: [write_buffer_len]u8 = undefined;
    var payload: [20000]u8 = undefined;
    pattern(&payload, 1);
    var answer: [15000]u8 = undefined; // sing-box's largest chunk payload
    pattern(&answer, 2);

    for ([_]Security{ .aes_128_gcm, .chacha20_poly1305, .none }) |sec| {
        var up: Io.Writer = .fixed(&up_buf);
        var below: Io.Reader = .fixed(&.{});
        var c: Conn = .init(testing.io, user, sec, &below, &up, &rbuf, &wbuf);
        try c.writeRequest(.{ .address = .{ .domain = "example.com" }, .port = 80 });
        try c.writer.writeAll(&payload);
        try c.writer.flush();
        try c.writer.writeAll("tail");
        try c.end();

        var in: Io.Reader = .fixed(up.buffered());
        var s: TestServer = try .accept(&user, &in, Io.Clock.real.now(testing.io).toSeconds());
        try testing.expectEqual(sec, s.security);
        try testing.expectEqual(sec.options(), s.options);
        try testing.expectEqual(.tcp, s.command);
        try testing.expectEqual(80, s.port);
        try testing.expectEqual(2, s.address_type);
        try testing.expectEqualStrings("example.com", s.address[0..s.address_len]);
        var total: usize = 0;
        var chunks: usize = 0;
        while (try s.readChunk(&in, got[total..])) |p| {
            try testing.expect(p.len <= sec.maxPayload());
            total += p.len;
            chunks += 1;
        }
        try testing.expectEqual(0, in.bufferedLen());
        try testing.expectEqualSlices(u8, &payload, got[0..20000]);
        try testing.expectEqualStrings("tail", got[20000..total]);
        // 20000 bytes in Xray's chunks, then the tail
        try testing.expectEqual(4, chunks);

        var resp: Io.Writer = .fixed(&down_buf);
        try s.writeResponse(&resp);
        try s.writeChunk(&resp, "HTTP/1.1 200 OK\r\n\r\n");
        try s.writeChunk(&resp, &answer);
        try s.writeChunk(&resp, ""); // the end
        below = .fixed(resp.buffered());
        const all = try c.reader.allocRemaining(testing.allocator, .unlimited);
        defer testing.allocator.free(all);
        try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n\r\n", all[0..19]);
        try testing.expectEqualSlices(u8, &answer, all[19..]);
        try testing.expectEqual(null, c.err);
    }
}

test "request header: every kind of address, mux without one" {
    const user: User = .init(test_uuid);
    var buf: [max_request]u8 = undefined;
    var rbuf: [read_buffer_len]u8 = undefined;
    var wbuf: [write_buffer_len]u8 = undefined;
    var below: Io.Reader = .fixed(&.{});
    const now = Io.Clock.real.now(testing.io).toSeconds();
    const longest: [255]u8 = @splat('a');
    const too_long: [256]u8 = @splat('a');
    const ip6 = hex("20010db8000000000000000000000001");
    const Case = struct { req: Request, type: u8 = 0, addr: []const u8 = "" };
    for ([_]Case{
        .{ .req = .{ .address = .{ .ip4 = .{ 192, 0, 2, 1 } }, .port = 443 }, .type = 1, .addr = &.{ 192, 0, 2, 1 } },
        .{ .req = .{ .address = .{ .ip6 = ip6 }, .port = 65535 }, .type = 3, .addr = &ip6 },
        .{ .req = .{ .address = .{ .domain = "a" }, .port = 1 }, .type = 2, .addr = "a" },
        .{ .req = .{ .address = .{ .domain = &longest }, .port = 8080 }, .type = 2, .addr = &longest },
        // mux names its destinations in its frames: whatever the request holds stays out
        .{ .req = .{ .command = .mux } },
        .{ .req = .{ .command = .mux, .address = .{ .domain = "v1.mux.cool" }, .port = 666 } },
    }) |case| {
        var up: Io.Writer = .fixed(&buf);
        var c: Conn = .init(testing.io, user, .chacha20_poly1305, &below, &up, &rbuf, &wbuf);
        try c.writeRequest(case.req);
        var in: Io.Reader = .fixed(up.buffered());
        const s: TestServer = try .accept(&user, &in, now);
        try testing.expectEqual(0, in.bufferedLen()); // the header and nothing else
        try testing.expectEqual(case.req.command, s.command);
        try testing.expectEqual(Security.chacha20_poly1305, s.security);
        try testing.expectEqual(c.session.v, s.session.v);
        try testing.expectEqualSlices(u8, &c.session.key, &s.session.key);
        try testing.expectEqual(if (case.req.command == .mux) 0 else case.req.port, s.port);
        try testing.expectEqual(case.type, s.address_type);
        try testing.expectEqualSlices(u8, case.addr, s.address[0..s.address_len]);
    }
    for ([_][]const u8{ "", &too_long }) |domain| {
        var up: Io.Writer = .fixed(&buf);
        var c: Conn = .init(testing.io, user, .auto, &below, &up, &rbuf, &wbuf);
        try testing.expectError(error.VmessBadAddress, c.writeRequest(.{ .address = .{ .domain = domain }, .port = 80 }));
        try testing.expectEqual(0, up.end);
    }
    // a server whose clock is more than 120 s away refuses the auth ID
    var up: Io.Writer = .fixed(&buf);
    var c: Conn = .init(testing.io, user, .auto, &below, &up, &rbuf, &wbuf);
    try c.writeRequest(.{ .address = .{ .domain = "example.com" }, .port = 80 });
    var in: Io.Reader = .fixed(up.buffered());
    try testing.expectError(error.BadTime, TestServer.accept(&user, &in, now + 200));
    // and one with another user's key does not find it
    in = .fixed(up.buffered());
    try testing.expectError(error.BadAuthId, TestServer.accept(&User.init(@splat(7)), &in, now));
}

/// A stream below that hands out at most `step` bytes at a time, as a
/// socket may.
const Trickle = struct {
    data: []const u8,
    step: usize,
    interface: Io.Reader,

    fn init(data: []const u8, step: usize, buffer: []u8) Trickle {
        return .{ .data = data, .step = step, .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 } };
    }

    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const t: *Trickle = @alignCast(@fieldParentPtr("interface", io_r));
        if (t.data.len == 0) return error.EndOfStream;
        const n = try w.write(t.data[0..limit.minInt(@min(t.step, t.data.len))]);
        t.data = t.data[n..];
        return n;
    }
};

const test_session: Session = .{ .key = @splat(0x31), .iv = @splat(0x32), .v = 0x33 };

test "chunks arriving in pieces, read in pieces" {
    var down_buf: [64 * 1024]u8 = undefined;
    var answer: [30000]u8 = undefined;
    pattern(&answer, 3);
    var rbuf: [read_buffer_len]u8 = undefined;
    var wbuf: [write_buffer_len]u8 = undefined;
    var sink: Io.Writer.Discarding = .init(&.{});
    var below_buf: [64]u8 = undefined;
    var got: [30000]u8 = undefined;

    for ([_]Security{ .aes_128_gcm, .chacha20_poly1305, .none }) |sec| {
        var s: TestServer = .init(test_session, sec);
        var resp: Io.Writer = .fixed(&down_buf);
        try s.writeResponse(&resp);
        // chunks of every kind of size: tiny, Xray's, sing-box's
        var sent: usize = 0;
        for ([_]usize{ 1, 2, 8192 - 82, 15000, 100, 6000, 786, 1 }) |n| {
            try s.writeChunk(&resp, answer[sent..][0..n]);
            sent += n;
        }
        try testing.expectEqual(answer.len, sent);
        try s.writeChunk(&resp, "");

        for ([_]usize{ 1, 7, 1000, 64 * 1024 }) |step| {
            var below: Trickle = .init(resp.buffered(), step, &below_buf);
            var c: Conn = .initSession(testing.io, .init(test_uuid), sec, test_session, &below.interface, &sink.writer, &rbuf, &wbuf);
            // a reader that takes odd amounts, so chunks straddle its reads
            var n: usize = 0;
            var want: usize = 1;
            while (n < got.len) : (want = want * 3 % 4099 + 1) {
                const k = @min(want, got.len - n);
                try c.reader.readSliceAll(got[n..][0..k]);
                n += k;
            }
            try testing.expectEqualSlices(u8, &answer, &got);
            try testing.expectError(error.EndOfStream, c.reader.takeByte());
            try testing.expectEqual(null, c.err);
        }
    }
}

test "what a broken stream reads as" {
    var down_buf: [40000]u8 = undefined;
    var rbuf: [read_buffer_len]u8 = undefined;
    var wbuf: [write_buffer_len]u8 = undefined;
    var sink: Io.Writer.Discarding = .init(&.{});
    var payload: [16000]u8 = undefined;
    pattern(&payload, 4);
    // Offsets are from the second chunk's start (`first` set) or the
    // stream's; `take` bytes of the second chunk read fine before the end.
    const Case = struct { cut: ?usize = null, flip: ?usize = null, big: bool = false, sec: Security = .aes_128_gcm, want: Error, first: bool = true, take: usize = 0 };
    const header_len = 2 + tag_len + 4 + tag_len;
    for ([_]Case{
        // nothing at all: the server refused the request
        .{ .cut = 0, .want = error.VmessNoResponse, .first = false },
        // the response header cut short, or damaged
        .{ .cut = 1, .want = error.VmessNoResponse, .first = false },
        .{ .cut = header_len - 1, .want = error.VmessTruncated, .first = false },
        .{ .flip = 1, .want = error.VmessBadResponse, .first = false },
        .{ .flip = 20, .want = error.VmessBadResponse, .first = false },
        // the second chunk: its payload or its tag damaged, or cut short
        .{ .flip = 2 + 1, .want = error.VmessBadChunk, .sec = .chacha20_poly1305 },
        .{ .flip = 2 + 12 + 3, .want = error.VmessBadChunk },
        .{ .cut = 1, .want = error.VmessTruncated },
        .{ .cut = 2 + 10, .want = error.VmessTruncated },
        .{ .cut = 1, .want = error.VmessTruncated, .sec = .none },
        // without a cipher what came of a chunk is passed on first
        .{ .cut = 2 + 3, .want = error.VmessTruncated, .sec = .none, .take = 3 },
        // a chunk the buffer cannot take
        .{ .big = true, .want = error.VmessChunkTooLarge },
    }) |case| {
        var s: TestServer = .init(test_session, case.sec);
        var resp: Io.Writer = .fixed(&down_buf);
        try s.writeResponse(&resp);
        try s.writeChunk(&resp, "first");
        const second = if (case.first) resp.end else 0;
        try s.writeChunk(&resp, if (case.big) &payload else "second chunk");
        var stream_bytes = resp.buffered();
        if (case.flip) |i| stream_bytes[second + i] ^= 0x40;
        if (case.cut) |n| stream_bytes = stream_bytes[0 .. second + n];

        var below: Io.Reader = .fixed(stream_bytes);
        var c: Conn = .initSession(testing.io, .init(test_uuid), case.sec, test_session, &below, &sink.writer, rbuf[0..8192], &wbuf);
        if (case.first) try testing.expectEqualStrings("first", try c.reader.take(5));
        try testing.expectEqualStrings("second chunk"[0..case.take], try c.reader.take(case.take));
        try testing.expectError(error.ReadFailed, c.reader.takeByte());
        try testing.expectEqual(case.want, c.err.?);
        // and it stays failed
        try testing.expectError(error.ReadFailed, c.reader.takeByte());
    }
}

/// "vmess://" and the base64 of `json`, as v2rayN writes a link.
fn testLink(buf: []u8, json: []const u8) []const u8 {
    const prefix = "vmess://";
    @memcpy(buf[0..prefix.len], prefix);
    return buf[0 .. prefix.len + std.base64.standard.Encoder.encode(buf[prefix.len..], json).len];
}

test "links: v2rayN's base64 JSON" {
    var lb: [1024]u8 = undefined;
    var sb: [2048]u8 = undefined;
    const user: User = .init(test_uuid);

    // WebSocket behind a CDN, everything a string
    const cdn = testLink(&lb,
        \\{"v":"2","ps":"\u041d\u0438\u0434\u0435\u0440\u043b\u0430\u043d\u0434\u044b 1","add":"cdn.example","port":"443",
        \\ "id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto","net":"ws","type":"none",
        \\ "host":"h.example","path":"/vm?ed=2048","tls":"tls","sni":"s.example","alpn":"h2,http/1.1","fp":"chrome"}
    );
    const sum = linkSummary(cdn, &sb).?;
    try testing.expectEqualStrings("Нидерланды 1", sum.name);
    try testing.expectEqualStrings("cdn.example", sum.host);
    try testing.expectEqual(443, sum.port);
    try testing.expect(sum.tls);
    const ws = try fromLink(cdn, sum.host, sum.port);
    try testing.expectEqualStrings("cdn.example", ws.host);
    try testing.expectEqual(443, ws.port);
    try testing.expectEqualSlices(u8, &user.cmd_key, &ws.user.cmd_key);
    try testing.expectEqualSlices(u8, &user.auth_key, &ws.user.auth_key);
    try testing.expectEqual(Security.auto, ws.security);
    try testing.expectEqualStrings("/vm?ed=2048", ws.transport.ws.path.slice());
    try testing.expectEqualStrings("h.example", ws.transport.ws.host.slice());
    try testing.expectEqualStrings("s.example", ws.tls.?.server_name.slice());
    try testing.expectEqual(.http11, ws.tls.?.alpn); // WebSocket, whatever the link offers
    try testing.expectEqual(null, ws.reality);

    // bare TCP, numbers as numbers, no padding on the base64, no remark
    const bare_json =
        \\{"v":2,"add":"1.2.3.4","port":8080,"id":"b831381d63244d53ad4f8cda48b30811","aid":0,"net":"tcp","scy":"chacha20-poly1305","tls":""}
    ;
    const bare_link = testLink(&lb, bare_json);
    const bare_sum = linkSummary(std.mem.trimEnd(u8, bare_link, "="), &sb).?;
    try testing.expectEqualStrings("", bare_sum.name);
    try testing.expectEqualStrings("1.2.3.4", bare_sum.host);
    try testing.expectEqual(8080, bare_sum.port);
    try testing.expect(!bare_sum.tls);
    const bare = try fromLink(std.mem.trimEnd(u8, bare_link, "="), "1.2.3.4", 8080);
    try testing.expectEqual(.raw, std.meta.activeTag(bare.transport));
    try testing.expectEqual(null, bare.tls);
    try testing.expectEqual(.chacha20_poly1305, bare.security);
    try testing.expectEqualSlices(u8, &user.cmd_key, &bare.user.cmd_key);

    // the fewest fields: TCP, auto, the name the certificate is checked
    // against falls back to the address; "none" and "zero" are auto as in Xray 26
    const min = try fromLink(testLink(&lb,
        \\{"add":"v.example","port":443,"id":"example","tls":"tls","scy":"none","alpn":"h2"}
    ), "v.example", 443);
    try testing.expectEqual(Security.auto, min.security);
    try testing.expectEqualStrings("v.example", min.tls.?.server_name.slice());
    try testing.expectEqual(.h2, min.tls.?.alpn);
    // a name for an id is the UUID Xray makes of it (feb54431-301b-52bb-a6dd-e1e93e81bb9e)
    try testing.expectEqualSlices(u8, &hex("c26b55a50b3f31064e0f76083f303302"), &min.user.cmd_key);

    // gRPC: path is the service, type the mode, host the authority
    const grpc = try fromLink(testLink(&lb,
        \\{"add":"g.example","port":"2053","id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"grpc","path":"tun/svc","type":"multi","host":"a.example","tls":"tls","sni":"g.example"}
    ), "g.example", 2053);
    try testing.expectEqualStrings("tun/svc", grpc.transport.grpc.service_name.slice());
    try testing.expectEqualStrings("a.example", grpc.transport.grpc.authority.slice());
    try testing.expect(grpc.transport.grpc.multi);
    try testing.expectEqual(.h2, grpc.tls.?.alpn);

    // HTTPUpgrade without TLS: the Host falls back to the address
    const hu = try fromLink(testLink(&lb,
        \\{"add":"u.example","port":80,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"httpupgrade","path":"/up"}
    ), "u.example", 80);
    try testing.expectEqualStrings("/up", hu.transport.httpupgrade.path.slice());
    try testing.expectEqualStrings("u.example", hu.transport.httpupgrade.host.slice());
    try testing.expectEqual(null, hu.tls);

    // XHTTP: type is the mode
    const xh = try fromLink(testLink(&lb,
        \\{"add":"x.example","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"xhttp","path":"/x","type":"packet-up","host":"xh.example","tls":"tls"}
    ), "x.example", 443);
    try testing.expectEqualStrings("/x", xh.transport.xhttp.path.slice());
    try testing.expectEqualStrings("packet-up", xh.transport.xhttp.mode.slice());
    try testing.expectEqualStrings("xh.example", xh.transport.xhttp.host.slice());
    try testing.expectEqualStrings("xh.example", xh.tls.?.server_name.slice());

    // the URL-safe alphabet, and line breaks inside the base64
    var ub: [1024]u8 = undefined;
    const url_safe = std.base64.url_safe_no_pad.Encoder.encode(ub[8..], bare_json);
    @memcpy(ub[0..8], "VMESS://");
    try testing.expectEqual(.chacha20_poly1305, (try fromLink(ub[0 .. 8 + url_safe.len], "1.2.3.4", 8080)).security);

    // what cannot be carried, or is no link
    const Bad = struct { json: []const u8, err: LinkError };
    for ([_]Bad{
        .{ .json = "{\"add\":\"h\",\"port\":1,\"id\":\"b831381d-6324-4d53-ad4f-8cda48b30811\",\"net\":\"kcp\"}", .err = error.UnsupportedTransport },
        .{ .json = "{\"add\":\"h\",\"port\":1,\"id\":\"b831381d-6324-4d53-ad4f-8cda48b30811\",\"net\":\"h2\"}", .err = error.UnsupportedTransport },
        .{ .json = "{\"add\":\"h\",\"port\":1,\"id\":\"b831381d-6324-4d53-ad4f-8cda48b30811\",\"net\":\"tcp\",\"type\":\"http\"}", .err = error.UnsupportedTransport },
        .{ .json = "{\"add\":\"h\",\"port\":1,\"id\":\"b831381d-6324-4d53-ad4f-8cda48b30811\",\"net\":\"ws\",\"path\":\"nope\"}", .err = error.UnsupportedTransport },
        .{ .json = "{\"add\":\"h\",\"port\":1,\"id\":\"b831381d-6324-4d53-ad4f-8cda48b30811\",\"tls\":\"xtls\"}", .err = error.UnsupportedSecurity },
        .{ .json = "{\"add\":\"h\",\"port\":1,\"id\":\"b831381d-6324-4d53-ad4f-8cda48b30811\",\"tls\":\"reality\"}", .err = error.BadRealityKey },
        .{ .json = "{\"add\":\"h\",\"port\":1,\"id\":\"\"}", .err = error.BadId },
        .{ .json = "{\"add\":\"h\",\"port\":1,\"id\":\"b831381d-6324-4d53-ad4f-8cda48b3081\"}", .err = error.BadId },
        .{ .json = "{\"add\":\"h\",\"port\":1}", .err = error.BadId },
        .{ .json = "{\"add\":\"h\",\"port\":1,\"id\":", .err = error.BadLink },
        .{ .json = "[1]", .err = error.BadLink },
        .{ .json = "", .err = error.BadLink },
    }) |bad| try testing.expectError(bad.err, fromLink(testLink(&lb, bad.json), "h", 1));
    try testing.expectError(error.NotVmess, fromLink("vless://b831381d-6324-4d53-ad4f-8cda48b30811@h:1", "h", 1));
    try testing.expectError(error.BadLink, fromLink("vmess://not*base64", "h", 1));
    // longer than a link may be
    var long: [8 + max_link + 4]u8 = @splat('A');
    @memcpy(long[0..8], "vmess://");
    try testing.expectError(error.BadLink, fromLink(&long, "h", 1));

    // a summary needs an address and a port
    try testing.expectEqual(null, linkSummary(testLink(&lb, "{\"ps\":\"x\",\"port\":1}"), &sb));
    try testing.expectEqual(null, linkSummary(testLink(&lb, "{\"add\":\"h\",\"port\":\"70000\"}"), &sb));
    try testing.expectEqual(null, linkSummary(testLink(&lb, "{\"add\":\"h\"}"), &sb));
    try testing.expectEqual(null, linkSummary("vmess://b831381d-6324-4d53-ad4f-8cda48b30811@h:1", &sb));
    try testing.expectEqual(null, linkSummary("trojan://pw@h:1", &sb));
    // and a buffer that takes the JSON
    try testing.expectEqual(null, linkSummary(cdn, sb[0..100]));
}

test "links: Xray's URL form" {
    const user: User = .init(test_uuid);
    const ws = try fromLink("vmess://b831381d-6324-4d53-ad4f-8cda48b30811@104.16.1.1:443?encryption=aes-128-gcm&type=ws&security=tls" ++
        "&host=cdn.example&sni=edge.example&path=%2Fvm%3Fed%3D2048&fp=chrome#name", "104.16.1.1", 443);
    try testing.expectEqualSlices(u8, &user.cmd_key, &ws.user.cmd_key);
    try testing.expectEqual(.aes_128_gcm, ws.security);
    try testing.expectEqualStrings("/vm?ed=2048", ws.transport.ws.path.slice());
    try testing.expectEqualStrings("cdn.example", ws.transport.ws.host.slice());
    try testing.expectEqualStrings("edge.example", ws.tls.?.server_name.slice());

    // bare, no parameters at all
    const bare = try fromLink("vmess://b831381d-6324-4d53-ad4f-8cda48b30811@h.example:10086", "h.example", 10086);
    try testing.expectEqual(.raw, std.meta.activeTag(bare.transport));
    try testing.expectEqual(null, bare.tls);
    try testing.expectEqual(null, bare.reality);
    try testing.expectEqual(Security.auto, bare.security);

    const grpc = try fromLink("vmess://b831381d-6324-4d53-ad4f-8cda48b30811@h:443?type=grpc&serviceName=tun%2Fsvc&mode=gun&authority=a.example&security=tls&peer=old.example", "h", 443);
    try testing.expectEqualStrings("tun/svc", grpc.transport.grpc.service_name.slice());
    try testing.expectEqualStrings("a.example", grpc.transport.grpc.authority.slice());
    try testing.expect(!grpc.transport.grpc.multi);
    try testing.expectEqualStrings("old.example", grpc.tls.?.server_name.slice());

    const link = "vmess://b831381d-6324-4d53-ad4f-8cda48b30811@h:443?type=xhttp&path=%2Fx&mode=stream-up&extra=%7B%22a%22%3A1%7D" ++
        "&security=reality&sni=www.example.com&pbk=jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8&sid=ab12";
    const re = try fromLink(link, "h", 443);
    try testing.expectEqualStrings("/x", re.transport.xhttp.path.slice());
    try testing.expectEqualStrings("stream-up", re.transport.xhttp.mode.slice());
    try testing.expectEqualStrings("{\"a\":1}", re.transport.xhttp.extra.slice());
    try testing.expectEqual(null, re.tls);
    try testing.expectEqualStrings("www.example.com", re.reality.?.server_name);
    try testing.expectEqual(0x8c, re.reality.?.public_key[0]);
    try testing.expectEqualSlices(u8, &.{ 0xab, 0x12, 0, 0, 0, 0, 0, 0 }, &re.reality.?.short_id);

    try testing.expectError(error.BadId, fromLink("vmess://@h:1", "h", 1));
    try testing.expectError(error.BadId, fromLink("vmess://zz31381d-6324-4d53-ad4f-8cda48b30811@h:1", "h", 1));
    try testing.expectError(error.UnsupportedTransport, fromLink("vmess://b831381d-6324-4d53-ad4f-8cda48b30811@h:1?type=kcp", "h", 1));
    try testing.expectError(error.UnsupportedTransport, fromLink("vmess://b831381d-6324-4d53-ad4f-8cda48b30811@h:1?type=tcp&headerType=http", "h", 1));
    try testing.expectError(error.UnsupportedSecurity, fromLink("vmess://b831381d-6324-4d53-ad4f-8cda48b30811@h:1?security=xtls", "h", 1));
    try testing.expectError(error.BadRealityKey, fromLink("vmess://b831381d-6324-4d53-ad4f-8cda48b30811@h:1?security=reality&pbk=short", "h", 1));
    try testing.expectError(error.BadRealityKey, fromLink("vmess://b831381d-6324-4d53-ad4f-8cda48b30811@h:1?security=reality&pbk=jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8&sid=abc", "h", 1));
}
