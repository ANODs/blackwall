//! Minimal TLS 1.3 client for proxy transports, with REALITY authentication.
//!
//! Only what an outbound needs: one round trip handshake (X25519MLKEM768 or
//! X25519), AES-GCM / ChaCha20-Poly1305 records, no resumption, no client
//! certificates. The ClientHello follows the shape of current Chrome so the
//! connection does not stand out.
//!
//! Records are encrypted and decrypted in place inside the socket buffers;
//! the only extra memory per connection is one outgoing record.
//!
//! REALITY (Xray): the legacy session id carries an AES-GCM sealed token
//! derived from an X25519 exchange with the server's static key. A server
//! that recognises it answers with a throwaway Ed25519 certificate whose
//! signature field is HMAC-SHA512(auth_key, public_key); anything else means
//! we reached the camouflage site and the connection is refused.
//!
//! Ordinary TLS (VLESS over WebSocket behind a CDN): the certificate chain
//! must lead to a system root and name the server, and CertificateVerify is
//! checked with the leaf's key. Certificates may come zlib-compressed; we
//! offer zlib instead of Chrome's brotli (same extension, so fingerprints
//! that list extension types do not change) because there is no brotli
//! decoder to carry.

const std = @import("std");
const crypto = std.crypto;
const aes_gcm = @import("aes_gcm.zig");
const tls = crypto.tls;
const Io = std.Io;

const X25519 = crypto.dh.X25519;
const MLKem768 = crypto.kem.ml_kem.MLKem768;
const Ed25519 = crypto.sign.Ed25519;

pub const max_plain = 16384;
pub const max_cipher = max_plain + 256;
/// The socket reader must hold one full record.
pub const min_read_buffer = 5 + max_cipher;

pub const Reality = struct {
    public_key: [32]u8,
    short_id: [8]u8 = @splat(0),
    /// Xray version reported to the server; some servers restrict it.
    version: [3]u8 = .{ 26, 11, 9 },
};

/// Application protocols offered.
pub const Alpn = enum {
    /// Chrome's own: h2, http/1.1
    h2_http11,
    http11,
    h2,
};

pub const Options = struct {
    server_name: []const u8,
    reality: ?Reality = null,
    /// Ordinary TLS: the trust store the certificate chain must lead to.
    /// Required without `reality`.
    roots: ?*const crypto.Certificate.Bundle = null,
    alpn: Alpn = .h2_http11,
};

/// What the server chose.
pub const Negotiated = struct {
    /// ALPN "h2"
    h2: bool = false,
};

/// The system's trust store, loaded on first use and kept for the life of
/// the process (a few hundred KB; REALITY-only setups never load it).
pub fn systemRoots(io: Io) error{NoRoots}!*const crypto.Certificate.Bundle {
    roots_mutex.lockUncancelable(io);
    defer roots_mutex.unlock(io);
    if (!roots_loaded) {
        roots_bundle.rescan(std.heap.page_allocator, io, Io.Clock.real.now(io)) catch return error.NoRoots;
        roots_loaded = true;
    }
    return &roots_bundle;
}

/// Tests only: trust an extra certificate authority (PEM file).
pub fn addTestRoot(io: Io, pem_path: []const u8) !void {
    _ = try systemRoots(io);
    roots_mutex.lockUncancelable(io);
    defer roots_mutex.unlock(io);
    try roots_bundle.addCertsFromFilePathAbsolute(std.heap.page_allocator, io, Io.Clock.real.now(io), pem_path);
}

var roots_mutex: Io.Mutex = .init;
var roots_loaded = false;
var roots_bundle: crypto.Certificate.Bundle = .empty;

pub const Suite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    chacha20_poly1305_sha256 = 0x1303,
};

fn Spec(comptime suite: Suite) type {
    return switch (suite) {
        .aes_128_gcm_sha256 => SpecT(crypto.aead.aes_gcm.Aes128Gcm, crypto.hash.sha2.Sha256),
        .aes_256_gcm_sha384 => SpecT(crypto.aead.aes_gcm.Aes256Gcm, crypto.hash.sha2.Sha384),
        .chacha20_poly1305_sha256 => SpecT(crypto.aead.chacha_poly.ChaCha20Poly1305, crypto.hash.sha2.Sha256),
    };
}

fn SpecT(comptime AeadT: type, comptime HashT: type) type {
    return struct {
        pub const Aead = AeadT;
        pub const Hash = HashT;
        pub const Hmac = crypto.auth.hmac.Hmac(Hash);
        pub const Hkdf = crypto.kdf.hkdf.Hkdf(Hmac);
    };
}

// ---------------------------------------------------------------- record protection

fn Protect(comptime Aead: type) type {
    // the AES suites go through aes_gcm.zig: its key schedule and powers of
    // H are made once per direction, and it runs on ARMv8's instructions
    const Fast = if (Aead == crypto.aead.aes_gcm.Aes128Gcm)
        aes_gcm.Aes128Gcm
    else if (Aead == crypto.aead.aes_gcm.Aes256Gcm)
        aes_gcm.Aes256Gcm
    else
        void;
    return struct {
        key: [Aead.key_length]u8,
        iv: [Aead.nonce_length]u8,
        seq: u64 = 0,
        fast: if (Fast == void) void else ?Fast = if (Fast == void) {} else null,

        fn cipher(self: *Self) *const Fast {
            if (self.fast == null) self.fast = Fast.init(self.key);
            return &self.fast.?;
        }

        const Self = @This();

        fn nonce(self: *Self) [Aead.nonce_length]u8 {
            var n = self.iv;
            var seq: [8]u8 = undefined;
            std.mem.writeInt(u64, &seq, self.seq, .big);
            for (seq, 0..) |b, i| n[n.len - 8 + i] ^= b;
            self.seq += 1;
            return n;
        }

        /// `rec[5..][0..inner_len]` holds the inner plaintext; it is
        /// encrypted in place and the header and tag are filled in.
        fn seal(self: *Self, rec: []u8, inner_len: usize) usize {
            const total = inner_len + Aead.tag_length;
            rec[0..3].* = .{ 0x17, 0x03, 0x03 };
            std.mem.writeInt(u16, rec[3..5], @intCast(total), .big);
            const body = rec[5..][0..inner_len];
            const tag = rec[5 + inner_len ..][0..Aead.tag_length];
            if (Fast != void) {
                self.cipher().encryptAd(body, tag, body, rec[0..5], self.nonce());
            } else Aead.encrypt(body, tag, body, rec[0..5], self.nonce(), self.key);
            return 5 + total;
        }

        fn open(self: *Self, hdr: *const [5]u8, payload: []u8) error{TlsBadRecordMac}![]u8 {
            if (payload.len < Aead.tag_length) return error.TlsBadRecordMac;
            const n = payload.len - Aead.tag_length;
            const body = payload[0..n];
            const tag = payload[n..][0..Aead.tag_length].*;
            if (Fast != void) {
                self.cipher().decryptAd(body, body, tag, hdr, self.nonce()) catch return error.TlsBadRecordMac;
            } else Aead.decrypt(body, body, tag, hdr, self.nonce(), self.key) catch
                return error.TlsBadRecordMac;
            return body;
        }
    };
}

pub const Keys = union(Suite) {
    aes_128_gcm_sha256: Protect(Spec(.aes_128_gcm_sha256).Aead),
    aes_256_gcm_sha384: Protect(Spec(.aes_256_gcm_sha384).Aead),
    chacha20_poly1305_sha256: Protect(Spec(.chacha20_poly1305_sha256).Aead),

    fn derive(comptime suite: Suite, secret: [Spec(suite).Hash.digest_length]u8) Keys {
        const S = Spec(suite);
        return @unionInit(Keys, @tagName(suite), .{
            .key = tls.hkdfExpandLabel(S.Hkdf, secret, "key", "", S.Aead.key_length),
            .iv = tls.hkdfExpandLabel(S.Hkdf, secret, "iv", "", S.Aead.nonce_length),
        });
    }

    fn seal(k: *Keys, rec: []u8, inner_len: usize) usize {
        return switch (k.*) {
            inline else => |*p| p.seal(rec, inner_len),
        };
    }

    fn open(k: *Keys, hdr: *const [5]u8, payload: []u8) error{TlsBadRecordMac}![]u8 {
        return switch (k.*) {
            inline else => |*p| p.open(hdr, payload),
        };
    }
};

const Inner = struct { content_type: u8, data: []u8 };

/// Strip TLS 1.3 record padding and the trailing content type.
fn splitInner(inner: []u8) error{TlsUnexpectedMessage}!Inner {
    var end = inner.len;
    while (end > 0 and inner[end - 1] == 0) end -= 1;
    if (end == 0) return error.TlsUnexpectedMessage;
    return .{ .content_type = inner[end - 1], .data = inner[0 .. end - 1] };
}

pub const ReadError = error{
    TlsBadRecordMac,
    TlsUnexpectedMessage,
    TlsRecordOverflow,
    TlsAlert,
    TlsKeyUpdateUnsupported,
} || Io.Reader.Error;

pub const RecordReader = struct {
    r: *Io.Reader,
    keys: Keys,

    /// Next chunk of application data, decrypted in place inside the socket
    /// reader's buffer and valid until the next call. Null on close_notify.
    pub fn next(rr: *RecordReader) ReadError!?[]u8 {
        while (true) {
            const hdr = (try rr.r.takeArray(5)).*;
            const len = std.mem.readInt(u16, hdr[3..5], .big);
            if (len > max_cipher) return error.TlsRecordOverflow;
            const payload = try rr.r.take(len);
            switch (hdr[0]) {
                0x14 => continue, // ChangeCipherSpec
                0x17 => {},
                0x15 => return error.TlsAlert,
                else => return error.TlsUnexpectedMessage,
            }
            const inner = try splitInner(try rr.keys.open(&hdr, payload));
            switch (inner.content_type) {
                0x17 => if (inner.data.len > 0) return inner.data,
                0x16 => {
                    // post-handshake: session tickets are ignored (we never
                    // resume); Go servers never start a key update
                    var rest = inner.data;
                    while (rest.len >= 4) {
                        const mlen = std.mem.readInt(u24, rest[1..4], .big);
                        if (rest[0] == 24) return error.TlsKeyUpdateUnsupported;
                        if (rest.len < 4 + mlen) break;
                        rest = rest[4 + mlen ..];
                    }
                },
                0x15 => {
                    if (inner.data.len >= 2 and inner.data[1] == 0) return null; // close_notify
                    return error.TlsAlert;
                },
                else => return error.TlsUnexpectedMessage,
            }
        }
    }
};

pub const RecordWriter = struct {
    w: *Io.Writer,
    keys: Keys,
    /// pending plaintext lives at `rec[5..][0..len]`
    len: usize,
    rec: [5 + max_plain + 1 + 16]u8,

    pub fn write(rw: *RecordWriter, bytes: []const u8) Io.Writer.Error!void {
        var rest = bytes;
        while (rest.len > 0) {
            const n = @min(rest.len, max_plain - rw.len);
            @memcpy(rw.rec[5 + rw.len ..][0..n], rest[0..n]);
            rw.len += n;
            rest = rest[n..];
            if (rw.len == max_plain) try rw.emit(0x17);
        }
    }

    /// At least `need` bytes of room in the current record, to be filled by
    /// the caller and committed with `advance`.
    pub fn writable(rw: *RecordWriter, need: usize) Io.Writer.Error![]u8 {
        std.debug.assert(need <= max_plain);
        if (max_plain - rw.len < need) try rw.emit(0x17);
        return rw.rec[5 + rw.len .. 5 + max_plain];
    }

    pub fn advance(rw: *RecordWriter, n: usize) void {
        rw.len += n;
        std.debug.assert(rw.len <= max_plain);
    }

    fn emit(rw: *RecordWriter, content_type: u8) Io.Writer.Error!void {
        if (rw.len == 0 and content_type == 0x17) return;
        rw.rec[5 + rw.len] = content_type;
        const n = rw.keys.seal(&rw.rec, rw.len + 1);
        rw.len = 0;
        try rw.w.writeAll(rw.rec[0..n]);
    }

    pub fn flush(rw: *RecordWriter) Io.Writer.Error!void {
        try rw.emit(0x17);
        try rw.w.flush();
    }

    pub fn closeNotify(rw: *RecordWriter) Io.Writer.Error!void {
        try rw.emit(0x17);
        rw.rec[5..7].* = .{ 1, 0 };
        rw.len = 2;
        try rw.emit(0x15);
        try rw.w.flush();
    }
};

/// `std.Io.Reader` over the application data of a RecordReader, for the
/// transports that run inside TLS (WebSocket, HTTP/2).
pub const StreamReader = struct {
    rr: *RecordReader,
    /// rest of the last record, still inside the socket buffer
    pending: []const u8 = &.{},
    interface: Io.Reader,
    err: ?ReadError = null,

    pub fn init(rr: *RecordReader, buffer: []u8) StreamReader {
        return .{ .rr = rr, .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 } };
    }

    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const s: *StreamReader = @alignCast(@fieldParentPtr("interface", io_r));
        if (s.pending.len == 0) {
            const chunk = s.rr.next() catch |e| {
                s.err = e;
                return error.ReadFailed;
            };
            s.pending = chunk orelse return error.EndOfStream;
        }
        const n = try w.write(s.pending[0..limit.minInt(s.pending.len)]);
        s.pending = s.pending[n..];
        return n;
    }
};

/// `std.Io.Writer` into a RecordWriter; `flush` ends the current record.
pub const StreamWriter = struct {
    rw: *RecordWriter,
    interface: Io.Writer,

    pub fn init(rw: *RecordWriter, buffer: []u8) StreamWriter {
        return .{ .rw = rw, .interface = .{ .vtable = &.{ .drain = drain, .flush = flush }, .buffer = buffer } };
    }

    fn drain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const s: *StreamWriter = @alignCast(@fieldParentPtr("interface", io_w));
        try s.rw.write(io_w.buffered());
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try s.rw.write(d);
            n += d.len;
        }
        for (0..splat) |_| {
            try s.rw.write(data[data.len - 1]);
            n += data[data.len - 1].len;
        }
        _ = io_w.consumeAll();
        return n;
    }

    fn flush(io_w: *Io.Writer) Io.Writer.Error!void {
        const s: *StreamWriter = @alignCast(@fieldParentPtr("interface", io_w));
        try s.rw.write(io_w.buffered());
        _ = io_w.consumeAll();
        try s.rw.flush();
    }
};

// ---------------------------------------------------------------- handshake

pub const HandshakeError = error{
    TlsUnexpectedMessage,
    TlsDecodeError,
    TlsIllegalParameter,
    TlsHelloRetryUnsupported,
    TlsVersionUnsupported,
    TlsRecordOverflow,
    TlsBadRecordMac,
    TlsAlert,
    TlsDecryptError,
    TlsBadSignature,
    TlsCertificateCompressed,
    TlsClientAuthUnsupported,
    /// Plain TLS needs a certificate chain check that is not built yet.
    TlsCertificateUnsupported,
    RealityBadKey,
    /// The server did not recognise us and handed the connection to its
    /// camouflage site: wrong public key, short id, server name or clock.
    RealityAuthFailed,
    /// Ordinary TLS: the chain does not lead to a trusted root, is expired,
    /// malformed, or does not name the server.
    TlsCertificateUntrusted,
    TlsCertificateHostMismatch,
    OutOfMemory,
} || Io.Reader.Error || Io.Writer.Error;

/// Run the handshake on an established TCP stream. On success `rr` and `rw`
/// carry application traffic.
pub fn handshake(io: Io, r: *Io.Reader, w: *Io.Writer, opts: Options, rr: *RecordReader, rw: *RecordWriter) HandshakeError!Negotiated {
    var random: [32]u8 = undefined;
    io.random(&random);
    const x_kp = X25519.KeyPair.generate(io);
    const kem_kp = MLKem768.KeyPair.generate(io);

    var hello_buf: [2560]u8 = undefined;
    const hello = buildClientHello(&hello_buf, io, &random, &x_kp.public_key, &kem_kp.public_key.toBytes(), opts.server_name, .{
        .alpn = opts.alpn,
        // REALITY answers like Go's TLS stack, which never compresses
        .cert_compression = if (opts.reality != null) .brotli else .zlib,
    });

    var auth_key: ?[32]u8 = null;
    if (opts.reality) |re| {
        auth_key = try sealRealitySessionId(hello, &random, x_kp.secret_key, re, Io.Clock.real.now(io).toSeconds());
    } else {
        if (opts.roots == null) return error.TlsCertificateUnsupported;
        io.random(hello[session_id_offset..][0..32]);
    }

    var hdr: [5]u8 = .{ 0x16, 0x03, 0x01, 0, 0 };
    std.mem.writeInt(u16, hdr[3..5], @intCast(hello.len), .big);
    try w.writeAll(&hdr);
    try w.writeAll(hello);
    try w.flush();

    const sh_hdr = (try r.takeArray(5)).*;
    if (sh_hdr[0] == 0x15) return error.TlsAlert;
    if (sh_hdr[0] != 0x16) return error.TlsUnexpectedMessage;
    const sh_len = std.mem.readInt(u16, sh_hdr[3..5], .big);
    if (sh_len > max_plain) return error.TlsRecordOverflow;
    const sh = try parseServerHello(try r.take(sh_len));

    // the ServerHello slice lives in the socket buffer: use it before reading on
    var shared_buf: [64]u8 = undefined;
    const shared = try sharedSecret(&shared_buf, sh, x_kp, kem_kp);

    const peer: Peer = .{
        .auth_key = auth_key,
        .roots = opts.roots,
        .server_name = opts.server_name,
        .now_sec = Io.Clock.real.now(io).toSeconds(),
    };
    return switch (sh.suite) {
        inline else => |suite| finish(suite, r, w, hello, sh.msg, shared, peer, rr, rw),
    };
}

/// How the server proves who it is.
const Peer = struct {
    /// REALITY: the certificate is bound to this key
    auth_key: ?[32]u8,
    /// ordinary TLS: chain to these roots, naming `server_name`
    roots: ?*const crypto.Certificate.Bundle,
    server_name: []const u8,
    now_sec: i64,
};

const session_id_offset = 4 + 2 + 32 + 1;

const ServerHello = struct {
    msg: []const u8,
    suite: Suite,
    group: u16,
    key: []const u8,
};

const hrr_random = [32]u8{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

const Cursor = struct {
    b: []const u8,
    i: usize = 0,

    fn take(c: *Cursor, n: usize) error{TlsDecodeError}![]const u8 {
        if (c.b.len - c.i < n) return error.TlsDecodeError;
        defer c.i += n;
        return c.b[c.i..][0..n];
    }
    fn int(c: *Cursor, comptime T: type) error{TlsDecodeError}!T {
        const n = @divExact(@bitSizeOf(T), 8);
        return std.mem.readInt(T, (try c.take(n))[0..n], .big);
    }
    fn vec(c: *Cursor, comptime Len: type) error{TlsDecodeError}![]const u8 {
        return c.take(try c.int(Len));
    }
};

fn parseServerHello(rec: []const u8) HandshakeError!ServerHello {
    if (rec.len < 4 or rec[0] != 2) return error.TlsUnexpectedMessage;
    if (4 + std.mem.readInt(u24, rec[1..4], .big) != rec.len) return error.TlsDecodeError;
    var c: Cursor = .{ .b = rec[4..] };
    _ = try c.int(u16); // legacy_version
    if (std.mem.eql(u8, try c.take(32), &hrr_random)) return error.TlsHelloRetryUnsupported;
    _ = try c.vec(u8); // session id echo
    const suite = std.enums.fromInt(Suite, try c.int(u16)) orelse return error.TlsIllegalParameter;
    if (try c.int(u8) != 0) return error.TlsIllegalParameter;
    var exts: Cursor = .{ .b = try c.vec(u16) };
    var tls13 = false;
    var group: u16 = 0;
    var key: ?[]const u8 = null;
    while (exts.i < exts.b.len) {
        const kind = try exts.int(u16);
        var body: Cursor = .{ .b = try exts.vec(u16) };
        switch (kind) {
            43 => tls13 = try body.int(u16) == 0x0304,
            51 => {
                group = try body.int(u16);
                key = try body.vec(u16);
            },
            else => {},
        }
    }
    if (!tls13) return error.TlsVersionUnsupported;
    return .{ .msg = rec, .suite = suite, .group = group, .key = key orelse return error.TlsIllegalParameter };
}

fn sharedSecret(buf: *[64]u8, sh: ServerHello, x_kp: X25519.KeyPair, kem_kp: MLKem768.KeyPair) HandshakeError![]const u8 {
    switch (sh.group) {
        0x001d => {
            if (sh.key.len != 32) return error.TlsIllegalParameter;
            buf[0..32].* = X25519.scalarmult(x_kp.secret_key, sh.key[0..32].*) catch return error.TlsIllegalParameter;
            return buf[0..32];
        },
        0x11ec => {
            const ct_len = MLKem768.ciphertext_length;
            if (sh.key.len != ct_len + 32) return error.TlsIllegalParameter;
            buf[0..32].* = kem_kp.secret_key.decaps(sh.key[0..ct_len]) catch return error.TlsIllegalParameter;
            buf[32..64].* = X25519.scalarmult(x_kp.secret_key, sh.key[ct_len..][0..32].*) catch return error.TlsIllegalParameter;
            return buf[0..64];
        },
        else => return error.TlsIllegalParameter,
    }
}

fn finish(
    comptime suite: Suite,
    r: *Io.Reader,
    w: *Io.Writer,
    hello: []const u8,
    sh_msg: []const u8,
    shared: []const u8,
    peer: Peer,
    rr: *RecordReader,
    rw: *RecordWriter,
) HandshakeError!Negotiated {
    const S = Spec(suite);
    const L = S.Hash.digest_length;

    var transcript = S.Hash.init(.{});
    transcript.update(hello);
    transcript.update(sh_msg);

    const zeroes: [L]u8 = @splat(0);
    const empty = tls.emptyHash(S.Hash);
    const early = S.Hkdf.extract(&.{}, &zeroes);
    const hs_secret = S.Hkdf.extract(&tls.hkdfExpandLabel(S.Hkdf, early, "derived", &empty, L), shared);
    const hello_hash = transcript.peek();
    const c_hs = tls.hkdfExpandLabel(S.Hkdf, hs_secret, "c hs traffic", &hello_hash, L);
    const s_hs = tls.hkdfExpandLabel(S.Hkdf, hs_secret, "s hs traffic", &hello_hash, L);
    var server_keys = Keys.derive(suite, s_hs);
    var client_keys = Keys.derive(suite, c_hs);

    // the encrypted server flight; a padded certificate can span records
    const msgs = try std.heap.page_allocator.alloc(u8, 64 * 1024);
    defer std.heap.page_allocator.free(msgs);
    var have: usize = 0;
    var cert_key: ?[32]u8 = null;
    var leaf: ?LeafKey = null;
    var cv_hash: [L]u8 = undefined;
    var verified = false;
    var negotiated: Negotiated = .{};

    while (true) {
        const hdr = (try r.takeArray(5)).*;
        const len = std.mem.readInt(u16, hdr[3..5], .big);
        if (len > max_cipher) return error.TlsRecordOverflow;
        const payload = try r.take(len);
        switch (hdr[0]) {
            0x14 => continue,
            0x17 => {},
            0x15 => return error.TlsAlert,
            else => return error.TlsUnexpectedMessage,
        }
        const inner = try splitInner(try server_keys.open(&hdr, payload));
        if (inner.content_type == 0x15) return error.TlsAlert;
        if (inner.content_type != 0x16) return error.TlsUnexpectedMessage;
        if (msgs.len - have < inner.data.len) return error.TlsRecordOverflow;
        @memcpy(msgs[have..][0..inner.data.len], inner.data);
        have += inner.data.len;

        var off: usize = 0;
        while (have - off >= 4) {
            const mlen = std.mem.readInt(u24, msgs[off + 1 ..][0..3], .big);
            if (have - off < 4 + mlen) break;
            const msg = msgs[off..][0 .. 4 + mlen];
            const body = msg[4..];
            off += msg.len;
            switch (msg[0]) {
                8 => { // EncryptedExtensions
                    negotiated.h2 = try alpnIsH2(body);
                    transcript.update(msg);
                },
                11, 25 => { // Certificate, CompressedCertificate
                    if (cert_key != null or leaf != null) return error.TlsUnexpectedMessage;
                    if (peer.auth_key) |key| {
                        if (msg[0] != 11) return error.TlsCertificateCompressed;
                        cert_key = realityCertificateKey(try firstCertificate(body), key) orelse return error.RealityAuthFailed;
                    } else {
                        var plain_buf: [max_cert_message]u8 = undefined;
                        const certs = if (msg[0] == 11) body else try decompressCertificate(body, &plain_buf);
                        leaf = try verifyChain(certs, peer.server_name, peer.roots.?, peer.now_sec);
                    }
                    // the message as sent is what the transcript covers
                    transcript.update(msg);
                    cv_hash = transcript.peek();
                },
                15 => {
                    if (cert_key) |k| {
                        try verifyCertificateVerify(body, k, &cv_hash);
                    } else if (leaf) |*k| {
                        try k.verifyCertificateVerify(body, &cv_hash);
                    } else return error.TlsUnexpectedMessage;
                    transcript.update(msg);
                    verified = true;
                },
                20 => {
                    if (!verified) return error.TlsUnexpectedMessage;
                    const fk = tls.hkdfExpandLabel(S.Hkdf, s_hs, "finished", "", S.Hmac.key_length);
                    const expect = tls.hmac(S.Hmac, &transcript.peek(), fk);
                    if (body.len != L or !crypto.timing_safe.eql([L]u8, body[0..L].*, expect)) return error.TlsDecryptError;
                    if (off != have) return error.TlsUnexpectedMessage;
                    transcript.update(msg);
                    const th = transcript.peek();

                    // our ChangeCipherSpec (middlebox compatibility) and Finished
                    const cfk = tls.hkdfExpandLabel(S.Hkdf, c_hs, "finished", "", S.Hmac.key_length);
                    var rec: [5 + 4 + L + 1 + 16]u8 = undefined;
                    rec[5..9].* = .{ 20, 0, 0, L };
                    rec[9..][0..L].* = tls.hmac(S.Hmac, &th, cfk);
                    rec[9 + L] = 0x16;
                    const n = client_keys.seal(&rec, 4 + L + 1);
                    try w.writeAll(&.{ 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 });
                    try w.writeAll(rec[0..n]);
                    try w.flush();

                    const master = S.Hkdf.extract(&tls.hkdfExpandLabel(S.Hkdf, hs_secret, "derived", &empty, L), &zeroes);
                    rr.r = r;
                    rr.keys = Keys.derive(suite, tls.hkdfExpandLabel(S.Hkdf, master, "s ap traffic", &th, L));
                    rw.w = w;
                    rw.keys = Keys.derive(suite, tls.hkdfExpandLabel(S.Hkdf, master, "c ap traffic", &th, L));
                    rw.len = 0;
                    return negotiated;
                },
                13 => return error.TlsClientAuthUnsupported,
                else => return error.TlsUnexpectedMessage,
            }
        }
        std.mem.copyForwards(u8, msgs[0 .. have - off], msgs[off..have]);
        have -= off;
    }
}

/// Whether the server's EncryptedExtensions select ALPN "h2".
fn alpnIsH2(body: []const u8) HandshakeError!bool {
    var c: Cursor = .{ .b = body };
    var exts: Cursor = .{ .b = try c.vec(u16) };
    while (exts.i < exts.b.len) {
        const kind = try exts.int(u16);
        var ext: Cursor = .{ .b = try exts.vec(u16) };
        if (kind != 16) continue;
        var list: Cursor = .{ .b = try ext.vec(u16) };
        return std.mem.eql(u8, try list.vec(u8), "h2");
    }
    return false;
}

/// Largest Certificate message we take apart (CDN chains are a few KB).
const max_cert_message = 32 * 1024;

/// The Certificate message inside a CompressedCertificate (RFC 8879), zlib
/// being the only algorithm we offer.
fn decompressCertificate(body: []const u8, out: *[max_cert_message]u8) HandshakeError![]const u8 {
    var c: Cursor = .{ .b = body };
    if (try c.int(u16) != 1) return error.TlsIllegalParameter;
    const len = try c.int(u24);
    if (len > out.len) return error.TlsRecordOverflow;
    var in: Io.Reader = .fixed(try c.vec(u24));
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var z: std.compress.flate.Decompress = .init(&in, .zlib, &window);
    z.reader.readSliceAll(out[0..len]) catch return error.TlsDecodeError;
    return out[0..len];
}

/// The leaf certificate's public key, kept to check CertificateVerify.
const LeafKey = struct {
    algo: crypto.Certificate.AlgorithmCategory,
    buf: [600]u8,
    len: u16,

    fn verifyCertificateVerify(k: *const LeafKey, body: []const u8, th: []const u8) HandshakeError!void {
        var c: Cursor = .{ .b = body };
        const scheme = try c.int(u16);
        const sig = try c.vec(u16);
        var content_buf: [64 + 33 + 1 + 64]u8 = undefined;
        @memset(content_buf[0..64], 0x20);
        content_buf[64..97].* = "TLS 1.3, server CertificateVerify".*;
        content_buf[97] = 0;
        @memcpy(content_buf[98..][0..th.len], th);
        const content = content_buf[0 .. 98 + th.len];
        const key = k.buf[0..k.len];
        const Cert = crypto.Certificate;
        // TLS 1.3 signatures: ECDSA, RSA-PSS (rsae), Ed25519; never PKCS#1 v1.5
        switch (scheme) {
            inline 0x0403, 0x0503 => |s| {
                if (k.algo != .X9_62_id_ecPublicKey) return error.TlsBadSignature;
                const Ecdsa = if (s == 0x0403) crypto.sign.ecdsa.EcdsaP256Sha256 else crypto.sign.ecdsa.EcdsaP384Sha384;
                const signature = Ecdsa.Signature.fromDer(sig) catch return error.TlsBadSignature;
                const pk = Ecdsa.PublicKey.fromSec1(key) catch return error.TlsBadSignature;
                signature.verify(content, pk) catch return error.TlsBadSignature;
            },
            inline 0x0804, 0x0805, 0x0806 => |s| {
                if (k.algo != .rsaEncryption) return error.TlsBadSignature;
                const Hash = switch (s) {
                    0x0804 => crypto.hash.sha2.Sha256,
                    0x0805 => crypto.hash.sha2.Sha384,
                    else => crypto.hash.sha2.Sha512,
                };
                const parts = Cert.rsa.PublicKey.parseDer(key) catch return error.TlsBadSignature;
                switch (parts.modulus.len) {
                    inline 256, 384, 512 => |n| {
                        const pk = Cert.rsa.PublicKey.fromBytes(parts.exponent, parts.modulus) catch return error.TlsBadSignature;
                        const signature = Cert.rsa.PSSSignature.fromBytes(n, sig);
                        Cert.rsa.PSSSignature.verify(n, &signature, content, pk, Hash) catch return error.TlsBadSignature;
                    },
                    else => return error.TlsBadSignature,
                }
            },
            0x0807 => {
                if (k.algo != .curveEd25519 or key.len != 32 or sig.len != 64) return error.TlsBadSignature;
                const pk = Ed25519.PublicKey.fromBytes(key[0..32].*) catch return error.TlsBadSignature;
                Ed25519.Signature.fromBytes(sig[0..64].*).verify(content, pk) catch return error.TlsBadSignature;
            },
            else => return error.TlsBadSignature,
        }
    }
};

/// Check a TLS 1.3 Certificate message (leaf first): every certificate is
/// signed by the next, one of them by a trusted root, all are within their
/// validity, and the leaf names `host`. Returns the leaf's key.
fn verifyChain(body: []const u8, host: []const u8, roots: *const crypto.Certificate.Bundle, now_sec: i64) HandshakeError!LeafKey {
    const Cert = crypto.Certificate;
    var c: Cursor = .{ .b = body };
    if ((try c.vec(u8)).len != 0) return error.TlsIllegalParameter; // request context
    var list: Cursor = .{ .b = try c.vec(u24) };
    var leaf: ?LeafKey = null;
    var prev: ?Cert.Parsed = null;
    var count: usize = 0;
    while (list.i < list.b.len) : (count += 1) {
        if (count == 10) return error.TlsCertificateUntrusted;
        const der = try list.vec(u24);
        _ = try list.vec(u16); // per-certificate extensions
        const parsed = (Cert{ .buffer = der, .index = 0 }).parse() catch return error.TlsCertificateUntrusted;
        if (prev) |p| {
            p.verify(parsed, now_sec) catch return error.TlsCertificateUntrusted;
        } else {
            parsed.verifyHostName(host) catch return error.TlsCertificateHostMismatch;
            const key = parsed.pubKey();
            if (key.len > 600) return error.TlsCertificateUntrusted;
            var k: LeafKey = .{ .algo = parsed.pub_key_algo, .buf = undefined, .len = @intCast(key.len) };
            @memcpy(k.buf[0..key.len], key);
            leaf = k;
        }
        if (roots.verify(parsed, now_sec)) |_| {
            return leaf.?;
        } else |err| switch (err) {
            error.CertificateIssuerNotFound => {},
            else => return error.TlsCertificateUntrusted,
        }
        prev = parsed;
    }
    return error.TlsCertificateUntrusted;
}

fn firstCertificate(body: []const u8) HandshakeError![]const u8 {
    var c: Cursor = .{ .b = body };
    _ = try c.vec(u8); // request context
    var list: Cursor = .{ .b = try c.vec(u24) };
    return list.vec(u24);
}

fn verifyCertificateVerify(body: []const u8, key: [32]u8, th: []const u8) HandshakeError!void {
    var c: Cursor = .{ .b = body };
    if (try c.int(u16) != 0x0807) return error.TlsBadSignature; // ed25519
    const sig = try c.vec(u16);
    if (sig.len != 64) return error.TlsBadSignature;
    var content: [64 + 33 + 1 + 64]u8 = undefined;
    @memset(content[0..64], 0x20);
    content[64..97].* = "TLS 1.3, server CertificateVerify".*;
    content[97] = 0;
    @memcpy(content[98..][0..th.len], th);
    const pk = Ed25519.PublicKey.fromBytes(key) catch return error.TlsBadSignature;
    Ed25519.Signature.fromBytes(sig[0..64].*).verify(content[0 .. 98 + th.len], pk) catch return error.TlsBadSignature;
}

// ---------------------------------------------------------------- REALITY

/// Seal the REALITY token into the session id of `hello` (a complete
/// ClientHello handshake message with a zeroed 32-byte session id).
/// Returns the auth key that the server's certificate must be bound to.
pub fn sealRealitySessionId(hello: []u8, random: *const [32]u8, secret: [32]u8, re: Reality, now: i64) HandshakeError![32]u8 {
    const shared = X25519.scalarmult(secret, re.public_key) catch return error.RealityBadKey;
    const prk = crypto.kdf.hkdf.HkdfSha256.extract(random[0..20], &shared);
    var auth: [32]u8 = undefined;
    crypto.kdf.hkdf.HkdfSha256.expand(&auth, "REALITY", prk);

    var plain: [16]u8 = undefined;
    plain[0..3].* = re.version;
    plain[3] = 0;
    std.mem.writeInt(u32, plain[4..8], @truncate(@as(u64, @bitCast(now))), .big);
    plain[8..16].* = re.short_id;

    const sid = hello[session_id_offset..][0..32];
    @memset(sid, 0); // the hello with an empty id is the associated data
    var sealed: [32]u8 = undefined;
    crypto.aead.aes_gcm.Aes256Gcm.encrypt(sealed[0..16], sealed[16..32], &plain, hello, random[20..32].*, auth);
    sid.* = sealed;
    return auth;
}

/// The Ed25519 key of a REALITY certificate bound to `auth_key`, or null.
pub fn realityCertificateKey(cert: []const u8, auth_key: [32]u8) ?[32]u8 {
    // SubjectPublicKeyInfo for Ed25519, followed by the 32 key bytes
    const spki = [_]u8{ 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };
    const at = std.mem.indexOf(u8, cert, &spki) orelse return null;
    if (cert.len < at + spki.len + 32 or cert.len < 67) return null;
    const key = cert[at + spki.len ..][0..32].*;
    // the certificate ends with its signature: BIT STRING of 64 bytes
    if (!std.mem.eql(u8, cert[cert.len - 67 ..][0..3], &.{ 0x03, 0x41, 0x00 })) return null;
    var mac: [64]u8 = undefined;
    crypto.auth.hmac.sha2.HmacSha512.create(&mac, &key, &auth_key);
    if (!crypto.timing_safe.eql([64]u8, mac, cert[cert.len - 64 ..][0..64].*)) return null;
    return key;
}

// ---------------------------------------------------------------- ClientHello

const Builder = struct {
    buf: []u8,
    n: usize = 0,

    fn byte(b: *Builder, v: u8) void {
        b.buf[b.n] = v;
        b.n += 1;
    }
    fn int16(b: *Builder, v: u16) void {
        std.mem.writeInt(u16, b.buf[b.n..][0..2], v, .big);
        b.n += 2;
    }
    fn bytes(b: *Builder, s: []const u8) void {
        @memcpy(b.buf[b.n..][0..s.len], s);
        b.n += s.len;
    }
    fn open(b: *Builder, comptime width: u8) usize {
        defer b.n += width;
        return b.n;
    }
    fn close(b: *Builder, at: usize, comptime width: u8) void {
        const len = b.n - at - width;
        switch (width) {
            1 => b.buf[at] = @intCast(len),
            2 => std.mem.writeInt(u16, b.buf[at..][0..2], @intCast(len), .big),
            3 => std.mem.writeInt(u24, b.buf[at..][0..3], @intCast(len), .big),
            else => unreachable,
        }
    }
};

fn grease(seed: u8) u16 {
    const n: u16 = seed & 0x0f;
    return (n << 12) | 0x0a00 | (n << 4) | 0x0a;
}

const Ext = enum(u16) {
    server_name = 0,
    status_request = 5,
    supported_groups = 10,
    ec_point_formats = 11,
    signature_algorithms = 13,
    alpn = 16,
    sct = 18,
    extended_master_secret = 23,
    compress_certificate = 27,
    session_ticket = 35,
    supported_versions = 43,
    psk_key_exchange_modes = 45,
    key_share = 51,
    application_settings = 0x44cd,
    encrypted_client_hello = 0xfe0d,
    renegotiation_info = 0xff01,
};

fn isIpLiteral(name: []const u8) bool {
    if (std.mem.indexOfScalar(u8, name, ':') != null) return true;
    for (name) |ch| if (!std.ascii.isDigit(ch) and ch != '.') return false;
    return true;
}

/// What varies between our ClientHellos.
const HelloShape = struct {
    alpn: Alpn = .h2_http11,
    cert_compression: enum(u8) { zlib = 1, brotli = 2 } = .brotli,
};

/// A ClientHello shaped like current Chrome: GREASE, post-quantum key
/// share, permuted extensions, GREASE ECH. The session id is left zeroed.
fn buildClientHello(
    buf: []u8,
    io: Io,
    random: *const [32]u8,
    x25519_pub: *const [32]u8,
    kem_pub: *const [MLKem768.PublicKey.encoded_length]u8,
    server_name: []const u8,
    shape: HelloShape,
) []u8 {
    var seed: [64]u8 = undefined;
    io.random(&seed);
    const g_cipher = grease(seed[0]);
    const g_ext1 = grease(seed[1]);
    var g_ext2 = grease(seed[2]);
    if (g_ext2 == g_ext1) g_ext2 ^= 0x1010;
    const g_group = grease(seed[3]);
    const g_version = grease(seed[4]);

    var b: Builder = .{ .buf = buf };
    b.byte(1);
    const hs = b.open(3);
    b.int16(0x0303);
    b.bytes(random);
    b.byte(32);
    @memset(buf[b.n..][0..32], 0);
    b.n += 32;

    const cs = b.open(2);
    b.int16(g_cipher);
    for ([_]u16{ 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035 }) |c|
        b.int16(c);
    b.close(cs, 2);
    b.bytes(&.{ 1, 0 }); // compression: null

    const exts = b.open(2);
    b.int16(g_ext1);
    b.int16(0);

    const names = @typeInfo(Ext).@"enum".field_names;
    var order: [names.len]Ext = undefined;
    inline for (names, 0..) |name, k| order[k] = @field(Ext, name);
    var i: usize = order.len;
    while (i > 1) {
        i -= 1;
        const j = seed[8 + i] % (i + 1);
        std.mem.swap(Ext, &order[i], &order[j]);
    }
    for (order) |ext| {
        if (ext == .server_name and (server_name.len == 0 or isIpLiteral(server_name))) continue;
        if (ext == .application_settings and shape.alpn == .http11) continue;
        b.int16(@intFromEnum(ext));
        const body = b.open(2);
        switch (ext) {
            .server_name => {
                const list = b.open(2);
                b.byte(0);
                const name = b.open(2);
                b.bytes(server_name);
                b.close(name, 2);
                b.close(list, 2);
            },
            .status_request => b.bytes(&.{ 1, 0, 0, 0, 0 }),
            .supported_groups => {
                const list = b.open(2);
                for ([_]u16{ g_group, 0x11ec, 0x001d, 0x0017, 0x0018 }) |g| b.int16(g);
                b.close(list, 2);
            },
            .ec_point_formats => b.bytes(&.{ 1, 0 }),
            .signature_algorithms => {
                const list = b.open(2);
                for ([_]u16{ 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601 }) |s| b.int16(s);
                b.close(list, 2);
            },
            .alpn => b.bytes(switch (shape.alpn) {
                .h2_http11 => &.{ 0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1' },
                .http11 => &.{ 0, 9, 8, 'h', 't', 't', 'p', '/', '1', '.', '1' },
                .h2 => &.{ 0, 3, 2, 'h', '2' },
            }),
            .sct, .extended_master_secret, .session_ticket => {},
            .compress_certificate => b.bytes(&.{ 2, 0, @intFromEnum(shape.cert_compression) }),
            .supported_versions => {
                b.byte(6);
                b.int16(g_version);
                b.int16(0x0304);
                b.int16(0x0303);
            },
            .psk_key_exchange_modes => b.bytes(&.{ 1, 1 }),
            .key_share => {
                const list = b.open(2);
                b.int16(g_group);
                b.int16(1);
                b.byte(0);
                b.int16(0x11ec);
                b.int16(kem_pub.len + 32);
                b.bytes(kem_pub);
                b.bytes(x25519_pub);
                b.int16(0x001d);
                b.int16(32);
                b.bytes(x25519_pub);
                b.close(list, 2);
            },
            // ALPS goes with h2 only, as Chrome does
            .application_settings => b.bytes(&.{ 0, 3, 2, 'h', '2' }),
            .encrypted_client_hello => {
                b.bytes(&.{ 0, 0, 1, 0, 1 }); // outer, HKDF-SHA256, AES-128-GCM
                b.byte(seed[5]); // config id
                b.int16(32);
                io.random(buf[b.n..][0..32]);
                b.n += 32;
                const payload_len: u16 = 32 * (4 + @as(u16, seed[6] % 4)) + 16;
                b.int16(payload_len);
                io.random(buf[b.n..][0..payload_len]);
                b.n += payload_len;
            },
            .renegotiation_info => b.byte(0),
        }
        b.close(body, 2);
    }
    b.int16(g_ext2);
    b.int16(1);
    b.byte(0);
    b.close(exts, 2);
    b.close(hs, 3);
    return buf[0..b.n];
}

// ---------------------------------------------------------------- tests

test "in-place record protection matches out-of-place AEAD" {
    inline for (.{ Suite.aes_128_gcm_sha256, Suite.aes_256_gcm_sha384, Suite.chacha20_poly1305_sha256 }) |suite| {
        const S = Spec(suite);
        var secret: [S.Hash.digest_length]u8 = undefined;
        for (&secret, 0..) |*b, k| b.* = @intCast(k);
        var keys = Keys.derive(suite, secret);
        var rec: [5 + 300 + 16]u8 = undefined;
        var msg: [300]u8 = undefined;
        for (&msg, 0..) |*b, k| b.* = @truncate(k *% 7);
        @memcpy(rec[5..][0..300], &msg);
        const n = keys.seal(&rec, 300);

        const p = @field(Keys.derive(suite, secret), @tagName(suite));
        var expect: [300]u8 = undefined;
        var tag: [16]u8 = undefined;
        S.Aead.encrypt(&expect, &tag, &msg, rec[0..5], p.iv, p.key);
        try std.testing.expectEqualSlices(u8, &expect, rec[5..305]);
        try std.testing.expectEqualSlices(u8, &tag, rec[305..321]);

        var back = Keys.derive(suite, secret);
        const plain = try back.open(rec[0..5], rec[5..n]);
        try std.testing.expectEqualSlices(u8, &msg, plain);
    }
}

test "REALITY token opens on the server side" {
    const io = std.testing.io;
    const server = X25519.KeyPair.generate(io);
    const client = X25519.KeyPair.generate(io);
    const kem = MLKem768.KeyPair.generate(io);
    var random: [32]u8 = undefined;
    io.random(&random);
    var buf: [2560]u8 = undefined;
    const hello = buildClientHello(&buf, io, &random, &client.public_key, &kem.public_key.toBytes(), "www.example.com", .{});
    const re: Reality = .{ .public_key = server.public_key, .short_id = .{ 0xab, 0x12, 0, 0, 0, 0, 0, 0 } };
    const auth = try sealRealitySessionId(hello, &random, client.secret_key, re, 1_700_000_000);

    // what a REALITY server does
    const shared = try X25519.scalarmult(server.secret_key, client.public_key);
    const prk = crypto.kdf.hkdf.HkdfSha256.extract(random[0..20], &shared);
    var key: [32]u8 = undefined;
    crypto.kdf.hkdf.HkdfSha256.expand(&key, "REALITY", prk);
    try std.testing.expectEqual(auth, key);
    var aad: [2560]u8 = undefined;
    @memcpy(aad[0..hello.len], hello);
    @memset(aad[session_id_offset..][0..32], 0);
    var plain: [16]u8 = undefined;
    const sid = hello[session_id_offset..][0..32];
    try crypto.aead.aes_gcm.Aes256Gcm.decrypt(&plain, sid[0..16], sid[16..32].*, aad[0..hello.len], random[20..32].*, key);
    try std.testing.expectEqualSlices(u8, &re.version, plain[0..3]);
    try std.testing.expectEqual(1_700_000_000, std.mem.readInt(u32, plain[4..8], .big));
    try std.testing.expectEqualSlices(u8, &re.short_id, plain[8..16]);
}

test "REALITY certificate binding" {
    var auth: [32]u8 = @splat(7);
    const key: [32]u8 = @splat(3);
    var cert: [12 + 32 + 10 + 3 + 64]u8 = undefined;
    cert[0..12].* = .{ 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };
    cert[12..44].* = key;
    @memset(cert[44..54], 0x30);
    cert[54..57].* = .{ 0x03, 0x41, 0x00 };
    crypto.auth.hmac.sha2.HmacSha512.create(cert[57..121], &key, &auth);
    try std.testing.expectEqual(key, realityCertificateKey(&cert, auth).?);
    auth[0] ^= 1;
    try std.testing.expect(realityCertificateKey(&cert, auth) == null);
}

test "ClientHello structure" {
    const io = std.testing.io;
    var random: [32]u8 = @splat(1);
    const x: [32]u8 = @splat(2);
    const kem: [MLKem768.PublicKey.encoded_length]u8 = @splat(3);
    var buf: [2560]u8 = undefined;
    const hello = buildClientHello(&buf, io, &random, &x, &kem, "example.com", .{});
    try std.testing.expectEqual(1, hello[0]);
    try std.testing.expectEqual(hello.len - 4, std.mem.readInt(u24, hello[1..4], .big));
    try std.testing.expectEqual(32, hello[session_id_offset - 1]);
    // every extension parses and the key share carries both groups
    var c: Cursor = .{ .b = hello[4..] };
    _ = try c.take(2 + 32);
    _ = try c.vec(u8);
    _ = try c.vec(u16);
    _ = try c.vec(u8);
    var exts: Cursor = .{ .b = try c.vec(u16) };
    try std.testing.expectEqual(c.b.len, c.i);
    var seen_sni = false;
    var shares: usize = 0;
    while (exts.i < exts.b.len) {
        const kind = try exts.int(u16);
        var body: Cursor = .{ .b = try exts.vec(u16) };
        if (kind == 0) seen_sni = std.mem.endsWith(u8, body.b, "example.com");
        if (kind == 51) {
            var list: Cursor = .{ .b = try body.vec(u16) };
            while (list.i < list.b.len) {
                _ = try list.int(u16);
                _ = try list.vec(u16);
                shares += 1;
            }
        }
    }
    try std.testing.expect(seen_sni);
    try std.testing.expectEqual(3, shares);
}

test "every handshake path compiles" {
    // the handshake is otherwise only reached from the proxy
    _ = &handshake;
    _ = &verifyChain;
    _ = &LeafKey.verifyCertificateVerify;
    _ = &decompressCertificate;
}
