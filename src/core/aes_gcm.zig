//! AES-GCM for streams of many messages under one key, without associated
//! data: what Shadowsocks seals each chunk with.
//!
//! The key schedule and the powers of H are made once, in `init`, not for
//! every message as std.crypto's AesGcm does; with Shadowsocks' chunks of 8
//! KiB that alone is a noticeable share. On ARMv8 with the Cryptography
//! Extensions (every 64-bit Apple chip, and most phones) messages are sealed
//! and opened here in one pass, eight blocks at a time: the counter blocks
//! go through AES while the ciphertext goes through GHASH, which keeps both
//! kinds of unit busy (std makes a pass for each). Each AES round is one
//! `aese` + `aesmc` pair with the round key inside it (std's adds an `eor`
//! per round); GHASH multiplies eight blocks by H^8..H^1 before one
//! reduction, and the block whose product waits for the last reduction goes
//! last. On an M4 Pro: 12.5 GB/s for 8 KiB messages with AES-128, std's
//! 3.2, Go's 10.2. Elsewhere std's AesGcm does the work.
//!
//! The field arithmetic is std's (crypto/ghash_polyval.zig): blocks as
//! big-endian 128-bit numbers, H shifted left by one bit and reduced, the
//! product reduced with 0xc2 << 56.
//!
//! `open` may write the plaintext over the ciphertext or anywhere before it
//! in the same buffer: what Shadowsocks uses to lay chunks out end to end.

const std = @import("std");
const builtin = @import("builtin");

/// The aese/pmull path. (The C backend cannot pass vectors to inline asm.)
pub const accelerated = builtin.cpu.arch == .aarch64 and builtin.zig_backend != .stage2_c and
    builtin.cpu.has(.aarch64, .aes);

pub const tag_length = 16;
pub const nonce_length = 12;

pub const Aes128Gcm = AesGcm(16);
pub const Aes256Gcm = AesGcm(32);

const V = @Vector(16, u8);
const W = @Vector(2, u64);

fn AesGcm(comptime key_len: comptime_int) type {
    const Std = if (key_len == 16) std.crypto.aead.aes_gcm.Aes128Gcm else std.crypto.aead.aes_gcm.Aes256Gcm;
    const StdAes = if (key_len == 16) std.crypto.core.aes.Aes128 else std.crypto.core.aes.Aes256;
    const rounds = if (key_len == 16) 10 else 14;

    return struct {
        const Self = @This();
        pub const key_length = key_len;

        state: if (accelerated) struct {
            /// round keys, as `aese` takes them
            rk: [rounds + 1]V,
            /// H^1 .. H^8, shifted and reduced as std's GHASH keeps H
            h: [8]W,
            /// the same with their halves swapped (see `Wide.addRev64`)
            hs: [8]W,
        } else [key_len]u8,

        pub fn init(key: [key_len]u8) Self {
            if (!accelerated) return .{ .state = key };
            const ctx = StdAes.initEnc(key);
            var s: Self = .{ .state = undefined };
            for (&s.state.rk, ctx.key_schedule.round_keys) |*d, k| d.* = k.toBytes();
            var hb: [16]u8 = @bitCast(s.encryptBlock(@splat(0)));
            var h = std.mem.readInt(u128, &hb, .big);
            const carry = ((@as(u128, 0xc2) << 120) | 1) & (@as(u128, 0) -% (h >> 127));
            h = (h << 1) ^ carry;
            const h1: W = @bitCast(h);
            s.state.h[0] = h1;
            for (1..8) |i| s.state.h[i] = mulReduce(s.state.h[i - 1], h1);
            for (&s.state.hs, s.state.h) |*d, x| d.* = swap(x);
            std.crypto.secureZero(u8, &hb);
            return s;
        }

        /// Seal `m` into `c` (which may be `m` itself).
        pub fn encrypt(s: *const Self, c: []u8, tag: *[tag_length]u8, m: []const u8, nonce: [nonce_length]u8) void {
            std.debug.assert(c.len == m.len);
            std.debug.assert(@intFromPtr(c.ptr) <= @intFromPtr(m.ptr) or @intFromPtr(c.ptr) >= @intFromPtr(m.ptr) + m.len);
            if (!accelerated) return Std.encrypt(c, tag, m, "", nonce, s.state);
            tag.* = s.crypt(.seal, c, m, nonce);
        }

        /// Open `c` into `m`, which may be `c` itself or start before it
        /// in the same buffer. `m` is undefined if the tag does not match.
        pub fn decrypt(s: *const Self, m: []u8, c: []const u8, tag: [tag_length]u8, nonce: [nonce_length]u8) error{AuthenticationFailed}!void {
            std.debug.assert(c.len == m.len);
            std.debug.assert(@intFromPtr(m.ptr) <= @intFromPtr(c.ptr) or @intFromPtr(m.ptr) >= @intFromPtr(c.ptr) + c.len);
            if (!accelerated) return Std.decrypt(m, c, tag, "", nonce, s.state);
            const want = s.crypt(.open, m, c, nonce);
            if (!std.crypto.timing_safe.eql([tag_length]u8, want, tag)) return error.AuthenticationFailed;
        }

        fn encryptBlock(s: *const Self, b: V) V {
            var x = b;
            inline for (0..rounds - 1) |r| x = aesRound(x, s.state.rk[r]);
            return aesLast(x, s.state.rk[rounds - 1]) ^ s.state.rk[rounds];
        }

        /// CTR from counter 2 and GHASH of the ciphertext in one pass, eight
        /// blocks at a time; returns the tag. Each group of eight is loaded
        /// before any of it is stored, so `dst` may start at `src` or
        /// before it.
        fn crypt(s: *const Self, comptime dir: enum { seal, open }, dst: []u8, src: []const u8, nonce: [nonce_length]u8) [16]u8 {
            const rk = &s.state.rk;
            const h = &s.state.h;
            const hs = &s.state.hs;
            const base = counterBlock(nonce, 0);
            var n: u32 = 2;
            var acc: W = @splat(0);
            var i: usize = 0;
            while (i + 128 <= src.len) : (i += 128) {
                const in = src[i..][0..128];
                const out = dst[i..][0..128];
                var b: [8]V = undefined;
                inline for (0..8) |j| {
                    var cb = base;
                    cb[3] = @byteSwap(n + @as(u32, j));
                    b[j] = @bitCast(cb);
                }
                n += 8;
                var x: [8]V = undefined;
                inline for (0..8) |j| x[j] = in[16 * j ..][0..16].*;
                var p: Wide = .{};
                // the ciphertext is hashed while the keystream is made; the
                // product that waits for the last reduction comes last
                if (dir == .open) {
                    inline for (1..8) |j| p.addRev64(rev64(x[j]), h[7 - j], hs[7 - j]);
                    p.addRev64(rev64(x[0]) ^ swap(acc), h[7], hs[7]);
                }
                inline for (0..rounds - 1) |r| {
                    inline for (0..8) |j| b[j] = aesRound(b[j], rk[r]);
                }
                inline for (0..8) |j| b[j] = aesLast(b[j], rk[rounds - 1]) ^ rk[rounds] ^ x[j];
                inline for (0..8) |j| out[16 * j ..][0..16].* = b[j];
                if (dir == .seal) {
                    inline for (1..8) |j| p.addRev64(rev64(b[j]), h[7 - j], hs[7 - j]);
                    p.addRev64(rev64(b[0]) ^ swap(acc), h[7], hs[7]);
                }
                acc = p.reduce();
            }
            // what is left, under eight blocks: hash the ciphertext, which
            // for `open` must be read before the plaintext lands on it
            if (dir == .open) acc = s.ghashTail(acc, src[i..], src.len);
            var k = i;
            while (k < src.len) : (k += 16) {
                var cb = base;
                cb[3] = @byteSwap(n);
                n += 1;
                const ks: [16]u8 = s.encryptBlock(@bitCast(cb));
                const len = @min(16, src.len - k);
                for (dst[k..][0..len], src[k..][0..len], ks[0..len]) |*d, a, y| d.* = a ^ y;
            }
            if (dir == .seal) acc = s.ghashTail(acc, dst[i..src.len], src.len);

            var cb = base;
            cb[3] = @byteSwap(@as(u32, 1));
            const mask: [16]u8 = s.encryptBlock(@bitCast(cb));
            var out: [16]u8 = undefined;
            std.mem.writeInt(u128, &out, @bitCast(acc), .big);
            for (&out, mask) |*o, y| o.* ^= y;
            return out;
        }

        /// GHASH of the last `c` (under eight blocks), zero-padded, and the
        /// lengths block for a message of `total` bytes.
        fn ghashTail(s: *const Self, acc: W, c: []const u8, total: usize) W {
            std.debug.assert(c.len < 128);
            const h = &s.state.h;
            // seven whole blocks, a partial one, the lengths: nine at most
            var tail: [9]W = undefined;
            var t: usize = 0;
            var i: usize = 0;
            while (i + 16 <= c.len) : (i += 16) {
                tail[t] = rev(c[i..][0..16].*);
                t += 1;
            }
            if (i < c.len) {
                var last: [16]u8 = @splat(0);
                @memcpy(last[0 .. c.len - i], c[i..]);
                tail[t] = rev(last);
                t += 1;
            }
            tail[t] = .{ @as(u64, total) * 8, 0 };
            t += 1;
            var a = acc;
            var k: usize = 0;
            if (t > h.len) {
                a = mulReduce(tail[0] ^ a, h[0]);
                k = 1;
            }
            tail[k] ^= a;
            var p: Wide = .{};
            for (tail[k..t], 0..) |x, j| p.add(x, h[t - k - 1 - j]);
            return p.reduce();
        }
    };
}

/// The nonce, then a 32-bit big-endian block counter.
inline fn counterBlock(nonce: [nonce_length]u8, n: u32) @Vector(4, u32) {
    var b: [16]u8 = undefined;
    b[0..12].* = nonce;
    std.mem.writeInt(u32, b[12..16], n, .big);
    return @bitCast(b);
}

/// A block as std's GHASH reads it: a big-endian 128-bit number.
inline fn rev(v: V) W {
    return @bitCast(@shuffle(u8, v, undefined, [16]i32{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }));
}

/// The same with its halves swapped: one `rev64`.
inline fn rev64(v: V) W {
    return @bitCast(@shuffle(u8, v, undefined, [16]i32{ 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8 }));
}

inline fn swap(x: W) W {
    return @shuffle(u64, x, undefined, [2]i32{ 1, 0 });
}

/// Unreduced sum of products: halves and the cross term.
const Wide = struct {
    lo: W = @splat(0),
    hi: W = @splat(0),
    mid: W = @splat(0),

    inline fn add(p: *Wide, x: W, h: W) void {
        const xs = swap(x);
        p.lo ^= pmull(x, h);
        p.hi ^= pmull2(x, h);
        p.mid ^= pmull(xs, h) ^ pmull2(xs, h);
    }

    /// `add` of the block whose halves are swapped in `r` (`rev64` of its
    /// bytes), with `hs` the halves of `h` swapped: no swap per block.
    inline fn addRev64(p: *Wide, r: W, h: W, hs: W) void {
        p.lo ^= pmull2(r, hs);
        p.hi ^= pmull(r, hs);
        p.mid ^= pmull(r, h) ^ pmull2(r, h);
    }

    /// std's `reduce`, the halves swapped with shuffles. Its first
    /// product takes the low word of `lo` alone, which the cross term
    /// does not touch: it starts before that term is in.
    inline fn reduce(p: Wide) W {
        const zero: W = @splat(0);
        const hi = p.hi ^ @shuffle(u64, p.mid, zero, [2]i32{ 1, -1 });
        const lo = p.lo ^ @shuffle(u64, p.mid, zero, [2]i32{ -1, 0 });
        const poly: W = .{ 0xc200000000000000, 0 };
        const b = @shuffle(u64, lo, undefined, [2]i32{ 1, 0 }) ^ pmull(p.lo, poly);
        const d = @shuffle(u64, b, undefined, [2]i32{ 1, 0 }) ^ pmull(b, poly);
        return d ^ hi;
    }
};

fn mulReduce(x: W, h: W) W {
    var p: Wide = .{};
    p.add(x, h);
    return p.reduce();
}

inline fn aesRound(b: V, k: V) V {
    return asm (
        \\ aese  %[b].16b, %[k].16b
        \\ aesmc %[b].16b, %[b].16b
        : [b] "=w" (-> V),
        : [in] "0" (b),
          [k] "w" (k),
    );
}

inline fn aesLast(b: V, k: V) V {
    return asm (
        \\ aese  %[b].16b, %[k].16b
        : [b] "=w" (-> V),
        : [in] "0" (b),
          [k] "w" (k),
    );
}

inline fn pmull(a: W, b: W) W {
    return asm (
        \\ pmull %[r].1q, %[a].1d, %[b].1d
        : [r] "=w" (-> W),
        : [a] "w" (a),
          [b] "w" (b),
    );
}

inline fn pmull2(a: W, b: W) W {
    return asm (
        \\ pmull2 %[r].1q, %[a].2d, %[b].2d
        : [r] "=w" (-> W),
        : [a] "w" (a),
          [b] "w" (b),
    );
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "matches std.crypto's AES-GCM, every length up to 300 and chunk sizes" {
    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const rand = prng.random();
    var m: [65535 + 64]u8 = undefined;
    var c: [m.len]u8 = undefined;
    var c2: [m.len]u8 = undefined;
    var back: [m.len]u8 = undefined;
    inline for (.{ Aes128Gcm, Aes256Gcm }) |A| {
        const S = if (A.key_length == 16) std.crypto.aead.aes_gcm.Aes128Gcm else std.crypto.aead.aes_gcm.Aes256Gcm;
        var key: [A.key_length]u8 = undefined;
        rand.bytes(&key);
        const a: A = .init(key);
        var lens: [310]usize = undefined;
        for (lens[0..301], 0..) |*l, i| l.* = i;
        for ([_]usize{ 1024, 8191, 8192, 8193, 16383, 65534, 65535, 65535 + 64, 4095 }, 301..) |l, i| lens[i] = l;
        for (lens) |len| {
            var nonce: [nonce_length]u8 = undefined;
            rand.bytes(&nonce);
            rand.bytes(m[0..len]);
            var tag: [16]u8 = undefined;
            var want_tag: [16]u8 = undefined;
            a.encrypt(c[0..len], &tag, m[0..len], nonce);
            S.encrypt(c2[0..len], &want_tag, m[0..len], "", nonce, key);
            try testing.expectEqualSlices(u8, c2[0..len], c[0..len]);
            try testing.expectEqualSlices(u8, &want_tag, &tag);
            try a.decrypt(back[0..len], c[0..len], tag, nonce);
            try testing.expectEqualSlices(u8, m[0..len], back[0..len]);
            // in place
            @memcpy(back[0..len], c[0..len]);
            try a.decrypt(back[0..len], back[0..len], tag, nonce);
            try testing.expectEqualSlices(u8, m[0..len], back[0..len]);
            // a changed tag or byte
            var bad = tag;
            bad[len % 16] ^= 0x40;
            try testing.expectError(error.AuthenticationFailed, a.decrypt(back[0..len], c[0..len], bad, nonce));
            if (len > 0) {
                c[len / 2] ^= 1;
                try testing.expectError(error.AuthenticationFailed, a.decrypt(back[0..len], c[0..len], tag, nonce));
                c[len / 2] ^= 1;
            }
        }
    }
}

test "the plaintext may land before the ciphertext in the same buffer" {
    var buf: [9000]u8 = undefined;
    var m: [8192]u8 = undefined;
    for (&m, 0..) |*b, i| b.* = @truncate(i * 7 + 3);
    const key: [16]u8 = @splat(9);
    const a: Aes128Gcm = .init(key);
    const nonce: [12]u8 = @splat(1);
    // gaps as Shadowsocks leaves them: a length chunk, then tags piling up
    for ([_]usize{ 1, 15, 16, 18, 34, 52, 127, 128, 129, 500 }) |gap| {
        for ([_]usize{ 0, 1, 17, 100, 1000, 8192 }) |len| {
            var tag: [16]u8 = undefined;
            a.encrypt(buf[gap..][0..len], &tag, m[0..len], nonce);
            try a.decrypt(buf[0..len], buf[gap..][0..len], tag, nonce);
            try testing.expectEqualSlices(u8, m[0..len], buf[0..len]);
        }
    }
}

test "GCM spec test case 3 (AES-128, 64 bytes, no associated data)" {
    // The Galois/Counter Mode of Operation (GCM), McGrew and Viega
    var key: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "feffe9928665731c6d6a8f9467308308");
    var nonce: [12]u8 = undefined;
    _ = try std.fmt.hexToBytes(&nonce, "cafebabefacedbaddecaf888");
    var m: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&m, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    var want: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985");
    var want_tag: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want_tag, "4d5c2af327cd64a62cf35abd2ba6fab4");
    const a: Aes128Gcm = .init(key);
    var c: [64]u8 = undefined;
    var tag: [16]u8 = undefined;
    a.encrypt(&c, &tag, &m, nonce);
    try testing.expectEqualSlices(u8, &want, &c);
    try testing.expectEqualSlices(u8, &want_tag, &tag);
}
