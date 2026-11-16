//! QR codes (ISO/IEC 18004): reading one from a picture (a screenshot, a
//! photo, the camera), and making one. For links and subscriptions shown
//! as QR codes, the way servers are often handed out.
//!
//!   decode(gray, w, h)  the text of a QR code found in a grayscale image
//!   readGrid(grid)      the text of a QR code given module by module
//!   encode(text, ...)   the modules of a QR code for `text` (byte mode)
//!
//! The tables and the placement follow the standard as Project Nayuki's
//! QR Code generator writes it down; the reader is checked against codes
//! made by Apple's CoreImage (see the tests).

const std = @import("std");

pub const Ecc = enum(u2) {
    low,
    medium,
    quartile,
    high,

    /// the two bits of the format information
    fn formatBits(e: Ecc) u5 {
        return switch (e) {
            .low => 1,
            .medium => 0,
            .quartile => 3,
            .high => 2,
        };
    }
};

pub const max_version = 40;
pub const max_size = 17 + 4 * max_version;

/// Error correction codewords per block, by level and version.
const ecc_per_block = [4][41]u8{
    .{ 0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 },
    .{ 0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28 },
    .{ 0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 },
    .{ 0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 },
};

/// Error correction blocks, by level and version.
const num_blocks = [4][41]u8{
    .{ 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25 },
    .{ 0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49 },
    .{ 0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68 },
    .{ 0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81 },
};

pub fn sizeOf(version: u8) usize {
    return 17 + 4 * @as(usize, version);
}

/// Modules that carry data or error correction, in bits.
fn rawDataModules(ver: u8) usize {
    const v: usize = ver;
    var r: usize = (16 * v + 128) * v + 64;
    if (v >= 2) {
        const n = v / 7 + 2;
        r -= (25 * n - 10) * n - 55;
        if (v >= 7) r -= 36;
    }
    return r;
}

fn dataCodewords(ver: u8, ecc: Ecc) usize {
    const e = @intFromEnum(ecc);
    return rawDataModules(ver) / 8 - @as(usize, ecc_per_block[e][ver]) * num_blocks[e][ver];
}

/// Row/column of each alignment pattern's centre.
fn alignmentPositions(ver: u8, out: *[7]u8) []const u8 {
    if (ver == 1) return out[0..0];
    const n: usize = ver / 7 + 2;
    const size: usize = sizeOf(ver);
    const step: usize = (@as(usize, ver) * 8 + n * 3 + 5) / (n * 4 - 4) * 2;
    out[0] = 6;
    var i: usize = n - 1;
    var pos: usize = size - 7;
    while (i >= 1) : (i -= 1) {
        out[i] = @intCast(pos);
        if (i > 1) pos -= step;
    }
    return out[0..n];
}

// ---------------------------------------------------------------- GF(256)

const Gf = struct {
    exp: [512]u8,
    log: [256]u8,

    fn init() Gf {
        var g: Gf = undefined;
        var x: u16 = 1;
        for (0..255) |i| {
            g.exp[i] = @intCast(x);
            g.log[x] = @intCast(i);
            x <<= 1;
            if (x & 0x100 != 0) x ^= 0x11d;
        }
        for (255..512) |i| g.exp[i] = g.exp[i - 255];
        g.log[0] = 0;
        return g;
    }

    fn mul(g: *const Gf, a: u8, b: u8) u8 {
        if (a == 0 or b == 0) return 0;
        return g.exp[@as(usize, g.log[a]) + g.log[b]];
    }

    fn div(g: *const Gf, a: u8, b: u8) u8 {
        if (a == 0) return 0;
        return g.exp[@as(usize, g.log[a]) + 255 - g.log[b]];
    }

    fn pow(g: *const Gf, e: usize) u8 {
        return g.exp[e % 255];
    }
};

const gf = Gf.init();

/// The error correction codewords of `data` (`out.len` of them).
fn rsEncode(data: []const u8, out: []u8) void {
    const n = out.len;
    var gen: [31]u8 = @splat(0);
    gen[n - 1] = 1;
    // the generator polynomial, highest coefficient implied (monic)
    var root: u8 = 1;
    for (0..n) |_| {
        for (0..n) |j| {
            gen[j] = gf.mul(gen[j], root);
            if (j + 1 < n) gen[j] ^= gen[j + 1];
        }
        root = gf.mul(root, 2);
    }
    @memset(out, 0);
    for (data) |b| {
        const factor = b ^ out[0];
        std.mem.copyForwards(u8, out[0 .. n - 1], out[1..n]);
        out[n - 1] = 0;
        for (0..n) |j| out[j] ^= gf.mul(gen[j], factor);
    }
}

/// Corrects `block` (data then error correction codewords, `ecc` of
/// them) in place. False when there are more errors than it can fix.
fn rsCorrect(block: []u8, ecc: usize) bool {
    var syn: [30]u8 = undefined;
    var clean = true;
    for (0..ecc) |j| {
        var s: u8 = 0;
        for (block) |b| s = gf.mul(s, gf.pow(j)) ^ b;
        syn[j] = s;
        if (s != 0) clean = false;
    }
    if (clean) return true;

    // Berlekamp-Massey: the error locator
    var lambda: [31]u8 = @splat(0);
    var prev: [31]u8 = @splat(0);
    lambda[0] = 1;
    prev[0] = 1;
    var l: usize = 0;
    var m: usize = 1;
    var b: u8 = 1;
    for (0..ecc) |n| {
        var d: u8 = syn[n];
        for (1..l + 1) |i| d ^= gf.mul(lambda[i], syn[n - i]);
        if (d == 0) {
            m += 1;
            continue;
        }
        const t = lambda;
        const coef = gf.div(d, b);
        for (0..31 - m) |i| lambda[i + m] ^= gf.mul(coef, prev[i]);
        if (2 * l <= n) {
            l = n + 1 - l;
            prev = t;
            b = d;
            m = 1;
        } else m += 1;
    }
    if (l == 0 or 2 * l > ecc) return false;

    // Chien search: positions where Λ(X⁻¹) = 0
    const len = block.len;
    var pos: [15]usize = undefined;
    var found: usize = 0;
    for (0..len) |i| {
        // the codeword at index i has the power len-1-i
        const p = len - 1 - i;
        const xinv = gf.pow(255 - (p % 255));
        var v: u8 = 0;
        var xp: u8 = 1;
        for (0..l + 1) |k| {
            v ^= gf.mul(lambda[k], xp);
            xp = gf.mul(xp, xinv);
        }
        if (v == 0) {
            if (found == pos.len) return false;
            pos[found] = i;
            found += 1;
        }
    }
    if (found != l) return false;

    // Forney: Ω = S·Λ mod x^ecc, e = X·Ω(X⁻¹)/Λ'(X⁻¹) (first root α⁰)
    var omega: [30]u8 = @splat(0);
    for (0..ecc) |i| {
        var v: u8 = 0;
        for (0..@min(i, l) + 1) |k| v ^= gf.mul(lambda[k], syn[i - k]);
        omega[i] = v;
    }
    for (pos[0..found]) |i| {
        const p = len - 1 - i;
        const x = gf.pow(p);
        const xinv = gf.pow(255 - (p % 255));
        var num: u8 = 0;
        var xp: u8 = 1;
        for (0..ecc) |k| {
            num ^= gf.mul(omega[k], xp);
            xp = gf.mul(xp, xinv);
        }
        // the formal derivative keeps the odd terms
        var den: u8 = 0;
        xp = 1;
        var k: usize = 1;
        while (k <= l) : (k += 2) {
            den ^= gf.mul(lambda[k], xp);
            xp = gf.mul(xp, gf.mul(xinv, xinv));
        }
        if (den == 0) return false;
        block[i] ^= gf.mul(x, gf.div(num, den));
    }
    // what is left must be a codeword
    for (0..ecc) |j| {
        var s: u8 = 0;
        for (block) |c| s = gf.mul(s, gf.pow(j)) ^ c;
        if (s != 0) return false;
    }
    return true;
}

// ---------------------------------------------------------------- the grid

/// Modules of a symbol, row by row; true is dark.
pub const Grid = struct {
    size: usize,
    bits: [max_size * max_size]bool = undefined,

    pub fn get(g: *const Grid, x: usize, y: usize) bool {
        return g.bits[y * g.size + x];
    }
    pub fn set(g: *Grid, x: usize, y: usize, v: bool) void {
        g.bits[y * g.size + x] = v;
    }
};

/// Which modules are function patterns (finders, timing, alignment,
/// format and version information) for a version.
const Function = struct {
    size: usize,
    bits: [max_size * max_size]bool = undefined,

    fn init(ver: u8) Function {
        const size = sizeOf(ver);
        var f: Function = .{ .size = size };
        @memset(f.bits[0 .. size * size], false);
        // finders with their separators, and the format areas next to them
        f.rect(0, 0, 9, 9);
        f.rect(size - 8, 0, 8, 9);
        f.rect(0, size - 8, 9, 8);
        // timing
        f.rect(6, 0, 1, size);
        f.rect(0, 6, size, 1);
        var ap: [7]u8 = undefined;
        const pos = alignmentPositions(ver, &ap);
        for (pos, 0..) |ay, i| for (pos, 0..) |ax, j| {
            const corner = (i == 0 and j == 0) or (i == 0 and j == pos.len - 1) or (i == pos.len - 1 and j == 0);
            if (!corner) f.rect(@as(usize, ax) - 2, @as(usize, ay) - 2, 5, 5);
        };
        if (ver >= 7) {
            f.rect(size - 11, 0, 3, 6);
            f.rect(0, size - 11, 6, 3);
        }
        return f;
    }

    fn rect(f: *Function, x: usize, y: usize, w: usize, h: usize) void {
        for (y..y + h) |yy| for (x..x + w) |xx| {
            f.bits[yy * f.size + xx] = true;
        };
    }

    fn is(f: *const Function, x: usize, y: usize) bool {
        return f.bits[y * f.size + x];
    }
};

fn maskBit(mask: u3, x: usize, y: usize) bool {
    return switch (mask) {
        0 => (x + y) % 2 == 0,
        1 => y % 2 == 0,
        2 => x % 3 == 0,
        3 => (x + y) % 3 == 0,
        4 => (x / 3 + y / 2) % 2 == 0,
        5 => x * y % 2 + x * y % 3 == 0,
        6 => (x * y % 2 + x * y % 3) % 2 == 0,
        7 => ((x + y) % 2 + x * y % 3) % 2 == 0,
    };
}

/// The data modules in reading order (the zigzag from the bottom right).
const Walk = struct {
    size: usize,
    right: isize,
    vert: usize = 0,
    j: usize = 0,

    fn init(size: usize) Walk {
        return .{ .size = size, .right = @intCast(size - 1) };
    }

    fn next(w: *Walk, f: *const Function) ?struct { usize, usize } {
        while (w.right >= 1) {
            while (w.vert < w.size) {
                while (w.j < 2) {
                    const x: usize = @intCast(w.right - @as(isize, @intCast(w.j)));
                    const upward = (@as(usize, @intCast(w.right)) + 1) & 2 == 0;
                    const y = if (upward) w.size - 1 - w.vert else w.vert;
                    w.j += 1;
                    if (!f.is(x, y)) return .{ x, y };
                }
                w.j = 0;
                w.vert += 1;
            }
            w.vert = 0;
            w.right -= 2;
            if (w.right == 6) w.right = 5;
        }
        return null;
    }
};

fn formatInfo(ecc: Ecc, mask: u3) u15 {
    const data: u32 = @as(u32, ecc.formatBits()) << 3 | mask;
    var rem = data;
    for (0..10) |_| rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    return @intCast(((data << 10) | (rem & 0x3ff)) ^ 0x5412);
}

fn versionInfo(ver: u8) u18 {
    var rem: u32 = ver;
    for (0..12) |_| rem = (rem << 1) ^ ((rem >> 11) * 0x1f25);
    return @intCast(@as(u32, ver) << 12 | (rem & 0xfff));
}

// ---------------------------------------------------------------- making one

pub const EncodeError = error{TooLong};

/// A QR code of `text` in byte mode, at the smallest version that holds
/// it with error correction `ecc`, mask 0..7 chosen by the standard's
/// penalty rules being left out: mask `mask` is used.
pub fn encode(text: []const u8, ecc: Ecc, mask: u3, out: *Grid) EncodeError!u8 {
    var ver: u8 = 1;
    while (ver <= max_version) : (ver += 1) {
        const cap = dataCodewords(ver, ecc) * 8;
        const count_bits: usize = if (ver <= 9) 8 else 16;
        if (4 + count_bits + text.len * 8 <= cap) break;
    } else return error.TooLong;
    const size = sizeOf(ver);
    out.size = size;
    @memset(out.bits[0 .. size * size], false);

    // the data bits, padded
    var data: [3706]u8 = @splat(0);
    const dlen = dataCodewords(ver, ecc);
    var bw: BitWriter = .{ .buf = data[0..dlen] };
    bw.put(4, 4);
    bw.put(text.len, if (ver <= 9) 8 else 16);
    for (text) |c| bw.put(c, 8);
    bw.put(0, @min(4, dlen * 8 - bw.n));
    while (bw.n % 8 != 0) bw.put(0, 1);
    var pad: u8 = 0xec;
    while (bw.n < dlen * 8) : (pad ^= 0xec ^ 0x11) bw.put(pad, 8);

    // blocks with their error correction, interleaved
    var all: [3706]u8 = undefined;
    const e = @intFromEnum(ecc);
    const nb: usize = num_blocks[e][ver];
    const eb: usize = ecc_per_block[e][ver];
    const raw = rawDataModules(ver) / 8;
    const short_len = raw / nb;
    const num_short = nb - raw % nb;
    var blocks: [81][153]u8 = undefined;
    var off: usize = 0;
    for (0..nb) |i| {
        const dl = short_len - eb + @intFromBool(i >= num_short);
        @memcpy(blocks[i][0..dl], data[off..][0..dl]);
        rsEncode(data[off..][0..dl], blocks[i][dl..][0..eb]);
        off += dl;
    }
    var k: usize = 0;
    for (0..short_len - eb + 1) |col| for (0..nb) |i| {
        if (col == short_len - eb and i < num_short) continue;
        all[k] = blocks[i][col];
        k += 1;
    };
    for (0..eb) |col| for (0..nb) |i| {
        const dl = short_len - eb + @intFromBool(i >= num_short);
        all[k] = blocks[i][dl + col];
        k += 1;
    };

    // the function patterns
    const f: Function = .init(ver);
    drawFunction(out, ver, ecc, mask);
    var walk: Walk = .init(size);
    var bit: usize = 0;
    while (walk.next(&f)) |p| : (bit += 1) {
        const x, const y = p;
        const v = bit < k * 8 and (all[bit / 8] >> @intCast(7 - bit % 8)) & 1 == 1;
        out.set(x, y, v != maskBit(mask, x, y));
    }
    return ver;
}

const BitWriter = struct {
    buf: []u8,
    n: usize = 0,

    fn put(w: *BitWriter, v: usize, bits: usize) void {
        var i = bits;
        while (i > 0) {
            i -= 1;
            if ((v >> @intCast(i)) & 1 == 1) w.buf[w.n / 8] |= @as(u8, 0x80) >> @intCast(w.n % 8);
            w.n += 1;
        }
    }
};

fn drawFunction(g: *Grid, ver: u8, ecc: Ecc, mask: u3) void {
    const size = g.size;
    for (0..size) |i| {
        g.set(6, i, i % 2 == 0);
        g.set(i, 6, i % 2 == 0);
    }
    for ([_][2]usize{ .{ 3, 3 }, .{ size - 4, 3 }, .{ 3, size - 4 } }) |c| {
        var dy: isize = -4;
        while (dy <= 4) : (dy += 1) {
            var dx: isize = -4;
            while (dx <= 4) : (dx += 1) {
                const x = @as(isize, @intCast(c[0])) + dx;
                const y = @as(isize, @intCast(c[1])) + dy;
                if (x < 0 or y < 0 or x >= size or y >= size) continue;
                const dist = @max(@abs(dx), @abs(dy));
                g.set(@intCast(x), @intCast(y), dist != 2 and dist != 4);
            }
        }
    }
    var ap: [7]u8 = undefined;
    const pos = alignmentPositions(ver, &ap);
    for (pos, 0..) |ay, i| for (pos, 0..) |ax, j| {
        const corner = (i == 0 and j == 0) or (i == 0 and j == pos.len - 1) or (i == pos.len - 1 and j == 0);
        if (corner) continue;
        var dy: isize = -2;
        while (dy <= 2) : (dy += 1) {
            var dx: isize = -2;
            while (dx <= 2) : (dx += 1) {
                g.set(@intCast(@as(isize, ax) + dx), @intCast(@as(isize, ay) + dy), @max(@abs(dx), @abs(dy)) != 1);
            }
        }
    };
    const fmt = formatInfo(ecc, mask);
    const bitOf = struct {
        fn f(v: u32, i: usize) bool {
            return (v >> @intCast(i)) & 1 == 1;
        }
    }.f;
    for (0..6) |i| g.set(8, i, bitOf(fmt, i));
    g.set(8, 7, bitOf(fmt, 6));
    g.set(8, 8, bitOf(fmt, 7));
    g.set(7, 8, bitOf(fmt, 8));
    for (9..15) |i| g.set(14 - i, 8, bitOf(fmt, i));
    for (0..8) |i| g.set(size - 1 - i, 8, bitOf(fmt, i));
    for (8..15) |i| g.set(8, size - 15 + i, bitOf(fmt, i));
    g.set(8, size - 8, true);
    if (ver >= 7) {
        const vi = versionInfo(ver);
        for (0..18) |i| {
            const a = size - 11 + i % 3;
            const b = i / 3;
            g.set(a, b, bitOf(vi, i));
            g.set(b, a, bitOf(vi, i));
        }
    }
}

// ---------------------------------------------------------------- reading a grid

pub const ReadError = error{ NotQr, BadFormat, TooManyErrors, BadData, TooLong };

/// The text of a symbol read module by module. `out` receives it.
pub fn readGrid(g: *const Grid, out: []u8) ReadError![]u8 {
    if (g.size < 21 or g.size > max_size or (g.size - 17) % 4 != 0) return error.NotQr;
    const ver: u8 = @intCast((g.size - 17) / 4);
    const ecc, const mask = try readFormat(g);
    const f: Function = .init(ver);

    // the codewords, unmasked
    var all: [3706]u8 = @splat(0);
    const raw = rawDataModules(ver) / 8;
    var walk: Walk = .init(g.size);
    var bit: usize = 0;
    while (walk.next(&f)) |p| : (bit += 1) {
        if (bit >= raw * 8) break;
        const x, const y = p;
        if (g.get(x, y) != maskBit(mask, x, y)) all[bit / 8] |= @as(u8, 0x80) >> @intCast(bit % 8);
    }

    // de-interleave and correct each block
    const e = @intFromEnum(ecc);
    const nb: usize = num_blocks[e][ver];
    const eb: usize = ecc_per_block[e][ver];
    const short_len = raw / nb;
    const num_short = nb - raw % nb;
    var blocks: [81][153]u8 = undefined;
    var k: usize = 0;
    for (0..short_len - eb + 1) |col| for (0..nb) |i| {
        if (col == short_len - eb and i < num_short) continue;
        blocks[i][col] = all[k];
        k += 1;
    };
    for (0..eb) |col| for (0..nb) |i| {
        const dl = short_len - eb + @intFromBool(i >= num_short);
        blocks[i][dl + col] = all[k];
        k += 1;
    };
    var data: [3706]u8 = undefined;
    var dlen: usize = 0;
    for (0..nb) |i| {
        const dl = short_len - eb + @intFromBool(i >= num_short);
        if (!rsCorrect(blocks[i][0 .. dl + eb], eb)) return error.TooManyErrors;
        @memcpy(data[dlen..][0..dl], blocks[i][0..dl]);
        dlen += dl;
    }
    return decodeData(data[0..dlen], ver, out);
}

/// Level and mask from the format information, either copy, allowing
/// three wrong bits.
fn readFormat(g: *const Grid) ReadError!struct { Ecc, u3 } {
    const size = g.size;
    var a: u32 = 0;
    var b: u32 = 0;
    const one = struct {
        fn f(v: *u32, i: usize, on: bool) void {
            if (on) v.* |= @as(u32, 1) << @intCast(i);
        }
    }.f;
    for (0..6) |i| one(&a, i, g.get(8, i));
    one(&a, 6, g.get(8, 7));
    one(&a, 7, g.get(8, 8));
    one(&a, 8, g.get(7, 8));
    for (9..15) |i| one(&a, i, g.get(14 - i, 8));
    for (0..8) |i| one(&b, i, g.get(size - 1 - i, 8));
    for (8..15) |i| one(&b, i, g.get(8, size - 15 + i));
    var best: ?struct { Ecc, u3 } = null;
    var best_d: u32 = 4;
    for ([_]Ecc{ .low, .medium, .quartile, .high }) |ecc| for (0..8) |m| {
        const code = formatInfo(ecc, @intCast(m));
        const d = @min(@popCount(code ^ a), @popCount(code ^ b));
        if (d < best_d) {
            best_d = d;
            best = .{ ecc, @intCast(m) };
        }
    };
    return best orelse error.BadFormat;
}

const BitReader = struct {
    buf: []const u8,
    n: usize = 0,

    fn left(r: *const BitReader) usize {
        return r.buf.len * 8 - r.n;
    }
    fn take(r: *BitReader, bits: usize) ?usize {
        if (bits > r.left()) return null;
        var v: usize = 0;
        for (0..bits) |_| {
            v = v << 1 | ((r.buf[r.n / 8] >> @intCast(7 - r.n % 8)) & 1);
            r.n += 1;
        }
        return v;
    }
};

const alnum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

fn decodeData(data: []const u8, ver: u8, out: []u8) ReadError![]u8 {
    var r: BitReader = .{ .buf = data };
    var n: usize = 0;
    const tier: usize = if (ver <= 9) 0 else if (ver <= 26) 1 else 2;
    while (r.left() >= 4) {
        const mode = r.take(4).?;
        switch (mode) {
            0 => break,
            1 => { // numeric
                var count = r.take(([_]usize{ 10, 12, 14 })[tier]) orelse return error.BadData;
                while (count > 0) {
                    const digits = @min(count, 3);
                    const v = r.take(([_]usize{ 0, 4, 7, 10 })[digits]) orelse return error.BadData;
                    var buf: [3]u8 = undefined;
                    var x = v;
                    var i = digits;
                    while (i > 0) {
                        i -= 1;
                        buf[i] = '0' + @as(u8, @intCast(x % 10));
                        x /= 10;
                    }
                    if (n + digits > out.len) return error.TooLong;
                    @memcpy(out[n..][0..digits], buf[0..digits]);
                    n += digits;
                    count -= digits;
                }
            },
            2 => { // alphanumeric
                var count = r.take(([_]usize{ 9, 11, 13 })[tier]) orelse return error.BadData;
                while (count >= 2) : (count -= 2) {
                    const v = r.take(11) orelse return error.BadData;
                    if (v / 45 >= 45 or n + 2 > out.len) return error.BadData;
                    out[n] = alnum[v / 45];
                    out[n + 1] = alnum[v % 45];
                    n += 2;
                }
                if (count == 1) {
                    const v = r.take(6) orelse return error.BadData;
                    if (v >= 45 or n + 1 > out.len) return error.BadData;
                    out[n] = alnum[v];
                    n += 1;
                }
            },
            4 => { // bytes
                const count = r.take(([_]usize{ 8, 16, 16 })[tier]) orelse return error.BadData;
                if (n + count > out.len) return error.TooLong;
                for (0..count) |_| {
                    out[n] = @intCast(r.take(8) orelse return error.BadData);
                    n += 1;
                }
            },
            7 => { // ECI: the designator is skipped, bytes are taken as UTF-8
                const first = r.take(8) orelse return error.BadData;
                if (first & 0x80 != 0) _ = r.take(if (first & 0x40 != 0) 16 else 8) orelse return error.BadData;
            },
            else => return error.BadData,
        }
    }
    return out[0..n];
}

// ---------------------------------------------------------------- finding one in a picture

pub const DecodeError = ReadError || error{ NotFound, OutOfMemory };

/// The text of a QR code in a grayscale picture (`w`×`h`, one byte per
/// pixel, row by row): a screenshot or a photo, upright or turned, light
/// on dark or dark on light.
pub fn decode(gpa: std.mem.Allocator, gray: []const u8, w: usize, h: usize, out: []u8) DecodeError![]u8 {
    if (w < 21 or h < 21 or gray.len < w * h) return error.NotFound;
    const dark = try gpa.alloc(bool, w * h);
    defer gpa.free(dark);
    binarize(gray, w, h, dark);
    const img: Bits = .{ .dark = dark, .w = w, .h = h };
    if (img.find(out)) |text| return text else |_| {}
    // light on dark
    for (dark) |*d| d.* = !d.*;
    return img.find(out);
}

/// Dark or light per pixel: each 8×8 block against the mean of the 5×5
/// blocks around it (screenshots and unevenly lit photos alike).
fn binarize(gray: []const u8, w: usize, h: usize, dark: []bool) void {
    const bs = 8;
    const bw = (w + bs - 1) / bs;
    const bh = (h + bs - 1) / bs;
    var means_buf: [512 * 512]u8 = undefined;
    if (bw * bh > means_buf.len) {
        // very large: one threshold for all
        var sum: u64 = 0;
        for (gray[0 .. w * h]) |v| sum += v;
        const t: u8 = @intCast(sum / (w * h));
        for (gray[0 .. w * h], dark[0 .. w * h]) |v, *d| d.* = v < t;
        return;
    }
    const means = means_buf[0 .. bw * bh];
    for (0..bh) |by| for (0..bw) |bx| {
        var sum: u32 = 0;
        var n: u32 = 0;
        var lo: u8 = 255;
        var hi: u8 = 0;
        for (by * bs..@min(h, by * bs + bs)) |y| for (bx * bs..@min(w, bx * bs + bs)) |x| {
            const v = gray[y * w + x];
            sum += v;
            n += 1;
            lo = @min(lo, v);
            hi = @max(hi, v);
        };
        var m: u8 = @intCast(sum / n);
        // a flat block: light unless its neighbours say it is dark
        if (hi - lo <= 24) {
            m = lo / 2;
            if (by > 0 and bx > 0) {
                const nb = (@as(u32, means[(by - 1) * bw + bx]) * 2 + means[by * bw + bx - 1] + means[(by - 1) * bw + bx - 1]) / 4;
                if (lo < nb) m = @intCast(nb);
            }
        }
        means[by * bw + bx] = m;
    };
    for (0..bh) |by| for (0..bw) |bx| {
        var sum: u32 = 0;
        var n: u32 = 0;
        const y0 = by -| 2;
        const x0 = bx -| 2;
        for (y0..@min(bh, by + 3)) |yy| for (x0..@min(bw, bx + 3)) |xx| {
            sum += means[yy * bw + xx];
            n += 1;
        };
        const t = sum / n;
        for (by * bs..@min(h, by * bs + bs)) |y| for (bx * bs..@min(w, bx * bs + bs)) |x| {
            dark[y * w + x] = gray[y * w + x] <= t;
        };
    };
}

const Pt = struct {
    x: f32,
    y: f32,

    fn dist(a: Pt, b: Pt) f32 {
        return @sqrt((a.x - b.x) * (a.x - b.x) + (a.y - b.y) * (a.y - b.y));
    }
};

const Finder = struct { p: Pt, ms: f32, count: u32 };

const Bits = struct {
    dark: []const bool,
    w: usize,
    h: usize,

    fn at(b: *const Bits, x: isize, y: isize) ?bool {
        if (x < 0 or y < 0 or x >= b.w or y >= b.h) return null;
        return b.dark[@as(usize, @intCast(y)) * b.w + @as(usize, @intCast(x))];
    }

    fn find(b: *const Bits, out: []u8) DecodeError![]u8 {
        var finders: [256]Finder = undefined;
        const n = b.findFinders(&finders);
        if (n < 3) return error.NotFound;
        // every triple that could be a symbol's corners, the most seen first
        // (a finder spans several rows; noise mostly one)
        std.mem.sort(Finder, finders[0..n], {}, struct {
            fn more(_: void, a: Finder, c: Finder) bool {
                return a.count > c.count;
            }
        }.more);
        const lim = @min(n, 12);
        for (0..lim) |i| for (i + 1..lim) |j| for (j + 1..lim) |k| {
            if (b.tryTriple(finders[i], finders[j], finders[k], out)) |text| return text else |_| {}
        };
        return error.NotFound;
    }

    /// Centres of the 1:1:3:1:1 patterns, row by row, checked down the column.
    fn findFinders(b: *const Bits, out: []Finder) usize {
        var n: usize = 0;
        const step = @max(1, b.h / 300);
        var y: usize = 0;
        while (y < b.h) : (y += step) {
            var runs: [5]usize = @splat(0);
            var state: usize = 0;
            var x: usize = 0;
            while (x <= b.w) : (x += 1) {
                const d = if (x < b.w) b.dark[y * b.w + x] else false;
                // states 0, 2, 4 count dark runs; 1, 3 light ones
                const want_dark = state % 2 == 0;
                if (d == want_dark) {
                    runs[state] += 1;
                    continue;
                }
                if (state == 0 and runs[0] == 0) continue; // light before the first dark
                if (state < 4) {
                    state += 1;
                    runs[state] = 1;
                    continue;
                }
                // five runs: is it a finder?
                if (ratioOk(runs)) {
                    const total: f32 = @floatFromInt(runs[0] + runs[1] + runs[2] + runs[3] + runs[4]);
                    const cx = @as(f32, @floatFromInt(x)) - @as(f32, @floatFromInt(runs[4] + runs[3])) - @as(f32, @floatFromInt(runs[2])) / 2;
                    if (b.crossCheck(cx, @floatFromInt(y), total)) |c| n = merge(out, n, c);
                }
                // shift by two runs and go on from the third
                runs = .{ runs[2], runs[3], runs[4], 1, 0 };
                state = 3;
            }
        }
        return n;
    }

    fn ratioOk(r: [5]usize) bool {
        const total = r[0] + r[1] + r[2] + r[3] + r[4];
        if (total < 7) return false;
        const ms = @as(f32, @floatFromInt(total)) / 7.0;
        const tol = ms / 1.5;
        for ([_]usize{ 0, 1, 3, 4 }) |i| if (@abs(@as(f32, @floatFromInt(r[i])) - ms) > tol) return false;
        return @abs(@as(f32, @floatFromInt(r[2])) - 3 * ms) <= 3 * tol;
    }

    /// The pattern down the column through `cx` too: its centre and module size.
    fn crossCheck(b: *const Bits, cx: f32, cy: f32, total: f32) ?Finder {
        const vy = b.centreAlong(cx, cy, 0, 1, total) orelse return null;
        const hx = b.centreAlong(cx, vy[0], 1, 0, total) orelse return null;
        const vy2 = b.centreAlong(hx[0], vy[0], 0, 1, total) orelse return null;
        return .{ .p = .{ .x = hx[0], .y = vy2[0] }, .ms = (hx[1] + vy2[1]) / 14.0, .count = 1 };
    }

    /// Along the direction (dx, dy) through (x, y): the centre of a
    /// 1:1:3:1:1 pattern about `total` long, and its length.
    fn centreAlong(b: *const Bits, x: f32, y: f32, dx: isize, dy: isize, total: f32) ?[2]f32 {
        const ix: isize = @intFromFloat(x);
        const iy: isize = @intFromFloat(y);
        var r: [5]usize = @splat(0);
        const max: usize = @intFromFloat(total * 1.5 + 2);
        // the centre run, both ways
        var back: isize = 0;
        while (b.at(ix - back * dx, iy - back * dy) orelse return null) {
            r[2] += 1;
            back += 1;
            if (r[2] > max) return null;
        }
        var fwd: isize = 1;
        while (b.at(ix + fwd * dx, iy + fwd * dy) orelse return null) {
            r[2] += 1;
            fwd += 1;
            if (r[2] > max) return null;
        }
        // light, then dark, each way
        inline for (.{ .{ 1, false }, .{ 0, true } }) |spec| {
            while ((b.at(ix - back * dx, iy - back * dy) orelse break) == spec[1]) {
                r[spec[0]] += 1;
                back += 1;
                if (r[spec[0]] > max) return null;
            }
        }
        inline for (.{ .{ 3, false }, .{ 4, true } }) |spec| {
            while ((b.at(ix + fwd * dx, iy + fwd * dy) orelse break) == spec[1]) {
                r[spec[0]] += 1;
                fwd += 1;
                if (r[spec[0]] > max) return null;
            }
        }
        if (!ratioOk(r)) return null;
        const len: f32 = @floatFromInt(r[0] + r[1] + r[2] + r[3] + r[4]);
        if (@abs(len - total) > total * 0.6) return null;
        // the middle of the centre run: from its first pixel to past its last
        const lo = -(back - @as(isize, @intCast(r[0] + r[1])));
        const hi = fwd - @as(isize, @intCast(r[3] + r[4]));
        const mid = @as(f32, @floatFromInt(lo + hi)) / 2.0;
        const base: f32 = if (dx != 0) @floatFromInt(ix) else @floatFromInt(iy);
        return .{ base + mid, len };
    }

    fn merge(out: []Finder, n: usize, c: Finder) usize {
        for (out[0..n]) |*f| {
            if (@abs(f.p.x - c.p.x) <= f.ms * 2 and @abs(f.p.y - c.p.y) <= f.ms * 2 and @abs(f.ms - c.ms) <= f.ms) {
                const k: f32 = @floatFromInt(f.count);
                f.p = .{ .x = (f.p.x * k + c.p.x) / (k + 1), .y = (f.p.y * k + c.p.y) / (k + 1) };
                f.ms = (f.ms * k + c.ms) / (k + 1);
                f.count += 1;
                return n;
            }
        }
        if (n == out.len) return n;
        out[n] = c;
        return n + 1;
    }

    fn tryTriple(b: *const Bits, f0: Finder, f1: Finder, f2: Finder, out: []u8) DecodeError![]u8 {
        // similar modules
        const ms_min = @min(f0.ms, @min(f1.ms, f2.ms));
        const ms_max = @max(f0.ms, @max(f1.ms, f2.ms));
        if (ms_max > ms_min * 1.6) return error.NotFound;
        // the corner opposite the longest side is the top left
        const d01 = f0.p.dist(f1.p);
        const d02 = f0.p.dist(f2.p);
        const d12 = f1.p.dist(f2.p);
        var tl = f0.p;
        var tr = f1.p;
        var bl = f2.p;
        if (d01 >= d02 and d01 >= d12) {
            tl = f2.p;
            tr = f0.p;
            bl = f1.p;
        } else if (d02 >= d01 and d02 >= d12) {
            tl = f1.p;
            tr = f0.p;
            bl = f2.p;
        }
        // a right angle with legs alike
        const a = tl.dist(tr);
        const c = tl.dist(bl);
        if (@abs(a - c) > @max(a, c) * 0.25) return error.NotFound;
        const cross = (tr.x - tl.x) * (bl.y - tl.y) - (tr.y - tl.y) * (bl.x - tl.x);
        if (cross < 0) std.mem.swap(Pt, &tr, &bl);
        // the module along the symbol's own axes (a turned finder is wider
        // across the rows than it is along them)
        const along = (b.moduleAlong(tl, tr) + b.moduleAlong(tr, tl) + b.moduleAlong(tl, bl) + b.moduleAlong(bl, tl)) / 4.0;
        const ms = if (along > 0) along else (f0.ms + f1.ms + f2.ms) / 3.0;
        const est: isize = @intFromFloat(@round((a + c) / 2.0 / ms) + 7);
        // the size rounded to one a version has, and its neighbours
        const base = est - @mod(est - 17, 4);
        for ([_]isize{ base, base + 4, base - 4, base + 8 }) |dim| {
            if (dim < 21 or dim > max_size) continue;
            if (b.tryDim(tl, tr, bl, ms, @intCast(dim), out)) |text| return text else |_| {}
        }
        return error.NotFound;
    }

    fn tryDim(b: *const Bits, tl: Pt, tr: Pt, bl: Pt, ms: f32, dim: usize, out: []u8) DecodeError![]u8 {
        const d: f32 = @floatFromInt(dim);
        // the fourth corner: the alignment pattern near it (which also
        // takes the perspective in), else the parallelogram's
        const br: Pt = .{ .x = tr.x - tl.x + bl.x, .y = tr.y - tl.y + bl.y };
        if (dim > 21) {
            const k = 1.0 - 3.0 / (d - 7.0);
            const est: Pt = .{ .x = tl.x + k * (br.x - tl.x), .y = tl.y + k * (br.y - tl.y) };
            const ul = tl.dist(tr);
            const vl = tl.dist(bl);
            const u: Pt = .{ .x = (tr.x - tl.x) / ul, .y = (tr.y - tl.y) / ul };
            const v: Pt = .{ .x = (bl.x - tl.x) / vl, .y = (bl.y - tl.y) / vl };
            if (b.findAlignment(est, ms, u, v)) |ap| {
                if (b.sample(tl, tr, bl, ap, .{ .x = d - 6.5, .y = d - 6.5 }, dim, out)) |text| return text else |_| {}
            }
        }
        return b.sample(tl, tr, bl, br, .{ .x = d - 3.5, .y = d - 3.5 }, dim, out);
    }

    /// The grid through the three finder centres and a fourth point (`br`
    /// in the picture, `br_mod` on the grid), read.
    fn sample(b: *const Bits, tl: Pt, tr: Pt, bl: Pt, br_img: Pt, br_mod: Pt, dim: usize, out: []u8) DecodeError![]u8 {
        const d: f32 = @floatFromInt(dim);
        const t: Transform = .quadToQuad(
            .{ .{ .x = 3.5, .y = 3.5 }, .{ .x = d - 3.5, .y = 3.5 }, br_mod, .{ .x = 3.5, .y = d - 3.5 } },
            .{ tl, tr, br_img, bl },
        );
        var g: Grid = .{ .size = dim };
        for (0..dim) |y| for (0..dim) |x| {
            const p = t.apply(.{ .x = @as(f32, @floatFromInt(x)) + 0.5, .y = @as(f32, @floatFromInt(y)) + 0.5 });
            g.set(x, y, b.at(@intFromFloat(@floor(p.x)), @intFromFloat(@floor(p.y))) orelse false);
        };
        if (readGrid(&g, out)) |text| return text else |_| {}
        // a mirror image (a selfie camera)
        var m: Grid = .{ .size = dim };
        for (0..dim) |y| for (0..dim) |x| m.set(x, y, g.get(y, x));
        return readGrid(&m, out);
    }

    /// The module size as measured from finder centre `p` towards `q`:
    /// out of the centre (1.5 modules), across the light ring and the dark
    /// one (2 more) and back, both ways: 7 modules. Zero if it does not
    /// look like a finder that way.
    fn moduleAlong(b: *const Bits, p: Pt, q: Pt) f32 {
        const len = p.dist(q);
        if (len < 1) return 0;
        const ux = (q.x - p.x) / len;
        const uy = (q.y - p.y) / len;
        var total: f32 = 0;
        for ([_]f32{ 1, -1 }) |sign| {
            var t: f32 = 0;
            var state: u2 = 0; // dark centre, light ring, dark ring
            while (t < len) : (t += 0.5) {
                const d = b.at(@intFromFloat(@floor(p.x + sign * ux * t)), @intFromFloat(@floor(p.y + sign * uy * t))) orelse break;
                if (state == 0 and !d) state = 1 else if (state == 1 and d) state = 2 else if (state == 2 and !d) break;
            }
            if (state != 2) return 0;
            total += t;
        }
        return total / 7.0;
    }

    /// The centre of an alignment pattern (a dark module in a light ring
    /// in a dark ring) near `est`.
    fn findAlignment(b: *const Bits, est: Pt, ms: f32, u: Pt, v: Pt) ?Pt {
        var radius: f32 = ms * 4;
        while (radius <= ms * 16) : (radius *= 2) {
            const x0: isize = @intFromFloat(@max(0, est.x - radius));
            const x1: isize = @intFromFloat(@min(@as(f32, @floatFromInt(b.w - 1)), est.x + radius));
            const y0: isize = @intFromFloat(@max(0, est.y - radius));
            const y1: isize = @intFromFloat(@min(@as(f32, @floatFromInt(b.h - 1)), est.y + radius));
            var best: ?Pt = null;
            var best_d: f32 = std.math.floatMax(f32);
            var y = y0;
            while (y <= y1) : (y += 1) {
                var x = x0;
                while (x <= x1) : (x += 1) {
                    if (!(b.at(x, y) orelse false)) continue;
                    if (b.ringAround(x, y, ms, u, v)) {
                        const p: Pt = .{ .x = @as(f32, @floatFromInt(x)) + 0.5, .y = @as(f32, @floatFromInt(y)) + 0.5 };
                        const dd = p.dist(est);
                        if (dd < best_d) {
                            best_d = dd;
                            best = p;
                        }
                    }
                }
            }
            if (best) |p| return b.refineCentre(p);
        }
        return null;
    }

    /// Light one module out, dark two out, along the symbol's axes `u`
    /// and `v` and their diagonals.
    fn ringAround(b: *const Bits, x: isize, y: isize, ms: f32, u: Pt, v: Pt) bool {
        if (ms < 1) return false;
        const cx = @as(f32, @floatFromInt(x)) + 0.5;
        const cy = @as(f32, @floatFromInt(y)) + 0.5;
        const dirs = [_][2]f32{ .{ 1, 0 }, .{ -1, 0 }, .{ 0, 1 }, .{ 0, -1 }, .{ 1, 1 }, .{ -1, -1 }, .{ 1, -1 }, .{ -1, 1 } };
        for (dirs) |dir| {
            const dx = (dir[0] * u.x + dir[1] * v.x) * ms;
            const dy = (dir[0] * u.y + dir[1] * v.y) * ms;
            const light = b.at(@intFromFloat(@floor(cx + dx)), @intFromFloat(@floor(cy + dy))) orelse return false;
            const dark = b.at(@intFromFloat(@floor(cx + 2 * dx)), @intFromFloat(@floor(cy + 2 * dy))) orelse return false;
            if (light or !dark) return false;
        }
        return true;
    }

    /// The middle of the dark spot at `p`.
    fn refineCentre(b: *const Bits, p: Pt) Pt {
        const ix: isize = @intFromFloat(p.x);
        const iy: isize = @intFromFloat(p.y);
        var l = ix;
        while (b.at(l - 1, iy) orelse false) l -= 1;
        var r = ix;
        while (b.at(r + 1, iy) orelse false) r += 1;
        var u = iy;
        while (b.at(ix, u - 1) orelse false) u -= 1;
        var d = iy;
        while (b.at(ix, d + 1) orelse false) d += 1;
        return .{ .x = @as(f32, @floatFromInt(l + r + 1)) / 2.0, .y = @as(f32, @floatFromInt(u + d + 1)) / 2.0 };
    }
};

/// A projective map of the plane (3×3, last entry 1).
const Transform = struct {
    m: [9]f32,

    fn apply(t: Transform, p: Pt) Pt {
        const z = t.m[6] * p.x + t.m[7] * p.y + t.m[8];
        return .{ .x = (t.m[0] * p.x + t.m[1] * p.y + t.m[2]) / z, .y = (t.m[3] * p.x + t.m[4] * p.y + t.m[5]) / z };
    }

    /// The unit square onto the quadrilateral q (corners in order).
    fn squareToQuad(q: [4]Pt) Transform {
        const dx3 = q[0].x - q[1].x + q[2].x - q[3].x;
        const dy3 = q[0].y - q[1].y + q[2].y - q[3].y;
        if (@abs(dx3) < 1e-6 and @abs(dy3) < 1e-6) {
            return .{ .m = .{ q[1].x - q[0].x, q[3].x - q[0].x, q[0].x, q[1].y - q[0].y, q[3].y - q[0].y, q[0].y, 0, 0, 1 } };
        }
        const dx1 = q[1].x - q[2].x;
        const dx2 = q[3].x - q[2].x;
        const dy1 = q[1].y - q[2].y;
        const dy2 = q[3].y - q[2].y;
        const den = dx1 * dy2 - dx2 * dy1;
        const a13 = (dx3 * dy2 - dx2 * dy3) / den;
        const a23 = (dx1 * dy3 - dx3 * dy1) / den;
        return .{ .m = .{
            q[1].x - q[0].x + a13 * q[1].x, q[3].x - q[0].x + a23 * q[3].x, q[0].x,
            q[1].y - q[0].y + a13 * q[1].y, q[3].y - q[0].y + a23 * q[3].y, q[0].y,
            a13,                            a23,                            1,
        } };
    }

    fn adjoint(t: Transform) Transform {
        const a = t.m;
        return .{ .m = .{
            a[4] * a[8] - a[5] * a[7], a[2] * a[7] - a[1] * a[8], a[1] * a[5] - a[2] * a[4],
            a[5] * a[6] - a[3] * a[8], a[0] * a[8] - a[2] * a[6], a[2] * a[3] - a[0] * a[5],
            a[3] * a[7] - a[4] * a[6], a[1] * a[6] - a[0] * a[7], a[0] * a[4] - a[1] * a[3],
        } };
    }

    fn times(a: Transform, b: Transform) Transform {
        var r: [9]f32 = undefined;
        for (0..3) |i| for (0..3) |j| {
            r[i * 3 + j] = a.m[i * 3] * b.m[j] + a.m[i * 3 + 1] * b.m[3 + j] + a.m[i * 3 + 2] * b.m[6 + j];
        };
        return .{ .m = r };
    }

    /// The quadrilateral `from` onto `to` (corners in the same order).
    fn quadToQuad(from: [4]Pt, to: [4]Pt) Transform {
        return squareToQuad(to).times(squareToQuad(from).adjoint());
    }
};

// ---------------------------------------------------------------- tests

test "Reed-Solomon fixes what it can, refuses the rest" {
    const msg = "hello, QR";
    var block: [9 + 10]u8 = undefined;
    @memcpy(block[0..9], msg);
    rsEncode(msg, block[9..]);
    const good = block;
    try std.testing.expect(rsCorrect(&block, 10));
    for ([_]usize{ 0, 3, 8, 12, 18 }) |i| block[i] ^= 0x5a;
    try std.testing.expect(rsCorrect(&block, 10));
    try std.testing.expectEqualSlices(u8, &good, &block);
    for ([_]usize{ 0, 2, 4, 6, 8, 10 }) |i| block[i] ^= 0x33;
    try std.testing.expect(!rsCorrect(&block, 10) or !std.mem.eql(u8, &good, &block));
}

test "every version and level there and back, with modules spoiled" {
    var g: Grid = undefined;
    var out: [3000]u8 = undefined;
    var text_buf: [2953]u8 = undefined;
    for (&text_buf, 0..) |*c, i| c.* = "vless://abc-def@host.example:443?type=ws#n"[i % 42];
    for ([_]Ecc{ .low, .medium, .quartile, .high }) |ecc| {
        var ver: u8 = 1;
        while (ver <= max_version) : (ver += 1) {
            // as long a text as this version holds
            const count_bits: usize = if (ver <= 9) 8 else 16;
            const len = (dataCodewords(ver, ecc) * 8 - 4 - count_bits) / 8;
            const mask: u3 = @intCast(ver % 8);
            try std.testing.expectEqual(ver, try encode(text_buf[0..len], ecc, mask, &g));
            try std.testing.expectEqualStrings(text_buf[0..len], try readGrid(&g, &out));
            // a few modules wrong in the data area
            for (0..4) |i| {
                const x = g.size - 1 - i;
                g.set(x, g.size - 1, !g.get(x, g.size - 1));
            }
            try std.testing.expectEqualStrings(text_buf[0..len], try readGrid(&g, &out));
        }
    }
}

test "format and version information" {
    // known values from the standard's examples
    try std.testing.expectEqual(@as(u15, 0x5412 ^ 0), formatInfo(.medium, 0) ^ 0);
    try std.testing.expectEqual(@as(u18, 0x07c94), versionInfo(7));
    try std.testing.expectEqual(@as(u18, 0x28c69), versionInfo(40));
}

test "codes made by another encoder (Apple's CoreImage) are read" {
    const fixtures = @import("qr_fixtures.zig");
    var out: [3000]u8 = undefined;
    for (fixtures.all) |fx| {
        var g: Grid = .{ .size = fx.rows.len };
        for (fx.rows, 0..) |row, y| {
            try std.testing.expectEqual(fx.rows.len, row.len);
            for (row, 0..) |c, x| g.set(x, y, c == '#');
        }
        try std.testing.expectEqualStrings(fx.text, try readGrid(&g, &out));
    }
}

/// A grid drawn as a picture: `scale` pixels a module, a quiet zone,
/// turned by `angle` (radians) about the centre, with gray noise.
fn render(gpa: std.mem.Allocator, g: *const Grid, scale: f32, angle: f32, w: usize, h: usize, invert: bool) ![]u8 {
    const img = try gpa.alloc(u8, w * h);
    var prng: std.Random.DefaultPrng = .init(42);
    const rand = prng.random();
    const cx = @as(f32, @floatFromInt(w)) / 2;
    const cy = @as(f32, @floatFromInt(h)) / 2;
    const half = @as(f32, @floatFromInt(g.size)) * scale / 2;
    const cs = @cos(angle);
    const sn = @sin(angle);
    for (0..h) |y| for (0..w) |x| {
        const px = @as(f32, @floatFromInt(x)) - cx;
        const py = @as(f32, @floatFromInt(y)) - cy;
        const u = (px * cs + py * sn + half) / scale;
        const v = (-px * sn + py * cs + half) / scale;
        var dark = false;
        if (u >= 0 and v >= 0 and u < @as(f32, @floatFromInt(g.size)) and v < @as(f32, @floatFromInt(g.size)))
            dark = g.get(@intFromFloat(u), @intFromFloat(v));
        if (invert) dark = !dark;
        const base: i32 = if (dark) 40 else 215;
        img[y * w + x] = @intCast(std.math.clamp(base + rand.intRangeAtMost(i32, -30, 30), 0, 255));
    };
    return img;
}

test "found in a picture: scaled, turned, inverted, noisy" {
    const gpa = std.testing.allocator;
    var g: Grid = undefined;
    var out: [3000]u8 = undefined;
    const link = "vless://11111111-2222-3333-4444-555555555555@nl.example.org:443?type=tcp&security=reality&sni=www.microsoft.com#NL";
    const cases = [_]struct { ecc: Ecc, scale: f32, angle: f32, invert: bool }{
        .{ .ecc = .medium, .scale = 4, .angle = 0, .invert = false },
        .{ .ecc = .low, .scale = 3, .angle = 0.35, .invert = false },
        .{ .ecc = .quartile, .scale = 5, .angle = 2.0, .invert = false },
        .{ .ecc = .high, .scale = 4, .angle = -0.8, .invert = true },
    };
    for (cases) |c| {
        _ = try encode(link, c.ecc, 3, &g);
        const w = 420;
        const img = try render(gpa, &g, c.scale, c.angle, w, w, c.invert);
        defer gpa.free(img);
        const got = decode(gpa, img, w, w, &out) catch |err| {
            std.debug.print("case scale {d} angle {d} invert {}: {t}\n", .{ c.scale, c.angle, c.invert, err });
            return err;
        };
        try std.testing.expectEqualStrings(link, got);
    }
    // nothing there
    const blank = try gpa.alloc(u8, 200 * 200);
    defer gpa.free(blank);
    @memset(blank, 200);
    try std.testing.expectError(error.NotFound, decode(gpa, blank, 200, 200, &out));
}
