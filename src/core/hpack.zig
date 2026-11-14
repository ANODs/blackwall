//! HPACK, the header compression of HTTP/2 (RFC 7541).
//!
//! Encoder: every field goes out as a literal without indexing (6.2.2), its
//! name taken from the static table when it is there, never Huffman coded.
//! The RFC allows that, it needs no state, and a tunnel sends one request
//! per connection, so compressing it would buy nothing.
//!
//! Decoder: complete (static table, dynamic table with size updates,
//! Huffman) and allocation-free. It has no scratch buffer: a field that
//! enters the dynamic table is decoded straight into the table's ring, any
//! other field straight into the caller's `List`.

const std = @import("std");
const Io = std.Io;

pub const Field = struct {
    name: []const u8,
    value: []const u8,
};

// ---------------------------------------------------------------- integers

/// An integer with a `prefix`-bit prefix (5.1); `first` holds the bits of the
/// first octet above the prefix.
pub fn writeInt(w: *Io.Writer, first: u8, comptime prefix: u4, value: usize) Io.Writer.Error!void {
    const max = (1 << prefix) - 1;
    if (value < max) return w.writeByte(first | @as(u8, @intCast(value)));
    try w.writeByte(first | max);
    var rest = value - max;
    while (rest >= 0x80) : (rest >>= 7) try w.writeByte(@as(u8, @truncate(rest)) | 0x80);
    try w.writeByte(@intCast(rest));
}

fn intLen(comptime prefix: u4, value: usize) usize {
    const max = (1 << prefix) - 1;
    if (value < max) return 1;
    var n: usize = 2;
    var rest = value - max;
    while (rest >= 0x80) : (rest >>= 7) n += 1;
    return n;
}

// ---------------------------------------------------------------- encoder

fn staticName(name: []const u8) ?usize {
    for (static_table, 1..) |f, i| if (std.mem.eql(u8, f.name, name)) return i;
    return null;
}

/// Exact size of `writeField(f)`, so a HEADERS frame header can be written
/// before the fields without encoding them twice.
pub fn fieldLen(f: Field) usize {
    const name = if (staticName(f.name)) |i| intLen(4, i) else 1 + intLen(7, f.name.len) + f.name.len;
    return name + intLen(7, f.value.len) + f.value.len;
}

/// One field as a literal without indexing. HTTP/2 wants lowercase names
/// (RFC 9113 8.2.1): the caller passes them so.
pub fn writeField(w: *Io.Writer, f: Field) Io.Writer.Error!void {
    if (staticName(f.name)) |i| {
        try writeInt(w, 0x00, 4, i);
    } else {
        try w.writeByte(0x00);
        try writeInt(w, 0x00, 7, f.name.len);
        try w.writeAll(f.name);
    }
    try writeInt(w, 0x00, 7, f.value.len);
    try w.writeAll(f.value);
}

// ---------------------------------------------------------------- tables

// Generated from the RFC 7541 text (Appendix A and B) by a script; do not edit by hand.
pub const static_table = [61]Field{
    .{ .name = ":authority", .value = "" }, // 1
    .{ .name = ":method", .value = "GET" }, // 2
    .{ .name = ":method", .value = "POST" }, // 3
    .{ .name = ":path", .value = "/" }, // 4
    .{ .name = ":path", .value = "/index.html" }, // 5
    .{ .name = ":scheme", .value = "http" }, // 6
    .{ .name = ":scheme", .value = "https" }, // 7
    .{ .name = ":status", .value = "200" }, // 8
    .{ .name = ":status", .value = "204" }, // 9
    .{ .name = ":status", .value = "206" }, // 10
    .{ .name = ":status", .value = "304" }, // 11
    .{ .name = ":status", .value = "400" }, // 12
    .{ .name = ":status", .value = "404" }, // 13
    .{ .name = ":status", .value = "500" }, // 14
    .{ .name = "accept-charset", .value = "" }, // 15
    .{ .name = "accept-encoding", .value = "gzip, deflate" }, // 16
    .{ .name = "accept-language", .value = "" }, // 17
    .{ .name = "accept-ranges", .value = "" }, // 18
    .{ .name = "accept", .value = "" }, // 19
    .{ .name = "access-control-allow-origin", .value = "" }, // 20
    .{ .name = "age", .value = "" }, // 21
    .{ .name = "allow", .value = "" }, // 22
    .{ .name = "authorization", .value = "" }, // 23
    .{ .name = "cache-control", .value = "" }, // 24
    .{ .name = "content-disposition", .value = "" }, // 25
    .{ .name = "content-encoding", .value = "" }, // 26
    .{ .name = "content-language", .value = "" }, // 27
    .{ .name = "content-length", .value = "" }, // 28
    .{ .name = "content-location", .value = "" }, // 29
    .{ .name = "content-range", .value = "" }, // 30
    .{ .name = "content-type", .value = "" }, // 31
    .{ .name = "cookie", .value = "" }, // 32
    .{ .name = "date", .value = "" }, // 33
    .{ .name = "etag", .value = "" }, // 34
    .{ .name = "expect", .value = "" }, // 35
    .{ .name = "expires", .value = "" }, // 36
    .{ .name = "from", .value = "" }, // 37
    .{ .name = "host", .value = "" }, // 38
    .{ .name = "if-match", .value = "" }, // 39
    .{ .name = "if-modified-since", .value = "" }, // 40
    .{ .name = "if-none-match", .value = "" }, // 41
    .{ .name = "if-range", .value = "" }, // 42
    .{ .name = "if-unmodified-since", .value = "" }, // 43
    .{ .name = "last-modified", .value = "" }, // 44
    .{ .name = "link", .value = "" }, // 45
    .{ .name = "location", .value = "" }, // 46
    .{ .name = "max-forwards", .value = "" }, // 47
    .{ .name = "proxy-authenticate", .value = "" }, // 48
    .{ .name = "proxy-authorization", .value = "" }, // 49
    .{ .name = "range", .value = "" }, // 50
    .{ .name = "referer", .value = "" }, // 51
    .{ .name = "refresh", .value = "" }, // 52
    .{ .name = "retry-after", .value = "" }, // 53
    .{ .name = "server", .value = "" }, // 54
    .{ .name = "set-cookie", .value = "" }, // 55
    .{ .name = "strict-transport-security", .value = "" }, // 56
    .{ .name = "transfer-encoding", .value = "" }, // 57
    .{ .name = "user-agent", .value = "" }, // 58
    .{ .name = "vary", .value = "" }, // 59
    .{ .name = "via", .value = "" }, // 60
    .{ .name = "www-authenticate", .value = "" }, // 61
};

/// Huffman code: { code aligned to the least significant bit, length in bits }, by symbol 0..256 (256 is EOS).
const huffman_code = [257]struct { u32, u8 }{
    .{ 0x1ff8, 13 }, .{ 0x7fffd8, 23 }, .{ 0xfffffe2, 28 }, .{ 0xfffffe3, 28 }, // 0
    .{ 0xfffffe4, 28 }, .{ 0xfffffe5, 28 }, .{ 0xfffffe6, 28 }, .{ 0xfffffe7, 28 }, // 4
    .{ 0xfffffe8, 28 }, .{ 0xffffea, 24 }, .{ 0x3ffffffc, 30 }, .{ 0xfffffe9, 28 }, // 8
    .{ 0xfffffea, 28 }, .{ 0x3ffffffd, 30 }, .{ 0xfffffeb, 28 }, .{ 0xfffffec, 28 }, // 12
    .{ 0xfffffed, 28 }, .{ 0xfffffee, 28 }, .{ 0xfffffef, 28 }, .{ 0xffffff0, 28 }, // 16
    .{ 0xffffff1, 28 }, .{ 0xffffff2, 28 }, .{ 0x3ffffffe, 30 }, .{ 0xffffff3, 28 }, // 20
    .{ 0xffffff4, 28 }, .{ 0xffffff5, 28 }, .{ 0xffffff6, 28 }, .{ 0xffffff7, 28 }, // 24
    .{ 0xffffff8, 28 }, .{ 0xffffff9, 28 }, .{ 0xffffffa, 28 }, .{ 0xffffffb, 28 }, // 28
    .{ 0x14, 6 }, .{ 0x3f8, 10 }, .{ 0x3f9, 10 }, .{ 0xffa, 12 }, // 32
    .{ 0x1ff9, 13 }, .{ 0x15, 6 }, .{ 0xf8, 8 }, .{ 0x7fa, 11 }, // 36
    .{ 0x3fa, 10 }, .{ 0x3fb, 10 }, .{ 0xf9, 8 }, .{ 0x7fb, 11 }, // 40
    .{ 0xfa, 8 }, .{ 0x16, 6 }, .{ 0x17, 6 }, .{ 0x18, 6 }, // 44
    .{ 0x0, 5 }, .{ 0x1, 5 }, .{ 0x2, 5 }, .{ 0x19, 6 }, // 48
    .{ 0x1a, 6 }, .{ 0x1b, 6 }, .{ 0x1c, 6 }, .{ 0x1d, 6 }, // 52
    .{ 0x1e, 6 }, .{ 0x1f, 6 }, .{ 0x5c, 7 }, .{ 0xfb, 8 }, // 56
    .{ 0x7ffc, 15 }, .{ 0x20, 6 }, .{ 0xffb, 12 }, .{ 0x3fc, 10 }, // 60
    .{ 0x1ffa, 13 }, .{ 0x21, 6 }, .{ 0x5d, 7 }, .{ 0x5e, 7 }, // 64
    .{ 0x5f, 7 }, .{ 0x60, 7 }, .{ 0x61, 7 }, .{ 0x62, 7 }, // 68
    .{ 0x63, 7 }, .{ 0x64, 7 }, .{ 0x65, 7 }, .{ 0x66, 7 }, // 72
    .{ 0x67, 7 }, .{ 0x68, 7 }, .{ 0x69, 7 }, .{ 0x6a, 7 }, // 76
    .{ 0x6b, 7 }, .{ 0x6c, 7 }, .{ 0x6d, 7 }, .{ 0x6e, 7 }, // 80
    .{ 0x6f, 7 }, .{ 0x70, 7 }, .{ 0x71, 7 }, .{ 0x72, 7 }, // 84
    .{ 0xfc, 8 }, .{ 0x73, 7 }, .{ 0xfd, 8 }, .{ 0x1ffb, 13 }, // 88
    .{ 0x7fff0, 19 }, .{ 0x1ffc, 13 }, .{ 0x3ffc, 14 }, .{ 0x22, 6 }, // 92
    .{ 0x7ffd, 15 }, .{ 0x3, 5 }, .{ 0x23, 6 }, .{ 0x4, 5 }, // 96
    .{ 0x24, 6 }, .{ 0x5, 5 }, .{ 0x25, 6 }, .{ 0x26, 6 }, // 100
    .{ 0x27, 6 }, .{ 0x6, 5 }, .{ 0x74, 7 }, .{ 0x75, 7 }, // 104
    .{ 0x28, 6 }, .{ 0x29, 6 }, .{ 0x2a, 6 }, .{ 0x7, 5 }, // 108
    .{ 0x2b, 6 }, .{ 0x76, 7 }, .{ 0x2c, 6 }, .{ 0x8, 5 }, // 112
    .{ 0x9, 5 }, .{ 0x2d, 6 }, .{ 0x77, 7 }, .{ 0x78, 7 }, // 116
    .{ 0x79, 7 }, .{ 0x7a, 7 }, .{ 0x7b, 7 }, .{ 0x7ffe, 15 }, // 120
    .{ 0x7fc, 11 }, .{ 0x3ffd, 14 }, .{ 0x1ffd, 13 }, .{ 0xffffffc, 28 }, // 124
    .{ 0xfffe6, 20 }, .{ 0x3fffd2, 22 }, .{ 0xfffe7, 20 }, .{ 0xfffe8, 20 }, // 128
    .{ 0x3fffd3, 22 }, .{ 0x3fffd4, 22 }, .{ 0x3fffd5, 22 }, .{ 0x7fffd9, 23 }, // 132
    .{ 0x3fffd6, 22 }, .{ 0x7fffda, 23 }, .{ 0x7fffdb, 23 }, .{ 0x7fffdc, 23 }, // 136
    .{ 0x7fffdd, 23 }, .{ 0x7fffde, 23 }, .{ 0xffffeb, 24 }, .{ 0x7fffdf, 23 }, // 140
    .{ 0xffffec, 24 }, .{ 0xffffed, 24 }, .{ 0x3fffd7, 22 }, .{ 0x7fffe0, 23 }, // 144
    .{ 0xffffee, 24 }, .{ 0x7fffe1, 23 }, .{ 0x7fffe2, 23 }, .{ 0x7fffe3, 23 }, // 148
    .{ 0x7fffe4, 23 }, .{ 0x1fffdc, 21 }, .{ 0x3fffd8, 22 }, .{ 0x7fffe5, 23 }, // 152
    .{ 0x3fffd9, 22 }, .{ 0x7fffe6, 23 }, .{ 0x7fffe7, 23 }, .{ 0xffffef, 24 }, // 156
    .{ 0x3fffda, 22 }, .{ 0x1fffdd, 21 }, .{ 0xfffe9, 20 }, .{ 0x3fffdb, 22 }, // 160
    .{ 0x3fffdc, 22 }, .{ 0x7fffe8, 23 }, .{ 0x7fffe9, 23 }, .{ 0x1fffde, 21 }, // 164
    .{ 0x7fffea, 23 }, .{ 0x3fffdd, 22 }, .{ 0x3fffde, 22 }, .{ 0xfffff0, 24 }, // 168
    .{ 0x1fffdf, 21 }, .{ 0x3fffdf, 22 }, .{ 0x7fffeb, 23 }, .{ 0x7fffec, 23 }, // 172
    .{ 0x1fffe0, 21 }, .{ 0x1fffe1, 21 }, .{ 0x3fffe0, 22 }, .{ 0x1fffe2, 21 }, // 176
    .{ 0x7fffed, 23 }, .{ 0x3fffe1, 22 }, .{ 0x7fffee, 23 }, .{ 0x7fffef, 23 }, // 180
    .{ 0xfffea, 20 }, .{ 0x3fffe2, 22 }, .{ 0x3fffe3, 22 }, .{ 0x3fffe4, 22 }, // 184
    .{ 0x7ffff0, 23 }, .{ 0x3fffe5, 22 }, .{ 0x3fffe6, 22 }, .{ 0x7ffff1, 23 }, // 188
    .{ 0x3ffffe0, 26 }, .{ 0x3ffffe1, 26 }, .{ 0xfffeb, 20 }, .{ 0x7fff1, 19 }, // 192
    .{ 0x3fffe7, 22 }, .{ 0x7ffff2, 23 }, .{ 0x3fffe8, 22 }, .{ 0x1ffffec, 25 }, // 196
    .{ 0x3ffffe2, 26 }, .{ 0x3ffffe3, 26 }, .{ 0x3ffffe4, 26 }, .{ 0x7ffffde, 27 }, // 200
    .{ 0x7ffffdf, 27 }, .{ 0x3ffffe5, 26 }, .{ 0xfffff1, 24 }, .{ 0x1ffffed, 25 }, // 204
    .{ 0x7fff2, 19 }, .{ 0x1fffe3, 21 }, .{ 0x3ffffe6, 26 }, .{ 0x7ffffe0, 27 }, // 208
    .{ 0x7ffffe1, 27 }, .{ 0x3ffffe7, 26 }, .{ 0x7ffffe2, 27 }, .{ 0xfffff2, 24 }, // 212
    .{ 0x1fffe4, 21 }, .{ 0x1fffe5, 21 }, .{ 0x3ffffe8, 26 }, .{ 0x3ffffe9, 26 }, // 216
    .{ 0xffffffd, 28 }, .{ 0x7ffffe3, 27 }, .{ 0x7ffffe4, 27 }, .{ 0x7ffffe5, 27 }, // 220
    .{ 0xfffec, 20 }, .{ 0xfffff3, 24 }, .{ 0xfffed, 20 }, .{ 0x1fffe6, 21 }, // 224
    .{ 0x3fffe9, 22 }, .{ 0x1fffe7, 21 }, .{ 0x1fffe8, 21 }, .{ 0x7ffff3, 23 }, // 228
    .{ 0x3fffea, 22 }, .{ 0x3fffeb, 22 }, .{ 0x1ffffee, 25 }, .{ 0x1ffffef, 25 }, // 232
    .{ 0xfffff4, 24 }, .{ 0xfffff5, 24 }, .{ 0x3ffffea, 26 }, .{ 0x7ffff4, 23 }, // 236
    .{ 0x3ffffeb, 26 }, .{ 0x7ffffe6, 27 }, .{ 0x3ffffec, 26 }, .{ 0x3ffffed, 26 }, // 240
    .{ 0x7ffffe7, 27 }, .{ 0x7ffffe8, 27 }, .{ 0x7ffffe9, 27 }, .{ 0x7ffffea, 27 }, // 244
    .{ 0x7ffffeb, 27 }, .{ 0xffffffe, 28 }, .{ 0x7ffffec, 27 }, .{ 0x7ffffed, 27 }, // 248
    .{ 0x7ffffee, 27 }, .{ 0x7ffffef, 27 }, .{ 0x7fffff0, 27 }, .{ 0x3ffffee, 26 }, // 252
    .{ 0x3fffffff, 30 }, // 256
};

/// Canonical decoding (as in zlib's puff): the code is canonical, so the
/// number of codes of each length plus the symbols sorted by (length, symbol)
/// is all a decoder needs: 62 + 256 bytes instead of a tree or state table.
/// Derived here from the RFC's table, and checked against it.
const huffman = blk: {
    @setEvalBranchQuota(20_000);
    var count: [31]u16 = @splat(0);
    for (huffman_code) |c| count[c[1]] += 1;
    // EOS has the longest code and the largest symbol, so it sorts last and
    // `symbol` can stop at 256 entries: index 256 means EOS.
    var symbol: [256]u8 = undefined;
    var n: usize = 0;
    var code: u32 = 0;
    for (1..31) |len| {
        for (huffman_code, 0..) |c, s| {
            if (c[1] != len) continue;
            if (c[0] != code) @compileError("the HPACK Huffman code is not canonical");
            if (s < 256) symbol[n] = @intCast(s) else if (n != 256) @compileError("EOS does not sort last");
            n += 1;
            code += 1;
        }
        code <<= 1;
    }
    // complete (Kraft sum 1): every 30-bit string starts with some code
    if (code != 1 << 31) @compileError("the HPACK Huffman code is not complete");
    break :blk .{ .count = count, .symbol = symbol };
};

// ---------------------------------------------------------------- decoder

pub const Error = error{
    /// Index 0, or past the end of the static and dynamic tables.
    HpackBadIndex,
    /// Huffman padding longer than 7 bits or not all ones, or an EOS symbol.
    HpackBadHuffman,
    /// An integer of more than 28 bits: larger than anything real.
    HpackBadInteger,
    /// The block ended inside a field.
    HpackTruncated,
    /// A table size update above our limit or after the first field.
    HpackBadSizeUpdate,
    /// The source failed; it has the details.
    ReadFailed,
};

/// Decoded fields, kept in caller-owned memory. Strings of static table
/// fields are not copied. A field that does not fit is left out and counted
/// in `dropped`; the dynamic table stays correct either way.
pub const List = struct {
    buf: []u8,
    fields: []Field,
    used: usize = 0,
    len: usize = 0,
    dropped: usize = 0,

    pub fn init(buf: []u8, fields: []Field) List {
        return .{ .buf = buf, .fields = fields };
    }

    pub fn slice(l: *const List) []const Field {
        return l.fields[0..l.len];
    }

    /// Value of the first field called `name`.
    pub fn get(l: *const List, name: []const u8) ?[]const u8 {
        for (l.slice()) |f| if (std.mem.eql(u8, f.name, name)) return f.value;
        return null;
    }

    fn full(l: *const List) bool {
        return l.len == l.fields.len;
    }

    fn alloc(l: *List, n: usize) ?[]u8 {
        if (l.full() or l.buf.len - l.used < n) return null;
        defer l.used += n;
        return l.buf[l.used..][0..n];
    }

    fn append(l: *List, f: Field) void {
        l.fields[l.len] = f;
        l.len += 1;
    }

    fn out(l: *const List) Out {
        return .{ .buf = l.buf, .pos = l.used, .room = if (l.full()) 0 else l.buf.len - l.used };
    }
};

/// Where decoded string bytes go: `buf` from `pos` on, wrapping at its end
/// (the ring). Bytes past `room` are counted but not kept.
const Out = struct {
    buf: []u8,
    pos: usize,
    room: usize,
    /// bytes produced, kept or not
    n: usize = 0,

    const none: Out = .{ .buf = &.{}, .pos = 0, .room = 0 };

    fn put(o: *Out, byte: u8) void {
        if (o.n < o.room) {
            o.buf[o.pos] = byte;
            o.pos += 1;
            if (o.pos == o.buf.len) o.pos = 0;
        }
        o.n += 1;
    }

    fn kept(o: Out) bool {
        return o.n <= o.room;
    }
};

fn take(src: *Io.Reader) Error!u8 {
    return src.takeByte() catch |e| switch (e) {
        error.EndOfStream => error.HpackTruncated,
        error.ReadFailed => error.ReadFailed,
    };
}

fn readInt(src: *Io.Reader, first: u8, comptime prefix: u4) Error!u32 {
    const max = (1 << prefix) - 1;
    var v: u32 = first & max;
    if (v < max) return v;
    var shift: u5 = 0;
    while (true) : (shift += 7) {
        const b = try take(src);
        v += @as(u32, b & 0x7f) << shift;
        if (b < 0x80) return v;
        if (shift == 21) return error.HpackBadInteger;
    }
}

/// A string literal (5.2), raw or Huffman coded, into `o`.
fn readString(src: *Io.Reader, o: *Out) Error!void {
    const b = try take(src);
    const len = try readInt(src, b, 7);
    if (b & 0x80 != 0) return huffmanDecode(src, len, o);
    var left: usize = len;
    while (left > 0) {
        if (o.n >= o.room) {
            src.discardAll(left) catch |e| return switch (e) {
                error.EndOfStream => error.HpackTruncated,
                error.ReadFailed => error.ReadFailed,
            };
            o.n += left;
            return;
        }
        const chunk = @min(left, o.room - o.n, o.buf.len - o.pos);
        src.readSliceAll(o.buf[o.pos..][0..chunk]) catch |e| return switch (e) {
            error.EndOfStream => error.HpackTruncated,
            error.ReadFailed => error.ReadFailed,
        };
        o.pos += chunk;
        if (o.pos == o.buf.len) o.pos = 0;
        o.n += chunk;
        left -= chunk;
    }
}

fn huffmanDecode(src: *Io.Reader, len: usize, o: *Out) Error!void {
    // bits of the current code, the first code of its length, and the
    // position of that code in `huffman.symbol`
    var code: u32 = 0;
    var first: u32 = 0;
    var index: u32 = 0;
    var bits: u8 = 0;
    for (0..len) |_| {
        const byte = try take(src);
        var mask: u8 = 0x80;
        while (mask != 0) : (mask >>= 1) {
            code |= @intFromBool(byte & mask != 0);
            bits += 1;
            const count = huffman.count[bits];
            if (code < first + count) {
                const i = index + code - first;
                if (i == 256) return error.HpackBadHuffman; // EOS
                o.put(huffman.symbol[i]);
                code = 0;
                first = 0;
                index = 0;
                bits = 0;
            } else {
                index += count;
                first = (first + count) << 1;
                code <<= 1;
            }
        }
    }
    // the code was shifted once more after its last bit
    if (bits > 7 or code >> 1 != (@as(u32, 1) << @intCast(bits)) - 1) return error.HpackBadHuffman;
}

/// The decoding context of one connection. `capacity` is the
/// SETTINGS_HEADER_TABLE_SIZE we announce (4096 when we announce none).
pub fn Decoder(comptime capacity: u16) type {
    comptime std.debug.assert(capacity >= 32);
    return struct {
        const Self = @This();
        const max_entries = capacity / 32;

        /// Entry bytes, name then value, oldest first from the oldest
        /// entry's `start` up to `head`, wrapping around.
        ring: [capacity]u8 = undefined,
        entries: [max_entries]Entry = undefined,
        oldest: u16 = 0,
        count: u16 = 0,
        head: u16 = 0,
        /// 4.1: name + value + 32 summed over the entries
        size: u32 = 0,
        /// current maximum size, moved by size updates (6.3)
        limit: u32 = capacity,

        const Entry = struct { start: u16, name_len: u16, value_len: u16 };

        /// Decode one header block, read from `src` until it ends, and
        /// append its fields to `list`. An error leaves the context unusable
        /// (RFC 9113: a connection error).
        pub fn decode(d: *Self, src: *Io.Reader, list: *List) Error!void {
            var any_field = false;
            while (true) {
                const b = src.takeByte() catch |e| switch (e) {
                    error.EndOfStream => return,
                    error.ReadFailed => return error.ReadFailed,
                };
                if (b >= 0x80) {
                    try d.indexed(try readInt(src, b, 7), list);
                } else if (b >= 0x40) {
                    try d.literalAdd(src, try readInt(src, b, 6), list);
                } else if (b >= 0x20) {
                    // 4.2: only at the start of a block, and within what we allow
                    const n = try readInt(src, b, 5);
                    if (any_field or n > capacity) return error.HpackBadSizeUpdate;
                    d.limit = n;
                    while (d.size > n) d.evict();
                    continue;
                } else {
                    // without indexing (0000) and never indexed (0001) decode alike
                    try d.literal(src, try readInt(src, b, 4), list);
                }
                any_field = true;
            }
        }

        fn entry(d: *const Self, index: u32) Error!Entry {
            // dynamic index 1 is the newest entry
            const i = index - static_table.len;
            if (i > d.count) return error.HpackBadIndex;
            return d.entries[(d.oldest + d.count - i) % max_entries];
        }

        fn evict(d: *Self) void {
            const e = d.entries[d.oldest];
            d.size -= @as(u32, e.name_len) + e.value_len + 32;
            d.oldest = (d.oldest + 1) % max_entries;
            d.count -= 1;
        }

        fn ringCopy(d: *const Self, start: usize, dst: []u8) void {
            const first = @min(dst.len, capacity - start);
            @memcpy(dst[0..first], d.ring[start..][0..first]);
            @memcpy(dst[first..], d.ring[0 .. dst.len - first]);
        }

        fn indexed(d: *Self, index: u32, list: *List) Error!void {
            if (index == 0) return error.HpackBadIndex;
            if (index <= static_table.len) {
                if (list.full()) list.dropped += 1 else list.append(static_table[index - 1]);
                return;
            }
            const e = try d.entry(index);
            // name and value sit next to each other in the ring: one copy
            const b = list.alloc(@as(usize, e.name_len) + e.value_len) orelse {
                list.dropped += 1;
                return;
            };
            d.ringCopy(e.start, b);
            list.append(.{ .name = b[0..e.name_len], .value = b[e.name_len..] });
        }

        /// 6.2.2 and 6.2.3: name and value go straight to the list.
        fn literal(d: *Self, src: *Io.Reader, name_index: u32, list: *List) Error!void {
            const mark = list.used;
            var keep = !list.full();
            var name: []const u8 = "";
            if (name_index > static_table.len) {
                const e = try d.entry(name_index);
                if (list.alloc(e.name_len)) |b| {
                    d.ringCopy(e.start, b);
                    name = b;
                } else keep = false;
            } else if (name_index > 0) {
                name = static_table[name_index - 1].name;
            } else {
                var no = list.out();
                try readString(src, &no);
                if (no.kept()) {
                    name = list.buf[list.used..][0..no.n];
                    list.used += no.n;
                } else keep = false;
            }
            var o = if (keep) list.out() else Out.none;
            try readString(src, &o);
            if (keep and o.kept()) {
                list.append(.{ .name = name, .value = list.buf[list.used..][0..o.n] });
                list.used += o.n;
            } else {
                list.used = mark;
                list.dropped += 1;
            }
        }

        /// 6.2.1: the field becomes the newest table entry. It is decoded
        /// right after the newest entry's bytes, over the oldest ones when
        /// the free part of the ring is too short. That is safe: if the new
        /// entry fits the limit, the bytes it covers belong to entries that
        /// its insertion evicts (4.4), and if it does not, all are evicted.
        /// A dynamic name is copied before anything else is written, front
        /// to back, and the copy only ever lands on bytes already read.
        fn literalAdd(d: *Self, src: *Io.Reader, name_index: u32, list: *List) Error!void {
            const start = d.head;
            var o: Out = .{ .buf = &d.ring, .pos = start, .room = capacity };
            var static_name: ?[]const u8 = null;
            if (name_index > static_table.len) {
                const e = try d.entry(name_index);
                var p: usize = e.start;
                for (0..e.name_len) |_| {
                    o.put(d.ring[p]);
                    p += 1;
                    if (p == capacity) p = 0;
                }
            } else if (name_index > 0) {
                static_name = static_table[name_index - 1].name;
                for (static_name.?) |c| o.put(c);
            } else {
                try readString(src, &o);
            }
            const name_len = o.n;
            try readString(src, &o);
            const len = o.n;

            if (len + 32 > d.limit) {
                // 4.4: an entry larger than the table empties it
                d.count = 0;
                d.size = 0;
            } else {
                while (d.size + len + 32 > d.limit) d.evict();
                d.entries[(d.oldest + d.count) % max_entries] = .{
                    .start = start,
                    .name_len = @intCast(name_len),
                    .value_len = @intCast(len - name_len),
                };
                d.count += 1;
                d.size += @intCast(len + 32);
                d.head = @intCast((start + len) % capacity);
            }

            // the bytes are whole in the ring unless they outgrew it
            if (len > capacity or list.full()) {
                list.dropped += 1;
                return;
            }
            const keep = if (static_name != null) len - name_len else len;
            const b = list.alloc(keep) orelse {
                list.dropped += 1;
                return;
            };
            d.ringCopy((start + len - keep) % capacity, b);
            list.append(if (static_name) |n|
                .{ .name = n, .value = b }
            else
                .{ .name = b[0..name_len], .value = b[name_len..] });
        }

        /// Entry `i` of the dynamic table (1 is the newest), copied into
        /// `buf`; for tests and diagnostics.
        pub fn tableEntry(d: *const Self, i: usize, buf: []u8) ?Field {
            if (i == 0 or i > d.count) return null;
            const e = d.entries[(d.oldest + d.count - i) % max_entries];
            const b = buf[0 .. @as(usize, e.name_len) + e.value_len];
            d.ringCopy(e.start, b);
            return .{ .name = b[0..e.name_len], .value = b[e.name_len..] };
        }
    };
}

// ---------------------------------------------------------------- tests

const Example = struct {
    id: []const u8,
    wire: []const u8,
    fields: []const Field,
    table: []const Field,
    table_size: u32,
};

// Generated from the RFC 7541 text (Appendix C.2-C.6) by a script; do not edit by hand.
const rfc_examples = [_]Example{
    .{
        .id = "C.2.1",
        .wire = "400a637573746f6d2d6b65790d637573746f6d2d686561646572",
        .fields = &.{
            .{ .name = "custom-key", .value = "custom-header" },
        },
        .table = &.{
            .{ .name = "custom-key", .value = "custom-header" },
        },
        .table_size = 55,
    },
    .{
        .id = "C.2.2",
        .wire = "040c2f73616d706c652f70617468",
        .fields = &.{
            .{ .name = ":path", .value = "/sample/path" },
        },
        .table = &.{},
        .table_size = 0,
    },
    .{
        .id = "C.2.3",
        .wire = "100870617373776f726406736563726574",
        .fields = &.{
            .{ .name = "password", .value = "secret" },
        },
        .table = &.{},
        .table_size = 0,
    },
    .{
        .id = "C.2.4",
        .wire = "82",
        .fields = &.{
            .{ .name = ":method", .value = "GET" },
        },
        .table = &.{},
        .table_size = 0,
    },
    .{
        .id = "C.3.1",
        .wire = "828684410f7777772e6578616d706c652e636f6d",
        .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "www.example.com" },
        },
        .table = &.{
            .{ .name = ":authority", .value = "www.example.com" },
        },
        .table_size = 57,
    },
    .{
        .id = "C.3.2",
        .wire = "828684be58086e6f2d6361636865",
        .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "www.example.com" },
            .{ .name = "cache-control", .value = "no-cache" },
        },
        .table = &.{
            .{ .name = "cache-control", .value = "no-cache" },
            .{ .name = ":authority", .value = "www.example.com" },
        },
        .table_size = 110,
    },
    .{
        .id = "C.3.3",
        .wire = "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
        .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/index.html" },
            .{ .name = ":authority", .value = "www.example.com" },
            .{ .name = "custom-key", .value = "custom-value" },
        },
        .table = &.{
            .{ .name = "custom-key", .value = "custom-value" },
            .{ .name = "cache-control", .value = "no-cache" },
            .{ .name = ":authority", .value = "www.example.com" },
        },
        .table_size = 164,
    },
    .{
        .id = "C.4.1",
        .wire = "828684418cf1e3c2e5f23a6ba0ab90f4ff",
        .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "www.example.com" },
        },
        .table = &.{
            .{ .name = ":authority", .value = "www.example.com" },
        },
        .table_size = 57,
    },
    .{
        .id = "C.4.2",
        .wire = "828684be5886a8eb10649cbf",
        .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "www.example.com" },
            .{ .name = "cache-control", .value = "no-cache" },
        },
        .table = &.{
            .{ .name = "cache-control", .value = "no-cache" },
            .{ .name = ":authority", .value = "www.example.com" },
        },
        .table_size = 110,
    },
    .{
        .id = "C.4.3",
        .wire = "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
        .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/index.html" },
            .{ .name = ":authority", .value = "www.example.com" },
            .{ .name = "custom-key", .value = "custom-value" },
        },
        .table = &.{
            .{ .name = "custom-key", .value = "custom-value" },
            .{ .name = "cache-control", .value = "no-cache" },
            .{ .name = ":authority", .value = "www.example.com" },
        },
        .table_size = 164,
    },
    .{
        .id = "C.5.1",
        .wire = "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
        .fields = &.{
            .{ .name = ":status", .value = "302" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .name = "location", .value = "https://www.example.com" },
        },
        .table = &.{
            .{ .name = "location", .value = "https://www.example.com" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = ":status", .value = "302" },
        },
        .table_size = 222,
    },
    .{
        .id = "C.5.2",
        .wire = "4803333037c1c0bf",
        .fields = &.{
            .{ .name = ":status", .value = "307" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .name = "location", .value = "https://www.example.com" },
        },
        .table = &.{
            .{ .name = ":status", .value = "307" },
            .{ .name = "location", .value = "https://www.example.com" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .name = "cache-control", .value = "private" },
        },
        .table_size = 222,
    },
    .{
        .id = "C.5.3",
        .wire = "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
            .{ .name = "location", .value = "https://www.example.com" },
            .{ .name = "content-encoding", .value = "gzip" },
            .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
        },
        .table = &.{
            .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
            .{ .name = "content-encoding", .value = "gzip" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
        },
        .table_size = 215,
    },
    .{
        .id = "C.6.1",
        .wire = "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
        .fields = &.{
            .{ .name = ":status", .value = "302" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .name = "location", .value = "https://www.example.com" },
        },
        .table = &.{
            .{ .name = "location", .value = "https://www.example.com" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = ":status", .value = "302" },
        },
        .table_size = 222,
    },
    .{
        .id = "C.6.2",
        .wire = "4883640effc1c0bf",
        .fields = &.{
            .{ .name = ":status", .value = "307" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .name = "location", .value = "https://www.example.com" },
        },
        .table = &.{
            .{ .name = ":status", .value = "307" },
            .{ .name = "location", .value = "https://www.example.com" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .name = "cache-control", .value = "private" },
        },
        .table_size = 222,
    },
    .{
        .id = "C.6.3",
        .wire = "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
            .{ .name = "location", .value = "https://www.example.com" },
            .{ .name = "content-encoding", .value = "gzip" },
            .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
        },
        .table = &.{
            .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
            .{ .name = "content-encoding", .value = "gzip" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
        },
        .table_size = 215,
    },
};

fn rep(comptime s: []const u8, comptime n: usize) []const u8 {
    return comptime blk: {
        var out: []const u8 = "";
        for (0..n) |_| out = out ++ s;
        break :blk out;
    };
}

fn unhex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn expectDecoded(d: anytype, comptime e: Example) !void {
    const wire = comptime unhex(e.wire);
    var src: Io.Reader = .fixed(&wire);
    var buf: [512]u8 = undefined;
    var fields: [16]Field = undefined;
    var list: List = .init(&buf, &fields);
    try d.decode(&src, &list);
    try std.testing.expectEqual(e.fields.len, list.len);
    try std.testing.expectEqual(0, list.dropped);
    for (e.fields, list.slice()) |want, got| {
        try std.testing.expectEqualStrings(want.name, got.name);
        try std.testing.expectEqualStrings(want.value, got.value);
    }
    try std.testing.expectEqual(e.table_size, d.size);
    try std.testing.expectEqual(e.table.len, d.count);
    var tb: [256]u8 = undefined;
    for (e.table, 1..) |want, i| {
        const got = d.tableEntry(i, &tb).?;
        try std.testing.expectEqualStrings(want.name, got.name);
        try std.testing.expectEqualStrings(want.value, got.value);
    }
}

test "RFC 7541 C.2: field representations" {
    inline for (rfc_examples[0..4]) |e| {
        var d: Decoder(4096) = .{};
        try expectDecoded(&d, e);
    }
}

test "RFC 7541 C.3 and C.4: requests, one context each, raw and Huffman" {
    inline for (.{ rfc_examples[4..7], rfc_examples[7..10] }) |run| {
        var d: Decoder(4096) = .{};
        inline for (run) |e| try expectDecoded(&d, e);
    }
}

test "RFC 7541 C.5 and C.6: responses with a 256-byte table, evictions" {
    inline for (.{ rfc_examples[10..13], rfc_examples[13..16] }) |run| {
        var d: Decoder(256) = .{};
        inline for (run) |e| try expectDecoded(&d, e);
    }
}

test "RFC 7541 C.1: integers" {
    var buf: [8]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeInt(&w, 0, 5, 10);
    try writeInt(&w, 0, 5, 1337);
    try writeInt(&w, 0, 8, 42);
    try std.testing.expectEqualSlices(u8, &.{ 10, 31, 154, 10, 42 }, w.buffered());
    try std.testing.expectEqual(3, intLen(5, 1337));
    var r: Io.Reader = .fixed(w.buffered()[1..]);
    try std.testing.expectEqual(1337, try readInt(&r, try r.takeByte(), 5));
}

test "encoder: C.2.2 byte for byte, and a request round trip" {
    var buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    const f: Field = .{ .name = ":path", .value = "/sample/path" };
    try writeField(&w, f);
    try std.testing.expectEqualSlices(u8, &unhex(rfc_examples[1].wire), w.buffered());
    try std.testing.expectEqual(w.end, fieldLen(f));

    const req = [_]Field{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" ++ comptime rep("x", 200) },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "x-custom", .value = "" },
    };
    w = .fixed(&buf);
    var total: usize = 0;
    for (req) |q| {
        try writeField(&w, q);
        total += fieldLen(q);
    }
    try std.testing.expectEqual(total, w.end);
    var src: Io.Reader = .fixed(w.buffered());
    var sbuf: [512]u8 = undefined;
    var fields: [8]Field = undefined;
    var list: List = .init(&sbuf, &fields);
    var d: Decoder(4096) = .{};
    try d.decode(&src, &list);
    try std.testing.expectEqual(req.len, list.len);
    for (req, list.slice()) |want, got| {
        try std.testing.expectEqualStrings(want.name, got.name);
        try std.testing.expectEqualStrings(want.value, got.value);
    }
    try std.testing.expectEqual(0, d.count);
}

fn decodeErr(comptime wire: []const u8) Error!void {
    const bytes = comptime unhex(wire);
    var src: Io.Reader = .fixed(&bytes);
    var buf: [64]u8 = undefined;
    var fields: [4]Field = undefined;
    var list: List = .init(&buf, &fields);
    var d: Decoder(4096) = .{};
    return d.decode(&src, &list);
}

test "decoder rejects malformed blocks" {
    const t = std.testing;
    try t.expectError(error.HpackBadIndex, decodeErr("80")); // index 0
    try t.expectError(error.HpackBadIndex, decodeErr("be")); // 62, table empty
    try t.expectError(error.HpackBadIndex, decodeErr("7e0161")); // literal with name 62
    try t.expectError(error.HpackBadInteger, decodeErr("ffffffffff7f"));
    try t.expectError(error.HpackTruncated, decodeErr("400a6375")); // name cut short
    try t.expectError(error.HpackTruncated, decodeErr("ff")); // integer cut short
    try t.expectError(error.HpackBadSizeUpdate, decodeErr("3fe21f")); // 4097 > 4096
    try t.expectError(error.HpackBadSizeUpdate, decodeErr("8220")); // after a field
    try decodeErr("203fe11f82"); // 0 then 4096, then a field: fine
    // Huffman: "www.example.com" from C.4.1 with its 1-bit padding turned to 0
    try decodeErr("0f018cf1e3c2e5f23a6ba0ab90f4ff");
    try t.expectError(error.HpackBadHuffman, decodeErr("0f018cf1e3c2e5f23a6ba0ab90f4fe"));
    // a whole padding byte (8 bits) after the same string
    try t.expectError(error.HpackBadHuffman, decodeErr("0f018df1e3c2e5f23a6ba0ab90f4ffff"));
    // EOS: 30 ones, padded with two more
    try t.expectError(error.HpackBadHuffman, decodeErr("0f0184ffffffff"));
}

test "a field too large for the list is dropped, the table stays in sync" {
    // C.5.1 into a list with room for two fields: the table must still hold
    // all four entries, and C.5.2 (which refers to them) must still decode
    var d: Decoder(256) = .{};
    const w1 = comptime unhex(rfc_examples[10].wire);
    var src: Io.Reader = .fixed(&w1);
    var buf: [64]u8 = undefined;
    var fields: [2]Field = undefined;
    var list: List = .init(&buf, &fields);
    try d.decode(&src, &list);
    try std.testing.expectEqual(2, list.len);
    try std.testing.expectEqual(2, list.dropped);
    try std.testing.expectEqualStrings("302", list.get(":status").?);
    try std.testing.expectEqual(222, d.size);
    try expectDecoded(&d, rfc_examples[11]);
}

test "an entry larger than the table empties it but still reaches the list" {
    var d: Decoder(64) = .{};
    // "a: b" (34) enters, then a 40-byte value (size 73 > 64) empties the table
    const wire = comptime unhex("4001610162" ++ "40016128" ++ rep("78", 40));
    var src: Io.Reader = .fixed(&wire);
    var buf: [128]u8 = undefined;
    var fields: [4]Field = undefined;
    var list: List = .init(&buf, &fields);
    try d.decode(&src, &list);
    try std.testing.expectEqual(2, list.len);
    try std.testing.expectEqualStrings(comptime rep("x", 40), list.slice()[1].value);
    try std.testing.expectEqual(0, d.count);
    try std.testing.expectEqual(0, d.size);
}

test "ring wrap-around and a dynamic name that is evicted by its own entry" {
    // 64-byte table: one entry of 32 + 30 fills it; each new entry that
    // reuses the name (index 62) evicts the one it names
    var d: Decoder(64) = .{};
    var r: [64]u8 = undefined;
    var w: Io.Writer = .fixed(&r);
    var i: u8 = 0;
    while (i < 5) : (i += 1) {
        w = .fixed(&r);
        if (i == 0) {
            try w.writeAll(&.{ 0x40, 0x0e });
            try w.writeAll("name-of-length");
        } else try w.writeByte(0x7e); // literal, name from index 62
        try w.writeByte(16);
        try w.splatByteAll('a' + i, 16);
        var src: Io.Reader = .fixed(w.buffered());
        var buf: [64]u8 = undefined;
        var fields: [2]Field = undefined;
        var list: List = .init(&buf, &fields);
        try d.decode(&src, &list);
        try std.testing.expectEqualStrings("name-of-length", list.slice()[0].name);
        const value: [16]u8 = @splat('a' + i);
        try std.testing.expectEqualStrings(&value, list.slice()[0].value);
        try std.testing.expectEqual(1, d.count);
        var tb: [64]u8 = undefined;
        const e = d.tableEntry(1, &tb).?;
        try std.testing.expectEqualStrings("name-of-length", e.name);
        try std.testing.expectEqualStrings(&value, e.value);
    }
}

/// Huffman-code `s` (5.2), for tests: the encoder never uses it.
fn huffmanEncode(w: *Io.Writer, s: []const u8) !void {
    var acc: u64 = 0;
    var bits: u6 = 0;
    for (s) |ch| {
        const c = huffman_code[ch];
        acc = (acc << @intCast(c[1])) | c[0];
        bits += @intCast(c[1]);
        while (bits >= 8) {
            bits -= 8;
            try w.writeByte(@truncate(acc >> bits));
        }
        acc &= (@as(u64, 1) << bits) - 1;
    }
    // pad with the most significant bits of EOS: ones
    if (bits > 0) try w.writeByte(@truncate((acc << @intCast(8 - bits)) | ((@as(u64, 1) << @intCast(8 - bits)) - 1)));
}

test "Huffman: every symbol, codes of every length, round trip" {
    var value: [512]u8 = undefined;
    for (value[0..256], 0..) |*b, i| b.* = @intCast(i);
    for (value[256..], 0..) |*b, i| b.* = @intCast(255 - i);
    var enc: [2048]u8 = undefined;
    var ew: Io.Writer = .fixed(&enc);
    try huffmanEncode(&ew, &value);
    var wire: [2100]u8 = undefined;
    var w: Io.Writer = .fixed(&wire);
    try w.writeAll(&.{ 0x00, 0x01, 'x' }); // literal, new name "x"
    try writeInt(&w, 0x80, 7, ew.end); // Huffman value
    try w.writeAll(ew.buffered());
    var src: Io.Reader = .fixed(w.buffered());
    var buf: [600]u8 = undefined;
    var fields: [2]Field = undefined;
    var list: List = .init(&buf, &fields);
    var d: Decoder(4096) = .{};
    try d.decode(&src, &list);
    try std.testing.expectEqualSlices(u8, &value, list.slice()[0].value);
}

test "size updates evict, 0 empties the table, raising it again works" {
    var d: Decoder(4096) = .{};
    try expectDecoded(&d, rfc_examples[4]); // C.3.1: :authority (57)
    try expectDecoded(&d, rfc_examples[5]); // C.3.2: + cache-control (53)
    var buf: [64]u8 = undefined;
    var fields: [4]Field = undefined;
    var list: List = .init(&buf, &fields);
    // limit 60 keeps only the newest entry, which index 62 still finds
    const w60 = comptime unhex("3f1d" ++ "be");
    var src: Io.Reader = .fixed(&w60);
    try d.decode(&src, &list);
    try std.testing.expectEqual(1, d.count);
    try std.testing.expectEqual(53, d.size);
    try std.testing.expectEqualStrings("no-cache", list.slice()[0].value);
    const w63 = comptime unhex("bf");
    src = .fixed(&w63);
    try std.testing.expectError(error.HpackBadIndex, d.decode(&src, &list));
    // at 0 nothing enters
    const zero = comptime unhex("20" ++ "4001610162");
    src = .fixed(&zero);
    try d.decode(&src, &list);
    try std.testing.expectEqual(0, d.count);
    try std.testing.expectEqual(0, d.limit);
    const back = comptime unhex("3fe11f" ++ "4001610162");
    src = .fixed(&back);
    try d.decode(&src, &list);
    try std.testing.expectEqual(1, d.count);
    try std.testing.expectEqual(34, d.size);
}
