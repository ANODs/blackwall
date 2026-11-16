//! The name a connection is for, from its first bytes: the server name
//! (SNI) of a TLS ClientHello, or the Host of an HTTP request. For flows
//! to a real address, where no fake DNS answer named the site.

const std = @import("std");

pub const Found = struct {
    name: []const u8,
    /// where the name starts in the data (for splitting a ClientHello at it)
    offset: usize,
};

pub const Kind = enum {
    /// not enough bytes yet to tell
    incomplete,
    /// a TLS ClientHello record (`need` bytes in all)
    tls,
    /// an HTTP/1 request
    http,
    other,
};

/// What the data starts with, and how many bytes it takes to read the
/// name (for TLS: the whole first record).
pub fn kind(data: []const u8) struct { Kind, usize } {
    if (data.len == 0) return .{ .incomplete, 1 };
    if (data[0] == 0x16) {
        if (data.len < 5) return .{ .incomplete, 5 };
        if (data[1] != 3) return .{ .other, 0 };
        const len = std.mem.readInt(u16, data[3..5], .big);
        return .{ .tls, 5 + @as(usize, len) };
    }
    const methods = [_][]const u8{ "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT " };
    for (methods) |m| {
        const n = @min(m.len, data.len);
        if (std.mem.eql(u8, data[0..n], m[0..n])) return if (n < m.len) .{ .incomplete, m.len } else .{ .http, 0 };
    }
    return .{ .other, 0 };
}

/// The server name of the ClientHello at the start of `data` (one TLS
/// record), or null.
pub fn serverName(data: []const u8) ?Found {
    if (data.len < 5 + 4 or data[0] != 0x16) return null;
    const rec_len = std.mem.readInt(u16, data[3..5], .big);
    const rec = data[5..@min(data.len, 5 + @as(usize, rec_len))];
    if (rec.len < 4 or rec[0] != 1) return null; // ClientHello
    var p = Parser{ .d = rec, .i = 4 };
    p.skip(2 + 32) orelse return null; // version, random
    p.skip(p.byte() orelse return null) orelse return null; // session id
    p.skip(p.int16() orelse return null) orelse return null; // cipher suites
    p.skip(p.byte() orelse return null) orelse return null; // compression
    const ext_len = p.int16() orelse return null;
    const end = @min(rec.len, p.i + ext_len);
    while (p.i + 4 <= end) {
        const kind_ = p.int16().?;
        const len = p.int16().?;
        if (p.i + len > end) return null;
        if (kind_ == 0) { // server_name
            var q = Parser{ .d = rec[0 .. p.i + len], .i = p.i };
            _ = q.int16() orelse return null; // list length
            while (q.i + 3 <= q.d.len) {
                const name_type = q.byte().?;
                const n = q.int16().?;
                if (q.i + n > q.d.len) return null;
                if (name_type == 0) {
                    const name = rec[q.i..][0..n];
                    if (!plausible(name)) return null;
                    return .{ .name = name, .offset = 5 + q.i };
                }
                q.i += n;
            }
            return null;
        }
        p.i += len;
    }
    return null;
}

/// The Host of an HTTP/1 request, without a port, or null.
pub fn httpHost(data: []const u8) ?Found {
    var lines = std.mem.splitSequence(u8, data, "\r\n");
    _ = lines.next() orelse return null; // the request line
    while (lines.next()) |line| {
        if (line.len == 0) return null;
        if (line.len > 5 and std.ascii.eqlIgnoreCase(line[0..5], "host:")) {
            var v = std.mem.trim(u8, line[5..], " \t");
            if (std.mem.lastIndexOfScalar(u8, v, ':')) |c| {
                if (std.mem.indexOfScalar(u8, v, ']') == null) v = v[0..c];
            }
            if (!plausible(v)) return null;
            const offset = @intFromPtr(v.ptr) - @intFromPtr(data.ptr);
            return .{ .name = v, .offset = offset };
        }
    }
    return null;
}

/// The name of either kind.
pub fn find(data: []const u8) ?Found {
    return switch (kind(data)[0]) {
        .tls => serverName(data),
        .http => httpHost(data),
        else => null,
    };
}

fn plausible(name: []const u8) bool {
    if (name.len == 0 or name.len > 253) return false;
    for (name) |c| if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '-' or c == '_')) return false;
    return true;
}

const Parser = struct {
    d: []const u8,
    i: usize,

    fn byte(p: *Parser) ?u8 {
        if (p.i + 1 > p.d.len) return null;
        defer p.i += 1;
        return p.d[p.i];
    }
    fn int16(p: *Parser) ?u16 {
        if (p.i + 2 > p.d.len) return null;
        defer p.i += 2;
        return std.mem.readInt(u16, p.d[p.i..][0..2], .big);
    }
    fn skip(p: *Parser, n: usize) ?void {
        if (p.i + n > p.d.len) return null;
        p.i += n;
    }
};

/// A ClientHello for the tests: some extensions, then server_name.
pub fn testHello(buf: []u8, name: []const u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.writeAll(&.{ 0x16, 3, 1, 0, 0 }) catch unreachable; // record, length later
    w.writeAll(&.{ 1, 0, 0, 0 }) catch unreachable; // ClientHello, length later
    w.writeAll(&.{ 3, 3 }) catch unreachable;
    w.splatByteAll(0xaa, 32) catch unreachable;
    w.writeAll(&.{32}) catch unreachable;
    w.splatByteAll(0xbb, 32) catch unreachable;
    w.writeAll(&.{ 0, 4, 0x13, 1, 0x13, 2, 1, 0 }) catch unreachable;
    const ext_at = w.end;
    w.writeAll(&.{ 0, 0 }) catch unreachable;
    // supported_versions, then server_name
    w.writeAll(&.{ 0, 43, 0, 3, 2, 3, 4 }) catch unreachable;
    w.writeInt(u16, 0, .big) catch unreachable;
    w.writeInt(u16, @intCast(name.len + 5), .big) catch unreachable;
    w.writeInt(u16, @intCast(name.len + 3), .big) catch unreachable;
    w.writeByte(0) catch unreachable;
    w.writeInt(u16, @intCast(name.len), .big) catch unreachable;
    w.writeAll(name) catch unreachable;
    const out = buf[0..w.end];
    std.mem.writeInt(u16, out[ext_at..][0..2], @intCast(out.len - ext_at - 2), .big);
    std.mem.writeInt(u16, out[3..5], @intCast(out.len - 5), .big);
    std.mem.writeInt(u24, out[6..9], @intCast(out.len - 9), .big);
    return out;
}

test "the server name of a ClientHello, and where it is" {
    var buf: [512]u8 = undefined;
    const hello = testHello(&buf, "www.example.com");
    try std.testing.expectEqual(Kind.tls, kind(hello)[0]);
    try std.testing.expectEqual(hello.len, kind(hello)[1]);
    const f = serverName(hello).?;
    try std.testing.expectEqualStrings("www.example.com", f.name);
    try std.testing.expectEqualStrings("www.example.com", hello[f.offset..][0..f.name.len]);
    // cut short: not read past what is there
    try std.testing.expect(serverName(hello[0 .. hello.len - 4]) == null);
    try std.testing.expectEqual(Kind.incomplete, kind(hello[0..3])[0]);
    // no TLS at all
    try std.testing.expect(serverName("\x16\x03\x01\x00\x01\x02") == null);
}

test "the Host of an HTTP request" {
    const req = "GET / HTTP/1.1\r\nUser-Agent: x\r\nHOST: Example.org:8080\r\n\r\n";
    try std.testing.expectEqual(Kind.http, kind(req)[0]);
    const f = find(req).?;
    try std.testing.expectEqualStrings("Example.org", f.name);
    try std.testing.expectEqual(Kind.incomplete, kind("GE")[0]);
    try std.testing.expectEqual(Kind.other, kind("SSH-2.0-OpenSSH")[0]);
    try std.testing.expect(find("GET / HTTP/1.1\r\n\r\nHost: late.example\r\n") == null);
}
