//! A report to attach to a GitHub issue: what the app and its service
//! logged, without what could point at the user, their servers or the
//! sites they visit.
//!
//!   links (vless://, https://, ...)   scheme://<hidden>
//!   UUIDs, e-mail addresses           <uuid>, <email>
//!   host names                        <host:3fa2c1>.ru
//!   public IPv4 / IPv6 addresses      <ip:9b01e4>  (private and fake ones stay)
//!   keys (base64, long hex)           <key>, <hex>
//!   the user's name in paths          /Users/<user>/...
//!
//! A name becomes the same token everywhere in one report, so its lines can
//! still be followed; the key is random per report and not in it, so a
//! token cannot be traced back by hashing guesses.

const std = @import("std");
const builtin = @import("builtin");

// ---------------------------------------------------------------- scrubbing

pub const Scrub = struct {
    key: u64,

    pub fn init(io: std.Io) Scrub {
        var b: [8]u8 = undefined;
        io.random(&b);
        return .{ .key = std.mem.readInt(u64, &b, .little) };
    }

    pub fn write(s: Scrub, w: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
        var i: usize = 0;
        while (i < text.len) {
            if (s.match(w, text, i)) |n| {
                i += n;
                continue;
            }
            // the rest of a word that matched nothing as a whole
            var j = i + 1;
            if (isWord(text[i])) while (j < text.len and isWord(text[j])) : (j += 1) {};
            try w.writeAll(text[i..j]);
            i = j;
        }
    }

    /// What starts at `i` and is replaced: its length, after writing the
    /// replacement. Null when nothing does.
    fn match(s: Scrub, w: *std.Io.Writer, t: []const u8, i: usize) ?usize {
        if (userPath(t, i)) |m| {
            w.writeAll(t[i..][0..m.prefix]) catch return null;
            w.writeAll("<user>") catch return null;
            return m.len;
        }
        if (i > 0 and (isWord(t[i - 1]) or t[i - 1] == '.')) return null;
        if (link(t, i)) |m| {
            w.print("{s}://<hidden>", .{t[i..][0..m.scheme]}) catch return null;
            return m.len;
        }
        if (email(t, i)) |n| {
            w.writeAll("<email>") catch return null;
            return n;
        }
        if (uuid(t, i)) |n| {
            w.writeAll("<uuid>") catch return null;
            return n;
        }
        if (ipv4(t, i)) |m| {
            if (m.private) return null;
            w.print("<ip:{x:0>6}>", .{s.token(t[i..][0..m.len])}) catch return null;
            return m.len;
        }
        if (ipv6(t, i)) |n| {
            w.print("<ip:{x:0>6}>", .{s.token(t[i..][0..n])}) catch return null;
            return n;
        }
        if (host(t, i)) |m| {
            const name = t[i..][0..m.len];
            if (keptHost(name)) return null;
            w.print("<host:{x:0>6}>{s}", .{ s.token(name), name[m.tld..] }) catch return null;
            return m.len;
        }
        if (secret(t, i)) |m| {
            w.writeAll(if (m.hex) "<hex>" else "<key>") catch return null;
            return m.len;
        }
        return null;
    }

    fn token(s: Scrub, name: []const u8) u24 {
        var h = std.hash.Wyhash.init(s.key);
        for (name) |c| h.update(&.{std.ascii.toLower(c)});
        return @truncate(h.final());
    }
};

/// A byte that continues a word: letters, digits, '_', '-', and any byte of
/// a non-ASCII character.
fn isWord(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c >= 0x80;
}

fn isDelim(c: u8) bool {
    return std.ascii.isWhitespace(c) or switch (c) {
        '"', '\'', '`', '<', '>', ',', ';', '(', ')', '[', ']', '{', '}', '|' => true,
        else => false,
    };
}

const UserPath = struct { prefix: usize, len: usize };

/// "/Users/name", "/home/name", "\Users\name" (any case): the name.
fn userPath(t: []const u8, i: usize) ?UserPath {
    for ([_][]const u8{ "/Users/", "/home/", "\\Users\\", "/data/user/" }) |p| {
        if (!std.ascii.startsWithIgnoreCase(t[i..], p)) continue;
        // Windows names may have spaces
        const windows = p[0] == '\\';
        var j = i + p.len;
        while (j < t.len and t[j] != '/' and t[j] != '\\' and t[j] != '\n' and t[j] != '"' and (windows or !isDelim(t[j]))) j += 1;
        if (j == i + p.len) return null;
        return .{ .prefix = p.len, .len = j - i };
    }
    return null;
}

const Link = struct { scheme: usize, len: usize };

/// scheme://anything up to a space or a quote
fn link(t: []const u8, i: usize) ?Link {
    var j = i;
    if (j >= t.len or !std.ascii.isAlphabetic(t[j])) return null;
    while (j < t.len and (std.ascii.isAlphanumeric(t[j]) or t[j] == '+' or t[j] == '.' or t[j] == '-')) j += 1;
    const scheme = j - i;
    if (scheme > 16 or !std.mem.startsWith(u8, t[j..], "://")) return null;
    j += 3;
    while (j < t.len and !std.ascii.isWhitespace(t[j]) and !isDelim(t[j])) j += 1;
    // punctuation of the sentence around it
    while (j > i + scheme + 3 and std.mem.indexOfScalar(u8, ".,:;!?", t[j - 1]) != null) j -= 1;
    return .{ .scheme = scheme, .len = j - i };
}

fn email(t: []const u8, i: usize) ?usize {
    var j = i;
    while (j < t.len and (std.ascii.isAlphanumeric(t[j]) or std.mem.indexOfScalar(u8, "._%+-", t[j]) != null)) j += 1;
    if (j == i or j >= t.len or t[j] != '@') return null;
    const h = host(t, j + 1) orelse return null;
    return j + 1 + h.len - i;
}

fn uuid(t: []const u8, i: usize) ?usize {
    const groups = [_]usize{ 8, 4, 4, 4, 12 };
    var j = i;
    for (groups, 0..) |n, g| {
        if (g > 0) {
            if (j >= t.len or t[j] != '-') return null;
            j += 1;
        }
        if (j + n > t.len) return null;
        for (t[j..][0..n]) |c| if (!std.ascii.isHex(c)) return null;
        j += n;
    }
    if (j < t.len and isWord(t[j])) return null;
    return j - i;
}

const V4 = struct { len: usize, private: bool };

fn ipv4(t: []const u8, i: usize) ?V4 {
    var parts: [4]u16 = undefined;
    var j = i;
    for (&parts, 0..) |*p, k| {
        if (k > 0) {
            if (j >= t.len or t[j] != '.') return null;
            j += 1;
        }
        const start = j;
        p.* = 0;
        while (j < t.len and std.ascii.isDigit(t[j]) and j - start < 3) : (j += 1) p.* = p.* * 10 + (t[j] - '0');
        if (j == start or p.* > 255) return null;
    }
    if (j < t.len and (isWord(t[j]) or (t[j] == '.' and j + 1 < t.len and std.ascii.isDigit(t[j + 1])))) return null;
    const a = parts[0];
    const b = parts[1];
    const private = a == 0 or a == 10 or a == 127 or a >= 224 or
        (a == 169 and b == 254) or (a == 172 and b >= 16 and b <= 31) or (a == 192 and b == 168) or
        // fake DNS answers and carrier NAT
        (a == 198 and (b == 18 or b == 19)) or (a == 100 and b >= 64 and b <= 127);
    return .{ .len = j - i, .private = private };
}

/// Groups of hex with "::" or at least five colons (a MAC address too);
/// "::" and "::1" stay.
fn ipv6(t: []const u8, i: usize) ?usize {
    var j = i;
    var colons: usize = 0;
    var double = false;
    var digits: usize = 0;
    var run: usize = 0;
    while (j < t.len and (std.ascii.isHex(t[j]) or t[j] == ':')) : (j += 1) {
        if (t[j] == ':') {
            if (j > i and t[j - 1] == ':') double = true;
            colons += 1;
            run = 0;
        } else {
            digits += 1;
            run += 1;
            if (run > 4) return null;
        }
    }
    // a trailing colon is the text's ("address fe80::1:"), unless "::"
    if (j > i + 1 and t[j - 1] == ':' and t[j - 2] != ':') {
        j -= 1;
        colons -= 1;
    }
    if (j < t.len and isWord(t[j])) return null;
    if (colons > 7 or digits == 0) return null;
    if (!(double and digits > 1) and colons < 5) return null;
    return j - i;
}

const Host = struct { len: usize, tld: usize };

/// Dotted labels ending in a top-level domain: letters only, lower case
/// (so "error.ConnectionRefused" and "std.Io" are not names), or a non-ASCII
/// one (".рф").
fn host(t: []const u8, i: usize) ?Host {
    var j = i;
    var labels: usize = 0;
    var last: usize = i;
    while (true) {
        const start = j;
        while (j < t.len and (std.ascii.isAlphanumeric(t[j]) or t[j] == '-' or t[j] >= 0x80)) j += 1;
        if (j == start or j - start > 63) return null;
        labels += 1;
        last = start;
        if (j + 1 < t.len and t[j] == '.' and (std.ascii.isAlphanumeric(t[j + 1]) or t[j + 1] >= 0x80)) {
            j += 1;
            continue;
        }
        break;
    }
    if (labels < 2) return null;
    if (j < t.len and (t[j] == '_' or t[j] == '@')) return null;
    const tld = t[last..j];
    const ascii = for (tld) |c| {
        if (!std.ascii.isLower(c)) break false;
    } else true;
    const other = for (tld) |c| {
        if (c < 0x80) break false;
    } else true;
    if (!(ascii and tld.len >= 2) and !(other and tld.len >= 4)) return null;
    if (ascii and file_types.has(tld)) return null;
    return .{ .len = j - i, .tld = last - 1 - i };
}

/// Endings of files that the logs name, which are no sites.
const file_types: std.StaticStringMap(void) = .initComptime(.{
    .{"log"},     .{"events"}, .{"error"}, .{"json"},     .{"zig"},    .{"txt"},     .{"plist"},
    .{"exe"},     .{"dll"},    .{"sig"},   .{"zip"},      .{"gz"},     .{"tar"},     .{"app"},
    .{"so"},      .{"pdb"},    .{"png"},   .{"sock"},     .{"java"},   .{"apk"},     .{"aab"},
    .{"staging"}, .{"update"}, .{"new"},   .{"previous"}, .{"helper"}, .{"service"},
});

/// Names that say nothing about the user: where updates come from, and
/// this app's own (Android package, classes in a stack trace).
fn keptHost(name: []const u8) bool {
    if (std.mem.eql(u8, name, "dev.blackwall") or std.mem.startsWith(u8, name, "dev.blackwall.")) return true;
    const kept = [_][]const u8{ "github.com", "githubusercontent.com", "blackwall.timoshkin.dev" };
    for (kept) |k| {
        if (std.ascii.eqlIgnoreCase(name, k)) return true;
        if (name.len > k.len and name[name.len - k.len - 1] == '.' and std.ascii.eqlIgnoreCase(name[name.len - k.len ..], k)) return true;
    }
    return false;
}

const Secret = struct { len: usize, hex: bool };

/// Long base64 (both cases and a digit) or long hex: keys, passwords,
/// short ids.
fn secret(t: []const u8, i: usize) ?Secret {
    var j = i;
    var upper = false;
    var lower = false;
    var digit = false;
    var hex = true;
    while (j < t.len and (std.ascii.isAlphanumeric(t[j]) or std.mem.indexOfScalar(u8, "+/=_-", t[j]) != null)) : (j += 1) {
        const c = t[j];
        if (std.ascii.isUpper(c)) upper = true;
        if (std.ascii.isLower(c)) lower = true;
        if (std.ascii.isDigit(c)) digit = true;
        if (!std.ascii.isHex(c)) hex = false;
    }
    const n = j - i;
    if (hex and n >= 16) return .{ .len = n, .hex = true };
    if (n >= 20 and upper and lower and digit) return .{ .len = n, .hex = false };
    return null;
}

// ---------------------------------------------------------------- the window's log

/// The latest lines the window logged (it has no file of its own), oldest
/// dropped first. Any thread may add.
pub const Ring = struct {
    buf: [64 * 1024]u8 = undefined,
    /// bytes added in all; the next one goes to `written % buf.len`
    written: usize = 0,
    busy: std.atomic.Value(bool) = .init(false),

    fn lock(r: *Ring) void {
        while (r.busy.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }

    fn unlock(r: *Ring) void {
        r.busy.store(false, .release);
    }

    pub fn add(r: *Ring, bytes: []const u8) void {
        const b = if (bytes.len > r.buf.len) bytes[bytes.len - r.buf.len ..] else bytes;
        r.lock();
        defer r.unlock();
        const at = r.written % r.buf.len;
        const first = @min(b.len, r.buf.len - at);
        @memcpy(r.buf[at..][0..first], b[0..first]);
        @memcpy(r.buf[0 .. b.len - first], b[first..]);
        r.written += b.len;
    }

    /// The kept text, oldest first, from the first whole line.
    pub fn copy(r: *Ring, gpa: std.mem.Allocator) ![]u8 {
        r.lock();
        defer r.unlock();
        if (r.written <= r.buf.len) return gpa.dupe(u8, r.buf[0..r.written]);
        const at = r.written % r.buf.len;
        const out = try gpa.alloc(u8, r.buf.len);
        @memcpy(out[0 .. r.buf.len - at], r.buf[at..]);
        @memcpy(out[r.buf.len - at ..], r.buf[0..at]);
        const nl = std.mem.indexOfScalar(u8, out, '\n') orelse return out;
        std.mem.copyForwards(u8, out, out[nl + 1 ..]);
        return gpa.realloc(out, out.len - nl - 1);
    }
};

// ---------------------------------------------------------------- pieces of a report

pub const Clock = struct { year: u32, mon: u32, day: u32, hour: u32, min: u32, sec: u32 };

const Tm = extern struct { sec: c_int, min: c_int, hour: c_int, mday: c_int, mon: c_int, year: c_int, wday: c_int, yday: c_int, isdst: c_int, rest: [32]u8 };
extern "c" fn time(t: ?*i64) i64;
extern "c" fn localtime_r(t: *const i64, out: *Tm) ?*Tm;

const k32 = struct {
    const SYSTEMTIME = extern struct { year: u16, month: u16, wday: u16, day: u16, hour: u16, min: u16, sec: u16, ms: u16 };
    extern "kernel32" fn GetLocalTime(t: *SYSTEMTIME) callconv(.winapi) void;
};

/// Local time, for log lines and file names.
pub fn now() Clock {
    if (comptime builtin.os.tag == .windows) {
        var st: k32.SYSTEMTIME = undefined;
        k32.GetLocalTime(&st);
        return .{ .year = st.year, .mon = st.month, .day = st.day, .hour = st.hour, .min = st.min, .sec = st.sec };
    }
    var t: i64 = time(null);
    var tm: Tm = undefined;
    _ = localtime_r(&t, &tm);
    return .{
        .year = @intCast(tm.year + 1900),
        .mon = @intCast(tm.mon + 1),
        .day = @intCast(tm.mday),
        .hour = @intCast(tm.hour),
        .min = @intCast(tm.min),
        .sec = @intCast(tm.sec),
    };
}

/// The end of a file, at most `max` bytes, from a whole line; null when it
/// cannot be read.
pub fn tail(gpa: std.mem.Allocator, io: std.Io, path: []const u8, max: usize) ?[]u8 {
    const f = std.Io.Dir.cwd().openFile(io, path, .{}) catch return null;
    defer f.close(io);
    const size = f.length(io) catch return null;
    const from = size -| max;
    const out = gpa.alloc(u8, @intCast(size - from)) catch return null;
    const n = f.readPositionalAll(io, out, from) catch {
        gpa.free(out);
        return null;
    };
    var text = out[0..n];
    if (from > 0) if (std.mem.indexOfScalar(u8, text, '\n')) |nl| {
        text = text[nl + 1 ..];
    };
    std.mem.copyForwards(u8, out, text);
    return gpa.realloc(out, text.len) catch out[0..text.len];
}

/// A section of the report: a title line, then the text (scrubbed).
pub fn section(w: *std.Io.Writer, s: Scrub, title: []const u8, text: ?[]const u8) !void {
    try w.print("\n===== {s}\n", .{title});
    const t = text orelse return w.writeAll("(none)\n");
    try s.write(w, t);
    if (t.len > 0 and t[t.len - 1] != '\n') try w.writeByte('\n');
}

/// github.com/<repo>/issues/new with a title and a body filled in.
pub fn issueUrl(w: *std.Io.Writer, repo: []const u8, title: []const u8, body: []const u8) !void {
    try w.print("https://github.com/{s}/issues/new?title=", .{repo});
    try percent(w, title);
    try w.writeAll("&body=");
    try percent(w, body);
}

fn percent(w: *std.Io.Writer, text: []const u8) !void {
    for (text) |c| {
        if (std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, "-._~", c) != null) {
            try w.writeByte(c);
        } else try w.print("%{X:0>2}", .{c});
    }
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn scrubbed(text: []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try (Scrub{ .key = 42 }).write(&out.writer, text);
    return out.toOwnedSlice();
}

fn expectScrub(want: []const u8, text: []const u8) !void {
    const got = try scrubbed(text);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

fn expectGone(text: []const u8, secrets: []const []const u8) !void {
    const got = try scrubbed(text);
    defer testing.allocator.free(got);
    for (secrets) |s| if (std.mem.indexOf(u8, got, s) != null) {
        std.debug.print("\"{s}\" left in: {s}\n", .{ s, got });
        return error.TestUnexpectedResult;
    };
}

test "links keep only their scheme" {
    try expectScrub("add vless://<hidden> now", "add vless://0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0@203.0.113.7:443?security=reality&pbk=jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8#NL now");
    try expectScrub("sub https://<hidden>: 404", "sub https://panel.example.com/sub/abcdef: 404");
    try expectScrub("\"ss://<hidden>\"", "\"ss://YWVzLTI1Ni1nY206cGFzcw@host:8388\"");
}

test "ids, mail, keys" {
    try expectScrub("user <uuid> ok", "user 0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0 ok");
    try expectScrub("from <email>.", "from someone.name+vpn@mail.example.org.");
    try expectScrub("pbk <key> sid <hex>", "pbk jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8 sid ab12cd34ef567890");
    // words that only look long
    try expectScrub("cipher chacha20-ietf-poly1305, 2022-blake3-aes-256-gcm", "cipher chacha20-ietf-poly1305, 2022-blake3-aes-256-gcm");
}

test "names become tokens, the same name the same token" {
    const got = try scrubbed("connect vpn.Example.com:443 failed; vpn.example.com again; sni www.youtube.com via dpi");
    defer testing.allocator.free(got);
    try testing.expect(std.mem.indexOf(u8, got, "example") == null);
    try testing.expect(std.mem.indexOf(u8, got, "youtube") == null);
    try testing.expect(std.mem.indexOf(u8, got, ".com:443 failed") != null);
    var tokens: [3][]const u8 = undefined;
    var n: usize = 0;
    var at: usize = 0;
    while (std.mem.indexOfPos(u8, got, at, "<host:")) |start| {
        const end = std.mem.indexOfScalarPos(u8, got, start, '>').?;
        tokens[n] = got[start..end];
        n += 1;
        at = end;
    }
    try testing.expectEqual(3, n);
    try testing.expectEqualStrings(tokens[0], tokens[1]);
    try testing.expect(!std.mem.eql(u8, tokens[0], tokens[2]));
    try expectGone("сайт пример.рф заблокирован", &.{"пример"});
    // other applications are the user's business
    try expectGone("package com.mojang.minecraftpe", &.{"mojang"});
}

test "what is not a name stays" {
    const keep =
        \\05-17 14:04:05 error(service): connect: error.ConnectionRefused
        \\update: BLACKWALL.app not replaced; std.Io; service.log, service.events.1, config.json
        \\BLACKWALL 0.2.1 (ru), v0.2.0-ru, dev.blackwall.helper, api.github.com, 1.5 s, e.g. x
        \\at dev.blackwall.Main.lambda(Main.java:812), process dev.blackwall:vpn
        \\utun5 fd 7, mtu 1500, 12:34:56, 0x1f
    ;
    try expectScrub(keep, keep);
}

test "addresses: public hidden, private and fake kept" {
    try expectGone("to 203.0.113.7:443 and [2a02:6b8::2:242]:443 and 2a02:6b8:0:1:2:3:4:5", &.{ "203.0.113", "2a02", "6b8" });
    const keep = "dns 198.18.0.1, lan 192.168.1.10, 10.0.2.2, 172.16.5.4, 127.0.0.1, ::1, :: x, 255.255.255.255";
    try expectScrub(keep, keep);
    // a MAC address too
    try expectGone("mac a4:83:e7:12:34:56 up", &.{"a4:83"});
    // version numbers with four parts are no addresses... unless they are
    try expectScrub("1.2.3", "1.2.3");
}

test "the user's name in paths" {
    try expectScrub("/Users/<user>/Library/Application Support/BLACKWALL/service.log", "/Users/tim/Library/Application Support/BLACKWALL/service.log");
    try expectScrub("C:\\Users\\<user>\\AppData\\Roaming\\BLACKWALL", "C:\\Users\\Tim Smith\\AppData\\Roaming\\BLACKWALL");
    try expectScrub("/home/<user>/.config/blackwall", "/home/someone/.config/blackwall");
}

test "ring keeps the latest whole lines" {
    var r: Ring = .{};
    r.add("one\n");
    r.add("two\n");
    const a = try r.copy(testing.allocator);
    defer testing.allocator.free(a);
    try testing.expectEqualStrings("one\ntwo\n", a);
    var line: [100]u8 = undefined;
    for (0..10000) |i| {
        const l = try std.fmt.bufPrint(&line, "line {d}\n", .{i});
        r.add(l);
    }
    const b = try r.copy(testing.allocator);
    defer testing.allocator.free(b);
    try testing.expect(std.mem.startsWith(u8, b, "line "));
    try testing.expect(std.mem.endsWith(u8, b, "line 9999\n"));
    try testing.expect(b.len <= r.buf.len);
}

test "issue address is percent-encoded" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try issueUrl(&w, "ANODs/blackwall", "Отчёт", "a b\n&c");
    try testing.expectEqualStrings("https://github.com/ANODs/blackwall/issues/new?title=%D0%9E%D1%82%D1%87%D1%91%D1%82&body=a%20b%0A%26c", w.buffered());
}

test "tail starts at a whole line" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "f.log", .data = "first line\nsecond\nthird\n" });
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, "f.log", &path_buf);
    const t = tail(testing.allocator, io, path_buf[0..n], 10).?;
    defer testing.allocator.free(t);
    try testing.expectEqualStrings("third\n", t);
    const all = tail(testing.allocator, io, path_buf[0..n], 1000).?;
    defer testing.allocator.free(all);
    try testing.expectEqualStrings("first line\nsecond\nthird\n", all);
}
