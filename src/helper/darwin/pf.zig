//! The strict kill switch (macOS, root helper): pf rules that let traffic out
//! only through the utun, to the VPN servers and to the upstream DNS servers.
//!
//! The rules live in the anchor com.apple/blackwall, which the stock
//! /etc/pf.conf already evaluates through `anchor "com.apple/*"`, so neither
//! pf.conf nor the main ruleset is touched. pf is enabled with a reference
//! token (DIOCSTARTREF), never `pfctl -e/-d`, so other pf users (AirDrop, the
//! application firewall, other VPNs) keep their own references. The kernel
//! keeps both the rules and the token when the helper dies: traffic stays
//! blocked until the next helper start calls disable() with the saved token.
//!
//! Every rule is outbound, `quick` (a quick match ends the evaluation of the
//! whole ruleset, so later anchors cannot override it) and `no state`: rule and
//! table changes apply to existing connections at once and nothing has to be
//! flushed from pf's global state table afterwards.

const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const Allocator = std.mem.Allocator;
const dns = @import("dns.zig");

pub const anchor = "com.apple/blackwall";
const table_servers = "bw_servers";
const table_dns = "bw_dns";
const pfctl = "/sbin/pfctl";

pub const Options = struct {
    utun: []const u8,
    servers4: []const [4]u8,
    servers6: []const [16]u8,
    dns4: []const [4]u8,
    allow_lan: bool,
    ipv6: enum { block, tunnel },
};

/// Our reference on pf's enable count. The value is what the kernel handed
/// out; the helper persists it and passes it back to disable() after a crash.
pub const Token = enum(u64) {
    /// no reference held: disable() then only flushes the anchor
    none = 0,
    _,
};

pub const Error = error{ AccessDenied, PfctlFailed, PfIoctlFailed };

/// The anchor's ruleset, tables included.
pub fn rules(gpa: Allocator, opts: Options) ![]u8 {
    try validTunnel(opts.utun);
    var s: std.ArrayList(u8) = .empty;
    errdefer s.deinit(gpa);
    try s.appendSlice(gpa, "table <" ++ table_servers ++ "> persist {");
    try appendAddrs(gpa, &s, opts.servers4, opts.servers6);
    try s.appendSlice(gpa, " }\ntable <" ++ table_dns ++ "> persist {");
    try appendAddrs(gpa, &s, opts.dns4, &.{});
    try s.appendSlice(gpa,
        \\ }
        \\pass out quick on lo0 all no state
        \\pass out quick inet proto udp from any port 68 to any port 67 no state
        \\pass out quick inet6 proto ipv6-icmp all icmp6-type { routersol, neighbrsol, neighbradv } no state
        \\pass out quick to <bw_servers> no state
        \\pass out quick proto { tcp, udp } to <bw_dns> port 53 no state
        \\
    );
    if (opts.ipv6 == .block) try s.appendSlice(gpa, "block return out quick inet6 all\n");
    try s.print(gpa, "pass out quick on {s} all no state\n", .{opts.utun});
    if (opts.ipv6 == .tunnel) try s.appendSlice(gpa, "pass out quick inet6 proto udp from fe80::/10 port 546 to { ff02::1:2, ff05::1:3 } port 547 no state\n");
    if (opts.allow_lan) {
        // DNS to LAN hosts other than the upstream servers stays blocked:
        // it would bypass the TUN resolver.
        try s.appendSlice(gpa,
            \\block return out quick proto { tcp, udp } to any port { 53, 853 }
            \\pass out quick inet to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } no state
            \\
        );
        if (opts.ipv6 == .tunnel) try s.appendSlice(gpa, "pass out quick inet6 to { fe80::/10, fc00::/7, ff00::/8 } no state\n");
    }
    try s.appendSlice(gpa, "block return out quick all\n");
    return s.toOwnedSlice(gpa);
}

/// Loads the anchor, then takes a reference on pf's enable count. Each call
/// takes a new token; release the previous one with disable().
pub fn enable(gpa: Allocator, opts: Options) !Token {
    const text = try rules(gpa, opts);
    defer gpa.free(text);
    try runPfctl(gpa, &.{ "-a", anchor, "-f", "-" }, text);
    errdefer flushAnchor(gpa) catch {};
    const fd = try openPf();
    defer closeFd(fd);
    var token: u64 = 0;
    if (c.ioctl(fd, ioc(.out, 8, u64), &token) != 0) return error.PfIoctlFailed;
    return @fromBackingInt(@intCast(token));
}

/// Replaces the anchor's rules in place; pf stays enabled under the same token.
pub fn reload(gpa: Allocator, opts: Options) !void {
    const text = try rules(gpa, opts);
    defer gpa.free(text);
    try runPfctl(gpa, &.{ "-a", anchor, "-f", "-" }, text);
}

/// Replaces the server and DNS tables in place, without reloading the rules.
pub fn updateTables(gpa: Allocator, opts: Options) !void {
    try replaceTable(gpa, table_servers, opts.servers4, opts.servers6);
    try replaceTable(gpa, table_dns, opts.dns4, &.{});
}

/// Flushes our anchor and releases `token`. Safe after a crash or a reboot:
/// a token pf no longer lists (pf stopped, `pfctl -d`, reboot) or one that now
/// belongs to another process (token values are reused) is left alone.
pub fn disable(gpa: Allocator, token: Token) !void {
    try flushAnchor(gpa);
    if (token == .none) return;
    const fd = try openPf();
    defer closeFd(fd);
    if (!try heldByUs(gpa, fd, token)) return;
    var req: RemoveToken = .{ .token_value = @backingInt(token), .refcount = 0 };
    if (c.ioctl(fd, ioc(.inout, 9, RemoveToken), &req) == 0) return;
    switch (c.errno(@as(c_int, -1))) {
        // ENOENT: pf is not running; EINVAL: the token is unknown
        .NOENT, .INVAL => {},
        else => return error.PfIoctlFailed,
    }
}

/// Rules and tables only: `-F all` would also flush pf's global state table.
/// Without tables the rule flush already removed the anchor, and the table
/// flush then fails with ENOENT (also when nothing was loaded); tables alone
/// block nothing, so that failure is only logged.
fn flushAnchor(gpa: Allocator) !void {
    try runPfctl(gpa, &.{ "-a", anchor, "-F", "rules" }, "");
    const out = try dns.exec(gpa, &.{ pfctl, "-q", "-a", anchor, "-F", "Tables" }, "");
    defer gpa.free(out.text);
    if (!out.ok) std.log.debug("pf: table flush: {s}", .{out.text});
}

/// The pass rule names this interface, so it must be a utun: a physical one
/// such as "en0" would silently open the kill switch.
fn validTunnel(name: []const u8) dns.Error!void {
    try dns.validInterface(name);
    if (name.len == 4 or !std.mem.startsWith(u8, name, "utun")) return error.InvalidInterface;
    for (name[4..]) |ch| if (!std.ascii.isDigit(ch)) return error.InvalidInterface;
}

fn replaceTable(gpa: Allocator, name: []const u8, v4: []const [4]u8, v6: []const [16]u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var args: std.ArrayList([]const u8) = .empty;
    try args.appendSlice(arena, &.{ "-a", anchor, "-t", name, "-T", "replace" });
    for (v4) |a| try args.append(arena, try std.fmt.allocPrint(arena, "{f}", .{dns.fmtIp4(a)}));
    for (v6) |a| try args.append(arena, try std.fmt.allocPrint(arena, "{f}", .{fmtIp6(a)}));
    try runPfctl(gpa, args.items, "");
}

fn appendAddrs(gpa: Allocator, s: *std.ArrayList(u8), v4: []const [4]u8, v6: []const [16]u8) !void {
    for (v4, 0..) |a, i| try s.print(gpa, "{s} {f}", .{ if (i == 0) "" else ",", dns.fmtIp4(a) });
    for (v6, 0..) |a, i| try s.print(gpa, "{s} {f}", .{ if (i + v4.len == 0) "" else ",", fmtIp6(a) });
}

fn fmtIp6(a: [16]u8) std.fmt.Alt([16]u8, writeIp6) {
    return .{ .data = a };
}

/// All eight groups, uncompressed: pfctl accepts it and there is nothing to get wrong.
fn writeIp6(a: [16]u8, w: *std.Io.Writer) std.Io.Writer.Error!void {
    for (0..8) |i| {
        if (i > 0) try w.writeByte(':');
        try w.print("{x}", .{std.mem.readInt(u16, a[i * 2 ..][0..2], .big)});
    }
}

fn runPfctl(gpa: Allocator, args: []const []const u8, input: []const u8) !void {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.appendSlice(gpa, &.{ pfctl, "-q" });
    try argv.appendSlice(gpa, args);
    const out = try dns.exec(gpa, argv.items, input);
    defer gpa.free(out.text);
    if (out.ok) return;
    std.log.warn("pf: pfctl failed: {s}", .{out.text});
    return error.PfctlFailed;
}

// pf's ioctl interface (xnu bsd/net/pfvar.h; the header is not in the SDK).

const RemoveToken = extern struct { token_value: u64, refcount: u64 };
const Tokens = extern struct { size: c_int, buf: ?[*]u8 };
/// struct pfioc_token is packed: u64 value, u64 timestamp, pid_t pid, char name[64].
const token_len = 84;
const token_pid = 16;
const token_name = 20;

/// _IOR/_IOWR('D', nr, T) from <sys/ioccom.h>.
fn ioc(comptime dir: enum { out, inout }, comptime nr: u8, comptime T: type) c_int {
    const d: u32 = if (dir == .out) 0x4000_0000 else 0xc000_0000;
    return @bitCast(d | (@as(u32, @sizeOf(T) & 0x1fff) << 16) | ('D' << 8) | nr);
}

fn openPf() !c.fd_t {
    const fd = c.open("/dev/pf", .{ .ACCMODE = .RDWR, .CLOEXEC = true });
    if (fd >= 0) return fd;
    return switch (c.errno(fd)) {
        .ACCES, .PERM => error.AccessDenied,
        else => error.PfIoctlFailed,
    };
}

fn closeFd(fd: c.fd_t) void {
    _ = c.close(fd);
}

/// Whether pf lists `token` as taken by this process or by an earlier run of
/// the same executable (the kernel records the short command name).
fn heldByUs(gpa: Allocator, fd: c.fd_t, token: Token) !bool {
    var q: Tokens = .{ .size = 0, .buf = null };
    if (c.ioctl(fd, ioc(.inout, 5, Tokens), &q) != 0) {
        if (c.errno(@as(c_int, -1)) == .NOENT) return false; // no tokens at all
        return error.PfIoctlFailed;
    }
    // room for tokens taken meanwhile
    const buf = try gpa.alloc(u8, @as(usize, @intCast(q.size)) + 8 * token_len);
    defer gpa.free(buf);
    q = .{ .size = @intCast(buf.len), .buf = buf.ptr };
    if (c.ioctl(fd, ioc(.inout, 5, Tokens), &q) != 0) {
        if (c.errno(@as(c_int, -1)) == .NOENT) return false;
        return error.PfIoctlFailed;
    }
    const comm = try ownComm();
    return isOurs(buf[0..@intCast(q.size)], @backingInt(token), c.getpid(), std.mem.sliceTo(&comm, 0));
}

fn isOurs(list: []const u8, token: u64, pid: c.pid_t, comm: []const u8) bool {
    var i: usize = 0;
    while (i + token_len <= list.len) : (i += token_len) {
        const rec = list[i..][0..token_len];
        if (std.mem.readInt(u64, rec[0..8], .little) != token) continue;
        if (std.mem.readInt(i32, rec[token_pid..][0..4], .little) == pid) return true;
        const name = std.mem.sliceTo(rec[token_name..], 0);
        return comm.len > 0 and std.mem.eql(u8, commPrefix(name), commPrefix(comm));
    }
    return false;
}

/// pf stores up to 16 bytes of the name, proc_pidinfo returns only 15
/// (pbi_comm[MAXCOMLEN - 1] = 0), so a 16-byte name like "blackwall-helper"
/// is compared on its first 15 bytes.
fn commPrefix(name: []const u8) []const u8 {
    return name[0..@min(name.len, 15)];
}

extern "c" fn proc_pidinfo(pid: c_int, flavor: c_int, arg: u64, buf: ?*anyopaque, size: c_int) c_int;

/// struct proc_bsdinfo (sys/proc_info.h); only the command name is used.
const BsdInfo = extern struct {
    ids: [12]u32,
    comm: [16]u8,
    name: [32]u8,
    rest: [6]u32,
    start: [2]u64,
};
comptime {
    std.debug.assert(@sizeOf(BsdInfo) == 136);
}
const proc_pidtbsdinfo = 3;

/// This process's p_comm, the name pf stores with a token (up to 16 bytes).
fn ownComm() ![17]u8 {
    var info: BsdInfo = undefined;
    if (proc_pidinfo(c.getpid(), proc_pidtbsdinfo, 0, &info, @sizeOf(BsdInfo)) != @sizeOf(BsdInfo))
        return error.PfIoctlFailed;
    var out: [17]u8 = @splat(0);
    @memcpy(out[0..16], &info.comm);
    return out;
}

fn testOptions(lan: bool, v6: @FieldType(Options, "ipv6")) Options {
    return .{
        .utun = "utun7",
        .servers4 = &.{.{ 203, 0, 113, 10 }},
        .servers6 = &.{.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 }},
        .dns4 = &.{ .{ 192, 168, 0, 1 }, .{ 1, 1, 1, 1 } },
        .allow_lan = lan,
        .ipv6 = v6,
    };
}

const head =
    \\table <bw_servers> persist { 203.0.113.10, 2001:db8:0:0:0:0:0:10 }
    \\table <bw_dns> persist { 192.168.0.1, 1.1.1.1 }
    \\pass out quick on lo0 all no state
    \\pass out quick inet proto udp from any port 68 to any port 67 no state
    \\pass out quick inet6 proto ipv6-icmp all icmp6-type { routersol, neighbrsol, neighbradv } no state
    \\pass out quick to <bw_servers> no state
    \\pass out quick proto { tcp, udp } to <bw_dns> port 53 no state
    \\
;

test "strict rules without LAN, IPv6 blocked" {
    const gpa = std.testing.allocator;
    const text = try rules(gpa, testOptions(false, .block));
    defer gpa.free(text);
    try std.testing.expectEqualStrings(head ++
        \\block return out quick inet6 all
        \\pass out quick on utun7 all no state
        \\block return out quick all
        \\
    , text);
}

test "strict rules with LAN, IPv6 tunneled" {
    const gpa = std.testing.allocator;
    const text = try rules(gpa, testOptions(true, .tunnel));
    defer gpa.free(text);
    try std.testing.expectEqualStrings(head ++
        \\pass out quick on utun7 all no state
        \\pass out quick inet6 proto udp from fe80::/10 port 546 to { ff02::1:2, ff05::1:3 } port 547 no state
        \\block return out quick proto { tcp, udp } to any port { 53, 853 }
        \\pass out quick inet to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } no state
        \\pass out quick inet6 to { fe80::/10, fc00::/7, ff00::/8 } no state
        \\block return out quick all
        \\
    , text);
}

test "LAN with IPv6 blocked opens only IPv4 ranges" {
    const gpa = std.testing.allocator;
    const text = try rules(gpa, testOptions(true, .block));
    defer gpa.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "pass out quick inet to { 10.0.0.0/8") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "fe80::/10, fc00::/7") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "port 546") == null);
}

test "empty tables and invalid interface names" {
    const gpa = std.testing.allocator;
    var o = testOptions(false, .tunnel);
    o.servers4 = &.{};
    o.servers6 = &.{};
    o.dns4 = &.{};
    const text = try rules(gpa, o);
    defer gpa.free(text);
    try std.testing.expect(std.mem.startsWith(u8, text, "table <bw_servers> persist { }\ntable <bw_dns> persist { }\n"));
    for ([_][]const u8{ "", "utun7 all\npass out quick", "utun-7", "{utun7}", "0utun", "utun12345678901234", "en0", "utun", "utun7a", "lo0" }) |bad| {
        o.utun = bad;
        try std.testing.expectError(error.InvalidInterface, rules(gpa, o));
    }
}

test "pfctl parses every variant (parse only, no root, nothing loaded)" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    for ([_]bool{ false, true }) |lan| for ([_]@FieldType(Options, "ipv6"){ .block, .tunnel }) |v6| {
        const text = try rules(gpa, testOptions(lan, v6));
        defer gpa.free(text);
        const out = try dns.exec(gpa, &.{ pfctl, "-n", "-q", "-a", anchor, "-f", "-" }, text);
        defer gpa.free(out.text);
        if (!out.ok) std.debug.print("{s}\n{s}\n", .{ text, out.text });
        try std.testing.expect(out.ok);
    };
}

test "ioctl numbers match xnu" {
    try std.testing.expectEqual(@as(u32, 0x40084408), @as(u32, @bitCast(ioc(.out, 8, u64)))); // DIOCSTARTREF
    try std.testing.expectEqual(@as(u32, 0xc0104409), @as(u32, @bitCast(ioc(.inout, 9, RemoveToken)))); // DIOCSTOPREF
    try std.testing.expectEqual(@as(u32, 0xc0104405), @as(u32, @bitCast(ioc(.inout, 5, Tokens)))); // DIOCGETSTARTERS
}

test "token ownership: same pid, same command name, foreign or missing" {
    var list: [3 * token_len]u8 = @splat(0);
    const recs = [_]struct { u64, i32, []const u8 }{
        .{ 0xaaaa, 100, "blackwall-helper" }, // pf keeps 16 bytes, proc_pidinfo 15
        .{ 0xbbbb, 200, "sing-box" },
        .{ 0xcccc, 300, "pfctl" },
    };
    for (recs, 0..) |r, i| {
        const rec = list[i * token_len ..][0..token_len];
        std.mem.writeInt(u64, rec[0..8], r[0], .little);
        std.mem.writeInt(i32, rec[token_pid..][0..4], r[1], .little);
        @memcpy(rec[token_name..][0..r[2].len], r[2]);
    }
    try std.testing.expect(isOurs(&list, 0xaaaa, 999, "blackwall-helpe")); // earlier run
    try std.testing.expect(isOurs(&list, 0xcccc, 300, "other")); // this process
    try std.testing.expect(!isOurs(&list, 0xbbbb, 999, "blackwall-helpe")); // value reused by another app
    try std.testing.expect(!isOurs(&list, 0xdddd, 999, "blackwall-helpe")); // already released
    try std.testing.expect(!isOurs(&list, 0xbbbb, 999, ""));
    try std.testing.expect(!isOurs(&list, 0xaaaa, 999, "blackwall")); // shorter name is another program
}

test "own command name (read-only)" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const comm = try ownComm();
    const name = std.mem.sliceTo(&comm, 0);
    try std.testing.expect(name.len > 0 and name.len <= 16);
}
