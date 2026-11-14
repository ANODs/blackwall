//! System DNS while connected (macOS, root helper).
//!
//! Instead of rewriting the user's network services we publish one of our own
//! in configd's dynamic store, as vpnc-script does: an IPv4 entity on the utun
//! with a Router and OverridePrimary makes IPMonitor rank it first, so its DNS
//! entity (198.18.0.2, answered by the TUN) becomes the default resolver.
//! configd derives State:/Network/Global/DNS and /etc/resolv.conf from it on its
//! own and ignores the service once the utun is gone, while the user's Setup:
//! and State: settings are never touched. scutil's session ends with its
//! script, so the keys are plain, not temporary: restore() removes them, also
//! at helper start after a crash.
//!
//! `exec` (a tool run with an argv and a stdin script, never a shell) is shared
//! with pf.zig.

const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const Allocator = std.mem.Allocator;

const scutil = "/usr/sbin/scutil";

/// Our service id in State:/Network/Service/<id>; fixed so restore() finds the
/// keys of a crashed run.
const service_id = "6E0C3A4B-0000-4B57-8000-424C41434B57";
const key_ipv4 = "State:/Network/Service/" ++ service_id ++ "/IPv4";
const key_dns = "State:/Network/Service/" ++ service_id ++ "/DNS";

/// The utun's own address (core/ipstack/dns.zig `gateway`). IPMonitor ignores
/// a service without a router, and drops its DNS servers with it.
const tun_addr = [4]u8{ 198, 18, 0, 1 };

pub const Error = error{ InvalidInterface, NoServers, ScutilFailed };

/// Points the system resolver at `servers` (normally 198.18.0.2) through our
/// service on `utun_name`. Setting the same keys again is harmless.
pub fn apply(gpa: Allocator, servers: []const [4]u8, utun_name: []const u8) !void {
    const script = try applyScript(gpa, servers, utun_name);
    defer gpa.free(script);
    try runScutil(gpa, script);
}

/// Removes our service; the previous primary service and its DNS come back.
/// Safe when nothing was applied.
pub fn restore(gpa: Allocator) !void {
    try runScutil(gpa, restore_script);
}

/// The DNS servers of the real networks (no root needed): default and
/// per-interface resolvers from `scutil --dns`, without our fake range
/// 198.18.0.0/15 and loopback. The caller frees the slice.
pub fn upstreamServers(gpa: Allocator) ![]const [4]u8 {
    const out = try exec(gpa, &.{ scutil, "--dns" }, "");
    defer gpa.free(out.text);
    if (!out.ok) return error.ScutilFailed;
    return parseResolvers(gpa, out.text);
}

/// Drops cached answers (fake IPs included) after DNS changes. Needs root and
/// signals mDNSResponder, so it is never called from tests. Best effort.
pub fn flushCache(gpa: Allocator) void {
    const cmds = [_][]const []const u8{
        &.{ "/usr/bin/dscacheutil", "-flushcache" },
        &.{ "/usr/bin/killall", "-HUP", "mDNSResponder" },
    };
    for (cmds) |argv| {
        const out = exec(gpa, argv, "") catch |err| {
            std.log.warn("dns: {s}: {t}", .{ argv[0], err });
            continue;
        };
        defer gpa.free(out.text);
        if (!out.ok) std.log.warn("dns: {s} failed: {s}", .{ argv[0], out.text });
    }
}

/// scutil commands that publish our service. DNS goes first so the service
/// never becomes primary without its resolver. ConfirmedServiceID scopes the
/// queries to the utun, so they enter the TUN even when another VPN holds more
/// specific routes.
pub fn applyScript(gpa: Allocator, servers: []const [4]u8, utun_name: []const u8) ![]u8 {
    try validInterface(utun_name);
    if (servers.len == 0) return error.NoServers;
    var s: std.ArrayList(u8) = .empty;
    errdefer s.deinit(gpa);
    try s.appendSlice(gpa, "open\nd.init\nd.add ServerAddresses *");
    for (servers) |a| try s.print(gpa, " {f}", .{fmtIp4(a)});
    try s.print(gpa, "\nd.add ConfirmedServiceID {s}\nset {s}\n", .{ service_id, key_dns });
    try s.print(gpa, "d.init\nd.add InterfaceName {s}\nd.add Addresses * {f}\n", .{ utun_name, fmtIp4(tun_addr) });
    try s.print(gpa, "d.add SubnetMasks * 255.255.255.255\nd.add Router {f}\n", .{fmtIp4(tun_addr)});
    try s.print(gpa, "d.add OverridePrimary # 1\nset {s}\nclose\nquit\n", .{key_ipv4});
    return s.toOwnedSlice(gpa);
}

/// The IPv4 entity goes first: the service stops being primary before its
/// resolver disappears.
pub const restore_script = "open\nremove " ++ key_ipv4 ++ "\nremove " ++ key_dns ++ "\nclose\nquit\n";

/// Interface names are interpolated into scutil and pf scripts: letters and
/// digits only, starting with a letter, shorter than IFNAMSIZ.
pub fn validInterface(name: []const u8) Error!void {
    if (name.len == 0 or name.len > 15 or !std.ascii.isAlphabetic(name[0])) return error.InvalidInterface;
    for (name) |ch| if (!std.ascii.isAlphanumeric(ch)) return error.InvalidInterface;
}

pub fn fmtIp4(a: [4]u8) std.fmt.Alt([4]u8, writeIp4) {
    return .{ .data = a };
}

fn writeIp4(a: [4]u8, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.print("{d}.{d}.{d}.{d}", .{ a[0], a[1], a[2], a[3] });
}

/// scutil prints nothing for a command that worked and the SCError text for one
/// that failed; a missing key is fine (restore after a clean shutdown).
fn runScutil(gpa: Allocator, script: []const u8) !void {
    const out = try exec(gpa, &.{scutil}, script);
    defer gpa.free(out.text);
    if (!out.ok) return error.ScutilFailed;
    var lines = std.mem.tokenizeScalar(u8, out.text, '\n');
    while (lines.next()) |line| {
        const msg = std.mem.trim(u8, line, " \t\r");
        if (msg.len == 0 or std.mem.eql(u8, msg, "No such key")) continue;
        std.log.warn("dns: scutil: {s}", .{msg});
        return error.ScutilFailed;
    }
}

/// Nameservers of resolvers without a `domain` (default and scoped ones;
/// supplemental resolvers serve only their domain), in order, deduplicated.
fn parseResolvers(gpa: Allocator, text: []const u8) ![]const [4]u8 {
    var all: std.ArrayList([4]u8) = .empty;
    errdefer all.deinit(gpa);
    var block: std.ArrayList([4]u8) = .empty;
    defer block.deinit(gpa);
    var supplemental = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or std.mem.startsWith(u8, line, "resolver #")) {
            if (!supplemental) try addUpstreams(gpa, &all, block.items);
            block.clearRetainingCapacity();
            supplemental = false;
            continue;
        }
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.mem.eql(u8, name, "domain")) supplemental = true;
        if (std.mem.startsWith(u8, name, "nameserver[")) {
            if (parseIp4(value)) |a| try block.append(gpa, a);
        }
    }
    if (!supplemental) try addUpstreams(gpa, &all, block.items);
    return all.toOwnedSlice(gpa);
}

fn addUpstreams(gpa: Allocator, all: *std.ArrayList([4]u8), found: []const [4]u8) !void {
    for (found) |a| {
        if (isOurs(a) or a[0] == 127 or std.mem.eql(u8, &a, &.{ 0, 0, 0, 0 })) continue;
        for (all.items) |b| {
            if (std.mem.eql(u8, &a, &b)) break;
        } else try all.append(gpa, a);
    }
}

/// 198.18.0.0/15: the fake-IP pool, including our own resolver.
fn isOurs(a: [4]u8) bool {
    return a[0] == 198 and (a[1] & 0xfe) == 18;
}

fn parseIp4(s: []const u8) ?[4]u8 {
    const ip = std.Io.net.Ip4Address.parse(s, 0) catch return null;
    return ip.bytes;
}

/// What a tool printed (stdout and stderr together) and whether it exited 0.
pub const Output = struct { ok: bool, text: []u8 };

/// Longest output we keep; `scutil --dns` prints a few KiB.
const output_max = 1 << 20;

/// Runs a tool by absolute path with `input` on its stdin, never through a
/// shell. The input is written into the pipe before the child starts, so a
/// child that exits early cannot raise SIGPIPE here; it must fit the pipe
/// buffer (16 KiB). The caller frees `text`.
pub fn exec(gpa: Allocator, argv: []const []const u8, input: []const u8) !Output {
    const in = try pipe();
    defer closeFd(in[0]);
    {
        defer closeFd(in[1]);
        try setNonblocking(in[1]);
        if (input.len > 0 and c.write(in[1], input.ptr, input.len) != @as(isize, @intCast(input.len)))
            return error.InputTooLong;
    }
    const out = try pipe();
    defer closeFd(out[0]);

    var threaded: std.Io.Threaded = .init_single_threaded;
    threaded.allocator = gpa;
    defer threaded.deinit();
    const io = threaded.io();

    var child = spawn: {
        defer closeFd(out[1]);
        const sink: std.Io.File = .{ .handle = out[1], .flags = .{ .nonblocking = false } };
        break :spawn try std.process.spawn(io, .{
            .argv = argv,
            .stdin = .{ .file = .{ .handle = in[0], .flags = .{ .nonblocking = false } } },
            .stdout = .{ .file = sink },
            .stderr = .{ .file = sink },
        });
    };
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(gpa);
    readAll(gpa, out[0], &text) catch |err| {
        child.kill(io);
        return err;
    };
    const term = try child.wait(io);
    return .{ .ok = term == .exited and term.exited == 0, .text = try text.toOwnedSlice(gpa) };
}

fn readAll(gpa: Allocator, fd: c.fd_t, text: *std.ArrayList(u8)) !void {
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = c.read(fd, &buf, buf.len);
        if (n == 0) return;
        if (n < 0) {
            if (c.errno(n) == .INTR) continue;
            return error.ReadFailed;
        }
        if (text.items.len + @as(usize, @intCast(n)) > output_max) return error.OutputTooLong;
        try text.appendSlice(gpa, buf[0..@intCast(n)]);
    }
}

/// A pipe whose ends other children never inherit.
fn pipe() ![2]c.fd_t {
    var fds: [2]c.fd_t = undefined;
    if (c.pipe(&fds) != 0) return error.PipeFailed;
    for (fds) |fd| _ = c.fcntl(fd, c.F.SETFD, @as(c_int, c.FD_CLOEXEC));
    return fds;
}

fn setNonblocking(fd: c.fd_t) !void {
    const flags = c.fcntl(fd, c.F.GETFL);
    const nb: c_int = @bitCast(@as(u32, @bitCast(c.O{ .NONBLOCK = true })));
    if (flags < 0 or c.fcntl(fd, c.F.SETFL, flags | nb) < 0) return error.PipeFailed;
}

fn closeFd(fd: c.fd_t) void {
    _ = c.close(fd);
}

test "apply script publishes DNS first, then the primary IPv4 entity" {
    const gpa = std.testing.allocator;
    const script = try applyScript(gpa, &.{ .{ 198, 18, 0, 2 }, .{ 10, 0, 0, 53 } }, "utun7");
    defer gpa.free(script);
    try std.testing.expectEqualStrings(
        "open\n" ++
            "d.init\nd.add ServerAddresses * 198.18.0.2 10.0.0.53\n" ++
            "d.add ConfirmedServiceID 6E0C3A4B-0000-4B57-8000-424C41434B57\n" ++
            "set State:/Network/Service/6E0C3A4B-0000-4B57-8000-424C41434B57/DNS\n" ++
            "d.init\nd.add InterfaceName utun7\nd.add Addresses * 198.18.0.1\n" ++
            "d.add SubnetMasks * 255.255.255.255\nd.add Router 198.18.0.1\nd.add OverridePrimary # 1\n" ++
            "set State:/Network/Service/6E0C3A4B-0000-4B57-8000-424C41434B57/IPv4\n" ++
            "close\nquit\n",
        script,
    );
}

test "restore script removes only our keys, IPv4 first" {
    try std.testing.expectEqualStrings(
        "open\nremove State:/Network/Service/6E0C3A4B-0000-4B57-8000-424C41434B57/IPv4\n" ++
            "remove State:/Network/Service/6E0C3A4B-0000-4B57-8000-424C41434B57/DNS\nclose\nquit\n",
        restore_script,
    );
}

test "apply script refuses values that could inject scutil commands" {
    const gpa = std.testing.allocator;
    const dns = [_][4]u8{.{ 198, 18, 0, 2 }};
    for ([_][]const u8{ "", "utun7\nremove State:/Network/Global/DNS", "utun 7", "utun-7", "7utun", "utun1234567890123", "ütun" }) |bad|
        try std.testing.expectError(error.InvalidInterface, applyScript(gpa, &dns, bad));
    try std.testing.expectError(error.NoServers, applyScript(gpa, &.{}, "utun7"));
    try validInterface("utun123");
    try validInterface("en0");
}

test "resolvers: default and scoped servers, no supplemental, fake or loopback ones" {
    const gpa = std.testing.allocator;
    const text =
        \\DNS configuration
        \\
        \\resolver #1
        \\  nameserver[0] : 198.18.0.2
        \\  if_index : 31 (utun7)
        \\  flags    : Request A records
        \\
        \\resolver #2
        \\  domain   : corp.example
        \\  nameserver[0] : 10.8.0.1
        \\
        \\resolver #3
        \\  domain   : local
        \\  options  : mdns
        \\
        \\DNS configuration (for scoped queries)
        \\
        \\resolver #1
        \\  search domain[0] : home.arpa
        \\  nameserver[0] : 192.168.0.1
        \\  nameserver[1] : fe80::1%en0
        \\  nameserver[2] : 127.0.0.1
        \\  nameserver[3] : 1.1.1.1
        \\  if_index : 14 (en0)
        \\
        \\resolver #2
        \\  nameserver[0] : 198.19.255.1
        \\  nameserver[1] : 192.168.0.1
        \\  if_index : 31 (utun7)
    ;
    const got = try parseResolvers(gpa, text);
    defer gpa.free(got);
    try std.testing.expectEqualSlices([4]u8, &.{ .{ 192, 168, 0, 1 }, .{ 1, 1, 1, 1 } }, got);
}

test "upstream servers of this machine (read-only)" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const got = try upstreamServers(gpa);
    defer gpa.free(got);
    for (got) |a| {
        try std.testing.expect(!isOurs(a));
        try std.testing.expect(a[0] != 127);
    }
}

test "exec passes stdin and collects stdout and stderr" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const out = try exec(gpa, &.{ "/bin/cat", "-", "/nonexistent-blackwall" }, "hello\n");
    defer gpa.free(out.text);
    try std.testing.expect(!out.ok);
    try std.testing.expect(std.mem.startsWith(u8, out.text, "hello\n"));
    try std.testing.expect(std.mem.indexOf(u8, out.text, "nonexistent-blackwall") != null);
}
