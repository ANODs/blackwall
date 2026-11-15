//! BLACKWALL privileged helper (macOS).
//!
//! Runs as root from launchd and does only what the unprivileged service
//! cannot: create the utun, give it its addresses and the routes that
//! capture traffic, point the system resolver at the TUN, and hold the pf
//! kill switch. It keeps its own copy of the utun, so if the service dies
//! traffic stays captured (and dropped) instead of leaking.
//!
//!   blackwall-helper run --allow-uid UID    launchd runs this
//!   sudo blackwall-helper install           copies itself and loads the daemon
//!   sudo blackwall-helper uninstall         unloads it and undoes everything
//!
//! Requests come from one user (the one who installed it) over a Unix
//! socket; every value is validated before it reaches an ioctl, a route
//! message or a command line. It runs no shell and no arbitrary command.
//!
//! It watches the process that asked for the utun. When that process ends
//! without "down" (a crash, a restart), the kill switch decides: off gives
//! the traffic back to the normal routes, selective and strict keep it
//! captured until a service is back.

const std = @import("std");
const builtin = @import("builtin");
const core = @import("core");
const fdpass = @import("fdpass");
const net = @import("darwin/net.zig");
const dns = @import("darwin/dns.zig");
const pf = @import("darwin/pf.zig");
const proc = @import("darwin/proc.zig");

const proto = core.helper_ipc;
const c = std.c;
const Io = std.Io;
const log = std.log.scoped(.helper);

const state_dir = "/Library/Application Support/BLACKWALL";
const state_path = state_dir ++ "/helper.state";
/// Exists while the user wants traffic held from boot (the "hold" command).
const hold_path = state_dir ++ "/hold";
/// How long after someone logged in a hold without a service is kept: the
/// app starts within seconds; if it never comes, the Mac must not stay
/// without network.
const hold_patience_ms = 120_000;

const Route = struct { dst: net.Addr, prefix: u8 };

fn v4(a: [4]u8) net.Addr {
    return [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff } ++ a;
}

/// What the TUN captures: the fake-IP range, then everything else in two
/// halves (more specific than the real default route, which stays put).
const routes4 = [_]Route{
    .{ .dst = v4(.{ 198, 18, 0, 0 }), .prefix = 15 },
    .{ .dst = v4(.{ 0, 0, 0, 0 }), .prefix = 1 },
    .{ .dst = v4(.{ 128, 0, 0, 0 }), .prefix = 1 },
};
const routes6 = [_]Route{
    .{ .dst = @splat(0), .prefix = 1 },
    .{ .dst = .{ 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .prefix = 1 },
};
const tun_addr6 = [16]u8{ 0xfd, 0x62, 0x6c, 0x61, 0x63, 0x6b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

const KillSwitch = enum { off, selective, strict };

const Helper = struct {
    gpa: std.mem.Allocator,
    io: Io,
    allow_uid: u32,

    utun: ?net.Utun = null,
    installed: std.ArrayList(Route) = .empty,
    killswitch: KillSwitch = .off,
    token: pf.Token = .none,
    bind_index: u32 = 0,
    bind_name: [16:0]u8 = @splat(0),
    upstream: []const [4]u8 = &.{},
    servers: std.ArrayList([4]u8) = .empty,
    allow_lan: bool = true,
    ipv6_tunnel: bool = true,
    /// IPv6 routes point into the utun (not with IPv6 left to the system)
    ipv6_captured: bool = false,
    /// the process that holds the utun (the service), watched for its exit
    owner_pid: c.pid_t = 0,
    kq: c_int = -1,
    /// Holding from boot: wanted and not yet taken over by a service (or
    /// given up). While set, the serve loop wakes every two seconds.
    boot_hold: bool = false,
    /// when a logged-in user was first seen during the hold (awake ms)
    login_seen_ms: i64 = 0,

    /// Undo whatever a crashed instance left behind.
    fn recover(h: *Helper) void {
        dns.restore(h.gpa) catch |err| log.warn("dns restore: {t}", .{err});
        if (readToken(h.gpa, h.io)) |tok| {
            pf.disable(h.gpa, tok) catch |err| log.warn("pf disable: {t}", .{err});
        }
        std.Io.Dir.cwd().deleteFile(h.io, state_path) catch {};
    }

    fn handle(h: *Helper, conn: c.fd_t) void {
        var buf: [16 * 1024]u8 = undefined;
        const got = fdpass.recvFd(conn, &buf) catch return;
        if (got.fd) |fd| _ = c.close(fd); // we never accept descriptors
        const line = std.mem.trimEnd(u8, buf[0..got.len], "\r\n");
        var arena: std.heap.ArenaAllocator = .init(h.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const req = std.json.parseFromSliceLeaky(proto.Request, a, line, .{ .ignore_unknown_fields = true }) catch {
            return h.reply(conn, a, .{ .@"error" = "bad request" }, null);
        };
        if (std.mem.eql(u8, req.cmd, "up")) {
            h.up(conn, a, req);
        } else if (std.mem.eql(u8, req.cmd, "down")) {
            h.boot_hold = false;
            h.down();
            h.reply(conn, a, .{ .ok = true }, null);
        } else if (std.mem.eql(u8, req.cmd, "hold")) {
            setHold(h.io, req.hold);
            h.reply(conn, a, .{ .ok = true }, null);
        } else if (std.mem.eql(u8, req.cmd, "servers")) {
            h.setServers(a, req) catch |err| return h.reply(conn, a, .{ .@"error" = @errorName(err) }, null);
            h.reply(conn, a, .{ .ok = true }, null);
        } else if (std.mem.eql(u8, req.cmd, "status")) {
            h.reply(conn, a, h.describe(a), null);
        } else if (std.mem.eql(u8, req.cmd, "conflicts")) {
            var r = h.describe(a);
            r.owners = h.owners(a) catch |err| return h.reply(conn, a, .{ .@"error" = @errorName(err) }, null);
            h.reply(conn, a, r, null);
        } else if (std.mem.eql(u8, req.cmd, "stop_zapret")) {
            stopZapret(h.gpa, h.io) catch |err| {
                log.warn("stop zapret: {t}", .{err});
                return h.reply(conn, a, .{ .@"error" = @errorName(err) }, null);
            };
            h.reply(conn, a, .{ .ok = true }, null);
        } else if (std.mem.eql(u8, req.cmd, "stop")) {
            h.stopOwner(a, req) catch |err| {
                log.warn("stop pid {d}: {t}", .{ req.pid, err });
                return h.reply(conn, a, .{ .@"error" = @errorName(err) }, null);
            };
            h.reply(conn, a, .{ .ok = true }, null);
        } else {
            h.reply(conn, a, .{ .@"error" = "unknown command" }, null);
        }
    }

    fn reply(h: *Helper, conn: c.fd_t, a: std.mem.Allocator, r: proto.Reply, fd: ?c.fd_t) void {
        _ = h;
        const text = std.json.Stringify.valueAlloc(a, r, .{}) catch return;
        const line = std.mem.concat(a, u8, &.{ text, "\n" }) catch return;
        if (fd) |f| {
            fdpass.sendFd(conn, f, line) catch |err| log.warn("send fd: {t}", .{err});
        } else {
            _ = c.write(conn, line.ptr, line.len);
        }
    }

    /// Our own tunnel, never a conflict.
    fn ownIfname(h: *Helper) ?[]const u8 {
        return if (h.utun) |*u| u.ifname() else null;
    }

    /// Other VPNs' capturing tunnels and the processes holding them.
    fn owners(h: *Helper, a: std.mem.Allocator) ![]proto.Owner {
        const caps = try net.foreignCaptures(a, h.ownIfname());
        var out: std.ArrayList(proto.Owner) = .empty;
        for (caps) |cap| {
            const name = std.mem.sliceTo(&cap.ifname, 0);
            for (out.items) |o| {
                if (std.mem.eql(u8, o.ifname, name)) break;
            } else {
                var o: proto.Owner = .{ .ifname = try a.dupe(u8, name) };
                if (proc.tunnelOwner(a, name)) |pid| if (proc.identity(pid)) |id| {
                    o.pid = id.pid;
                    o.uid = id.uid;
                    o.start_us = id.start_us;
                    o.path = try a.dupe(u8, id.path());
                };
                try out.append(a, o);
            }
        }
        return out.items;
    }

    /// Ask the process the user picked to quit: only if it is still that
    /// process, still holds a capturing tunnel, and is not part of the OS.
    fn stopOwner(h: *Helper, a: std.mem.Allocator, req: proto.Request) !void {
        const id = proc.identity(req.pid) orelse return error.Gone;
        if (id.start_us != req.start_us or !std.mem.eql(u8, id.path(), req.path)) return error.Gone;
        if (!proc.mayStop(&id, &.{proto.install_path})) return error.Protected;
        // a target is what stands in the way: a tunnel's holder, or a DPI tool
        const list = try h.owners(a);
        for (list) |o| {
            if (o.pid == id.pid) break;
        } else if (!isDpiTool(id.path())) return error.NotATunnelOwner;
        // a launchd daemon with KeepAlive comes straight back after a
        // signal: stopping the service is unloading its job (until the next
        // boot, or until its app loads it again)
        if (id.ppid == 1) if (launchdLabel(a, h.io, id.path())) |label| {
            const target = try std.fmt.allocPrint(a, "system/{s}", .{label});
            const out = try dns.exec(h.gpa, &.{ "/bin/launchctl", "bootout", target }, "");
            defer h.gpa.free(out.text);
            if (out.ok) {
                log.info("unloaded {s} (pid {d}, {s}): it held another VPN's tunnel", .{ label, id.pid, id.path() });
                if (!req.kill) return;
            } else log.warn("launchctl bootout {s}: {s}", .{ label, out.text });
        };
        const sig: std.posix.SIG = if (req.kill) .KILL else .TERM;
        if (c.kill(id.pid, sig) != 0) return error.SignalFailed;
        log.info("{s} pid {d} ({s}): it held another VPN's tunnel", .{ if (req.kill) "killed" else "asked to quit", id.pid, id.path() });
    }

    fn describe(h: *Helper, a: std.mem.Allocator) proto.Reply {
        var dns_list: std.ArrayList([]const u8) = .empty;
        for (h.upstream) |ip| dns_list.append(a, std.fmt.allocPrint(a, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch continue) catch {};
        return .{
            .version = proto.version,
            .build = @import("build_options").version,
            .ok = true,
            .up = h.utun != null,
            .ifname = if (h.utun) |*u| a.dupe(u8, u.ifname()) catch "" else "",
            .bind_index = h.bind_index,
            .bind_name = a.dupe(u8, std.mem.sliceTo(&h.bind_name, 0)) catch "",
            .dns = dns_list.items,
            .killswitch = @tagName(h.killswitch),
        };
    }

    /// One step of the hold from boot: capture as soon as there is a
    /// network to capture, then wait for the service; let go when nobody
    /// came for a while after login.
    fn holdStep(h: *Helper) void {
        if (!h.boot_hold) return;
        const now = Io.Clock.awake.now(h.io).toMilliseconds();
        if (h.utun == null) {
            var arena: std.heap.ArenaAllocator = .init(h.gpa);
            defer arena.deinit();
            // fails until the network is up, and while another VPN is in the way
            h.bringUp(arena.allocator(), .{ .cmd = "up", .killswitch = "selective", .ipv6 = "block" }) catch {
                // only what a half-finished attempt left behind is undone
                if (h.utun != null or h.installed.items.len > 0) h.down();
                return;
            };
            log.info("holding traffic from boot until the service takes over", .{});
        }
        if (!someoneLoggedIn()) return;
        if (h.login_seen_ms == 0) h.login_seen_ms = now;
        if (now - h.login_seen_ms < hold_patience_ms) return;
        log.warn("no service came within {d} s of login: traffic is released", .{hold_patience_ms / 1000});
        h.boot_hold = false;
        h.down();
    }

    fn up(h: *Helper, conn: c.fd_t, a: std.mem.Allocator, req: proto.Request) void {
        // a service is here: the hold from boot has done its job
        h.boot_hold = false;
        if (h.utun != null) {
            // a new service takes over (restart, update): same utun, new settings
            h.reconfigure(req) catch |err| {
                log.err("reconfigure: {t}", .{err});
                return h.reply(conn, a, .{ .@"error" = @errorName(err) }, null);
            };
        } else {
            h.bringUp(a, req) catch |err| {
                if (err == error.Conflict) {
                    var names: std.ArrayList([]const u8) = .empty;
                    const caps = net.foreignCaptures(a, null) catch &.{};
                    for (caps) |cap| {
                        const name = std.mem.sliceTo(&cap.ifname, 0);
                        for (names.items) |n| {
                            if (std.mem.eql(u8, n, name)) break;
                        } else names.append(a, a.dupe(u8, name) catch continue) catch {};
                    }
                    return h.reply(conn, a, .{ .@"error" = "conflict", .conflicts = names.items }, null);
                }
                log.err("up: {t}", .{err});
                h.down();
                return h.reply(conn, a, .{ .@"error" = @errorName(err) }, null);
            };
        }
        h.watchOwner(conn);
        h.reply(conn, a, h.describe(a), h.utun.?.fd);
    }

    /// Settings of an `up` that finds the utun already there.
    fn reconfigure(h: *Helper, req: proto.Request) !void {
        const ks = std.meta.stringToEnum(KillSwitch, req.killswitch) orelse return error.BadKillSwitch;
        var servers: std.ArrayList([4]u8) = .empty;
        defer servers.deinit(h.gpa);
        try parseServers(h.gpa, &servers, req.servers);
        std.mem.swap(std.ArrayList([4]u8), &h.servers, &servers);
        h.allow_lan = req.allow_lan;
        h.ipv6_tunnel = !std.mem.eql(u8, req.ipv6, "block");
        const name = h.utun.?.ifname();
        net.setMtu(name, std.math.clamp(req.mtu, 1280, 9000)) catch |err| log.warn("mtu: {t}", .{err});
        h.captureIpv6(name, !std.mem.eql(u8, req.ipv6, "system"));
        if (ks == .strict) {
            if (h.token == .none) {
                h.token = try pf.enable(h.gpa, h.pfOptions(name));
                writeToken(h.io, h.token);
            } else try pf.reload(h.gpa, h.pfOptions(name));
        } else if (h.token != .none) {
            pf.disable(h.gpa, h.token) catch |err| log.warn("pf disable: {t}", .{err});
            h.token = .none;
            std.Io.Dir.cwd().deleteFile(h.io, state_path) catch {};
        }
        h.killswitch = ks;
        log.info("reconfigured: kill switch {t}", .{ks});
    }

    /// IPv6 routes into the utun on or off.
    fn captureIpv6(h: *Helper, name: []const u8, on: bool) void {
        if (on == h.ipv6_captured) return;
        if (on) {
            net.addAddress6(name, tun_addr6, 126) catch |err| log.warn("ipv6 address: {t}", .{err});
            for (routes6) |r| h.addRoute(r, name) catch |err| log.warn("ipv6 route: {t}", .{err});
        } else {
            var i: usize = 0;
            while (i < h.installed.items.len) {
                const r = h.installed.items[i];
                if (net.isV4(r.dst)) {
                    i += 1;
                    continue;
                }
                net.deleteRoute(r.dst, r.prefix, name) catch {};
                _ = h.installed.swapRemove(i);
            }
        }
        h.ipv6_captured = on;
    }

    /// Remember who holds the utun and get told when it exits.
    fn watchOwner(h: *Helper, conn: c.fd_t) void {
        var pid: c.pid_t = 0;
        var len: c.socklen_t = @sizeOf(c.pid_t);
        if (c.getsockopt(conn, sol_local, local_peerpid, &pid, &len) != 0 or pid <= 0) return;
        h.owner_pid = pid;
        if (h.kq < 0) return;
        const ev = [1]c.Kevent{.{
            .ident = @intCast(pid),
            .filter = c.EVFILT.PROC,
            .flags = c.EV.ADD | c.EV.ONESHOT,
            .fflags = c.NOTE.EXIT,
            .data = 0,
            .udata = 0,
        }};
        var none: [1]c.Kevent = undefined;
        if (c.kevent(h.kq, &ev, 1, &none, 0, null) != 0) log.warn("cannot watch the service (pid {d})", .{pid});
    }

    /// The service went away without "down".
    fn ownerExited(h: *Helper, pid: c.pid_t) void {
        if (pid != h.owner_pid) return;
        h.owner_pid = 0;
        if (h.utun == null) return;
        if (h.killswitch == .off) {
            log.info("service exited; traffic goes back to the normal routes", .{});
            h.down();
        } else {
            log.warn("service exited; traffic stays blocked until it is back (kill switch {t})", .{h.killswitch});
        }
    }

    fn bringUp(h: *Helper, a: std.mem.Allocator, req: proto.Request) !void {
        const ks = std.meta.stringToEnum(KillSwitch, req.killswitch) orelse return error.BadKillSwitch;
        h.ipv6_tunnel = !std.mem.eql(u8, req.ipv6, "block");
        h.allow_lan = req.allow_lan;
        h.servers.clearRetainingCapacity();
        try parseServers(h.gpa, &h.servers, req.servers);

        // another VPN that captures the default space would win over our routes
        const caps = try net.foreignCaptures(a, null);
        if (caps.len > 0) return error.Conflict;

        const def = try net.defaultRoute();
        h.bind_index = def.ifindex;
        h.bind_name = def.ifname;
        if (h.upstream.len > 0) h.gpa.free(h.upstream);
        h.upstream = &.{};
        h.upstream = dns.upstreamServers(h.gpa) catch &.{};

        var u = try net.openUtun();
        errdefer {
            u.close();
            h.utun = null;
        }
        _ = c.fcntl(u.fd, c.F.SETFD, @as(c_int, c.FD_CLOEXEC));
        h.utun = u;
        const name = u.ifname();
        try net.setMtu(name, std.math.clamp(req.mtu, 1280, 9000));
        try net.addAddress4(name, proto.tun_addr, proto.tun_dns);
        for (routes4) |r| try h.addRoute(r, name);
        // IPv6 is captured (tunnelled, or refused by the data plane) unless
        // the user leaves it to the system
        h.ipv6_captured = false;
        h.captureIpv6(name, !std.mem.eql(u8, req.ipv6, "system"));

        try dns.apply(h.gpa, &.{proto.tun_dns}, name);
        if (ks == .strict) {
            h.token = try pf.enable(h.gpa, h.pfOptions(name));
            writeToken(h.io, h.token);
        }
        h.killswitch = ks;
        log.info("up: {s} via {s}, kill switch {t}", .{ name, std.mem.sliceTo(&h.bind_name, 0), ks });
    }

    fn pfOptions(h: *Helper, name: []const u8) pf.Options {
        return .{
            .utun = name,
            .servers4 = h.servers.items,
            .servers6 = &.{},
            .dns4 = h.upstream,
            .allow_lan = h.allow_lan,
            .ipv6 = if (h.ipv6_tunnel) .tunnel else .block,
        };
    }

    fn addRoute(h: *Helper, r: Route, name: []const u8) !void {
        try net.addRoute(r.dst, r.prefix, name);
        try h.installed.append(h.gpa, r);
    }

    fn setServers(h: *Helper, a: std.mem.Allocator, req: proto.Request) !void {
        _ = a;
        h.servers.clearRetainingCapacity();
        try parseServers(h.gpa, &h.servers, req.servers);
        if (h.killswitch == .strict) if (h.utun) |*u| try pf.updateTables(h.gpa, h.pfOptions(u.ifname()));
    }

    /// Back to the state before `up`. Safe to call twice.
    fn down(h: *Helper) void {
        if (h.killswitch == .strict or h.token != .none) {
            pf.disable(h.gpa, h.token) catch |err| log.warn("pf disable: {t}", .{err});
            h.token = .none;
            std.Io.Dir.cwd().deleteFile(h.io, state_path) catch {};
        }
        h.killswitch = .off;
        dns.restore(h.gpa) catch |err| log.warn("dns restore: {t}", .{err});
        if (h.utun) |*u| {
            for (h.installed.items) |r| net.deleteRoute(r.dst, r.prefix, u.ifname()) catch {};
            u.close();
            h.utun = null;
            dns.flushCache(h.gpa);
            log.info("down", .{});
        }
        h.installed.clearRetainingCapacity();
        h.ipv6_captured = false;
        h.owner_pid = 0;
    }
};

// <sys/un.h>: the peer's pid of a connected Unix socket
const sol_local = 0;
const local_peerpid = 0x002;

/// DPI circumvention tools a user may stop from the conflict list.
fn isDpiTool(path: []const u8) bool {
    const base = std.fs.path.basename(path);
    for ([_][]const u8{ "tpws", "dvtws", "nfqws", "ciadpi", "byedpi", "spoofdpi" }) |t| {
        if (std.ascii.eqlIgnoreCase(base, t)) return true;
    }
    return false;
}

const zapret_script = "/opt/zapret/init.d/macos/zapret";

/// zapret's own "stop" (tpws and its pf rules). Only from its standard place,
/// and only if nobody but root could have changed the script or its folders:
/// the helper never runs a file the user could rewrite.
fn stopZapret(gpa: std.mem.Allocator, io: Io) !void {
    var path: []const u8 = zapret_script;
    while (true) {
        try rootOnly(io, path);
        const parent = std.fs.path.dirname(path) orelse break;
        if (std.mem.eql(u8, parent, path)) break;
        path = parent;
    }
    const out = try dns.exec(gpa, &.{ zapret_script, "stop" }, "");
    defer gpa.free(out.text);
    if (!out.ok) {
        log.warn("zapret stop: {s}", .{out.text});
        return error.ZapretStopFailed;
    }
    log.info("stopped zapret with its own script", .{});
}

/// Owned by root and writable by nobody else.
fn rootOnly(io: Io, path: []const u8) !void {
    const st = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch return error.NotFound;
    if (st.kind == .sym_link) return error.Untrusted;
    var z: [std.fs.max_path_bytes:0]u8 = undefined;
    if (path.len >= z.len) return error.Untrusted;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    var s: c.Stat = undefined;
    if (c.fstatat(c.AT.FDCWD, &z, &s, c.AT.SYMLINK_NOFOLLOW) != 0) return error.NotFound;
    if (s.uid != 0 or s.mode & 0o022 != 0) return error.Untrusted;
}

/// The label of the system LaunchDaemon that runs `program`, if one does.
/// Only plists naming exactly this executable count, and labels are
/// checked before they reach a command line.
fn launchdLabel(a: std.mem.Allocator, io: Io, program: []const u8) ?[]const u8 {
    var dir = std.Io.Dir.cwd().openDir(io, "/Library/LaunchDaemons", .{ .iterate = true }) catch return null;
    defer dir.close(io);
    var it = dir.iterate();
    const want = std.fmt.allocPrint(a, "<string>{s}</string>", .{program}) catch return null;
    while (it.next(io) catch null) |entry| {
        if (!std.mem.endsWith(u8, entry.name, ".plist")) continue;
        const text = dir.readFileAlloc(io, entry.name, a, .limited(64 * 1024)) catch continue;
        if (std.mem.indexOf(u8, text, want) == null) continue;
        const label = plistLabel(text) orelse continue;
        return label;
    }
    return null;
}

/// <key>Label</key><string>X</string>, with X made of [A-Za-z0-9._-] only.
fn plistLabel(text: []const u8) ?[]const u8 {
    const key = std.mem.indexOf(u8, text, "<key>Label</key>") orelse return null;
    const open = std.mem.indexOfPos(u8, text, key, "<string>") orelse return null;
    const start = open + "<string>".len;
    const end = std.mem.indexOfPos(u8, text, start, "</string>") orelse return null;
    const label = text[start..end];
    if (label.len == 0 or label.len > 128) return null;
    for (label) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '.' and ch != '_' and ch != '-') return null;
    return label;
}

/// Dotted IPv4 addresses only; anything else is refused.
fn parseServers(gpa: std.mem.Allocator, out: *std.ArrayList([4]u8), list: []const []const u8) !void {
    if (list.len > 256) return error.TooManyServers;
    for (list) |text| {
        const ip = std.Io.net.Ip4Address.parse(text, 0) catch return error.BadServerAddress;
        try out.append(gpa, ip.bytes);
    }
}

fn readToken(gpa: std.mem.Allocator, io: Io) ?pf.Token {
    const text = std.Io.Dir.cwd().readFileAlloc(io, state_path, gpa, .limited(64)) catch return null;
    defer gpa.free(text);
    const v = std.fmt.parseInt(u64, std.mem.trim(u8, text, " \n"), 10) catch return null;
    return @enumFromInt(v);
}

fn writeToken(io: Io, tok: pf.Token) void {
    var buf: [32]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, "{d}\n", .{@intFromEnum(tok)}) catch return;
    std.Io.Dir.cwd().createDirPath(io, state_dir) catch {};
    std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = state_path,
        .data = text,
        .flags = .{ .permissions = .fromMode(0o600) },
    }) catch |err| log.warn("state not saved: {t}", .{err});
}

extern "c" fn getpeereid(fd: c.fd_t, uid: *c.uid_t, gid: *c.gid_t) c_int;

fn serve(h: *Helper) !void {
    std.Io.Dir.cwd().deleteFile(h.io, proto.socket_path) catch {};
    const addr = try std.Io.net.UnixAddress.init(proto.socket_path);
    var server = try addr.listen(h.io, .{});
    defer server.deinit(h.io);
    // anyone may connect; requests from anyone but the owner are dropped
    _ = c.chmod(proto.socket_path, 0o666);

    // one wait for both: a new connection, or the service's exit
    h.kq = c.kqueue();
    if (h.kq < 0) return error.KqueueFailed;
    defer {
        _ = c.close(h.kq);
        h.kq = -1;
    }
    const listen = [1]c.Kevent{.{
        .ident = @intCast(server.socket.handle),
        .filter = c.EVFILT.READ,
        .flags = c.EV.ADD,
        .fflags = 0,
        .data = 0,
        .udata = 0,
    }};
    var events: [8]c.Kevent = undefined;
    if (c.kevent(h.kq, &listen, 1, &events, 0, null) != 0) return error.KqueueFailed;
    log.info("ready, serving uid {d}", .{h.allow_uid});
    h.boot_hold = holdWanted(h.io);
    while (true) {
        h.holdStep();
        // while holding from boot, look again every two seconds
        const tick: c.timespec = .{ .sec = 2, .nsec = 0 };
        const n = c.kevent(h.kq, &listen, 0, &events, events.len, if (h.boot_hold) &tick else null);
        if (n < 0) {
            if (c.errno(n) == .INTR) continue;
            return error.KqueueFailed;
        }
        var incoming = false;
        for (events[0..@intCast(n)]) |ev| {
            if (ev.filter == c.EVFILT.PROC) h.ownerExited(@intCast(ev.ident)) else incoming = true;
        }
        if (!incoming) continue;
        const conn = server.accept(h.io) catch continue;
        defer conn.close(h.io);
        const fd = conn.socket.handle;
        _ = c.fcntl(fd, c.F.SETFD, @as(c_int, c.FD_CLOEXEC));
        var uid: c.uid_t = undefined;
        var gid: c.gid_t = undefined;
        if (getpeereid(fd, &uid, &gid) != 0) continue;
        if (uid != h.allow_uid and uid != 0) continue;
        h.handle(fd);
    }
}

/// Remember (across reboots) whether traffic is held from boot.
fn setHold(io: Io, on: bool) void {
    const cwd = std.Io.Dir.cwd();
    if (on) {
        cwd.createDirPath(io, state_dir) catch {};
        cwd.writeFile(io, .{ .sub_path = hold_path, .data = "" }) catch |err| log.warn("hold flag: {t}", .{err});
    } else cwd.deleteFile(io, hold_path) catch {};
}

fn holdWanted(io: Io) bool {
    std.Io.Dir.cwd().access(io, hold_path, .{}) catch return false;
    return true;
}

/// Whether a user sits at the Mac: the console device belongs to whoever
/// is logged in at the screen, and to root before that.
fn someoneLoggedIn() bool {
    var s: c.Stat = undefined;
    if (c.fstatat(c.AT.FDCWD, "/dev/console", &s, 0) != 0) return true;
    return s.uid != 0;
}

// ---------------------------------------------------------------- install

fn plist(a: std.mem.Allocator, uid: u32) ![]u8 {
    return std.fmt.allocPrint(a,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<plist version="1.0">
        \\<dict>
        \\  <key>Label</key><string>{s}</string>
        \\  <key>ProgramArguments</key>
        \\  <array><string>{s}</string><string>run</string><string>--allow-uid</string><string>{d}</string></array>
        \\  <key>RunAtLoad</key><true/>
        \\  <key>KeepAlive</key><true/>
        \\  <key>ProcessType</key><string>Interactive</string>
        \\  <key>StandardErrorPath</key><string>/var/log/blackwall-helper.log</string>
        \\</dict>
        \\</plist>
        \\
    , .{ proto.label, proto.install_path, uid });
}

fn install(gpa: std.mem.Allocator, io: Io, uid: u32) !void {
    const self = try std.process.executablePathAlloc(io, gpa);
    defer gpa.free(self);
    if (!std.mem.eql(u8, self, proto.install_path)) {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(io, self, gpa, .limited(64 << 20));
        defer gpa.free(bytes);
        try std.Io.Dir.cwd().createDirPath(io, "/Library/PrivilegedHelperTools");
        const tmp = proto.install_path ++ ".new";
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = tmp, .data = bytes, .flags = .{ .permissions = .fromMode(0o755) } });
        try std.Io.Dir.rename(.cwd(), tmp, .cwd(), proto.install_path, io);
    }
    const text = try plist(gpa, uid);
    defer gpa.free(text);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = proto.plist_path, .data = text, .flags = .{ .permissions = .fromMode(0o644) } });
    const out1 = dns.exec(gpa, &.{ "/bin/launchctl", "bootout", "system/" ++ proto.label }, "") catch null;
    if (out1) |o| gpa.free(o.text);
    const out2 = try dns.exec(gpa, &.{ "/bin/launchctl", "bootstrap", "system", proto.plist_path }, "");
    defer gpa.free(out2.text);
    if (!out2.ok) {
        std.debug.print("launchctl bootstrap failed: {s}\n", .{out2.text});
        return error.LaunchctlFailed;
    }
    std.debug.print("installed {s} for uid {d}\n", .{ proto.install_path, uid });
}

fn uninstall(gpa: std.mem.Allocator, io: Io) !void {
    const out = dns.exec(gpa, &.{ "/bin/launchctl", "bootout", "system/" ++ proto.label }, "") catch null;
    if (out) |o| gpa.free(o.text);
    var h: Helper = .{ .gpa = gpa, .io = io, .allow_uid = 0 };
    h.recover();
    for ([_][]const u8{ proto.plist_path, proto.install_path, proto.socket_path, state_path, hold_path }) |p|
        std.Io.Dir.cwd().deleteFile(io, p) catch {};
    std.debug.print("uninstalled\n", .{});
}

pub fn main(init: std.process.Init) !void {
    if (builtin.os.tag != .macos) return error.Unsupported;
    const a = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(a);
    if (argv.len < 2) return usage();
    if (c.geteuid() != 0) {
        std.debug.print("blackwall-helper must run as root (sudo)\n", .{});
        return error.NotRoot;
    }
    const cmd = argv[1];
    if (std.mem.eql(u8, cmd, "run")) {
        if (argv.len != 4 or !std.mem.eql(u8, argv[2], "--allow-uid")) return usage();
        const uid = try std.fmt.parseInt(u32, argv[3], 10);
        var h: Helper = .{ .gpa = init.gpa, .io = init.io, .allow_uid = uid };
        h.recover();
        defer h.down();
        try serve(&h);
    } else if (std.mem.eql(u8, cmd, "install")) {
        // the user who ran sudo owns the helper
        var uid: ?u32 = null;
        if (argv.len == 4 and std.mem.eql(u8, argv[2], "--uid")) uid = try std.fmt.parseInt(u32, argv[3], 10);
        if (uid == null) if (init.environ_map.get("SUDO_UID")) |s| {
            uid = std.fmt.parseInt(u32, s, 10) catch null;
        };
        try install(init.gpa, init.io, uid orelse return usage());
    } else if (std.mem.eql(u8, cmd, "uninstall")) {
        try uninstall(init.gpa, init.io);
    } else return usage();
}

fn usage() error{Usage} {
    std.debug.print(
        \\usage: blackwall-helper run --allow-uid UID
        \\       sudo blackwall-helper install [--uid UID]
        \\       sudo blackwall-helper uninstall
        \\
    , .{});
    return error.Usage;
}

test {
    _ = net;
    _ = dns;
    _ = pf;
    _ = proc;
}

test "DPI tools by name, and root-only checks" {
    try std.testing.expect(isDpiTool("/opt/zapret/tpws/tpws"));
    try std.testing.expect(isDpiTool("/usr/local/bin/ciadpi"));
    try std.testing.expect(!isDpiTool("/Applications/Safari.app/Contents/MacOS/Safari"));
    // a folder every user may write is never trusted
    try std.testing.expectError(error.Untrusted, rootOnly(std.testing.io, "/tmp"));
    try rootOnly(std.testing.io, "/usr/bin/true");
}

test "launchd labels are read strictly" {
    try std.testing.expectEqualStrings("com.happ.happd", plistLabel("<dict>\n    <key>Label</key>\n    <string>com.happ.happd</string>").?);
    try std.testing.expect(plistLabel("<key>Label</key><string>x; rm -rf /</string>") == null);
    try std.testing.expect(plistLabel("<key>Label</key><string></string>") == null);
}

test "launchd plist names the installed binary and the owner" {
    const text = try plist(std.testing.allocator, 501);
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "<string>" ++ proto.install_path ++ "</string><string>run</string><string>--allow-uid</string><string>501</string>") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "<key>KeepAlive</key><true/>") != null);
}

test "only dotted IPv4 server addresses pass" {
    var list: std.ArrayList([4]u8) = .empty;
    defer list.deinit(std.testing.allocator);
    try parseServers(std.testing.allocator, &list, &.{ "203.0.113.7", "1.1.1.1" });
    try std.testing.expectEqual(2, list.items.len);
    try std.testing.expectError(error.BadServerAddress, parseServers(std.testing.allocator, &list, &.{"1.1.1.1; rm -rf /"}));
    try std.testing.expectError(error.BadServerAddress, parseServers(std.testing.allocator, &list, &.{"example.com"}));
}

test "requests parse with defaults" {
    const r = try std.json.parseFromSlice(proto.Request, std.testing.allocator, "{\"cmd\":\"up\",\"killswitch\":\"strict\",\"servers\":[\"203.0.113.7\"]}", .{ .ignore_unknown_fields = true });
    defer r.deinit();
    try std.testing.expectEqualStrings("strict", r.value.killswitch);
    try std.testing.expectEqual(1500, r.value.mtu);
    try std.testing.expect(std.meta.stringToEnum(KillSwitch, "strict").? == .strict);
    try std.testing.expect(std.meta.stringToEnum(KillSwitch, "everything") == null);
}
