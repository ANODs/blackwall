//! BLACKWALL background service: the data plane without the window.
//!
//!   blackwall-service [--config DIR] [--tun helper | --tun auto | --tun linux:NAME | --tun fd:N]
//!                     [--bind IFNAME] [--dns IP[:PORT]]... [--mtu N] [--socks PORT]
//!
//! --tun helper (macOS): the root helper creates the utun, routes and DNS,
//! applies the kill switch from the settings and hands the utun over.
//!
//! --tun wintun (Windows, as LocalSystem or an administrator): the
//! service creates the Wintun adapter and its routes itself (windows.zig);
//! wintun.dll is next to the executable.
//!
//! --tun auto (Linux): the device, the routes and the capture of the
//! resolvers (linux.zig) are set up by blackwall-tun, which holds
//! CAP_NET_ADMIN and hands the device over (tun_main.zig); run as root the
//! service does it itself. Connections are matched to their programs
//! through /proc (linux_proc.zig), and the strict kill switch is an
//! nftables table (nft.zig). `--release` removes a device that a service
//! which is gone left behind.
//!
//! Reads the configuration the app writes (config.json in DIR), carries the
//! traffic of applications routed into the TUN and/or the SOCKS port, and
//! answers the app on DIR/service.sock (see core/ipc.zig). Closing the window
//! does not touch it; it stops only when asked or killed.
//!
//! The TUN's addresses and routes are set up by whoever starts the service:
//! the root helper on macOS, a script or systemd on Linux.

const std = @import("std");
const builtin = @import("builtin");
const core = @import("core");
const build_options = @import("build_options");
const routes = @import("routes.zig");
const fdpass = @import("fdpass");
const linux = @import("linux.zig");
const linux_proc = @import("linux_proc.zig");
const win = @import("windows.zig");
const win_owner = @import("win_owner.zig");
const on_windows = builtin.os.tag == .windows;
const darwin = if (builtin.os.tag.isDarwin()) struct {
    const process = @import("darwin/process.zig");
    const helper = @import("helper_client.zig");
} else struct {};

const Io = std.Io;
const c = std.c;
const tunnel = core.tunnel;
const proxy = core.proxy;
const ipc = core.ipc;
const packet = core.ipstack.packet;

const log = std.log.scoped(.service);

pub const std_options: std.Options = .{ .logFn = logFn };

/// service.events in the configuration folder: what the log says, with
/// the time, kept across restarts (the window starts each run's
/// service.log afresh). Lets "why did it stop working" be answered later.
var events_fd: if (on_windows) ?std.os.windows.HANDLE else c.fd_t = if (on_windows) null else -1;
const events_name = "service.events";
const events_max = 512 * 1024;

/// struct tm (the same leading fields on macOS and Linux; the tail is padding here)
const Tm = extern struct { sec: c_int, min: c_int, hour: c_int, mday: c_int, mon: c_int, year: c_int, wday: c_int, yday: c_int, isdst: c_int, rest: [32]u8 };
extern "c" fn time(t: ?*i64) i64;
extern "c" fn localtime_r(t: *const i64, out: *Tm) ?*Tm;

/// Windows: the calls the events file needs (kernel32).
const k32 = struct {
    const W: std.builtin.CallingConvention = .winapi;
    const SYSTEMTIME = extern struct { year: u16, month: u16, wday: u16, day: u16, hour: u16, min: u16, sec: u16, ms: u16 };
    extern "kernel32" fn CreateFileW(name: [*:0]const u16, access: u32, share: u32, sa: ?*anyopaque, disp: u32, flags: u32, template: ?std.os.windows.HANDLE) callconv(W) std.os.windows.HANDLE;
    extern "kernel32" fn WriteFile(h: std.os.windows.HANDLE, buf: [*]const u8, n: u32, written: ?*u32, ov: ?*anyopaque) callconv(W) i32;
    extern "kernel32" fn GetLocalTime(t: *SYSTEMTIME) callconv(W) void;
    extern "kernel32" fn GetCurrentProcessId() callconv(W) u32;
};

fn openEvents(io: Io, config_dir: []const u8) void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    var old_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(buf[0 .. buf.len - 1], "{s}/" ++ events_name, .{config_dir}) catch return;
    buf[path.len] = 0;
    const old = std.fmt.bufPrint(&old_buf, "{s}/" ++ events_name ++ ".1", .{config_dir}) catch return;
    const cwd = std.Io.Dir.cwd();
    if (cwd.statFile(io, path, .{})) |st| {
        if (st.size > events_max) cwd.rename(path, cwd, old, io) catch {};
    } else |_| {}
    if (comptime on_windows) {
        var wide: [std.fs.max_path_bytes:0]u16 = undefined;
        const n = std.unicode.wtf8ToWtf16Le(&wide, path) catch return;
        wide[n] = 0;
        // FILE_APPEND_DATA, shared for reading, OPEN_ALWAYS
        const h = k32.CreateFileW(wide[0..n :0], 0x4, 0x1 | 0x2, null, 4, 0x80, null);
        if (h != std.os.windows.INVALID_HANDLE_VALUE) events_fd = h;
        return;
    }
    events_fd = c.open(@ptrCast(path.ptr), .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .CLOEXEC = true }, @as(c.mode_t, 0o600));
}

fn logFn(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime format: []const u8, args: anytype) void {
    std.log.defaultLog(level, scope, format, args);
    if (if (on_windows) events_fd == null else events_fd < 0) return;
    var buf: [640]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    var mon: u32 = 0;
    var day: u32 = 0;
    var hour: u32 = 0;
    var min: u32 = 0;
    var sec: u32 = 0;
    if (comptime on_windows) {
        var st: k32.SYSTEMTIME = undefined;
        k32.GetLocalTime(&st);
        mon = st.month;
        day = st.day;
        hour = st.hour;
        min = st.min;
        sec = st.sec;
    } else {
        var now: i64 = time(null);
        var tm: Tm = undefined;
        _ = localtime_r(&now, &tm);
        mon = @intCast(tm.mon + 1);
        day = @intCast(tm.mday);
        hour = @intCast(tm.hour);
        min = @intCast(tm.min);
        sec = @intCast(tm.sec);
    }
    w.print("{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} {s}({s}): ", .{ mon, day, hour, min, sec, @tagName(level), @tagName(scope) }) catch {};
    w.print(format, args) catch {};
    // a line cut short still ends as a line
    if (w.end >= buf.len) w.end = buf.len - 1;
    w.writeByte('\n') catch {};
    const line = w.buffered();
    if (comptime on_windows) {
        _ = k32.WriteFile(events_fd.?, line.ptr, @intCast(line.len), null, null);
    } else _ = c.write(events_fd, line.ptr, line.len);
}

const Args = struct {
    config_dir: ?[]const u8 = null,
    tun: ?Tun = null,
    bind: ?[]const u8 = null,
    dns: std.ArrayList(packet.Endpoint) = .empty,
    mtu: u16 = 1500,
    socks: ?u16 = null,

    const Tun = union(enum) { helper, auto, wintun, linux: []const u8, fd: i32 };
};

const Service = struct {
    gpa: std.mem.Allocator,
    io: Io,
    args: Args,
    config_dir: []const u8,
    t: ?*tunnel.Tunnel = null,
    device: tunnel.Device = undefined,
    device_thread: ?std.Thread = null,
    socks: ?*proxy.Proxy = null,
    built: ?routes.Built = null,
    settings: core.model.Settings = .{},
    /// VPN server addresses, for the strict kill switch
    server_ips: std.ArrayList([]const u8) = .empty,
    tun_fd: ?i32 = null,
    /// the Wintun adapter and its routes (Windows)
    lease: if (on_windows) ?win.Lease else void = if (on_windows) null else {},
    via_helper: bool = false,
    /// the device is ours to set up and take down (Linux, `--tun auto`)
    own_device: bool = false,
    /// "suspend": leave the helper's capture in place (the kill switch decides)
    keep_capture: bool = false,
    searcher: if (builtin.os.tag.isDarwin()) darwin.process.Searcher else void = undefined,
    /// resolvers the service itself asks (Linux strict kill switch)
    dns4: [8][4]u8 = undefined,
    dns4_len: usize = 0,
    /// who owns a connection (Linux, `--tun auto`)
    owners: if (builtin.os.tag == .linux) linux_proc.Searcher else if (on_windows) win_owner.Searcher else void = undefined,
    stopping: std.atomic.Value(bool) = .init(false),

    /// The kill switch the helper holds. In standby direct traffic must
    /// pass (strict would stop it) and a crash must not release the
    /// applications being held (off would): selective does both.
    fn killSwitch(s: *const Service) core.model.KillSwitch {
        return if (s.settings.standby) .selective else s.settings.kill_switch;
    }

    /// Server id of the group's server in use; 0 when there is none.
    fn serverInUse(s: *Service) u32 {
        const t = s.t orelse return 0;
        const b = s.built orelse return 0;
        const i = t.mainInUse();
        if (i >= b.cfg.main.len) return 0;
        return b.ids[b.cfg.main[i]];
    }

    fn loadConfig(s: *Service) !void {
        var state: core.model.State = .init(s.gpa);
        defer state.deinit();
        _ = core.store.load(s.gpa, s.io, s.config_dir, &state) catch |err| {
            log.warn("config not readable ({t}); everything is blocked", .{err});
        };
        var b = try routes.build(s.gpa, &state);
        errdefer b.deinit();
        s.settings = state.settings;
        for (s.server_ips.items) |ip| s.gpa.free(ip);
        s.server_ips.clearRetainingCapacity();
        // only the strict kill switch needs them (its pf table), and only
        // for the servers the routes use: a long list would hold up reloads
        if (s.args.tun != null and s.settings.kill_switch == .strict) {
            for (b.cfg.outbounds, 0..) |ob, i| {
                if (!routes.uses(b.cfg, @intCast(i))) continue;
                const host = ob.host() orelse continue;
                if (s.serverAddress(host)) |ip| s.server_ips.append(s.gpa, ip) catch s.gpa.free(ip);
            }
        }
        if (s.via_helper and builtin.os.tag.isDarwin()) darwin.helper.servers(s.gpa, s.io, s.server_ips.items);
        s.applyFirewall();
        if (s.t) |t| try t.setConfig(b.cfg);
        if (s.built) |*old| old.deinit();
        s.built = b;
        if (s.settings.standby)
            log.info("config: standby, {d} rules held", .{b.cfg.rules.len})
        else
            log.info("config: {d} outbounds, {d} rules, {d} in reserve, {d} servers not supported", .{ b.cfg.outbounds.len, b.cfg.rules.len, b.cfg.main.len -| 1, b.skipped });
    }

    /// IPv4 address of a server, as text (caller frees). Once the TUN is up
    /// the system resolver answers with fake addresses, so the tunnel's own
    /// resolver (real DNS through the physical interface) is asked instead.
    fn serverAddress(s: *Service, host: []const u8) ?[]const u8 {
        if (s.t) |t| {
            if (std.Io.net.Ip4Address.parse(host, 0)) |_| return s.gpa.dupe(u8, host) catch null else |_| {}
            const addr = t.resolver.resolve(host) catch return null;
            if (!packet.isV4(&addr)) return null;
            return std.fmt.allocPrint(s.gpa, "{d}.{d}.{d}.{d}", .{ addr[12], addr[13], addr[14], addr[15] }) catch null;
        }
        return resolve4(s.gpa, host);
    }

    fn start(s: *Service) !void {
        try s.loadConfig();
        if (s.args.tun) |tun| outer: {
            if (comptime on_windows) {
                try s.startWintun(tun);
                break :outer;
            }
            var bind: core.sys.Bind = if (s.args.bind) |name| .interface(name) else .none;
            var dns_buf: [8]packet.Endpoint = undefined;
            var dns_servers: []const packet.Endpoint = if (s.args.dns.items.len > 0) s.args.dns.items else &default_dns;
            var lookup: ?tunnel.AppLookup = null;
            const fd: c.fd_t = switch (tun) {
                .fd => |f| f,
                .wintun => return error.Unsupported,
                .linux => |name| if (builtin.os.tag == .linux) try linux.openTun(name) else return error.Unsupported,
                .auto => if (builtin.os.tag == .linux) blk: {
                    const opts: linux.Options = .{
                        .mtu = s.args.mtu,
                        // the device that stays behind a dead service is the kill switch
                        .hold = s.killSwitch() != .off,
                        .ipv6 = s.settings.ipv6 != .system,
                    };
                    // as root (systemd) the service does it itself; as the user it
                    // asks blackwall-tun, also for a device it held before, which
                    // it could open again but not set up
                    const as_user = c.geteuid() != 0;
                    const lease = (if (as_user) tunHelper(s.gpa, s.io, opts) else linux.up(s.io, s.gpa, opts)) catch |err| switch (err) {
                        error.NeedsAdministrator => (if (as_user) err else tunHelper(s.gpa, s.io, opts)) catch |e| {
                            s.writeError(e);
                            return e;
                        },
                        else => {
                            s.writeError(err);
                            return err;
                        },
                    };
                    s.own_device = true;
                    bind = .interface(lease.bindName());
                    s.owners = .init(s.gpa, s.io);
                    lookup = .{ .ctx = &s.owners, .find = findLinuxApp };
                    for (lease.dns[0..lease.dns_len], 0..) |ip, k| dns_buf[k] = .{ .addr = packet.v4(ip), .port = 53 };
                    if (lease.dns_len > 0) dns_servers = dns_buf[0..lease.dns_len];
                    log.info("device {s}, own traffic on {s}, {d} resolvers captured", .{ linux.device, lease.bindName(), lease.dns_len });
                    for (lease.dns[0..lease.dns_len]) |ip| s.addDns(ip);
                    for (core.ipstack.dns.Resolver.public_servers) |e| s.addDns(e.addr[12..16].*);
                    break :blk lease.fd;
                } else return error.Unsupported,
                .helper => if (builtin.os.tag.isDarwin()) blk: {
                    const lease = darwin.helper.up(s.gpa, s.io, .{
                        .cmd = "up",
                        .mtu = s.args.mtu,
                        .killswitch = @tagName(s.killSwitch()),
                        .ipv6 = @tagName(s.settings.ipv6),
                        .allow_lan = s.settings.allow_lan,
                        .servers = s.server_ips.items,
                    }) catch |err| {
                        if (err == error.Conflict) {
                            for (darwin.helper.conflict_names[0..darwin.helper.conflict_count]) |n|
                                log.err("another VPN captures traffic through {s}", .{std.mem.sliceTo(&n, 0)});
                        }
                        s.writeError(err);
                        return err;
                    };
                    s.via_helper = true;
                    bind = .{ .index = lease.bind_index };
                    for (lease.upstream(), 0..) |ip, k| dns_buf[k] = .{ .addr = packet.v4(ip), .port = 53 };
                    if (lease.dns_len > 0) dns_servers = dns_buf[0..lease.dns_len];
                    s.searcher = .init(s.gpa);
                    lookup = .{ .ctx = &s.searcher, .find = findApp };
                    log.info("utun {s} from the helper, own traffic on interface {d}", .{ std.mem.sliceTo(&lease.ifname, 0), lease.bind_index });
                    break :blk lease.fd;
                } else return error.Unsupported,
            };
            s.tun_fd = fd;
            s.applyFirewall();
            const t = try tunnel.Tunnel.create(s.gpa, s.io, .{ .mtu = s.args.mtu, .bind = bind, .upstream_dns = dns_servers, .lookup = lookup });
            errdefer t.destroy();
            try t.setConfig(s.built.?.cfg);
            s.device = try .init(fd, builtin.os.tag.isDarwin());
            s.t = t;
            s.device_thread = try std.Thread.spawn(.{ .stack_size = core.sys.stackSize(512 * 1024) }, tunnel.Tunnel.run, .{ t, &s.device });
            log.info("tun up (fd {d}, mtu {d})", .{ fd, s.args.mtu });
        }
        if (s.args.socks) |port| {
            const p = try s.gpa.create(proxy.Proxy);
            p.* = .{ .io = s.io };
            const cfg = s.built.?.cfg;
            p.setOutbound(switch (cfg.default) {
                .direct => .direct,
                .block => .block,
                .outbound => |i| cfg.outbounds[i],
                // the port has no reserve: it stays on the main server
                .main => if (cfg.main.len > 0) cfg.outbounds[cfg.main[0]] else .block,
            });
            if (s.t) |t| {
                p.extra = &t.meter;
                p.dialer = t.dialer;
            }
            try p.start(port);
            s.socks = p;
            log.info("socks5 on 127.0.0.1:{d}", .{p.port});
        }
    }

    /// Windows: the adapter, its routes and the tunnel on it (windows.zig).
    fn startWintun(s: *Service, tun: Args.Tun) !void {
        if (comptime !on_windows) return error.Unsupported;
        if (tun != .wintun) return error.Unsupported;
        var dll_buf: [std.fs.max_path_bytes]u8 = undefined;
        const dir_len = std.process.executableDirPath(s.io, &dll_buf) catch return error.WintunMissing;
        const dll = std.fmt.bufPrint(dll_buf[dir_len..], "\\wintun.dll", .{}) catch return error.WintunMissing;
        const path = dll_buf[0 .. dir_len + dll.len];
        s.lease = win.up(.{ .mtu = s.args.mtu, .ipv6 = s.settings.ipv6 != .system, .dll = path }) catch |err| {
            s.writeError(err);
            return err;
        };
        const lease = &s.lease.?;
        errdefer {
            win.down(lease);
            s.lease = null;
        }
        var dns_buf: [8]packet.Endpoint = undefined;
        var dns_servers: []const packet.Endpoint = if (s.args.dns.items.len > 0) s.args.dns.items else &default_dns;
        for (lease.dns[0..lease.dns_len], 0..) |ip, k| dns_buf[k] = .{ .addr = packet.v4(ip), .port = 53 };
        if (lease.dns_len > 0) dns_servers = dns_buf[0..lease.dns_len];
        for (lease.dns[0..lease.dns_len]) |ip| s.addDns(ip);
        for (core.ipstack.dns.Resolver.public_servers) |e| s.addDns(e.addr[12..16].*);
        log.info("adapter {d}, own traffic on interface {d}, {d} resolvers captured", .{ lease.index, lease.bind_index, lease.dns_len });
        s.owners = .init(s.gpa, s.io);
        const lookup: tunnel.AppLookup = .{ .ctx = &s.owners, .find = findWinApp };
        const t = try tunnel.Tunnel.create(s.gpa, s.io, .{ .mtu = s.args.mtu, .bind = .{ .index = lease.bind_index }, .upstream_dns = dns_servers, .lookup = lookup });
        errdefer t.destroy();
        try t.setConfig(s.built.?.cfg);
        s.t = t;
        s.device_thread = try std.Thread.spawn(.{ .stack_size = 512 * 1024 }, tunnel.Tunnel.run, .{ t, &lease.device });
        log.info("tun up (wintun, mtu {d})", .{s.args.mtu});
    }

    fn shutdown(s: *Service) void {
        if (s.socks) |p| {
            p.stop();
            s.gpa.destroy(p);
            s.socks = null;
        }
        if (s.t) |t| {
            t.stop();
            if (s.device_thread) |th| th.join();
            t.destroy();
            if (comptime on_windows) {
                if (s.lease) |*l| {
                    l.device.deinit();
                    win.down(l);
                    s.owners.deinit();
                }
                s.lease = null;
            } else s.device.deinit();
            s.t = null;
        }
        if (s.tun_fd) |fd| if (comptime !on_windows) {
            // a clean stop lets the traffic go; "suspend" (and a crash,
            // which never gets here) leaves the device holding it
            if (s.own_device and !s.keep_capture) {
                linux.release(fd);
                s.runTunTool(&.{"open"});
            }
            if (builtin.os.tag == .linux and s.own_device) s.owners.deinit();
            _ = c.close(fd);
        };
        s.tun_fd = null;
        s.own_device = false;
        if (builtin.os.tag.isDarwin()) {
            if (s.via_helper) {
                if (!s.keep_capture) darwin.helper.down(s.gpa, s.io);
                s.searcher.deinit();
            }
        }
        s.via_helper = false;
        if (s.built) |*b| b.deinit();
        s.built = null;
        for (s.server_ips.items) |ip| s.gpa.free(ip);
        s.server_ips.deinit(s.gpa);
    }

    fn addDns(s: *Service, ip: [4]u8) void {
        for (s.dns4[0..s.dns4_len]) |have| if (std.mem.eql(u8, &have, &ip)) return;
        if (s.dns4_len == s.dns4.len) return;
        s.dns4[s.dns4_len] = ip;
        s.dns4_len += 1;
    }

    /// The strict kill switch on Linux: an nftables table that outlives the
    /// service (nft.zig), set and removed by blackwall-tun.
    fn applyFirewall(s: *Service) void {
        if (builtin.os.tag != .linux or !s.own_device) return;
        if (s.killSwitch() != .strict) return s.runTunTool(&.{"open"});
        var servers: std.ArrayList(u8) = .empty;
        defer servers.deinit(s.gpa);
        for (s.server_ips.items, 0..) |ip, i| {
            if (i > 0) servers.append(s.gpa, ',') catch return;
            servers.appendSlice(s.gpa, ip) catch return;
        }
        var dns: std.ArrayList(u8) = .empty;
        defer dns.deinit(s.gpa);
        for (s.dns4[0..s.dns4_len], 0..) |ip, i| {
            var b: [16]u8 = undefined;
            const t = std.fmt.bufPrint(&b, "{s}{d}.{d}.{d}.{d}", .{ if (i > 0) "," else "", ip[0], ip[1], ip[2], ip[3] }) catch return;
            dns.appendSlice(s.gpa, t) catch return;
        }
        var argv_buf: [8][]const u8 = undefined;
        var argv: std.ArrayList([]const u8) = .initBuffer(&argv_buf);
        argv.appendSliceAssumeCapacity(&.{ "strict", "--servers", servers.items, "--dns", dns.items });
        if (s.settings.allow_lan) argv.appendAssumeCapacity("--lan");
        if (s.settings.ipv6 == .block) argv.appendAssumeCapacity("--ipv6-block");
        s.runTunTool(argv.items);
    }

    /// blackwall-tun next to this executable, with `args`.
    fn runTunTool(s: *Service, args: []const []const u8) void {
        if (builtin.os.tag != .linux) return;
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const tool = tunToolPath(&path_buf) orelse return;
        var argv_buf: [10][]const u8 = undefined;
        var argv: std.ArrayList([]const u8) = .initBuffer(&argv_buf);
        argv.appendAssumeCapacity(tool);
        argv.appendSliceAssumeCapacity(args);
        var child = std.process.spawn(s.io, .{ .argv = argv.items, .stdin = .ignore, .stdout = .ignore, .stderr = .inherit }) catch |err| {
            log.err("blackwall-tun {s}: {t}", .{ args[0], err });
            return;
        };
        const term = child.wait(s.io) catch return;
        if (term != .exited or term.exited != 0) log.err("blackwall-tun {s} failed", .{args[0]}) else log.info("kill switch: {s}", .{args[0]});
    }

    /// Why the service could not start, for the window to show.
    fn writeError(s: *Service, err: anyerror) void {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "{s}/" ++ ipc.error_name, .{s.config_dir}) catch return;
        var text: [256]u8 = undefined;
        var w: Io.Writer = .fixed(&text);
        w.print("{t}", .{err}) catch {};
        if (builtin.os.tag.isDarwin() and err == error.Conflict) {
            for (darwin.helper.conflict_names[0..darwin.helper.conflict_count]) |n| w.print(" {s}", .{std.mem.sliceTo(&n, 0)}) catch {};
        }
        std.Io.Dir.cwd().writeFile(s.io, .{ .sub_path = path, .data = w.buffered() }) catch {};
    }

    fn status(s: *Service, out: *Io.Writer) !void {
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        var apps: std.ArrayList(ipc.AppStatus) = .empty;
        var total: proxy.Meter = .{};
        if (s.t) |t| {
            const Ctx = struct { a: std.mem.Allocator, list: *std.ArrayList(ipc.AppStatus) };
            const visit = struct {
                fn f(ctx: Ctx, id: []const u8, m: *const proxy.Meter) void {
                    ctx.list.append(ctx.a, .{
                        .id = ctx.a.dupe(u8, id) catch return,
                        .down = m.down.load(.monotonic),
                        .up = m.up.load(.monotonic),
                        .active = m.active.load(.monotonic),
                    }) catch {};
                }
            }.f;
            t.eachApp(Ctx{ .a = a, .list = &apps }, visit);
            addMeter(&total, &t.meter);
        }
        if (s.socks) |p| addMeter(&total, &p.meter);
        // reported once: the window shows each fault a single time
        var fault: proxy.Fault = .none;
        if (s.t) |t| fault = t.meter.fault.swap(.none, .monotonic);
        if (s.socks) |p| {
            const f = p.meter.fault.swap(.none, .monotonic);
            if (fault == .none) fault = f;
        }
        const st: ipc.Status = .{
            .pid = if (comptime on_windows) @intCast(k32.GetCurrentProcessId()) else c.getpid(),
            .build = build_options.version,
            .tun = s.t != null,
            .socks_port = if (s.socks) |p| p.port else 0,
            .down = total.down.raw,
            .up = total.up.raw,
            .active = total.active.raw,
            .failed = total.failed.raw,
            .direct = total.direct_down.raw,
            .fault = @tagName(fault),
            .skipped = if (s.built) |b| b.skipped else 0,
            .server = s.serverInUse(),
            .switches = if (s.t) |t| t.mainSwitches() else 0,
            .standby = s.settings.standby,
            .apps = apps.items,
        };
        try std.json.Stringify.value(st, .{}, out);
        try out.writeByte('\n');
    }

    fn addMeter(into: *proxy.Meter, m: *const proxy.Meter) void {
        into.down.raw += m.down.load(.monotonic);
        into.up.raw += m.up.load(.monotonic);
        into.active.raw += m.active.load(.monotonic);
        into.failed.raw += m.failed.load(.monotonic);
        into.direct_down.raw += m.direct_down.load(.monotonic);
    }

    /// The window's socket. It stays open until the shutdown is complete,
    /// so a window waiting for the service to go sees it go only then.
    fn listen(s: *Service, path: []const u8) !std.Io.net.Server {
        std.Io.Dir.cwd().deleteFile(s.io, path) catch {};
        const addr = try std.Io.net.UnixAddress.init(path);
        const server = try addr.listen(s.io, .{});
        // the socket file is the access control: owner only
        var z: [std.fs.max_path_bytes:0]u8 = undefined;
        @memcpy(z[0..path.len], path);
        z[path.len] = 0;
        // Windows: the folder's own permissions (the user's profile) guard it
        if (comptime !on_windows) _ = c.chmod(&z, 0o600);
        log.info("listening on {s}", .{path});
        return server;
    }

    /// Serve the window until "stop".
    fn serveIpc(s: *Service, server: *std.Io.net.Server) void {
        while (!s.stopping.load(.acquire)) {
            const conn = server.accept(s.io) catch continue;
            defer conn.close(s.io);
            if (!s.peerAllowed(conn.socket.handle)) continue;
            var rb: [1024]u8 = undefined;
            var r = conn.reader(s.io, &rb);
            var wb: [64 * 1024]u8 = undefined;
            var w = conn.writer(s.io, &wb);
            const line = r.interface.takeDelimiterExclusive('\n') catch continue;
            const req = std.json.parseFromSlice(ipc.Request, s.gpa, line, .{ .ignore_unknown_fields = true }) catch {
                w.interface.writeAll("{\"error\":\"bad request\"}\n") catch {};
                w.interface.flush() catch {};
                continue;
            };
            defer req.deinit();
            const cmd = req.value.cmd;
            if (std.mem.eql(u8, cmd, "status")) {
                s.status(&w.interface) catch {};
            } else if (std.mem.eql(u8, cmd, "reload")) {
                s.loadConfig() catch |err| log.err("reload: {t}", .{err});
                w.interface.writeAll("{\"ok\":true}\n") catch {};
            } else if (std.mem.eql(u8, cmd, "stop") or std.mem.eql(u8, cmd, "suspend")) {
                s.keep_capture = std.mem.eql(u8, cmd, "suspend");
                w.interface.writeAll("{\"ok\":true}\n") catch {};
                w.interface.flush() catch {};
                s.stopping.store(true, .release);
                break;
            } else {
                w.interface.writeAll("{\"error\":\"unknown command\"}\n") catch {};
            }
            w.interface.flush() catch {};
        }
    }

    fn peerAllowed(s: *Service, fd: c.fd_t) bool {
        _ = s;
        // the socket file is in the user's profile, where only the user,
        // the administrators and the system may open it
        if (comptime on_windows) return true;
        const uid = core.sys.peerUid(fd) orelse return false;
        const me = c.geteuid();
        return uid == me or uid == 0;
    }
};

fn findApp(ctx: *anyopaque, udp: bool, local: packet.Endpoint, remote: packet.Endpoint, buf: []u8) ?[]u8 {
    if (!builtin.os.tag.isDarwin()) return null;
    const searcher: *darwin.process.Searcher = @ptrCast(@alignCast(ctx));
    return searcher.find(udp, local.addr, local.port, remote.addr, remote.port, buf);
}

fn findWinApp(ctx: *anyopaque, udp: bool, local: packet.Endpoint, remote: packet.Endpoint, buf: []u8) ?[]u8 {
    if (comptime !on_windows) return null;
    const owners: *win_owner.Searcher = @ptrCast(@alignCast(ctx));
    return owners.find(udp, !packet.isV4(&local.addr), local.port, remote.port, buf);
}

fn tunToolPath(out: *[std.fs.max_path_bytes]u8) ?[]const u8 {
    var self_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = c.readlink("/proc/self/exe", &self_buf, self_buf.len);
    if (n <= 0) return null;
    return std.fmt.bufPrint(out, "{s}/blackwall-tun", .{std.fs.path.dirname(self_buf[0..@intCast(n)]) orelse "."}) catch null;
}

/// The device from blackwall-tun, which holds CAP_NET_ADMIN (tun_main.zig).
fn tunHelper(gpa: std.mem.Allocator, io: Io, o: linux.Options) !linux.Lease {
    if (builtin.os.tag != .linux) return error.Unsupported;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const helper = tunToolPath(&path_buf) orelse return error.NeedsAdministrator;

    var pair: [2]c.fd_t = undefined;
    if (c.socketpair(c.AF.UNIX, c.SOCK.STREAM, 0, &pair) != 0) return error.SocketFailed;
    defer _ = c.close(pair[0]);
    // ours must not leak into the child; the child's end must reach it
    _ = c.fcntl(pair[0], c.F.SETFD, @as(c_int, c.FD_CLOEXEC));
    var fd_buf: [12]u8 = undefined;
    var mtu_buf: [8]u8 = undefined;
    var argv_buf: [9][]const u8 = undefined;
    var argv: std.ArrayList([]const u8) = .initBuffer(&argv_buf);
    argv.appendSliceAssumeCapacity(&.{ helper, "up", "--sock", try std.fmt.bufPrint(&fd_buf, "{d}", .{pair[1]}), "--mtu", try std.fmt.bufPrint(&mtu_buf, "{d}", .{o.mtu}) });
    if (o.hold) argv.appendAssumeCapacity("--hold");
    if (o.ipv6) argv.appendAssumeCapacity("--ipv6");
    var child = std.process.spawn(io, .{ .argv = argv.items, .stdin = .ignore, .stdout = .ignore, .stderr = .inherit }) catch {
        _ = c.close(pair[1]);
        return error.NeedsAdministrator;
    };
    _ = c.close(pair[1]);
    defer _ = child.wait(io) catch {};

    if (!core.sys.waitFd(pair[0], false, 15_000)) return error.Timeout;
    var buf: [1024]u8 = undefined;
    const got = fdpass.recvFd(pair[0], &buf) catch return error.NeedsAdministrator;
    errdefer if (got.fd) |f| {
        _ = c.close(f);
    };
    const line = std.mem.trim(u8, buf[0..got.len], " \r\n");
    const Reply = struct { bind: []const u8 = "", dns: []const []const u8 = &.{}, @"error": []const u8 = "" };
    const r = std.json.parseFromSlice(Reply, gpa, line, .{ .ignore_unknown_fields = true }) catch return error.BadReply;
    defer r.deinit();
    if (r.value.@"error".len > 0) {
        log.err("blackwall-tun: {s}", .{r.value.@"error"});
        // the capability is missing (never granted, or the file was replaced)
        return error.NeedsAdministrator;
    }
    var lease: linux.Lease = .{ .fd = got.fd orelse return error.BadReply };
    const bind = r.value.bind[0..@min(r.value.bind.len, 15)];
    @memcpy(lease.bind[0..bind.len], bind);
    for (r.value.dns) |text| {
        if (lease.dns_len == lease.dns.len) break;
        const ip = std.Io.net.Ip4Address.parse(text, 0) catch continue;
        lease.dns[lease.dns_len] = ip.bytes;
        lease.dns_len += 1;
    }
    return lease;
}

fn findLinuxApp(ctx: *anyopaque, udp: bool, local: packet.Endpoint, remote: packet.Endpoint, buf: []u8) ?[]u8 {
    if (builtin.os.tag != .linux) return null;
    const owners: *linux_proc.Searcher = @ptrCast(@alignCast(ctx));
    return owners.find(udp, local.port, remote.port, buf);
}

/// IPv4 address of a server name, through the system resolver (used before
/// the TUN takes over DNS). Caller frees.
fn resolve4(gpa: std.mem.Allocator, host: []const u8) ?[]const u8 {
    if (std.Io.net.Ip4Address.parse(host, 0)) |_| return gpa.dupe(u8, host) catch null else |_| {}
    if (comptime on_windows) return null; // the kill switch there is not built yet
    var name: [256:0]u8 = @splat(0);
    if (host.len >= name.len) return null;
    @memcpy(name[0..host.len], host);
    var hints = std.mem.zeroes(c.addrinfo);
    hints.family = c.AF.INET;
    hints.socktype = c.SOCK.STREAM;
    var res: ?*c.addrinfo = null;
    if (@intFromEnum(c.getaddrinfo(&name, null, &hints, &res)) != 0) return null;
    defer if (res) |r| c.freeaddrinfo(r);
    const ai = res orelse return null;
    const sa: *const c.sockaddr.in = @ptrCast(@alignCast(ai.addr orelse return null));
    const b: [4]u8 = @bitCast(sa.addr);
    return std.fmt.allocPrint(gpa, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }) catch null;
}

const default_dns = [_]packet.Endpoint{
    .{ .addr = packet.v4(.{ 1, 1, 1, 1 }), .port = 53 },
    .{ .addr = packet.v4(.{ 8, 8, 8, 8 }), .port = 53 },
};

fn parseEndpoint(text: []const u8, default_port: u16) ?packet.Endpoint {
    const ip = std.Io.net.IpAddress.parse(text, default_port) catch blk: {
        const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return null;
        const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return null;
        break :blk std.Io.net.IpAddress.parse(text[0..colon], port) catch return null;
    };
    const a, const p = core.sys.fromIpAddress(ip);
    return .{ .addr = a, .port = p };
}

fn defaultConfigDir(a: std.mem.Allocator, env: *std.process.Environ.Map) ![]const u8 {
    if (comptime on_windows) {
        const appdata = env.get("APPDATA") orelse return a.dupe(u8, "BLACKWALL");
        return std.fmt.allocPrint(a, "{s}\\BLACKWALL", .{appdata});
    }
    const home = env.get("HOME") orelse return a.dupe(u8, ".blackwall");
    if (builtin.os.tag.isDarwin()) return std.fmt.allocPrint(a, "{s}/Library/Application Support/BLACKWALL", .{home});
    if (env.get("XDG_CONFIG_HOME")) |x| return std.fmt.allocPrint(a, "{s}/blackwall", .{x});
    return std.fmt.allocPrint(a, "{s}/.config/blackwall", .{home});
}

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(a);
    var args: Args = .{};
    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        const val = if (i + 1 < argv.len) argv[i + 1] else "";
        if (std.mem.eql(u8, arg, "--config")) {
            args.config_dir = val;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--tun")) {
            if (std.mem.eql(u8, val, "helper")) {
                args.tun = .helper;
            } else if (std.mem.eql(u8, val, "wintun")) {
                args.tun = .wintun;
            } else if (std.mem.eql(u8, val, "auto")) {
                args.tun = .auto;
            } else if (std.mem.startsWith(u8, val, "linux:")) {
                args.tun = .{ .linux = val[6..] };
            } else if (std.mem.startsWith(u8, val, "fd:")) {
                args.tun = .{ .fd = try std.fmt.parseInt(i32, val[3..], 10) };
            } else return usage();
            i += 1;
        } else if (std.mem.eql(u8, arg, "--release")) {
            // let go of what a service that is gone still holds
            linux.remove();
            return;
        } else if (std.mem.eql(u8, arg, "--bind")) {
            args.bind = val;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--dns")) {
            try args.dns.append(a, parseEndpoint(val, 53) orelse return usage());
            i += 1;
        } else if (std.mem.eql(u8, arg, "--mtu")) {
            args.mtu = try std.fmt.parseInt(u16, val, 10);
            i += 1;
        } else if (std.mem.eql(u8, arg, "--socks")) {
            args.socks = try std.fmt.parseInt(u16, val, 10);
            i += 1;
        } else return usage();
    }
    if (args.tun == null and args.socks == null) return usage();

    raiseFileLimit();
    var s: Service = .{
        .gpa = init.gpa,
        .io = init.io,
        .args = args,
        .config_dir = args.config_dir orelse try defaultConfigDir(a, init.environ_map),
    };
    std.Io.Dir.cwd().createDirPath(init.io, s.config_dir) catch {};
    openEvents(init.io, s.config_dir);
    {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (std.fmt.bufPrint(&buf, "{s}/" ++ ipc.error_name, .{s.config_dir})) |p| std.Io.Dir.cwd().deleteFile(init.io, p) catch {} else |_| {}
    }
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = ipc.socketPath(&path_buf, s.config_dir);
    var server = s.listen(path) catch |err| {
        s.writeError(err);
        return err;
    };
    // runs last: the window learns the service is gone once all is undone
    defer {
        server.deinit(init.io);
        std.Io.Dir.cwd().deleteFile(init.io, path) catch {};
    }
    s.start() catch |err| {
        s.writeError(err);
        return err;
    };
    defer s.shutdown();
    s.serveIpc(&server);
}

/// Every flow holds a socket, and a process started from the window's
/// session gets 256 descriptors: an ordinary browser load runs out of them,
/// after which every new connection is refused until a restart.
fn raiseFileLimit() void {
    if (builtin.os.tag == .windows) return;
    var lim = std.posix.getrlimit(.NOFILE) catch return;
    // macOS refuses more than OPEN_MAX even where the hard limit is unlimited
    const want: @TypeOf(lim.cur) = 10240;
    if (lim.cur >= want) return;
    lim.cur = @min(want, lim.max);
    std.posix.setrlimit(.NOFILE, lim) catch |err| log.warn("descriptor limit stays at the default: {t}", .{err});
}

fn usage() error{Usage} {
    std.debug.print(
        \\usage: blackwall-service [--config DIR] [--tun helper | --tun auto | --tun wintun | --tun linux:NAME | --tun fd:N]
        \\                         [--bind IFNAME] [--dns IP[:PORT]]... [--mtu N] [--socks PORT]
        \\
    , .{});
    return error.Usage;
}

test {
    _ = routes;
    _ = linux;
    _ = linux_proc;
    _ = @import("nft.zig");
    _ = win;
    _ = win_owner;
    if (builtin.os.tag.isDarwin()) _ = darwin.process;
}
