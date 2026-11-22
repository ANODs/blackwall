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
const wfp = @import("wfp.zig");
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

/// Windows: the calls the events file needs (kernel32).
const k32 = struct {
    const W: std.builtin.CallingConvention = .winapi;
    extern "kernel32" fn CreateFileW(name: [*:0]const u16, access: u32, share: u32, sa: ?*anyopaque, disp: u32, flags: u32, template: ?std.os.windows.HANDLE) callconv(W) std.os.windows.HANDLE;
    extern "kernel32" fn WriteFile(h: std.os.windows.HANDLE, buf: [*]const u8, n: u32, written: ?*u32, ov: ?*anyopaque) callconv(W) i32;
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

/// What this run has logged. A service runs for weeks and the events file
/// is only rotated at a start: past `events_max`, only what went wrong is
/// written; past twice that, nothing more (service.log and service.events).
var logged = std.atomic.Value(usize).init(0);

fn logFn(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime format: []const u8, args: anytype) void {
    const so_far = logged.load(.monotonic);
    if (so_far > 2 * events_max) return;
    if (so_far > events_max and @backingInt(level) > @backingInt(std.log.Level.warn)) return;
    std.log.defaultLog(level, scope, format, args);
    if (if (on_windows) events_fd == null else events_fd < 0) {
        _ = logged.fetchAdd(80, .monotonic);
        return;
    }
    var buf: [640]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    const t = core.diag.now();
    w.print("{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} {s}({s}): ", .{ t.mon, t.day, t.hour, t.min, t.sec, @tagName(level), @tagName(scope) }) catch {};
    w.print(format, args) catch {};
    // a line cut short still ends as a line
    if (w.end >= buf.len) w.end = buf.len - 1;
    w.writeByte('\n') catch {};
    const line = w.buffered();
    _ = logged.fetchAdd(line.len, .monotonic);
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
    /// where the window reaches the service, and the secret it sends (Windows)
    endpoint: if (on_windows) ipc.Endpoint else void = if (on_windows) undefined else {},
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
    /// "ping" requests being measured; the tunnel (its dialer and resolver)
    /// outlives them
    pings: std.atomic.Value(u32) = .init(0),

    /// The kill switch the helper holds. In standby direct traffic must
    /// pass (strict would stop it) and a crash must not release the
    /// applications being held (off would): selective does both.
    fn killSwitch(s: *const Service) core.model.KillSwitch {
        return if (s.settings.standby) .selective else s.settings.kill_switch;
    }

    /// The group's server in use and where it exits; server 0 when there
    /// is none.
    fn serverInUse(s: *Service) routes.InUse {
        const t = s.t orelse return .{};
        const b = s.built orelse return .{};
        return routes.inUse(&b, t);
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
        // a reload keeps the rules in place when new ones fail: they still hold
        s.applyFirewall() catch |err| log.err("kill switch not updated: {t}", .{err});
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
        return resolve4(s.gpa, s.io, host);
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
            // the strict kill switch is what was asked for: no start without it
            try s.applyFirewall();
            const t = try tunnel.Tunnel.create(s.gpa, s.io, .{ .mtu = s.args.mtu, .bind = bind, .upstream_dns = dns_servers, .lookup = lookup });
            errdefer t.destroy();
            try t.setConfig(s.built.?.cfg);
            s.device = try .init(fd, builtin.os.tag.isDarwin());
            errdefer s.device.deinit();
            s.device_thread = try std.Thread.spawn(.{ .stack_size = core.sys.stackSize(512 * 1024) }, tunnel.Tunnel.run, .{ t, &s.device });
            s.t = t;
            log.info("tun up (fd {d}, mtu {d})", .{ fd, s.args.mtu });
        }
        if (s.args.socks) |port| {
            const p = try s.gpa.create(proxy.Proxy);
            errdefer s.gpa.destroy(p);
            p.* = .{ .io = s.io };
            const cfg = s.built.?.cfg;
            p.setOutbound(switch (cfg.default) {
                .direct => .direct,
                .block => .block,
                .dpi => .dpi,
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
        placeWintun(s.io, s.gpa, path);
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
        try s.applyFirewall();
        s.owners = .init(s.gpa, s.io);
        const lookup: tunnel.AppLookup = .{ .ctx = &s.owners, .find = findWinApp };
        const t = try tunnel.Tunnel.create(s.gpa, s.io, .{ .mtu = s.args.mtu, .bind = .{ .index = lease.bind_index }, .upstream_dns = dns_servers, .lookup = lookup });
        errdefer t.destroy();
        try t.setConfig(s.built.?.cfg);
        s.device_thread = try std.Thread.spawn(.{ .stack_size = 512 * 1024 }, tunnel.Tunnel.run, .{ t, &lease.device });
        s.t = t;
        log.info("tun up (wintun, mtu {d})", .{s.args.mtu});
    }

    fn shutdown(s: *Service) void {
        // a ping gives up within its timeout (plus a lookup)
        var waited: u32 = 0;
        while (s.pings.load(.acquire) > 0 and waited < 100) : (waited += 1)
            s.io.sleep(.fromMilliseconds(50), .awake) catch break;
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
                    // a clean stop lets the traffic go; "suspend" leaves it held
                    if (!s.keep_capture) wfp.clear();
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
                s.runTunTool(&.{"open"}) catch {};
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
    /// Fails only where the strict kill switch was asked for and could not
    /// be set; lifting it never fails the caller.
    fn applyFirewall(s: *Service) !void {
        if (comptime on_windows) return s.applyWfp();
        if (builtin.os.tag != .linux or !s.own_device) return;
        if (s.killSwitch() != .strict) return s.runTunTool(&.{"open"}) catch {};
        var servers: std.ArrayList(u8) = .empty;
        defer servers.deinit(s.gpa);
        for (s.server_ips.items, 0..) |ip, i| {
            if (i > 0) try servers.append(s.gpa, ',');
            try servers.appendSlice(s.gpa, ip);
        }
        var dns: std.ArrayList(u8) = .empty;
        defer dns.deinit(s.gpa);
        for (s.dns4[0..s.dns4_len], 0..) |ip, i| {
            var b: [16]u8 = undefined;
            try dns.appendSlice(s.gpa, try std.fmt.bufPrint(&b, "{s}{d}.{d}.{d}.{d}", .{ if (i > 0) "," else "", ip[0], ip[1], ip[2], ip[3] }));
        }
        var argv_buf: [8][]const u8 = undefined;
        var argv: std.ArrayList([]const u8) = .initBuffer(&argv_buf);
        argv.appendSliceAssumeCapacity(&.{ "strict", "--servers", servers.items, "--dns", dns.items });
        if (s.settings.allow_lan) argv.appendAssumeCapacity("--lan");
        if (s.settings.ipv6 == .block) argv.appendAssumeCapacity("--ipv6-block");
        try s.runTunTool(argv.items);
    }

    /// Windows: filters that hold the traffic when the service is gone
    /// (wfp.zig); off removes them.
    fn applyWfp(s: *Service) !void {
        if (comptime !on_windows) return;
        const lease = s.lease orelse return;
        const mode: wfp.Mode = switch (s.killSwitch()) {
            .off => return wfp.clear(),
            .selective => .selective,
            .strict => .strict,
        };
        var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = std.process.executablePath(s.io, &exe_buf) catch |err| {
            log.err("kill switch: no executable path", .{});
            return err;
        };
        var servers: [wfp.max_servers][4]u8 = undefined;
        var count: usize = 0;
        for (s.server_ips.items) |ip| {
            if (count == servers.len) {
                log.warn("kill switch: only the first {d} servers are let through", .{servers.len});
                break;
            }
            const a = std.Io.net.Ip4Address.parse(ip, 0) catch continue;
            servers[count] = a.bytes;
            count += 1;
        }
        wfp.apply(.{
            .mode = mode,
            .luid = lease.luid,
            .service_exe = exe_buf[0..n],
            .servers4 = servers[0..count],
            .dns4 = s.dns4[0..s.dns4_len],
            .allow_lan = s.settings.allow_lan,
            .ipv6_block = s.settings.ipv6 == .block,
        }) catch |err| {
            log.err("kill switch: {t}", .{err});
            // selective only spares the service its own filters: without
            // them it still runs, as before the switch was set
            if (mode == .strict) return error.KillSwitchFailed;
        };
    }

    /// blackwall-tun next to this executable, with `args`.
    fn runTunTool(s: *Service, args: []const []const u8) !void {
        if (builtin.os.tag != .linux) return;
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const tool = tunToolPath(&path_buf) orelse return error.KillSwitchFailed;
        var argv_buf: [10][]const u8 = undefined;
        var argv: std.ArrayList([]const u8) = .initBuffer(&argv_buf);
        argv.appendAssumeCapacity(tool);
        argv.appendSliceAssumeCapacity(args);
        var child = std.process.spawn(s.io, .{ .argv = argv.items, .stdin = .ignore, .stdout = .ignore, .stderr = .inherit }) catch |err| {
            log.err("blackwall-tun {s}: {t}", .{ args[0], err });
            return error.KillSwitchFailed;
        };
        const term = child.wait(s.io) catch return error.KillSwitchFailed;
        if (term != .exited or term.exited != 0) {
            log.err("blackwall-tun {s} failed", .{args[0]});
            return error.KillSwitchFailed;
        }
        log.info("kill switch: {s}", .{args[0]});
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
        // Windows: the programs by name ("Conflict hidemy.name VPN")
        if (comptime on_windows) if (err == error.Conflict) {
            for (win.conflicts[0..win.conflict_count], 0..) |*cf, i| w.print("{s}{s}", .{ if (i == 0) " " else ", ", cf.name() }) catch {};
        };
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
        const in_use = s.serverInUse();
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
            .server = in_use.server,
            .switches = if (s.t) |t| t.mainSwitches() else 0,
            .member = in_use.member,
            .exit = if (core.model.knownCountry(in_use.exit)) &in_use.exit else "",
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
        if (comptime on_windows) return s.listenLoopback(path);
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

    /// Windows: on the loopback, at a port the system picks; the file at
    /// `path` says where, with the secret a client must send first
    /// (`ipc.Endpoint`). Written whole under another name and renamed, so
    /// a window never reads half of it.
    fn listenLoopback(s: *Service, path: []const u8) !std.Io.net.Server {
        const here: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        var server = try here.listen(s.io, .{});
        errdefer server.deinit(s.io);
        s.endpoint = .fresh(s.io, server.socket.address.getPort());
        var text_buf: [ipc.Endpoint.max_text]u8 = undefined;
        var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
        const tmp = try std.fmt.bufPrint(&tmp_buf, "{s}.new", .{path});
        const dir = std.Io.Dir.cwd();
        try dir.writeFile(s.io, .{ .sub_path = tmp, .data = s.endpoint.text(&text_buf) });
        try dir.rename(tmp, dir, path, s.io);
        log.info("listening on 127.0.0.1:{d}", .{s.endpoint.port});
        return server;
    }

    /// Serve the window until "stop".
    fn serveIpc(s: *Service, server: *std.Io.net.Server) void {
        while (!s.stopping.load(.acquire)) {
            const conn = server.accept(s.io) catch continue;
            var conn_kept = false;
            defer if (!conn_kept) conn.close(s.io);
            if (!s.peerAllowed(conn.socket.handle)) continue;
            var rb: [1024]u8 = undefined;
            var r = conn.reader(s.io, &rb);
            var wb: [64 * 1024]u8 = undefined;
            var w = conn.writer(s.io, &wb);
            // Windows: anyone on the machine reaches the port; the secret first
            var req_buf: [ipc.Endpoint.max_text + 1024]u8 = undefined;
            const line = if (comptime on_windows)
                (ipc.readAdmitted(s.io, &s.endpoint, conn.socket.handle, &req_buf) orelse continue)
            else
                (r.interface.takeDelimiterExclusive('\n') catch continue);
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
            } else if (std.mem.eql(u8, cmd, "ping")) {
                // measured on a thread of its own: a slow server must not
                // hold the window's status calls
                const job = s.gpa.create(PingJob) catch continue;
                const host = s.gpa.dupe(u8, req.value.host[0..@min(req.value.host.len, 253)]) catch {
                    s.gpa.destroy(job);
                    continue;
                };
                job.* = .{ .s = s, .conn = conn, .host = host, .port = req.value.port };
                _ = s.pings.fetchAdd(1, .acq_rel);
                if (std.Thread.spawn(.{ .stack_size = core.sys.stackSize(128 * 1024) }, PingJob.run, .{job})) |th| {
                    th.detach();
                    conn_kept = true;
                } else |_| {
                    _ = s.pings.fetchSub(1, .acq_rel);
                    s.gpa.free(host);
                    s.gpa.destroy(job);
                    w.interface.writeAll("{\"ms\":null}\n") catch {};
                }
            } else if (on_windows and std.mem.eql(u8, cmd, "stop_dpi")) {
                // zapret or GoodbyeDPI beside us, at the window's word (core/win_dpi.zig);
                // it answers from a thread of its own
                if (core.win_dpi.serve(s.io, conn, line)) conn_kept = true else w.interface.writeAll("{\"ok\":false}\n") catch {};
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

    const ping_timeout_ms = 2500;

    /// One "ping": the TCP connect time to a server the way the tunnel
    /// reaches servers — bound to the physical interface and resolved
    /// through its resolver — so the window, whose own sockets go into
    /// the TUN, sees the server from the real address and not through
    /// the server it is connected to.
    const PingJob = struct {
        s: *Service,
        conn: std.Io.net.Stream,
        host: []u8,
        port: u16,

        fn run(j: *PingJob) void {
            const s = j.s;
            defer {
                j.conn.close(s.io);
                s.gpa.free(j.host);
                s.gpa.destroy(j);
                _ = s.pings.fetchSub(1, .acq_rel);
            }
            const d: proxy.Dialer = if (s.t) |t| t.dialer else .{};
            const reply: ipc.PingReply = .{ .ms = measure(s.io, d, j.host, j.port) };
            var wb: [64]u8 = undefined;
            var w = j.conn.writer(s.io, &wb);
            std.json.Stringify.value(reply, .{}, &w.interface) catch return;
            w.interface.writeByte('\n') catch return;
            w.interface.flush() catch {};
        }

        fn measure(io: Io, d: proxy.Dialer, host: []const u8, port: u16) ?u32 {
            if (host.len == 0 or port == 0) return null;
            const addr = d.resolve(io, host) catch return null;
            const began = Io.Clock.awake.now(io);
            const stream = core.sys.connectTcp(&addr, port, d.bind, ping_timeout_ms) catch return null;
            stream.close(io);
            return @intCast(std.math.clamp(began.untilNow(io, .awake).toMilliseconds(), 1, 9999));
        }
    };

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
fn resolve4(gpa: std.mem.Allocator, io: Io, host: []const u8) ?[]const u8 {
    if (std.Io.net.Ip4Address.parse(host, 0)) |_| return gpa.dupe(u8, host) catch null else |_| {}
    if (comptime on_windows) {
        const name = std.Io.net.HostName.init(host) catch return null;
        var results: [16]std.Io.net.HostName.LookupResult = undefined;
        var q: Io.Queue(std.Io.net.HostName.LookupResult) = .init(&results);
        name.lookup(io, &q, .{ .port = 0, .family = .ip4 }) catch return null;
        while (q.getOne(io)) |r| switch (r) {
            .address => |a| if (a == .ip4) {
                const b = a.ip4.bytes;
                return std.fmt.allocPrint(gpa, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }) catch null;
            },
            .canonical_name => {},
        } else |_| return null;
        return null;
    }
    var name: [256:0]u8 = @splat(0);
    if (host.len >= name.len) return null;
    @memcpy(name[0..host.len], host);
    var hints = std.mem.zeroes(c.addrinfo);
    hints.family = c.AF.INET;
    hints.socktype = c.SOCK.STREAM;
    var res: ?*c.addrinfo = null;
    if (@backingInt(c.getaddrinfo(&name, null, &hints, &res)) != 0) return null;
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
    if (comptime on_windows) {
        const first: []const u8 = if (argv.len > 1) argv[1] else "";
        if (std.mem.eql(u8, first, "install")) return installWindows(init, argv[2..]);
        if (std.mem.eql(u8, first, "uninstall")) return core.win_scm.uninstall();
        if (std.mem.eql(u8, first, "--scm")) {
            scm_init = init;
            return core.win_scm.dispatch(argv[2..], .{ .run = scmRun, .stop = scmStop });
        }
    }
    return serve(init, argv[1..]);
}

/// Windows, as an administrator: puts the service in place for one user
/// (see core/win_scm.zig).
fn installWindows(init: std.process.Init, argv: []const []const u8) !void {
    var config: ?[]const u8 = null;
    var sid: ?[]const u8 = null;
    var i: usize = 0;
    while (i + 1 < argv.len) : (i += 2) {
        if (std.mem.eql(u8, argv[i], "--config")) config = argv[i + 1];
        if (std.mem.eql(u8, argv[i], "--user")) sid = argv[i + 1];
    }
    const exe = try std.process.executablePathAlloc(init.io, init.arena.allocator());
    core.win_scm.install(init.environ_map, exe, config orelse return usage(), sid orelse return usage(), build_options.version) catch |err| {
        log.err("install: {t}", .{err});
        return err;
    };
    log.info("installed", .{});
}

/// Windows: the installed service replaces itself with the one in `dir`
/// (unpacked there by the window) when the release key signed it and it is
/// not older. Nothing else may replace a file the system runs.
fn upgradeWindows(init: std.process.Init, dir: []const u8) !void {
    const gpa = init.gpa;
    var p_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd = std.Io.Dir.cwd();
    const bytes = try cwd.readFileAlloc(init.io, try std.fmt.bufPrint(&p_buf, "{s}\\blackwall-service.exe", .{dir}), gpa, .limited(64 << 20));
    defer gpa.free(bytes);
    const sig = try cwd.readFileAlloc(init.io, try std.fmt.bufPrint(&p_buf, "{s}\\blackwall-service.sig", .{dir}), gpa, .limited(1024));
    defer gpa.free(sig);
    const key = build_options.update_pubkey;
    if (key.len == 0) return log.err("upgrade: this build trusts no signature", .{});
    // the release key also signs the macOS helper: only a Windows program may be one
    if (!core.helper_ipc.isProgram(.windows_service, bytes)) return log.err("upgrade: not a Windows program", .{});
    const signed = core.helper_ipc.Signed.parse(sig) orelse return log.err("upgrade: no signature", .{});
    core.helper_ipc.verifyHelper(key, signed, bytes) catch return log.err("upgrade: the signature does not match", .{});
    const theirs = std.SemanticVersion.parse(signed.version) catch return log.err("upgrade: bad release", .{});
    const ours = std.SemanticVersion.parse(build_options.version) catch return;
    if (theirs.order(ours) == .lt) return log.err("upgrade: {s} is older than {s}", .{ signed.version, build_options.version });
    core.win_scm.replaceSelf(init.environ_map, bytes, signed.version) catch |err| return log.err("upgrade: {t}", .{err});
    log.info("replaced by {s}", .{signed.version});
}

/// Windows: wintun.dll, which this executable carries, next to it.
fn placeWintun(io: Io, gpa: std.mem.Allocator, path: []const u8) void {
    if (comptime !on_windows) return;
    const dll = @embedFile("wintun_dll");
    if (dll.len == 0) return; // a build without it: the file must be there
    const cwd = std.Io.Dir.cwd();
    if (cwd.readFileAlloc(io, path, gpa, .limited(4 << 20))) |have| {
        defer gpa.free(have);
        if (std.mem.eql(u8, have, dll)) return;
    } else |_| {}
    cwd.writeFile(io, .{ .sub_path = path, .data = dll }) catch |err| log.err("wintun.dll: {t}", .{err});
}

var scm_init: std.process.Init = undefined;
var scm_config: ?[]const u8 = null;

fn scmRun(args: []const []const u8) void {
    serve(scm_init, args) catch |err| log.err("service: {t}", .{err});
}

/// The SCM asked it to stop: the same as the window's "stop".
fn scmStop() void {
    const dir = scm_config orelse return;
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const line = ipc.call(scm_init.gpa, scm_init.io, ipc.socketPath(&buf, dir), "stop", 5000) catch return;
    scm_init.gpa.free(line);
}

fn serve(init: std.process.Init, argv: []const []const u8) !void {
    const a = init.arena.allocator();
    var args: Args = .{};
    var i: usize = 0;
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
        } else if (on_windows and std.mem.eql(u8, arg, "--upgrade")) {
            return upgradeWindows(init, val);
        } else if (on_windows and std.mem.eql(u8, arg, "--stop-dpi")) {
            // started by the window just for this, when no service ran to ask
            core.win_dpi.handle(val) catch {};
            return;
        } else if (std.mem.eql(u8, arg, "--release")) {
            // let go of what a service that is gone still holds
            linux.remove();
            wfp.clear();
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
    scm_config = s.config_dir;
    openEvents(init.io, s.config_dir);
    {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (std.fmt.bufPrint(&buf, "{s}/" ++ ipc.error_name, .{s.config_dir})) |p| std.Io.Dir.cwd().deleteFile(init.io, p) catch {} else |_| {}
    }
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = ipc.socketPath(&path_buf, s.config_dir);
    // which step failed goes to the events (a report shows them)
    var server = s.listen(path) catch |err| {
        log.err("window channel: {t}", .{err});
        s.writeError(err);
        return err;
    };
    // runs last: the window learns the service is gone once all is undone
    defer {
        server.deinit(init.io);
        std.Io.Dir.cwd().deleteFile(init.io, path) catch {};
    }
    s.start() catch |err| {
        log.err("start: {t}", .{err});
        s.writeError(err);
        // what was set up is freed; a capture in place stays, as after a
        // crash: the kill switch decides
        s.keep_capture = true;
        s.shutdown();
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
    _ = wfp;
    if (builtin.os.tag.isDarwin()) _ = darwin.process;
}
