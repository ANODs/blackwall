//! Programs in the way of the connection (product concept 7.1), macOS:
//! another VPN whose tunnel captures the traffic, or DPI circumvention
//! beside us. Windows: DPI circumvention (zapret, GoodbyeDPI, see
//! core/win_dpi.zig), stopped by the BLACKWALL service.
//!
//! A conflict is what is observed: routes that send the address space into
//! another tunnel. Who holds that tunnel is confirmed when the system says
//! so (a connected VPN service of macOS names its interface) or when its
//! owner is seen with the tunnel open (the root helper sees every process,
//! the window only its own); otherwise the likeliest VPN program is named as
//! a presumption.
//!
//! Stopping: a system VPN service is disconnected through the system
//! (`scutil --nc stop`, nothing is killed). Otherwise one chosen,
//! re-identified process is asked to quit: by the user, or by the helper for
//! root daemons (which unloads a launchd job, so it does not come straight
//! back); never a system process.

const std = @import("std");
const builtin = @import("builtin");
const core = @import("core");

const on_macos = builtin.os.tag == .macos;
const on_windows = builtin.os.tag == .windows;
pub const supported = on_macos or on_windows;

const net = if (on_macos) @import("../helper/darwin/net.zig") else struct {};
const proc = if (on_macos) @import("../helper/darwin/proc.zig") else if (on_windows) struct {
    pub const Identity = core.win_dpi.Identity;
} else struct {
    pub const Identity = struct {
        pid: i32 = 0,
        uid: u32 = 0,
        start_us: u64 = 0,
        pub fn path(_: *const @This()) []const u8 {
            return "";
        }
    };
};
const helper = core.helper_ipc;
const ipc = core.ipc;
const win_dpi = core.win_dpi;
const Io = std.Io;

pub const Identity = proc.Identity;

/// What the program does to the traffic.
pub const Kind = enum {
    /// its tunnel captures the traffic
    vpn,
    /// it redirects traffic to circumvent DPI (zapret, ByeDPI, SpoofDPI)
    dpi,
};

pub const Conflict = struct {
    kind: Kind = .vpn,
    ifname_buf: [16]u8 = undefined,
    ifname_len: u8 = 0,
    /// the process holding the tunnel, when one is known
    owner: ?Identity = null,
    /// seen holding it (true), or only the likeliest candidate (false)
    confirmed: bool = false,
    /// "Happ": the application around the owner
    name_buf: [64]u8 = undefined,
    name_len: u8 = 0,
    /// "/Applications/Happ.app", to open it; empty without a bundle
    bundle_buf: [512]u8 = undefined,
    bundle_len: u16 = 0,
    /// a connected VPN service of the system (its ID), stopped through it;
    /// on Windows the service a DPI tool runs as (its name)
    service_buf: [64]u8 = undefined,
    service_len: u8 = 0,

    pub fn ifname(c: *const Conflict) []const u8 {
        return c.ifname_buf[0..c.ifname_len];
    }
    pub fn name(c: *const Conflict) []const u8 {
        return if (c.name_len > 0) c.name_buf[0..c.name_len] else c.ifname();
    }
    pub fn bundle(c: *const Conflict) []const u8 {
        return c.bundle_buf[0..c.bundle_len];
    }
    pub fn service(c: *const Conflict) []const u8 {
        return c.service_buf[0..c.service_len];
    }

    fn setOwner(c: *Conflict, id: Identity, confirmed: bool) void {
        c.owner = id;
        c.confirmed = confirmed;
        const p = id.path();
        const b = bundleOf(p);
        const label = if (b.len > 0) std.fs.path.stem(b) else std.fs.path.basename(p);
        c.name_len = @intCast(@min(label.len, c.name_buf.len));
        @memcpy(c.name_buf[0..c.name_len], label[0..c.name_len]);
        c.bundle_len = @intCast(@min(b.len, c.bundle_buf.len));
        @memcpy(c.bundle_buf[0..c.bundle_len], b[0..c.bundle_len]);
    }
};

/// "/Applications/Happ.app/Contents/MacOS/happd" -> "/Applications/Happ.app"
fn bundleOf(path: []const u8) []const u8 {
    const at = std.mem.indexOf(u8, path, ".app/") orelse return "";
    return path[0 .. at + 4];
}

/// Other VPNs' tunnels that capture traffic now, with their owners.
/// `own_ifname`: our own tunnel, when it is up. Caller frees.
pub fn detect(gpa: std.mem.Allocator, io: Io) ![]Conflict {
    if (comptime on_windows) return detectWindows(gpa);
    if (!supported) return &.{};
    // the helper knows our own tunnel (when it is up) and every owner
    const from_helper = helperOwners(gpa, io);
    defer if (from_helper) |p| p.deinit();
    const own: ?[]const u8 = if (from_helper) |p| (if (p.value.up and p.value.ifname.len > 0) p.value.ifname else null) else null;
    const caps = try net.foreignCaptures(gpa, own);
    defer gpa.free(caps);
    var out: std.ArrayList(Conflict) = .empty;
    errdefer out.deinit(gpa);
    for (caps) |cap| {
        const name = std.mem.sliceTo(&cap.ifname, 0);
        for (out.items) |c| {
            if (std.mem.eql(u8, c.ifname(), name)) break;
        } else {
            var c: Conflict = .{};
            c.ifname_len = @intCast(@min(name.len, c.ifname_buf.len));
            @memcpy(c.ifname_buf[0..c.ifname_len], name[0..c.ifname_len]);
            try out.append(gpa, c);
        }
    }
    // DPI circumvention running beside us (concept 7.1: network filtering)
    dpiTools(gpa, io, &out);
    if (out.items.len == 0) return out.toOwnedSlice(gpa);

    // a VPN service of the system says itself which tunnel is its own
    systemServices(gpa, io, out.items);

    // owners: the root helper sees everybody, we see our own processes
    if (from_helper) |parsed| {
        for (out.items) |*c| for (parsed.value.owners) |o| {
            // a system service already names its app, and stops through the system
            if (c.service_len > 0 or c.kind != .vpn) continue;
            if (!std.mem.eql(u8, o.ifname, c.ifname()) or o.pid == 0) continue;
            if (proc.identity(o.pid)) |id| if (id.start_us == o.start_us) c.setOwner(id, true);
        };
    }
    for (out.items) |*c| {
        if (c.owner != null or c.kind != .vpn) continue;
        if (proc.tunnelOwner(gpa, c.ifname())) |pid| if (proc.identity(pid)) |id| {
            c.setOwner(id, true);
            continue;
        };
        // the helper looked and found nobody: do not guess over its answer
        if (from_helper != null) continue;
        if (likelyOwner(gpa)) |id| c.setOwner(id, false);
    }
    return out.toOwnedSlice(gpa);
}

/// Windows: zapret and GoodbyeDPI, one entry per tool, the one that runs
/// as a service first (stopping only the process of a service would have
/// the SCM start it again). Confirmed when the WinDivert driver they divert
/// packets through is loaded.
fn detectWindows(gpa: std.mem.Allocator) ![]Conflict {
    const s = try win_dpi.scan(gpa);
    defer gpa.free(s.found);
    var out: std.ArrayList(Conflict) = .empty;
    errdefer out.deinit(gpa);
    for (s.found) |*f| {
        const name = win_dpi.tools[f.tool].name;
        const at = for (out.items, 0..) |c, i| {
            if (std.mem.eql(u8, c.name(), name)) break i;
        } else null;
        if (at) |i| if (out.items[i].service_len > 0 or f.service_len == 0) continue;
        var c: Conflict = .{ .kind = .dpi };
        c.setOwner(f.id, s.windivert);
        c.name_len = @intCast(name.len);
        @memcpy(c.name_buf[0..name.len], name);
        c.service_len = f.service_len;
        @memcpy(c.service_buf[0..f.service_len], f.service());
        if (at) |i| out.items[i] = c else try out.append(gpa, c);
    }
    return out.toOwnedSlice(gpa);
}

/// DPI circumvention tools of macOS and the names users know them by.
const dpi_tools = [_]struct { exe: []const u8, name: []const u8 }{
    // zapret: tpws, put in the path of 80/443 by pf rules
    .{ .exe = "tpws", .name = "zapret" },
    .{ .exe = "dvtws", .name = "zapret" },
    .{ .exe = "nfqws", .name = "zapret" },
    // ByeDPI: a SOCKS proxy, by default on our own port 1080
    .{ .exe = "ciadpi", .name = "ByeDPI" },
    .{ .exe = "byedpi", .name = "ByeDPI" },
    // SpoofDPI: an HTTP proxy that it makes the system proxy
    .{ .exe = "spoofdpi", .name = "SpoofDPI" },
};

/// zapret's own switch on macOS, run by the helper to stop it with its pf rules.
pub const zapret_script = "/opt/zapret/init.d/macos/zapret";

/// Running DPI circumvention tools, one entry per tool. Confirmed when what
/// they do to the traffic is seen: zapret's pf anchor in /etc/pf.conf, or a
/// system proxy on this machine; a presumption otherwise.
fn dpiTools(gpa: std.mem.Allocator, io: Io, out: *std.ArrayList(Conflict)) void {
    const pids = listPids(gpa) catch return;
    defer gpa.free(pids);
    const pf_conf = std.Io.Dir.cwd().readFileAlloc(io, "/etc/pf.conf", gpa, .limited(256 * 1024)) catch null;
    defer if (pf_conf) |t| gpa.free(t);
    const proxy = scutil(gpa, io, &.{ "/usr/sbin/scutil", "--proxy" });
    defer if (proxy) |t| gpa.free(t);
    const local_proxy = if (proxy) |t| localProxy(t) else false;

    for (pids) |pid| {
        const id = proc.identity(pid) orelse continue;
        const base = std.fs.path.basename(id.path());
        const tool = for (dpi_tools) |t| {
            if (std.ascii.eqlIgnoreCase(base, t.exe)) break t;
        } else continue;
        for (out.items) |c| {
            if (c.kind == .dpi and std.mem.eql(u8, c.name(), tool.name)) break;
        } else {
            var c: Conflict = .{ .kind = .dpi };
            c.setOwner(id, false);
            c.name_len = @intCast(tool.name.len);
            @memcpy(c.name_buf[0..tool.name.len], tool.name);
            c.confirmed = if (std.mem.eql(u8, tool.name, "zapret"))
                (if (pf_conf) |t| std.mem.indexOf(u8, t, "zapret") != null else false)
            else
                local_proxy;
            out.append(gpa, c) catch return;
        }
    }
}

/// Whether the system proxy (HTTP, HTTPS or SOCKS) points at this machine.
fn localProxy(scutil_proxy: []const u8) bool {
    for ([_][]const u8{ "HTTP", "HTTPS", "SOCKS" }) |p| {
        var key_buf: [24]u8 = undefined;
        const enable = std.fmt.bufPrint(&key_buf, "{s}Enable", .{p}) catch continue;
        const on = statusField(scutil_proxy, enable) orelse continue;
        if (!std.mem.eql(u8, on, "1")) continue;
        var host_buf: [24]u8 = undefined;
        const host_key = std.fmt.bufPrint(&host_buf, "{s}Proxy", .{p}) catch continue;
        const host = statusField(scutil_proxy, host_key) orelse continue;
        if (std.mem.eql(u8, host, "127.0.0.1") or std.mem.eql(u8, host, "localhost") or std.mem.eql(u8, host, "::1")) return true;
    }
    return false;
}

/// Connected VPN services of the system (Network Extension providers like
/// hidemy.name's OpenVPN, IKEv2, ...): `scutil --nc` names each one's
/// interface and the app that started it.
fn systemServices(gpa: std.mem.Allocator, io: Io, list: []Conflict) void {
    const listed = scutil(gpa, io, &.{ "/usr/sbin/scutil", "--nc", "list" }) orelse return;
    defer gpa.free(listed);
    var lines = std.mem.splitScalar(u8, listed, '\n');
    while (lines.next()) |line| {
        const svc = parseServiceLine(line) orelse continue;
        if (!svc.connected) continue;
        const status = scutil(gpa, io, &.{ "/usr/sbin/scutil", "--nc", "status", svc.id }) orelse continue;
        defer gpa.free(status);
        const iface = statusField(status, "InterfaceName") orelse continue;
        for (list) |*c| {
            if (!std.mem.eql(u8, c.ifname(), iface)) continue;
            // the app that started the session gives the name and the bundle
            if (statusField(status, "SessionPID")) |pid_text| {
                const pid = std.fmt.parseInt(i32, pid_text, 10) catch 0;
                if (proc.identity(pid)) |id| c.setOwner(id, true);
            }
            if (c.name_len == 0) {
                c.name_len = @intCast(@min(svc.name.len, c.name_buf.len));
                @memcpy(c.name_buf[0..c.name_len], svc.name[0..c.name_len]);
            }
            c.confirmed = true;
            c.service_len = @intCast(@min(svc.id.len, c.service_buf.len));
            @memcpy(c.service_buf[0..c.service_len], svc.id[0..c.service_len]);
        }
    }
}

const ServiceLine = struct { connected: bool, id: []const u8, name: []const u8 };

/// `* (Connected)  B4828DCE-... VPN (hidemyname.vpn) "hidemyname.vpn (OpenVPN)"  [VPN:...]`
fn parseServiceLine(line: []const u8) ?ServiceLine {
    const open = std.mem.indexOfScalar(u8, line, '(') orelse return null;
    const close = std.mem.indexOfScalarPos(u8, line, open, ')') orelse return null;
    const status = line[open + 1 .. close];
    var rest = std.mem.trimStart(u8, line[close + 1 ..], " \t");
    const id_end = std.mem.indexOfAny(u8, rest, " \t") orelse return null;
    const id = rest[0..id_end];
    if (id.len != 36 or std.mem.count(u8, id, "-") != 4) return null;
    rest = rest[id_end..];
    const q1 = std.mem.indexOfScalar(u8, rest, '"') orelse return null;
    const q2 = std.mem.indexOfScalarPos(u8, rest, q1 + 1, '"') orelse return null;
    return .{ .connected = std.mem.eql(u8, status, "Connected"), .id = id, .name = rest[q1 + 1 .. q2] };
}

/// "  InterfaceName : utun7" -> "utun7"
fn statusField(text: []const u8, key: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (!std.mem.startsWith(u8, line, key)) continue;
        const rest = std.mem.trimStart(u8, line[key.len..], " ");
        if (!std.mem.startsWith(u8, rest, ":")) continue;
        return std.mem.trim(u8, rest[1..], " ");
    }
    return null;
}

fn scutil(gpa: std.mem.Allocator, io: Io, argv: []const []const u8) ?[]u8 {
    const r = std.process.run(gpa, io, .{ .argv = argv, .stdout_limit = .limited(256 * 1024), .stderr_limit = .limited(16 * 1024) }) catch return null;
    gpa.free(r.stderr);
    if (r.term != .exited or r.term.exited != 0) {
        gpa.free(r.stdout);
        return null;
    }
    return r.stdout;
}

fn helperOwners(gpa: std.mem.Allocator, io: Io) ?std.json.Parsed(helper.Reply) {
    const line = ipc.call(gpa, io, helper.socket_path, "conflicts", 3000) catch return null;
    defer gpa.free(line);
    const r = std.json.parseFromSlice(helper.Reply, gpa, line, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch return null;
    if (!r.value.ok) {
        r.deinit();
        return null;
    }
    return r;
}

/// Programs known to run VPN tunnels on macOS (their executables or bundles).
/// Only a presumption: being on this list proves nothing by itself.
const known = [_][]const u8{
    "happ",       "hiddify",   "v2raytun",  "v2ray",      "xray",    "sing-box", "singbox",
    "clash",      "mihomo",    "nekoray",   "outline",    "wireguard", "openvpn", "tunnelblick",
    "amnezia",    "nordvpn",   "expressvpn", "protonvpn", "mullvad", "windscribe", "surfshark",
    "hidemy",     "psiphon",   "lantern",   "shadowrocket", "surge", "streisand", "foxray",
    "tailscale",  "zerotier",  "warp",      "cloudflare", "anyconnect", "globalprotect", "forticlient",
};

/// The likeliest program behind a tunnel nobody could be seen holding: a
/// known VPN program, preferring a root daemon (tunnels need root).
fn likelyOwner(gpa: std.mem.Allocator) ?Identity {
    const pids = listPids(gpa) catch return null;
    defer gpa.free(pids);
    var best: ?Identity = null;
    for (pids) |pid| {
        const id = proc.identity(pid) orelse continue;
        if (!proc.mayStop(&id, &.{})) continue;
        var lower_buf: [1024]u8 = undefined;
        const lower = std.ascii.lowerString(&lower_buf, id.path()[0..@min(id.path().len, lower_buf.len)]);
        const hit = for (known) |k| {
            if (std.mem.indexOf(u8, lower, k) != null) break true;
        } else false;
        if (!hit) continue;
        if (best == null or (id.uid == 0 and best.?.uid != 0)) best = id;
    }
    return best;
}

extern "c" fn proc_listallpids(buffer: ?*anyopaque, size: c_int) c_int;

fn listPids(gpa: std.mem.Allocator) ![]i32 {
    var cap: usize = 1024;
    while (cap <= 1 << 20) : (cap *= 2) {
        const buf = try gpa.alloc(i32, cap);
        const n = proc_listallpids(buf.ptr, @intCast(cap * @sizeOf(i32)));
        if (n < 0) {
            gpa.free(buf);
            return error.ListFailed;
        }
        if (@as(usize, @intCast(n)) < cap) return gpa.realloc(buf, @intCast(n)) catch buf[0..@intCast(n)];
        gpa.free(buf);
    }
    return error.ListFailed;
}

pub const StopError = error{
    /// nobody is known to hold the tunnel
    UnknownOwner,
    /// the process exited or is not the one that was shown
    Gone,
    /// a root daemon, and the helper that could stop it is not installed
    NeedsHelper,
    /// the helper refused or could not stop it
    Refused,
    /// it was stopped, yet the tunnel is back or still there
    StillActive,
};

/// Stop the owner of `c` (`kill`: without asking), then wait for its tunnel
/// to stop capturing traffic. `config_dir`: where the service listens (Windows).
pub fn stop(gpa: std.mem.Allocator, io: Io, config_dir: []const u8, c: *const Conflict, kill: bool) StopError!void {
    if (comptime on_windows) return stopWindows(gpa, io, config_dir, c, kill);
    if (!supported) return error.UnknownOwner;
    // zapret leaves pf sending 80/443 to a dead port when only its process
    // goes: its own script stops it and takes the rules away (as root)
    if (c.kind == .dpi and std.mem.eql(u8, c.name(), "zapret") and !kill) {
        const line = ipc.call(gpa, io, helper.socket_path, "stop_zapret", 30_000) catch |err| return switch (err) {
            error.FileNotFound, error.ConnectionRefused => error.NeedsHelper,
            else => error.Refused,
        };
        defer gpa.free(line);
        const r = std.json.parseFromSlice(helper.Reply, gpa, line, .{ .ignore_unknown_fields = true }) catch return error.Refused;
        defer r.deinit();
        if (!r.value.ok) return error.Refused;
        return;
    }
    // a system VPN service: disconnected the way its own switch does it
    // (killing its provider would only make the system restart it)
    if (c.service_len > 0) {
        const out = scutil(gpa, io, &.{ "/usr/sbin/scutil", "--nc", "stop", c.service() }) orelse return error.Refused;
        gpa.free(out);
        return waitFree(gpa, io, c);
    }
    const shown = c.owner orelse return error.UnknownOwner;
    // the very process the user picked, not a pid that was reused since
    const now = proc.identity(shown.pid) orelse return error.Gone;
    if (!now.same(&shown) or !proc.mayStop(&now, &.{})) return error.Gone;

    if (now.uid == std.c.getuid()) {
        const sig: std.posix.SIG = if (kill) .KILL else .TERM;
        if (std.c.kill(now.pid, sig) != 0) return error.Refused;
        // a proxy-type tool is gone once its process is
        if (c.kind == .dpi) return;
    } else {
        var req_buf: [2048]u8 = undefined;
        var w: Io.Writer = .fixed(&req_buf);
        std.json.Stringify.value(helper.Request{
            .cmd = "stop",
            .pid = now.pid,
            .start_us = now.start_us,
            .path = now.path(),
            .kill = kill,
        }, .{}, &w) catch return error.Refused;
        w.writeByte('\n') catch return error.Refused;
        const line = ipc.request(gpa, io, helper.socket_path, w.buffered(), 10_000) catch |err| return switch (err) {
            error.FileNotFound, error.ConnectionRefused => error.NeedsHelper,
            else => error.Refused,
        };
        defer gpa.free(line);
        const r = std.json.parseFromSlice(helper.Reply, gpa, line, .{ .ignore_unknown_fields = true }) catch return error.Refused;
        defer r.deinit();
        if (!r.value.ok) return if (std.mem.eql(u8, r.value.@"error", "Gone")) error.Gone else error.Refused;
    }

    if (c.kind == .dpi) {
        // gone once its process is
        for (0..25) |_| {
            if (proc.identity(now.pid) == null) return;
            io.sleep(.fromMilliseconds(200), .awake) catch {};
        }
        return error.StillActive;
    }
    return waitFree(gpa, io, c);
}

/// Windows: the tools run as administrators or as LocalSystem, so the
/// BLACKWALL service (LocalSystem) stops them: the running one over its
/// channel, or else the installed one, started just for this.
fn stopWindows(gpa: std.mem.Allocator, io: Io, config_dir: []const u8, c: *const Conflict, kill: bool) StopError!void {
    if (c.owner == null and c.service_len == 0) return error.UnknownOwner;
    const id: win_dpi.Identity = c.owner orelse .{};
    const r: win_dpi.Request = .{ .service = c.service(), .pid = id.pid, .start = id.start, .kill = kill };
    var line_buf: [256]u8 = undefined;
    const line = r.line(&line_buf) orelse return error.Refused;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var once = false;
    if (ipc.request(gpa, io, ipc.socketPath(&path_buf, config_dir), line, 20_000)) |answer| {
        defer gpa.free(answer);
        const reply = std.json.parseFromSlice(win_dpi.Reply, gpa, answer, .{ .ignore_unknown_fields = true }) catch return error.Refused;
        defer reply.deinit();
        if (!reply.value.ok) return if (std.mem.eql(u8, reply.value.@"error", "Gone")) error.Gone else error.Refused;
    } else |err| switch (err) {
        // no service runs: the installed one does just this and ends
        error.FileNotFound, error.ConnectionRefused => {
            core.win_scm.start(&.{ "--stop-dpi", line[0 .. line.len - 1] }) catch return error.NeedsHelper;
            once = true;
        },
        else => return error.Refused,
    }
    // gone once its process (and its service) is
    for (0..75) |_| {
        if (!win_dpi.present(c.service(), id.pid, id.start)) break;
        io.sleep(.fromMilliseconds(200), .awake) catch {};
    } else return error.StillActive;
    // the service that ran for this has ended before the reconnect starts it
    if (once) for (0..25) |_| {
        if ((core.win_scm.query() orelse .stopped) == .stopped) break;
        io.sleep(.fromMilliseconds(200), .awake) catch {};
    };
}

/// The network is free once that tunnel no longer captures anything.
fn waitFree(gpa: std.mem.Allocator, io: Io, c: *const Conflict) StopError!void {
    for (0..30) |_| {
        io.sleep(.fromMilliseconds(200), .awake) catch {};
        const caps = net.foreignCaptures(gpa, null) catch continue;
        defer gpa.free(caps);
        const still = for (caps) |cap| {
            if (std.mem.eql(u8, std.mem.sliceTo(&cap.ifname, 0), c.ifname())) break true;
        } else false;
        if (!still) return;
    }
    return error.StillActive;
}

/// Bring the conflicting application forward, so its own switch can be used.
pub fn openApp(io: Io, c: *const Conflict) void {
    if (!on_macos or c.bundle_len == 0) return;
    var child = std.process.spawn(io, .{
        .argv = &.{ "/usr/bin/open", c.bundle() },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return;
    _ = child.wait(io) catch {};
}

test "what is in the way on this machine (read-only)" {
    if (!supported) return error.SkipZigTest;
    const found = try detect(std.testing.allocator, std.testing.io);
    defer std.testing.allocator.free(found);
    for (found) |c| {
        std.debug.print("\nconflict: {s} via {s}, confirmed={}, service={s}, owner pid {d} {s}\n", .{
            c.name(), c.ifname(), c.confirmed, c.service(), if (c.owner) |o| o.pid else 0, if (c.owner) |*o| o.path() else "",
        });
    }
}

test "system VPN services from scutil" {
    const line = "* (Connected)      B4828DCE-64B6-4A53-A881-63C325816318 VPN (hidemyname.vpn) \"hidemyname.vpn (OpenVPN)\"       [VPN:hidemyname.vpn]";
    const s = parseServiceLine(line).?;
    try std.testing.expect(s.connected);
    try std.testing.expectEqualStrings("B4828DCE-64B6-4A53-A881-63C325816318", s.id);
    try std.testing.expectEqualStrings("hidemyname.vpn (OpenVPN)", s.name);
    const off = parseServiceLine("* (Disconnected)   C6074C63-DD5A-4B37-9DCB-D7DA36B94FF3 VPN (com.x) \"v2RayTun\"  [VPN:com.x]").?;
    try std.testing.expect(!off.connected);
    try std.testing.expect(parseServiceLine("Available network connection services in the current set (*=enabled):") == null);
    const status = "Connected\nExtended Status <dictionary> {\n  IPv4 : <dictionary> {\n    InterfaceName : utun7\n  }\n  StartMessage : <dictionary> {\n    SessionPID : 21909\n  }\n}";
    try std.testing.expectEqualStrings("utun7", statusField(status, "InterfaceName").?);
    try std.testing.expectEqualStrings("21909", statusField(status, "SessionPID").?);
    try std.testing.expect(statusField(status, "Missing") == null);
}

test "a system proxy on this machine" {
    try std.testing.expect(localProxy("<dictionary> {\n  SOCKSEnable : 1\n  SOCKSPort : 1080\n  SOCKSProxy : 127.0.0.1\n}"));
    try std.testing.expect(!localProxy("<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : proxy.corp\n}"));
    try std.testing.expect(!localProxy("<dictionary> {\n  HTTPEnable : 0\n  HTTPProxy : 127.0.0.1\n}"));
    try std.testing.expect(!localProxy("<dictionary> {\n  FTPPassive : 1\n}"));
}

test "bundle and name of an owner" {
    try std.testing.expectEqualStrings("/Applications/Happ.app", bundleOf("/Applications/Happ.app/Contents/MacOS/happd"));
    try std.testing.expectEqualStrings("", bundleOf("/opt/homebrew/bin/sing-box"));
    if (!on_macos) return;
    var c: Conflict = .{};
    var id: Identity = .{ .pid = 9, .uid = 0, .ppid = 1, .start_us = 1 };
    const p = "/Applications/Happ.app/Contents/MacOS/happd";
    @memcpy(id.path_buf[0..p.len], p);
    id.path_len = p.len;
    c.setOwner(id, true);
    try std.testing.expectEqualStrings("Happ", c.name());
    try std.testing.expectEqualStrings("/Applications/Happ.app", c.bundle());
}
