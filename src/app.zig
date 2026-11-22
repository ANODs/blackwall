//! Application context: owns the model and the engine, runs background
//! jobs (subscription download, latency probes) and applies their results
//! on the UI thread.

const std = @import("std");
const builtin = @import("builtin");
const dvui = @import("dvui");
const core = @import("core");
const apps_platform = @import("platform/apps.zig");
const autostart = @import("platform/autostart.zig");
const conflicts_mod = @import("platform/conflicts.zig");
pub const Conflict = conflicts_mod.Conflict;
const link_mod = @import("link.zig");
const updater = @import("app/updater.zig");
const instance = @import("app/instance.zig");
const tray = @import("platform/tray.zig");
const build_options = @import("build_options");
const tr = @import("i18n.zig").t;

const model = core.model;
const Io = std.Io;

pub const Screen = enum { connect, apps, servers, stats, settings };

pub var gpa: std.mem.Allocator = undefined;
pub var io: Io = undefined;
pub var win: *dvui.Window = undefined;
pub var state: model.State = undefined;
pub var engine: core.engine.Engine = .{};
/// The background service (TUN or SOCKS5) and the window's link to it;
/// null in screenshot mode and where no service is shipped next to the
/// app. Then the in-window SOCKS5 proxy below carries the traffic.
pub var link: ?*link_mod.Link = null;
/// What the running service reported (set from link events).
pub var service_on: bool = false;
pub var service_tun: bool = false;
pub var service_socks: u16 = 0;
/// In-window SOCKS5 inbound, used when there is no service.
pub var proxy: core.proxy.Proxy = .{ .io = undefined };
pub const preferred_proxy_port = 1080;
pub var screen: Screen = .connect;
var previous: Screen = .connect;

/// Switch screens, remembering where we came from for the back arrow.
pub fn go(to: Screen) void {
    if (to == screen) return;
    previous = screen;
    screen = to;
}

pub fn back() void {
    const to: Screen = if (previous == screen) .connect else previous;
    previous = .connect;
    screen = to;
}
pub var config_dir: []const u8 = "";
/// the user's home folder (HOME, or USERPROFILE on Windows)
pub var home_dir: ?[]const u8 = null;
/// HOME and XDG_CONFIG_HOME, for the login item
var env_paths: autostart.Env = .{};

/// Short status line shown at the bottom of the window for a few seconds.
pub var notice_buf: [160]u8 = undefined;
pub var notice_len: usize = 0;
pub var notice_bad: bool = false;
pub var notice_until_ns: i128 = 0;

pub var fetching: u32 = 0;
pub var probing: bool = false;

var last_tick_ns: i128 = 0;
var dirty: bool = false;
/// false in screenshot mode so reviews never touch the user's config
pub var persist: bool = true;

pub const Result = union(enum) {
    ping: struct { id: u32, member: ?u8, ms: ?u16 },
    ping_done,
    sub: struct { sub_id: u32, body: ?[]u8, meta: ?Meta = null },
    update_staged: std.SemanticVersion,
    update_failed: std.SemanticVersion,
    link: link_mod.Event,
    conflicts: []Conflict,
    conflict_stop: ?conflicts_mod.StopError,
    /// another start of the app asks this window to show itself, or to
    /// leave for a newer release (app/instance.zig)
    instance: instance.Signal,
};

var results: std.ArrayList(Result) = .empty;
var results_mutex: Io.Mutex = .init;

pub fn init(w: *dvui.Window) !void {
    win = w;
    gpa = w.gpa;
    io = dvui.io;
    state = .init(gpa);
    proxy.io = io;
    // first, so that a fresh version crashing anywhere below is rolled back
    updater.resumeInstall();

    if (dvui.App.main_init) |mi| {
        const env = mi.environ_map;
        home_dir = env.get("HOME") orelse env.get("USERPROFILE");
        config_dir = try configDir(env);
        env_paths = .{ .home = env.get("HOME"), .xdg_config = env.get("XDG_CONFIG_HOME") };
        // screenshot mode (src/shots.zig) touches neither the config nor the service
        if (env.get("BLACKWALL_SHOTS") != null) persist = false;
    }

    // screenshot mode shows sample data only, never the user's servers
    var unreadable = false;
    if (persist) _ = core.store.load(gpa, io, config_dir, &state) catch |err| blk: {
        // kept aside, so the first save does not replace it with nothing
        std.log.err("config not loaded: {t}; kept as {s}", .{ err, core.store.unreadable_name });
        core.store.setAside(io, config_dir) catch |e| std.log.err("config not set aside: {t}", .{e});
        state.deinit();
        state = .init(gpa);
        unreadable = true;
        break :blk false;
    };

    apps_platform.discover(io, &state, home_dir);
    refreshCarried();

    // the sample data only where it replaces nothing of the user's: it sets
    // routes and sites of its own, which leaving it clears
    if (state.subs.items.len == 0 and state.domains.items.len == 0 and !state.hasRules()) {
        try core.demo.load(&state, tr.demo_sub);
        engine.simulate_traffic = true;
    } else {
        probeAll();
    }
    dvui.reduce_motion = state.settings.reduce_motion;
    if (unreadable) notify(true, tr.config_unreadable, .{});
    updater.start();
    if (persist and config_dir.len > 0)
        link = link_mod.Link.init(gpa, io, config_dir, build_options.version, tr.admin_prompt, onLinkEvent);
    if (persist) instance.watch(io, onInstance);
    // follows the app if it was moved or updated in place
    if (persist and state.settings.launch_at_login) autostart.apply(gpa, io, env_paths, true);
    // an update restarted the window while its proxy was on
    const resumed = takeReconnectMark();
    syncBootHold();
    if (state.settings.auto_connect or resumed) connect();
    // otherwise the link reports what it found (a running service, or
    // nothing: see `.idle`), and the guard starts from there
}

fn configDir(env: *std.process.Environ.Map) ![]const u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    return gpa.dupe(u8, settingsDir(&buf, env) orelse return error.NameTooLong);
}

/// The user's settings folder; also asked before the window exists (its
/// log, src/report.zig).
pub fn settingsDir(buf: []u8, env: *std.process.Environ.Map) ?[]const u8 {
    const h = env.get("HOME") orelse env.get("USERPROFILE") orelse return std.fmt.bufPrint(buf, ".blackwall", .{}) catch null;
    return switch (builtin.os.tag) {
        .macos => std.fmt.bufPrint(buf, "{s}/Library/Application Support/BLACKWALL", .{h}),
        .windows => std.fmt.bufPrint(buf, "{s}\\BLACKWALL", .{env.get("APPDATA") orelse h}),
        else => if (env.get("XDG_CONFIG_HOME")) |x|
            std.fmt.bufPrint(buf, "{s}/blackwall", .{x})
        else
            std.fmt.bufPrint(buf, "{s}/.config/blackwall", .{h}),
    } catch null;
}

/// Another start asks this window something (on the watcher's thread).
fn onInstance(what: instance.Signal) void {
    pushResult(.{ .instance = what });
}

/// A newer release takes over: leave, and leave the service as it is. The
/// new window adopts it and restarts it from its own binary, as after an
/// update, so the traffic is carried all the while.
fn handOver() void {
    std.log.info("a newer release takes over: leaving", .{});
    if (dirty) _ = writeConfig();
    std.process.exit(0);
}

/// Quit: nothing of the app stays behind. The VPN is disconnected, the
/// service ends and lets the traffic go, and this waits until it has. The
/// one thing that stays is what the user asked to stay: with "protect
/// when the VPN is off" and applications held to the VPN, the service
/// keeps holding those (as after Disconnect), or quitting the app would
/// send them out with the real address.
fn quitService() void {
    const l = link orelse return;
    if (!persist) return;
    if (canGuard()) {
        if (!guarding()) disconnect();
    } else release();
    l.drain(15_000);
}

pub fn deinit() void {
    // a clean quit also counts as a successful first start
    if (updater.verifying) updater.confirm();
    proxy.stop();
    quitService();
    save();
    state.deinit();
    gpa.free(config_dir);
}

pub fn markDirty() void {
    dirty = true;
}

/// Settings toggle "Launch at login".
pub fn setLaunchAtLogin(on: bool) void {
    state.settings.launch_at_login = on;
    markDirty();
    if (persist) autostart.apply(gpa, io, env_paths, on);
}

/// Write config.json; false (after telling the user) when that failed.
fn writeConfig() bool {
    dirty = false;
    if (config_dir.len == 0 or !persist) return false;
    core.store.save(gpa, io, config_dir, &state) catch |err| {
        std.log.err("config not saved: {t}", .{err});
        notify(true, tr.save_failed, .{});
        return false;
    };
    return true;
}

/// Whether the helper should hold all traffic from boot until the service
/// is up. Only when this app is sure to come and take over: it starts at
/// login, in TUN mode, and then either connects or guards.
fn bootHoldWanted() bool {
    const s = &state.settings;
    if (state.demo or !persist or !link_mod.hold_supported) return false;
    if (!s.launch_at_login or s.tunnel_mode != .tun or s.kill_switch == .off) return false;
    return s.auto_connect or (s.protect_when_off and state.hasProtectedApps());
}

var boot_hold_sent: ?bool = null;

/// Keep the helper's hold-from-boot flag in step with the settings.
fn syncBootHold() void {
    const want = bootHoldWanted();
    if (boot_hold_sent == want) return;
    const l = link orelse return;
    boot_hold_sent = want;
    l.post(.{ .hold = want });
}

pub fn save() void {
    if (!writeConfig()) return;
    syncBootHold();
    // the running service follows: routes by reloading, the TUN's own
    // settings (mode, kill switch, IPv6, LAN, MTU) by restarting
    const l = link orelse return;
    // the kill switch was turned off while it held the traffic: let go
    if (engine.status == .blocked and state.settings.kill_switch == .off) return release();
    if (!service_on) return;
    // nothing left to guard (the rules or the setting changed)
    if (state.settings.standby and !canGuard()) return release();
    var want = wanted();
    if (std.meta.eql(appliedFor(want), applied)) return l.post(.reload);
    applied = appliedFor(want);
    if (!state.settings.standby) {
        engine.status = .reconnecting;
        engine.pending = true;
    }
    // only the user's own settings change these, so they are there for a
    // password prompt (switching to TUN the first time installs the helper)
    want.interactive = true;
    l.post(.{ .restart = want });
}

/// Which servers this build can carry, and which one "Fastest" means; both
/// change with the server list and with latency results.
fn refreshCarried() void {
    if (state.demo) return;
    for (state.servers.items) |*sv| sv.carried = core.proxy.carries(sv);
    updateAutoServer();
}

fn updateAutoServer() void {
    if (state.demo) return;
    const id: ?u32 = if (state.fastest()) |sv| sv.id else null;
    if (id == state.settings.auto_server) return;
    state.settings.auto_server = id;
    markDirty();
}

pub fn notify(bad: bool, comptime fmt: []const u8, args: anytype) void {
    notice_fix = false;
    // a long server name must not turn the message into nothing: what fits
    // is shown, cut between characters
    var w: Io.Writer = .fixed(&notice_buf);
    w.print(fmt, args) catch {};
    var len = w.end;
    while (len > 0 and !std.unicode.utf8ValidateSlice(notice_buf[0..len])) len -= 1;
    notice_len = len;
    notice_bad = bad;
    notice_until_ns = dvui.frameTimeNS() + 4 * std.time.ns_per_s;
}

/// Called once per frame before any UI.
pub fn frame() void {
    drainResults();

    const now = dvui.frameTimeNS();
    engine.advance(dvui.secondsSinceLastFrame());
    if (last_tick_ns == 0) last_tick_ns = now;
    if (now - last_tick_ns >= std.time.ns_per_s) {
        last_tick_ns = now;
        // the provider's refresh period (profile-update-interval)
        if (!state.demo and persist) if (state.dueForRefresh(Io.Clock.real.now(io).toSeconds())) |sub| fetch(sub.id);
        // while the service runs, its status reports drive the counters
        if (!service_on) {
            reportFault(now);
            engine.real_dt = 1;
            engine.real_totals = if (proxy.running.load(.acquire))
                .{ proxy.meter.down.load(.monotonic), proxy.meter.up.load(.monotonic) }
            else
                null;
            engine.tick(&state);
        }
    }
    if (dirty) save();
    if (retry_at_ns != 0 and now >= retry_at_ns) {
        retry_at_ns = 0;
        if (want_on and !service_on and !engine.pending) startService(false);
    }
    updater.frame(now);

    // wake up once a second for counters; continuously only while animating
    const id = dvui.parentGet().extendId(@src(), 0);
    if (dvui.timerDoneOrNone(id)) dvui.timer(id, 1_000_000);
    if (engine.busy()) dvui.refresh(null, @src(), null);
}

pub fn pushResult(r: Result) void {
    results_mutex.lockUncancelable(io);
    results.append(gpa, r) catch {};
    results_mutex.unlock(io);
    dvui.refresh(win, @src(), null);
}

fn drainResults() void {
    results_mutex.lockUncancelable(io);
    var batch = results;
    results = .empty;
    results_mutex.unlock(io);
    defer batch.deinit(gpa);

    for (batch.items) |r| switch (r) {
        .ping => |p| state.recordPing(p.id, p.member, p.ms),
        .ping_done => {
            probing = false;
            updateAutoServer();
        },
        .sub => |s| {
            fetching -|= 1;
            defer if (s.body) |b| gpa.free(b);
            var meta = s.meta;
            defer if (meta) |*m| m.deinit();
            applyFetched(s.sub_id, s.body, if (meta) |m| m.value else null);
        },
        .update_staged => |v| updater.staged = v,
        .update_failed => |v| updater.failed(v),
        .link => |ev| onLink(ev),
        .conflicts => |list| onConflicts(list),
        .conflict_stop => |err| onConflictStop(err),
        .instance => |what| switch (what) {
            .show => tray.reveal(),
            .quit => handOver(),
        },
    };
}

/// A downloaded subscription: its servers, and what the provider says about
/// it (in the body's comment lines, overridden by its headers).
fn applyFetched(sub_id: u32, body: ?[]u8, headers: ?model.SubMeta) void {
    const sub = state.subById(sub_id) orelse return;
    const bytes = body orelse {
        sub.last_error = true;
        notify(true, tr.sub_not_updated, .{});
        return;
    };
    var parsed = core.sublink.parseBody(gpa, bytes) catch {
        sub.last_error = true;
        notify(true, tr.sub_no_servers, .{});
        return;
    };
    defer parsed.deinit();
    state.applySubscription(sub_id, parsed.servers) catch return;
    state.applyMeta(sub_id, parsed.meta) catch {};
    if (headers) |h| state.applyMeta(sub_id, h) catch {};
    refreshCarried();
    if (state.subById(sub_id)) |s2| {
        s2.last_error = false;
        s2.updated_unix = Io.Clock.real.now(io).toSeconds();
    }
    const skipped = parsed.unsupported + parsed.malformed;
    if (skipped > 0)
        notify(false, tr.servers_skipped, .{ parsed.servers.len, skipped })
    else
        notify(false, tr.servers_n, .{parsed.servers.len});
    markDirty();
    probeAll();
}

// ---------------------------------------------------------------- subscriptions

pub const AddError = error{ Empty, OutOfMemory };

/// Accepts a subscription URL or pasted connection links / base64 block.
pub fn addFromText(raw: []const u8) AddError!void {
    const input = std.mem.trim(u8, raw, " \t\r\n");
    if (input.len == 0) return error.Empty;

    const is_url = std.ascii.startsWithIgnoreCase(input, "https://") or std.ascii.startsWithIgnoreCase(input, "http://");
    if (is_url) {
        leaveDemo();
        const sub = try state.addSubscription(hostOf(input), input);
        markDirty();
        fetch(sub.id);
        return;
    }

    var parsed = core.sublink.parseBody(gpa, input) catch |err| switch (err) {
        error.Empty => return error.Empty,
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer parsed.deinit();
    leaveDemo();
    var sub_id: ?u32 = null;
    for (state.subs.items) |s| if (s.url.len == 0) {
        sub_id = s.id;
    };
    if (sub_id == null) sub_id = (try state.addSubscription(tr.keys_sub, "")).id;
    for (parsed.servers) |n| _ = try state.addServer(sub_id.?, n);
    refreshCarried();
    const skipped = parsed.unsupported + parsed.malformed;
    if (skipped > 0)
        notify(false, tr.added_skipped, .{ parsed.servers.len, skipped })
    else
        notify(false, tr.added_n, .{parsed.servers.len});
    markDirty();
    probeAll();
}

fn leaveDemo() void {
    if (!state.demo) return;
    state.clearDemo();
    engine.simulate_traffic = false;
    disconnect();
    // the sample graph and totals are not the user's traffic
    engine.resetHistory();
}

fn hostOf(url: []const u8) []const u8 {
    const start = (std.mem.indexOf(u8, url, "://") orelse return url) + 3;
    var end = url.len;
    for (url[start..], start..) |c, i| {
        if (c == '/' or c == '?' or c == ':' or c == '#') {
            end = i;
            break;
        }
    }
    const host = url[start..end];
    return if (host.len == 0) url else host;
}

pub fn fetch(sub_id: u32) void {
    const sub = state.subById(sub_id) orelse return;
    if (sub.url.len == 0) return;
    const url = gpa.dupe(u8, sub.url) catch return;
    const t = std.Thread.spawn(.{}, fetchThread, .{ sub_id, url }) catch {
        gpa.free(url);
        return;
    };
    t.detach();
    fetching += 1;
}

pub fn fetchAll() void {
    for (state.subs.items) |s| fetch(s.id);
}

fn fetchThread(sub_id: u32, url: []u8) void {
    defer gpa.free(url);
    var meta: ?Meta = null;
    const body = download(url, &meta) catch null;
    pushResult(.{ .sub = .{ .sub_id = sub_id, .body = body, .meta = meta } });
}

/// What the provider's headers said, decoded (its own arena).
const Meta = struct {
    arena: std.heap.ArenaAllocator,
    value: model.SubMeta,

    fn deinit(m: *Meta) void {
        m.arena.deinit();
    }
};

/// The subscription's body; its headers into `meta` (title, refresh
/// period, announcement, support link). Providers pick the format by the
/// User-Agent: Xray JSON (with groups) for the clients they know.
fn download(url: []const u8, meta: *?Meta) ![]u8 {
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    const uri = try std.Uri.parse(url);
    var req = try client.request(.GET, uri, .{
        .redirect_behavior = .init(3),
        .headers = .{ .user_agent = .{ .override = "BLACKWALL/" ++ @import("build_options").version } },
    });
    defer req.deinit();
    try req.sendBodiless();
    var redirect_buf: [8 * 1024]u8 = undefined;
    var res = try req.receiveHead(&redirect_buf);
    if (res.head.status != .ok) return error.BadStatus;

    // the header bytes are the connection's: decoded before the body is read
    var m: Meta = .{ .arena = .init(gpa), .value = .{} };
    errdefer m.deinit();
    var title: ?[]const u8 = null;
    var interval: ?[]const u8 = null;
    var announce: ?[]const u8 = null;
    var support: ?[]const u8 = null;
    var it = res.head.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "profile-title")) title = h.value;
        if (std.ascii.eqlIgnoreCase(h.name, "profile-update-interval")) interval = h.value;
        if (std.ascii.eqlIgnoreCase(h.name, "announce")) announce = h.value;
        if (std.ascii.eqlIgnoreCase(h.name, "support-url")) support = h.value;
    }
    m.value = try core.sublink.metaFromHeaders(m.arena.allocator(), title, interval, announce, support);

    const decompress_buf = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(decompress_buf);
    var transfer_buf: [64]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    const reader = res.readerDecompressing(&transfer_buf, &decompress, decompress_buf);
    // the whole body (one `stream` call is one chunk of it), 4 MiB at most
    const body = reader.allocRemaining(gpa, .limited(4 << 20)) catch |err| switch (err) {
        error.ReadFailed => return res.bodyErr().?,
        else => |e| return e,
    };
    meta.* = m;
    return body;
}

// ---------------------------------------------------------------- latency

const ProbeJob = struct {
    targets: []model.State.ProbeTarget,
    /// measured by the service: its sockets bypass the TUN, ours do not
    via_service: bool,
    next: std.atomic.Value(usize) = .init(0),
    workers_left: std.atomic.Value(usize),
};

const probe_workers = 4;

/// TCP connect time to every server, a few at a time.
pub fn probeAll() void {
    if (probing or state.demo) return;
    // a group's servers each, so that its time is its best one's
    const targets = state.probeTargets(gpa) catch return;
    if (targets.len == 0) return gpa.free(targets);
    const job = gpa.create(ProbeJob) catch {
        for (targets) |t| gpa.free(t.host);
        return gpa.free(targets);
    };
    const n = @min(probe_workers, targets.len);
    job.* = .{ .targets = targets, .via_service = service_on, .workers_left = .init(n) };
    probing = true;
    for (0..n) |_| {
        const t = std.Thread.spawn(.{}, probeThread, .{job}) catch {
            finishWorker(job);
            continue;
        };
        t.detach();
    }
}

fn probeThread(job: *ProbeJob) void {
    while (true) {
        const i = job.next.fetchAdd(1, .monotonic);
        if (i >= job.targets.len) break;
        const t = job.targets[i];
        const ms = if (job.via_service) servicePing(t.host, t.port) orelse probe(t.host, t.port) else probe(t.host, t.port);
        pushResult(.{ .ping = .{ .id = t.id, .member = t.member, .ms = ms } });
    }
    finishWorker(job);
}

fn finishWorker(job: *ProbeJob) void {
    if (job.workers_left.fetchSub(1, .acq_rel) != 1) return;
    for (job.targets) |t| gpa.free(t.host);
    gpa.free(job.targets);
    gpa.destroy(job);
    pushResult(.ping_done);
}

const probe_timeout_ms = 2500;

/// The service's measurement: `null` only when it could not be asked
/// (an older service, or none), `.{ null }` when the server is unreachable.
fn servicePing(host: []const u8, port: u16) ??u16 {
    var line: Io.Writer.Allocating = .init(gpa);
    defer line.deinit();
    std.json.Stringify.value(core.ipc.Request{ .cmd = "ping", .host = host, .port = port }, .{}, &line.writer) catch return null;
    line.writer.writeByte('\n') catch return null;
    var path_buf: [256]u8 = undefined;
    const answer = core.ipc.request(gpa, io, core.ipc.socketPath(&path_buf, config_dir), line.written(), probe_timeout_ms + 2000) catch |err| switch (err) {
        // asked, but the measurement did not come back in time
        error.Timeout => return @as(?u16, null),
        else => return null,
    };
    defer gpa.free(answer);
    const r = std.json.parseFromSlice(core.ipc.PingReply, gpa, answer, .{ .ignore_unknown_fields = true }) catch return null;
    defer r.deinit();
    // an older service answers {"error":"unknown command"}
    if (std.mem.indexOf(u8, answer, "\"ms\"") == null) return null;
    const ms = r.value.ms orelse return @as(?u16, null);
    const out: u16 = @intCast(@min(ms, 9999));
    return @as(?u16, out);
}

/// TCP connect time in milliseconds, or null when unreachable.
/// std's connect has no timeout on POSIX yet, so the connect runs as a
/// concurrent task that is cancelled once the deadline passes.
fn probe(host: []const u8, port: u16) ?u16 {
    var done: std.atomic.Value(bool) = .init(false);
    const start = Io.Clock.awake.now(io);
    var task = io.concurrent(connectOnce, .{ host, port, &done }) catch return null;
    while (!done.load(.acquire)) {
        if (start.untilNow(io, .awake).toMilliseconds() >= probe_timeout_ms) break;
        io.sleep(.fromMilliseconds(10), .awake) catch break;
    }
    const ms = task.cancel(io) orelse return null;
    return @intCast(std.math.clamp(ms, 1, 9999));
}

fn connectOnce(host: []const u8, port: u16, done: *std.atomic.Value(bool)) ?i64 {
    defer done.store(true, .release);
    const opts: Io.net.IpAddress.ConnectOptions = .{ .mode = .stream };
    const start = Io.Clock.awake.now(io);
    const stream = blk: {
        if (Io.net.IpAddress.parse(host, port)) |addr| {
            break :blk addr.connect(io, opts) catch return null;
        } else |_| {
            const name = Io.net.HostName.init(host) catch return null;
            break :blk name.connect(io, port, opts) catch return null;
        }
    };
    stream.close(io);
    return start.untilNow(io, .awake).toMilliseconds();
}

// ---------------------------------------------------------------- helpers for the UI

pub fn selectServer(id: ?u32) void {
    state.settings.selected_server = id;
    markDirty();
    // held by the kill switch for want of a usable server: try this one
    if (engine.status == .blocked) return connect();
    if (engine.status != .connected) return;
    if (state.demo) {
        engine.status = .reconnecting;
        engine.connecting_left = 0.6;
    } else if (!service_on) {
        // the service re-reads the selection on save; the in-window proxy restarts
        disconnect();
        connect();
    }
}

/// The default route's server as an outbound, or null after telling the
/// user why it cannot carry traffic.
fn defaultOutbound() ?core.proxy.Outbound {
    if (state.settings.default_route == .direct) return .direct;
    const sv = state.currentServer() orelse {
        notify(true, tr.no_server, .{});
        return null;
    };
    return core.proxy.outboundFromLink(sv.link, sv.host, sv.port) catch |err| {
        notify(true, "{s}: {s}", .{
            sv.name,
            switch (err) {
                // a scheme, or a Shadowsocks cipher, this build does not speak
                error.UnsupportedProtocol, error.UnsupportedMethod => tr.err_protocol,
                error.UnsupportedSecurity => tr.err_security,
                error.BadRealityKey => tr.err_reality_key,
                // a plugin is a transport of its own around Shadowsocks
                error.UnsupportedTransport, error.UnsupportedPlugin => tr.err_transport,
                error.UnsupportedFlow => tr.err_flow,
                error.BadLink, error.BadUuid, error.BadPassword => tr.err_key,
            },
        });
        return null;
    };
}

/// Start carrying traffic. With sample data this only drives the simulated
/// state machine; with real servers it starts the background service, or
/// the in-window proxy where there is none.
pub fn connect() void {
    if (state.demo) return engine.connect();
    // another VPN in the way is told about (and can be fixed) in either mode
    checkConflicts();
    if (link != null) {
        if (want_on and !state.settings.standby and engine.status != .blocked and (service_on or engine.pending)) return;
        // no usable server (the user was told why): nothing changes, a
        // guard or a held connection stays as it is
        if (defaultOutbound() == null) return;
        want_on = true;
        // what is captured already (the guard, or the kill switch holding
        // a dropped connection) stays captured if this attempt fails
        ever_up = service_on or engine.status == .blocked;
        retry_n = 0;
        retry_at_ns = 0;
        state.settings.standby = false;
        return startService(true);
    }
    if (proxy.running.load(.acquire)) return;
    const outbound = defaultOutbound() orelse return;
    proxy.setOutbound(outbound);
    proxy.start(preferred_proxy_port) catch proxy.start(0) catch |err| {
        notify(true, tr.proxy_failed, .{err});
        return;
    };
    engine.last_real = .{ proxy.meter.down.load(.monotonic), proxy.meter.up.load(.monotonic) };
    engine.connect();
    notify(false, "SOCKS5 127.0.0.1:{d}", .{proxy.port});
}

var last_fault: core.proxy.Fault = .none;
var last_fault_ns: i128 = 0;

fn reportFault(now: i128) void {
    showFault(proxy.meter.fault.swap(.none, .monotonic), now);
}

/// Tell the user once why connections to the server fail; repeats of the
/// same reason are folded for half a minute.
fn showFault(fault: core.proxy.Fault, now: i128) void {
    if (fault == .none) return;
    if (fault == last_fault and now - last_fault_ns < 30 * std.time.ns_per_s) return;
    last_fault = fault;
    last_fault_ns = now;
    notify(true, "{s}", .{switch (fault) {
        .unreachable_server => tr.fault_unreachable,
        .handshake => tr.fault_handshake,
        .reality_rejected => tr.fault_reality,
        .none => unreachable,
    }});
}

/// Turn the VPN off. Applications with a rule that sends them through the
/// VPN (or blocks them) stay without network when the guard is enabled:
/// the service keeps running for them alone, everything else goes direct.
pub fn disconnect() void {
    // a chosen server that left its subscription while in use goes now
    if (state.dropVanishedChoice()) markDirty();
    proxy.stop();
    retry_at_ns = 0;
    retry_n = 0;
    engine.pending = false;
    clearAppRates();
    if (!canGuard()) return release();
    state.settings.standby = true;
    want_on = true;
    ever_up = true;
    engine.disconnect();
    startService(false);
}

/// Whether the guard can hold anything: it needs the TUN, the setting, and
/// at least one application with such a rule.
fn canGuard() bool {
    return link != null and link_mod.tun_supported and !state.demo and persist and
        state.settings.protect_when_off and state.settings.tunnel_mode == .tun and
        state.hasProtectedApps();
}

/// The VPN is off and the service only holds the applications with a rule.
pub fn guarding() bool {
    return service_on and state.settings.standby;
}

/// Stop everything and give all traffic back to the normal routes.
fn release() void {
    want_on = false;
    ever_up = false;
    retry_at_ns = 0;
    service_on = false;
    active_server = null;
    engine.pending = false;
    engine.real_apps = false;
    engine.disconnect();
    clearAppRates();
    if (state.settings.standby) {
        state.settings.standby = false;
        _ = writeConfig();
    }
    // always, even when nothing seems to run: this also releases traffic the
    // helper still holds for a service that is gone
    if (link) |l| l.post(.stop);
}

/// The VPN cannot come back by itself and the kill switch is on: what is
/// captured stays captured (and blocked) until the user connects again or
/// turns the kill switch off. Letting go here would send every protected
/// application out with the real address.
fn hold() void {
    retry_at_ns = 0;
    service_on = false;
    engine.pending = false;
    engine.real_apps = false;
    clearAppRates();
    engine.status = .blocked;
}

/// Server the service really uses for the main route (a reserve server
/// when the main one stopped working), from its status.
pub var active_server: ?u32 = null;
/// which of its group's servers carries it
var active_member: u16 = 0;
var last_switches: u32 = 0;
var mode_fix_sent = false;
/// A start or restart is on its way: the statuses still arriving are the
/// old service's and say nothing about the mode the new one will run in.
var awaiting_up = false;

/// The server to show as the one in use.
pub fn shownServer() ?*model.Server {
    if (service_on and !state.settings.standby) {
        if (active_server) |id| if (state.serverById(id)) |sv| return sv;
    }
    return state.currentServer();
}

/// Which of `sv`'s group members carries the main route now; null when
/// `sv` is not in use.
pub fn memberInUse(sv: *const model.Server) ?usize {
    if (!service_on or state.settings.standby) return null;
    return if (active_server == sv.id) active_member else null;
}

/// Where `sv` was seen to exit (a group: its member in use), when that is
/// not what its provider says; null otherwise.
pub fn otherExit(sv: *const model.Server) ?[2]u8 {
    const cc = if (sv.isGroup()) blk: {
        const m = memberInUse(sv) orelse return null;
        break :blk if (m < sv.members.len) sv.members[m].exit else return null;
    } else sv.exit;
    if (!model.knownCountry(cc) or std.mem.eql(u8, &cc, &sv.country)) return null;
    return cc;
}

// ---------------------------------------------------------------- service

/// The user wants the VPN on: set by connect(), cleared by disconnect().
/// Events of a start the user has since cancelled are ignored by it.
var want_on = false;
/// The service came up at least once since the user asked for it: a later
/// failure is a drop to recover from, not a refusal to report and stop at.
var ever_up = false;
/// Reconnecting after a drop, with growing pauses. The kill switch keeps
/// the traffic captured meanwhile.
var retry_at_ns: i128 = 0;
var retry_n: u8 = 0;
const retry_delays_s = [_]u8{ 2, 5, 10, 30, 60 };

/// Ask the link for a service. `interactive` when the user just clicked
/// Connect: only then may the administrator prompt appear.
fn startService(interactive: bool) void {
    const l = link orelse return;
    const standby = state.settings.standby;
    // tells the user why there is nothing to connect to (the guard needs no server)
    if (!standby and defaultOutbound() == null) return giveUp();
    _ = writeConfig(); // the service reads config.json
    var want = wanted();
    want.interactive = interactive;
    applied = appliedFor(want);
    if (!standby) {
        engine.pending = true;
        engine.connect();
        if (ever_up) engine.status = .reconnecting;
    }
    // a running service (the guard, or the VPN going into guard) is
    // replaced; the helper keeps the capture meanwhile
    awaiting_up = true;
    l.post(if (service_on) .{ .restart = want } else .{ .start = want });
}

/// Stop trying. Traffic that was never captured has nothing to protect and
/// is given back; once something was captured, the kill switch decides.
fn giveUp() void {
    if (ever_up and state.settings.kill_switch != .off) return hold();
    release();
}

fn scheduleRetry() void {
    const delay: i128 = retry_delays_s[@min(retry_n, retry_delays_s.len - 1)];
    retry_n +|= 1;
    retry_at_ns = dvui.frameTimeNS() + delay * std.time.ns_per_s;
    engine.pending = false;
    engine.status = if (state.settings.standby) .disconnected else .reconnecting;
}

/// How the service should run with the current settings.
fn wanted() link_mod.Options {
    const tun = link_mod.tun_supported and state.settings.tunnel_mode == .tun;
    return .{ .tun = tun, .socks = if (tun) 0 else preferred_proxy_port, .mtu = state.settings.mtu };
}

/// The settings a running service cannot pick up without a restart.
const Applied = struct {
    tun: bool = false,
    kill_switch: model.KillSwitch = .off,
    ipv6: model.Ipv6Mode = .block,
    allow_lan: bool = true,
    mtu: u16 = 0,
    /// VPN or guard: the service starts differently for each
    standby: bool = false,
};
var applied: Applied = .{};

fn appliedFor(o: link_mod.Options) Applied {
    // without the TUN nothing but the proxy port matters, and that is fixed
    if (!o.tun) return .{};
    const s = state.settings;
    return .{ .tun = true, .kill_switch = if (s.standby) .selective else s.kill_switch, .ipv6 = s.ipv6, .allow_lan = s.allow_lan, .mtu = o.mtu, .standby = s.standby };
}

/// Runs on the link thread.
fn onLinkEvent(ev: link_mod.Event) void {
    pushResult(.{ .link = ev });
}

var first_status = true;
var last_status_ns: i128 = 0;
/// a restart into a newer release's service is under way (after an update)
pub var stale_restart = false;

fn onLink(ev: link_mod.Event) void {
    switch (ev) {
        .up => |u| {
            awaiting_up = false;
            // the helper is the current one now (it may just have been
            // installed): tell it again what to do at boot
            boot_hold_sent = null;
            syncBootHold();
            // a start the user cancelled meanwhile: the stop behind it follows
            if (!want_on and !u.startup) return;
            // a service from before this window: the VPN is on
            want_on = true;
            const was_stale_restart = stale_restart and !u.adopted;
            stale_restart = false;
            service_on = true;
            service_tun = u.tun;
            service_socks = u.socks_port;
            ever_up = true;
            retry_n = 0;
            retry_at_ns = 0;
            engine.pending = false;
            engine.real_apps = true;
            if (state.settings.standby) engine.disconnect() else engine.status = .connected;
            first_status = true;
            if (u.adopted) applied = appliedFor(wanted());
            if (u.stale) {
                // the service of an older release: restart it from this
                // release's binary (kept as it is if that needs a password)
                stale_restart = true;
                if (link) |l| l.post(.{ .restart = wanted() });
            } else if (!u.adopted and !u.tun and u.socks_port != 0 and !was_stale_restart) {
                notify(false, "SOCKS5 127.0.0.1:{d}", .{u.socks_port});
            }
        },
        .status => |p| {
            defer p.deinit();
            if (service_on) applyStatus(&p.value);
        },
        .kept => {
            // the restart needs the administrator first; the running service
            // carries on with what it has, and a later Connect updates it
            stale_restart = false;
            awaiting_up = false;
            applied = .{ .mtu = std.math.maxInt(u16) };
            // the guard could not replace the VPN's service: a VPN that
            // stays on behind a window saying "off" would be a lie
            if (state.settings.standby) return release();
            if (service_on) {
                engine.pending = false;
                engine.status = .connected;
            }
        },
        .down => |d| {
            awaiting_up = false;
            service_on = false;
            service_tun = false;
            service_socks = 0;
            engine.real_apps = false;
            clearAppRates();
            if (d.why == .stopped) {
                // asked for; a stray start finished in between may have shown
                // Connected, so settle the state here
                if (!want_on) {
                    engine.pending = false;
                    engine.disconnect();
                }
                return;
            }
            const failed_restart = stale_restart;
            stale_restart = false;
            // tell the reason once per series of attempts
            if (retry_n == 0 or !ever_up) switch (d.why) {
                .stopped => unreachable,
                .need_admin => notify(true, "{s}", .{tr.svc_need_admin}),
                .conflict => {
                    notify(true, tr.svc_conflict, .{d.detail.text()});
                    // which program it is, and the way to fix it
                    checkConflicts();
                },
                .failed => notify(true, tr.svc_failed, .{failureText(d.detail.text())}),
                .crashed => notify(true, "{s}", .{tr.svc_crashed}),
            };
            if (failed_restart and updater.verifying) return updater.rollBack();
            if (!want_on) {
                engine.pending = false;
                engine.disconnect();
                return;
            }
            // the very first attempt failed, or the administrator is needed
            // first: stop trying (what was captured stays with the kill switch)
            if (d.why == .need_admin or !ever_up) return giveUp();
            // a drop: the kill switch keeps the traffic, we come back by ourselves
            scheduleRetry();
        },
        // the helper holds traffic for a service that is gone (it died while
        // the window was closed): bring it back, or give the traffic back
        // when there is nothing to carry it with
        .orphaned => {
            if (service_on or engine.pending or state.demo) {
                if (state.demo) if (link) |l| l.post(.stop);
                return;
            }
            want_on = true;
            ever_up = true;
            retry_n = 0;
            startService(false);
        },
        // nothing runs and nothing is held: the VPN is off. Applications
        // that may only use it are held from the start.
        .idle => if (!want_on and !engine.pending and !state.demo) startGuard(),
    }
}

/// A start failure in words where there are words for it; the error name otherwise.
fn failureText(name: []const u8) []const u8 {
    const known = [_]struct { []const u8, []const u8 }{
        .{ "HelperNotResponding", tr.why_helper_silent },
        .{ "HelperNotAnswering", tr.why_helper_silent },
        .{ "AddressInUse", tr.why_port_busy },
        .{ "Timeout", tr.why_timeout },
        .{ "Exited", tr.why_exited },
    };
    for (known) |k| if (std.mem.eql(u8, name, k[0])) return k[1];
    return name;
}

// ---------------------------------------------------------------- conflicts (concept 7.1)

/// Other VPNs in the way, from the last check.
pub var conflicts: []Conflict = &.{};
pub var show_conflicts = false;
/// a check or a stop is running
pub var conflict_busy = false;
/// the polite stop did not free the network
pub var conflict_failed = false;
/// the notice carries "Fix"
pub var notice_fix = false;
var conflict_name_buf: [64]u8 = undefined;
var conflict_name_len: usize = 0;

fn checkConflicts() void {
    if (!conflicts_mod.supported or conflict_busy or !persist) return;
    conflict_busy = true;
    const t = std.Thread.spawn(.{}, conflictCheckThread, .{}) catch {
        conflict_busy = false;
        return;
    };
    t.detach();
}

fn conflictCheckThread() void {
    const list = conflicts_mod.detect(gpa, io) catch gpa.alloc(Conflict, 0) catch return;
    pushResult(.{ .conflicts = list });
}

fn onConflicts(list: []Conflict) void {
    conflict_busy = false;
    gpa.free(conflicts);
    conflicts = list;
    if (list.len == 0) {
        show_conflicts = false;
        conflict_failed = false;
        return;
    }
    notify(true, tr.conflict_notice, .{list[0].name()});
    notice_fix = true;
    notice_until_ns += 8 * std.time.ns_per_s;
}

/// "Stop and reconnect" (or, `kill`, the forceful way) for conflict `i`.
pub fn stopConflict(i: usize, kill: bool) void {
    if (conflict_busy or i >= conflicts.len) return;
    const cf = conflicts[i];
    conflict_name_len = @min(cf.name().len, conflict_name_buf.len);
    @memcpy(conflict_name_buf[0..conflict_name_len], cf.name()[0..conflict_name_len]);
    conflict_busy = true;
    const t = std.Thread.spawn(.{}, conflictStopThread, .{ cf, kill }) catch {
        conflict_busy = false;
        return;
    };
    t.detach();
}

fn conflictStopThread(cf: Conflict, kill: bool) void {
    const err: ?conflicts_mod.StopError = if (conflicts_mod.stop(gpa, io, config_dir, &cf, kill)) |_| null else |e| e;
    pushResult(.{ .conflict_stop = err });
}

fn onConflictStop(err: ?conflicts_mod.StopError) void {
    conflict_busy = false;
    const name = conflict_name_buf[0..conflict_name_len];
    if (err) |e| switch (e) {
        error.StillActive => {
            conflict_failed = true;
            notify(true, tr.conflict_persists, .{name});
        },
        // it changed meanwhile: look again
        error.Gone => checkConflicts(),
        error.NeedsHelper, error.Refused, error.UnknownOwner => {
            conflict_failed = true;
            notify(true, tr.conflict_failed, .{name});
        },
    } else {
        // the network is free: check it again, then connect
        conflict_failed = false;
        show_conflicts = false;
        notice_fix = false;
        notify(false, tr.conflict_stopped, .{name});
        if (!state.demo) {
            disconnect();
            connect();
        } else checkConflicts();
    }
}

pub fn openConflictApp(i: usize) void {
    if (i >= conflicts.len) return;
    const t = std.Thread.spawn(.{}, conflictOpenThread, .{conflicts[i]}) catch return;
    t.detach();
}

fn conflictOpenThread(cf: Conflict) void {
    conflicts_mod.openApp(io, &cf);
}

fn clearAppRates() void {
    for (state.apps.items) |*a| {
        a.online = false;
        a.down_bps = 0;
        a.up_bps = 0;
    }
}

/// Counters from the service: totals, per-application rates, faults.
fn applyStatus(st: *const core.ipc.Status) void {
    const now = dvui.frameTimeNS();
    const dt: f32 = if (last_status_ns == 0) 1 else std.math.clamp(@as(f32, @floatFromInt(now - last_status_ns)) / std.time.ns_per_s, 0.2, 5);
    last_status_ns = now;
    if (std.meta.stringToEnum(core.proxy.Fault, st.fault)) |f| showFault(f, now);
    // a service in the other mode than the window means (a start that
    // crossed a mode change): replace it once
    if (st.standby != state.settings.standby and !awaiting_up) {
        if (!mode_fix_sent) if (link) |l| {
            mode_fix_sent = true;
            l.post(.{ .restart = wanted() });
        };
    } else mode_fix_sent = false;
    // the main route's real server; a change is worth telling
    active_server = if (st.server != 0) st.server else null;
    active_member = st.member;
    // where it exits, once a request through it said: kept with the server
    if (st.server != 0 and st.exit.len == 2 and !state.demo) {
        if (state.recordExit(st.server, st.member, st.exit[0..2].*)) {
            // a change waiting to be saved takes this along; otherwise
            // only the file is written, the service has nothing to reload
            if (!dirty) _ = writeConfig();
        }
    }
    if (st.switches != last_switches) {
        if (!first_status and st.switches > last_switches) {
            if (state.serverById(st.server)) |sv| {
                const main = if (state.currentServer()) |cur| cur.id == sv.id else false;
                if (main) notify(false, tr.reserve_back, .{sv.name}) else notify(false, tr.reserve_now, .{sv.name});
            }
        }
        last_switches = st.switches;
    }

    for (state.apps.items) |*a| {
        a.online = false;
        a.down_bps = 0;
        a.up_bps = 0;
    }
    for (st.apps) |s| {
        const a = state.appById(s.id) orelse seenApp(s.id) orelse continue;
        // a restarted service counts from zero again
        const dd = if (first_status) 0 else s.down -| a.total_down;
        const du = if (first_status) 0 else s.up -| a.total_up;
        a.total_down = s.down;
        a.total_up = s.up;
        a.down_bps = @as(f32, @floatFromInt(dd)) / dt;
        a.up_bps = @as(f32, @floatFromInt(du)) / dt;
        a.online = s.active > 0 or dd + du > 0;
    }

    if (first_status) engine.last_real = .{ st.down, st.up };
    first_status = false;
    engine.real_totals = .{ st.down, st.up };
    engine.real_dt = dt;
    engine.tick(&state);
}

/// A program the service saw that is not in the list yet (command-line
/// tools, apps outside the scanned folders): listed so it can get a rule.
fn seenApp(id: []const u8) ?*model.App {
    if (id.len == 0 or id[0] != '/') return null;
    var name = std.fs.path.basename(id);
    if (std.mem.endsWith(u8, name, ".app")) name = name[0 .. name.len - 4];
    if (name.len == 0) return null;
    return state.addApp(id, name, id) catch null;
}

const reconnect_mark = "reconnect";

/// An update relaunched the window while the in-window proxy was on.
pub fn takeReconnectMark() bool {
    if (config_dir.len == 0 or !persist) return false;
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, "{s}/" ++ reconnect_mark, .{config_dir}) catch return false;
    std.Io.Dir.cwd().deleteFile(io, path) catch return false;
    return true;
}

pub fn setReconnectMark() void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, "{s}/" ++ reconnect_mark, .{config_dir}) catch return;
    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "" }) catch {};
}

pub fn toggle() void {
    if (engine.status == .disconnected or engine.status == .blocked) connect() else disconnect();
}

pub fn setRoute(app: *model.App, route: model.Route) void {
    app.route = route;
    if (state.demo) return;
    markDirty();
    // the first rule that must hold while the VPN is off starts the guard
    // (the last one going away ends it: see `save`)
    if (!service_on and !want_on and engine.status == .disconnected) startGuard();
}

pub fn setDomainRoute(d: *model.Domain, route: model.Route) void {
    d.route = route;
    if (state.demo) return;
    markDirty();
    if (!service_on and !want_on and engine.status == .disconnected) startGuard();
}

/// A site rule from what the user typed; false when it is not a host name.
pub fn addDomain(text: []const u8) bool {
    _ = state.addDomain(text) catch return false;
    if (!state.demo) markDirty();
    return true;
}

pub fn removeDomain(index: usize) void {
    state.removeDomain(index);
    if (!state.demo) markDirty();
}

/// With the VPN off, hold the applications that may only use the VPN.
fn startGuard() void {
    if (!canGuard()) {
        if (state.settings.standby) {
            state.settings.standby = false;
            markDirty();
        }
        return;
    }
    state.settings.standby = true;
    want_on = true;
    ever_up = false;
    startService(false);
}

pub const Summary = struct { vpn: u32 = 0, direct: u32 = 0, dpi: u32 = 0, blocked: u32 = 0 };

/// How the online apps are currently split between kinds of exits.
pub fn summary() Summary {
    var s: Summary = .{};
    for (state.apps.items) |a| {
        if (!a.online) continue;
        const r: model.Route = if (a.route == .default) state.settings.default_route else a.route;
        switch (r) {
            .direct => s.direct += 1,
            .dpi => s.dpi += 1,
            .block => s.blocked += 1,
            else => s.vpn += 1,
        }
    }
    return s;
}
