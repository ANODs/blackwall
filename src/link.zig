//! The window's side of the background service (blackwall-service): starts
//! it — in TUN mode on macOS after making sure the root helper is
//! installed; on Windows as the system service the app put in place with
//! the administrator's consent (core/win_scm.zig) — stops it, asks it to re-read the configuration and reads its
//! counters once a second.
//!
//! Everything that can block (starting processes, the administrator
//! prompt, socket calls) runs on one thread of its own. The window posts
//! requests with `post` and receives `Event`s through the callback; when no
//! service runs the thread sleeps until the next request.

const std = @import("std");
const builtin = @import("builtin");
const core = @import("core");

const Io = std.Io;
const ipc = core.ipc;
const helper = core.helper_ipc;
const c = std.c;
const log = std.log.scoped(.link);

/// The service runs on macOS, Linux and Windows (not on Android, where the app is the service).
pub const supported = builtin.os.tag == .macos or builtin.os.tag == .windows or (builtin.os.tag == .linux and !builtin.abi.isAndroid());
/// Capturing all traffic: through the root helper on macOS; on Linux
/// through blackwall-tun, which holds CAP_NET_ADMIN granted to it once (see
/// `ensureCapabilities`) and hands the device to the service.
/// On Windows the service itself creates the Wintun adapter; it runs as
/// LocalSystem.
pub const tun_supported = supported;
/// Holding traffic from boot until the service is up is the helper's job.
pub const hold_supported = builtin.os.tag == .macos;
const on_linux = builtin.os.tag == .linux and !builtin.abi.isAndroid();
const on_windows = builtin.os.tag == .windows;
const scm = core.win_scm;
/// The service and wintun.dll the Windows app carries (build.zig).
const win_embed = if (on_windows) @import("win_embed") else struct {};

/// A process id where processes are numbers (on Windows the SCM knows the service).
const Pid = if (supported and !on_windows) c.pid_t else i32;

pub const Options = struct {
    /// capture all traffic through the TUN (needs the helper)
    tun: bool,
    /// local SOCKS5 port, 0 = none
    socks: u16 = 0,
    /// 0 = the service's default
    mtu: u16 = 0,
    /// the user just clicked Connect and can answer the administrator
    /// prompt; automatic starts never install or update the helper
    interactive: bool = false,
};

pub const Request = union(enum) {
    start: Options,
    /// stop the running service and start it again with these options;
    /// when that would need the administrator, the running one is kept
    restart: Options,
    stop,
    reload,
    /// tell the helper whether to hold traffic from boot until the service
    /// is there (see `helper_ipc`); nothing happens without a helper
    hold: bool,
};

pub const Failure = enum {
    /// stopped on request
    stopped,
    /// the administrator prompt was cancelled or the helper did not come up
    need_admin,
    /// another VPN captures the traffic; its interfaces are in `detail`
    conflict,
    /// the service ended by itself
    crashed,
    /// it did not start; the reason is in `detail`
    failed,
};

pub const Event = union(enum) {
    /// the service answers. `adopted`: this request did not start it;
    /// `startup`: it was already running when the window opened
    up: struct { tun: bool, socks_port: u16, adopted: bool, stale: bool, startup: bool = false },
    /// counters; the receiver calls `deinit`
    status: std.json.Parsed(ipc.Status),
    down: struct { why: Failure, detail: Detail = .{} },
    /// the helper still captures traffic but no service carries it (the
    /// service died while the window was closed)
    orphaned,
    /// a restart was skipped because the helper needs the administrator
    /// first; the running service carries on as it was
    kept,
    /// at startup: no service runs and the helper holds nothing
    idle,
};

pub const Detail = struct {
    buf: [64]u8 = undefined,
    len: u8 = 0,

    pub fn text(d: *const Detail) []const u8 {
        return d.buf[0..d.len];
    }

    fn of(s: []const u8) Detail {
        var d: Detail = .{};
        const n = @min(s.len, d.buf.len);
        @memcpy(d.buf[0..n], s[0..n]);
        d.len = @intCast(n);
        return d;
    }
};

pub const Link = struct {
    gpa: std.mem.Allocator,
    io: Io,
    /// directory holding blackwall-service and blackwall-helper
    bin_dir: []const u8,
    config_dir: []const u8,
    /// release of this window; a service of another release is restarted
    build: []const u8,
    /// text of the administrator prompt (macOS)
    admin_prompt: []const u8,
    sink: *const fn (Event) void,

    mutex: Io.Mutex = .init,
    cond: Io.Condition = .init,
    queue: [8]Request = undefined,
    queued: usize = 0,

    // link thread only
    /// the service when this window started it (reaped here)
    child: ?Pid = null,
    /// the service's process, from its status when another window started it
    pid: Pid = 0,
    running: bool = false,
    tun: bool = false,
    socks: u16 = 0,
    misses: u8 = 0,

    /// null when the service binary is not next to the executable.
    pub fn init(gpa: std.mem.Allocator, io: Io, config_dir: []const u8, build: []const u8, admin_prompt: []const u8, sink: *const fn (Event) void) ?*Link {
        if (!supported) return null;
        const exe = std.process.executablePathAlloc(io, gpa) catch return null;
        defer gpa.free(exe);
        const dir = std.fs.path.dirname(exe) orelse return null;
        // Windows carries the service inside the app
        if (!on_windows) {
            var probe_buf: [std.fs.max_path_bytes]u8 = undefined;
            const probe = std.fmt.bufPrint(&probe_buf, "{s}/blackwall-service", .{dir}) catch return null;
            std.Io.Dir.cwd().access(io, probe, .{ .execute = true }) catch return null;
        }
        const l = gpa.create(Link) catch return null;
        l.* = .{
            .gpa = gpa,
            .io = io,
            .bin_dir = gpa.dupe(u8, dir) catch {
                gpa.destroy(l);
                return null;
            },
            .config_dir = config_dir,
            .build = build,
            .admin_prompt = admin_prompt,
            .sink = sink,
        };
        const t = std.Thread.spawn(.{ .stack_size = core.sys.stackSize(256 * 1024) }, run, .{l}) catch {
            gpa.free(l.bin_dir);
            gpa.destroy(l);
            return null;
        };
        t.detach();
        return l;
    }

    /// Queue a request for the link thread. Repeated reloads fold into one.
    pub fn post(l: *Link, r: Request) void {
        l.mutex.lockUncancelable(l.io);
        defer l.mutex.unlock(l.io);
        if (r == .reload) for (l.queue[0..l.queued]) |q| if (q == .reload) return;
        if (l.queued == l.queue.len) {
            std.mem.copyForwards(Request, l.queue[0 .. l.queue.len - 1], l.queue[1..]);
            l.queued -= 1;
        }
        l.queue[l.queued] = r;
        l.queued += 1;
        l.cond.signal(l.io);
    }

    /// Next request, or null after `ms` (forever when null).
    fn next(l: *Link, ms: ?i64) ?Request {
        l.mutex.lockUncancelable(l.io);
        defer l.mutex.unlock(l.io);
        if (l.queued == 0) {
            if (ms) |t| {
                l.cond.waitTimeout(l.io, &l.mutex, .{ .duration = .{ .raw = .fromMilliseconds(t), .clock = .awake } }) catch {};
            } else {
                l.cond.waitUncancelable(l.io, &l.mutex);
            }
        }
        if (l.queued == 0) return null;
        const r = l.queue[0];
        std.mem.copyForwards(Request, l.queue[0 .. l.queued - 1], l.queue[1..l.queued]);
        l.queued -= 1;
        return r;
    }

    fn run(l: *Link) void {
        l.adopt();
        var last_poll = Io.Clock.awake.now(l.io);
        while (true) {
            const req = l.next(if (l.running) 1000 else null);
            if (req) |r| switch (r) {
                .start => |o| l.start(o),
                .restart => |o| restart: {
                    // never leave the traffic captured with nothing behind it
                    // while waiting for a password nobody may be there to type
                    if (l.running and o.tun and !o.interactive and !l.privileged()) {
                        l.sink(.kept);
                        break :restart;
                    }
                    if (l.running) l.stop(if (l.tun and o.tun) "suspend" else "stop", false);
                    l.start(o);
                },
                .stop => l.stop("stop", true),
                .hold => |on| if (hold_supported) {
                    var buf: [64]u8 = undefined;
                    const line = std.fmt.bufPrint(&buf, "{{\"cmd\":\"hold\",\"hold\":{}}}\n", .{on}) catch unreachable;
                    if (ipc.request(l.gpa, l.io, helper.socket_path, line, 3000)) |answer| l.gpa.free(answer) else |_| {}
                },
                .reload => if (l.running) {
                    const line = ipc.call(l.gpa, l.io, l.socketPath(), "reload", 15_000) catch null;
                    if (line) |s| l.gpa.free(s);
                },
            };
            // counters once a second, however often requests arrive
            if (l.running and last_poll.untilNow(l.io, .awake).toMilliseconds() >= 900) {
                last_poll = Io.Clock.awake.now(l.io);
                l.poll();
            }
        }
    }

    /// A service left running by an earlier window, or a helper capturing
    /// traffic for a service that is gone.
    fn adopt(l: *Link) void {
        // one that is still starting (or busy) answers within its start budget
        if (l.waitAnswer(20_000)) |st| {
            l.took(&st.value);
            const stale = st.value.version != ipc.version or !std.mem.eql(u8, st.value.build, l.build);
            l.sink(.{ .up = .{ .tun = st.value.tun, .socks_port = st.value.socks_port, .adopted = true, .stale = stale, .startup = true } });
            l.sink(.{ .status = st });
            return;
        }
        if (hold_supported) if (l.helperReply()) |r| {
            defer r.deinit();
            if (r.value.ok and r.value.up) return l.sink(.orphaned);
        };
        // the device a service that is gone left behind keeps holding traffic
        if (on_linux and linuxDevice()) return l.sink(.orphaned);
        l.sink(.idle);
    }

    /// The service answered: remember what it is.
    fn took(l: *Link, st: *const ipc.Status) void {
        l.running = true;
        l.tun = st.tun;
        l.socks = st.socks_port;
        l.misses = 0;
        if (l.child == null) l.pid = st.pid;
    }

    fn start(l: *Link, o: Options) void {
        // never a second service next to one that answers (or is starting)
        if (!l.running) if (l.waitAnswer(20_000)) |st| {
            l.took(&st.value);
            const stale = st.value.version != ipc.version or !std.mem.eql(u8, st.value.build, l.build);
            l.sink(.{ .up = .{ .tun = st.value.tun, .socks_port = st.value.socks_port, .adopted = true, .stale = stale } });
            l.sink(.{ .status = st });
            return;
        };
        if (l.running) {
            l.sink(.{ .up = .{ .tun = l.tun, .socks_port = l.socks, .adopted = true, .stale = false } });
            return;
        }
        // Windows: the system service carries the proxy port too
        if (o.tun or on_windows) (if (on_windows) l.ensureWinService(o.interactive) else if (on_linux) l.ensureCapabilities(o.interactive) else l.ensureHelper(o.interactive)) catch |err| {
            log.err("helper: {t}", .{err});
            const why: Failure = switch (err) {
                error.Refused, error.NeedsAdministrator => .need_admin,
                else => .failed,
            };
            return l.sink(.{ .down = .{ .why = why, .detail = .of(@errorName(err)) } });
        };
        l.spawn(o) catch |err| {
            log.err("service not started: {t}", .{err});
            return l.sink(.{ .down = .{ .why = .failed, .detail = .of(@errorName(err)) } });
        };
        // the helper may take a few seconds (DNS, kill switch)
        const begin = Io.Clock.awake.now(l.io);
        while (begin.untilNow(l.io, .awake).toMilliseconds() < 20_000) {
            if (l.status()) |st| {
                l.took(&st.value);
                l.sink(.{ .up = .{ .tun = st.value.tun, .socks_port = st.value.socks_port, .adopted = false, .stale = false } });
                l.sink(.{ .status = st });
                return;
            }
            if (l.exited()) {
                var f = l.failure(.failed);
                if (f.detail.len == 0) f.detail = .of("Exited");
                return l.sink(.{ .down = f });
            }
            l.io.sleep(.fromMilliseconds(100), .awake) catch {};
        }
        l.kill();
        l.sink(.{ .down = .{ .why = .failed, .detail = .of("Timeout") } });
    }

    /// `cmd` is "stop" (release the TUN) or "suspend" (leave the capture to
    /// the kill switch while another service takes over).
    fn stop(l: *Link, cmd: []const u8, report: bool) void {
        const was_running = l.running;
        if (l.running) {
            if (ipc.call(l.gpa, l.io, l.socketPath(), cmd, 5000)) |line| l.gpa.free(line) else |_| {}
            // it undoes the TUN and the helper's state before it exits
            const begin = Io.Clock.awake.now(l.io);
            while (begin.untilNow(l.io, .awake).toMilliseconds() < 10_000) {
                if (l.exited()) break;
                l.io.sleep(.fromMilliseconds(50), .awake) catch {};
            } else l.kill();
        }
        l.running = false;
        // a service that died or was killed could not release the capture
        if (hold_supported and std.mem.eql(u8, cmd, "stop")) {
            if (ipc.call(l.gpa, l.io, helper.socket_path, "down", 5000)) |line| l.gpa.free(line) else |_| {}
        }
        if (on_linux and std.mem.eql(u8, cmd, "stop") and linuxDevice()) l.releaseDevice();
        // Windows: the filters a service that died left holding the traffic
        if (on_windows and !was_running and std.mem.eql(u8, cmd, "stop")) scm.start(&.{"--release"}) catch {};
        if (report) l.sink(.{ .down = .{ .why = .stopped } });
    }

    fn poll(l: *Link) void {
        if (l.status()) |st| {
            l.misses = 0;
            l.sink(.{ .status = st });
            return;
        }
        l.misses +|= 1;
        // a live service may just be busy; only a process that is gone (or
        // one we cannot see) counts as down
        if (!l.exited() and (l.child != null or l.pid != 0 or l.misses < 3)) return;
        l.running = false;
        l.kill();
        l.sink(.{ .down = l.failure(.crashed) });
    }

    fn status(l: *Link) ?std.json.Parsed(ipc.Status) {
        return l.statusOr(2000) catch null;
    }

    /// Status, or why there is none: a missing or refused socket means no
    /// service; a timeout means one that is busy (still starting, say).
    fn statusOr(l: *Link, timeout_ms: i64) !std.json.Parsed(ipc.Status) {
        const line = try ipc.call(l.gpa, l.io, l.socketPath(), "status", timeout_ms);
        defer l.gpa.free(line);
        return std.json.parseFromSlice(ipc.Status, l.gpa, line, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch error.BadReply;
    }

    /// The status of a service that is there, waiting up to `budget_ms` for
    /// one that is busy; null when there is none.
    fn waitAnswer(l: *Link, budget_ms: i64) ?std.json.Parsed(ipc.Status) {
        const begin = Io.Clock.awake.now(l.io);
        while (true) {
            if (l.statusOr(2000)) |st| return st else |err| switch (err) {
                error.FileNotFound, error.ConnectionRefused, error.NameTooLong => return null,
                else => {},
            }
            if (begin.untilNow(l.io, .awake).toMilliseconds() >= budget_ms) return null;
            l.io.sleep(.fromMilliseconds(250), .awake) catch {};
        }
    }

    var socket_buf: [std.fs.max_path_bytes]u8 = undefined;

    fn socketPath(l: *Link) []const u8 {
        return ipc.socketPath(&socket_buf, l.config_dir);
    }

    // ------------------------------------------------------------ process

    fn spawn(l: *Link, o: Options) !void {
        if (comptime on_windows) return l.spawnWin(o);
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const exe = try std.fmt.bufPrint(&path_buf, "{s}/blackwall-service", .{l.bin_dir});
        var file_buf: [std.fs.max_path_bytes]u8 = undefined;
        const dir = std.Io.Dir.cwd();
        dir.deleteFile(l.io, try std.fmt.bufPrint(&file_buf, "{s}/" ++ ipc.error_name, .{l.config_dir})) catch {};

        var socks_buf: [8]u8 = undefined;
        var mtu_buf: [8]u8 = undefined;
        var argv_buf: [10][]const u8 = undefined;
        var argv: std.ArrayList([]const u8) = .initBuffer(&argv_buf);
        argv.appendSliceAssumeCapacity(&.{ exe, "--config", l.config_dir });
        if (o.tun) argv.appendSliceAssumeCapacity(&.{ "--tun", if (on_linux) "auto" else "helper" });
        if (o.socks != 0) argv.appendSliceAssumeCapacity(&.{ "--socks", try std.fmt.bufPrint(&socks_buf, "{d}", .{o.socks}) });
        if (o.mtu != 0) argv.appendSliceAssumeCapacity(&.{ "--mtu", try std.fmt.bufPrint(&mtu_buf, "{d}", .{o.mtu}) });

        // its log replaces the previous run's; a fresh one each start keeps it small
        const log_path = try std.fmt.bufPrint(&file_buf, "{s}/" ++ ipc.log_name, .{l.config_dir});
        const log_file = try dir.createFile(l.io, log_path, .{ .truncate = true, .permissions = .fromMode(0o600) });
        defer log_file.close(l.io);
        const child = try std.process.spawn(l.io, .{
            .argv = argv.items,
            .stdin = .ignore,
            .stdout = .{ .file = log_file },
            .stderr = .{ .file = log_file },
            // its own process group: signals for the window (Ctrl-C in a
            // terminal) do not reach it, and it outlives the window
            .pgid = 0,
        });
        l.child = child.id;
    }

    /// Whether the service has ended (a child of ours is reaped here). False
    /// when its process is unknown.
    fn exited(l: *Link) bool {
        if (comptime on_windows) {
            const st = scm.query() orelse return true;
            return st == .stopped;
        }
        if (l.child) |pid| {
            var st: c_int = 0;
            if (c.waitpid(pid, &st, c.W.NOHANG) == 0) return false;
            l.child = null;
            return true;
        }
        if (l.pid <= 0) return false;
        if (c.kill(l.pid, @enumFromInt(0)) == 0 or c.errno(@as(c_int, -1)) != .SRCH) return false;
        l.pid = 0;
        return true;
    }

    /// Last resort for a service that neither answers nor stops.
    fn kill(l: *Link) void {
        if (comptime on_windows) return scm.stop();
        if (l.child) |pid| {
            _ = c.kill(pid, c.SIG.KILL);
            var st: c_int = 0;
            _ = c.waitpid(pid, &st, 0);
            l.child = null;
        } else if (l.pid > 0) {
            _ = c.kill(l.pid, c.SIG.KILL);
            l.pid = 0;
        }
    }

    /// What the service wrote before it ended, as a Failure.
    fn failure(l: *Link, default: Failure) @FieldType(Event, "down") {
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/" ++ ipc.error_name, .{l.config_dir}) catch return .{ .why = default };
        var buf: [256]u8 = undefined;
        const text = std.mem.trim(u8, std.Io.Dir.cwd().readFile(l.io, path, &buf) catch return .{ .why = default }, " \r\n");
        const name_end = std.mem.indexOfScalar(u8, text, ' ') orelse text.len;
        const name = text[0..name_end];
        if (std.mem.eql(u8, name, "Conflict")) return .{ .why = .conflict, .detail = .of(std.mem.trim(u8, text[name_end..], " ")) };
        if (std.mem.eql(u8, name, "HelperMissing") or std.mem.eql(u8, name, "NeedsAdministrator")) return .{ .why = .need_admin };
        if (name.len == 0) return .{ .why = default };
        return .{ .why = .failed, .detail = .of(name) };
    }

    /// Whether TUN mode can start without asking anyone.
    fn privileged(l: *Link) bool {
        if (on_linux) return l.capable();
        if (on_windows) return l.winServiceCurrent();
        return l.helperState() == .current;
    }

    // ------------------------------------------------------------ service (Windows)

    /// The installed service is this release's.
    fn winServiceCurrent(l: *Link) bool {
        if (comptime !on_windows) return false;
        if (scm.query() == null) return false;
        var env = win.env(l.gpa) orelse return false;
        defer env.deinit();
        var buf: [128]u8 = undefined;
        const have = scm.installedBuild(&env, &buf, l.io) orelse return false;
        return std.mem.eql(u8, have, l.build);
    }

    /// Puts this release's service in place. An installed service of an
    /// earlier release replaces itself with this one when it is signed (a
    /// release); otherwise, and the first time, the administrator's consent
    /// (UAC). The service then starts and stops at the window's word
    /// without asking.
    fn ensureWinService(l: *Link, interactive: bool) anyerror!void {
        if (comptime !on_windows) return error.Unsupported;
        if (l.winServiceCurrent()) return;
        // the service, unpacked where the installer or the old service reads it
        var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
        const dir = try std.fmt.bufPrint(&dir_buf, "{s}\\setup", .{l.config_dir});
        const cwd = std.Io.Dir.cwd();
        try cwd.createDirPath(l.io, dir);
        var p_buf: [std.fs.max_path_bytes]u8 = undefined;
        const exe = try std.fmt.bufPrint(&p_buf, "{s}\\blackwall-service.exe", .{dir});
        try cwd.writeFile(l.io, .{ .sub_path = exe, .data = win_embed.service });
        if (scm.query() != null and win_embed.service_sig.len > 0) {
            var s_buf: [std.fs.max_path_bytes]u8 = undefined;
            try cwd.writeFile(l.io, .{ .sub_path = try std.fmt.bufPrint(&s_buf, "{s}\\blackwall-service.sig", .{dir}), .data = win_embed.service_sig });
            if (scm.query() != .stopped) scm.stop();
            l.waitStopped();
            if (scm.start(&.{ "--upgrade", dir })) {
                l.waitStopped();
                if (l.winServiceCurrent()) return;
                log.info("the service keeps its release", .{});
            } else |err| log.info("service upgrade: {t}", .{err});
        }
        if (!interactive) return error.NeedsAdministrator;
        var sid_buf: [128]u8 = undefined;
        const sid = win.userSid(&sid_buf) orelse return error.NoUser;
        var params_buf: [std.fs.max_path_bytes + 256]u8 = undefined;
        const params = try std.fmt.bufPrint(&params_buf, "install --config \"{s}\" --user {s}", .{ l.config_dir, sid });
        try win.runElevated(exe, params);
        if (!l.winServiceCurrent()) return error.InstallFailed;
    }

    fn waitStopped(l: *Link) void {
        for (0..100) |_| {
            const st = scm.query() orelse return;
            if (st == .stopped) return;
            l.io.sleep(.fromMilliseconds(200), .awake) catch {};
        }
    }

    fn spawnWin(l: *Link, o: Options) !void {
        var file_buf: [std.fs.max_path_bytes]u8 = undefined;
        std.Io.Dir.cwd().deleteFile(l.io, try std.fmt.bufPrint(&file_buf, "{s}/" ++ ipc.error_name, .{l.config_dir})) catch {};
        var socks_buf: [8]u8 = undefined;
        var mtu_buf: [8]u8 = undefined;
        var argv_buf: [8][]const u8 = undefined;
        var argv: std.ArrayList([]const u8) = .initBuffer(&argv_buf);
        if (o.tun) argv.appendSliceAssumeCapacity(&.{ "--tun", "wintun" });
        if (o.socks != 0) argv.appendSliceAssumeCapacity(&.{ "--socks", try std.fmt.bufPrint(&socks_buf, "{d}", .{o.socks}) });
        if (o.mtu != 0) argv.appendSliceAssumeCapacity(&.{ "--mtu", try std.fmt.bufPrint(&mtu_buf, "{d}", .{o.mtu}) });
        try scm.start(argv.items);
    }

    // ------------------------------------------------------------ capabilities (Linux)

    /// The device is set up by blackwall-tun, which needs CAP_NET_ADMIN. It
    /// is granted to that file once, through polkit's password dialog. The
    /// service runs without it, so updating the service asks for nothing;
    /// only a changed blackwall-tun (the updater keeps an unchanged one)
    /// asks again at the next Connect.
    fn ensureCapabilities(l: *Link, interactive: bool) !void {
        if (!on_linux) return error.Unsupported;
        if (l.capable()) return;
        if (!interactive) return error.NeedsAdministrator;
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const tun = try std.fmt.bufPrint(&path_buf, "{s}/blackwall-tun", .{l.bin_dir});
        const pkexec = firstExisting(l.io, &.{ "/usr/bin/pkexec", "/bin/pkexec" }) orelse return error.NeedsAdministrator;
        const setcap = firstExisting(l.io, &.{ "/usr/sbin/setcap", "/sbin/setcap", "/usr/bin/setcap" }) orelse return error.SetcapMissing;
        var child = try std.process.spawn(l.io, .{
            .argv = &.{ pkexec, setcap, "cap_net_admin+ep", tun },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        const term = try child.wait(l.io);
        if (!l.capable()) {
            // 126: the dialog was dismissed, 127: not authorized
            return switch (term) {
                .exited => |code| if (code == 126 or code == 127) error.Refused else error.NeedsAdministrator,
                else => error.NeedsAdministrator,
            };
        }
    }

    /// blackwall-tun carries its file capability.
    fn capable(l: *Link) bool {
        if (!on_linux) return false;
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const p = std.fmt.bufPrint(path_buf[0 .. path_buf.len - 1], "{s}/blackwall-tun", .{l.bin_dir}) catch return false;
        path_buf[p.len] = 0;
        var value: [64]u8 = undefined;
        return getxattr(path_buf[0..p.len :0], "security.capability", &value, value.len) > 0;
    }

    /// Lets go of the device and the strict kill switch that a service
    /// which is gone left holding the traffic.
    fn releaseDevice(l: *Link) void {
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const tool = std.fmt.bufPrint(&path_buf, "{s}/blackwall-tun", .{l.bin_dir}) catch return;
        var child = std.process.spawn(l.io, .{ .argv = &.{ tool, "release" }, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore }) catch return;
        _ = child.wait(l.io) catch {};
    }

    // ------------------------------------------------------------ helper (macOS)

    fn helperReply(l: *Link) ?std.json.Parsed(helper.Reply) {
        const line = ipc.call(l.gpa, l.io, helper.socket_path, "status", 2000) catch return null;
        defer l.gpa.free(line);
        return std.json.parseFromSlice(helper.Reply, l.gpa, line, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch null;
    }

    const HelperState = enum {
        /// answers with this release's protocol and build
        current,
        /// answers, but is another release: needs reinstalling
        outdated,
        /// not installed or not running (no socket, nobody listening)
        missing,
        /// there but not answering usefully (busy, hung, another user's)
        unresponsive,
    };

    fn helperState(l: *Link) HelperState {
        const line = ipc.call(l.gpa, l.io, helper.socket_path, "status", 2000) catch |err| return switch (err) {
            error.FileNotFound, error.ConnectionRefused => .missing,
            else => .unresponsive,
        };
        defer l.gpa.free(line);
        const r = std.json.parseFromSlice(helper.Reply, l.gpa, line, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch return .unresponsive;
        defer r.deinit();
        if (!r.value.ok) return .unresponsive;
        // Administrator rights are asked for once, when the helper is set up.
        // Only a helper that speaks another protocol is reinstalled; one of
        // another release (r.value.build) keeps working, so updating the app
        // never asks for the password again.
        if (r.value.version != helper.version) return .outdated;
        return .current;
    }

    /// Installs (or updates) the helper with the administrator's consent.
    /// Only when the user is there to answer, and only for a helper that is
    /// missing or reported another release: a helper that does not answer
    /// is an error, not a reason to run a binary as root.
    fn ensureHelper(l: *Link, interactive: bool) anyerror!void {
        if (!tun_supported) return error.Unsupported;
        switch (l.helperState()) {
            .current => return,
            .unresponsive => return error.HelperNotResponding,
            .missing, .outdated => {},
        }
        // a helper from a release replaces itself with this app's newer
        // signed one: no administrator, also for automatic starts
        if (l.upgradeHelper()) {
            for (0..50) |_| {
                if (l.helperState() == .current) return;
                l.io.sleep(.fromMilliseconds(200), .awake) catch {};
            }
        }
        if (!interactive) return error.NeedsAdministrator;
        try l.installHelper();
        // launchd starts it right away; give it a moment to listen
        for (0..50) |_| {
            if (l.helperState() == .current) return;
            l.io.sleep(.fromMilliseconds(200), .awake) catch {};
        }
        return error.HelperNotAnswering;
    }

    /// Ask the installed helper to replace itself with the one in this app,
    /// which works when both come from releases (the helper checks the
    /// signature next to it). False when there is nothing to offer or the
    /// helper says no; the administrator prompt remains the other way.
    fn upgradeHelper(l: *Link) bool {
        var bin_buf: [std.fs.max_path_bytes]u8 = undefined;
        var sig_buf: [std.fs.max_path_bytes]u8 = undefined;
        const bin = std.fmt.bufPrint(&bin_buf, "{s}/blackwall-helper", .{l.bin_dir}) catch return false;
        const sig_path = std.fmt.bufPrint(&sig_buf, "{s}/../Resources/" ++ helper.sig_file, .{l.bin_dir}) catch return false;
        const sig = std.Io.Dir.cwd().readFileAlloc(l.io, sig_path, l.gpa, .limited(1024)) catch return false;
        defer l.gpa.free(sig);
        const line = std.json.Stringify.valueAlloc(l.gpa, .{ .cmd = "upgrade", .path = bin, .sig = sig }, .{}) catch return false;
        defer l.gpa.free(line);
        const req = std.mem.concat(l.gpa, u8, &.{ line, "\n" }) catch return false;
        defer l.gpa.free(req);
        const answer = ipc.request(l.gpa, l.io, helper.socket_path, req, 10_000) catch return false;
        defer l.gpa.free(answer);
        const r = std.json.parseFromSlice(helper.Reply, l.gpa, answer, .{ .ignore_unknown_fields = true }) catch return false;
        defer r.deinit();
        if (!r.value.ok) log.info("helper keeps its version: {s}", .{r.value.@"error"});
        return r.value.ok;
    }

    fn installHelper(l: *Link) !void {
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "{s}/blackwall-helper", .{l.bin_dir});
        const script = try adminScript(l.gpa, path, c.getuid(), l.admin_prompt);
        defer l.gpa.free(script);
        var child = try std.process.spawn(l.io, .{
            .argv = &.{ "/usr/bin/osascript", "-e", script },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        const term = try child.wait(l.io);
        // osascript fails with -128 when the user cancels
        if (term != .exited or term.exited != 0) return error.Refused;
    }
};

/// Windows calls of the window's side.
const win = struct {
    const w = std.os.windows;
    const W: std.builtin.CallingConvention = .winapi;
    const SHELLEXECUTEINFOW = extern struct {
        cbSize: u32 = @sizeOf(SHELLEXECUTEINFOW),
        fMask: u32 = 0,
        hwnd: ?w.HANDLE = null,
        lpVerb: ?[*:0]const u16 = null,
        lpFile: ?[*:0]const u16 = null,
        lpParameters: ?[*:0]const u16 = null,
        lpDirectory: ?[*:0]const u16 = null,
        nShow: i32 = 0,
        hInstApp: ?w.HANDLE = null,
        lpIDList: ?*anyopaque = null,
        lpClass: ?[*:0]const u16 = null,
        hkeyClass: ?w.HANDLE = null,
        dwHotKey: u32 = 0,
        hIcon: ?w.HANDLE = null,
        hProcess: ?w.HANDLE = null,
    };
    extern "shell32" fn ShellExecuteExW(info: *SHELLEXECUTEINFOW) callconv(W) i32;
    extern "kernel32" fn WaitForSingleObject(h: w.HANDLE, ms: u32) callconv(W) u32;
    extern "kernel32" fn GetExitCodeProcess(h: w.HANDLE, code: *u32) callconv(W) i32;
    extern "kernel32" fn GetLastError() callconv(W) u32;
    extern "kernel32" fn GetCurrentProcess() callconv(W) w.HANDLE;
    extern "kernel32" fn LocalFree(p: ?*anyopaque) callconv(W) ?*anyopaque;
    extern "advapi32" fn OpenProcessToken(process: w.HANDLE, access: u32, token: *w.HANDLE) callconv(W) i32;
    extern "advapi32" fn GetTokenInformation(token: w.HANDLE, class: u32, info: ?*anyopaque, len: u32, ret: *u32) callconv(W) i32;
    extern "advapi32" fn ConvertSidToStringSidW(sid: *anyopaque, out: *?[*:0]u16) callconv(W) i32;

    fn env(gpa: std.mem.Allocator) ?std.process.Environ.Map {
        return std.process.Environ.createMap(.{ .block = .global }, gpa) catch null;
    }

    /// The user's SID as text ("S-1-5-21-…").
    fn userSid(out: []u8) ?[]const u8 {
        var token: w.HANDLE = undefined;
        if (OpenProcessToken(GetCurrentProcess(), 0x8, &token) == 0) return null; // TOKEN_QUERY
        defer w.CloseHandle(token);
        var buf: [256]u8 align(8) = undefined;
        var len: u32 = 0;
        if (GetTokenInformation(token, 1, &buf, buf.len, &len) == 0) return null; // TokenUser
        // TOKEN_USER: { SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes } }
        const sid: *anyopaque = @ptrFromInt(std.mem.readInt(usize, buf[0..@sizeOf(usize)], .little));
        var text: ?[*:0]u16 = null;
        if (ConvertSidToStringSidW(sid, &text) == 0) return null;
        defer _ = LocalFree(text);
        const n = std.unicode.wtf16LeToWtf8(out, std.mem.sliceTo(text.?, 0));
        return out[0..n];
    }

    /// Runs `exe params` as an administrator (the UAC prompt) and waits.
    fn runElevated(exe: []const u8, params: []const u8) !void {
        var exe_w: [std.fs.max_path_bytes:0]u16 = undefined;
        var par_w: [std.fs.max_path_bytes + 256:0]u16 = undefined;
        const en = try std.unicode.wtf8ToWtf16Le(&exe_w, exe);
        exe_w[en] = 0;
        const pn = try std.unicode.wtf8ToWtf16Le(&par_w, params);
        par_w[pn] = 0;
        var info: SHELLEXECUTEINFOW = .{
            .fMask = 0x40, // SEE_MASK_NOCLOSEPROCESS
            .lpVerb = std.unicode.utf8ToUtf16LeStringLiteral("runas"),
            .lpFile = exe_w[0..en :0],
            .lpParameters = par_w[0..pn :0],
            .nShow = 0, // SW_HIDE
        };
        if (ShellExecuteExW(&info) == 0) {
            // ERROR_CANCELLED: the user said no
            return if (GetLastError() == 1223) error.Refused else error.NeedsAdministrator;
        }
        const h = info.hProcess orelse return;
        defer w.CloseHandle(h);
        _ = WaitForSingleObject(h, 120_000);
        var code: u32 = 1;
        _ = GetExitCodeProcess(h, &code);
        if (code != 0) return error.InstallFailed;
    }
};

extern "c" fn getxattr(path: [*:0]const u8, name: [*:0]const u8, value: [*]u8, size: usize) isize;

/// Whether the service's device exists (Linux): it outlives a service that
/// was killed, so that the traffic stays held.
fn linuxDevice() bool {
    if (!on_linux) return false;
    const fd = c.open("/sys/class/net/blackwall0", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    if (fd < 0) return false;
    _ = c.close(fd);
    return true;
}

fn firstExisting(io: Io, paths: []const []const u8) ?[]const u8 {
    for (paths) |p| {
        std.Io.Dir.cwd().access(io, p, .{}) catch continue;
        return p;
    }
    return null;
}

/// AppleScript that runs `<helper> install --uid <uid>` as root after the
/// system's administrator prompt. The path is quoted for the shell by
/// AppleScript itself; both strings are escaped for AppleScript.
fn adminScript(gpa: std.mem.Allocator, helper_path: []const u8, uid: c.uid_t, prompt: []const u8) ![]u8 {
    var s: std.ArrayList(u8) = .empty;
    errdefer s.deinit(gpa);
    try s.appendSlice(gpa, "do shell script (quoted form of \"");
    try appendEscaped(gpa, &s, helper_path);
    try s.print(gpa, "\") & \" install --uid {d}\" with administrator privileges with prompt \"", .{uid});
    try appendEscaped(gpa, &s, prompt);
    try s.appendSlice(gpa, "\"");
    return s.toOwnedSlice(gpa);
}

fn appendEscaped(gpa: std.mem.Allocator, s: *std.ArrayList(u8), text: []const u8) !void {
    for (text) |ch| {
        if (ch == '"' or ch == '\\') try s.append(gpa, '\\');
        try s.append(gpa, ch);
    }
}

test "administrator script quotes the path and escapes both strings" {
    const gpa = std.testing.allocator;
    const s = try adminScript(gpa, "/Apps/My \"VPN\"\\x/BLACKWALL.app/Contents/MacOS/blackwall-helper", 501, "Allow \"it\"");
    defer gpa.free(s);
    try std.testing.expectEqualStrings(
        "do shell script (quoted form of \"/Apps/My \\\"VPN\\\"\\\\x/BLACKWALL.app/Contents/MacOS/blackwall-helper\") & \" install --uid 501\" with administrator privileges with prompt \"Allow \\\"it\\\"\"",
        s,
    );
}

test "failure reasons from service.error" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(io, &dir_buf);
    var l: Link = .{ .gpa = std.testing.allocator, .io = io, .bin_dir = "", .config_dir = dir_buf[0..n], .build = "", .admin_prompt = "", .sink = undefined };
    try std.testing.expectEqual(Failure.crashed, l.failure(.crashed).why);
    try tmp.dir.writeFile(io, .{ .sub_path = ipc.error_name, .data = "Conflict utun5 utun6" });
    const f = l.failure(.failed);
    try std.testing.expectEqual(Failure.conflict, f.why);
    try std.testing.expectEqualStrings("utun5 utun6", f.detail.text());
    try tmp.dir.writeFile(io, .{ .sub_path = ipc.error_name, .data = "HelperMissing" });
    try std.testing.expectEqual(Failure.need_admin, l.failure(.failed).why);
    try tmp.dir.writeFile(io, .{ .sub_path = ipc.error_name, .data = "AddressInUse\n" });
    const g = l.failure(.crashed);
    try std.testing.expectEqual(Failure.failed, g.why);
    try std.testing.expectEqualStrings("AddressInUse", g.detail.text());
}
