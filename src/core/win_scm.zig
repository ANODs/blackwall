//! The service as a Windows service: installed once with the
//! administrator's consent, run by the Service Control Manager as
//! LocalSystem (Wintun, routes and the firewall need it), started and
//! stopped by the window of the user who installed it.
//!
//!   blackwall-service install --config DIR --user SID   (as an administrator)
//!   blackwall-service uninstall                         (as an administrator)
//!   blackwall-service --scm                             (by the SCM)
//!
//! `install` copies the executable and wintun.dll from its own folder to
//! %ProgramFiles%\BLACKWALL, where only administrators may write (the
//! system runs this file), registers the service with the user's
//! configuration folder fixed in its command line, and lets that user
//! start, stop and query it. The window passes only the SOCKS port and
//! the MTU when it starts the service.

const std = @import("std");
const builtin = @import("builtin");
const w = std.os.windows;

pub const service_name = "BLACKWALL";
const display_name = "BLACKWALL";

const W: std.builtin.CallingConvention = .winapi;
const SC_HANDLE = *opaque {};

const SERVICE_STATUS = extern struct {
    dwServiceType: u32 = 0x10, // SERVICE_WIN32_OWN_PROCESS
    dwCurrentState: u32,
    dwControlsAccepted: u32 = 0,
    dwWin32ExitCode: u32 = 0,
    dwServiceSpecificExitCode: u32 = 0,
    dwCheckPoint: u32 = 0,
    dwWaitHint: u32 = 0,
};
const SERVICE_TABLE_ENTRYW = extern struct {
    name: ?[*:0]const u16,
    proc: ?*const fn (argc: u32, argv: [*][*:0]u16) callconv(W) void,
};
const Handler = *const fn (control: u32, event: u32, data: ?*anyopaque, ctx: ?*anyopaque) callconv(W) u32;

extern "advapi32" fn StartServiceCtrlDispatcherW(table: [*]const SERVICE_TABLE_ENTRYW) callconv(W) i32;
extern "advapi32" fn RegisterServiceCtrlHandlerExW(name: [*:0]const u16, handler: Handler, ctx: ?*anyopaque) callconv(W) ?*anyopaque;
extern "advapi32" fn SetServiceStatus(h: *anyopaque, st: *const SERVICE_STATUS) callconv(W) i32;
extern "advapi32" fn OpenSCManagerW(machine: ?[*:0]const u16, db: ?[*:0]const u16, access: u32) callconv(W) ?SC_HANDLE;
extern "advapi32" fn OpenServiceW(scm: SC_HANDLE, name: [*:0]const u16, access: u32) callconv(W) ?SC_HANDLE;
extern "advapi32" fn CreateServiceW(scm: SC_HANDLE, name: [*:0]const u16, display: [*:0]const u16, access: u32, kind: u32, start: u32, err_ctl: u32, path: [*:0]const u16, group: ?[*:0]const u16, tag: ?*u32, deps: ?[*:0]const u16, user: ?[*:0]const u16, password: ?[*:0]const u16) callconv(W) ?SC_HANDLE;
extern "advapi32" fn ChangeServiceConfigW(svc: SC_HANDLE, kind: u32, start: u32, err_ctl: u32, path: ?[*:0]const u16, group: ?[*:0]const u16, tag: ?*u32, deps: ?[*:0]const u16, user: ?[*:0]const u16, password: ?[*:0]const u16, display: ?[*:0]const u16) callconv(W) i32;
extern "advapi32" fn DeleteService(svc: SC_HANDLE) callconv(W) i32;
extern "advapi32" fn CloseServiceHandle(h: SC_HANDLE) callconv(W) i32;
extern "advapi32" fn ControlService(svc: SC_HANDLE, control: u32, st: *SERVICE_STATUS) callconv(W) i32;
extern "advapi32" fn QueryServiceStatus(svc: SC_HANDLE, st: *SERVICE_STATUS) callconv(W) i32;
extern "advapi32" fn StartServiceW(svc: SC_HANDLE, argc: u32, argv: ?[*]const [*:0]const u16) callconv(W) i32;
extern "advapi32" fn SetServiceObjectSecurity(svc: SC_HANDLE, info: u32, sd: *anyopaque) callconv(W) i32;
extern "advapi32" fn ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl: [*:0]const u16, rev: u32, sd: *?*anyopaque, size: ?*u32) callconv(W) i32;
extern "kernel32" fn LocalFree(p: ?*anyopaque) callconv(W) ?*anyopaque;
extern "kernel32" fn GetLastError() callconv(W) u32;
extern "kernel32" fn CopyFileW(from: [*:0]const u16, to: [*:0]const u16, fail_if_exists: i32) callconv(W) i32;
extern "kernel32" fn MoveFileExW(from: [*:0]const u16, to: ?[*:0]const u16, flags: u32) callconv(W) i32;
extern "kernel32" fn CreateDirectoryW(path: [*:0]const u16, sa: ?*anyopaque) callconv(W) i32;
extern "kernel32" fn Sleep(ms: u32) callconv(W) void;

const SC_MANAGER_ALL_ACCESS = 0xF003F;
const SC_MANAGER_CONNECT = 0x1;
const SERVICE_ALL_ACCESS = 0xF01FF;
const SERVICE_QUERY_STATUS = 0x4;
const SERVICE_START = 0x10;
const SERVICE_STOP = 0x20;
const SERVICE_DEMAND_START = 3;
const SERVICE_ERROR_NORMAL = 1;
const SERVICE_NO_CHANGE = 0xffffffff;
const DACL_SECURITY_INFORMATION = 0x4;
const ERROR_SERVICE_EXISTS = 1073;
const ERROR_SERVICE_DOES_NOT_EXIST = 1060;
const ERROR_SERVICE_ALREADY_RUNNING = 1056;
const MOVEFILE_REPLACE_EXISTING = 0x1;
const MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

pub const State = enum(u32) { stopped = 1, start_pending = 2, stop_pending = 3, running = 4, continue_pending = 5, pause_pending = 6, paused = 7, _ };

fn wide(buf: []u16, s: []const u8) [:0]const u16 {
    const n = std.unicode.wtf8ToWtf16Le(buf[0 .. buf.len - 1], s) catch 0;
    buf[n] = 0;
    return buf[0..n :0];
}

const L = std.unicode.utf8ToUtf16LeStringLiteral;

// ------------------------------------------------------------ run by the SCM

/// What runs the service once the SCM has started it: the args after the
/// executable's own (its fixed `--config DIR` and the window's options),
/// and a call that stops it.
pub const Body = struct {
    run: *const fn (args: []const []const u8) void,
    stop: *const fn () void,
};

var body: Body = undefined;
var fixed_args: []const []const u8 = &.{};
var status_handle: ?*anyopaque = null;
var arena_buf: [16 * 1024]u8 = undefined;

/// Hands the process to the SCM; returns when the service has stopped.
/// `args` are the executable's own after `--scm` (the configuration folder).
pub fn dispatch(args: []const []const u8, b: Body) !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    body = b;
    fixed_args = args;
    const table = [_]SERVICE_TABLE_ENTRYW{
        .{ .name = L(service_name), .proc = serviceMain },
        .{ .name = null, .proc = null },
    };
    if (StartServiceCtrlDispatcherW(&table) == 0) return error.NotUnderScm;
}

fn report(state: State, exit_code: u32) void {
    const h = status_handle orelse return;
    const st: SERVICE_STATUS = .{
        .dwCurrentState = @intFromEnum(state),
        // stop and shutdown, once it runs
        .dwControlsAccepted = if (state == .running) 0x1 | 0x4 else 0,
        .dwWin32ExitCode = exit_code,
        .dwWaitHint = if (state == .running or state == .stopped) 0 else 15_000,
    };
    _ = SetServiceStatus(h, &st);
}

fn handler(control: u32, _: u32, _: ?*anyopaque, _: ?*anyopaque) callconv(W) u32 {
    switch (control) {
        1, 5 => { // STOP, SHUTDOWN
            report(.stop_pending, 0);
            // the handler must return at once; the stop itself talks to the
            // service's socket
            const t = std.Thread.spawn(.{}, struct {
                fn f() void {
                    body.stop();
                }
            }.f, .{}) catch return 0;
            t.detach();
            return 0;
        },
        4 => return 0, // INTERROGATE
        else => return 120, // ERROR_CALL_NOT_IMPLEMENTED
    }
}

fn serviceMain(argc: u32, argv: [*][*:0]u16) callconv(W) void {
    status_handle = RegisterServiceCtrlHandlerExW(L(service_name), handler, null);
    report(.start_pending, 0);
    // the fixed args, then what StartService passed (after the service's name)
    var fba: std.heap.FixedBufferAllocator = .init(&arena_buf);
    const a = fba.allocator();
    var list: std.ArrayList([]const u8) = .empty;
    list.appendSlice(a, fixed_args) catch {};
    var i: u32 = 1;
    while (i < argc) : (i += 1) {
        const s = std.unicode.wtf16LeToWtf8Alloc(a, std.mem.sliceTo(argv[i], 0)) catch continue;
        list.append(a, s) catch {};
    }
    report(.running, 0);
    body.run(list.items);
    report(.stopped, 0);
}

// ------------------------------------------------------------ install (as an administrator)

/// %ProgramFiles%\BLACKWALL
pub fn installDir(env: *std.process.Environ.Map, buf: []u8) []const u8 {
    const pf = env.get("ProgramFiles") orelse "C:\\Program Files";
    return std.fmt.bufPrint(buf, "{s}\\BLACKWALL", .{pf}) catch "C:\\Program Files\\BLACKWALL";
}

/// Copies the files next to `self_exe` into the install folder and
/// registers the service for `config_dir`, startable by `user_sid`.
pub fn install(env: *std.process.Environ.Map, self_exe: []const u8, config_dir: []const u8, user_sid: []const u8, build: []const u8) !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    // a SID is all the descriptor below takes from outside
    for (user_sid) |ch| if (!(std.ascii.isDigit(ch) or ch == 'S' or ch == '-')) return error.BadSid;
    for (config_dir) |ch| if (ch == '"') return error.BadPath;

    var dir_buf: [512]u8 = undefined;
    const dir = installDir(env, &dir_buf);
    var wb: [1024]u16 = undefined;
    _ = CreateDirectoryW(wide(&wb, dir), null);

    // the running service holds its executable: stop it first
    stopAndWait();

    const src_dir = std.fs.path.dirname(self_exe) orelse ".";
    for ([_][]const u8{ "blackwall-service.exe", "wintun.dll" }) |name| {
        var from_buf: [1024]u8 = undefined;
        var to_buf: [1024]u8 = undefined;
        const from = try std.fmt.bufPrint(&from_buf, "{s}\\{s}", .{ src_dir, name });
        const to = try std.fmt.bufPrint(&to_buf, "{s}\\{s}", .{ dir, name });
        if (std.ascii.eqlIgnoreCase(from, to)) continue;
        var fw: [1024]u16 = undefined;
        var tw: [1024]u16 = undefined;
        if (CopyFileW(wide(&fw, from), wide(&tw, to), 0) == 0) {
            // a wintun.dll still loaded by a service that is going away
            // is replaced at the next start of Windows
            std.log.err("copy {s}: error {d}", .{ name, GetLastError() });
            return error.CopyFailed;
        }
    }
    {
        var p_buf: [1024]u8 = undefined;
        const p = try std.fmt.bufPrint(&p_buf, "{s}\\build", .{dir});
        var pw: [1024]u16 = undefined;
        try writeSmallFile(wide(&pw, p), build);
    }

    var cmd_buf: [2048]u8 = undefined;
    const cmd = try std.fmt.bufPrint(&cmd_buf, "\"{s}\\blackwall-service.exe\" --scm --config \"{s}\"", .{ dir, config_dir });
    var cw: [2048]u16 = undefined;
    const scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS) orelse return error.NeedsAdministrator;
    defer _ = CloseServiceHandle(scm);
    var svc = CreateServiceW(scm, L(service_name), L(display_name), SERVICE_ALL_ACCESS, 0x10, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, wide(&cw, cmd), null, null, null, null, null);
    if (svc == null) {
        if (GetLastError() != ERROR_SERVICE_EXISTS) return error.CreateFailed;
        svc = OpenServiceW(scm, L(service_name), SERVICE_ALL_ACCESS) orelse return error.CreateFailed;
        if (ChangeServiceConfigW(svc.?, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, wide(&cw, cmd), null, null, null, null, null, null) == 0) return error.CreateFailed;
    }
    defer _ = CloseServiceHandle(svc.?);

    // the system and administrators as usual; the user may start, stop
    // and ask about it, nothing more
    var sddl_buf: [512]u8 = undefined;
    const sddl = try std.fmt.bufPrint(&sddl_buf, "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;{s})", .{user_sid});
    var sw: [512]u16 = undefined;
    var sd: ?*anyopaque = null;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(&sw, sddl), 1, &sd, null) == 0) return error.BadSid;
    defer _ = LocalFree(sd);
    if (SetServiceObjectSecurity(svc.?, DACL_SECURITY_INFORMATION, sd.?) == 0) return error.SecurityFailed;
}

pub fn uninstall() !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    stopAndWait();
    const scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS) orelse return error.NeedsAdministrator;
    defer _ = CloseServiceHandle(scm);
    const svc = OpenServiceW(scm, L(service_name), SERVICE_ALL_ACCESS) orelse return;
    defer _ = CloseServiceHandle(svc);
    _ = DeleteService(svc);
}

fn stopAndWait() void {
    const scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT) orelse return;
    defer _ = CloseServiceHandle(scm);
    const svc = OpenServiceW(scm, L(service_name), SERVICE_STOP | SERVICE_QUERY_STATUS) orelse return;
    defer _ = CloseServiceHandle(svc);
    var st: SERVICE_STATUS = .{ .dwCurrentState = 0 };
    _ = ControlService(svc, 1, &st);
    var waited: u32 = 0;
    while (waited < 20_000) : (waited += 200) {
        if (QueryServiceStatus(svc, &st) == 0 or st.dwCurrentState == @intFromEnum(State.stopped)) return;
        Sleep(200);
    }
}

fn writeSmallFile(path: [*:0]const u16, data: []const u8) !void {
    const k = struct {
        extern "kernel32" fn CreateFileW(name: [*:0]const u16, access: u32, share: u32, sa: ?*anyopaque, disp: u32, flags: u32, template: ?w.HANDLE) callconv(W) w.HANDLE;
        extern "kernel32" fn WriteFile(h: w.HANDLE, buf: [*]const u8, n: u32, written: ?*u32, ov: ?*anyopaque) callconv(W) i32;
    };
    // GENERIC_WRITE, CREATE_ALWAYS
    const h = k.CreateFileW(path, 0x40000000, 0, null, 2, 0x80, null);
    if (h == w.INVALID_HANDLE_VALUE) return error.WriteFailed;
    defer w.CloseHandle(h);
    if (k.WriteFile(h, data.ptr, @intCast(data.len), null, null) == 0) return error.WriteFailed;
}

// ------------------------------------------------------------ control (the window)

/// The service as the window sees it.
pub fn query() ?State {
    if (comptime builtin.os.tag != .windows) return null;
    const scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT) orelse return null;
    defer _ = CloseServiceHandle(scm);
    const svc = OpenServiceW(scm, L(service_name), SERVICE_QUERY_STATUS) orelse return null;
    defer _ = CloseServiceHandle(svc);
    var st: SERVICE_STATUS = .{ .dwCurrentState = 0 };
    if (QueryServiceStatus(svc, &st) == 0) return null;
    return @enumFromInt(st.dwCurrentState);
}

/// Starts the installed service with the window's options.
pub fn start(args: []const []const u8) !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT) orelse return error.ScmUnavailable;
    defer _ = CloseServiceHandle(scm);
    const svc = OpenServiceW(scm, L(service_name), SERVICE_START | SERVICE_QUERY_STATUS) orelse return error.NeedsAdministrator;
    defer _ = CloseServiceHandle(svc);
    var bufs: [8][256]u16 = undefined;
    var ptrs: [8][*:0]const u16 = undefined;
    const n = @min(args.len, ptrs.len);
    for (args[0..n], 0..) |a, i| ptrs[i] = wide(&bufs[i], a).ptr;
    if (StartServiceW(svc, @intCast(n), &ptrs) == 0) {
        if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) return;
        return error.StartFailed;
    }
}

/// Asks the SCM to stop it (when it no longer answers on its socket).
pub fn stop() void {
    if (comptime builtin.os.tag != .windows) return;
    const scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT) orelse return;
    defer _ = CloseServiceHandle(scm);
    const svc = OpenServiceW(scm, L(service_name), SERVICE_STOP) orelse return;
    defer _ = CloseServiceHandle(svc);
    var st: SERVICE_STATUS = .{ .dwCurrentState = 0 };
    _ = ControlService(svc, 1, &st);
}

/// The release that `install` put in place, or null when none is installed.
pub fn installedBuild(env: *std.process.Environ.Map, buf: []u8, io: std.Io) ?[]const u8 {
    var dir_buf: [512]u8 = undefined;
    var p_buf: [600]u8 = undefined;
    const p = std.fmt.bufPrint(&p_buf, "{s}\\build", .{installDir(env, &dir_buf)}) catch return null;
    const text = std.Io.Dir.cwd().readFile(io, p, buf) catch return null;
    return std.mem.trim(u8, text, " \r\n");
}
