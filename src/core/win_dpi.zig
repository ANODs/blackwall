//! DPI circumvention tools of Windows beside the VPN (product concept 7.1):
//! zapret (winws.exe, also in the zapret-discord-youtube bundle) and
//! GoodbyeDPI (goodbyedpi.exe). Both divert packets through the WinDivert
//! driver, and both are often installed as services of their own
//! (zapret-discord-youtube's service.bat makes "zapret", GoodbyeDPI's
//! scripts "GoodbyeDPI").
//!
//! The window finds them without any rights: the process list and the
//! services' status are open to every user. It cannot stop them, they run
//! as administrators or as LocalSystem; the BLACKWALL service (LocalSystem)
//! does it at the window's word ("stop_dpi", ipc.zig): a service through
//! the SCM, its process only when it does not stop; a plain process by
//! ending that very process, found again by its number and start time.
//! Only the tools below are ever touched, never anything of the system.

const std = @import("std");
const builtin = @import("builtin");
const w = std.os.windows;
const log = std.log.scoped(.dpi);
const Io = std.Io;

const on_windows = builtin.os.tag == .windows;

pub const Tool = struct {
    /// the executable, as the process list names it
    exe: []const u8,
    /// what users know it by
    name: []const u8,
    /// the services its own scripts install
    services: []const []const u8,
};

pub const tools = [_]Tool{
    .{ .exe = "winws.exe", .name = "zapret", .services = &.{"zapret"} },
    .{ .exe = "goodbyedpi.exe", .name = "GoodbyeDPI", .services = &.{"GoodbyeDPI"} },
};

/// The tool whose executable this is ("C:\zapret\bin\WinWS.exe" too).
pub fn toolOf(path: []const u8) ?u8 {
    const base = basename(path);
    for (tools, 0..) |t, i| if (std.ascii.eqlIgnoreCase(base, t.exe)) return @intCast(i);
    return null;
}

/// The tool whose scripts install a service of this name.
pub fn toolOfService(name: []const u8) ?u8 {
    for (tools, 0..) |t, i| for (t.services) |s| if (std.ascii.eqlIgnoreCase(name, s)) return @intCast(i);
    return null;
}

fn basename(path: []const u8) []const u8 {
    const at = std.mem.lastIndexOfAny(u8, path, "\\/") orelse return path;
    return path[at + 1 ..];
}

/// Whether a process running `path` may be ended: one of the tools, and
/// nothing from the Windows folder (`windows_dir`, "C:\Windows").
pub fn imageAllowed(path: []const u8, windows_dir: []const u8) bool {
    const p = if (std.mem.startsWith(u8, path, "\\\\?\\")) path[4..] else path;
    if (toolOf(p) == null) return false;
    const dir = std.mem.trimEnd(u8, windows_dir, "\\/");
    if (dir.len == 0) return false;
    if (p.len > dir.len and std.ascii.eqlIgnoreCase(p[0..dir.len], dir) and (p[dir.len] == '\\' or p[dir.len] == '/')) return false;
    return true;
}

/// A process as the window saw it.
pub const Identity = struct {
    pid: u32 = 0,
    /// when it started (FILETIME); 0 when the window may not ask
    start: u64 = 0,
    exe_buf: [32]u8 = undefined,
    exe_len: u8 = 0,

    pub fn path(id: *const Identity) []const u8 {
        return id.exe_buf[0..id.exe_len];
    }

    fn setExe(id: *Identity, exe: []const u8) void {
        id.exe_len = @intCast(@min(exe.len, id.exe_buf.len));
        @memcpy(id.exe_buf[0..id.exe_len], exe[0..id.exe_len]);
    }
};

pub const Found = struct {
    /// index in `tools`
    tool: u8,
    id: Identity,
    /// the service it runs as, when it is one
    service_buf: [64]u8 = undefined,
    service_len: u8 = 0,

    pub fn service(f: *const Found) []const u8 {
        return f.service_buf[0..f.service_len];
    }

    fn setService(f: *Found, name: []const u8) void {
        // a name that does not fit could not be asked for: a plain process then
        if (name.len > f.service_buf.len) return;
        @memcpy(f.service_buf[0..name.len], name);
        f.service_len = @intCast(name.len);
    }
};

pub const Scan = struct {
    /// caller frees
    found: []Found,
    /// the WinDivert driver is loaded: packets are being diverted
    windivert: bool = false,
};

/// The tools running now: their processes, and the services they run as
/// (also a service of a known name whose executable is called otherwise).
pub fn scan(gpa: std.mem.Allocator) !Scan {
    if (comptime !on_windows) return .{ .found = &.{} };
    var found: std.ArrayList(Found) = .empty;
    errdefer found.deinit(gpa);
    const snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == w.INVALID_HANDLE_VALUE) return error.ListFailed;
    defer w.CloseHandle(snap);
    var e: PROCESSENTRY32W = .{};
    var ok = Process32FirstW(snap, &e) != 0;
    while (ok) : (ok = Process32NextW(snap, &e) != 0) {
        var name_buf: [3 * 260]u8 = undefined;
        const name = name_buf[0..std.unicode.wtf16LeToWtf8(&name_buf, std.mem.sliceTo(&e.szExeFile, 0))];
        const t = toolOf(name) orelse continue;
        var f: Found = .{ .tool = t, .id = .{ .pid = e.th32ProcessID, .start = startedAt(e.th32ProcessID) } };
        f.id.setExe(tools[t].exe);
        try found.append(gpa, f);
    }
    var s: Scan = .{ .found = &.{} };
    try services(gpa, &found, &s.windivert);
    s.found = try found.toOwnedSlice(gpa);
    return s;
}

/// Active services and drivers, read once: which tool runs as which
/// service, and whether WinDivert is loaded.
fn services(gpa: std.mem.Allocator, found: *std.ArrayList(Found), windivert: *bool) !void {
    const scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE) orelse return;
    defer _ = CloseServiceHandle(scm);
    const buf = try gpa.alignedAlloc(u8, .of(ENUM_SERVICE_STATUS_PROCESSW), 64 * 1024);
    defer gpa.free(buf);
    var resume_at: u32 = 0;
    while (true) {
        var needed: u32 = 0;
        var count: u32 = 0;
        const done = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER | SERVICE_WIN32, SERVICE_ACTIVE, buf.ptr, @intCast(buf.len), &needed, &count, &resume_at, null) != 0;
        if (!done and GetLastError() != ERROR_MORE_DATA) return;
        const list: [*]const ENUM_SERVICE_STATUS_PROCESSW = @ptrCast(buf.ptr);
        for (list[0..count]) |*en| try oneService(gpa, found, windivert, en);
        if (done or count == 0) return;
    }
}

fn oneService(gpa: std.mem.Allocator, found: *std.ArrayList(Found), windivert: *bool, en: *const ENUM_SERVICE_STATUS_PROCESSW) !void {
    const name_w = std.mem.sliceTo(en.lpServiceName, 0);
    if (name_w.len > 256) return;
    var name_buf: [3 * 256]u8 = undefined;
    const name = name_buf[0..std.unicode.wtf16LeToWtf8(&name_buf, name_w)];
    const st = en.ServiceStatusProcess;
    if (st.dwServiceType & SERVICE_DRIVER != 0) {
        // WinDivert (2.x), WinDivert14 (1.4)
        if (st.dwCurrentState == SERVICE_RUNNING and std.ascii.startsWithIgnoreCase(name, "WinDivert")) windivert.* = true;
        return;
    }
    if (st.dwProcessId == 0) return;
    for (found.items) |*f| if (f.id.pid == st.dwProcessId) {
        f.setService(name);
        return;
    };
    const t = toolOfService(name) orelse return;
    var f: Found = .{ .tool = t, .id = .{ .pid = st.dwProcessId, .start = startedAt(st.dwProcessId) } };
    f.setService(name);
    if (f.service_len == 0) return;
    try found.append(gpa, f);
}

/// When a process started, 0 when this user may not ask (a service's).
fn startedAt(pid: u32) u64 {
    if (comptime !on_windows) return 0;
    const h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) orelse return 0;
    defer w.CloseHandle(h);
    return startOf(h);
}

fn startOf(h: w.HANDLE) u64 {
    var cr: u64 = 0;
    var ex: u64 = 0;
    var k: u64 = 0;
    var u: u64 = 0;
    if (GetProcessTimes(h, &cr, &ex, &k, &u) == 0) return 0;
    return cr;
}

/// Whether what was found is still there: its service, or its process
/// (one of the tools with that number, started then when that is known).
pub fn present(service_name: []const u8, pid: u32, start: u64) bool {
    if (comptime !on_windows) return false;
    if (service_name.len > 0 and serviceActive(service_name)) return true;
    if (pid == 0) return false;
    const snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == w.INVALID_HANDLE_VALUE) return true;
    defer w.CloseHandle(snap);
    var e: PROCESSENTRY32W = .{};
    var ok = Process32FirstW(snap, &e) != 0;
    while (ok) : (ok = Process32NextW(snap, &e) != 0) {
        if (e.th32ProcessID != pid) continue;
        var name_buf: [3 * 260]u8 = undefined;
        const name = name_buf[0..std.unicode.wtf16LeToWtf8(&name_buf, std.mem.sliceTo(&e.szExeFile, 0))];
        if (toolOf(name) == null) return false;
        // one that has ended while something still holds it is gone; one
        // this user may not open (a service's) is there while it is listed
        const h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) orelse return true;
        defer w.CloseHandle(h);
        if (WaitForSingleObject(h, 0) == WAIT_OBJECT_0) return false;
        const now = startOf(h);
        return start == 0 or now == 0 or now == start;
    }
    return false;
}

fn serviceActive(name: []const u8) bool {
    var nw: [257]u16 = undefined;
    const wname = wide(&nw, name) orelse return false;
    const scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT) orelse return false;
    defer _ = CloseServiceHandle(scm);
    const svc = OpenServiceW(scm, wname, SERVICE_QUERY_STATUS) orelse return false;
    defer _ = CloseServiceHandle(svc);
    const st = statusOf(svc) orelse return false;
    return st.dwCurrentState != SERVICE_STOPPED;
}

// ------------------------------------------------------------ the service's side

/// {"cmd":"stop_dpi","service":"zapret","pid":1234,"start":133…,"kill":false}
pub const Request = struct {
    cmd: []const u8 = "stop_dpi",
    /// stop this service through the SCM; empty for a plain process
    service: []const u8 = "",
    /// the process, as the window saw it
    pid: u32 = 0,
    /// its start (FILETIME), 0 when the window could not read it
    start: u64 = 0,
    /// at once: a service's process without asking the SCM first
    kill: bool = false,

    /// The request line, newline included.
    pub fn line(r: *const Request, buf: []u8) ?[]const u8 {
        var wr: Io.Writer = .fixed(buf);
        std.json.Stringify.value(r.*, .{}, &wr) catch return null;
        wr.writeByte('\n') catch return null;
        return wr.buffered();
    }
};

/// {"ok":true} or {"ok":false,"error":"Gone"}
pub const Reply = struct {
    ok: bool = false,
    @"error": []const u8 = "",
};

pub const StopError = error{
    /// not running any more, or not the process that was shown
    Gone,
    /// not one of the tools, something of the system, or it would not stop
    Refused,
};

/// The service's side of "stop_dpi" for connection `conn`: on a thread of
/// its own, since the SCM and a process going away take seconds and the
/// service answers one client at a time. The thread answers and closes
/// `conn`; false when it could not start (the caller answers then).
pub fn serve(io: Io, conn: Io.net.Stream, request_line: []const u8) bool {
    const job = std.heap.page_allocator.create(Job) catch return false;
    if (request_line.len > job.line_buf.len) {
        std.heap.page_allocator.destroy(job);
        return false;
    }
    job.* = .{ .io = io, .conn = conn, .line_len = request_line.len };
    @memcpy(job.line_buf[0..request_line.len], request_line);
    const th = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, Job.run, .{job}) catch {
        std.heap.page_allocator.destroy(job);
        return false;
    };
    th.detach();
    return true;
}

const Job = struct {
    io: Io,
    conn: Io.net.Stream,
    line_buf: [1024]u8 = undefined,
    line_len: usize,

    fn run(j: *Job) void {
        defer {
            j.conn.close(j.io);
            std.heap.page_allocator.destroy(j);
        }
        const reply: Reply = if (handle(j.line_buf[0..j.line_len])) |_| .{ .ok = true } else |err| .{ .@"error" = @errorName(err) };
        var wb: [128]u8 = undefined;
        var wr = j.conn.writer(j.io, &wb);
        std.json.Stringify.value(reply, .{}, &wr.interface) catch return;
        wr.interface.writeByte('\n') catch return;
        wr.interface.flush() catch {};
    }
};

/// A request line, parsed and carried out (also the `--stop-dpi` start of
/// the installed service, when none was running to ask).
pub fn handle(request_line: []const u8) StopError!void {
    var buf: [2048]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    const r = std.json.parseFromSliceLeaky(Request, fba.allocator(), request_line, .{ .ignore_unknown_fields = true }) catch return error.Refused;
    stop(r) catch |err| {
        log.warn("stop {s} pid {d}: {t}", .{ r.service, r.pid, err });
        return err;
    };
    log.info("stopped {s} pid {d}", .{ r.service, r.pid });
}

/// Stop what `r` names; as LocalSystem.
pub fn stop(r: Request) StopError!void {
    if (comptime !on_windows) return error.Refused;
    if (r.service.len > 0) return stopService(r.service, r.kill);
    return terminate(r.pid, r.start);
}

fn stopService(name: []const u8, kill: bool) StopError!void {
    // never this program's own
    if (std.ascii.eqlIgnoreCase(name, "BLACKWALL")) return error.Refused;
    var nw: [257]u16 = undefined;
    const wname = wide(&nw, name) orelse return error.Refused;
    const scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT) orelse return error.Refused;
    defer _ = CloseServiceHandle(scm);
    const svc = OpenServiceW(scm, wname, SERVICE_STOP | SERVICE_QUERY_STATUS) orelse
        return if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) error.Gone else error.Refused;
    defer _ = CloseServiceHandle(svc);
    const st = statusOf(svc) orelse return error.Refused;
    if (st.dwCurrentState == SERVICE_STOPPED) return error.Gone;
    // a tool runs in a process of its own, never in a shared host (svchost)
    if (st.dwServiceType & SERVICE_WIN32_OWN_PROCESS == 0) return error.Refused;
    const pid = st.dwProcessId;
    const tool_process = pid != 0 and toolProcess(pid);
    if (!tool_process and toolOfService(name) == null) return error.Refused;
    if (!kill) {
        var ss: SERVICE_STATUS = undefined;
        _ = ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        var waited: u32 = 0;
        while (waited < 10_000) : (waited += 200) {
            const now = statusOf(svc) orelse break;
            if (now.dwCurrentState == SERVICE_STOPPED) return;
            Sleep(200);
        }
    }
    // it does not stop: its process, when that is one of the tools
    if (!tool_process) return error.Refused;
    return terminate(pid, 0);
}

/// That very process, when it is one of the tools and not the system's.
fn terminate(pid: u32, start: u64) StopError!void {
    if (pid <= 4 or pid == GetCurrentProcessId()) return error.Refused;
    const h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) orelse
        return if (GetLastError() == ERROR_INVALID_PARAMETER) error.Gone else error.Refused;
    defer w.CloseHandle(h);
    if (WaitForSingleObject(h, 0) == WAIT_OBJECT_0) return error.Gone;
    // not a later process that got the same number
    if (start != 0 and startOf(h) != start) return error.Gone;
    if (!mayEnd(h)) return error.Refused;
    if (TerminateProcess(h, 1) == 0) return error.Refused;
    if (WaitForSingleObject(h, 5000) != WAIT_OBJECT_0) return error.Refused;
}

fn toolProcess(pid: u32) bool {
    const h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) orelse return false;
    defer w.CloseHandle(h);
    return mayEnd(h);
}

/// One of the tools by its executable, outside the Windows folder, and not
/// a process the system cannot run without.
fn mayEnd(h: w.HANDLE) bool {
    var pw: [1024]u16 = undefined;
    var size: u32 = pw.len;
    if (QueryFullProcessImageNameW(h, 0, &pw, &size) == 0) return false;
    var pb: [3 * 1024]u8 = undefined;
    const path = pb[0..std.unicode.wtf16LeToWtf8(&pb, pw[0..size])];
    var dw: [260]u16 = undefined;
    const dn = GetSystemWindowsDirectoryW(&dw, dw.len);
    if (dn == 0 or dn >= dw.len) return false;
    var db: [3 * 260]u8 = undefined;
    const dir = db[0..std.unicode.wtf16LeToWtf8(&db, dw[0..dn])];
    if (!imageAllowed(path, dir)) return false;
    var critical: i32 = 0;
    if (IsProcessCritical(h, &critical) == 0 or critical != 0) return false;
    return true;
}

fn statusOf(svc: SC_HANDLE) ?SERVICE_STATUS_PROCESS {
    var st: SERVICE_STATUS_PROCESS = undefined;
    var needed: u32 = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, @ptrCast(&st), @sizeOf(SERVICE_STATUS_PROCESS), &needed) == 0) return null;
    return st;
}

fn wide(buf: []u16, s: []const u8) ?[:0]const u16 {
    if (s.len == 0 or s.len >= buf.len) return null;
    const n = std.unicode.wtf8ToWtf16Le(buf[0 .. buf.len - 1], s) catch return null;
    buf[n] = 0;
    return buf[0..n :0];
}

// ------------------------------------------------------------ Windows API

const W: std.builtin.CallingConvention = .winapi;
const SC_HANDLE = *opaque {};

const PROCESSENTRY32W = extern struct {
    dwSize: u32 = @sizeOf(PROCESSENTRY32W),
    cntUsage: u32 = 0,
    th32ProcessID: u32 = 0,
    th32DefaultHeapID: usize = 0,
    th32ModuleID: u32 = 0,
    cntThreads: u32 = 0,
    th32ParentProcessID: u32 = 0,
    pcPriClassBase: i32 = 0,
    dwFlags: u32 = 0,
    szExeFile: [260]u16 = @splat(0),
};
const SERVICE_STATUS = extern struct {
    dwServiceType: u32,
    dwCurrentState: u32,
    dwControlsAccepted: u32,
    dwWin32ExitCode: u32,
    dwServiceSpecificExitCode: u32,
    dwCheckPoint: u32,
    dwWaitHint: u32,
};
const SERVICE_STATUS_PROCESS = extern struct {
    dwServiceType: u32,
    dwCurrentState: u32,
    dwControlsAccepted: u32,
    dwWin32ExitCode: u32,
    dwServiceSpecificExitCode: u32,
    dwCheckPoint: u32,
    dwWaitHint: u32,
    dwProcessId: u32,
    dwServiceFlags: u32,
};
const ENUM_SERVICE_STATUS_PROCESSW = extern struct {
    lpServiceName: [*:0]const u16,
    lpDisplayName: [*:0]const u16,
    ServiceStatusProcess: SERVICE_STATUS_PROCESS,
};

extern "kernel32" fn CreateToolhelp32Snapshot(flags: u32, pid: u32) callconv(W) w.HANDLE;
extern "kernel32" fn Process32FirstW(snap: w.HANDLE, entry: *PROCESSENTRY32W) callconv(W) i32;
extern "kernel32" fn Process32NextW(snap: w.HANDLE, entry: *PROCESSENTRY32W) callconv(W) i32;
extern "kernel32" fn OpenProcess(access: u32, inherit: i32, pid: u32) callconv(W) ?w.HANDLE;
extern "kernel32" fn GetProcessTimes(h: w.HANDLE, creation: *u64, exit: *u64, kernel: *u64, user: *u64) callconv(W) i32;
extern "kernel32" fn QueryFullProcessImageNameW(h: w.HANDLE, flags: u32, name: [*]u16, size: *u32) callconv(W) i32;
extern "kernel32" fn IsProcessCritical(h: w.HANDLE, critical: *i32) callconv(W) i32;
extern "kernel32" fn TerminateProcess(h: w.HANDLE, code: u32) callconv(W) i32;
extern "kernel32" fn WaitForSingleObject(h: w.HANDLE, ms: u32) callconv(W) u32;
extern "kernel32" fn GetCurrentProcessId() callconv(W) u32;
extern "kernel32" fn GetSystemWindowsDirectoryW(buf: [*]u16, size: u32) callconv(W) u32;
extern "kernel32" fn GetLastError() callconv(W) u32;
extern "kernel32" fn Sleep(ms: u32) callconv(W) void;
extern "advapi32" fn OpenSCManagerW(machine: ?[*:0]const u16, db: ?[*:0]const u16, access: u32) callconv(W) ?SC_HANDLE;
extern "advapi32" fn OpenServiceW(scm: SC_HANDLE, name: [*:0]const u16, access: u32) callconv(W) ?SC_HANDLE;
extern "advapi32" fn CloseServiceHandle(h: SC_HANDLE) callconv(W) i32;
extern "advapi32" fn ControlService(svc: SC_HANDLE, control: u32, st: *SERVICE_STATUS) callconv(W) i32;
extern "advapi32" fn QueryServiceStatusEx(svc: SC_HANDLE, level: u32, buf: [*]u8, size: u32, needed: *u32) callconv(W) i32;
extern "advapi32" fn EnumServicesStatusExW(scm: SC_HANDLE, level: u32, kind: u32, state: u32, buf: [*]u8, size: u32, needed: *u32, count: *u32, resume_at: *u32, group: ?[*:0]const u16) callconv(W) i32;

const TH32CS_SNAPPROCESS = 0x2;
const PROCESS_TERMINATE = 0x1;
const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
const SYNCHRONIZE = 0x100000;
const WAIT_OBJECT_0 = 0;
const SC_MANAGER_CONNECT = 0x1;
const SC_MANAGER_ENUMERATE_SERVICE = 0x4;
const SERVICE_QUERY_STATUS = 0x4;
const SERVICE_STOP = 0x20;
const SERVICE_CONTROL_STOP = 1;
const SC_ENUM_PROCESS_INFO = 0;
const SC_STATUS_PROCESS_INFO = 0;
const SERVICE_DRIVER = 0x0B;
const SERVICE_WIN32_OWN_PROCESS = 0x10;
const SERVICE_WIN32 = 0x30;
const SERVICE_ACTIVE = 0x1;
const SERVICE_STOPPED = 1;
const SERVICE_RUNNING = 4;
const ERROR_INVALID_PARAMETER = 87;
const ERROR_MORE_DATA = 234;
const ERROR_SERVICE_DOES_NOT_EXIST = 1060;

// ------------------------------------------------------------ tests

test "the tools by their executables and services" {
    try std.testing.expectEqual(@as(?u8, 0), toolOf("winws.exe"));
    try std.testing.expectEqual(@as(?u8, 0), toolOf("C:\\zapret-discord-youtube\\bin\\WinWS.EXE"));
    try std.testing.expectEqual(@as(?u8, 1), toolOf("D:/GoodbyeDPI/x86_64/goodbyedpi.exe"));
    try std.testing.expectEqual(@as(?u8, null), toolOf("winws.exe.bak"));
    try std.testing.expectEqual(@as(?u8, null), toolOf("svchost.exe"));
    try std.testing.expectEqual(@as(?u8, 0), toolOfService("zapret"));
    try std.testing.expectEqual(@as(?u8, 1), toolOfService("goodbyedpi"));
    try std.testing.expectEqual(@as(?u8, null), toolOfService("BLACKWALL"));
    try std.testing.expectEqual(@as(?u8, null), toolOfService("Spooler"));
}

test "only a tool outside the Windows folder may be ended" {
    try std.testing.expect(imageAllowed("C:\\zapret\\bin\\winws.exe", "C:\\Windows"));
    try std.testing.expect(imageAllowed("\\\\?\\C:\\GoodbyeDPI\\x86_64\\goodbyedpi.exe", "C:\\Windows\\"));
    // a tool's name on a file of the system's
    try std.testing.expect(!imageAllowed("C:\\Windows\\System32\\winws.exe", "C:\\Windows"));
    try std.testing.expect(!imageAllowed("c:\\windows\\winws.exe", "C:\\Windows"));
    // a folder that only starts like it is not it
    try std.testing.expect(imageAllowed("C:\\WindowsApps2\\winws.exe", "C:\\Windows"));
    try std.testing.expect(!imageAllowed("C:\\Windows\\System32\\svchost.exe", "C:\\Windows"));
    try std.testing.expect(!imageAllowed("C:\\tools\\explorer.exe", "C:\\Windows"));
    // without the Windows folder nothing is
    try std.testing.expect(!imageAllowed("C:\\zapret\\winws.exe", ""));
}

test "a stop request: its line and back" {
    const r: Request = .{ .service = "zapret", .pid = 4242, .start = 134_067_123_456_789_012 };
    var buf: [256]u8 = undefined;
    const l = r.line(&buf).?;
    try std.testing.expect(std.mem.endsWith(u8, l, "\n"));
    const back = try std.json.parseFromSlice(Request, std.testing.allocator, l, .{ .ignore_unknown_fields = true });
    defer back.deinit();
    try std.testing.expectEqualStrings("stop_dpi", back.value.cmd);
    try std.testing.expectEqualStrings("zapret", back.value.service);
    try std.testing.expectEqual(4242, back.value.pid);
    // a FILETIME is past 2^53: kept exact
    try std.testing.expectEqual(134_067_123_456_789_012, back.value.start);
    try std.testing.expect(!back.value.kill);
    try std.testing.expectError(error.Refused, handle("not json"));
}

test "Windows: a tool's process is found and ended, nothing else is" {
    if (comptime !on_windows) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const k = struct {
        extern "kernel32" fn GetSystemDirectoryW(buf: [*]u16, size: u32) callconv(W) u32;
        extern "kernel32" fn CopyFileW(from: [*:0]const u16, to: [*:0]const u16, fail_if_exists: i32) callconv(W) i32;
        extern "kernel32" fn GetProcessId(h: w.HANDLE) callconv(W) u32;
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];
    // a stand-in for winws.exe: a copy of cmd.exe that waits
    var sw: [260]u16 = undefined;
    const sn = k.GetSystemDirectoryW(&sw, sw.len);
    try std.testing.expect(sn > 0 and sn < sw.len);
    var sys_buf: [3 * 260]u8 = undefined;
    const sys = sys_buf[0..std.unicode.wtf16LeToWtf8(&sys_buf, sw[0..sn])];
    var from_buf: [1024]u8 = undefined;
    var to_buf: [1024]u8 = undefined;
    const from = try std.fmt.bufPrint(&from_buf, "{s}\\cmd.exe", .{sys});
    const to = try std.fmt.bufPrint(&to_buf, "{s}\\winws.exe", .{dir});
    var fw: [1024]u16 = undefined;
    var tw: [1024]u16 = undefined;
    try std.testing.expect(k.CopyFileW(wide(&fw, from).?, wide(&tw, to).?, 0) != 0);
    var child = try std.process.spawn(io, .{
        .argv = &.{ to, "/d", "/c", "ping", "-n", "30", "127.0.0.1" },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer child.kill(io);
    const pid = k.GetProcessId(child.id.?);

    const s = try scan(gpa);
    defer gpa.free(s.found);
    const f = for (s.found) |f| {
        if (f.id.pid == pid) break f;
    } else return error.TestExpectedToFindIt;
    try std.testing.expectEqualStrings("zapret", tools[f.tool].name);
    try std.testing.expectEqualStrings("", f.service());
    try std.testing.expect(f.id.start != 0);
    try std.testing.expect(present("", pid, f.id.start));

    // nothing but the tools: not this process, not this program's service,
    // not a service of the system
    try std.testing.expectError(error.Refused, stop(.{ .pid = GetCurrentProcessId() }));
    try std.testing.expectError(error.Refused, stop(.{ .pid = 4 }));
    try std.testing.expectError(error.Refused, stop(.{ .service = "BLACKWALL" }));
    const spooler = serviceActive("Spooler");
    if (stop(.{ .service = "Spooler" })) |_| return error.TestUnexpectedResult else |_| {}
    try std.testing.expectEqual(spooler, serviceActive("Spooler"));
    // a later process with its number is not the one that was shown
    try std.testing.expectError(error.Gone, stop(.{ .pid = pid, .start = f.id.start + 1 }));
    try std.testing.expect(present("", pid, f.id.start));

    try stop(.{ .pid = pid, .start = f.id.start });
    try std.testing.expect(!present("", pid, f.id.start));
    try std.testing.expectError(error.Gone, stop(.{ .pid = pid, .start = f.id.start }));
}
