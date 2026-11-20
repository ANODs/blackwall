//! Settings → "Report for GitHub": what the app and its service logged,
//! without secrets (core/diag.zig), saved as a file in Downloads; then the
//! file is shown and a new issue opens in the browser, to attach it to.

const std = @import("std");
const builtin = @import("builtin");
const dvui = @import("dvui");
const core = @import("core");
const app = @import("app.zig");
const build_options = @import("build_options");
const tr = @import("i18n.zig").t;

const diag = core.diag;
const on_windows = builtin.os.tag == .windows;

/// Issues go where releases come from; a build without a release
/// repository still reports to the project.
const repo = if (build_options.update_repo.len > 0) build_options.update_repo else "ANODs/blackwall";

// ---------------------------------------------------------------- the window's log

/// The latest lines, for the report.
var ring: diag.Ring = .{};

pub fn logFn(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime format: []const u8, args: anytype) void {
    var buf: [640]u8 = undefined;
    var w: std.Io.Writer = .fixed(buf[0 .. buf.len - 1]);
    const t = diag.now();
    w.print("{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} {s}({s}): ", .{ t.mon, t.day, t.hour, t.min, t.sec, @tagName(level), @tagName(scope) }) catch {};
    w.print(format, args) catch {};
    const n = w.buffered().len;
    buf[n] = '\n';
    const line = buf[0 .. n + 1];
    ring.add(line);
    if (!to_file) return dvui.App.logFn(level, scope, format, args);
    // past the cap, only what went wrong
    if (log_written.load(.monotonic) > log_cap and @intFromEnum(level) > @intFromEnum(std.log.Level.warn)) return;
    var sbuf: [256]u8 = undefined;
    const ls = std.debug.lockStderr(&sbuf);
    defer std.debug.unlockStderr();
    const out = &ls.file_writer.interface;
    log_scrub.write(out, line) catch {};
    out.flush() catch {};
    _ = log_written.fetchAdd(line.len, .monotonic);
}

// ---------------------------------------------------------------- the window's log file

/// A window started without a terminal (from Finder, Explorer, a menu) has
/// nowhere to say anything: its log, scrubbed as in a report, and what it
/// crashed on go to this file in the settings folder. The run before is
/// kept beside it, and goes into the report.
pub const log_name = "window.log";
pub const previous_log_name = "window.previous.log";
/// past this, only warnings and errors are written
const log_cap = 4 << 20;

var to_file = false;
var log_written = std.atomic.Value(usize).init(0);
var log_scrub: diag.Scrub = .{ .key = 0 };
var log_path_buf: [std.fs.max_path_bytes]u8 = undefined;

/// First thing, before the window opens: stderr into the log file when
/// it leads nowhere.
pub fn start(init: std.process.Init) void {
    // screenshot mode touches nothing of the user's
    if (init.environ_map.get("BLACKWALL_SHOTS") != null) return;
    if (hasTerminal()) return;
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = app.settingsDir(&dir_buf, init.environ_map) orelse return;
    const cwd = std.Io.Dir.cwd();
    cwd.createDirPath(init.io, dir) catch return;
    const path = std.fmt.bufPrint(&log_path_buf, "{s}{c}" ++ log_name, .{ dir, std.fs.path.sep }) catch return;
    var prev_buf: [std.fs.max_path_bytes]u8 = undefined;
    const prev = std.fmt.bufPrint(&prev_buf, "{s}{c}" ++ previous_log_name, .{ dir, std.fs.path.sep }) catch return;
    cwd.rename(path, cwd, prev, init.io) catch {};
    if (!redirect(init.io, path)) return;
    log_scrub = .init(init.io);
    to_file = true;
    if (on_windows) crash.prepare(path);
    // the check of all this (tools/windows/e2e.ps1): crash right here, the
    // way the window would, without asking anyone
    if (init.environ_map.get("BLACKWALL_CRASH")) |how| {
        crash.quiet = true;
        if (std.mem.eql(u8, how, "panic")) @panic("BLACKWALL_CRASH");
        @trap();
    }
}

fn hasTerminal() bool {
    if (comptime on_windows) {
        const h = crash.win.GetStdHandle(crash.win.STD_ERROR_HANDLE) orelse return false;
        if (h == std.os.windows.INVALID_HANDLE_VALUE) return false;
        var mode: u32 = 0;
        return crash.win.GetConsoleMode(h, &mode) != 0;
    }
    return std.c.isatty(2) != 0;
}

/// stderr, where Zig's panics and crash reports go, into the file at `path`.
fn redirect(io: std.Io, path: []const u8) bool {
    if (comptime on_windows) {
        // a plain synchronous handle: written from a crash too
        var wpath: [std.fs.max_path_bytes:0]u16 = undefined;
        const n = std.unicode.wtf8ToWtf16Le(&wpath, path) catch return false;
        wpath[n] = 0;
        const W = crash.win;
        const h = W.CreateFileW(&wpath, W.GENERIC_WRITE, W.FILE_SHARE_READ | W.FILE_SHARE_WRITE | W.FILE_SHARE_DELETE, null, W.CREATE_ALWAYS, W.FILE_ATTRIBUTE_NORMAL, null);
        if (h == std.os.windows.INVALID_HANDLE_VALUE) return false;
        _ = W.SetStdHandle(W.STD_ERROR_HANDLE, h);
        // std reads stderr from the process parameters
        std.os.windows.peb().ProcessParameters.hStdError = h;
        return true;
    }
    const f = std.Io.Dir.cwd().createFile(io, path, .{}) catch return false;
    defer f.close(io);
    return std.c.dup2(f.handle, 2) >= 0;
}

/// Bytes to stderr without a lock: from a crash, where any lock may be held.
fn writeRaw(bytes: []const u8) void {
    if (comptime on_windows) {
        var done: u32 = 0;
        _ = crash.win.WriteFile(std.os.windows.peb().ProcessParameters.hStdError, bytes.ptr, @intCast(bytes.len), &done, null);
        return;
    }
    _ = std.c.write(2, bytes.ptr, bytes.len);
}

/// The window's panic: written to the log and, on Windows, told to the
/// user with where to report it; then Zig's own (the trace, the exit).
pub fn panicked(msg: []const u8, first_trace_addr: ?usize) noreturn {
    if (to_file and !crash.happened.load(.acquire)) {
        var buf: [512]u8 = undefined;
        writeRaw(std.fmt.bufPrint(&buf, "panic: {s}, BLACKWALL {s}\n", .{ msg, build_options.version }) catch "panic\n");
        if (on_windows) crash.tellUser();
    }
    std.debug.defaultPanic(msg, first_trace_addr);
}

/// Windows: a crash that is not a panic (an illegal instruction, a bad
/// address, also a trap in C code) is caught here instead of by Zig's
/// handler (main.zig turns that off): its code and its place in the
/// program (an offset that the release's symbols resolve) go to the log,
/// and the user is told what happened and where to report it.
const crash = struct {
    const w = std.os.windows;
    const win = struct {
        const STD_ERROR_HANDLE: u32 = @bitCast(@as(i32, -12));
        const GENERIC_WRITE: u32 = 0x40000000;
        const FILE_SHARE_READ: u32 = 1;
        const FILE_SHARE_WRITE: u32 = 2;
        const FILE_SHARE_DELETE: u32 = 4;
        const CREATE_ALWAYS: u32 = 2;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
        const Filter = *const fn (*w.EXCEPTION_POINTERS) callconv(.winapi) c_long;
        extern "kernel32" fn GetStdHandle(which: u32) callconv(.winapi) ?w.HANDLE;
        extern "kernel32" fn SetStdHandle(which: u32, h: w.HANDLE) callconv(.winapi) c_int;
        extern "kernel32" fn GetConsoleMode(h: w.HANDLE, mode: *u32) callconv(.winapi) c_int;
        extern "kernel32" fn CreateFileW(name: [*:0]const u16, access: u32, share: u32, sa: ?*anyopaque, disposition: u32, flags: u32, template: ?w.HANDLE) callconv(.winapi) w.HANDLE;
        extern "kernel32" fn WriteFile(h: w.HANDLE, buf: [*]const u8, n: u32, written: ?*u32, overlapped: ?*anyopaque) callconv(.winapi) c_int;
        extern "kernel32" fn SetUnhandledExceptionFilter(filter: ?Filter) callconv(.winapi) ?Filter;
        extern "kernel32" fn GetModuleHandleW(name: ?[*:0]const u16) callconv(.winapi) ?*anyopaque;
        extern "user32" fn MessageBoxW(hwnd: ?*anyopaque, text: [*:0]const u16, caption: [*:0]const u16, kind: u32) callconv(.winapi) c_int;
        extern "shell32" fn ShellExecuteW(hwnd: ?*anyopaque, op: ?[*:0]const u16, file: [*:0]const u16, params: ?[*:0]const u16, dir: ?[*:0]const u16, show: c_int) callconv(.winapi) ?*anyopaque;
    };

    /// told once, whatever comes after
    var happened = std.atomic.Value(bool).init(false);
    /// logged only (a check, BLACKWALL_CRASH)
    var quiet = false;
    var ready = false;
    // made at start: nothing is formatted or allocated during a crash
    var text: [4096:0]u16 = undefined;
    var issue: [6144:0]u16 = undefined;
    var select: [std.fs.max_path_bytes + 16:0]u16 = undefined;

    fn wide(out: []u16, s: []const u8) bool {
        if (s.len >= out.len) return false;
        const n = std.unicode.wtf8ToWtf16Le(out, s) catch return false;
        out[n] = 0;
        return true;
    }

    fn prepare(path: []const u8) void {
        if (comptime !on_windows) return;
        var text_buf: [2048]u8 = undefined;
        if (!wide(&text, std.fmt.bufPrint(&text_buf, tr.crash_text, .{path}) catch return)) return;
        var system_buf: [96]u8 = undefined;
        var body_buf: [1024]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf, "{s}\n\n\n\n{s} " ++ log_name ++ "\n\nBLACKWALL {s} ({s}), {s}\n", .{
            tr.issue_what, tr.crash_attach, build_options.version, build_options.lang, describeSystem(&system_buf),
        }) catch return;
        var url_buf: [4096]u8 = undefined;
        var url: std.Io.Writer = .fixed(&url_buf);
        diag.issueUrl(&url, repo, "", body) catch return;
        if (!wide(&issue, url.buffered())) return;
        var sel_buf: [std.fs.max_path_bytes + 16]u8 = undefined;
        if (!wide(&select, std.fmt.bufPrint(&sel_buf, "/select,\"{s}\"", .{path}) catch return)) return;
        ready = true;
        _ = win.SetUnhandledExceptionFilter(onException);
    }

    fn onException(info: *w.EXCEPTION_POINTERS) callconv(.winapi) c_long {
        const rec = info.ExceptionRecord;
        const base = if (win.GetModuleHandleW(null)) |h| @intFromPtr(h) else 0;
        const at = @intFromPtr(rec.ExceptionAddress);
        var buf: [192]u8 = undefined;
        writeRaw(std.fmt.bufPrint(&buf, "crash: {s} (0x{x:0>8}) at BLACKWALL+0x{x}, BLACKWALL {s}\n", .{
            name(rec.ExceptionCode), rec.ExceptionCode, at -% base, build_options.version,
        }) catch "crash\n");
        tellUser();
        // the process ends here
        return 1; // EXCEPTION_EXECUTE_HANDLER
    }

    fn name(code: u32) []const u8 {
        return switch (code) {
            0xC0000005 => "access violation",
            0xC000001D => "illegal instruction",
            0xC00000FD => "stack overflow",
            0xC0000094 => "division by zero",
            0x80000003 => "breakpoint",
            else => "exception",
        };
    }

    /// What happened and where to report it; "Yes" opens a new issue and
    /// shows the log file to attach.
    fn tellUser() void {
        if (comptime !on_windows) return;
        if (!ready or quiet or happened.swap(true, .acq_rel)) return;
        const MB_YESNO = 0x4;
        const MB_ICONERROR = 0x10;
        const MB_SETFOREGROUND = 0x10000;
        const MB_TOPMOST = 0x40000;
        const IDYES = 6;
        const answer = win.MessageBoxW(null, &text, std.unicode.utf8ToUtf16LeStringLiteral("BLACKWALL"), MB_YESNO | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
        if (answer != IDYES) return;
        const open = std.unicode.utf8ToUtf16LeStringLiteral("open");
        _ = win.ShellExecuteW(null, open, &issue, null, null, 1);
        _ = win.ShellExecuteW(null, open, std.unicode.utf8ToUtf16LeStringLiteral("explorer.exe"), &select, null, 1);
    }
};

// ---------------------------------------------------------------- the report

/// Builds and saves the report, shows it and opens a new issue. Called from
/// a click, so on the window thread.
pub fn make() void {
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = downloads(&dir_buf) orelse return app.notify(true, tr.report_failed, .{});
    const path = save(dir, &path_buf) orelse return app.notify(true, tr.report_failed, .{});
    const name = std.fs.path.basename(path);
    app.notify(false, tr.report_saved, .{name});
    reveal(app.io, path, dir);

    var system_buf: [96]u8 = undefined;
    var body_buf: [1024]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{s}\n\n\n\n{s} {s}\n\nBLACKWALL {s} ({s}), {s}\n", .{
        tr.issue_what, tr.issue_attach, name, build_options.version, build_options.lang, describeSystem(&system_buf),
    }) catch return;
    var url_buf: [4096]u8 = undefined;
    var url: std.Io.Writer = .fixed(&url_buf);
    diag.issueUrl(&url, repo, "", body) catch return;
    _ = dvui.openURL(.{ .url = url.buffered() });
}

/// Writes the report into `dir`; its path, or null (logged) when it could
/// not be written.
pub fn save(dir: []const u8, path_buf: []u8) ?[]const u8 {
    const t = diag.now();
    const path = std.fmt.bufPrint(path_buf, "{s}{c}BLACKWALL-report-{d}-{d:0>2}-{d:0>2}-{d:0>2}{d:0>2}.txt", .{
        dir, std.fs.path.sep, t.year, t.mon, t.day, t.hour, t.min,
    }) catch return null;
    var system_buf: [96]u8 = undefined;
    var out: std.Io.Writer.Allocating = .init(app.gpa);
    defer out.deinit();
    write(&out.writer, describeSystem(&system_buf), t) catch return null;
    std.Io.Dir.cwd().writeFile(app.io, .{ .sub_path = path, .data = out.written() }) catch |err| {
        std.log.err("report not saved: {t}", .{err});
        return null;
    };
    return path;
}

const kib = 1024;

fn write(w: *std.Io.Writer, system: []const u8, t: diag.Clock) !void {
    const gpa = app.gpa;
    const io = app.io;
    const s = diag.Scrub.init(io);
    const st = &app.state;

    try w.print("BLACKWALL report, {d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}\n", .{ t.year, t.mon, t.day, t.hour, t.min });
    try w.print("version {s} ({s}), {s}\n", .{ build_options.version, build_options.lang, system });
    try w.print("updates: {s}\n", .{app.updaterState()});
    try w.writeAll("engine: ");
    if (st.demo) {
        try w.writeAll("demo\n");
    } else if (app.service_on and app.service_tun) {
        try w.writeAll("service, TUN\n");
    } else if (app.service_on) {
        try w.print("service, SOCKS on port {d}\n", .{app.service_socks});
    } else if (app.proxy.running.load(.acquire)) {
        try w.print("window, SOCKS on port {d}\n", .{app.proxy.port});
    } else try w.writeAll("off\n");

    // what the servers are, never where
    var protocols: std.enums.EnumArray(core.model.Protocol, u32) = .initFill(0);
    var carried: u32 = 0;
    for (st.servers.items) |sv| {
        protocols.getPtr(sv.protocol).* += 1;
        if (sv.carried) carried += 1;
    }
    try w.print("subscriptions {d}, servers {d} (this build carries {d}):", .{ st.subs.items.len, st.servers.items.len, carried });
    var it = protocols.iterator();
    while (it.next()) |e| if (e.value.* > 0) try w.print(" {t} {d}", .{ e.key, e.value.* });
    try w.writeByte('\n');
    if (st.settings.selected_server) |id| for (st.servers.items) |sv| if (sv.id == id) {
        try w.print("chosen server: {t}, {t}, {s}\n", .{ sv.protocol, sv.security, &sv.country });
    };
    try w.print("rules: {d} applications, {d} sites\n", .{ countRules(st.apps.items), countRules(st.domains.items) });
    try w.print("settings: {f}\n", .{std.json.fmt(st.settings, .{})});

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const files = [_]struct { name: []const u8, max: usize }{
        .{ .name = "service.error", .max = 4 * kib },
        .{ .name = "service.events", .max = 256 * kib },
        .{ .name = "service.log", .max = 128 * kib },
        // the run before this one, and what it crashed on
        .{ .name = previous_log_name, .max = 64 * kib },
    };
    for (files) |f| {
        const path = try std.fmt.bufPrint(&path_buf, "{s}{c}{s}", .{ app.config_dir, std.fs.path.sep, f.name });
        const text = diag.tail(gpa, io, path, f.max);
        defer if (text) |x| gpa.free(x);
        try diag.section(w, s, f.name, text);
    }
    const window = ring.copy(gpa) catch null;
    defer if (window) |x| gpa.free(x);
    try diag.section(w, s, "window", window);
}

fn countRules(items: anytype) usize {
    var n: usize = 0;
    for (items) |x| {
        if (x.route != .default) n += 1;
    }
    return n;
}

/// "macOS 26.1 aarch64", "Windows 10.0.26100 x86_64", "Linux 6.8.0 x86_64"
fn describeSystem(buf: []u8) []const u8 {
    const arch = @tagName(builtin.cpu.arch);
    switch (builtin.os.tag) {
        .macos => {
            var v: [32]u8 = undefined;
            var len: usize = v.len;
            const ok = std.c.sysctlbyname("kern.osproductversion", &v, &len, null, 0) == 0;
            const version = if (ok) std.mem.sliceTo(v[0..len], 0) else "?";
            return std.fmt.bufPrint(buf, "macOS {s} {s}", .{ version, arch }) catch "macOS";
        },
        .windows => {
            var info: std.os.windows.RTL_OSVERSIONINFOW = undefined;
            info.dwOSVersionInfoSize = @sizeOf(std.os.windows.RTL_OSVERSIONINFOW);
            _ = std.os.windows.ntdll.RtlGetVersion(&info);
            return std.fmt.bufPrint(buf, "Windows {d}.{d}.{d} {s}", .{ info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber, arch }) catch "Windows";
        },
        else => {
            const u = std.posix.uname();
            return std.fmt.bufPrint(buf, "{s} {s} {s}", .{ std.mem.sliceTo(&u.sysname, 0), std.mem.sliceTo(&u.release, 0), arch }) catch "Linux";
        },
    }
}

/// The user's Downloads folder, else their home.
fn downloads(buf: []u8) ?[]const u8 {
    const home = app.home_dir orelse return null;
    const d = std.fmt.bufPrint(buf, "{s}{c}Downloads", .{ home, std.fs.path.sep }) catch return null;
    if (std.Io.Dir.cwd().access(app.io, d, .{})) |_| return d else |_| {}
    return std.fmt.bufPrint(buf, "{s}", .{home}) catch null;
}

/// The file selected in Finder / Explorer (a folder window on Linux), ready
/// to be dragged into the issue.
fn reveal(io: std.Io, path: []const u8, dir: []const u8) void {
    const argv: []const []const u8 = switch (builtin.os.tag) {
        .macos => &.{ "/usr/bin/open", "-R", path },
        // `/select, "C:\Users\A B\Downloads\..."`: the path quoted on its own
        .windows => &.{ "explorer.exe", "/select,", path },
        else => &.{ "xdg-open", dir },
    };
    var child = std.process.spawn(io, .{ .argv = argv, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore }) catch |err| {
        return std.log.warn("report: file not shown: {t}", .{err});
    };
    _ = child.wait(io) catch {};
}
