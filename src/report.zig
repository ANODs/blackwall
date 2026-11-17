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

/// Issues go where releases come from; a build without a release
/// repository still reports to the project.
const repo = if (build_options.update_repo.len > 0) build_options.update_repo else "ANODs/blackwall";

// ---------------------------------------------------------------- the window's log

/// The window has no log file: its latest lines are kept here.
var ring: diag.Ring = .{};

pub fn logFn(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime format: []const u8, args: anytype) void {
    dvui.App.logFn(level, scope, format, args);
    var buf: [640]u8 = undefined;
    var w: std.Io.Writer = .fixed(buf[0 .. buf.len - 1]);
    const t = diag.now();
    w.print("{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} {s}({s}): ", .{ t.mon, t.day, t.hour, t.min, t.sec, @tagName(level), @tagName(scope) }) catch {};
    w.print(format, args) catch {};
    const n = w.buffered().len;
    buf[n] = '\n';
    ring.add(buf[0 .. n + 1]);
}

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
