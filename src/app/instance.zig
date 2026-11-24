//! One window per user, and the newest release is the one that runs.
//!
//! The window that runs holds a lock on `window.lock` in the settings
//! folder for as long as it lives (the system lets go of it when the
//! process ends, however it ends) and says who it is in `window.info`:
//! its release, its process and its executable.
//!
//! A second start finds the lock taken. The same release, or an older
//! one: it asks the running window to show itself (`window.show`) and
//! leaves. A newer one: it asks the running window to leave
//! (`window.quit`), waits for the lock, and on Windows, where a release is
//! a single file wherever the user keeps it, removes the older file. The
//! window that is asked to leave hands the service over as it is: the new
//! one adopts it, as after an update.
//!
//! Releases before this one hold no lock. On Windows their windows are
//! found by their executable's name, ended, and their files removed.
//!
//! A start that carries a link (`blackwall://...`, core/applink.zig: the
//! system starts the app with it as an argument) and finds a window
//! running leaves the link for it in `window.open`, a line of text, before
//! it asks that window to show itself.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

const on_windows = builtin.os.tag == .windows;
const log = std.log.scoped(.instance);

const lock_name = "window.lock";
const info_name = "window.info";
const show_name = "window.show";
const quit_name = "window.quit";
const open_name = "window.open";
/// the running window's own copy of `window.open` while it reads it
const taken_name = "window.open.taken";
/// The longest link handed over; longer ones are no links (core/applink.zig).
pub const max_link = 8 * 1024;

/// the lock, for as long as this process lives
var held: ?Io.File = null;
var show_buf: [std.fs.max_path_bytes]u8 = undefined;
var quit_buf: [std.fs.max_path_bytes]u8 = undefined;
var open_buf: [std.fs.max_path_bytes]u8 = undefined;
var taken_buf: [std.fs.max_path_bytes]u8 = undefined;
var show_path: []const u8 = "";
var quit_path: []const u8 = "";
var open_path: []const u8 = "";
var taken_path: []const u8 = "";
/// the links being handed over (the watcher's thread only)
var links_buf: [4 * max_link]u8 = undefined;

pub const Claim = enum {
    /// this process is the window
    first,
    /// another window runs and stays: leave
    second,
};

/// What another start asks of the running window.
pub const Signal = union(enum) {
    show,
    quit,
    /// a link it was started with; the text is the watcher's, good for the
    /// length of the call
    open: []const u8,
};

/// The window that runs, as it wrote itself down.
const Info = struct {
    version: []const u8,
    pid: u32,
    exe: []const u8,

    /// "<version>\n<pid>\n<executable>\n"
    fn parse(text: []const u8) ?Info {
        var it = std.mem.splitScalar(u8, text, '\n');
        const version = std.mem.trim(u8, it.next() orelse return null, " \r");
        const pid = std.fmt.parseInt(u32, std.mem.trim(u8, it.next() orelse return null, " \r"), 10) catch return null;
        const exe = std.mem.trim(u8, it.next() orelse return null, " \r");
        if (version.len == 0 or exe.len == 0) return null;
        return .{ .version = version, .pid = pid, .exe = exe };
    }
};

/// Whether release `mine` is to replace the window that runs: only when
/// that one is known and strictly older.
fn replaces(mine: []const u8, other: ?Info) bool {
    const o = other orelse return false;
    const a = std.SemanticVersion.parse(mine) catch return false;
    const b = std.SemanticVersion.parse(o.version) catch return false;
    return a.order(b) == .gt;
}

/// Become the window, or learn that another one stays. Nothing here may
/// keep the app from starting: a folder that cannot be locked means no
/// guard, not no window. `link` is what this start was given to open: the
/// window that stays gets it.
pub fn claim(gpa: std.mem.Allocator, io: Io, config_dir: []const u8, version: []const u8, link: ?[]const u8) Claim {
    if (config_dir.len == 0) return .first;
    const cwd = Io.Dir.cwd();
    cwd.createDirPath(io, config_dir) catch return .first;
    var dir = cwd.openDir(io, config_dir, .{}) catch return .first;
    defer dir.close(io);
    show_path = std.fmt.bufPrint(&show_buf, "{s}{c}" ++ show_name, .{ config_dir, std.fs.path.sep }) catch return .first;
    quit_path = std.fmt.bufPrint(&quit_buf, "{s}{c}" ++ quit_name, .{ config_dir, std.fs.path.sep }) catch return .first;
    open_path = std.fmt.bufPrint(&open_buf, "{s}{c}" ++ open_name, .{ config_dir, std.fs.path.sep }) catch return .first;
    taken_path = std.fmt.bufPrint(&taken_buf, "{s}{c}" ++ taken_name, .{ config_dir, std.fs.path.sep }) catch return .first;
    const own = std.process.executablePathAlloc(io, gpa) catch return .first;
    defer gpa.free(own);
    if (on_windows) win.announce();

    var text_buf: [std.fs.max_path_bytes + 64]u8 = undefined;
    // a link goes to the window that runs at once, not after the wait
    // below: whoever clicked it is looking at the screen. Should that
    // window be leaving, this start becomes the window and opens the link
    // itself; an address opened twice is one subscription all the same.
    var left = false;
    if (link) |l| if (!take(dir, io, 0)) {
        if (on_windows) if (current(dir, io, &text_buf)) |o| win.allowFront(o.pid);
        leave(dir, io, l);
        left = true;
    };
    // a window that is leaving (an update relaunched us) is gone in a moment
    if (held == null and !take(dir, io, 2000)) {
        const other = current(dir, io, &text_buf);
        if (!replaces(version, other)) {
            ask(dir, io, other, if (left) null else link);
            return .second;
        }
        log.info("release {s} runs; this one ({s}) takes over", .{ other.?.version, version });
        touch(dir, io, quit_name);
        if (!take(dir, io, 8000)) {
            // it does not answer: on Windows that very process is ended
            if (on_windows) win.end(other.?.pid, other.?.exe);
            if (!take(dir, io, 3000)) {
                dir.deleteFile(io, quit_name) catch {};
                ask(dir, io, other, if (left) null else link);
                return .second;
            }
        }
        if (on_windows) win.remove(io, other.?.exe, own);
    }
    dir.deleteFile(io, show_name) catch {};
    dir.deleteFile(io, quit_name) catch {};
    // a link nobody took is not opened by a later window
    dir.deleteFile(io, open_name) catch {};
    dir.deleteFile(io, taken_name) catch {};
    var info_buf: [std.fs.max_path_bytes + 64]u8 = undefined;
    if (std.fmt.bufPrint(&info_buf, "{s}\n{d}\n{s}\n", .{ version, ownPid(), own })) |text|
        dir.writeFile(io, .{ .sub_path = info_name, .data = text }) catch {}
    else |_| {}
    if (on_windows) win.sweep(io, own);
    return .first;
}

/// The window that runs, as `window.info` has it.
fn current(dir: Io.Dir, io: Io, buf: []u8) ?Info {
    return Info.parse(dir.readFile(io, info_name, buf) catch return null);
}

/// The lock, tried for `wait_ms`. True also when the folder cannot hold a
/// lock at all.
fn take(dir: Io.Dir, io: Io, wait_ms: i64) bool {
    const begin = Io.Clock.awake.now(io);
    while (true) {
        if (dir.createFile(io, lock_name, .{ .truncate = false, .lock = .exclusive, .lock_nonblocking = true })) |f| {
            held = f;
            return true;
        } else |err| switch (err) {
            error.WouldBlock => {},
            else => return true,
        }
        if (begin.untilNow(io, .awake).toMilliseconds() >= wait_ms) return false;
        io.sleep(.fromMilliseconds(100), .awake) catch return false;
    }
}

/// Ask the window that runs to show itself, and to open `link` first when
/// there is one.
fn ask(dir: Io.Dir, io: Io, other: ?Info, link: ?[]const u8) void {
    if (link) |l| leave(dir, io, l);
    // Windows lets only the process the user just started bring a window
    // to the front: it passes that right on
    if (on_windows) if (other) |o| win.allowFront(o.pid);
    touch(dir, io, show_name);
}

/// Add `link` to `window.open`, a line of its own (two starts at once each
/// leave theirs).
fn leave(dir: Io.Dir, io: Io, link: []const u8) void {
    const text = std.mem.trim(u8, link, " \t\r\n");
    if (text.len == 0 or text.len > max_link or std.mem.indexOfAny(u8, text, "\r\n") != null) return;
    const f = dir.createFile(io, open_name, .{ .truncate = false }) catch return;
    defer f.close(io);
    const end = f.length(io) catch return;
    if (end > links_buf.len) return;
    var line_buf: [max_link + 1]u8 = undefined;
    @memcpy(line_buf[0..text.len], text);
    line_buf[text.len] = '\n';
    f.writePositionalAll(io, line_buf[0 .. text.len + 1], end) catch {};
}

fn touch(dir: Io.Dir, io: Io, name: []const u8) void {
    dir.writeFile(io, .{ .sub_path = name, .data = "" }) catch {};
}

fn ownPid() u32 {
    if (comptime on_windows) return win.GetCurrentProcessId();
    return @intCast(std.c.getpid());
}

/// Watch for what another start asks, on a thread of its own: two looks at
/// the folder a second. `tell` is called on that thread.
pub fn watch(io: Io, tell: *const fn (Signal) void) void {
    if (held == null) return;
    const t = std.Thread.spawn(.{ .stack_size = 64 * 1024 }, watcher, .{ io, tell }) catch return;
    t.detach();
}

fn watcher(io: Io, tell: *const fn (Signal) void) void {
    const cwd = Io.Dir.cwd();
    while (true) {
        io.sleep(.fromMilliseconds(500), .awake) catch return;
        if (cwd.access(io, quit_path, .{})) |_| {
            cwd.deleteFile(io, quit_path) catch {};
            return tell(.quit);
        } else |_| {}
        // before the show that follows it, so the window comes forward
        // with the link already taken
        taken(io, tell);
        if (cwd.access(io, show_path, .{})) |_| {
            cwd.deleteFile(io, show_path) catch {};
            tell(.show);
        } else |_| {}
    }
}

/// The links other starts left, one call each. The file is made ours
/// first, so a start that writes at this moment loses nothing: its line
/// goes to a new file, for the next look.
fn taken(io: Io, tell: *const fn (Signal) void) void {
    const cwd = Io.Dir.cwd();
    cwd.rename(open_path, cwd, taken_path, io) catch return;
    defer cwd.deleteFile(io, taken_path) catch {};
    const text = cwd.readFile(io, taken_path, &links_buf) catch return;
    var it = std.mem.tokenizeAny(u8, text, "\r\n");
    while (it.next()) |line| tell(.{ .open = line });
}

/// A window's executable by its name, not the service's: "BLACKWALL.exe",
/// "BLACKWALL-0.2.16-ru-windows-x86_64.exe".
fn windowExe(path: []const u8) bool {
    const at = std.mem.lastIndexOfAny(u8, path, "\\/");
    const base = if (at) |i| path[i + 1 ..] else path;
    if (!std.ascii.startsWithIgnoreCase(base, "blackwall") or !std.ascii.endsWithIgnoreCase(base, ".exe")) return false;
    for ([_][]const u8{ "blackwall-service.exe", "blackwall-tun.exe", "blackwall-sign.exe", "blackwall-helper.exe" }) |other|
        if (std.ascii.eqlIgnoreCase(base, other)) return false;
    return true;
}

const win = struct {
    const w = std.os.windows;
    const W: std.builtin.CallingConvention = .winapi;

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
    const TH32CS_SNAPPROCESS = 0x2;
    const PROCESS_TERMINATE = 0x1;
    const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const SYNCHRONIZE = 0x100000;
    const WAIT_OBJECT_0 = 0;

    extern "kernel32" fn CreateToolhelp32Snapshot(flags: u32, pid: u32) callconv(W) w.HANDLE;
    extern "kernel32" fn Process32FirstW(snap: w.HANDLE, entry: *PROCESSENTRY32W) callconv(W) i32;
    extern "kernel32" fn Process32NextW(snap: w.HANDLE, entry: *PROCESSENTRY32W) callconv(W) i32;
    extern "kernel32" fn OpenProcess(access: u32, inherit: i32, pid: u32) callconv(W) ?w.HANDLE;
    extern "kernel32" fn QueryFullProcessImageNameW(h: w.HANDLE, flags: u32, name: [*]u16, size: *u32) callconv(W) i32;
    extern "kernel32" fn TerminateProcess(h: w.HANDLE, code: u32) callconv(W) i32;
    extern "kernel32" fn WaitForSingleObject(h: w.HANDLE, ms: u32) callconv(W) u32;
    extern "kernel32" fn GetCurrentProcessId() callconv(W) u32;
    extern "kernel32" fn CreateEventW(attrs: ?*anyopaque, manual: i32, initial: i32, name: [*:0]const u16) callconv(W) ?w.HANDLE;
    extern "kernel32" fn OpenEventW(access: u32, inherit: i32, name: [*:0]const u16) callconv(W) ?w.HANDLE;
    extern "user32" fn AllowSetForegroundWindow(pid: u32) callconv(W) i32;

    /// Let process `id` bring its window to the front.
    fn allowFront(id: u32) void {
        if (comptime !on_windows) return;
        _ = AllowSetForegroundWindow(id);
    }

    /// "Local\BLACKWALL-window-<pid>": an event every window of a release
    /// that knows the lock holds for its lifetime. A window without one is
    /// of an older release.
    fn eventName(buf: *[48:0]u16, id: u32) [*:0]const u16 {
        var text: [48]u8 = undefined;
        const s = std.fmt.bufPrint(&text, "Local\\BLACKWALL-window-{d}", .{id}) catch unreachable;
        for (s, 0..) |ch, i| buf[i] = ch;
        buf[s.len] = 0;
        return @ptrCast(buf);
    }

    fn announce() void {
        if (comptime !on_windows) return;
        var buf: [48:0]u16 = undefined;
        // kept open until the process ends
        _ = CreateEventW(null, 1, 0, eventName(&buf, GetCurrentProcessId()));
    }

    fn announced(id: u32) bool {
        var buf: [48:0]u16 = undefined;
        const h = OpenEventW(SYNCHRONIZE, 0, eventName(&buf, id)) orelse return false;
        w.CloseHandle(h);
        return true;
    }

    /// The executable of an open process, or null.
    fn image(h: w.HANDLE, out: []u8) ?[]const u8 {
        var pw: [1024]u16 = undefined;
        var size: u32 = pw.len;
        if (QueryFullProcessImageNameW(h, 0, &pw, &size) == 0) return null;
        if (out.len < 3 * @as(usize, size)) return null;
        return out[0..std.unicode.wtf16LeToWtf8(out, pw[0..size])];
    }

    /// End process `id` when it still runs `exe`: not a later process that
    /// got the same number.
    fn end(id: u32, exe: []const u8) void {
        if (comptime !on_windows) return;
        if (id <= 4 or id == GetCurrentProcessId() or !windowExe(exe)) return;
        const h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, id) orelse return;
        defer w.CloseHandle(h);
        var buf: [3 * 1024]u8 = undefined;
        const path = image(h, &buf) orelse return;
        if (!std.ascii.eqlIgnoreCase(path, exe)) return;
        if (TerminateProcess(h, 0) == 0) return;
        _ = WaitForSingleObject(h, 5000);
    }

    /// Remove the older release's file, unless it is our own (an update in
    /// place) or not a window's executable at all.
    fn remove(io: Io, exe: []const u8, own: []const u8) void {
        if (comptime !on_windows) return;
        if (!windowExe(exe) or std.ascii.eqlIgnoreCase(exe, own)) return;
        // a file whose process just ended is held a moment longer
        for (0..20) |_| {
            Io.Dir.cwd().deleteFile(io, exe) catch |err| switch (err) {
                error.FileNotFound => return,
                else => {
                    io.sleep(.fromMilliseconds(150), .awake) catch return;
                    continue;
                },
            };
            return log.info("the older release's file is removed: {s}", .{exe});
        }
        log.warn("the older release's file could not be removed: {s}", .{exe});
    }

    /// Windows of releases that hold no lock: ended, their files removed.
    fn sweep(io: Io, own: []const u8) void {
        if (comptime !on_windows) return;
        const snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == w.INVALID_HANDLE_VALUE) return;
        defer w.CloseHandle(snap);
        const me = GetCurrentProcessId();
        var e: PROCESSENTRY32W = .{};
        var ok = Process32FirstW(snap, &e) != 0;
        while (ok) : (ok = Process32NextW(snap, &e) != 0) {
            const id = e.th32ProcessID;
            if (id == me or id <= 4) continue;
            var name_buf: [3 * 260]u8 = undefined;
            const name = name_buf[0..std.unicode.wtf16LeToWtf8(&name_buf, std.mem.sliceTo(&e.szExeFile, 0))];
            if (!windowExe(name) or announced(id)) continue;
            const h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, id) orelse continue;
            defer w.CloseHandle(h);
            var buf: [3 * 1024]u8 = undefined;
            const path = image(h, &buf) orelse continue;
            if (!windowExe(path)) continue;
            log.info("a window of an older release runs ({s}): ended", .{path});
            if (TerminateProcess(h, 0) == 0) continue;
            _ = WaitForSingleObject(h, 5000);
            remove(io, path, own);
        }
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "the running window's note: release, process, executable" {
    const i = Info.parse("0.2.19\n4242\nC:\\Users\\u\\Downloads\\BLACKWALL-0.2.19-ru-windows-x86_64.exe\n").?;
    try testing.expectEqualStrings("0.2.19", i.version);
    try testing.expectEqual(4242, i.pid);
    try testing.expectEqualStrings("C:\\Users\\u\\Downloads\\BLACKWALL-0.2.19-ru-windows-x86_64.exe", i.exe);
    try testing.expect(Info.parse("") == null);
    try testing.expect(Info.parse("0.2.19\nnot a number\nx\n") == null);
    try testing.expect(Info.parse("0.2.19\n1\n") == null);
}

test "only a strictly newer release replaces the window that runs" {
    const running: Info = .{ .version = "0.2.19", .pid = 1, .exe = "x" };
    try testing.expect(replaces("0.2.20", running));
    try testing.expect(replaces("0.3.0", running));
    try testing.expect(!replaces("0.2.19", running));
    try testing.expect(!replaces("0.2.18", running));
    // a window that did not say who it is stays
    try testing.expect(!replaces("0.2.20", null));
    try testing.expect(!replaces("0.2.20", .{ .version = "garbage", .pid = 1, .exe = "x" }));
}

test "a window's executable is told from the service's by its name" {
    try testing.expect(windowExe("C:\\Users\\u\\Downloads\\BLACKWALL-0.2.16-ru-windows-x86_64.exe"));
    try testing.expect(windowExe("blackwall.exe"));
    try testing.expect(!windowExe("C:\\Program Files\\BLACKWALL\\blackwall-service.exe"));
    try testing.expect(!windowExe("C:\\Program Files\\BLACKWALL\\BLACKWALL-SERVICE.EXE"));
    try testing.expect(!windowExe("C:\\Windows\\System32\\cmd.exe"));
    try testing.expect(!windowExe("C:\\x\\BLACKWALL-0.2.16.exe.previous"));
}

test "the lock is held by one, and free again once it is let go" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const saved = held;
    defer held = saved;
    held = null;
    try testing.expect(take(tmp.dir, testing.io, 0));
    const first = held.?;
    held = null;
    // a second taker waits in vain
    try testing.expect(!take(tmp.dir, testing.io, 150));
    try testing.expect(held == null);
    first.close(testing.io);
    try testing.expect(take(tmp.dir, testing.io, 0));
    held.?.close(testing.io);
}

/// The folder of a `tmpDir`, as a path from the working directory.
fn tmpPath(buf: []u8, tmp: *const testing.TmpDir) []const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache/tmp/{s}", .{&tmp.sub_path}) catch unreachable;
}

test "a second start of the same release asks the running window to show itself and leaves" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const saved = held;
    defer held = saved;
    held = null;
    var buf: [128]u8 = undefined;
    const dir = tmpPath(&buf, &tmp);

    try testing.expectEqual(.first, claim(testing.allocator, testing.io, dir, "0.2.20", null));
    const running = held.?;
    defer running.close(testing.io);
    var text: [std.fs.max_path_bytes + 64]u8 = undefined;
    const info = Info.parse(try tmp.dir.readFile(testing.io, info_name, &text)).?;
    try testing.expectEqualStrings("0.2.20", info.version);
    try testing.expectEqual(ownPid(), info.pid);

    held = null;
    try testing.expectEqual(.second, claim(testing.allocator, testing.io, dir, "0.2.20", null));
    try testing.expect(held == null);
    try tmp.dir.access(testing.io, show_name, .{});
    // an older release leaves too
    try tmp.dir.deleteFile(testing.io, show_name);
    try testing.expectEqual(.second, claim(testing.allocator, testing.io, dir, "0.2.19", null));
    try tmp.dir.access(testing.io, show_name, .{});
    try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, quit_name, .{}));
}

test "a newer release asks the running window to leave and takes its place" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const saved = held;
    defer held = saved;
    held = null;
    var buf: [128]u8 = undefined;
    const dir = tmpPath(&buf, &tmp);

    try testing.expectEqual(.first, claim(testing.allocator, testing.io, dir, "0.2.20", null));
    const Old = struct {
        file: Io.File,
        dir: Io.Dir,
        asked: bool = false,
        /// the running window: it leaves when it is asked to
        fn run(o: *@This()) void {
            for (0..400) |_| {
                if (o.dir.access(testing.io, quit_name, .{})) |_| {
                    o.asked = true;
                    break;
                } else |_| {}
                testing.io.sleep(.fromMilliseconds(10), .awake) catch {};
            }
            o.file.close(testing.io);
        }
    };
    var old: Old = .{ .file = held.?, .dir = tmp.dir };
    held = null;
    const th = try std.Thread.spawn(.{}, Old.run, .{&old});
    const got = claim(testing.allocator, testing.io, dir, "0.2.21", null);
    th.join();
    try testing.expectEqual(.first, got);
    try testing.expect(old.asked);
    defer held.?.close(testing.io);
    var text: [std.fs.max_path_bytes + 64]u8 = undefined;
    try testing.expectEqualStrings("0.2.21", Info.parse(try tmp.dir.readFile(testing.io, info_name, &text)).?.version);
    // nothing is left to ask the new window anything
    try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, quit_name, .{}));
}

test "a second start with a link leaves it for the running window, which takes it once" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const saved = held;
    defer held = saved;
    held = null;
    var buf: [128]u8 = undefined;
    const dir = tmpPath(&buf, &tmp);

    try testing.expectEqual(.first, claim(testing.allocator, testing.io, dir, "0.2.23", null));
    const running = held.?;
    defer running.close(testing.io);

    held = null;
    try testing.expectEqual(.second, claim(testing.allocator, testing.io, dir, "0.2.23", "blackwall://add/https://example.invalid/s/one\n"));
    try testing.expectEqual(.second, claim(testing.allocator, testing.io, dir, "0.2.22", "blackwall://add/https://example.invalid/s/two"));
    // nothing that is not one line of a sane length
    try testing.expectEqual(.second, claim(testing.allocator, testing.io, dir, "0.2.23", "blackwall://add/https://example.invalid/a\nblackwall://add/https://example.invalid/b"));
    try testing.expectEqual(.second, claim(testing.allocator, testing.io, dir, "0.2.23", &@as([max_link + 1]u8, @splat('a'))));
    try testing.expect(held == null);
    try tmp.dir.access(testing.io, show_name, .{});

    const Got = struct {
        var n: usize = 0;
        var text: [2][64]u8 = undefined;
        var len: [2]usize = undefined;
        fn tell(what: Signal) void {
            const link = what.open;
            if (n < 2) {
                @memcpy(text[n][0..link.len], link);
                len[n] = link.len;
            }
            n += 1;
        }
    };
    Got.n = 0;
    taken(testing.io, Got.tell);
    try testing.expectEqual(2, Got.n);
    try testing.expectEqualStrings("blackwall://add/https://example.invalid/s/one", Got.text[0][0..Got.len[0]]);
    try testing.expectEqualStrings("blackwall://add/https://example.invalid/s/two", Got.text[1][0..Got.len[1]]);
    // taken once
    taken(testing.io, Got.tell);
    try testing.expectEqual(2, Got.n);
    try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, open_name, .{}));
    try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, taken_name, .{}));
}

test "a link nobody took is gone when the next window starts" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const saved = held;
    defer held = saved;
    held = null;
    var buf: [128]u8 = undefined;
    const dir = tmpPath(&buf, &tmp);

    try tmp.dir.writeFile(testing.io, .{ .sub_path = open_name, .data = "blackwall://add/https://example.invalid/s/old\n" });
    try testing.expectEqual(.first, claim(testing.allocator, testing.io, dir, "0.2.23", null));
    defer held.?.close(testing.io);
    try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, open_name, .{}));
}
