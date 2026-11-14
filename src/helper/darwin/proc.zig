//! Processes, as the conflict handling needs them (macOS): who holds a
//! tunnel interface, and a process identity that a reused pid can never
//! match.
//!
//! A utun belongs to the process that has its kernel control socket open
//! (com.apple.net.utun_control, unit = N + 1 for utunN). Root sees every
//! process's descriptors; a user sees only its own, so the window asks the
//! root helper and falls back to its own processes.

const std = @import("std");
const builtin = @import("builtin");

/// libproc.h and sys/proc_info.h, translated by build.zig
const c = @import("libproc");

const max_path = 4 * 1024; // PROC_PIDPATHINFO_MAXSIZE

/// A process as it was when it was looked at: the pid, its start time
/// (pids are reused, start times are not) and its executable.
pub const Identity = struct {
    pid: i32,
    uid: u32,
    ppid: i32,
    /// start time in microseconds since the epoch
    start_us: u64,
    path_buf: [1024]u8 = undefined,
    path_len: u16 = 0,

    pub fn path(i: *const Identity) []const u8 {
        return i.path_buf[0..i.path_len];
    }

    /// The same process, not just the same pid.
    pub fn same(a: *const Identity, b: *const Identity) bool {
        return a.pid == b.pid and a.start_us == b.start_us and std.mem.eql(u8, a.path(), b.path());
    }
};

pub fn identity(pid: i32) ?Identity {
    if (pid <= 0) return null;
    var info: c.struct_proc_bsdinfo = undefined;
    const n = c.proc_pidinfo(pid, c.PROC_PIDTBSDINFO, 0, &info, @sizeOf(c.struct_proc_bsdinfo));
    if (n != @sizeOf(c.struct_proc_bsdinfo)) return null;
    var id: Identity = .{
        .pid = pid,
        .uid = info.pbi_uid,
        .ppid = @intCast(info.pbi_ppid),
        .start_us = info.pbi_start_tvsec * std.time.us_per_s + info.pbi_start_tvusec,
    };
    var buf: [max_path]u8 = undefined;
    const len = c.proc_pidpath(pid, &buf, buf.len);
    if (len <= 0 or len > id.path_buf.len) return null;
    @memcpy(id.path_buf[0..@intCast(len)], buf[0..@intCast(len)]);
    id.path_len = @intCast(len);
    return id;
}

/// Whether this process may be offered for stopping at all: never the
/// system's own (launchd, anything shipped in the OS), never ourselves.
pub fn mayStop(id: *const Identity, own_paths: []const []const u8) bool {
    if (id.pid <= 1) return false;
    const p = id.path();
    if (p.len == 0 or p[0] != '/') return false;
    for ([_][]const u8{ "/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/" }) |prefix| {
        if (std.mem.startsWith(u8, p, prefix)) return false;
    }
    for (own_paths) |own| if (std.mem.eql(u8, p, own)) return false;
    return true;
}

/// The unit number of utunN's kernel control socket, or null for another name.
pub fn utunUnit(ifname: []const u8) ?u32 {
    if (!std.mem.startsWith(u8, ifname, "utun")) return null;
    const n = std.fmt.parseInt(u32, ifname[4..], 10) catch return null;
    return n + 1;
}

/// The process holding `ifname` (a utun), among those this process may
/// inspect, or null.
pub fn tunnelOwner(gpa: std.mem.Allocator, ifname: []const u8) ?i32 {
    const unit = utunUnit(ifname) orelse return null;
    const pids = allPids(gpa) catch return null;
    defer gpa.free(pids);
    var fds: std.ArrayList(c.struct_proc_fdinfo) = .empty;
    defer fds.deinit(gpa);
    for (pids) |pid| {
        if (pid <= 0) continue;
        if (holdsUnit(gpa, pid, unit, &fds)) return pid;
    }
    return null;
}

fn allPids(gpa: std.mem.Allocator) ![]c_int {
    var cap: usize = 1024;
    while (true) {
        const buf = try gpa.alloc(c_int, cap);
        const n = c.proc_listallpids(buf.ptr, @intCast(cap * @sizeOf(c_int)));
        if (n < 0) {
            gpa.free(buf);
            return error.ListFailed;
        }
        const count: usize = @intCast(n);
        if (count < cap) return gpa.realloc(buf, count) catch buf[0..count];
        gpa.free(buf);
        cap *= 2;
        if (cap > 1 << 20) return error.ListFailed;
    }
}

fn holdsUnit(gpa: std.mem.Allocator, pid: c_int, unit: u32, fds: *std.ArrayList(c.struct_proc_fdinfo)) bool {
    const size = c.proc_pidinfo(pid, c.PROC_PIDLISTFDS, 0, null, 0);
    if (size <= 0) return false; // gone, or not ours to look at
    const want: usize = @as(usize, @intCast(size)) / @sizeOf(c.struct_proc_fdinfo) + 16;
    fds.resize(gpa, want) catch return false;
    const got = c.proc_pidinfo(pid, c.PROC_PIDLISTFDS, 0, fds.items.ptr, @intCast(want * @sizeOf(c.struct_proc_fdinfo)));
    if (got <= 0) return false;
    const n: usize = @as(usize, @intCast(got)) / @sizeOf(c.struct_proc_fdinfo);
    for (fds.items[0..n]) |fd| {
        if (fd.proc_fdtype != c.PROX_FDTYPE_SOCKET) continue;
        var si: c.struct_socket_fdinfo = undefined;
        const k = c.proc_pidfdinfo(pid, fd.proc_fd, c.PROC_PIDFDSOCKETINFO, &si, @sizeOf(c.struct_socket_fdinfo));
        if (k != @sizeOf(c.struct_socket_fdinfo)) continue;
        if (si.psi.soi_kind != c.SOCKINFO_KERN_CTL) continue;
        const kc = si.psi.soi_proto.pri_kern_ctl;
        if (kc.kcsi_unit != unit) continue;
        const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&kc.kcsi_name)), 0);
        if (std.mem.eql(u8, name, "com.apple.net.utun_control")) return true;
    }
    return false;
}

test "identity of this process, and a pid that is not running" {
    const me = identity(std.c.getpid()).?;
    try std.testing.expect(me.path().len > 0);
    try std.testing.expect(me.start_us > 0);
    var again = identity(std.c.getpid()).?;
    try std.testing.expect(me.same(&again));
    again.start_us += 1; // a reused pid starts later
    try std.testing.expect(!me.same(&again));
    try std.testing.expect(identity(-5) == null);
}

test "system processes are never offered for stopping" {
    var id: Identity = .{ .pid = 500, .uid = 0, .ppid = 1, .start_us = 1 };
    const set = struct {
        fn f(i: *Identity, p: []const u8) void {
            @memcpy(i.path_buf[0..p.len], p);
            i.path_len = @intCast(p.len);
        }
    }.f;
    set(&id, "/usr/libexec/mDNSResponder");
    try std.testing.expect(!mayStop(&id, &.{}));
    set(&id, "/System/Library/Frameworks/NetworkExtension.framework/x");
    try std.testing.expect(!mayStop(&id, &.{}));
    set(&id, "/Applications/Happ.app/Contents/MacOS/happd");
    try std.testing.expect(mayStop(&id, &.{}));
    try std.testing.expect(!mayStop(&id, &.{"/Applications/Happ.app/Contents/MacOS/happd"}));
    id.pid = 1;
    try std.testing.expect(!mayStop(&id, &.{}));
}

test "utun units" {
    try std.testing.expectEqual(@as(?u32, 8), utunUnit("utun7"));
    try std.testing.expectEqual(@as(?u32, null), utunUnit("en0"));
    try std.testing.expectEqual(@as(?u32, null), utunUnit("utunx"));
}

test "the owner of a utun we cannot see is unknown, not guessed" {
    // without root, another user's tunnel is never attributed to anyone
    if (std.c.geteuid() == 0) return error.SkipZigTest;
    try std.testing.expect(tunnelOwner(std.testing.allocator, "utun999") == null);
}
