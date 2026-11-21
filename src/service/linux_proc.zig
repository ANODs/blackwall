//! Who owns a connection on Linux: the socket's inode from /proc/net, the
//! process holding that inode from /proc/<pid>/fd, and that process's
//! executable with the executables of its parents (the identity chain the
//! tunnel's rules read, see `tunnel.AppLookup`).
//!
//! The service runs as the user, so it sees the user's own processes; the
//! applications a desktop user routes are among them. A flow of another
//! user (root's daemons) has no owner here and follows the default route.
//!
//! Finding the process means looking through every process's descriptors,
//! so what was found is kept: a socket's inode belongs to one process for
//! the socket's whole life, and the scan is redone only for an inode it has
//! not seen, at most a few times a second.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const c = std.c;

/// Parents followed above the process itself.
const ancestors_max = 8;
/// Room for the chain: the process and its parents, NUL between them.
const chain_max = 2048;
/// A new scan of /proc for an unknown inode no sooner than this after the last.
const rescan_ms = 40;
/// Forget what was found once it grows past this (sockets come and go).
const cache_max = 4096;

pub const Searcher = struct {
    gpa: std.mem.Allocator,
    io: Io,
    mutex: Io.Mutex = .init,
    /// socket inode → pid holding it
    owners: std.AutoHashMapUnmanaged(u64, i32) = .empty,
    last_scan_ms: i64 = 0,

    pub fn init(gpa: std.mem.Allocator, io: Io) Searcher {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn deinit(s: *Searcher) void {
        s.owners.deinit(s.gpa);
    }

    /// The identity chain of the process that owns the flow from
    /// `local_port` to `remote_port` (UDP: the local port alone), or null.
    pub fn find(s: *Searcher, udp: bool, local_port: u16, remote_port: u16, buf: []u8) ?[]u8 {
        if (comptime builtin.os.tag != .linux) return null;
        const inode = socketInode(s.gpa, udp, local_port, if (udp) null else remote_port) orelse return null;
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        var pid = s.owners.get(inode);
        if (pid) |p| if (!alive(p)) {
            _ = s.owners.remove(inode);
            pid = null;
        };
        if (pid == null) {
            // a burst of new connections shares one scan: the later ones wait
            // for the window to pass instead of going without an owner
            const since = Io.Clock.awake.now(s.io).toMilliseconds() - s.last_scan_ms;
            if (s.last_scan_ms != 0 and since < rescan_ms) s.io.sleep(.fromMilliseconds(rescan_ms - since), .awake) catch {};
            s.last_scan_ms = Io.Clock.awake.now(s.io).toMilliseconds();
            s.scan();
            pid = s.owners.get(inode);
        }
        var chain: [chain_max]u8 = undefined;
        const ids = withAncestors(pid orelse return null, &chain) orelse return null;
        if (ids.len > buf.len) return null;
        @memcpy(buf[0..ids.len], ids);
        return buf[0..ids.len];
    }

    /// Every socket descriptor of every process we may look into.
    fn scan(s: *Searcher) void {
        if (s.owners.count() > cache_max) s.owners.clearRetainingCapacity();
        var proc = Io.Dir.cwd().openDir(s.io, "/proc", .{ .iterate = true }) catch return;
        defer proc.close(s.io);
        var it = proc.iterate();
        while (it.next(s.io) catch null) |entry| {
            const pid = std.fmt.parseInt(i32, entry.name, 10) catch continue;
            var path_buf: [64]u8 = undefined;
            const fd_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/fd", .{pid}) catch continue;
            var fds = Io.Dir.cwd().openDir(s.io, fd_path, .{ .iterate = true }) catch continue;
            defer fds.close(s.io);
            var fit = fds.iterate();
            while (fit.next(s.io) catch null) |fd| {
                var link_path: [96]u8 = undefined;
                const lp = cpath(&link_path, "/proc/{d}/fd/{s}", .{ pid, fd.name }) orelse continue;
                var target: [64]u8 = undefined;
                const n = c.readlink(lp.ptr, &target, target.len);
                if (n <= 0) continue;
                const inode = socketTarget(target[0..@intCast(n)]) orelse continue;
                s.owners.put(s.gpa, inode, pid) catch return;
            }
        }
    }
};

/// "socket:[12345]" → 12345
fn socketTarget(link: []const u8) ?u64 {
    const prefix = "socket:[";
    if (!std.mem.startsWith(u8, link, prefix) or link.len < prefix.len + 2 or link[link.len - 1] != ']') return null;
    return std.fmt.parseInt(u64, link[prefix.len .. link.len - 1], 10) catch null;
}

fn alive(pid: i32) bool {
    return c.kill(pid, @fromBackingInt(@intCast(0))) == 0 or c.errno(@as(c_int, -1)) == .PERM;
}

/// Inode of the socket bound to `local_port` (and connected to
/// `remote_port`, when given), from the kernel's socket tables.
fn socketInode(gpa: std.mem.Allocator, udp: bool, local_port: u16, remote_port: ?u16) ?u64 {
    const tables: [2][:0]const u8 = if (udp) .{ "/proc/net/udp", "/proc/net/udp6" } else .{ "/proc/net/tcp", "/proc/net/tcp6" };
    for (tables) |table| {
        const text = readAll(gpa, table) orelse continue;
        defer gpa.free(text);
        if (findInode(text, local_port, remote_port)) |inode| return inode;
    }
    return null;
}

/// The table's lines read
///   sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode
///   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 31337 ...
pub fn findInode(text: []const u8, local_port: u16, remote_port: ?u16) ?u64 {
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    _ = lines.next(); // header
    while (lines.next()) |line| {
        var f = std.mem.tokenizeAny(u8, line, " \t");
        _ = f.next() orelse continue; // sl
        const local = f.next() orelse continue;
        const remote = f.next() orelse continue;
        if (portOf(local) != local_port) continue;
        if (remote_port) |rp| if (portOf(remote) != rp) continue;
        // st, tx:rx, tr:when, retrnsmt, uid, timeout, then the inode
        var k: usize = 0;
        var field: ?[]const u8 = null;
        while (k < 7) : (k += 1) field = f.next();
        const inode = std.fmt.parseInt(u64, field orelse continue, 10) catch continue;
        if (inode != 0) return inode;
    }
    return null;
}

fn portOf(addr: []const u8) ?u16 {
    const colon = std.mem.lastIndexOfScalar(u8, addr, ':') orelse return null;
    return std.fmt.parseInt(u16, addr[colon + 1 ..], 16) catch null;
}

/// The executable of `pid`, then those of its parents, NUL between them;
/// a parent that runs the same program as its child is not repeated.
fn withAncestors(pid: i32, out: *[chain_max]u8) ?[]const u8 {
    var len: usize = 0;
    var p = pid;
    var last: []const u8 = "";
    for (0..ancestors_max + 1) |_| {
        var path: [std.fs.max_path_bytes]u8 = undefined;
        if (exeOf(p, &path)) |exe| {
            // systemd starts everything else; it says nothing about the app
            if (len > 0 and std.mem.eql(u8, std.fs.path.basename(exe), "systemd")) break;
            if (!std.mem.eql(u8, exe, last)) {
                if (len + @intFromBool(len > 0) + exe.len > out.len) break;
                if (len > 0) {
                    out[len] = 0;
                    len += 1;
                }
                @memcpy(out[len..][0..exe.len], exe);
                last = out[len..][0..exe.len];
                len += exe.len;
            }
        } else if (len == 0) return null;
        p = parentOf(p) orelse break;
        if (p <= 1) break;
    }
    return if (len == 0) null else out[0..len];
}

fn exeOf(pid: i32, buf: *[std.fs.max_path_bytes]u8) ?[]const u8 {
    var path_buf: [64]u8 = undefined;
    const p = cpath(&path_buf, "/proc/{d}/exe", .{pid}) orelse return null;
    const n = c.readlink(p.ptr, buf, buf.len);
    if (n <= 0) return null;
    var exe = buf[0..@intCast(n)];
    // a program replaced on disk while it runs (an update)
    const deleted = " (deleted)";
    if (std.mem.endsWith(u8, exe, deleted)) exe = exe[0 .. exe.len - deleted.len];
    return exe;
}

/// The fourth field of /proc/<pid>/stat, after the command in parentheses
/// (which may itself hold spaces and parentheses).
fn parentOf(pid: i32) ?i32 {
    var path_buf: [64]u8 = undefined;
    const p = cpath(&path_buf, "/proc/{d}/stat", .{pid}) orelse return null;
    const fd = c.open(p.ptr, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    if (fd < 0) return null;
    defer _ = c.close(fd);
    var buf: [512]u8 = undefined;
    const n = c.read(fd, &buf, buf.len);
    if (n <= 0) return null;
    return parseParent(buf[0..@intCast(n)]);
}

pub fn parseParent(stat: []const u8) ?i32 {
    const close = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return null;
    var f = std.mem.tokenizeScalar(u8, stat[close + 1 ..], ' ');
    _ = f.next() orelse return null; // state
    return std.fmt.parseInt(i32, f.next() orelse return null, 10) catch null;
}

/// A NUL-terminated path for the C calls.
fn cpath(buf: []u8, comptime fmt: []const u8, args: anytype) ?[:0]const u8 {
    const p = std.fmt.bufPrint(buf[0 .. buf.len - 1], fmt, args) catch return null;
    buf[p.len] = 0;
    return buf[0..p.len :0];
}

/// Files in /proc report size 0, so they are read until the end.
fn readAll(gpa: std.mem.Allocator, path: [:0]const u8) ?[]u8 {
    const fd = c.open(path.ptr, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    if (fd < 0) return null;
    defer _ = c.close(fd);
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    while (true) {
        list.ensureUnusedCapacity(gpa, 16 * 1024) catch {
            list.deinit(gpa);
            return null;
        };
        const n = c.read(fd, list.unusedCapacitySlice().ptr, list.unusedCapacitySlice().len);
        if (n < 0) {
            list.deinit(gpa);
            return null;
        }
        if (n == 0) break;
        list.items.len += @intCast(n);
    }
    return list.toOwnedSlice(gpa) catch null;
}

// ---------------------------------------------------------------- tests

test "socket tables: the inode of a port, and of a connection" {
    const table =
        \\  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
        \\   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 31337 1 0000000000000000 100 0 0 10 0
        \\   1: 010012C6:C350 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 20 4 30 10 -1
        \\   2: 010012C6:C351 22D8B85D:01BB 06 00000000:00000000 03:00001556 00000000     0        0 0 3 0000000000000000
    ;
    try std.testing.expectEqual(@as(?u64, 31337), findInode(table, 8080, null));
    try std.testing.expectEqual(@as(?u64, 4242), findInode(table, 50000, 443));
    // the right local port, the wrong remote one
    try std.testing.expectEqual(@as(?u64, null), findInode(table, 50000, 80));
    // a socket in TIME_WAIT has no inode
    try std.testing.expectEqual(@as(?u64, null), findInode(table, 50001, 443));
}

test "parent of a process whose name holds parentheses" {
    try std.testing.expectEqual(@as(?i32, 812), parseParent("4242 (Web Content (x)) S 812 4242 812 0 -1 4194560"));
    try std.testing.expectEqual(@as(?i32, null), parseParent("garbage"));
}

test "this process owns its own connection" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const lfd = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    defer _ = c.close(lfd);
    var addr: c.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    try std.testing.expectEqual(@as(c_int, 0), c.bind(lfd, @ptrCast(&addr), @sizeOf(c.sockaddr.in)));
    try std.testing.expectEqual(@as(c_int, 0), c.listen(lfd, 1));
    var len: c.socklen_t = @sizeOf(c.sockaddr.in);
    _ = c.getsockname(lfd, @ptrCast(&addr), &len);
    const server_port = std.mem.bigToNative(u16, addr.port);

    const cfd = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    defer _ = c.close(cfd);
    try std.testing.expectEqual(@as(c_int, 0), c.connect(cfd, @ptrCast(&addr), @sizeOf(c.sockaddr.in)));
    var mine: c.sockaddr.in = undefined;
    len = @sizeOf(c.sockaddr.in);
    _ = c.getsockname(cfd, @ptrCast(&mine), &len);
    const client_port = std.mem.bigToNative(u16, mine.port);

    var s: Searcher = .init(gpa, std.testing.io);
    defer s.deinit();
    var buf: [chain_max]u8 = undefined;
    const chain = s.find(false, client_port, server_port, &buf) orelse return error.NotFound;
    var self_buf: [std.fs.max_path_bytes]u8 = undefined;
    const self = exeOf(c.getpid(), &self_buf).?;
    const first = chain[0 .. std.mem.indexOfScalar(u8, chain, 0) orelse chain.len];
    try std.testing.expectEqualStrings(self, first);
}
