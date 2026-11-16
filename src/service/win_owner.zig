//! Who owns a connection on Windows: the TCP and UDP tables of the IP
//! Helper API name the process of each local port, and the process's
//! executable, with the executables of its parents, is the identity chain
//! the tunnel's rules read (see `tunnel.AppLookup`).
//!
//! The service runs as LocalSystem, so it sees every process. Paths are
//! kept in lower case: Windows does not tell `C:\Program Files` from
//! `c:\program files`, and the list of applications (platform/apps.zig)
//! writes them the same way.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const w = std.os.windows;

/// Parents followed above the process itself.
const ancestors_max = 8;
/// What is known of a process: its chain, for this long.
const cache_ms = 5_000;
const cache_max = 1024;

const W: std.builtin.CallingConvention = .winapi;
extern "iphlpapi" fn GetExtendedTcpTable(table: ?*anyopaque, size: *u32, order: i32, af: u32, class: u32, reserved: u32) callconv(W) u32;
extern "iphlpapi" fn GetExtendedUdpTable(table: ?*anyopaque, size: *u32, order: i32, af: u32, class: u32, reserved: u32) callconv(W) u32;
extern "kernel32" fn OpenProcess(access: u32, inherit: i32, pid: u32) callconv(W) ?w.HANDLE;
extern "kernel32" fn QueryFullProcessImageNameW(h: w.HANDLE, flags: u32, name: [*]u16, size: *u32) callconv(W) i32;
extern "kernel32" fn GetProcessTimes(h: w.HANDLE, creation: *u64, exit: *u64, kernel: *u64, user: *u64) callconv(W) i32;
extern "kernel32" fn CreateToolhelp32Snapshot(flags: u32, pid: u32) callconv(W) w.HANDLE;
extern "kernel32" fn Process32FirstW(snap: w.HANDLE, entry: *PROCESSENTRY32W) callconv(W) i32;
extern "kernel32" fn Process32NextW(snap: w.HANDLE, entry: *PROCESSENTRY32W) callconv(W) i32;

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

const TCP_TABLE_OWNER_PID_ALL = 5;
const UDP_TABLE_OWNER_PID = 1;
const AF_INET = 2;
const AF_INET6 = 23;
const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
const TH32CS_SNAPPROCESS = 0x2;

pub const Searcher = struct {
    gpa: std.mem.Allocator,
    io: Io,
    mutex: Io.Mutex = .init,
    /// pid → its chain, while fresh
    chains: std.AutoHashMapUnmanaged(u32, Known) = .empty,
    table: std.ArrayList(u8) = .empty,

    const Known = struct { chain: []u8, at_ms: i64 };

    pub fn init(gpa: std.mem.Allocator, io: Io) Searcher {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn deinit(s: *Searcher) void {
        var it = s.chains.valueIterator();
        while (it.next()) |k| s.gpa.free(k.chain);
        s.chains.deinit(s.gpa);
        s.table.deinit(s.gpa);
    }

    /// The identity chain of the process with the flow from `local_port`
    /// (to `remote_port` for TCP), or null.
    pub fn find(s: *Searcher, udp: bool, v6: bool, local_port: u16, remote_port: u16, buf: []u8) ?[]u8 {
        if (comptime builtin.os.tag != .windows) return null;
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        const pid = s.owner(udp, v6, local_port, remote_port) orelse return null;
        if (pid == 0 or pid == 4) return null; // the idle process and the kernel
        const now = Io.Clock.awake.now(s.io).toMilliseconds();
        if (s.chains.get(pid)) |k| if (now - k.at_ms < cache_ms) {
            const n = @min(k.chain.len, buf.len);
            @memcpy(buf[0..n], k.chain[0..n]);
            return buf[0..n];
        };
        const chain = chainOf(pid, buf) orelse return null;
        if (s.chains.count() >= cache_max) s.clear();
        const copy = s.gpa.dupe(u8, chain) catch return chain;
        const gop = s.chains.getOrPut(s.gpa, pid) catch {
            s.gpa.free(copy);
            return chain;
        };
        if (gop.found_existing) s.gpa.free(gop.value_ptr.chain);
        gop.value_ptr.* = .{ .chain = copy, .at_ms = now };
        return chain;
    }

    fn clear(s: *Searcher) void {
        var it = s.chains.valueIterator();
        while (it.next()) |k| s.gpa.free(k.chain);
        s.chains.clearRetainingCapacity();
    }

    /// The process of the local port, from the system's table.
    fn owner(s: *Searcher, udp: bool, v6: bool, local_port: u16, remote_port: u16) ?u32 {
        const af: u32 = if (v6) AF_INET6 else AF_INET;
        var size: u32 = @intCast(s.table.capacity);
        var tries: usize = 0;
        while (tries < 4) : (tries += 1) {
            s.table.ensureTotalCapacity(s.gpa, @max(size, 16 * 1024)) catch return null;
            size = @intCast(s.table.capacity);
            const rc = if (udp)
                GetExtendedUdpTable(s.table.items.ptr, &size, 0, af, UDP_TABLE_OWNER_PID, 0)
            else
                GetExtendedTcpTable(s.table.items.ptr, &size, 0, af, TCP_TABLE_OWNER_PID_ALL, 0);
            if (rc == 0) break;
            if (rc != 122) return null; // ERROR_INSUFFICIENT_BUFFER: grow and again
        } else return null;
        const t = s.table.allocatedSlice()[0..size];
        return ownerIn(t, udp, v6, local_port, remote_port);
    }
};

/// Finds the local port in a table as GetExtendedTcpTable/UdpTable write it.
pub fn ownerIn(t: []const u8, udp: bool, v6: bool, local_port: u16, remote_port: u16) ?u32 {
    if (t.len < 4) return null;
    const n = std.mem.readInt(u32, t[0..4], .little);
    // the row's size and where the ports and the pid are in it
    const row: usize, const lport: usize, const rport: ?usize, const pid: usize = if (!v6)
        (if (udp) .{ 12, 4, null, 8 } else .{ 24, 8, 16, 20 })
    else
        (if (udp) .{ 28, 20, null, 24 } else .{ 56, 20, 44, 52 });
    // the rows begin after the count (IPv6 rows hold 16-byte addresses, no padding)
    var off: usize = 4;
    var i: usize = 0;
    while (i < n and off + row <= t.len) : ({
        i += 1;
        off += row;
    }) {
        const r = t[off..][0..row];
        // ports are in network order in the low 16 bits
        if (port(r[lport..][0..4]) != local_port) continue;
        if (rport) |rp| if (port(r[rp..][0..4]) != remote_port) continue;
        return std.mem.readInt(u32, r[pid..][0..4], .little);
    }
    return null;
}

fn port(b: *const [4]u8) u16 {
    return std.mem.readInt(u16, b[0..2], .big);
}

/// The process's executable and its parents', NUL between them.
fn chainOf(pid: u32, buf: []u8) ?[]u8 {
    var parents: [ancestors_max + 1]u32 = undefined;
    const count = ancestry(pid, &parents);
    var n: usize = 0;
    for (parents[0..count], 0..) |p, k| {
        var path: [1024]u8 = undefined;
        const exe = imagePath(p, &path) orelse {
            if (k == 0) return null;
            break;
        };
        if (k > 0) {
            if (n + 1 > buf.len) break;
            buf[n] = 0;
            n += 1;
        }
        if (n + exe.len > buf.len) break;
        @memcpy(buf[n..][0..exe.len], exe);
        n += exe.len;
    }
    return buf[0..n];
}

/// `pid` and its parents, nearest first. A parent that started after its
/// child is a later process that got the same number: the chain ends there.
fn ancestry(pid: u32, out: []u32) usize {
    out[0] = pid;
    var count: usize = 1;
    const snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == w.INVALID_HANDLE_VALUE) return count;
    defer w.CloseHandle(snap);
    var entries: [2048]struct { pid: u32, parent: u32 } = undefined;
    var len: usize = 0;
    var e: PROCESSENTRY32W = .{};
    var ok = Process32FirstW(snap, &e) != 0;
    while (ok and len < entries.len) : (ok = Process32NextW(snap, &e) != 0) {
        entries[len] = .{ .pid = e.th32ProcessID, .parent = e.th32ParentProcessID };
        len += 1;
    }
    var cur = pid;
    var cur_start = started(cur);
    while (count < out.len) {
        const parent = for (entries[0..len]) |x| {
            if (x.pid == cur) break x.parent;
        } else break;
        if (parent == 0 or parent == 4 or parent == cur) break;
        const parent_start = started(parent);
        if (parent_start == 0 or (cur_start != 0 and parent_start > cur_start)) break;
        out[count] = parent;
        count += 1;
        cur = parent;
        cur_start = parent_start;
    }
    return count;
}

fn started(pid: u32) u64 {
    const h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) orelse return 0;
    defer w.CloseHandle(h);
    var cr: u64 = 0;
    var ex: u64 = 0;
    var k: u64 = 0;
    var u: u64 = 0;
    if (GetProcessTimes(h, &cr, &ex, &k, &u) == 0) return 0;
    return cr;
}

/// The full path of the process's executable, in lower case UTF-8.
fn imagePath(pid: u32, out: []u8) ?[]u8 {
    const h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) orelse return null;
    defer w.CloseHandle(h);
    var wide: [512]u16 = undefined;
    var size: u32 = wide.len;
    if (QueryFullProcessImageNameW(h, 0, &wide, &size) == 0) return null;
    return identity(wide[0..size], out);
}

/// A Windows path as an identity: UTF-8, lower case.
pub fn identity(wide: []const u16, out: []u8) ?[]u8 {
    const n = std.unicode.wtf16LeToWtf8(out, wide);
    if (n > out.len) return null;
    const s = out[0..n];
    for (s) |*ch| ch.* = std.ascii.toLower(ch.*);
    return s;
}

test "the owner of a port in the system's tables" {
    // two IPv4 TCP rows: count, then state, local addr, local port, remote addr, remote port, pid
    var t: [4 + 2 * 24]u8 = @splat(0);
    std.mem.writeInt(u32, t[0..4], 2, .little);
    for ([_][3]u32{ .{ 50000, 443, 111 }, .{ 50001, 443, 222 } }, 0..) |r, k| {
        const o = 4 + k * 24;
        std.mem.writeInt(u16, t[o + 8 ..][0..2], @intCast(r[0]), .big);
        std.mem.writeInt(u16, t[o + 16 ..][0..2], @intCast(r[1]), .big);
        std.mem.writeInt(u32, t[o + 20 ..][0..4], r[2], .little);
    }
    try std.testing.expectEqual(@as(?u32, 222), ownerIn(&t, false, false, 50001, 443));
    try std.testing.expectEqual(@as(?u32, null), ownerIn(&t, false, false, 50001, 80));
    // UDP rows: local addr, local port, pid
    var u: [4 + 12]u8 = @splat(0);
    std.mem.writeInt(u32, u[0..4], 1, .little);
    std.mem.writeInt(u16, u[8..10], 5353, .big);
    std.mem.writeInt(u32, u[12..16], 777, .little);
    try std.testing.expectEqual(@as(?u32, 777), ownerIn(&u, true, false, 5353, 0));
}

test "identities are lower case" {
    var out: [64]u8 = undefined;
    const wide = std.unicode.utf8ToUtf16LeStringLiteral("C:\\Program Files\\App\\App.EXE");
    try std.testing.expectEqualStrings("c:\\program files\\app\\app.exe", identity(wide, &out).?);
}
