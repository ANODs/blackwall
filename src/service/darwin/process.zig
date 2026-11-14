//! Which application owns a flow seen on the TUN (macOS).
//!
//! The kernel's socket tables (sysctl net.inet.{tcp,udp}.pcblist_n) are
//! readable by any user and carry each socket's addresses and the pids that
//! use it; proc_pidpath turns a pid into an executable path, also without
//! root. The records are private xnu structs packed to 4 bytes, so they are
//! parsed by byte offset (verified on macOS 26.6 arm64), never through an
//! `extern struct`, whose natural alignment would shift the 64-bit fields.

const std = @import("std");
const builtin = @import("builtin");
const c = std.c;

extern "c" fn proc_pidpath(pid: c.pid_t, buf: [*]u8, size: u32) c_int;
extern "c" fn proc_pidinfo(pid: c.pid_t, flavor: c_int, arg: u64, buffer: ?*anyopaque, size: c_int) c_int;

/// PROC_PIDTBSDINFO and the part of struct proc_bsdinfo used here
/// (bsd/sys/proc_info.h): the parent's pid.
const proc_pidtbsdinfo = 3;
const bsdinfo_len = 136;
const pbi_ppid = 16;
/// How far up the process tree a flow's owner is followed, and the room
/// for the identities found there.
const ancestors_max = 8;
const chain_max = 2048;

/// Longest path proc_pidpath returns (PROC_PIDPATHINFO_MAXSIZE; it refuses
/// buffers below 1024 or above 4096 bytes).
const path_max = 4096;

/// Cached answers live this long; a local port is rarely reused sooner.
const cache_ttl_ns = std.time.ns_per_s;
const cache_slots = 128;
/// The tables are a few hundred KiB with ~1000 sockets; refuse absurd sizes.
const table_max = 32 << 20;

/// Record kinds and field offsets of the pcblist_n stream (xnu
/// bsd/netinet/in_pcb.h, bsd/sys/socketvar.h, bsd/netinet/tcp_var.h).
const xinpgen_len = 24;
const xso_socket = 0x001;
const xso_inpcb = 0x010;
const xso_tcpcb = 0x020;
const inp_fport = 16; // network order
const inp_lport = 18; // network order
const inp_vflag = 44;
const inp_faddr = 48; // 16 bytes; IPv4 sits in the last 4
const inp_laddr = 64;
const inp_min_len = inp_laddr + 16;
const so_last_pid = 68;
const so_e_pid = 72;
const so_min_len = so_e_pid + 4;
const tcp_t_state = 36;
const tcp_min_len = tcp_t_state + 4;
const vflag_ipv4 = 0x1;
const vflag_ipv6 = 0x2;
const tcps_closed = 0;
const tcps_listen = 1;
const tcps_time_wait = 10;

/// Private libquarantine SPI: the app a helper process runs on behalf of.
const ResponsibleFn = *const fn (c.pid_t) callconv(.c) c.pid_t;

pub const Searcher = struct {
    gpa: std.mem.Allocator,
    lock: c.os_unfair_lock = .{},
    /// one sysctl buffer for both tables, grown on demand
    buf: []u8 = &.{},
    /// which table `buf` holds, how much of it, and when it was fetched
    held: ?struct { udp: bool, len: usize, at: u64 } = null,
    cache: [cache_slots]Entry = @splat(.{}),
    responsible: ?ResponsibleFn,

    const Entry = struct {
        q: Query = undefined,
        /// matched the remote end too; otherwise any remote shares the answer
        exact: bool = false,
        at: u64 = 0,
        id: []u8 = &.{},
    };

    pub fn init(gpa: std.mem.Allocator) Searcher {
        // RTLD_DEFAULT is (void *)-2 on Darwin
        const sym = c.dlsym(@ptrFromInt(@as(usize, @bitCast(@as(isize, -2)))), "responsibility_get_pid_responsible_for_pid");
        return .{ .gpa = gpa, .responsible = @ptrCast(@alignCast(sym)) };
    }

    pub fn deinit(s: *Searcher) void {
        for (&s.cache) |*e| s.gpa.free(e.id);
        s.gpa.free(s.buf);
        s.* = undefined;
    }

    /// Owner of a flow seen on the TUN. local = the application's end (source of its packets), remote = its destination.
    /// Addresses are 16 bytes; IPv4 uses the IPv4-mapped form ::ffff:a.b.c.d. Ports in host order.
    /// Writes a stable identity into buf: the OUTERMOST ".app" bundle path if the executable lives inside one
    /// (so helpers like ".../Google Chrome.app/Contents/Frameworks/.../Google Chrome Helper.app/..." map to ".../Google Chrome.app"),
    /// otherwise the executable path. Returns null when unknown (or when buf is too short for it).
    pub fn find(s: *Searcher, udp: bool, local_addr: [16]u8, local_port: u16, remote_addr: [16]u8, remote_port: u16, buf: []u8) ?[]u8 {
        const q: Query = .{ .udp = udp, .laddr = local_addr, .lport = local_port, .raddr = remote_addr, .rport = remote_port };
        // A table fetched after this moment surely lists the flow's socket,
        // so concurrent misses can share one fetch.
        const asked = now();
        c.os_unfair_lock_lock(&s.lock);
        defer c.os_unfair_lock_unlock(&s.lock);

        if (s.cached(q, asked)) |id| return copyOut(id, buf);
        const hit = s.search(q, asked) orelse return null;
        var path: [path_max]u8 = undefined;
        const owner = s.identity(hit.pcb, &path) orelse return null;
        var chain_buf: [chain_max]u8 = undefined;
        const chain = s.withAncestors(owner.id, owner.pid, &chain_buf);
        s.remember(q, hit.exact, chain);
        return copyOut(chain, buf);
    }

    /// `id`, then the identities of the applications that started the
    /// process, nearest first, each after a 0 byte: a tool run by a shell
    /// run by an application follows that application's rule when it has
    /// none of its own, and so does a new version of a program installed
    /// under another path. Stops at launchd, which starts everything.
    fn withAncestors(s: *Searcher, id: []const u8, pid: c.pid_t, out: *[chain_max]u8) []const u8 {
        if (id.len > out.len) return id;
        @memcpy(out[0..id.len], id);
        var len = id.len;
        var last: []const u8 = out[0..len];
        var p = pid;
        var path: [path_max]u8 = undefined;
        for (0..ancestors_max) |_| {
            p = parentOf(p) orelse break;
            const up = s.appPath(p, &path) orelse continue;
            if (std.mem.eql(u8, up, last)) continue;
            if (len + 1 + up.len > out.len) break;
            out[len] = 0;
            @memcpy(out[len + 1 ..][0..up.len], up);
            last = out[len + 1 ..][0..up.len];
            len += 1 + up.len;
        }
        return out[0..len];
    }

    fn cached(s: *Searcher, q: Query, t: u64) ?[]const u8 {
        for (&s.cache) |*e| {
            if (e.id.len == 0 or t -| e.at >= cache_ttl_ns) continue;
            if (e.q.udp != q.udp or e.q.lport != q.lport or !std.mem.eql(u8, &e.q.laddr, &q.laddr)) continue;
            if (e.exact and (e.q.rport != q.rport or !std.mem.eql(u8, &e.q.raddr, &q.raddr))) continue;
            return e.id;
        }
        return null;
    }

    /// Store in the slot of the same flow, else an expired one, else the oldest.
    fn remember(s: *Searcher, q: Query, exact: bool, id: []const u8) void {
        const t = now();
        var slot = &s.cache[0];
        for (&s.cache) |*e| {
            if (e.id.len == 0 or t -| e.at >= cache_ttl_ns or std.meta.eql(e.q, q)) {
                slot = e;
                break;
            }
            if (e.at < slot.at) slot = e;
        }
        const copy = s.gpa.dupe(u8, id) catch return;
        s.gpa.free(slot.id);
        slot.* = .{ .q = q, .exact = exact, .at = t, .id = copy };
    }

    /// Best socket for the flow in a table no older than `asked`.
    fn search(s: *Searcher, q: Query, asked: u64) ?Match {
        const fresh = if (s.held) |h| h.udp == q.udp and h.at >= asked else false;
        if (!fresh and !s.fetch(q.udp)) return null;
        return best(s.buf[0..s.held.?.len], q);
    }

    fn fetch(s: *Searcher, udp: bool) bool {
        s.held = null;
        const name = if (udp) "net.inet.udp.pcblist_n" else "net.inet.tcp.pcblist_n";
        const at = now();
        // The table can grow between sizing and reading (ENOMEM): resize and retry.
        for (0..5) |_| {
            if (s.buf.len > 0) {
                var len = s.buf.len;
                const rc = c.sysctlbyname(name, s.buf.ptr, &len, null, 0);
                if (rc == 0) {
                    s.held = .{ .udp = udp, .len = len, .at = at };
                    return true;
                }
                if (c.errno(rc) != .NOMEM) return false;
            }
            var need: usize = 0;
            if (c.sysctlbyname(name, null, &need, null, 0) != 0 or need > table_max) return false;
            s.gpa.free(s.buf);
            s.buf = s.gpa.alloc(u8, @min(table_max, @max(need, s.buf.len + s.buf.len / 4))) catch {
                s.buf = &.{};
                return false;
            };
        }
        return false;
    }

    const Owner = struct { id: []const u8, pid: c.pid_t };

    /// The owner's app; the last user's when the delegating owner is gone.
    fn identity(s: *Searcher, p: Pcb, out: *[path_max]u8) ?Owner {
        const o = p.owner();
        if (o > 0) if (s.appPath(o, out)) |id| return .{ .id = id, .pid = o };
        if (o != p.last_pid and p.last_pid > 0) {
            if (s.appPath(p.last_pid, out)) |id| return .{ .id = id, .pid = p.last_pid };
        }
        return null;
    }

    fn appPath(s: *Searcher, pid: c.pid_t, out: *[path_max]u8) ?[]const u8 {
        const path = pidPath(pid, out) orelse return null;
        if (bundleOf(path)) |b| return b;
        if (std.mem.indexOf(u8, path, ".xpc/") == null) return path;
        // XPC services of system frameworks (WebKit networking and the like)
        // live outside any bundle; name the app they work for instead.
        const responsible = s.responsible orelse return path;
        const rpid = responsible(pid);
        if (rpid <= 0 or rpid == pid) return path;
        var tmp: [path_max]u8 = undefined;
        const b = bundleOf(pidPath(rpid, &tmp) orelse return path) orelse return path;
        @memcpy(out[0..b.len], b);
        return out[0..b.len];
    }
};

const Query = struct {
    udp: bool,
    laddr: [16]u8,
    lport: u16,
    raddr: [16]u8,
    rport: u16,

    fn isV4(q: Query) bool {
        return isMapped(&q.laddr);
    }
};

/// One socket of the table, as far as attribution needs it.
const Pcb = struct {
    vflag: u8,
    lport: u16,
    fport: u16,
    laddr: [16]u8,
    faddr: [16]u8,
    last_pid: c.pid_t = 0,
    e_pid: c.pid_t = 0,
    /// TCP state; null for UDP
    state: ?u32 = null,

    /// Addresses in the query's family (IPv4 mapped), or null if the socket
    /// does not speak it. Dual-stack wildcard sockets (vflag 3) speak both.
    fn addrs(p: Pcb, v4: bool) ?struct { [16]u8, [16]u8 } {
        if (v4) {
            if (p.vflag & vflag_ipv4 == 0) return null;
            return .{ mapped(p.laddr[12..16].*), mapped(p.faddr[12..16].*) };
        }
        if (p.vflag & vflag_ipv6 == 0) return null;
        return .{ p.laddr, p.faddr };
    }

    /// The delegating app when the socket is used on its behalf (a pid other
    /// than the last user), otherwise the process that last used it. UUID
    /// delegation (mDNSResponder, NECP) copies last_pid into e_pid, so those
    /// sockets name the daemon.
    fn owner(p: Pcb) c.pid_t {
        return if (p.e_pid > 0 and p.e_pid != p.last_pid) p.e_pid else p.last_pid;
    }

    /// Old sockets of a reused 4-tuple linger in TIME_WAIT next to the new one.
    fn live(p: Pcb) bool {
        const st = p.state orelse return true;
        return st != tcps_closed and st != tcps_listen and st != tcps_time_wait;
    }
};

const Match = struct { pcb: Pcb, exact: bool };

/// How well a socket fits the flow, 0 for not at all. TCP needs the full
/// 4-tuple; UDP also accepts unconnected sockets (no remote) and wildcard
/// local addresses, preferring the more specific ones.
fn score(p: Pcb, q: Query) u8 {
    if (p.lport != q.lport) return 0;
    const v4 = q.isV4();
    const laddr, const faddr = p.addrs(v4) orelse return 0;
    const l_exact = std.mem.eql(u8, &laddr, &q.laddr);
    const r_exact = p.fport == q.rport and std.mem.eql(u8, &faddr, &q.raddr);
    if (!q.udp and !(l_exact and r_exact)) return 0;
    if (!l_exact and !isAny(&laddr, v4)) return 0;
    if (!r_exact and !(p.fport == 0 and isAny(&faddr, v4))) return 0;
    const fit: u8 = 1 + @as(u8, if (r_exact) 4 else 0) + @as(u8, if (l_exact) 2 else 0);
    return fit * 4 + @as(u8, if (p.live()) 2 else 0) + @as(u8, if (p.last_pid > 0) 1 else 0);
}

/// The best-fitting socket, or null when none fits or equally good sockets
/// of different processes share the port (SO_REUSEPORT): guessing could
/// route one app's traffic by another's rules.
fn best(table: []const u8, q: Query) ?Match {
    var top: ?Pcb = null;
    var top_score: u8 = 0;
    var shared = false;
    var it: Iterator = .init(table);
    while (it.next()) |p| {
        const sc = score(p, q);
        if (sc > top_score) {
            top = p;
            top_score = sc;
            shared = false;
        } else if (sc > 0 and sc == top_score and p.owner() != top.?.owner()) {
            shared = true;
        }
    }
    if (shared) return null;
    const p = top orelse return null;
    return .{ .pcb = p, .exact = top_score >= (1 + 4) * 4 };
}

/// Walks the pcblist_n stream: a 24-byte header, per socket a run of
/// records each starting with u32 len and u32 kind (8-byte aligned, the
/// socket's xinpcb_n first), then a 24-byte trailer. Walking by kind and
/// length keeps working when xnu grows a struct.
const Iterator = struct {
    b: []const u8,
    off: usize,

    fn init(b: []const u8) Iterator {
        if (b.len < xinpgen_len) return .{ .b = b, .off = b.len };
        return .{ .b = b, .off = std.mem.alignForward(usize, rd(u32, b, 0), 8) };
    }

    fn next(it: *Iterator) ?Pcb {
        var cur: ?Pcb = null;
        while (it.off + 8 <= it.b.len) {
            const len = rd(u32, it.b, it.off);
            const kind = rd(u32, it.b, it.off + 4);
            if (len == xinpgen_len and it.off + len == it.b.len) break;
            if (len < 8 or it.off + len > it.b.len) break;
            const rec = it.b[it.off..][0..len];
            if (kind == xso_inpcb) {
                // the next socket's xinpcb_n ends this one; a malformed one is skipped
                if (cur) |p| return p;
                cur = parseInpcb(rec);
            } else if (cur) |*p| switch (kind) {
                xso_socket => if (len >= so_min_len) {
                    p.last_pid = rd(i32, rec, so_last_pid);
                    p.e_pid = rd(i32, rec, so_e_pid);
                },
                xso_tcpcb => if (len >= tcp_min_len) {
                    p.state = rd(u32, rec, tcp_t_state);
                },
                else => {},
            };
            it.off += std.mem.alignForward(usize, len, 8);
        }
        it.off = it.b.len;
        return cur;
    }
};

fn parseInpcb(rec: []const u8) ?Pcb {
    if (rec.len < inp_min_len) return null;
    return .{
        .vflag = rec[inp_vflag],
        .lport = std.mem.readInt(u16, rec[inp_lport..][0..2], .big),
        .fport = std.mem.readInt(u16, rec[inp_fport..][0..2], .big),
        .laddr = rec[inp_laddr..][0..16].*,
        .faddr = rec[inp_faddr..][0..16].*,
    };
}

/// Host-order field (pids, lengths, kinds); the kernel writes native endianness.
fn rd(comptime T: type, b: []const u8, off: usize) T {
    return std.mem.readInt(T, b[off..][0..@sizeOf(T)], builtin.cpu.arch.endian());
}

/// The outermost ".app" bundle in `path`: the first "/X.app/" component, so
/// helpers nested in an app map to that app (".appex/" does not match).
fn bundleOf(path: []const u8) ?[]const u8 {
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, path, from, ".app/")) |i| : (from = i + 5) {
        if (i > 0 and path[i - 1] != '/') return path[0 .. i + 4];
    }
    return null;
}

fn pidPath(pid: c.pid_t, out: *[path_max]u8) ?[]const u8 {
    const n = proc_pidpath(pid, out, path_max);
    if (n <= 0) return null;
    return withoutCryptex(out[0..@intCast(n)]);
}

/// System apps run from cryptexes; dropping the
/// /System/Volumes/Preboot/Cryptexes/{App,OS} prefix gives the path users
/// know (/System/Applications/Safari.app) and survives OS updates.
fn withoutCryptex(path: []const u8) []const u8 {
    const prefix = "/System/Volumes/Preboot/Cryptexes/";
    if (!std.mem.startsWith(u8, path, prefix)) return path;
    const i = std.mem.indexOfScalarPos(u8, path, prefix.len, '/') orelse return path;
    return path[i..];
}

/// The parent of `pid`; null for launchd's children and processes that are gone.
fn parentOf(pid: c.pid_t) ?c.pid_t {
    var info: [bsdinfo_len]u8 align(8) = undefined;
    if (proc_pidinfo(pid, proc_pidtbsdinfo, 0, &info, bsdinfo_len) != bsdinfo_len) return null;
    const ppid = rd(i32, &info, pbi_ppid);
    return if (ppid > 1) ppid else null;
}

/// Copy an identity chain; what does not fit is left off from the far end
/// (the flow's own identity comes first and matters most).
fn copyOut(chain: []const u8, buf: []u8) ?[]u8 {
    var len = chain.len;
    while (len > buf.len) len = std.mem.lastIndexOfScalar(u8, chain[0..len], 0) orelse return null;
    @memcpy(buf[0..len], chain[0..len]);
    return buf[0..len];
}

fn now() u64 {
    var ts: c.timespec = undefined;
    _ = c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

const v4_prefix = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

fn mapped(v4: [4]u8) [16]u8 {
    return v4_prefix ++ v4;
}

fn isMapped(a: *const [16]u8) bool {
    return std.mem.eql(u8, a[0..12], &v4_prefix);
}

fn isAny(a: *const [16]u8, v4: bool) bool {
    return std.mem.allEqual(u8, if (v4) a[12..16] else a[0..], 0);
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "bundle path is the outermost .app" {
    const chrome = "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/1/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)";
    try testing.expectEqualStrings("/Applications/Google Chrome.app", bundleOf(chrome).?);
    try testing.expectEqualStrings("/Applications/Telegram.app", bundleOf("/Applications/Telegram.app/Contents/MacOS/Telegram").?);
    try testing.expectEqual(null, bundleOf("/usr/bin/curl"));
    try testing.expectEqual(null, bundleOf("/Applications/X.app")); // the bundle itself is no executable
    try testing.expectEqual(null, bundleOf("/Library/Ext/Foo.appex/Contents/MacOS/Foo"));
    try testing.expectEqual(null, bundleOf("/opt/.app/bin/tool")); // no bundle name
    try testing.expectEqualStrings("/A.app", bundleOf("/A.app/Contents/PlugIns/B.appex/Contents/MacOS/B").?);
    try testing.expectEqualStrings("/opt/.app/C.app", bundleOf("/opt/.app/C.app/Contents/MacOS/C").?);
}

test "cryptex prefix is dropped from system paths" {
    const safari = "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari";
    try testing.expectEqualStrings("/System/Applications/Safari.app", bundleOf(withoutCryptex(safari)).?);
    const webkit = "/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking";
    try testing.expect(std.mem.startsWith(u8, withoutCryptex(webkit), "/System/Library/Frameworks/WebKit.framework/"));
    try testing.expectEqualStrings("/usr/bin/curl", withoutCryptex("/usr/bin/curl"));
}

/// A synthetic pcblist_n stream laid out like xnu's: header, groups, trailer.
const TestTable = struct {
    bytes: [2 * xinpgen_len + 4 * 616]u8 = @splat(0),
    len: usize = xinpgen_len,

    const Sock = struct {
        vflag: u8 = vflag_ipv4,
        laddr: [16]u8,
        lport: u16,
        faddr: [16]u8,
        fport: u16,
        last_pid: i32,
        e_pid: i32 = 0,
        state: ?u32 = null,
    };

    fn put(t: *TestTable, comptime T: type, off: usize, v: T) void {
        std.mem.writeInt(T, t.bytes[off..][0..@sizeOf(T)], v, builtin.cpu.arch.endian());
    }

    fn record(t: *TestTable, kind: u32, len: u32) usize {
        const off = t.len;
        t.put(u32, off, len);
        t.put(u32, off + 4, kind);
        t.len += std.mem.alignForward(usize, len, 8);
        return off;
    }

    fn add(t: *TestTable, s: Sock) void {
        const inp = t.record(xso_inpcb, 104);
        std.mem.writeInt(u16, t.bytes[inp + inp_lport ..][0..2], s.lport, .big);
        std.mem.writeInt(u16, t.bytes[inp + inp_fport ..][0..2], s.fport, .big);
        t.bytes[inp + inp_vflag] = s.vflag;
        // IPv4 in the kernel's in_addr_4in6 form: zero pad, address last
        const v4 = s.vflag & vflag_ipv4 != 0;
        const pad: [12]u8 = @splat(0);
        const l = if (v4) pad ++ s.laddr[12..16].* else s.laddr;
        const f = if (v4) pad ++ s.faddr[12..16].* else s.faddr;
        @memcpy(t.bytes[inp + inp_laddr ..][0..16], &l);
        @memcpy(t.bytes[inp + inp_faddr ..][0..16], &f);
        const so = t.record(xso_socket, 104);
        t.put(i32, so + so_last_pid, s.last_pid);
        t.put(i32, so + so_e_pid, s.e_pid);
        _ = t.record(0x002, 32);
        _ = t.record(0x004, 32);
        _ = t.record(0x008, 136);
        if (s.state) |st| t.put(u32, t.record(xso_tcpcb, 204) + tcp_t_state, st);
    }

    fn finish(t: *TestTable) []const u8 {
        t.put(u32, 0, xinpgen_len);
        // the trailer's second word is a count, not a kind
        _ = t.record(7, xinpgen_len);
        return t.bytes[0..t.len];
    }
};

const lo4 = mapped(.{ 127, 0, 0, 1 });
const dst4 = mapped(.{ 1, 1, 1, 1 });
const any4 = mapped(.{ 0, 0, 0, 0 });

test "parser walks groups by kind and length" {
    var t: TestTable = .{};
    t.add(.{ .laddr = lo4, .lport = 50000, .faddr = dst4, .fport = 443, .last_pid = 11, .e_pid = 22, .state = 4 });
    var v6: [16]u8 = @splat(0);
    v6[15] = 1;
    // a truncated xinpcb_n and its socket record: skipped, the walk goes on
    _ = t.record(xso_inpcb, 40);
    t.put(i32, t.record(xso_socket, 104) + so_last_pid, 99);
    t.add(.{ .vflag = vflag_ipv6, .laddr = v6, .lport = 5353, .faddr = @splat(0), .fport = 0, .last_pid = 33 });
    const table = t.finish();
    try testing.expectEqual(2 * xinpgen_len + 616 + 40 + 104 + 408, table.len);

    var it: Iterator = .init(table);
    const a = it.next().?;
    try testing.expectEqual(50000, a.lport);
    try testing.expectEqual(443, a.fport);
    try testing.expectEqual(11, a.last_pid);
    try testing.expectEqual(22, a.e_pid);
    try testing.expectEqual(4, a.state.?);
    try testing.expectEqualSlices(u8, &lo4, &a.addrs(true).?[0]);
    try testing.expectEqual(null, a.addrs(false));
    const b = it.next().?;
    try testing.expectEqual(5353, b.lport);
    try testing.expectEqual(33, b.last_pid);
    try testing.expectEqual(null, b.state);
    try testing.expectEqualSlices(u8, &v6, &b.addrs(false).?[0]);
    try testing.expectEqual(null, it.next());
    // truncated input stops cleanly
    var cut: Iterator = .init(table[0 .. xinpgen_len + 100]);
    while (cut.next()) |_| {}
}

test "match prefers live tcp sockets and specific udp ones" {
    var t: TestTable = .{};
    // a reused 4-tuple: the old socket in TIME_WAIT, the new one connecting
    t.add(.{ .laddr = lo4, .lport = 50000, .faddr = dst4, .fport = 443, .last_pid = 1, .state = tcps_time_wait });
    t.add(.{ .laddr = lo4, .lport = 50000, .faddr = dst4, .fport = 443, .last_pid = 2, .state = 2 });
    // udp on one port: a wildcard socket and one bound to the local address
    t.add(.{ .laddr = any4, .lport = 6000, .faddr = any4, .fport = 0, .last_pid = 3 });
    t.add(.{ .laddr = lo4, .lport = 6000, .faddr = any4, .fport = 0, .last_pid = 4 });
    const table = t.finish();

    const tcp = best(table, .{ .udp = false, .laddr = lo4, .lport = 50000, .raddr = dst4, .rport = 443 }).?;
    try testing.expectEqual(2, tcp.pcb.last_pid);
    try testing.expect(tcp.exact);
    // TCP never matches on the port alone
    try testing.expectEqual(null, best(table, .{ .udp = false, .laddr = lo4, .lport = 50000, .raddr = dst4, .rport = 80 }));

    const udp = best(table, .{ .udp = true, .laddr = lo4, .lport = 6000, .raddr = dst4, .rport = 53 }).?;
    try testing.expectEqual(4, udp.pcb.last_pid);
    try testing.expect(!udp.exact);
    const other = best(table, .{ .udp = true, .laddr = mapped(.{ 10, 0, 0, 2 }), .lport = 6000, .raddr = dst4, .rport = 53 }).?;
    try testing.expectEqual(3, other.pcb.last_pid);
}

test "a port shared by different processes has no owner" {
    var t: TestTable = .{};
    // SO_REUSEPORT: two sockets of one process are fine, a third app is not
    t.add(.{ .laddr = any4, .lport = 5353, .faddr = any4, .fport = 0, .last_pid = 5 });
    t.add(.{ .laddr = any4, .lport = 5353, .faddr = any4, .fport = 0, .last_pid = 5 });
    const one = t.finish();
    const q: Query = .{ .udp = true, .laddr = lo4, .lport = 5353, .raddr = dst4, .rport = 5353 };
    try testing.expectEqual(5, best(one, q).?.pcb.last_pid);

    t = .{};
    t.add(.{ .laddr = any4, .lport = 5353, .faddr = any4, .fport = 0, .last_pid = 5 });
    t.add(.{ .laddr = any4, .lport = 5353, .faddr = any4, .fport = 0, .last_pid = 6 });
    try testing.expectEqual(null, best(t.finish(), q));
    // a more specific socket still decides
    t.len -= xinpgen_len;
    t.add(.{ .laddr = lo4, .lport = 5353, .faddr = any4, .fport = 0, .last_pid = 7 });
    try testing.expectEqual(7, best(t.finish(), q).?.pcb.last_pid);
}

test "a delegated socket belongs to the app it works for" {
    const base: Pcb = .{ .vflag = vflag_ipv4, .lport = 1, .fport = 2, .laddr = lo4, .faddr = dst4 };
    var p = base;
    p.last_pid = 413; // trustd for syspolicyd
    p.e_pid = 506;
    try testing.expectEqual(506, p.owner());
    p.e_pid = 413; // UUID delegation copies last_pid: only the daemon is known
    try testing.expectEqual(413, p.owner());
    p.e_pid = 0;
    try testing.expectEqual(413, p.owner());
    p.last_pid = 0; // in-kernel socket
    try testing.expectEqual(0, p.owner());
}

test "dual-stack wildcard udp socket matches both families" {
    var t: TestTable = .{};
    t.add(.{ .vflag = vflag_ipv4 | vflag_ipv6, .laddr = @splat(0), .lport = 7000, .faddr = @splat(0), .fport = 0, .last_pid = 9 });
    const table = t.finish();
    var v6: [16]u8 = @splat(0);
    v6[0] = 0xfd;
    try testing.expectEqual(9, best(table, .{ .udp = true, .laddr = lo4, .lport = 7000, .raddr = dst4, .rport = 53 }).?.pcb.last_pid);
    try testing.expectEqual(9, best(table, .{ .udp = true, .laddr = v6, .lport = 7000, .raddr = v6, .rport = 53 }).?.pcb.last_pid);
}

const Sockaddr4 = c.sockaddr.in;

fn loopback(port: u16) Sockaddr4 {
    return .{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
}

fn localPort(fd: c.fd_t) !u16 {
    var sa: Sockaddr4 = undefined;
    var len: c.socklen_t = @sizeOf(Sockaddr4);
    if (c.getsockname(fd, @ptrCast(&sa), &len) != 0) return error.GetSockName;
    return std.mem.bigToNative(u16, sa.port);
}

/// What find() should report for sockets of this test process.
fn selfIdentity(out: *[path_max]u8) ![]const u8 {
    const path = pidPath(c.getpid(), out) orelse return error.NoPath;
    return bundleOf(path) orelse path;
}

test "finds this process for a loopback tcp connection" {
    var self: [path_max]u8 = undefined;
    const want = try selfIdentity(&self);

    const ls = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    try testing.expect(ls >= 0);
    defer _ = c.close(ls);
    var sa = loopback(0);
    try testing.expectEqual(0, c.bind(ls, @ptrCast(&sa), @sizeOf(Sockaddr4)));
    try testing.expectEqual(0, c.listen(ls, 4));
    const sport = try localPort(ls);

    const cs = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    try testing.expect(cs >= 0);
    defer _ = c.close(cs);
    sa = loopback(sport);
    try testing.expectEqual(0, c.connect(cs, @ptrCast(&sa), @sizeOf(Sockaddr4)));
    const cport = try localPort(cs);
    const as = c.accept(ls, null, null);
    try testing.expect(as >= 0);
    defer _ = c.close(as);

    var s: Searcher = .init(testing.allocator);
    defer s.deinit();
    var buf: [path_max]u8 = undefined;
    try testing.expectEqualStrings(want, own(s.find(false, lo4, cport, lo4, sport, &buf).?));
    // the second answer comes from the cache
    try testing.expectEqualStrings(want, own(s.find(false, lo4, cport, lo4, sport, &buf).?));
    // a buffer too small for the identity gives no answer rather than a cut one
    var small: [4]u8 = undefined;
    try testing.expectEqual(null, s.find(false, lo4, cport, lo4, sport, &small));
    // nobody owns this flow
    try testing.expectEqual(null, s.find(false, lo4, cport, lo4, sport +% 1, &buf));
}

test "finds this process for connected and unconnected udp sockets" {
    var self: [path_max]u8 = undefined;
    const want = try selfIdentity(&self);
    var s: Searcher = .init(testing.allocator);
    defer s.deinit();
    var buf: [path_max]u8 = undefined;

    const us = c.socket(c.AF.INET, c.SOCK.DGRAM, 0);
    try testing.expect(us >= 0);
    defer _ = c.close(us);
    var sa = loopback(9);
    try testing.expectEqual(0, c.connect(us, @ptrCast(&sa), @sizeOf(Sockaddr4)));
    const uport = try localPort(us);
    try testing.expectEqualStrings(want, own(s.find(true, lo4, uport, lo4, 9, &buf).?));

    // bound but unconnected: any destination from that port is ours
    const bs = c.socket(c.AF.INET, c.SOCK.DGRAM, 0);
    try testing.expect(bs >= 0);
    defer _ = c.close(bs);
    sa = loopback(0);
    try testing.expectEqual(0, c.bind(bs, @ptrCast(&sa), @sizeOf(Sockaddr4)));
    const bport = try localPort(bs);
    try testing.expectEqualStrings(want, own(s.find(true, lo4, bport, dst4, 53, &buf).?));
    try testing.expectEqualStrings(want, own(s.find(true, lo4, bport, mapped(.{ 8, 8, 8, 8 }), 53, &buf).?));
}

test "concurrent lookups share the searcher" {
    var self: [path_max]u8 = undefined;
    const want = try selfIdentity(&self);
    const us = c.socket(c.AF.INET, c.SOCK.DGRAM, 0);
    try testing.expect(us >= 0);
    defer _ = c.close(us);
    var sa = loopback(9);
    try testing.expectEqual(0, c.connect(us, @ptrCast(&sa), @sizeOf(Sockaddr4)));
    const uport = try localPort(us);

    var s: Searcher = .init(testing.allocator);
    defer s.deinit();
    const Worker = struct {
        fn run(sr: *Searcher, port: u16, expect: []const u8, ok: *std.atomic.Value(u32)) void {
            var b: [path_max]u8 = undefined;
            for (0..50) |i| {
                // alternate tables so the shared buffer is refetched under contention
                const id = if (i % 2 == 0) sr.find(true, lo4, port, lo4, 9, &b) else sr.find(false, lo4, port, lo4, 9, &b);
                if (i % 2 == 0 and id != null and std.mem.eql(u8, own(id.?), expect)) _ = ok.fetchAdd(1, .monotonic);
            }
        }
    };
    var ok: std.atomic.Value(u32) = .init(0);
    var threads: [6]std.Thread = undefined;
    for (&threads) |*th| th.* = try std.Thread.spawn(.{}, Worker.run, .{ &s, uport, want, &ok });
    for (threads) |th| th.join();
    try testing.expectEqual(6 * 25, ok.load(.monotonic));
}

/// The flow's own identity: the first of the chain `find` returns.
fn own(chain: []const u8) []const u8 {
    return chain[0 .. std.mem.indexOfScalar(u8, chain, 0) orelse chain.len];
}

test "the parent of this process, and an identity chain that names it" {
    try testing.expectEqual(@as(?c.pid_t, c.getppid()), parentOf(c.getpid()));
    try testing.expect(parentOf(1) == null);
    var s: Searcher = .init(testing.allocator);
    defer s.deinit();
    var path: [path_max]u8 = undefined;
    var me_buf: [path_max]u8 = undefined;
    const me = s.appPath(c.getpid(), &me_buf).?;
    var out: [chain_max]u8 = undefined;
    const chain = s.withAncestors(me, c.getpid(), &out);
    try testing.expect(std.mem.startsWith(u8, chain, me));
    // whoever runs the tests (zig, a shell) follows, unless it is this very program
    if (s.appPath(c.getppid(), &path)) |up| {
        if (!std.mem.eql(u8, up, me)) try testing.expect(std.mem.indexOf(u8, chain, up) != null);
    }
    // a short buffer keeps the nearest identities whole
    var small: [8]u8 = undefined;
    try testing.expectEqualStrings("/a/b", copyOut("/a/b\x00/c/d/e", &small).?);
    try testing.expect(copyOut("/a/b/c/d/e/f", &small) == null);
}
