//! DNS for the TUN.
//!
//! Applications resolve names through us. An A query gets an address from
//! 198.18.0.0/15 that stands for the name ("fake IP"), so the connection that
//! follows carries the domain to the outbound: the server resolves it, rules
//! can match it, and no query leaves the machine in clear text. AAAA and
//! HTTPS/SVCB get empty answers so clients settle on the IPv4 fake address.
//! Everything else, and names on the exclusion list, is forwarded to a real
//! resolver through the physical interface.

const std = @import("std");
const Io = std.Io;
const packet = @import("packet.zig");
const sys = @import("../sys.zig");

pub const type_a: u16 = 1;
pub const type_ptr: u16 = 12;
pub const type_aaaa: u16 = 28;
pub const type_svcb: u16 = 64;
pub const type_https: u16 = 65;

pub const fake_base: u32 = (198 << 24) | (18 << 16); // 198.18.0.0/15
pub const fake_size: u32 = 1 << 17;
/// 198.18.0.1 is the TUN's own address, 198.18.0.2 the DNS server we answer as.
pub const fake_first: u32 = 3;
pub const gateway = [4]u8{ 198, 18, 0, 1 };
pub const server = [4]u8{ 198, 18, 0, 2 };

pub fn isFake(addr: *const packet.Addr) bool {
    if (!packet.isV4(addr)) return false;
    const v = std.mem.readInt(u32, addr[12..16], .big);
    return v -% fake_base < fake_size;
}

/// Names that must keep their real addresses.
pub const default_exclusions = [_][]const u8{
    "local", "localhost", "lan", "home.arpa", "internal", "in-addr.arpa", "ip6.arpa",
    // captive portal and time checks expect real answers
    "captive.apple.com", "time.apple.com", "time.windows.com", "pool.ntp.org", "msftconnecttest.com",
};

/// A fake address goes to another name only after this long unused: well
/// past what applications cache regardless of TTL (Firefox 1-2 min, Java
/// 30 s), so a connection to an address it still holds reaches its name.
pub const fake_grace_s = 10 * 60;

/// Names and the fake addresses standing for them. Addresses are handed out
/// in order while the pool lasts; after that the least recently used one is
/// recycled, and only once it has been unused for `fake_grace_s`. Answering
/// a name and looking an address up both count as use.
pub const FakeIp = struct {
    gpa: std.mem.Allocator,
    io: Io,
    mutex: Io.Mutex = .init,
    by_name: std.StringHashMapUnmanaged(u32) = .empty,
    /// slot i is the address fake_first + i; grows until `capacity`
    slots: std.ArrayList(Slot) = .empty,
    /// recency list through the slots, from `oldest` (next to recycle)
    oldest: u32 = none,
    newest: u32 = none,
    capacity: u32 = fake_size - fake_first,
    /// fixed clock for tests, seconds
    test_now: ?i64 = null,

    const none = std.math.maxInt(u32);
    const Slot = struct {
        name: []u8,
        /// last use, seconds on the awake clock
        used: i64,
        older: u32,
        newer: u32,
    };

    pub fn init(gpa: std.mem.Allocator, io: Io) FakeIp {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn deinit(f: *FakeIp) void {
        for (f.slots.items) |s| f.gpa.free(s.name);
        f.slots.deinit(f.gpa);
        f.by_name.deinit(f.gpa);
    }

    /// Address standing for `name` (lower case, no trailing dot).
    /// error.PoolExhausted: every address was used within the grace period.
    pub fn assign(f: *FakeIp, name: []const u8) error{ OutOfMemory, PoolExhausted }![4]u8 {
        f.mutex.lockUncancelable(f.io);
        defer f.mutex.unlock(f.io);
        const now = f.clock();
        if (f.by_name.get(name)) |i| {
            f.touch(i, now);
            return toAddr(i);
        }
        const fresh = f.slots.items.len < f.capacity;
        if (!fresh and now - f.slots.items[f.oldest].used < fake_grace_s) return error.PoolExhausted;
        try f.by_name.ensureUnusedCapacity(f.gpa, 1);
        if (fresh and f.slots.items.len == f.slots.capacity) {
            const want = std.ArrayList(Slot).growCapacity(f.slots.capacity + 1);
            try f.slots.ensureTotalCapacityPrecise(f.gpa, @min(want, f.capacity));
        }
        const copy = try f.gpa.dupe(u8, name);
        const i: u32 = if (fresh) blk: {
            f.slots.appendAssumeCapacity(.{ .name = copy, .used = now, .older = none, .newer = none });
            break :blk @intCast(f.slots.items.len - 1);
        } else blk: {
            const old = f.oldest;
            f.unlink(old);
            _ = f.by_name.remove(f.slots.items[old].name);
            f.gpa.free(f.slots.items[old].name);
            f.slots.items[old].name = copy;
            break :blk old;
        };
        f.by_name.putAssumeCapacityNoClobber(copy, i);
        f.pushNewest(i, now);
        return toAddr(i);
    }

    /// The name behind a fake address, copied into `buf`.
    pub fn lookup(f: *FakeIp, addr: *const packet.Addr, buf: []u8) ?[]u8 {
        if (!isFake(addr)) return null;
        const off = std.mem.readInt(u32, addr[12..16], .big) - fake_base;
        if (off < fake_first) return null;
        const i = off - fake_first;
        f.mutex.lockUncancelable(f.io);
        defer f.mutex.unlock(f.io);
        if (i >= f.slots.items.len) return null;
        const name = f.slots.items[i].name;
        if (name.len > buf.len) return null;
        f.touch(i, f.clock());
        @memcpy(buf[0..name.len], name);
        return buf[0..name.len];
    }

    /// seconds on the awake clock, which stands still while the machine
    /// sleeps: addresses stay reserved across a sleep
    fn clock(f: *const FakeIp) i64 {
        return f.test_now orelse @intCast(@divTrunc(Io.Clock.awake.now(f.io).nanoseconds, std.time.ns_per_s));
    }

    fn touch(f: *FakeIp, i: u32, now_s: i64) void {
        f.unlink(i);
        f.pushNewest(i, now_s);
    }

    fn unlink(f: *FakeIp, i: u32) void {
        const s = &f.slots.items[i];
        if (s.older == none) f.oldest = s.newer else f.slots.items[s.older].newer = s.newer;
        if (s.newer == none) f.newest = s.older else f.slots.items[s.newer].older = s.older;
    }

    fn pushNewest(f: *FakeIp, i: u32, now_s: i64) void {
        const s = &f.slots.items[i];
        s.used = now_s;
        s.older = f.newest;
        s.newer = none;
        if (f.newest == none) f.oldest = i else f.slots.items[f.newest].newer = i;
        f.newest = i;
    }

    fn toAddr(i: u32) [4]u8 {
        var a: [4]u8 = undefined;
        std.mem.writeInt(u32, &a, fake_base + fake_first + i, .big);
        return a;
    }
};

pub const Question = struct {
    /// lower case, no trailing dot
    name_buf: [255]u8 = undefined,
    name_len: u8 = 0,
    qtype: u16,
    qclass: u16,
    /// offset just past the question in the message
    end: usize,

    pub fn name(q: *const Question) []const u8 {
        return q.name_buf[0..q.name_len];
    }
};

/// The single question of a standard query, or null if the message is not
/// one we answer ourselves.
pub fn parseQuery(msg: []const u8) ?Question {
    if (msg.len < 12) return null;
    const flags = std.mem.readInt(u16, msg[2..4], .big);
    if (flags & 0x8000 != 0) return null; // a response
    if ((flags >> 11) & 0xf != 0) return null; // opcode other than QUERY
    if (std.mem.readInt(u16, msg[4..6], .big) != 1) return null;
    var q: Question = .{ .qtype = 0, .qclass = 0, .end = 0 };
    var i: usize = 12;
    var n: usize = 0;
    while (true) {
        if (i >= msg.len) return null;
        const len = msg[i];
        if (len == 0) {
            i += 1;
            break;
        }
        if (len & 0xc0 != 0) return null; // compression in a question: unusual, forward it
        if (i + 1 + len > msg.len) return null;
        if (n > 0) {
            if (n >= q.name_buf.len) return null;
            q.name_buf[n] = '.';
            n += 1;
        }
        if (n + len > q.name_buf.len) return null;
        for (msg[i + 1 ..][0..len], 0..) |ch, k| q.name_buf[n + k] = std.ascii.toLower(ch);
        n += len;
        i += 1 + len;
    }
    if (i + 4 > msg.len) return null;
    q.name_len = @intCast(n);
    q.qtype = std.mem.readInt(u16, msg[i..][0..2], .big);
    q.qclass = std.mem.readInt(u16, msg[i + 2 ..][0..2], .big);
    q.end = i + 4;
    return q;
}

pub const Record = struct { rtype: u16, ttl: u32, data: []const u8 };

/// Response to `query` with the given answers; returns its length (0 if
/// `out` is too small).
pub fn respond(out: []u8, query: []const u8, q: *const Question, rcode: u4, answers: []const Record) usize {
    var w: std.Io.Writer = .fixed(out);
    const qflags = std.mem.readInt(u16, query[2..4], .big);
    const flags: u16 = 0x8000 | (qflags & 0x7900) | 0x0080 | rcode; // QR, opcode+RD copied, RA
    w.writeAll(query[0..2]) catch return 0;
    w.writeInt(u16, flags, .big) catch return 0;
    w.writeInt(u16, 1, .big) catch return 0;
    w.writeInt(u16, @intCast(answers.len), .big) catch return 0;
    w.writeAll(&.{ 0, 0, 0, 0 }) catch return 0;
    w.writeAll(query[12..q.end]) catch return 0;
    for (answers) |a| {
        w.writeAll(&.{ 0xc0, 0x0c }) catch return 0; // pointer to the question name
        w.writeInt(u16, a.rtype, .big) catch return 0;
        w.writeInt(u16, 1, .big) catch return 0;
        w.writeInt(u32, a.ttl, .big) catch return 0;
        w.writeInt(u16, @intCast(a.data.len), .big) catch return 0;
        w.writeAll(a.data) catch return 0;
    }
    return w.buffered().len;
}

/// Encode a domain name in wire format into `out`.
fn encodeName(out: []u8, name: []const u8) ?usize {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        if (label.len == 0 or label.len > 63 or n + 1 + label.len >= out.len) return null;
        out[n] = @intCast(label.len);
        @memcpy(out[n + 1 ..][0..label.len], label);
        n += 1 + label.len;
    }
    if (n >= out.len) return null;
    out[n] = 0;
    return n + 1;
}

/// "4.3.2.1.in-addr.arpa" -> 1.2.3.4
fn reverseV4(name: []const u8) ?[4]u8 {
    const suffix = ".in-addr.arpa";
    if (!std.mem.endsWith(u8, name, suffix)) return null;
    var parts = std.mem.splitScalar(u8, name[0 .. name.len - suffix.len], '.');
    var a: [4]u8 = undefined;
    var k: usize = 0;
    while (parts.next()) |p| {
        if (k == 4) return null;
        a[3 - k] = std.fmt.parseInt(u8, p, 10) catch return null;
        k += 1;
    }
    return if (k == 4) a else null;
}

pub fn excluded(name: []const u8, extra: []const []const u8) bool {
    for (default_exclusions) |e| if (matchSuffix(name, e)) return true;
    for (extra) |e| if (matchSuffix(name, e)) return true;
    // a single label ("printer") is a local name
    return std.mem.indexOfScalar(u8, name, '.') == null;
}

fn matchSuffix(name: []const u8, suffix: []const u8) bool {
    if (!std.mem.endsWith(u8, name, suffix)) return false;
    return name.len == suffix.len or name[name.len - suffix.len - 1] == '.';
}

pub const Verdict = union(enum) {
    /// answered locally: the response is in the caller's buffer
    answered: usize,
    /// must be sent to a real resolver
    forward,
};

/// Answer what we can ourselves. TTL is short so a reused fake address can
/// never be served from a stale cache. While every fake address is in use,
/// new names are forwarded and get their real addresses.
pub fn answerLocally(fake: *FakeIp, query: []const u8, out: []u8, exclusions: []const []const u8) Verdict {
    const q = parseQuery(query) orelse return .forward;
    if (q.qclass != 1) return .forward;
    const name = q.name();
    switch (q.qtype) {
        type_a => {
            if (excluded(name, exclusions)) return .forward;
            const ip = fake.assign(name) catch return .forward;
            return .{ .answered = respond(out, query, &q, 0, &.{.{ .rtype = type_a, .ttl = 1, .data = &ip }}) };
        },
        type_aaaa, type_https, type_svcb => {
            if (excluded(name, exclusions)) return .forward;
            return .{ .answered = respond(out, query, &q, 0, &.{}) };
        },
        type_ptr => {
            const ip = reverseV4(name) orelse return .forward;
            const addr = packet.v4(ip);
            var nb: [255]u8 = undefined;
            const domain = fake.lookup(&addr, &nb) orelse return .forward;
            var enc: [256]u8 = undefined;
            const len = encodeName(&enc, domain) orelse return .forward;
            return .{ .answered = respond(out, query, &q, 0, &.{.{ .rtype = type_ptr, .ttl = 1, .data = enc[0..len] }}) };
        },
        else => return .forward,
    }
}

/// Real DNS lookups through the physical interface, with a small cache.
///
/// Every dial to a VPN server by name goes through here, so a resolver that
/// stops answering must not stop the VPN: a name is asked for by one
/// thread at a time (the others wait for its answer), a failed lookup is
/// not repeated for a few seconds, the last known address keeps being used
/// while lookups fail, and public resolvers stand in for the network's own.
pub const Resolver = struct {
    gpa: std.mem.Allocator,
    io: Io,
    /// the network's own resolvers (normally port 53)
    servers: []const packet.Endpoint,
    /// asked after `servers`
    fallback: []const packet.Endpoint = &public_servers,
    bind: sys.Bind = .none,
    /// one server's time to answer one attempt
    timeout_ms: i32 = 900,
    mutex: Io.Mutex = .init,
    cond: Io.Condition = .init,
    cache: std.StringHashMapUnmanaged(Entry) = .empty,
    /// the server that answered last is asked first
    good: std.atomic.Value(usize) = .init(0),

    const Entry = struct {
        addr: packet.Addr = @splat(0),
        /// an address was learned at some point (it may have expired)
        known: bool = false,
        expires_ns: i96 = 0,
        /// no new lookup before this: one failed a moment ago
        retry_ns: i96 = 0,
        /// a thread is asking right now
        asking: bool = false,
    };
    /// Applications pick the names (each direct dial to a fake address
    /// resolves one), so the cache is bounded.
    const cache_max = 1024;
    const retry_after_ns = 3 * std.time.ns_per_s;

    pub const public_servers = [_]packet.Endpoint{
        .{ .addr = packet.v4(.{ 8, 8, 8, 8 }), .port = 53 },
        .{ .addr = packet.v4(.{ 1, 1, 1, 1 }), .port = 53 },
        .{ .addr = packet.v4(.{ 9, 9, 9, 9 }), .port = 53 },
    };

    pub fn deinit(r: *Resolver) void {
        var it = r.cache.keyIterator();
        while (it.next()) |k| r.gpa.free(k.*);
        r.cache.deinit(r.gpa);
    }

    fn server(r: *const Resolver, i: usize) packet.Endpoint {
        return if (i < r.servers.len) r.servers[i] else r.fallback[i - r.servers.len];
    }

    /// Send a raw query to the upstream servers and return the response.
    /// Two rounds over all servers, starting with the one that answered last.
    pub fn forward(r: *Resolver, query: []const u8, out: []u8) !usize {
        if (query.len < 2) return error.BadQuery;
        const total = r.servers.len + r.fallback.len;
        if (total == 0) return error.NoAnswer;
        const first = r.good.load(.monotonic) % total;
        for (0..2) |_| {
            for (0..total) |k| {
                const i = (first + k) % total;
                const srv = r.server(i);
                const u = sys.Udp.open(&srv.addr, srv.port, r.bind) catch continue;
                defer u.close();
                u.send(query) catch continue;
                while (true) {
                    const n = u.recv(out, r.timeout_ms) catch break;
                    // answer to this query: same id
                    if (n >= 12 and std.mem.eql(u8, out[0..2], query[0..2])) {
                        r.good.store(i, .monotonic);
                        return n;
                    }
                }
            }
        }
        return error.NoAnswer;
    }

    /// First IPv4 address of `name`.
    pub fn resolve(r: *Resolver, name: []const u8) !packet.Addr {
        var stale: ?packet.Addr = null;
        {
            r.mutex.lockUncancelable(r.io);
            defer r.mutex.unlock(r.io);
            while (true) {
                const now = Io.Clock.awake.now(r.io).nanoseconds;
                const e = r.cache.getPtr(name) orelse break;
                if (e.known and e.expires_ns > now) return e.addr;
                if (e.asking) {
                    // someone asks already: their answer is ours too
                    r.cond.waitUncancelable(r.io, &r.mutex);
                    continue;
                }
                if (e.retry_ns > now) return if (e.known) e.addr else error.NoAnswer;
                if (e.known) stale = e.addr;
                break;
            }
            r.mark(name, true);
        }
        const answer = r.ask(name);

        r.mutex.lockUncancelable(r.io);
        defer r.mutex.unlock(r.io);
        defer r.cond.broadcast(r.io);
        const now = Io.Clock.awake.now(r.io).nanoseconds;
        const e = r.cache.getPtr(name);
        if (e) |x| x.asking = false;
        const addr, const ttl = answer catch |err| {
            if (e) |x| x.retry_ns = now + retry_after_ns;
            // the last known address beats no connection at all
            return stale orelse err;
        };
        if (e) |x| {
            x.addr = addr;
            x.known = true;
            x.expires_ns = now + @as(i96, @max(ttl, 30)) * std.time.ns_per_s;
            x.retry_ns = 0;
        }
        return addr;
    }

    fn ask(r: *Resolver, name: []const u8) !struct { packet.Addr, u32 } {
        var q: [300]u8 = undefined;
        var id: [2]u8 = undefined;
        r.io.random(&id);
        q[0..12].* = .{ id[0], id[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
        const nlen = encodeName(q[12..][0..256], name) orelse return error.BadName;
        std.mem.writeInt(u16, q[12 + nlen ..][0..2], type_a, .big);
        std.mem.writeInt(u16, q[14 + nlen ..][0..2], 1, .big);
        var resp: [1500]u8 = undefined;
        const n = try r.forward(q[0 .. 16 + nlen], &resp);
        return firstA(resp[0..n]) orelse error.NoAddress;
    }

    /// Ask again on the next dial even though the address has not expired
    /// (a server behind a CDN may have moved). The address stays as the
    /// fallback for a lookup that fails.
    pub fn forget(r: *Resolver, name: []const u8) void {
        r.mutex.lockUncancelable(r.io);
        defer r.mutex.unlock(r.io);
        if (r.cache.getPtr(name)) |e| {
            e.expires_ns = 0;
            e.retry_ns = 0;
        }
    }

    /// Note that `name` is being asked for (mutex held), making room when
    /// the cache is full: the entry that expires first goes, never one
    /// another thread is waiting on.
    fn mark(r: *Resolver, name: []const u8, asking: bool) void {
        if (r.cache.getPtr(name)) |v| {
            v.asking = asking;
            return;
        }
        if (r.cache.count() >= cache_max) {
            var it = r.cache.iterator();
            var first: ?@TypeOf(it.next().?) = null;
            while (it.next()) |x| {
                if (x.value_ptr.asking) continue;
                if (first == null or x.value_ptr.expires_ns < first.?.value_ptr.expires_ns) first = x;
            }
            if (first) |f| {
                const key = f.key_ptr.*;
                r.cache.removeByPtr(f.key_ptr);
                r.gpa.free(key);
            }
        }
        const key = r.gpa.dupe(u8, name) catch return;
        r.cache.put(r.gpa, key, .{ .asking = asking }) catch r.gpa.free(key);
    }

    /// Cache an answer (tests).
    fn remember(r: *Resolver, name: []const u8, addr: packet.Addr, expires_ns: i96) void {
        r.mutex.lockUncancelable(r.io);
        defer r.mutex.unlock(r.io);
        r.mark(name, false);
        if (r.cache.getPtr(name)) |e| {
            e.addr = addr;
            e.known = true;
            e.expires_ns = expires_ns;
        }
    }
};

fn skipName(msg: []const u8, start: usize) ?usize {
    var i = start;
    while (i < msg.len) {
        const len = msg[i];
        if (len == 0) return i + 1;
        if (len & 0xc0 == 0xc0) return if (i + 2 <= msg.len) i + 2 else null;
        i += 1 + len;
    }
    return null;
}

/// First A record in the answer section, with its TTL.
pub fn firstA(msg: []const u8) ?struct { packet.Addr, u32 } {
    if (msg.len < 12) return null;
    if (std.mem.readInt(u16, msg[2..4], .big) & 0xf != 0) return null; // rcode
    const qd = std.mem.readInt(u16, msg[4..6], .big);
    const an = std.mem.readInt(u16, msg[6..8], .big);
    var i: usize = 12;
    for (0..qd) |_| i = (skipName(msg, i) orelse return null) + 4;
    for (0..an) |_| {
        i = skipName(msg, i) orelse return null;
        if (i + 10 > msg.len) return null;
        const rtype = std.mem.readInt(u16, msg[i..][0..2], .big);
        const ttl = std.mem.readInt(u32, msg[i + 4 ..][0..4], .big);
        const rdlen = std.mem.readInt(u16, msg[i + 8 ..][0..2], .big);
        i += 10;
        if (i + rdlen > msg.len) return null;
        if (rtype == type_a and rdlen == 4) return .{ packet.v4(msg[i..][0..4].*), ttl };
        i += rdlen;
    }
    return null;
}

// ---------------------------------------------------------------- tests

fn makeQuery(buf: []u8, id: u16, name: []const u8, qtype: u16) []u8 {
    std.mem.writeInt(u16, buf[0..2], id, .big);
    buf[2..12].* = .{ 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
    const n = encodeName(buf[12..], name).?;
    std.mem.writeInt(u16, buf[12 + n ..][0..2], qtype, .big);
    std.mem.writeInt(u16, buf[14 + n ..][0..2], 1, .big);
    return buf[0 .. 16 + n];
}

test "A gets a stable fake address, PTR maps it back, AAAA is empty" {
    var fake: FakeIp = .init(std.testing.allocator, std.testing.io);
    defer fake.deinit();
    var qb: [300]u8 = undefined;
    var out: [512]u8 = undefined;

    const q1 = makeQuery(&qb, 0x1234, "YouTube.com", type_a);
    const n1 = answerLocally(&fake, q1, &out, &.{}).answered;
    try std.testing.expectEqual(0x1234, std.mem.readInt(u16, out[0..2], .big));
    const ip1, const ttl = firstA(out[0..n1]).?;
    try std.testing.expect(isFake(&ip1));
    try std.testing.expectEqual(1, ttl);
    try std.testing.expectEqualSlices(u8, &.{ 198, 18, 0, 3 }, ip1[12..16]);

    // same name, same address; case does not matter
    const n2 = answerLocally(&fake, makeQuery(&qb, 1, "youtube.com", type_a), &out, &.{}).answered;
    try std.testing.expectEqualSlices(u8, &ip1, &firstA(out[0..n2]).?[0]);

    var nb: [64]u8 = undefined;
    try std.testing.expectEqualStrings("youtube.com", fake.lookup(&ip1, &nb).?);

    const n3 = answerLocally(&fake, makeQuery(&qb, 2, "3.0.18.198.in-addr.arpa", type_ptr), &out, &.{}).answered;
    try std.testing.expectEqual(1, std.mem.readInt(u16, out[6..8], .big));
    try std.testing.expect(std.mem.indexOf(u8, out[0..n3], "\x07youtube\x03com\x00") != null);

    const n4 = answerLocally(&fake, makeQuery(&qb, 3, "youtube.com", type_aaaa), &out, &.{}).answered;
    try std.testing.expectEqual(0, std.mem.readInt(u16, out[6..8], .big));
    try std.testing.expectEqual(0x8180, std.mem.readInt(u16, out[2..4], .big));
    _ = n4;
}

test "exclusions, other types and responses are forwarded" {
    var fake: FakeIp = .init(std.testing.allocator, std.testing.io);
    defer fake.deinit();
    var qb: [300]u8 = undefined;
    var out: [512]u8 = undefined;
    try std.testing.expect(answerLocally(&fake, makeQuery(&qb, 1, "printer.local", type_a), &out, &.{}) == .forward);
    try std.testing.expect(answerLocally(&fake, makeQuery(&qb, 1, "nas", type_a), &out, &.{}) == .forward);
    try std.testing.expect(answerLocally(&fake, makeQuery(&qb, 1, "bank.example", type_a), &out, &.{"bank.example"}) == .forward);
    try std.testing.expect(answerLocally(&fake, makeQuery(&qb, 1, "example.com", 15), &out, &.{}) == .forward); // MX
    var resp = makeQuery(&qb, 1, "example.com", type_a);
    resp[2] |= 0x80;
    try std.testing.expect(answerLocally(&fake, resp, &out, &.{}) == .forward);
}

test "a full pool recycles the least recently used address, and only an idle one" {
    var fake: FakeIp = .init(std.testing.allocator, std.testing.io);
    defer fake.deinit();
    fake.capacity = 3;
    fake.test_now = 1000;
    var nb: [64]u8 = undefined;
    const a = try fake.assign("a.example");
    const b = try fake.assign("b.example");
    const c = try fake.assign("c.example");
    try std.testing.expectEqualSlices(u8, &.{ 198, 18, 0, 3 }, &a);
    try std.testing.expectEqualSlices(u8, &.{ 198, 18, 0, 5 }, &c);
    // the pool is full and everything was used just now: no address is taken
    // from a name an application may still hold, the query is forwarded
    try std.testing.expectError(error.PoolExhausted, fake.assign("d.example"));
    var qb: [300]u8 = undefined;
    var out: [512]u8 = undefined;
    try std.testing.expect(answerLocally(&fake, makeQuery(&qb, 1, "d.example", type_a), &out, &.{}) == .forward);

    // a is answered again and b is connected to: c is now the least recent
    fake.test_now.? += fake_grace_s - 1;
    _ = try fake.assign("a.example");
    try std.testing.expectEqualStrings("b.example", fake.lookup(&packet.v4(b), &nb).?);
    fake.test_now.? += 1;
    try std.testing.expectEqualSlices(u8, &c, &try fake.assign("d.example"));
    try std.testing.expectEqualStrings("d.example", fake.lookup(&packet.v4(c), &nb).?);
    try std.testing.expect(fake.by_name.get("c.example") == null);
    try std.testing.expectEqualStrings("a.example", fake.lookup(&packet.v4(a), &nb).?);
    // the last address of the range, and addresses never handed out
    try std.testing.expectEqualSlices(u8, &.{ 198, 19, 255, 255 }, &FakeIp.toAddr(fake_size - fake_first - 1));
    try std.testing.expect(fake.lookup(&packet.v4(.{ 198, 18, 0, 6 }), &nb) == null);
    try std.testing.expect(fake.lookup(&packet.v4(server), &nb) == null);
}

test "names other applications churn through cannot take an address in use" {
    var fake: FakeIp = .init(std.testing.allocator, std.testing.io);
    defer fake.deinit();
    fake.capacity = 64;
    fake.test_now = 0;
    const victim = try fake.assign("bank.example");
    var nb: [64]u8 = undefined;
    var name_buf: [32]u8 = undefined;
    var refused: usize = 0;
    for (0..1000) |k| {
        fake.test_now.? += 1;
        // the victim keeps connecting to the address it was given
        if (k % 100 == 0) try std.testing.expectEqualStrings("bank.example", fake.lookup(&packet.v4(victim), &nb).?);
        const name = try std.fmt.bufPrint(&name_buf, "n{d}.attacker.example", .{k});
        _ = fake.assign(name) catch {
            refused += 1;
            continue;
        };
    }
    try std.testing.expect(refused > 0);
    try std.testing.expectEqualStrings("bank.example", fake.lookup(&packet.v4(victim), &nb).?);
    try std.testing.expectEqualSlices(u8, &victim, &try fake.assign("bank.example"));
}

test "the resolver cache stays bounded and drops what expires first" {
    var r: Resolver = .{ .gpa = std.testing.allocator, .io = std.testing.io, .servers = &.{} };
    defer r.deinit();
    var name_buf: [32]u8 = undefined;
    const addr = packet.v4(.{ 10, 0, 0, 1 });
    // one entry that has already expired, then more names than fit
    r.remember("old.example", addr, 1);
    for (0..Resolver.cache_max) |k| {
        const name = try std.fmt.bufPrint(&name_buf, "n{d}.example", .{k});
        r.remember(name, addr, 1000 + @as(i96, @intCast(k)));
    }
    try std.testing.expectEqual(Resolver.cache_max, r.cache.count());
    try std.testing.expect(r.cache.get("old.example") == null);
    try std.testing.expect(r.cache.get("n0.example") != null);
    // next goes the one closest to expiry
    r.remember("new.example", addr, 5000);
    try std.testing.expectEqual(Resolver.cache_max, r.cache.count());
    try std.testing.expect(r.cache.get("n0.example") == null);
    try std.testing.expect(r.cache.get("new.example") != null);
}

test "resolver forwards to a real server and caches the answer" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest; // POSIX sockets and pipes
    // a tiny DNS server on loopback answering every A query with 10.1.2.3
    const c = std.c;
    const lo = packet.v4(.{ 127, 0, 0, 1 });
    const srv = c.socket(c.AF.INET, c.SOCK.DGRAM, 0);
    defer _ = c.close(srv);
    var sa: c.sockaddr.in = .{ .port = 0, .addr = @bitCast([4]u8{ 127, 0, 0, 1 }) };
    try std.testing.expectEqual(0, c.bind(srv, @ptrCast(&sa), @sizeOf(c.sockaddr.in)));
    var len: c.socklen_t = @sizeOf(c.sockaddr.in);
    _ = c.getsockname(srv, @ptrCast(&sa), &len);
    const port = std.mem.bigToNative(u16, sa.port);

    const T = struct {
        fn serve(fd: c.fd_t) void {
            var buf: [512]u8 = undefined;
            var from: c.sockaddr.in = undefined;
            var flen: c.socklen_t = @sizeOf(c.sockaddr.in);
            const n = c.recvfrom(fd, &buf, buf.len, 0, @ptrCast(&from), &flen);
            if (n <= 0) return;
            const q = parseQuery(buf[0..@intCast(n)]).?;
            var out: [512]u8 = undefined;
            const m = respond(&out, buf[0..@intCast(n)], &q, 0, &.{.{ .rtype = type_a, .ttl = 60, .data = &.{ 10, 1, 2, 3 } }});
            _ = c.sendto(fd, &out, m, 0, @ptrCast(&from), flen);
        }
    };
    const th = try std.Thread.spawn(.{}, T.serve, .{srv});
    var r: Resolver = .{ .gpa = std.testing.allocator, .io = std.testing.io, .servers = &.{.{ .addr = lo, .port = port }}, .fallback = &.{}, .timeout_ms = 40 };
    defer r.deinit();
    const got = try r.resolve("example.org");
    th.join();
    try std.testing.expectEqualSlices(u8, &.{ 10, 1, 2, 3 }, got[12..16]);
    // the server answered once and is gone: the second lookup is served from the cache
    try std.testing.expectEqualSlices(u8, &got, &(try r.resolve("example.org")));

    // the address expired and nobody answers any more: the last known one
    // keeps being used, and the dead server is not asked again right away
    r.forget("example.org");
    try std.testing.expectEqualSlices(u8, &got, &(try r.resolve("example.org")));
    const e = r.cache.get("example.org").?;
    try std.testing.expect(e.known and !e.asking and e.retry_ns > 0);
    const before = Io.Clock.awake.now(r.io).toMilliseconds();
    try std.testing.expectEqualSlices(u8, &got, &(try r.resolve("example.org")));
    try std.testing.expect(Io.Clock.awake.now(r.io).toMilliseconds() - before < 30);
    // a name never seen has nothing to fall back to
    try std.testing.expectError(error.NoAnswer, r.resolve("unknown.example"));
    try std.testing.expectError(error.NoAnswer, r.resolve("unknown.example"));
}

test "resolver: a silent first server, the next one answers; lookups of one name share a query" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest; // POSIX sockets and pipes
    const c = std.c;
    const lo = packet.v4(.{ 127, 0, 0, 1 });
    // a socket nobody reads stands for the resolver that stopped answering
    const silent = c.socket(c.AF.INET, c.SOCK.DGRAM, 0);
    defer _ = c.close(silent);
    const srv = c.socket(c.AF.INET, c.SOCK.DGRAM, 0);
    defer _ = c.close(srv);
    var ports: [2]u16 = undefined;
    for ([_]c.fd_t{ silent, srv }, &ports) |fd, *port| {
        var sa: c.sockaddr.in = .{ .port = 0, .addr = @bitCast([4]u8{ 127, 0, 0, 1 }) };
        try std.testing.expectEqual(0, c.bind(fd, @ptrCast(&sa), @sizeOf(c.sockaddr.in)));
        var len: c.socklen_t = @sizeOf(c.sockaddr.in);
        _ = c.getsockname(fd, @ptrCast(&sa), &len);
        port.* = std.mem.bigToNative(u16, sa.port);
    }
    const T = struct {
        var queries: std.atomic.Value(u32) = .init(0);
        fn serve(fd: c.fd_t) void {
            var buf: [512]u8 = undefined;
            var from: c.sockaddr.in = undefined;
            var flen: c.socklen_t = @sizeOf(c.sockaddr.in);
            const n = c.recvfrom(fd, &buf, buf.len, 0, @ptrCast(&from), &flen);
            if (n <= 0) return;
            _ = queries.fetchAdd(1, .monotonic);
            // slow enough for the other lookups to arrive meanwhile
            std.Io.sleep(std.testing.io, .fromMilliseconds(60), .awake) catch {};
            const q = parseQuery(buf[0..@intCast(n)]).?;
            var out: [512]u8 = undefined;
            const m = respond(&out, buf[0..@intCast(n)], &q, 0, &.{.{ .rtype = type_a, .ttl = 60, .data = &.{ 10, 9, 8, 7 } }});
            _ = c.sendto(fd, &out, m, 0, @ptrCast(&from), flen);
        }
        fn lookup(r: *Resolver, ok: *std.atomic.Value(u32)) void {
            const a = r.resolve("shared.example") catch return;
            if (std.mem.eql(u8, a[12..16], &.{ 10, 9, 8, 7 })) _ = ok.fetchAdd(1, .monotonic);
        }
    };
    const th = try std.Thread.spawn(.{}, T.serve, .{srv});
    var r: Resolver = .{
        .gpa = std.testing.allocator,
        .io = std.testing.io,
        .servers = &.{.{ .addr = lo, .port = ports[0] }},
        .fallback = &.{.{ .addr = lo, .port = ports[1] }},
        .timeout_ms = 150,
    };
    defer r.deinit();
    var ok: std.atomic.Value(u32) = .init(0);
    var threads: [6]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, T.lookup, .{ &r, &ok });
    for (threads) |t| t.join();
    th.join();
    try std.testing.expectEqual(6, ok.load(.monotonic));
    try std.testing.expectEqual(1, T.queries.load(.monotonic));
    // the one that answered is asked first from now on
    try std.testing.expectEqual(1, r.good.load(.monotonic));
}
