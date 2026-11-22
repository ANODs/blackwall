//! Windows: who carries the traffic now. Read from the IPv4 route table
//! (iphlpapi), by the service before it captures anything and by the
//! window to tell the user (platform/conflicts.zig).
//!
//! Another VPN that is connected takes the traffic with routes of its own
//! on an adapter of its own: OpenVPN (hidemy.name and many others) with
//! the two halves 0.0.0.0/1 and 128.0.0.0/1, as we do; WireGuard and the
//! sing-box/xray clients with a default route cheaper than the network's.
//! Two VPNs at once cannot both work: our kill switch blocks the other
//! one's own connection to its server, and its routes or ours win the
//! traffic by metric. So the service refuses to start (error.Conflict, as
//! on macOS) and the window names the program to turn off.
//!
//! An adapter whose default route only waits behind the network's (Radmin
//! VPN, Hamachi: a high metric) takes nothing and is left alone.

const std = @import("std");
const builtin = @import("builtin");
const w = std.os.windows;

const on_windows = builtin.os.tag == .windows;
const W: std.builtin.CallingConvention = .winapi;

/// Our own adapter (service/windows.zig names it so).
pub const own_alias = "BLACKWALL";

// ---------------------------------------------------------------- the decision

pub const Route = struct {
    /// interface index
    index: u32,
    dest: [4]u8,
    prefix: u8,
    /// route metric + interface metric, as Windows weighs them
    cost: u64,
    /// the network itself: a hardware adapter, or a dial-up / mobile link
    physical: bool,
    /// our own adapter
    own: bool = false,
};

/// Indices of the interfaces that take the traffic away from the network,
/// written to `out`; how many.
pub fn captures(routes: []const Route, out: []u32) usize {
    var best_physical: ?u64 = null;
    for (routes) |r| {
        if (r.prefix != 0 or !r.physical or r.own) continue;
        if (best_physical == null or r.cost < best_physical.?) best_physical = r.cost;
    }
    var n: usize = 0;
    for (routes) |r| {
        if (r.physical or r.own) continue;
        if (std.mem.indexOfScalar(u32, out[0..n], r.index) != null) continue;
        const takes = switch (r.prefix) {
            0 => if (best_physical) |b| r.cost < b else false,
            1 => halves(routes, r.index),
            else => false,
        };
        if (!takes or n == out.len) continue;
        out[n] = r.index;
        n += 1;
    }
    return n;
}

/// Both halves of the address space on interface `index`.
fn halves(routes: []const Route, index: u32) bool {
    var low = false;
    var high = false;
    for (routes) |r| {
        if (r.index != index or r.prefix != 1) continue;
        if (r.dest[0] == 0) low = true;
        if (r.dest[0] == 128) high = true;
    }
    return low and high;
}

// ---------------------------------------------------------------- the system

const NET_LUID = u64;

const SockaddrInet = extern union {
    in: extern struct { family: u16, port: u16, addr: [4]u8, zero: [8]u8 },
    in6: extern struct { family: u16, port: u16, flowinfo: u32, addr: [16]u8, scope_id: u32 },
    family: u16,
};

const MIB_IPFORWARD_ROW2 = extern struct {
    InterfaceLuid: NET_LUID,
    InterfaceIndex: u32,
    DestinationPrefix: extern struct { Prefix: SockaddrInet, PrefixLength: u8 },
    NextHop: SockaddrInet,
    SitePrefixLength: u8,
    ValidLifetime: u32,
    PreferredLifetime: u32,
    Metric: u32,
    Protocol: i32,
    Loopback: u8,
    AutoconfigureAddress: u8,
    Publish: u8,
    Immortal: u8,
    Age: u32,
    Origin: i32,
};

const MIB_IPFORWARD_TABLE2 = extern struct {
    NumEntries: u32,
    Table: [1]MIB_IPFORWARD_ROW2,
};

const MIB_IPINTERFACE_ROW = extern struct {
    Family: u16,
    InterfaceLuid: NET_LUID,
    InterfaceIndex: u32,
    MaxReassemblySize: u32,
    InterfaceIdentifier: u64,
    MinRouterAdvertisementInterval: u32,
    MaxRouterAdvertisementInterval: u32,
    AdvertisingEnabled: u8,
    ForwardingEnabled: u8,
    WeakHostSend: u8,
    WeakHostReceive: u8,
    UseAutomaticMetric: u8,
    UseNeighborUnreachabilityDetection: u8,
    ManagedAddressConfigurationSupported: u8,
    OtherStatefulConfigurationSupported: u8,
    AdvertiseDefaultRoute: u8,
    RouterDiscoveryBehavior: i32,
    DadTransmits: u32,
    BaseReachableTime: u32,
    RetransmitTime: u32,
    PathMtuDiscoveryTimeout: u32,
    LinkLocalAddressBehavior: i32,
    LinkLocalAddressTimeout: u32,
    ZoneIndices: [16]u32,
    SitePrefixLength: u32,
    Metric: u32,
    NlMtu: u32,
    Connected: u8,
    SupportsWakeUpPatterns: u8,
    SupportsNeighborDiscovery: u8,
    SupportsRouterDiscovery: u8,
    ReachableTime: u32,
    TransmitOffload: u8,
    ReceiveOffload: u8,
    DisableDefaultRoutes: u8,
};

/// MIB_IF_ROW2, read as bytes: the LUID at 0, Alias and Description (each
/// 257 UTF-16 units) at 28 and 542, the interface type at 1128, and the
/// flags byte (bit 0: HardwareInterface) at 1152.
const if_row_size = 1352;
const if_alias = 28;
const if_description = 542;
const if_type = 1128;
const if_flags = 1152;

comptime {
    if (on_windows and builtin.cpu.arch == .x86_64) {
        std.debug.assert(@sizeOf(MIB_IPFORWARD_ROW2) == 104);
        std.debug.assert(@sizeOf(MIB_IPINTERFACE_ROW) == 168);
    }
}

extern "iphlpapi" fn GetIpForwardTable2(family: u16, table: *?*MIB_IPFORWARD_TABLE2) callconv(W) u32;
extern "iphlpapi" fn FreeMibTable(memory: *anyopaque) callconv(W) void;
extern "iphlpapi" fn GetIfEntry2(row: *[if_row_size]u8) callconv(W) u32;
extern "iphlpapi" fn InitializeIpInterfaceEntry(row: *MIB_IPINTERFACE_ROW) callconv(W) void;
extern "iphlpapi" fn GetIpInterfaceEntry(row: *MIB_IPINTERFACE_ROW) callconv(W) u32;

const Iface = struct {
    luid: NET_LUID,
    index: u32,
    physical: bool,
    own: bool,
    connected: bool,
    metric: u32,
    description: [96]u8 = undefined,
    description_len: u8 = 0,
};

fn iface(luid: NET_LUID) ?Iface {
    var ip: MIB_IPINTERFACE_ROW = undefined;
    InitializeIpInterfaceEntry(&ip);
    ip.Family = 2;
    ip.InterfaceLuid = luid;
    if (GetIpInterfaceEntry(&ip) != 0) return null;
    var row: [if_row_size]u8 align(8) = @splat(0);
    @memcpy(row[0..8], std.mem.asBytes(&luid));
    if (GetIfEntry2(&row) != 0) return null;
    const kind = std.mem.readInt(u32, row[if_type..][0..4], .little);
    // 23 PPP (PPPoE), 243/244 mobile broadband: the network, not a tunnel
    const is_physical = row[if_flags] & 1 != 0 or kind == 23 or kind == 243 or kind == 244;
    var f: Iface = .{ .luid = luid, .index = ip.InterfaceIndex, .physical = is_physical, .own = false, .connected = ip.Connected != 0, .metric = ip.Metric };
    f.own = wideEql(row[if_alias..][0..514], own_alias);
    f.description_len = @intCast(wideToUtf8(row[if_description..][0..514], &f.description).len);
    return f;
}

fn wideUnits(bytes: *const [514]u8) []const u16 {
    const units: *const [257]u16 = @ptrCast(@alignCast(bytes));
    return std.mem.sliceTo(units, 0);
}

fn wideEql(bytes: *const [514]u8, ascii: []const u8) bool {
    const u = wideUnits(bytes);
    if (u.len != ascii.len) return false;
    for (u, ascii) |a, b| if (a != b) return false;
    return true;
}

/// UTF-8 into `buf`, cut between characters.
fn wideToUtf8(bytes: *const [514]u8, buf: []u8) []const u8 {
    var tmp: [3 * 257]u8 = undefined;
    const s = tmp[0..std.unicode.wtf16LeToWtf8(&tmp, wideUnits(bytes))];
    var n = @min(s.len, buf.len);
    while (n < s.len and n > 0 and s[n] & 0xC0 == 0x80) n -= 1;
    @memcpy(buf[0..n], s[0..n]);
    return buf[0..n];
}

/// The routes that matter here: defaults and the two halves, on connected
/// interfaces. `ifaces` gets the interfaces they are on.
fn table(routes: []Route, ifaces: []Iface, nif: *usize) usize {
    nif.* = 0;
    if (comptime !on_windows) return 0;
    var t: ?*MIB_IPFORWARD_TABLE2 = null;
    if (GetIpForwardTable2(2, &t) != 0) return 0;
    const tab = t orelse return 0;
    defer FreeMibTable(tab);
    const rows = @as([*]const MIB_IPFORWARD_ROW2, @ptrCast(&tab.Table))[0..tab.NumEntries];
    var n: usize = 0;
    for (rows) |*r| {
        const p = r.DestinationPrefix.PrefixLength;
        if (p > 1 or r.Loopback != 0 or n == routes.len) continue;
        const f = for (ifaces[0..nif.*]) |*f| {
            if (f.luid == r.InterfaceLuid) break f;
        } else blk: {
            if (nif.* == ifaces.len) continue;
            ifaces[nif.*] = iface(r.InterfaceLuid) orelse continue;
            nif.* += 1;
            break :blk &ifaces[nif.* - 1];
        };
        if (!f.connected) continue;
        routes[n] = .{
            .index = r.InterfaceIndex,
            .dest = r.DestinationPrefix.Prefix.in.addr,
            .prefix = p,
            .cost = @as(u64, r.Metric) + f.metric,
            .physical = f.physical,
            .own = f.own,
        };
        n += 1;
    }
    return n;
}

/// The interface the network itself is reached through: the cheapest
/// default route of a physical interface, or of any other but ours when
/// there is none. Null: no default route.
pub fn physical() ?u32 {
    var routes: [128]Route = undefined;
    var ifaces: [32]Iface = undefined;
    var nif: usize = 0;
    const n = table(&routes, &ifaces, &nif);
    var best: ?Route = null;
    for (routes[0..n]) |r| {
        if (r.prefix != 0 or r.own) continue;
        if (best) |b| {
            if (b.physical and !r.physical) continue;
            if (b.physical == r.physical and b.cost <= r.cost) continue;
        }
        best = r;
    }
    return if (best) |b| b.index else null;
}

pub const Capture = struct {
    index: u32 = 0,
    /// the VPN program when one is known to run, else the adapter
    name_buf: [64]u8 = undefined,
    name_len: u8 = 0,
    /// the adapter's description ("TAP-Windows Adapter V9")
    adapter_buf: [64]u8 = undefined,
    adapter_len: u8 = 0,
    /// the program was seen running (not only the adapter)
    program: bool = false,

    pub fn name(c: *const Capture) []const u8 {
        return c.name_buf[0..c.name_len];
    }
    pub fn adapter(c: *const Capture) []const u8 {
        return c.adapter_buf[0..c.adapter_len];
    }
};

/// Other VPNs that take the traffic now; how many were written to `out`.
pub fn foreign(out: []Capture) usize {
    if (comptime !on_windows) return 0;
    var routes: [128]Route = undefined;
    var ifaces: [32]Iface = undefined;
    var nif: usize = 0;
    const n = table(&routes, &ifaces, &nif);
    var idx: [8]u32 = undefined;
    const k = captures(routes[0..n], idx[0..@min(idx.len, out.len)]);
    const prog = vpnProgram();
    for (idx[0..k], 0..) |index, i| {
        var c: Capture = .{ .index = index };
        for (ifaces[0..nif]) |*f| if (f.index == index) {
            c.adapter_len = @intCast(@min(f.description_len, c.adapter_buf.len));
            @memcpy(c.adapter_buf[0..c.adapter_len], f.description[0..c.adapter_len]);
        };
        const nm = if (prog) |p| p else c.adapter();
        c.program = prog != null;
        c.name_len = @intCast(@min(nm.len, c.name_buf.len));
        @memcpy(c.name_buf[0..c.name_len], nm[0..c.name_len]);
        out[i] = c;
    }
    return k;
}

// ---------------------------------------------------------------- the program

/// VPN programs of Windows by their executables, and the names users know.
const programs = [_]struct { exe: []const u8, name: []const u8 }{
    .{ .exe = "hidemy.name vpn.exe", .name = "hidemy.name VPN" },
    .{ .exe = "hidemyname.exe", .name = "hidemy.name VPN" },
    .{ .exe = "hmnvpn.exe", .name = "hidemy.name VPN" },
    .{ .exe = "openvpn-gui.exe", .name = "OpenVPN" },
    .{ .exe = "openvpnconnect.exe", .name = "OpenVPN Connect" },
    .{ .exe = "openvpn.exe", .name = "OpenVPN" },
    .{ .exe = "wireguard.exe", .name = "WireGuard" },
    .{ .exe = "amneziavpn.exe", .name = "AmneziaVPN" },
    .{ .exe = "amneziawg.exe", .name = "AmneziaWG" },
    .{ .exe = "outline.exe", .name = "Outline" },
    .{ .exe = "hiddify.exe", .name = "Hiddify" },
    .{ .exe = "happ.exe", .name = "Happ" },
    .{ .exe = "nekoray.exe", .name = "NekoBox" },
    .{ .exe = "nekobox.exe", .name = "NekoBox" },
    .{ .exe = "v2rayn.exe", .name = "v2rayN" },
    .{ .exe = "clash-verge.exe", .name = "Clash Verge" },
    .{ .exe = "clash verge.exe", .name = "Clash Verge" },
    .{ .exe = "mihomo.exe", .name = "Clash (mihomo)" },
    .{ .exe = "protonvpn.exe", .name = "Proton VPN" },
    .{ .exe = "protonvpn.client.exe", .name = "Proton VPN" },
    .{ .exe = "nordvpn.exe", .name = "NordVPN" },
    .{ .exe = "expressvpn.exe", .name = "ExpressVPN" },
    .{ .exe = "windscribe.exe", .name = "Windscribe" },
    .{ .exe = "kaspersky vpn.exe", .name = "Kaspersky VPN" },
    .{ .exe = "planetvpn.exe", .name = "Planet VPN" },
    .{ .exe = "psiphon3.exe", .name = "Psiphon" },
};

/// The name of a known VPN program by its executable.
pub fn programOf(exe: []const u8) ?[]const u8 {
    const at = std.mem.lastIndexOfAny(u8, exe, "\\/");
    const base = if (at) |i| exe[i + 1 ..] else exe;
    for (programs) |p| if (std.ascii.eqlIgnoreCase(base, p.exe)) return p.name;
    return null;
}

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
extern "kernel32" fn CreateToolhelp32Snapshot(flags: u32, pid: u32) callconv(W) w.HANDLE;
extern "kernel32" fn Process32FirstW(snap: w.HANDLE, entry: *PROCESSENTRY32W) callconv(W) i32;
extern "kernel32" fn Process32NextW(snap: w.HANDLE, entry: *PROCESSENTRY32W) callconv(W) i32;

/// The first known VPN program that runs (in the order of `programs`: a
/// client before the engine it starts).
fn vpnProgram() ?[]const u8 {
    if (comptime !on_windows) return null;
    const snap = CreateToolhelp32Snapshot(0x2, 0);
    if (snap == w.INVALID_HANDLE_VALUE) return null;
    defer w.CloseHandle(snap);
    var best: ?usize = null;
    var e: PROCESSENTRY32W = .{};
    var ok = Process32FirstW(snap, &e) != 0;
    while (ok) : (ok = Process32NextW(snap, &e) != 0) {
        var buf: [3 * 260]u8 = undefined;
        const exe = buf[0..std.unicode.wtf16LeToWtf8(&buf, std.mem.sliceTo(&e.szExeFile, 0))];
        for (programs, 0..) |p, i| {
            if (!std.ascii.eqlIgnoreCase(exe, p.exe)) continue;
            if (best == null or i < best.?) best = i;
        }
    }
    return if (best) |i| programs[i].name else null;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn route(index: u32, a: u8, prefix: u8, cost: u64, phys: bool) Route {
    return .{ .index = index, .dest = .{ a, 0, 0, 0 }, .prefix = prefix, .cost = cost, .physical = phys };
}

test "OpenVPN's two halves take the traffic; a default route behind the network's does not" {
    // the user's PC: hidemy.name on a TAP adapter (14), Radmin VPN (9) with
    // its default route far behind Ethernet (16)
    const routes = [_]Route{
        route(14, 0, 1, 4, false),
        route(14, 128, 1, 4, false),
        route(9, 0, 0, 9257, false),
        route(16, 0, 0, 35, true),
    };
    var out: [4]u32 = undefined;
    const n = captures(&routes, &out);
    try testing.expectEqualSlices(u32, &.{14}, out[0..n]);
}

test "a VPN's default route cheaper than the network's takes the traffic" {
    const routes = [_]Route{ route(30, 0, 0, 5, false), route(16, 0, 0, 35, true) };
    var out: [4]u32 = undefined;
    try testing.expectEqual(1, captures(&routes, &out));
    try testing.expectEqual(30, out[0]);
}

test "nothing in the way: the network alone, our own adapter, one half only" {
    var own = route(64, 0, 1, 0, false);
    own.own = true;
    var own2 = route(64, 128, 1, 0, false);
    own2.own = true;
    const routes = [_]Route{ own, own2, route(16, 0, 0, 35, true), route(20, 0, 1, 1, false) };
    var out: [4]u32 = undefined;
    try testing.expectEqual(0, captures(&routes, &out));
    // without a physical default route, a lone default is not a capture
    const lone = [_]Route{route(31, 0, 0, 5, false)};
    try testing.expectEqual(0, captures(&lone, &out));
}

test "a VPN program is known by its executable" {
    try testing.expectEqualStrings("OpenVPN", programOf("C:\\Program Files\\OpenVPN\\bin\\openvpn.exe").?);
    try testing.expectEqualStrings("WireGuard", programOf("WireGuard.exe").?);
    try testing.expect(programOf("C:\\Windows\\System32\\svchost.exe") == null);
}
