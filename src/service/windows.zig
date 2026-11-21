//! Windows pieces of the data plane: the Wintun adapter and the routes
//! around it, through the IP Helper API (iphlpapi.dll). The same plan as
//! Linux (linux.zig): the adapter gets the tunnel's address, everything is
//! routed into it in two halves (more specific than the real default
//! route, which stays for our own sockets), the network's resolvers are
//! routed into it too, so name lookups reach the tunnel's own DNS, and the
//! service's own sockets are kept on the physical interface with
//! IP_UNICAST_IF.
//!
//! It needs an administrator (the service runs as LocalSystem). The
//! adapter goes away with the process that opened it, routes and all.

const std = @import("std");
const builtin = @import("builtin");
const core = @import("core");
const w = std.os.windows;
const wintun = core.wintun;

const log = std.log.scoped(.windows);

pub const adapter_name = "BLACKWALL";
/// The same adapter every time, so Windows keeps one network profile for it.
const adapter_guid: w.GUID = .{ .Data1 = 0xd7c4b1a2, .Data2 = 0x5e3f, .Data3 = 0x4b8a, .Data4 = .{ 0x9c, 0x61, 0x0b, 0x1a, 0xc4, 0xf0, 0x0d, 0x01 } };

/// The tunnel's address and prefix (as on macOS and Linux).
const tun_addr = [4]u8{ 198, 18, 0, 1 };
const tun_prefix = 15;
const tun_addr6 = [16]u8{ 0xfd, 0x62, 0x6c, 0x61, 0x63, 0x6b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

const W: std.builtin.CallingConvention = .winapi;
const NET_LUID = u64;

const SockaddrInet = extern union {
    in: extern struct { family: u16 = 2, port: u16 = 0, addr: [4]u8, zero: [8]u8 = @splat(0) },
    in6: extern struct { family: u16 = 23, port: u16 = 0, flowinfo: u32 = 0, addr: [16]u8, scope_id: u32 = 0 },
    family: u16,

    fn v4(a: [4]u8) SockaddrInet {
        var s: SockaddrInet = std.mem.zeroes(SockaddrInet);
        s.in = .{ .addr = a };
        return s;
    }
    fn v6(a: [16]u8) SockaddrInet {
        var s: SockaddrInet = std.mem.zeroes(SockaddrInet);
        s.in6 = .{ .addr = a };
        return s;
    }
};

const MIB_UNICASTIPADDRESS_ROW = extern struct {
    Address: SockaddrInet,
    InterfaceLuid: NET_LUID,
    InterfaceIndex: u32,
    PrefixOrigin: i32,
    SuffixOrigin: i32,
    ValidLifetime: u32,
    PreferredLifetime: u32,
    OnLinkPrefixLength: u8,
    SkipAsSource: u8,
    DadState: i32,
    ScopeId: u32,
    CreationTimeStamp: i64,
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

comptime {
    if (builtin.os.tag == .windows and builtin.cpu.arch == .x86_64) {
        std.debug.assert(@sizeOf(SockaddrInet) == 28);
        std.debug.assert(@sizeOf(MIB_UNICASTIPADDRESS_ROW) == 80);
        std.debug.assert(@sizeOf(MIB_IPFORWARD_ROW2) == 104);
        std.debug.assert(@sizeOf(MIB_IPINTERFACE_ROW) == 168);
    }
}

extern "iphlpapi" fn InitializeUnicastIpAddressEntry(row: *MIB_UNICASTIPADDRESS_ROW) callconv(W) void;
extern "iphlpapi" fn CreateUnicastIpAddressEntry(row: *const MIB_UNICASTIPADDRESS_ROW) callconv(W) u32;
extern "iphlpapi" fn InitializeIpForwardEntry(row: *MIB_IPFORWARD_ROW2) callconv(W) void;
extern "iphlpapi" fn CreateIpForwardEntry2(row: *const MIB_IPFORWARD_ROW2) callconv(W) u32;
extern "iphlpapi" fn InitializeIpInterfaceEntry(row: *MIB_IPINTERFACE_ROW) callconv(W) void;
extern "iphlpapi" fn GetIpInterfaceEntry(row: *MIB_IPINTERFACE_ROW) callconv(W) u32;
extern "iphlpapi" fn SetIpInterfaceEntry(row: *MIB_IPINTERFACE_ROW) callconv(W) u32;
extern "iphlpapi" fn ConvertInterfaceLuidToIndex(luid: *const NET_LUID, index: *u32) callconv(W) u32;
extern "iphlpapi" fn GetBestInterfaceEx(dest: *const SockaddrInet, index: *u32) callconv(W) u32;
extern "iphlpapi" fn GetAdaptersAddresses(family: u32, flags: u32, reserved: ?*anyopaque, out: ?[*]u8, size: *u32) callconv(W) u32;

const ERROR_OBJECT_ALREADY_EXISTS = 5010;
const NO_ERROR = 0;

pub const Options = struct {
    mtu: u16 = 1500,
    /// send IPv6 into the adapter too (to be carried or refused there)
    ipv6: bool = true,
    /// wintun.dll
    dll: []const u8,
};

/// What `up` set up, for the service to run on.
pub const Lease = struct {
    adapter: wintun.Adapter,
    device: wintun.Device,
    /// the adapter's interface index and LUID
    index: u32,
    luid: u64 = 0,
    /// the physical interface our own sockets must stay on
    bind_index: u32,
    /// the network's resolvers; routed into the adapter, reached by us
    /// through `bind_index`
    dns: [4][4]u8 = undefined,
    dns_len: usize = 0,
};

/// Create (or open) the adapter and capture the traffic with it.
pub fn up(o: Options) !Lease {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const api = try wintun.Api.load(o.dll);
    // before our routes exist: where the real default route goes
    var dest = SockaddrInet.v4(.{ 1, 1, 1, 1 });
    var bind_index: u32 = 0;
    if (GetBestInterfaceEx(&dest, &bind_index) != NO_ERROR or bind_index == 0) return error.NoNetwork;

    const a = wintun.adapter(api, adapter_name, &adapter_guid) catch |err| {
        log.err("wintun adapter: {t} (error {d})", .{ err, wintun.lastError() });
        return if (wintun.lastError() == 5) error.NeedsAdministrator else err;
    };
    errdefer api.closeAdapter(a);
    var luid: NET_LUID = 0;
    api.getAdapterLuid(a, &luid);
    var index: u32 = 0;
    _ = ConvertInterfaceLuidToIndex(&luid, &index);
    if (index == bind_index) return error.NoNetwork; // only our own adapter routes anywhere

    var lease: Lease = .{ .adapter = a, .device = undefined, .index = index, .luid = luid, .bind_index = bind_index };
    lease.dns_len = resolvers(bind_index, &lease.dns);

    try addAddress(luid, SockaddrInet.v4(tun_addr), tun_prefix);
    if (o.ipv6) addAddress(luid, SockaddrInet.v6(tun_addr6), 64) catch |err| log.warn("IPv6 address: {t}", .{err});
    setInterface(luid, 2, o.mtu);
    if (o.ipv6) setInterface(luid, 23, o.mtu);

    // everything, in two halves
    try addRoute(luid, SockaddrInet.v4(.{ 0, 0, 0, 0 }), 1);
    try addRoute(luid, SockaddrInet.v4(.{ 128, 0, 0, 0 }), 1);
    // the resolvers, even on the local network
    for (lease.dns[0..lease.dns_len]) |ip| addRoute(luid, SockaddrInet.v4(ip), 32) catch |err|
        log.warn("resolver {d}.{d}.{d}.{d} is not captured: {t}", .{ ip[0], ip[1], ip[2], ip[3], err });
    if (o.ipv6) {
        const h0: [16]u8 = @splat(0);
        var h1: [16]u8 = @splat(0);
        h1[0] = 0x80;
        addRoute(luid, SockaddrInet.v6(h0), 1) catch |err| log.warn("IPv6 is not captured: {t}", .{err});
        addRoute(luid, SockaddrInet.v6(h1), 1) catch {};
    }
    lease.device = try wintun.Device.init(api, a);
    return lease;
}

/// Let the traffic go: the adapter and its routes disappear.
pub fn down(l: *Lease) void {
    if (comptime builtin.os.tag != .windows) return;
    l.device.api.closeAdapter(l.adapter);
}

fn addAddress(luid: NET_LUID, addr: SockaddrInet, prefix: u8) !void {
    var row: MIB_UNICASTIPADDRESS_ROW = undefined;
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = luid;
    row.Address = addr;
    row.OnLinkPrefixLength = prefix;
    row.DadState = 4; // IpDadStatePreferred: usable at once
    const rc = CreateUnicastIpAddressEntry(&row);
    if (rc != NO_ERROR and rc != ERROR_OBJECT_ALREADY_EXISTS) {
        log.err("address: error {d}", .{rc});
        return error.AddressFailed;
    }
}

fn addRoute(luid: NET_LUID, dest: SockaddrInet, prefix: u8) !void {
    var row: MIB_IPFORWARD_ROW2 = undefined;
    InitializeIpForwardEntry(&row);
    row.InterfaceLuid = luid;
    row.DestinationPrefix = .{ .Prefix = dest, .PrefixLength = prefix };
    // on-link: no gateway, the adapter takes it
    row.NextHop = if (dest.family == 2) SockaddrInet.v4(@splat(0)) else SockaddrInet.v6(@splat(0));
    row.Metric = 0;
    const rc = CreateIpForwardEntry2(&row);
    if (rc != NO_ERROR and rc != ERROR_OBJECT_ALREADY_EXISTS) {
        log.err("route: error {d}", .{rc});
        return error.RouteFailed;
    }
}

/// The lowest metric (its DNS servers are asked first) and the MTU.
fn setInterface(luid: NET_LUID, family: u16, mtu: u16) void {
    var row: MIB_IPINTERFACE_ROW = undefined;
    InitializeIpInterfaceEntry(&row);
    row.Family = family;
    row.InterfaceLuid = luid;
    if (GetIpInterfaceEntry(&row) != NO_ERROR) return;
    row.UseAutomaticMetric = 0;
    row.Metric = 0;
    row.NlMtu = std.math.clamp(mtu, 1280, 9000);
    // SitePrefixLength must be 0 for IPv4 when it is written back
    if (family == 2) row.SitePrefixLength = 0;
    const rc = SetIpInterfaceEntry(&row);
    if (rc != NO_ERROR) log.warn("interface settings: error {d}", .{rc});
}

/// The IPv4 resolvers of interface `index`.
fn resolvers(index: u32, out: *[4][4]u8) usize {
    var buf: [32 * 1024]u8 align(8) = undefined;
    var size: u32 = buf.len;
    // skip unicast, anycast and multicast addresses: only the DNS servers
    const flags: u32 = 0x1 | 0x2 | 0x4;
    if (GetAdaptersAddresses(2, flags, null, &buf, &size) != NO_ERROR) return 0;
    var n: usize = 0;
    var p: ?[*]u8 = &buf;
    while (p) |a| {
        // IP_ADAPTER_ADDRESSES: Length, IfIndex, Next, ..., FirstDnsServerAddress at 48
        const if_index = std.mem.readInt(u32, a[4..8], .little);
        const next: ?[*]u8 = @ptrFromInt(std.mem.readInt(usize, a[8..16], .little));
        if (if_index == index) {
            var d: ?[*]u8 = @ptrFromInt(std.mem.readInt(usize, a[48..56], .little));
            while (d) |srv| : (d = @ptrFromInt(std.mem.readInt(usize, srv[8..16], .little))) {
                // IP_ADAPTER_DNS_SERVER_ADDRESS: Length, Reserved, Next, SOCKET_ADDRESS
                const sa: ?[*]const u8 = @ptrFromInt(std.mem.readInt(usize, srv[16..24], .little));
                const s = sa orelse continue;
                if (std.mem.readInt(u16, s[0..2], .little) != 2) continue;
                if (n == out.len) break;
                out[n] = s[4..8].*;
                n += 1;
            }
            break;
        }
        p = next;
    }
    return n;
}
