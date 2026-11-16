//! The kill switch on Windows: persistent filters of the Windows Filtering
//! Platform in a sublayer of our own. They live in the system, not in the
//! service: when the service dies (and the Wintun adapter with it) they
//! stay, and traffic that would leave past the VPN is blocked until a
//! service is back or `clear` lets it go. The same rules as pf on macOS
//! (src/helper/darwin/pf.zig) and nftables on Linux (nft.zig):
//!
//!   selective: out through the adapter, loopback, DHCP, the local network
//!              when allowed, and the service itself (its servers, its
//!              resolvers, the direct routes); everything else is blocked.
//!              While the service runs nothing changes (the routes send all
//!              into the adapter); when it dies, nothing goes out directly.
//!   strict:    the same, but the service too only to the VPN servers and
//!              the resolvers it asks: no direct route works.
//!
//! The filters are at the ALE connect layers (a TCP connect, the first
//! datagram to a peer), IPv4 and IPv6. Their keys are fixed, so a new
//! service replaces what an earlier one left.

const std = @import("std");
const builtin = @import("builtin");
const w = std.os.windows;

const log = std.log.scoped(.wfp);

const W: std.builtin.CallingConvention = .winapi;
const GUID = w.GUID;

pub const Mode = enum { selective, strict };

pub const Options = struct {
    mode: Mode,
    /// the Wintun adapter
    luid: u64,
    /// blackwall-service.exe (selective lets it out as it is)
    service_exe: []const u8,
    servers4: []const [4]u8,
    dns4: []const [4]u8,
    allow_lan: bool,
    ipv6_block: bool,
};

// ------------------------------------------------------------ the API (fwpuclnt.dll)

const FWP_BYTE_BLOB = extern struct { size: u32, data: ?[*]u8 };
const FWPM_DISPLAY_DATA0 = extern struct { name: ?[*:0]const u16, description: ?[*:0]const u16 = null };
const FWP_VALUE0 = extern struct { type: u32, value: usize };
const FWP_V4_ADDR_AND_MASK = extern struct { addr: u32, mask: u32 };
const FWP_V6_ADDR_AND_MASK = extern struct { addr: [16]u8, prefix: u8 };
const FWPM_FILTER_CONDITION0 = extern struct { field: GUID, match: u32, value: FWP_VALUE0 };
const FWPM_ACTION0 = extern struct { type: u32, filter_type: GUID = std.mem.zeroes(GUID) };
const FWPM_FILTER0 = extern struct {
    key: GUID,
    display: FWPM_DISPLAY_DATA0,
    flags: u32,
    provider_key: ?*GUID = null,
    provider_data: FWP_BYTE_BLOB = .{ .size = 0, .data = null },
    layer: GUID,
    sublayer: GUID,
    weight: FWP_VALUE0,
    num_conditions: u32,
    conditions: ?[*]const FWPM_FILTER_CONDITION0,
    action: FWPM_ACTION0,
    context: extern union { raw: u64, key: GUID } = .{ .raw = 0 },
    reserved: ?*GUID = null,
    id: u64 = 0,
    effective_weight: FWP_VALUE0 = .{ .type = 0, .value = 0 },
};
const FWPM_SUBLAYER0 = extern struct {
    key: GUID,
    display: FWPM_DISPLAY_DATA0,
    flags: u32,
    provider_key: ?*GUID = null,
    provider_data: FWP_BYTE_BLOB = .{ .size = 0, .data = null },
    weight: u16,
};

comptime {
    if (builtin.os.tag == .windows and builtin.cpu.arch == .x86_64) {
        std.debug.assert(@sizeOf(FWPM_FILTER_CONDITION0) == 40);
        std.debug.assert(@sizeOf(FWPM_FILTER0) == 200);
    }
}

extern "fwpuclnt" fn FwpmEngineOpen0(server: ?[*:0]const u16, authn: u32, identity: ?*anyopaque, session: ?*anyopaque, engine: *w.HANDLE) callconv(W) u32;
extern "fwpuclnt" fn FwpmEngineClose0(engine: w.HANDLE) callconv(W) u32;
extern "fwpuclnt" fn FwpmTransactionBegin0(engine: w.HANDLE, flags: u32) callconv(W) u32;
extern "fwpuclnt" fn FwpmTransactionCommit0(engine: w.HANDLE) callconv(W) u32;
extern "fwpuclnt" fn FwpmTransactionAbort0(engine: w.HANDLE) callconv(W) u32;
extern "fwpuclnt" fn FwpmSubLayerAdd0(engine: w.HANDLE, sublayer: *const FWPM_SUBLAYER0, sd: ?*anyopaque) callconv(W) u32;
extern "fwpuclnt" fn FwpmSubLayerDeleteByKey0(engine: w.HANDLE, key: *const GUID) callconv(W) u32;
extern "fwpuclnt" fn FwpmFilterAdd0(engine: w.HANDLE, filter: *const FWPM_FILTER0, sd: ?*anyopaque, id: ?*u64) callconv(W) u32;
extern "fwpuclnt" fn FwpmFilterDeleteByKey0(engine: w.HANDLE, key: *const GUID) callconv(W) u32;
extern "fwpuclnt" fn FwpmFilterGetByKey0(engine: w.HANDLE, key: *const GUID, filter: *?*FWPM_FILTER0) callconv(W) u32;
extern "fwpuclnt" fn FwpmGetAppIdFromFileName0(name: [*:0]const u16, app_id: *?*FWP_BYTE_BLOB) callconv(W) u32;
extern "fwpuclnt" fn FwpmFreeMemory0(p: *?*anyopaque) callconv(W) void;

const RPC_C_AUTHN_WINNT = 10;
const FWP_E_ALREADY_EXISTS = 0x80320009;

const FWP_UINT8 = 1;
const FWP_UINT16 = 2;
const FWP_UINT32 = 3;
const FWP_UINT64 = 4;
const FWP_BYTE_BLOB_TYPE = 12;
const FWP_V4_ADDR_MASK = 0x100;
const FWP_V6_ADDR_MASK = 0x101;

const FWP_MATCH_EQUAL = 0;
const FWP_MATCH_FLAGS_ANY_SET = 7;

const FWP_ACTION_BLOCK = 0x1001;
const FWP_ACTION_PERMIT = 0x1002;
const FWPM_FILTER_FLAG_PERSISTENT = 0x1;
const FWPM_SUBLAYER_FLAG_PERSISTENT = 0x1;
const FWP_CONDITION_FLAG_IS_LOOPBACK = 0x1;

fn guid(comptime s: []const u8) GUID {
    return GUID.parse("{" ++ s ++ "}");
}

const layer_connect_v4 = guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
const layer_connect_v6 = guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
const cond_remote_address = guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
const cond_remote_port = guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
const cond_ip_protocol = guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
const cond_local_interface = guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4");
const cond_flags = guid("632ce23b-5167-435c-86d7-e903684aa80c");
const cond_app_id = guid("d78e1e87-8644-4ea5-9437-d809ecefc971");

/// Ours: the sublayer, and the first of the filters' keys (the rest count
/// up from it in Data1).
const sublayer_key = guid("8c1a4f60-2b7e-4d1a-9f3b-6e2c5a7d0b10");
const filter_key_base = guid("8c1a4f61-2b7e-4d1a-9f3b-6e2c5a7d0b10");
const filters_max = 64;

const L = std.unicode.utf8ToUtf16LeStringLiteral;

// ------------------------------------------------------------ what the service calls

/// Replaces our filters with those of `o`. Needs an administrator (the
/// service runs as LocalSystem).
pub fn apply(o: Options) !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const engine = try open();
    defer _ = FwpmEngineClose0(engine);
    if (FwpmTransactionBegin0(engine, 0) != 0) return error.WfpFailed;
    errdefer _ = FwpmTransactionAbort0(engine);
    removeFilters(engine);
    const sub: FWPM_SUBLAYER0 = .{
        .key = sublayer_key,
        .display = .{ .name = L("BLACKWALL kill switch") },
        .flags = FWPM_SUBLAYER_FLAG_PERSISTENT,
        // above the others: our blocks are seen whatever they permit
        .weight = 0xffff,
    };
    const rc = FwpmSubLayerAdd0(engine, &sub, null);
    if (rc != 0 and rc != FWP_E_ALREADY_EXISTS) {
        log.err("sublayer: 0x{x}", .{rc});
        return error.WfpFailed;
    }
    var b: Builder = .{ .engine = engine };
    try b.rules(o);
    if (FwpmTransactionCommit0(engine) != 0) return error.WfpFailed;
    log.info("kill switch: {t}, {d} filters", .{ o.mode, b.next });
}

/// Lets the traffic go: our filters and sublayer are removed.
pub fn clear() void {
    if (comptime builtin.os.tag != .windows) return;
    const engine = open() catch return;
    defer _ = FwpmEngineClose0(engine);
    if (FwpmTransactionBegin0(engine, 0) != 0) return;
    removeFilters(engine);
    _ = FwpmSubLayerDeleteByKey0(engine, &sublayer_key);
    _ = FwpmTransactionCommit0(engine);
}

/// Whether filters of ours are in place (a service that is gone left them).
pub fn active() bool {
    if (comptime builtin.os.tag != .windows) return false;
    const engine = open() catch return false;
    defer _ = FwpmEngineClose0(engine);
    var f: ?*FWPM_FILTER0 = null;
    const k = keyAt(0);
    if (FwpmFilterGetByKey0(engine, &k, &f) != 0) return false;
    var p: ?*anyopaque = @ptrCast(f);
    FwpmFreeMemory0(&p);
    return true;
}

fn open() !w.HANDLE {
    var engine: w.HANDLE = undefined;
    const rc = FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, null, null, &engine);
    if (rc != 0) {
        log.err("engine: 0x{x}", .{rc});
        return if (rc == 5) error.NeedsAdministrator else error.WfpFailed;
    }
    return engine;
}

fn keyAt(i: usize) GUID {
    var k = filter_key_base;
    k.Data1 +%= @intCast(i);
    return k;
}

fn removeFilters(engine: w.HANDLE) void {
    for (0..filters_max) |i| {
        const k = keyAt(i);
        _ = FwpmFilterDeleteByKey0(engine, &k);
    }
}

const Builder = struct {
    engine: w.HANDLE,
    next: usize = 0,

    fn add(b: *Builder, layer: GUID, action: u32, weight: u8, conds: []const FWPM_FILTER_CONDITION0) !void {
        if (b.next == filters_max) return error.TooManyFilters;
        const f: FWPM_FILTER0 = .{
            .key = keyAt(b.next),
            .display = .{ .name = L("BLACKWALL") },
            .flags = FWPM_FILTER_FLAG_PERSISTENT,
            .layer = layer,
            .sublayer = sublayer_key,
            .weight = .{ .type = FWP_UINT8, .value = weight },
            .num_conditions = @intCast(conds.len),
            .conditions = if (conds.len > 0) conds.ptr else null,
            .action = .{ .type = action },
        };
        const rc = FwpmFilterAdd0(b.engine, &f, null, null);
        if (rc != 0) {
            log.err("filter {d}: 0x{x}", .{ b.next, rc });
            return error.WfpFailed;
        }
        b.next += 1;
    }

    fn permit(b: *Builder, layer: GUID, conds: []const FWPM_FILTER_CONDITION0) !void {
        return b.add(layer, FWP_ACTION_PERMIT, 10, conds);
    }

    fn rules(b: *Builder, o: Options) !void {
        var luid = o.luid;
        const loopback = [_]FWPM_FILTER_CONDITION0{.{ .field = cond_flags, .match = FWP_MATCH_FLAGS_ANY_SET, .value = .{ .type = FWP_UINT32, .value = FWP_CONDITION_FLAG_IS_LOOPBACK } }};
        const adapter = [_]FWPM_FILTER_CONDITION0{.{ .field = cond_local_interface, .match = FWP_MATCH_EQUAL, .value = .{ .type = FWP_UINT64, .value = @intFromPtr(&luid) } }};
        for ([_]GUID{ layer_connect_v4, layer_connect_v6 }) |layer| {
            try b.permit(layer, &loopback);
            try b.permit(layer, &adapter);
        }

        // DHCP keeps the network itself working
        const dhcp = [_]FWPM_FILTER_CONDITION0{
            .{ .field = cond_ip_protocol, .match = FWP_MATCH_EQUAL, .value = .{ .type = FWP_UINT8, .value = 17 } },
            .{ .field = cond_remote_port, .match = FWP_MATCH_EQUAL, .value = .{ .type = FWP_UINT16, .value = 67 } },
        };
        try b.permit(layer_connect_v4, &dhcp);

        // the service as it is (selective), or only to its servers and resolvers (strict)
        var app_blob: ?*FWP_BYTE_BLOB = null;
        defer if (app_blob != null) {
            var p: ?*anyopaque = @ptrCast(app_blob);
            FwpmFreeMemory0(&p);
        };
        if (o.mode == .selective) {
            var wide: [std.fs.max_path_bytes:0]u16 = undefined;
            const n = try std.unicode.wtf8ToWtf16Le(&wide, o.service_exe);
            wide[n] = 0;
            if (FwpmGetAppIdFromFileName0(wide[0..n :0], &app_blob) != 0) return error.WfpFailed;
            const me = [_]FWPM_FILTER_CONDITION0{.{ .field = cond_app_id, .match = FWP_MATCH_EQUAL, .value = .{ .type = FWP_BYTE_BLOB_TYPE, .value = @intFromPtr(app_blob.?) } }};
            try b.permit(layer_connect_v4, &me);
            try b.permit(layer_connect_v6, &me);
        } else {
            for (o.servers4) |ip| {
                const to = [_]FWPM_FILTER_CONDITION0{.{ .field = cond_remote_address, .match = FWP_MATCH_EQUAL, .value = .{ .type = FWP_UINT32, .value = std.mem.readInt(u32, &ip, .big) } }};
                try b.permit(layer_connect_v4, &to);
            }
            for (o.dns4) |ip| {
                const to = [_]FWPM_FILTER_CONDITION0{
                    .{ .field = cond_remote_address, .match = FWP_MATCH_EQUAL, .value = .{ .type = FWP_UINT32, .value = std.mem.readInt(u32, &ip, .big) } },
                    .{ .field = cond_remote_port, .match = FWP_MATCH_EQUAL, .value = .{ .type = FWP_UINT16, .value = 53 } },
                };
                try b.permit(layer_connect_v4, &to);
            }
        }

        if (o.allow_lan) {
            // the local network, but no name lookups past the VPN through it
            const lan4 = [_]FWP_V4_ADDR_AND_MASK{
                .{ .addr = 0x0a000000, .mask = 0xff000000 },
                .{ .addr = 0xac100000, .mask = 0xfff00000 },
                .{ .addr = 0xc0a80000, .mask = 0xffff0000 },
                .{ .addr = 0xa9fe0000, .mask = 0xffff0000 },
                .{ .addr = 0xe0000000, .mask = 0xf0000000 },
                .{ .addr = 0xffffffff, .mask = 0xffffffff },
            };
            for (&lan4) |*m| {
                for ([_]u16{ 53, 853 }) |port| {
                    const dns_there = [_]FWPM_FILTER_CONDITION0{
                        .{ .field = cond_remote_address, .match = FWP_MATCH_EQUAL, .value = .{ .type = FWP_V4_ADDR_MASK, .value = @intFromPtr(m) } },
                        .{ .field = cond_remote_port, .match = FWP_MATCH_EQUAL, .value = .{ .type = FWP_UINT16, .value = port } },
                    };
                    // a block that weighs more than the permit below
                    try b.add(layer_connect_v4, FWP_ACTION_BLOCK, 12, &dns_there);
                }
                const there = [_]FWPM_FILTER_CONDITION0{.{ .field = cond_remote_address, .match = FWP_MATCH_EQUAL, .value = .{ .type = FWP_V4_ADDR_MASK, .value = @intFromPtr(m) } }};
                try b.permit(layer_connect_v4, &there);
            }
            if (!o.ipv6_block) {
                const lan6 = [_]FWP_V6_ADDR_AND_MASK{
                    .{ .addr = .{ 0xfe, 0x80 } ++ @as([14]u8, @splat(0)), .prefix = 10 },
                    .{ .addr = .{ 0xfc, 0 } ++ @as([14]u8, @splat(0)), .prefix = 7 },
                    .{ .addr = .{ 0xff, 0 } ++ @as([14]u8, @splat(0)), .prefix = 8 },
                };
                for (&lan6) |*m| {
                    const there = [_]FWPM_FILTER_CONDITION0{.{ .field = cond_remote_address, .match = FWP_MATCH_EQUAL, .value = .{ .type = FWP_V6_ADDR_MASK, .value = @intFromPtr(m) } }};
                    try b.permit(layer_connect_v6, &there);
                }
            }
        }

        // everything else
        try b.add(layer_connect_v4, FWP_ACTION_BLOCK, 0, &.{});
        try b.add(layer_connect_v6, FWP_ACTION_BLOCK, 0, &.{});
    }
};
