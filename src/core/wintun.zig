//! Wintun (www.wintun.net): the layer-3 virtual adapter of WireGuard for
//! Windows, the TUN device there. wintun.dll is loaded at run time from
//! the folder the service keeps it in; the adapter is created once and
//! kept, a session is a pair of rings in our own memory that packets are
//! read from and written to.

const std = @import("std");
const builtin = @import("builtin");
const w = std.os.windows;

pub const Adapter = *opaque {};
pub const Session = *opaque {};

pub const NET_LUID = u64;

const W: std.builtin.CallingConvention = .winapi;
extern "kernel32" fn LoadLibraryExW(name: [*:0]const u16, file: ?w.HANDLE, flags: u32) callconv(W) ?w.HMODULE;
extern "kernel32" fn GetProcAddress(module: w.HMODULE, name: [*:0]const u8) callconv(W) ?*const anyopaque;
extern "kernel32" fn GetLastError() callconv(W) u32;
extern "kernel32" fn SetLastError(code: u32) callconv(W) void;
extern "kernel32" fn CreateEventW(attrs: ?*anyopaque, manual: i32, initial: i32, name: ?[*:0]const u16) callconv(W) ?w.HANDLE;
extern "kernel32" fn SetEvent(ev: w.HANDLE) callconv(W) i32;
extern "kernel32" fn WaitForMultipleObjects(count: u32, handles: [*]const w.HANDLE, all: i32, ms: u32) callconv(W) u32;

const ERROR_NO_MORE_ITEMS = 259;
const ERROR_HANDLE_EOF = 38;
const LOAD_WITH_ALTERED_SEARCH_PATH = 0x8;

/// The functions of wintun.dll.
pub const Api = struct {
    createAdapter: *const fn (name: [*:0]const u16, tunnel_type: [*:0]const u16, guid: ?*const w.GUID) callconv(W) ?Adapter,
    openAdapter: *const fn (name: [*:0]const u16) callconv(W) ?Adapter,
    closeAdapter: *const fn (a: Adapter) callconv(W) void,
    getAdapterLuid: *const fn (a: Adapter, luid: *NET_LUID) callconv(W) void,
    getRunningDriverVersion: *const fn () callconv(W) u32,
    startSession: *const fn (a: Adapter, capacity: u32) callconv(W) ?Session,
    endSession: *const fn (s: Session) callconv(W) void,
    getReadWaitEvent: *const fn (s: Session) callconv(W) w.HANDLE,
    receivePacket: *const fn (s: Session, size: *u32) callconv(W) ?[*]u8,
    releaseReceivePacket: *const fn (s: Session, p: [*]const u8) callconv(W) void,
    allocateSendPacket: *const fn (s: Session, size: u32) callconv(W) ?[*]u8,
    sendPacket: *const fn (s: Session, p: [*]const u8) callconv(W) void,

    var loaded: ?Api = null;

    /// Loads wintun.dll from `path` (once per process).
    pub fn load(path: []const u8) !*const Api {
        if (loaded) |*a| return a;
        var wide: [std.fs.max_path_bytes:0]u16 = undefined;
        const n = std.unicode.wtf8ToWtf16Le(&wide, path) catch return error.BadPath;
        wide[n] = 0;
        const m = LoadLibraryExW(wide[0..n :0], null, LOAD_WITH_ALTERED_SEARCH_PATH) orelse return error.WintunMissing;
        var api: Api = undefined;
        inline for (.{
            .{ "createAdapter", "WintunCreateAdapter" },
            .{ "openAdapter", "WintunOpenAdapter" },
            .{ "closeAdapter", "WintunCloseAdapter" },
            .{ "getAdapterLuid", "WintunGetAdapterLUID" },
            .{ "getRunningDriverVersion", "WintunGetRunningDriverVersion" },
            .{ "startSession", "WintunStartSession" },
            .{ "endSession", "WintunEndSession" },
            .{ "getReadWaitEvent", "WintunGetReadWaitEvent" },
            .{ "receivePacket", "WintunReceivePacket" },
            .{ "releaseReceivePacket", "WintunReleaseReceivePacket" },
            .{ "allocateSendPacket", "WintunAllocateSendPacket" },
            .{ "sendPacket", "WintunSendPacket" },
        }) |f| {
            const p = GetProcAddress(m, f[1]) orelse return error.WintunMissing;
            @field(api, f[0]) = @ptrCast(p);
        }
        loaded = api;
        return &loaded.?;
    }
};

pub fn lastError() u32 {
    return GetLastError();
}

/// The adapter called `name`, created when it is not there yet. Creating
/// one installs the driver the first time; both need an administrator.
pub fn adapter(api: *const Api, name: []const u8, guid: *const w.GUID) !Adapter {
    var wide: [128:0]u16 = undefined;
    const n = std.unicode.wtf8ToWtf16Le(&wide, name) catch return error.BadName;
    wide[n] = 0;
    if (api.openAdapter(wide[0..n :0])) |a| return a;
    return api.createAdapter(wide[0..n :0], std.unicode.utf8ToUtf16LeStringLiteral("BLACKWALL"), guid) orelse error.AdapterFailed;
}

/// A session on an adapter: the rings, the event that says packets wait,
/// and one of ours that wakes the reader.
pub const Device = struct {
    api: *const Api,
    session: Session,
    wake_event: w.HANDLE,
    dropped: std.atomic.Value(u64) = .init(0),

    /// 4 MiB rings: room for a burst at gigabit speed.
    pub const capacity = 0x400000;

    pub fn init(api: *const Api, a: Adapter) !Device {
        const s = api.startSession(a, capacity) orelse return error.SessionFailed;
        const ev = CreateEventW(null, 0, 0, null) orelse {
            api.endSession(s);
            return error.SessionFailed;
        };
        return .{ .api = api, .session = s, .wake_event = ev };
    }

    pub fn deinit(d: *Device) void {
        d.api.endSession(d.session);
        w.CloseHandle(d.wake_event);
    }

    pub const Woke = enum { packets, woken, time };

    /// Waits for packets, or `wake`, at most `ms`; says which came.
    pub fn wait(d: *Device, ms: u32) Woke {
        const hs = [2]w.HANDLE{ d.api.getReadWaitEvent(d.session), d.wake_event };
        return switch (WaitForMultipleObjects(2, &hs, 0, ms)) {
            0 => .packets,
            1 => .woken,
            else => .time,
        };
    }

    pub fn wake(d: *Device) void {
        _ = SetEvent(d.wake_event);
    }

    /// The next packet, copied into `buf`; null when none waits (or the
    /// adapter went away).
    pub fn read(d: *Device, buf: []u8) ?[]u8 {
        var size: u32 = 0;
        const p = d.api.receivePacket(d.session, &size) orelse return null;
        defer d.api.releaseReceivePacket(d.session, p);
        if (size > buf.len) return buf[0..0];
        @memcpy(buf[0..size], p[0..size]);
        return buf[0..size];
    }

    pub fn write(d: *Device, pkt: []const u8) void {
        if (pkt.len == 0) return;
        const p = d.api.allocateSendPacket(d.session, @intCast(pkt.len)) orelse {
            // the ring is full or the adapter is gone
            _ = d.dropped.fetchAdd(1, .monotonic);
            return;
        };
        @memcpy(p[0..pkt.len], pkt);
        d.api.sendPacket(d.session, p);
    }
};
