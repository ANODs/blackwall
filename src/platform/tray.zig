//! The menu bar (macOS) or notification area (Windows, Linux) item: the
//! state of the connection at a glance and the two or three things one
//! does without opening the window.
//!
//!   VPN is on · Netherlands          (what is going on, and through where;
//!                                     "· Germany" after it when the server
//!                                     was seen to exit elsewhere)
//!   ↓ 12.4 Mbit/s  ↑ 1.1 Mbit/s      (current speed)
//!   ─────────
//!   Disconnect / Connect
//!   Open BLACKWALL
//!   Quit
//!
//! With the item there, closing the window only hides it: the app keeps
//! running behind the item. The VPN itself never depended on the window
//! (the background service carries it); Quit leaves it as it is, too.
//!
//! SDL draws the item natively on each system. Where the system has no
//! such area (some Linux desktops) there is no item, and closing the window
//! quits as before.

const std = @import("std");
const dvui = @import("dvui");
const core = @import("core");
const app = @import("../app.zig");
const tr = @import("../i18n.zig").t;
const countries = @import("../countries.zig");

const c = dvui.backend.c;

var tray: ?*c.SDL_Tray = null;
var window: ?*c.SDL_Window = null;
var e_status: ?*c.SDL_TrayEntry = null;
var e_speed: ?*c.SDL_TrayEntry = null;
var e_toggle: ?*c.SDL_TrayEntry = null;

/// The window is hidden behind the item: nothing needs drawing.
pub var hidden = false;

/// What the menu shows now, to touch the system only when it changes.
var shown_status: [160]u8 = undefined;
var shown_status_len: usize = 0;
var shown_speed: [96]u8 = undefined;
var shown_speed_len: usize = 0;
var shown_on: ?bool = null;
var shown_look: ?Look = null;

/// Clicks arrive between frames; the frame acts on them.
var want_toggle = std.atomic.Value(bool).init(false);
var want_open = std.atomic.Value(bool).init(false);

const Look = enum { off, guard, busy, on, blocked };

const icon_px = 44;
const looks = std.enums.values(Look).len;
var icons: [looks][icon_px * icon_px * 4]u8 = undefined;
var surfaces: [looks]?*c.SDL_Surface = @splat(null);

/// Create the item. Call once the window exists.
pub fn init() void {
    if (tray != null or !app.persist) return;
    var n: c_int = 0;
    const list = c.SDL_GetWindows(&n);
    if (list != null) {
        if (n > 0) window = list[0];
        c.SDL_free(@ptrCast(list));
    }
    for (std.enums.values(Look)) |look| {
        const i = @intFromEnum(look);
        paint(&icons[i], look);
        surfaces[i] = c.SDL_CreateSurfaceFrom(icon_px, icon_px, c.SDL_PIXELFORMAT_RGBA32, &icons[i], icon_px * 4);
    }
    const t = c.SDL_CreateTray(surfaces[@intFromEnum(Look.off)], "BLACKWALL") orelse return;
    const menu = c.SDL_CreateTrayMenu(t) orelse {
        c.SDL_DestroyTray(t);
        return;
    };
    tray = t;
    e_status = c.SDL_InsertTrayEntryAt(menu, -1, "BLACKWALL", c.SDL_TRAYENTRY_BUTTON | c.SDL_TRAYENTRY_DISABLED);
    e_speed = c.SDL_InsertTrayEntryAt(menu, -1, " ", c.SDL_TRAYENTRY_BUTTON | c.SDL_TRAYENTRY_DISABLED);
    _ = c.SDL_InsertTrayEntryAt(menu, -1, null, 0); // separator
    e_toggle = c.SDL_InsertTrayEntryAt(menu, -1, z(tr.tray_connect), c.SDL_TRAYENTRY_BUTTON);
    const open = c.SDL_InsertTrayEntryAt(menu, -1, z(tr.tray_open), c.SDL_TRAYENTRY_BUTTON);
    const quit = c.SDL_InsertTrayEntryAt(menu, -1, z(tr.tray_quit), c.SDL_TRAYENTRY_BUTTON);
    c.SDL_SetTrayEntryCallback(e_toggle, onToggle, null);
    c.SDL_SetTrayEntryCallback(open, onOpen, null);
    c.SDL_SetTrayEntryCallback(quit, onQuit, null);
    // from now on closing the window hides it
    c.SDL_SetEventFilter(onEvent, null);
}

pub fn deinit() void {
    if (tray) |t| {
        c.SDL_SetEventFilter(null, null);
        c.SDL_DestroyTray(t);
        tray = null;
    }
    for (&surfaces) |*s| {
        if (s.*) |x| c.SDL_DestroySurface(x);
        s.* = null;
    }
}

/// Once per frame: act on clicks, and keep the item's texts current.
pub fn frame() void {
    if (tray == null) return;
    if (want_open.swap(false, .acq_rel)) show();
    if (want_toggle.swap(false, .acq_rel)) {
        if (app.state.servers.items.len == 0) {
            app.go(.servers);
            show();
        } else app.toggle();
    }
    update();
}

fn update() void {
    const e = &app.engine;
    const look: Look = switch (e.status) {
        .connected => .on,
        .connecting, .reconnecting => .busy,
        .blocked => .blocked,
        .disconnected => if (app.guarding()) .guard else .off,
    };
    if (shown_look != look) {
        shown_look = look;
        c.SDL_SetTrayIcon(tray, surfaces[@intFromEnum(look)]);
    }

    var buf: [160]u8 = undefined;
    const state_text = switch (e.status) {
        .connected => tr.st_on,
        .connecting => tr.st_connecting,
        .reconnecting => tr.st_reconnecting,
        .blocked => tr.st_blocked,
        .disconnected => if (app.guarding()) tr.st_guard else tr.st_disconnected,
    };
    const server = if (e.status == .connected) app.shownServer() else null;
    const status = if (server) |sv| blk: {
        // and where it really exits, when that is not what its name says
        if (app.otherExit(sv)) |cc| {
            const real = countries.name(cc) orelse &cc;
            break :blk std.fmt.bufPrint(buf[0 .. buf.len - 1], "{s} · {s} · {s}", .{ state_text, sv.name, real }) catch state_text;
        }
        break :blk std.fmt.bufPrint(buf[0 .. buf.len - 1], "{s} · {s}", .{ state_text, sv.name }) catch state_text;
    } else state_text;
    if (!std.mem.eql(u8, status, shown_status[0..shown_status_len])) {
        shown_status_len = @min(status.len, shown_status.len - 1);
        @memcpy(shown_status[0..shown_status_len], status[0..shown_status_len]);
        shown_status[shown_status_len] = 0;
        c.SDL_SetTrayEntryLabel(e_status, @ptrCast(&shown_status));
        c.SDL_SetTrayTooltip(tray, @ptrCast(&shown_status));
    }

    var speed_buf: [96]u8 = undefined;
    const speed = if (e.status == .connected or app.guarding()) blk: {
        const d = core.fmt.rate(e.down_bps);
        const u = core.fmt.rate(e.up_bps);
        break :blk std.fmt.bufPrint(speed_buf[0 .. speed_buf.len - 1], "↓ {s} {s}   ↑ {s} {s}", .{ d.value(), d.unit, u.value(), u.unit }) catch " ";
    } else " ";
    if (!std.mem.eql(u8, speed, shown_speed[0..shown_speed_len])) {
        shown_speed_len = @min(speed.len, shown_speed.len - 1);
        @memcpy(shown_speed[0..shown_speed_len], speed[0..shown_speed_len]);
        shown_speed[shown_speed_len] = 0;
        c.SDL_SetTrayEntryLabel(e_speed, @ptrCast(&shown_speed));
    }

    // the button says what a click will do
    const on = !(e.status == .disconnected or e.status == .blocked);
    if (shown_on != on) {
        shown_on = on;
        c.SDL_SetTrayEntryLabel(e_toggle, z(if (on) tr.tray_disconnect else tr.tray_connect));
    }
}

fn show() void {
    const w = window orelse return;
    hidden = false;
    _ = c.SDL_ShowWindow(w);
    _ = c.SDL_RaiseWindow(w);
}

/// Wake the frame loop: it sleeps until an event or a timer.
fn wake() void {
    dvui.refresh(app.win, @src(), null);
}

fn onToggle(_: ?*anyopaque, _: ?*c.SDL_TrayEntry) callconv(.c) void {
    want_toggle.store(true, .release);
    wake();
}

fn onOpen(_: ?*anyopaque, _: ?*c.SDL_TrayEntry) callconv(.c) void {
    want_open.store(true, .release);
    wake();
}

fn onQuit(_: ?*anyopaque, _: ?*c.SDL_TrayEntry) callconv(.c) void {
    var ev: c.SDL_Event = std.mem.zeroes(c.SDL_Event);
    ev.type = c.SDL_EVENT_QUIT;
    _ = c.SDL_PushEvent(&ev);
}

/// Closing the window hides it instead; everything else passes.
fn onEvent(_: ?*anyopaque, ev: [*c]c.SDL_Event) callconv(.c) bool {
    if (ev.*.type != c.SDL_EVENT_WINDOW_CLOSE_REQUESTED or tray == null) return true;
    const w = c.SDL_GetWindowFromID(ev.*.window.windowID) orelse return true;
    window = w;
    hidden = true;
    _ = c.SDL_HideWindow(w);
    return false;
}

/// A translated text as the C string SDL wants (all of them are literals,
/// so each is copied once into a small table and kept).
fn z(text: []const u8) [*c]const u8 {
    const Slot = struct { src: []const u8 = "", buf: [64]u8 = undefined };
    const S = struct {
        var slots: [6]Slot = @splat(.{});
    };
    for (&S.slots) |*s| {
        if (s.src.ptr == text.ptr and s.src.len == text.len) return @ptrCast(&s.buf);
        if (s.src.len != 0) continue;
        const n = @min(text.len, s.buf.len - 1);
        @memcpy(s.buf[0..n], text[0..n]);
        s.buf[n] = 0;
        s.src = text;
        return @ptrCast(&s.buf);
    }
    return "BLACKWALL";
}

/// The item's picture: a ring, with a dot in the middle that tells the
/// state by its colour. Drawn here so that no image file is needed and the
/// greys read on a light menu bar as well as on a dark one.
fn paint(px: *[icon_px * icon_px * 4]u8, look: Look) void {
    const ring: [3]u8 = .{ 142, 142, 147 };
    const dot: ?[3]u8 = switch (look) {
        .off => null,
        .guard => ring,
        .busy => .{ 255, 179, 64 },
        .on => .{ 48, 209, 88 },
        .blocked => .{ 255, 69, 58 },
    };
    const mid: f32 = icon_px / 2.0;
    for (0..icon_px) |y| for (0..icon_px) |x| {
        const dx = @as(f32, @floatFromInt(x)) + 0.5 - mid;
        const dy = @as(f32, @floatFromInt(y)) + 0.5 - mid;
        const d = @sqrt(dx * dx + dy * dy);
        // ring: radius 15, 3.5 thick; dot: radius 6.5; edges one pixel soft
        const ring_a = std.math.clamp(1.75 + 0.5 - @abs(d - 15.0), 0, 1);
        const dot_a: f32 = if (dot != null) std.math.clamp(6.5 + 0.5 - d, 0, 1) else 0;
        const col = if (dot_a > 0) dot.? else ring;
        const a = @max(ring_a, dot_a);
        const o = (y * icon_px + x) * 4;
        px[o] = col[0];
        px[o + 1] = col[1];
        px[o + 2] = col[2];
        px[o + 3] = @intFromFloat(a * 255);
    };
}
