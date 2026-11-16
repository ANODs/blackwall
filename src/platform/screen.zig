//! Finding a QR code to add a subscription from: a picture on the
//! clipboard (a screenshot copied, an image copied from a chat), else
//! what is on the screen.
//!
//!   macOS    screencapture(1), after the system's Screen Recording consent
//!   Windows  the desktop through GDI
//!   Linux    grim (Wayland) or import (X11), when one is installed

const std = @import("std");
const builtin = @import("builtin");
const dvui = @import("dvui");
const core = @import("core");

const c = dvui.backend.c;

pub const Result = union(enum) {
    /// the text of a code; the caller frees it
    text: []u8,
    /// no code anywhere
    none,
    /// macOS: the screen may not be read yet; the system asked the user
    needs_permission,
};

pub fn scan(gpa: std.mem.Allocator, io: std.Io) Result {
    if (fromClipboard(gpa)) |t| return .{ .text = t };
    return fromScreen(gpa, io);
}

// ---------------------------------------------------------------- the clipboard

fn fromClipboard(gpa: std.mem.Allocator) ?[]u8 {
    for ([_][*:0]const u8{ "image/png", "image/jpeg", "image/bmp" }) |mime| {
        if (!c.SDL_HasClipboardData(mime)) continue;
        var size: usize = 0;
        const data = c.SDL_GetClipboardData(mime, &size) orelse continue;
        defer c.SDL_free(data);
        const bytes: [*]const u8 = @ptrCast(data);
        if (fromImageFile(gpa, bytes[0..size])) |t| return t;
    }
    return null;
}

/// A PNG, JPEG or BMP file's bytes.
fn fromImageFile(gpa: std.mem.Allocator, bytes: []const u8) ?[]u8 {
    var w: c_int = 0;
    var h: c_int = 0;
    var ch: c_int = 0;
    const px = dvui.c.stbi_load_from_memory(bytes.ptr, @intCast(bytes.len), &w, &h, &ch, 1) orelse return null;
    defer dvui.c.stbi_image_free(px);
    return fromGray(gpa, px[0..@intCast(w * h)], @intCast(w), @intCast(h));
}

/// Large pictures are halved until the reader's blocks cover them.
fn fromGray(gpa: std.mem.Allocator, gray: []const u8, w: usize, h: usize) ?[]u8 {
    var out: [4096]u8 = undefined;
    if (w <= 4096 and h <= 4096) {
        const text = core.qr.decode(gpa, gray, w, h, &out) catch return null;
        return gpa.dupe(u8, text) catch null;
    }
    const hw = w / 2;
    const hh = h / 2;
    const half = gpa.alloc(u8, hw * hh) catch return null;
    defer gpa.free(half);
    for (0..hh) |y| for (0..hw) |x| {
        const s: u16 = @as(u16, gray[2 * y * w + 2 * x]) + gray[2 * y * w + 2 * x + 1] + gray[(2 * y + 1) * w + 2 * x] + gray[(2 * y + 1) * w + 2 * x + 1];
        half[y * hw + x] = @intCast(s / 4);
    };
    return fromGray(gpa, half, hw, hh);
}

// ---------------------------------------------------------------- the screen

fn fromScreen(gpa: std.mem.Allocator, io: std.Io) Result {
    return switch (builtin.os.tag) {
        .macos => macScreen(gpa, io),
        .windows => if (winScreen(gpa)) |t| .{ .text = t } else .none,
        .linux => if (linuxScreen(gpa, io)) |t| .{ .text = t } else .none,
        else => .none,
    };
}

extern "c" fn CGPreflightScreenCaptureAccess() bool;
extern "c" fn CGRequestScreenCaptureAccess() bool;

fn macScreen(gpa: std.mem.Allocator, io: std.Io) Result {
    if (comptime builtin.os.tag != .macos) return .none;
    if (!CGPreflightScreenCaptureAccess()) {
        // the system's dialog; the consent counts from the next start
        _ = CGRequestScreenCaptureAccess();
        return .needs_permission;
    }
    // one file a display: name.png, name 2.png, ...
    var dir_buf: [64]u8 = undefined;
    var rnd: [6]u8 = undefined;
    io.random(&rnd);
    const dir = std.fmt.bufPrint(&dir_buf, "/tmp/blackwall-qr-{x}", .{rnd}) catch return .none;
    std.Io.Dir.cwd().createDirPath(io, dir) catch return .none;
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var files: [8][96]u8 = undefined;
    var argv: [10][]const u8 = undefined;
    argv[0] = "/usr/sbin/screencapture";
    argv[1] = "-x";
    var n: usize = 0;
    while (n < files.len) : (n += 1) {
        argv[2 + n] = std.fmt.bufPrint(&files[n], "{s}/{d}.png", .{ dir, n }) catch break;
    }
    var child = std.process.spawn(io, .{ .argv = argv[0 .. 2 + n], .stdin = .ignore, .stdout = .ignore, .stderr = .ignore }) catch return .none;
    _ = child.wait(io) catch return .none;
    for (argv[2 .. 2 + n]) |path| {
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(256 << 20)) catch continue;
        defer gpa.free(bytes);
        if (fromImageFile(gpa, bytes)) |t| return .{ .text = t };
    }
    return .none;
}

fn linuxScreen(gpa: std.mem.Allocator, io: std.Io) ?[]u8 {
    if (comptime builtin.os.tag != .linux) return null;
    const tools = [_][]const []const u8{
        &.{ "grim", "-t", "png", "-" },
        &.{ "import", "-window", "root", "png:-" },
    };
    for (tools) |argv| {
        var child = std.process.spawn(io, .{ .argv = argv, .stdin = .ignore, .stdout = .pipe, .stderr = .ignore }) catch continue;
        var buf: [64 * 1024]u8 = undefined;
        var r = child.stdout.?.readerStreaming(io, &buf);
        const bytes = r.interface.allocRemaining(gpa, .limited(256 << 20)) catch {
            _ = child.wait(io) catch {};
            continue;
        };
        defer gpa.free(bytes);
        _ = child.wait(io) catch {};
        if (fromImageFile(gpa, bytes)) |t| return t;
    }
    return null;
}

const win = struct {
    const W: std.builtin.CallingConvention = .winapi;
    const H = ?*anyopaque;
    extern "user32" fn GetDC(hwnd: H) callconv(W) H;
    extern "user32" fn ReleaseDC(hwnd: H, dc: H) callconv(W) i32;
    extern "user32" fn GetSystemMetrics(i: i32) callconv(W) i32;
    extern "gdi32" fn CreateCompatibleDC(dc: H) callconv(W) H;
    extern "gdi32" fn CreateCompatibleBitmap(dc: H, w: i32, h: i32) callconv(W) H;
    extern "gdi32" fn SelectObject(dc: H, obj: H) callconv(W) H;
    extern "gdi32" fn BitBlt(dst: H, x: i32, y: i32, w: i32, h: i32, src: H, sx: i32, sy: i32, rop: u32) callconv(W) i32;
    extern "gdi32" fn GetDIBits(dc: H, bmp: H, start: u32, lines: u32, bits: ?*anyopaque, info: *BITMAPINFO, usage: u32) callconv(W) i32;
    extern "gdi32" fn DeleteObject(obj: H) callconv(W) i32;
    extern "gdi32" fn DeleteDC(dc: H) callconv(W) i32;
    const BITMAPINFO = extern struct {
        size: u32 = @sizeOf(BITMAPINFO) - 4,
        width: i32,
        height: i32,
        planes: u16 = 1,
        bit_count: u16 = 32,
        compression: u32 = 0,
        size_image: u32 = 0,
        x_ppm: i32 = 0,
        y_ppm: i32 = 0,
        clr_used: u32 = 0,
        clr_important: u32 = 0,
        colors: u32 = 0,
    };
};

fn winScreen(gpa: std.mem.Allocator) ?[]u8 {
    if (comptime builtin.os.tag != .windows) return null;
    // the whole virtual desktop, every monitor
    const x = win.GetSystemMetrics(76);
    const y = win.GetSystemMetrics(77);
    const w = win.GetSystemMetrics(78);
    const h = win.GetSystemMetrics(79);
    if (w <= 0 or h <= 0) return null;
    const screen = win.GetDC(null) orelse return null;
    defer _ = win.ReleaseDC(null, screen);
    const mem = win.CreateCompatibleDC(screen) orelse return null;
    defer _ = win.DeleteDC(mem);
    const bmp = win.CreateCompatibleBitmap(screen, w, h) orelse return null;
    defer _ = win.DeleteObject(bmp);
    const old = win.SelectObject(mem, bmp);
    // SRCCOPY | CAPTUREBLT
    if (win.BitBlt(mem, 0, 0, w, h, screen, x, y, 0x00CC0020 | 0x40000000) == 0) return null;
    _ = win.SelectObject(mem, old);
    const uw: usize = @intCast(w);
    const uh: usize = @intCast(h);
    const bgra = gpa.alloc(u8, uw * uh * 4) catch return null;
    defer gpa.free(bgra);
    var info: win.BITMAPINFO = .{ .width = w, .height = -h };
    if (win.GetDIBits(mem, bmp, 0, @intCast(h), bgra.ptr, &info, 0) == 0) return null;
    const gray = gpa.alloc(u8, uw * uh) catch return null;
    defer gpa.free(gray);
    for (gray, 0..) |*g, i| {
        const p = bgra[i * 4 ..][0..3];
        g.* = @intCast((@as(u32, p[0]) * 29 + @as(u32, p[1]) * 150 + @as(u32, p[2]) * 77) >> 8);
    }
    return fromGray(gpa, gray, uw, uh);
}
