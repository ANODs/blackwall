//! libblackwall.so: the native functions the Android shell calls.
//!
//!   dev.blackwall.Core.start(int fd)
//!   dev.blackwall.Core.qr(ByteBuffer gray, int w, int h, ByteBuffer out)
//!
//! `fd` is one end of a socket pair; the session (session.zig) serves it on
//! its own thread until the shell closes the other end. `qr` reads a QR
//! code in a camera frame or a picture (direct buffers: the only thing of
//! the JNI environment used is their address).

const std = @import("std");
const core = @import("core");
const session = @import("session.zig");

const c = std.c;

pub const std_options: std.Options = .{ .logFn = logFn };

extern "log" fn __android_log_write(prio: c_int, tag: [*:0]const u8, text: [*:0]const u8) c_int;

/// The log goes to logcat (tag "blackwall"): `adb logcat -s blackwall`.
fn logFn(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime format: []const u8, args: anytype) void {
    var buf: [640]u8 = undefined;
    var w: std.Io.Writer = .fixed(buf[0 .. buf.len - 1]);
    w.print("(" ++ @tagName(scope) ++ ") " ++ format, args) catch {};
    const n = w.buffered().len;
    buf[n] = 0;
    // ANDROID_LOG_DEBUG = 3 ... ANDROID_LOG_ERROR = 6
    const prio: c_int = switch (level) {
        .debug => 3,
        .info => 4,
        .warn => 5,
        .err => 6,
    };
    _ = __android_log_write(prio, "blackwall", @ptrCast(&buf));
}

export fn Java_dev_blackwall_Core_start(env: ?*anyopaque, class: ?*anyopaque, fd: c_int) callconv(.c) void {
    _ = env;
    _ = class;
    const th = std.Thread.spawn(.{ .stack_size = 1024 * 1024 }, serve, .{fd}) catch {
        _ = c.close(fd);
        return;
    };
    th.detach();
}

fn serve(fd: c_int) void {
    const gpa = std.heap.c_allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    var s: session.Session = .init(gpa, threaded.io(), fd);
    s.run();
    s.deinit();
    _ = c.close(fd);
}

/// JNIEnv: a pointer to the table of the environment's functions.
const JniEnv = *const *const [240]?*const anyopaque;
const GetDirectBufferAddress = *const fn (JniEnv, ?*anyopaque) callconv(.c) ?[*]u8;
const GetDirectBufferCapacity = *const fn (JniEnv, ?*anyopaque) callconv(.c) i64;

/// The text of a QR code in `gray` (w×h bytes) into `out`: its length, or
/// -1 when there is none.
/// A report's text without secrets (core/diag.zig): `in` holds `n` bytes of
/// UTF-8, the result goes to `out`. Its length, or -1 when it does not fit.
export fn Java_dev_blackwall_Core_scrub(env: JniEnv, class: ?*anyopaque, in: ?*anyopaque, n: c_int, out: ?*anyopaque) callconv(.c) c_int {
    _ = class;
    const fns = env.*;
    const address: GetDirectBufferAddress = @ptrCast(@alignCast(fns[230] orelse return -1));
    const capacity: GetDirectBufferCapacity = @ptrCast(@alignCast(fns[231] orelse return -1));
    if (n < 0) return -1;
    const len: usize = @intCast(n);
    const in_ptr = address(env, in) orelse return -1;
    if (capacity(env, in) < len) return -1;
    const out_ptr = address(env, out) orelse return -1;
    const out_len: usize = @intCast(@max(0, capacity(env, out)));
    var w: std.Io.Writer = .fixed(out_ptr[0..out_len]);
    var key: [8]u8 = undefined;
    std.c.arc4random_buf(&key, key.len);
    const s: core.diag.Scrub = .{ .key = std.mem.readInt(u64, &key, .little) };
    s.write(&w, in_ptr[0..len]) catch return -1;
    return @intCast(w.buffered().len);
}

export fn Java_dev_blackwall_Core_qr(env: JniEnv, class: ?*anyopaque, gray: ?*anyopaque, w: c_int, h: c_int, out: ?*anyopaque) callconv(.c) c_int {
    _ = class;
    const fns = env.*;
    const address: GetDirectBufferAddress = @ptrCast(@alignCast(fns[230] orelse return -1));
    const capacity: GetDirectBufferCapacity = @ptrCast(@alignCast(fns[231] orelse return -1));
    if (w <= 0 or h <= 0) return -1;
    const n: usize = @intCast(w * h);
    const in_ptr = address(env, gray) orelse return -1;
    if (capacity(env, gray) < n) return -1;
    const out_ptr = address(env, out) orelse return -1;
    const out_len: usize = @intCast(@max(0, capacity(env, out)));
    var text_buf: [4096]u8 = undefined;
    const text = core.qr.decode(std.heap.c_allocator, in_ptr[0..n], @intCast(w), @intCast(h), &text_buf) catch return -1;
    if (text.len > out_len) return -1;
    @memcpy(out_ptr[0..text.len], text);
    return @intCast(text.len);
}
