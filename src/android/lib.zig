//! libblackwall.so: the one native function the Android shell calls.
//!
//!   dev.blackwall.Core.start(int fd)
//!
//! `fd` is one end of a socket pair; the session (session.zig) serves it on
//! its own thread until the shell closes the other end. The function takes
//! nothing but a number, so nothing here touches the JNI environment.

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
