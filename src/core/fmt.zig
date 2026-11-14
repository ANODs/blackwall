//! Compact number formatting for the UI: value and unit are returned
//! separately so the unit can be drawn dimmer than the number.

const std = @import("std");

pub const Quantity = struct {
    buf: [12]u8 = undefined,
    len: usize = 0,
    unit: []const u8 = "",

    pub fn value(q: *const Quantity) []const u8 {
        return q.buf[0..q.len];
    }
};

fn scaled(v: f64, units: []const []const u8, base: f64) Quantity {
    var x = v;
    var u: usize = 0;
    while (x >= base and u + 1 < units.len) : (u += 1) x /= base;
    var q: Quantity = .{ .unit = units[u] };
    const s = if (u == 0 or x >= 100)
        std.fmt.bufPrint(&q.buf, "{d:.0}", .{x})
    else if (x >= 10)
        std.fmt.bufPrint(&q.buf, "{d:.1}", .{x})
    else
        std.fmt.bufPrint(&q.buf, "{d:.2}", .{x});
    q.len = if (s) |ok| ok.len else |_| 0;
    return q;
}

/// bytes per second -> bit rate, the way network speeds are usually quoted
pub fn rate(bytes_per_sec: f32) Quantity {
    return scaled(@as(f64, bytes_per_sec) * 8, &.{ "bit/s", "Kbit/s", "Mbit/s", "Gbit/s" }, 1000);
}

pub fn bytes(n: u64) Quantity {
    return scaled(@floatFromInt(n), &.{ "B", "KB", "MB", "GB", "TB" }, 1024);
}

pub fn duration(buf: []u8, secs: u64) []const u8 {
    return std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}:{d:0>2}", .{ secs / 3600, (secs / 60) % 60, secs % 60 }) catch "";
}

test "formatting" {
    try std.testing.expectEqualStrings("12.4", rate(1_550_000).value());
    try std.testing.expectEqualStrings("Mbit/s", rate(1_550_000).unit);
    try std.testing.expectEqualStrings("0", rate(0).value());
    try std.testing.expectEqualStrings("1.50", bytes(1536).value());
    try std.testing.expectEqualStrings("KB", bytes(1536).unit);
    var b: [16]u8 = undefined;
    try std.testing.expectEqualStrings("01:02:03", duration(&b, 3723));
}
