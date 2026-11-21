//! The Chrome disguise the HTTP transports share (WebSocket, HTTPUpgrade,
//! gRPC, XHTTP): which Chrome we say we are, as Xray says it
//! (common/utils/browser.go), so a request of ours and one of Xray's look
//! the same to whoever watches.

const std = @import("std");
const Io = std.Io;

/// Chrome's major version as Xray derives it from the date: 144 on
/// 2026-01-13, one more every 35 days after a 35-day lag. Xray adds a
/// random lag of up to 105 days, fixed per machine; we add none and claim
/// the newest version, which most Chrome installations run.
pub fn chromeMajor(now_s: i64) u32 {
    const days = @divFloor(now_s, 86400) - 20466; // 2026-01-13
    return 144 + @as(u32, @intCast(@max(0, @divTrunc(days - 35, 35))));
}

/// Xray's ChromeUA for Chrome `v`.
pub fn writeUserAgent(w: *Io.Writer, v: u32) Io.Writer.Error!void {
    try w.print("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " ++
        "Chrome/{d}.0.0.0 Safari/537.36", .{v});
}

/// Sec-CH-UA for Chrome `v` the way Chromium greases it (seeded by the
/// version): a made-up brand, Chromium and Google Chrome, in an order that
/// depends on the version.
pub fn writeBrands(w: *Io.Writer, v: u32) Io.Writer.Error!void {
    const grease = " (:-./);=?_";
    const grease_versions = [_][]const u8{ "8", "99", "24" };
    const orders = [6][3]u2{ .{ 0, 1, 2 }, .{ 0, 2, 1 }, .{ 1, 0, 2 }, .{ 1, 2, 0 }, .{ 2, 0, 1 }, .{ 2, 1, 0 } };
    // brand i goes to place order[i]
    var at: [3]u2 = undefined;
    for (orders[v % 6], 0..) |place, i| at[place] = @intCast(i);
    for (at, 0..) |brand, i| {
        if (i > 0) try w.writeAll(", ");
        switch (brand) {
            0 => try w.print("\"Not{c}A{c}Brand\";v=\"{s}\"", .{ grease[v % 11], grease[(v + 1) % 11], grease_versions[v % 3] }),
            1 => try w.print("\"Chromium\";v=\"{d}\"", .{v}),
            else => try w.print("\"Google Chrome\";v=\"{d}\"", .{v}),
        }
    }
}

test "Chrome's version follows the date as Xray's does" {
    const testing = std.testing;
    try testing.expectEqual(@as(u32, 151), chromeMajor(1_794_614_400)); // 2026-11-14
    try testing.expectEqual(@as(u32, 144), chromeMajor(20466 * 86400)); // 2026-01-13
    try testing.expectEqual(@as(u32, 144), chromeMajor((20466 + 69) * 86400 + 86399));
    try testing.expectEqual(@as(u32, 145), chromeMajor((20466 + 70) * 86400));
    try testing.expectEqual(@as(u32, 144), chromeMajor(0)); // a clock that is off
}
