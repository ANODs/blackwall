//! The strict kill switch on Linux: an nftables table that lets traffic out
//! only through the device, to the VPN servers and to the resolvers the
//! service itself asks (the same rules as pf on macOS, src/helper/darwin/pf.zig).
//!
//! The table lives in the kernel, not in the service: when the service dies
//! it stays, and nothing leaves past the VPN until it is removed (`open`, or
//! `blackwall-tun release`). It is written by blackwall-tun, which holds
//! CAP_NET_ADMIN (tun_main.zig).

const std = @import("std");

pub const table = "blackwall";

pub const Options = struct {
    servers4: []const [4]u8,
    dns4: []const [4]u8,
    allow_lan: bool,
    ipv6_block: bool,
};

/// A script for `nft -f -` that replaces the whole table in one transaction.
pub fn rules(gpa: std.mem.Allocator, o: Options) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    // declaring it first makes the delete succeed when it is not there yet
    try w.writeAll("table inet " ++ table ++ "\ndelete table inet " ++ table ++ "\n");
    try w.writeAll("table inet " ++ table ++ " {\n    chain out {\n        type filter hook output priority 0; policy accept;\n");
    try w.writeAll("        oifname \"lo\" accept\n");
    try w.writeAll("        oifname \"blackwall0\" accept\n");
    // DHCP and IPv6 neighbour discovery keep the network itself working
    try w.writeAll("        udp sport 68 udp dport 67 accept\n");
    try w.writeAll("        icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept\n");
    if (o.servers4.len > 0) {
        try w.writeAll("        ip daddr { ");
        try list(w, o.servers4);
        try w.writeAll(" } accept\n");
    }
    if (o.dns4.len > 0) {
        try w.writeAll("        ip daddr { ");
        try list(w, o.dns4);
        try w.writeAll(" } meta l4proto { tcp, udp } th dport 53 accept\n");
    }
    if (o.ipv6_block) try w.writeAll("        meta nfproto ipv6 reject\n");
    if (o.allow_lan) {
        // the local network, but no name lookups past the VPN through it
        try w.writeAll("        meta l4proto { tcp, udp } th dport { 53, 853 } reject\n");
        try w.writeAll("        ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept\n");
        if (!o.ipv6_block) try w.writeAll("        ip6 daddr { fe80::/10, fc00::/7, ff00::/8 } accept\n");
    }
    try w.writeAll("        reject\n    }\n}\n");
    return out.toOwnedSlice();
}

/// A script that removes the table (and is fine when there is none).
pub const open_script = "table inet " ++ table ++ "\ndelete table inet " ++ table ++ "\n";

fn list(w: *std.Io.Writer, ips: []const [4]u8) !void {
    for (ips, 0..) |ip, i| {
        if (i > 0) try w.writeAll(", ");
        try w.print("{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
    }
}

/// "a.b.c.d,e.f.g.h" → addresses, skipping what does not parse.
pub fn parseList(text: []const u8, out: [][4]u8) usize {
    var n: usize = 0;
    var it = std.mem.tokenizeScalar(u8, text, ',');
    while (it.next()) |t| {
        if (n == out.len) break;
        const ip = std.Io.net.Ip4Address.parse(t, 0) catch continue;
        out[n] = ip.bytes;
        n += 1;
    }
    return n;
}

test "strict: device, servers and resolvers only" {
    const gpa = std.testing.allocator;
    const text = try rules(gpa, .{ .servers4 = &.{.{ 203, 0, 113, 7 }}, .dns4 = &.{ .{ 192, 168, 1, 1 }, .{ 1, 1, 1, 1 } }, .allow_lan = false, .ipv6_block = true });
    defer gpa.free(text);
    try std.testing.expectEqualStrings(
        \\table inet blackwall
        \\delete table inet blackwall
        \\table inet blackwall {
        \\    chain out {
        \\        type filter hook output priority 0; policy accept;
        \\        oifname "lo" accept
        \\        oifname "blackwall0" accept
        \\        udp sport 68 udp dport 67 accept
        \\        icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
        \\        ip daddr { 203.0.113.7 } accept
        \\        ip daddr { 192.168.1.1, 1.1.1.1 } meta l4proto { tcp, udp } th dport 53 accept
        \\        meta nfproto ipv6 reject
        \\        reject
        \\    }
        \\}
        \\
    , text);
}

test "strict with the local network and IPv6 through the tunnel" {
    const gpa = std.testing.allocator;
    const text = try rules(gpa, .{ .servers4 = &.{}, .dns4 = &.{}, .allow_lan = true, .ipv6_block = false });
    defer gpa.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "th dport { 53, 853 } reject\n        ip daddr { 10.0.0.0/8") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "ip6 daddr { fe80::/10") != null);
    // no empty sets: nft refuses them
    try std.testing.expect(std.mem.indexOf(u8, text, "{  }") == null);
}

test "address lists from the command line" {
    var out: [4][4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 2), parseList("1.2.3.4,bad,5.6.7.8", &out));
    try std.testing.expectEqualSlices(u8, &.{ 5, 6, 7, 8 }, &out[1]);
}
