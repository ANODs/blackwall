pub const model = @import("model.zig");
pub const sublink = @import("sublink.zig");
pub const engine = @import("engine.zig");
pub const store = @import("store.zig");
pub const demo = @import("demo.zig");
pub const fmt = @import("fmt.zig");
pub const proxy = @import("proxy.zig");
pub const tls13 = @import("tls13.zig");
pub const ws = @import("ws.zig");
pub const httpupgrade = @import("httpupgrade.zig");
pub const hpack = @import("hpack.zig");
pub const h2 = @import("h2.zig");
pub const grpc = @import("grpc.zig");
pub const xhttp = @import("xhttp.zig");
pub const trojan = @import("trojan.zig");
pub const shadowsocks = @import("shadowsocks.zig");
pub const vmess = @import("vmess.zig");
pub const vision = @import("vision.zig");
pub const xudp = @import("xudp.zig");
pub const sys = @import("sys.zig");
pub const wintun = @import("wintun.zig");
pub const win_scm = @import("win_scm.zig");
pub const tunnel = @import("tunnel.zig");
pub const failover = @import("failover.zig");
pub const ipc = @import("ipc.zig");
pub const helper_ipc = @import("helper_ipc.zig");
pub const ipstack = struct {
    pub const packet = @import("ipstack/packet.zig");
    pub const stack = @import("ipstack/stack.zig");
    pub const dns = @import("ipstack/dns.zig");
};

test {
    _ = model;
    _ = sublink;
    _ = engine;
    _ = store;
    _ = fmt;
    _ = proxy;
    _ = tls13;
    _ = ws;
    _ = httpupgrade;
    _ = hpack;
    _ = h2;
    _ = grpc;
    _ = xhttp;
    _ = trojan;
    _ = shadowsocks;
    _ = vmess;
    _ = vision;
    _ = xudp;
    _ = sys;
    _ = tunnel;
    _ = failover;
    _ = ipc;
    _ = helper_ipc;
    _ = ipstack.packet;
    _ = ipstack.stack;
    _ = ipstack.dns;
}

test "Xray JSON with REALITY + Vision becomes a usable outbound" {
    const std = @import("std");
    const body =
        \\[{"remarks":"🇳🇱 Нидерланды","outbounds":[
        \\  {"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.7","port":443,
        \\    "users":[{"id":"0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0","flow":"xtls-rprx-vision","encryption":"none"}]}]},
        \\   "streamSettings":{"network":"raw","security":"reality","realitySettings":{"serverName":"www.microsoft.com",
        \\     "publicKey":"jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8","shortId":"ab12cd34","fingerprint":"chrome"}}},
        \\  {"protocol":"freedom","tag":"direct"}]}]
    ;
    var parsed = try sublink.parseBody(std.testing.allocator, body);
    defer parsed.deinit();
    const sv = parsed.servers[0];
    try std.testing.expectEqualStrings("NL", &sv.country);
    const v = (try proxy.outboundFromLink(sv.link, sv.host, sv.port)).vless;
    try std.testing.expect(v.vision);
    try std.testing.expectEqualStrings("203.0.113.7", v.host);
    try std.testing.expectEqual(443, v.port);
    try std.testing.expectEqualStrings("www.microsoft.com", v.reality.?.server_name);
    try std.testing.expectEqual(0x8c, v.reality.?.public_key[0]);
    try std.testing.expectEqualSlices(u8, &.{ 0xab, 0x12, 0xcd, 0x34, 0, 0, 0, 0 }, &v.reality.?.short_id);
}
