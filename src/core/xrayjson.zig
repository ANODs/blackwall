//! A server as an Xray config, for "Copy JSON": the reverse of what
//! sublink.zig reads from Xray JSON subscriptions. One link is one proxy
//! outbound; a group (a provider's "Auto") is a balancer over its servers,
//! as Remnawave and the like write it, so Happ, v2rayN and Xray itself take
//! it as it is, and BLACKWALL reads it back as the same group.
//!
//! Links are secrets: the text goes to the clipboard, never to a log.

const std = @import("std");
const sublink = @import("sublink.zig");

pub const Error = error{ UnsupportedScheme, Malformed, OutOfMemory };

/// The Xray config of a server named `name`: one link, or a group's.
pub fn config(gpa: std.mem.Allocator, name: []const u8, links: []const []const u8) Error![]u8 {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    var s: std.json.Stringify = .{ .writer = &out.writer, .options = .{ .whitespace = .indent_2 } };
    (blk: {
        s.beginObject() catch |e| break :blk e;
        s.objectField("remarks") catch |e| break :blk e;
        s.write(name) catch |e| break :blk e;
        s.objectField("outbounds") catch |e| break :blk e;
        s.beginArray() catch |e| break :blk e;
        for (links, 0..) |link, i| {
            var tag_buf: [16]u8 = undefined;
            const tag = if (i == 0) "proxy" else std.fmt.bufPrint(&tag_buf, "proxy-{d}", .{i + 1}) catch unreachable;
            const ob = outbound(a, link, tag) catch |e| return e;
            s.write(ob) catch |e| break :blk e;
        }
        s.write(.{ .tag = "direct", .protocol = "freedom" }) catch |e| break :blk e;
        s.write(.{ .tag = "block", .protocol = "blackhole" }) catch |e| break :blk e;
        s.endArray() catch |e| break :blk e;
        if (links.len > 1) {
            // the group: every server, the first as the fallback, the
            // fastest by Xray's own measurement
            const selector = [_][]const u8{"proxy"};
            s.objectField("routing") catch |e| break :blk e;
            s.write(.{
                .rules = .{.{ .type = "field", .network = "tcp,udp", .balancerTag = "balancer" }},
                .balancers = .{.{ .tag = "balancer", .selector = selector, .fallbackTag = "proxy", .strategy = .{ .type = "leastPing" } }},
            }) catch |e| break :blk e;
            s.objectField("observatory") catch |e| break :blk e;
            s.write(.{ .subjectSelector = selector, .probeUrl = "https://www.gstatic.com/generate_204", .probeInterval = "3m" }) catch |e| break :blk e;
        }
        s.endObject() catch |e| break :blk e;
        break :blk {};
    }) catch return error.OutOfMemory;
    return out.toOwnedSlice() catch error.OutOfMemory;
}

/// What a link says, before it becomes JSON.
const Parts = struct {
    scheme: []const u8,
    user: []const u8 = "",
    host: []const u8 = "",
    port: u16 = 0,
    params: std.StringHashMapUnmanaged([]const u8) = .empty,

    fn get(p: *const Parts, key: []const u8) []const u8 {
        return p.params.get(key) orelse "";
    }
};

fn parse(a: std.mem.Allocator, link: []const u8) Error!Parts {
    const sep = std.mem.indexOf(u8, link, "://") orelse return error.Malformed;
    var p: Parts = .{ .scheme = link[0..sep] };
    var rest = link[sep + 3 ..];
    if (std.mem.lastIndexOfScalar(u8, rest, '#')) |i| rest = rest[0..i];
    if (std.mem.indexOfScalar(u8, rest, '?')) |i| {
        var it = std.mem.splitScalar(u8, rest[i + 1 ..], '&');
        while (it.next()) |kv| {
            const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
            try p.params.put(a, try sublink.percentDecode(a, kv[0..eq]), try sublink.percentDecode(a, kv[eq + 1 ..]));
        }
        rest = rest[0..i];
    }
    const at = std.mem.lastIndexOfScalar(u8, rest, '@') orelse return error.Malformed;
    p.user = try sublink.percentDecode(a, rest[0..at]);
    var hostport = rest[at + 1 ..];
    if (std.mem.indexOfScalar(u8, hostport, '/')) |i| hostport = hostport[0..i];
    const colon = std.mem.lastIndexOfScalar(u8, hostport, ':') orelse return error.Malformed;
    p.host = std.mem.trim(u8, hostport[0..colon], "[]");
    p.port = std.fmt.parseInt(u16, hostport[colon + 1 ..], 10) catch return error.Malformed;
    if (p.host.len == 0 or p.user.len == 0) return error.Malformed;
    return p;
}

/// One link as an Xray outbound (a JSON value).
fn outbound(a: std.mem.Allocator, link: []const u8, tag: []const u8) Error!std.json.Value {
    if (std.ascii.startsWithIgnoreCase(link, "vmess://") and std.mem.indexOfScalar(u8, link, '@') == null)
        return v2raynVmess(a, link, tag);
    var p = try parse(a, link);
    var settings: std.json.ObjectMap = .empty;
    var protocol: []const u8 = undefined;
    if (std.ascii.eqlIgnoreCase(p.scheme, "vless") or std.ascii.eqlIgnoreCase(p.scheme, "vmess")) {
        const vmess = std.ascii.eqlIgnoreCase(p.scheme, "vmess");
        protocol = if (vmess) "vmess" else "vless";
        var user: std.json.ObjectMap = .empty;
        try user.put(a, "id", .{ .string = p.user });
        const enc = p.get("encryption");
        if (vmess) {
            try user.put(a, "security", .{ .string = if (enc.len > 0) enc else "auto" });
        } else {
            try user.put(a, "encryption", .{ .string = if (enc.len > 0) enc else "none" });
            if (p.get("flow").len > 0) try user.put(a, "flow", .{ .string = p.get("flow") });
        }
        try settings.put(a, "vnext", try one(a, try endpoint(a, p.host, p.port, "users", .{ .object = user })));
    } else if (std.ascii.eqlIgnoreCase(p.scheme, "trojan")) {
        protocol = "trojan";
        var server = try endpointObject(a, p.host, p.port);
        try server.put(a, "password", .{ .string = p.user });
        try settings.put(a, "servers", try one(a, .{ .object = server }));
    } else if (std.ascii.eqlIgnoreCase(p.scheme, "ss")) {
        protocol = "shadowsocks";
        // "method:password", or the same in base64
        const plain = if (std.mem.indexOfScalar(u8, p.user, ':') != null) p.user else ((try sublink.decodeBase64(a, p.user)) orelse return error.Malformed);
        const colon = std.mem.indexOfScalar(u8, plain, ':') orelse return error.Malformed;
        var server = try endpointObject(a, p.host, p.port);
        try server.put(a, "method", .{ .string = plain[0..colon] });
        try server.put(a, "password", .{ .string = plain[colon + 1 ..] });
        try settings.put(a, "servers", try one(a, .{ .object = server }));
    } else return error.UnsupportedScheme;

    var ob: std.json.ObjectMap = .empty;
    try ob.put(a, "tag", .{ .string = tag });
    try ob.put(a, "protocol", .{ .string = protocol });
    try ob.put(a, "settings", .{ .object = settings });
    if (!std.mem.eql(u8, protocol, "shadowsocks")) try ob.put(a, "streamSettings", try stream(a, &p));
    return .{ .object = ob };
}

/// streamSettings from a link's parameters: the transport and its security.
fn stream(a: std.mem.Allocator, p: *const Parts) Error!std.json.Value {
    var st: std.json.ObjectMap = .empty;
    const net = if (p.get("type").len > 0) p.get("type") else "tcp";
    try st.put(a, "network", .{ .string = net });
    const sec = if (p.get("security").len > 0) p.get("security") else "none";
    try st.put(a, "security", .{ .string = sec });
    if (std.mem.eql(u8, sec, "reality")) {
        var r: std.json.ObjectMap = .empty;
        try putIf(a, &r, "serverName", p.get("sni"));
        try putIf(a, &r, "fingerprint", if (p.get("fp").len > 0) p.get("fp") else "chrome");
        try putIf(a, &r, "publicKey", p.get("pbk"));
        try putIf(a, &r, "shortId", p.get("sid"));
        try putIf(a, &r, "spiderX", p.get("spx"));
        try st.put(a, "realitySettings", .{ .object = r });
    } else if (std.mem.eql(u8, sec, "tls")) {
        var t: std.json.ObjectMap = .empty;
        try putIf(a, &t, "serverName", p.get("sni"));
        try putIf(a, &t, "fingerprint", p.get("fp"));
        if (p.get("alpn").len > 0) {
            var list: std.json.Array = .init(a);
            var it = std.mem.splitScalar(u8, p.get("alpn"), ',');
            while (it.next()) |x| try list.append(.{ .string = x });
            try t.put(a, "alpn", .{ .array = list });
        }
        try st.put(a, "tlsSettings", .{ .object = t });
    }
    var tr: std.json.ObjectMap = .empty;
    if (std.mem.eql(u8, net, "ws") or std.mem.eql(u8, net, "httpupgrade")) {
        try putIf(a, &tr, "path", p.get("path"));
        try putIf(a, &tr, "host", p.get("host"));
    } else if (std.mem.eql(u8, net, "grpc")) {
        try putIf(a, &tr, "serviceName", p.get("serviceName"));
        try putIf(a, &tr, "authority", p.get("authority"));
        if (std.mem.eql(u8, p.get("mode"), "multi")) try tr.put(a, "multiMode", .{ .bool = true });
    } else if (std.mem.eql(u8, net, "xhttp") or std.mem.eql(u8, net, "splithttp")) {
        try putIf(a, &tr, "path", p.get("path"));
        try putIf(a, &tr, "host", p.get("host"));
        try putIf(a, &tr, "mode", p.get("mode"));
        if (p.get("extra").len > 0) {
            const extra = std.json.parseFromSliceLeaky(std.json.Value, a, p.get("extra"), .{}) catch return error.Malformed;
            try tr.put(a, "extra", extra);
        }
    } else if (std.mem.eql(u8, net, "h2") or std.mem.eql(u8, net, "http")) {
        try putIf(a, &tr, "path", p.get("path"));
        if (p.get("host").len > 0) {
            var hosts: std.json.Array = .init(a);
            try hosts.append(.{ .string = p.get("host") });
            try tr.put(a, "host", .{ .array = hosts });
        }
    }
    if (tr.count() > 0) {
        var key_buf: [32]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "{s}Settings", .{net}) catch return error.Malformed;
        try st.put(a, try a.dupe(u8, key), .{ .object = tr });
    }
    return .{ .object = st };
}

/// VMess as v2rayN writes it: base64 of {add, port, id, net, tls, ...}.
fn v2raynVmess(a: std.mem.Allocator, link: []const u8, tag: []const u8) Error!std.json.Value {
    var body = link["vmess://".len..];
    if (std.mem.indexOfScalar(u8, body, '#')) |i| body = body[0..i];
    const text = (try sublink.decodeBase64(a, body)) orelse return error.Malformed;
    const j = std.json.parseFromSliceLeaky(std.json.Value, a, text, .{}) catch return error.Malformed;
    if (j != .object) return error.Malformed;
    const str = struct {
        fn of(v: std.json.Value, k: []const u8) []const u8 {
            const x = v.object.get(k) orelse return "";
            return switch (x) {
                .string => |s| s,
                else => "",
            };
        }
    }.of;
    const port: u16 = switch (j.object.get("port") orelse return error.Malformed) {
        .integer => |i| std.math.cast(u16, i) orelse return error.Malformed,
        .string => |s| std.fmt.parseInt(u16, s, 10) catch return error.Malformed,
        else => return error.Malformed,
    };
    // the same thing as a link, which the rest already knows
    var w: std.Io.Writer.Allocating = .init(a);
    (blk: {
        w.writer.print("vmess://{s}@{s}:{d}?type={s}&security={s}", .{ str(j, "id"), str(j, "add"), port, if (str(j, "net").len > 0) str(j, "net") else "tcp", if (std.mem.eql(u8, str(j, "tls"), "tls")) "tls" else "none" }) catch |e| break :blk e;
        const pairs = [_][2][]const u8{ .{ "sni", "sni" }, .{ "fp", "fp" }, .{ "alpn", "alpn" }, .{ "path", "path" }, .{ "host", "host" }, .{ "encryption", "scy" } };
        for (pairs) |pp| {
            const v = str(j, pp[1]);
            if (v.len == 0) continue;
            w.writer.print("&{s}=", .{pp[0]}) catch |e| break :blk e;
            std.Uri.Component.percentEncode(&w.writer, v, isUnreserved) catch |e| break :blk e;
        }
        break :blk {};
    }) catch return error.OutOfMemory;
    if (std.mem.eql(u8, str(j, "net"), "grpc")) {
        w.writer.print("&serviceName={s}", .{str(j, "path")}) catch return error.OutOfMemory;
    }
    return outbound(a, w.written(), tag);
}

fn isUnreserved(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~';
}

fn putIf(a: std.mem.Allocator, o: *std.json.ObjectMap, key: []const u8, value: []const u8) !void {
    if (value.len > 0) try o.put(a, key, .{ .string = value });
}

fn endpointObject(a: std.mem.Allocator, host: []const u8, port: u16) !std.json.ObjectMap {
    var o: std.json.ObjectMap = .empty;
    try o.put(a, "address", .{ .string = host });
    try o.put(a, "port", .{ .integer = port });
    return o;
}

fn endpoint(a: std.mem.Allocator, host: []const u8, port: u16, key: []const u8, single: std.json.Value) !std.json.Value {
    var o = try endpointObject(a, host, port);
    try o.put(a, key, try one(a, single));
    return .{ .object = o };
}

fn one(a: std.mem.Allocator, v: std.json.Value) !std.json.Value {
    var arr: std.json.Array = .init(a);
    try arr.append(v);
    return .{ .array = arr };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const proxy = @import("proxy.zig");

/// The link read back from the JSON is the same server, the same way.
fn expectRoundTrip(link: []const u8) !void {
    const json = try config(testing.allocator, "X", &.{link});
    defer testing.allocator.free(json);
    var parsed = try sublink.parseBody(testing.allocator, json);
    defer parsed.deinit();
    try testing.expectEqual(1, parsed.servers.len);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try sublink.parseLink(a, link);
    const got = parsed.servers[0];
    try testing.expectEqualStrings(want.host, got.host);
    try testing.expectEqual(want.port, got.port);
    try testing.expectEqual(want.protocol, got.protocol);
    try testing.expectEqual(want.security, got.security);
    const ob_want = try proxy.outboundFromLink(want.link, want.host, want.port);
    const ob_got = try proxy.outboundFromLink(got.link, got.host, got.port);
    try testing.expect(ob_want.sameServer(&ob_got));
    // and once more: the JSON of the link read back is the same JSON
    const again = try config(testing.allocator, "X", &.{got.link});
    defer testing.allocator.free(again);
    try testing.expectEqualStrings(json, again);
}

test "links become Xray outbounds that read back as the same server" {
    try expectRoundTrip("vless://0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0@203.0.113.7:443?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=jFuNsxsFdIt0Xig5jM1PAOIpJPKvJg9nU2PAMD5dPm8&sid=ab12cd34&flow=xtls-rprx-vision#NL");
    try expectRoundTrip("vless://0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0@cdn.example.com:443?type=ws&security=tls&sni=cdn.example.com&path=%2Fws%3Fed%3D2048&host=cdn.example.com#WS");
    try expectRoundTrip("trojan://p%40ss%2Fword@t.example.com:443?type=grpc&security=tls&serviceName=svc&sni=t.example.com#T");
    try expectRoundTrip("ss://2022-blake3-aes-128-gcm:QUJDREVGR0hJSktMTU5PUA%3D%3D@s.example.com:8388#S");
    try expectRoundTrip("ss://YWVzLTI1Ni1nY206cGFzcw@s2.example.com:8389#S2");
    try expectRoundTrip("vmess://0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0@v.example.com:443?type=ws&security=tls&path=%2Fv&host=v.example.com&encryption=auto#V");
}

test "a group is a balancer that reads back as the same group" {
    const links = [_][]const u8{
        "vless://0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0@1.example.com:443?type=tcp&security=tls&sni=1.example.com#A",
        "trojan://pw@2.example.com:443?type=tcp&security=tls&sni=2.example.com#B",
        "ss://2022-blake3-aes-128-gcm:QUJDREVGR0hJSktMTU5PUA%3D%3D@3.example.com:8388#C",
    };
    const json = try config(testing.allocator, "⚡ Авто 1", &links);
    defer testing.allocator.free(json);
    var parsed = try sublink.parseBody(testing.allocator, json);
    defer parsed.deinit();
    try testing.expectEqual(1, parsed.servers.len);
    const g = parsed.servers[0];
    try testing.expectEqualStrings("Авто 1", g.name);
    try testing.expectEqual(3, g.members.len);
    try testing.expectEqualStrings("3.example.com", g.members[2].host);
}

test "unsupported and broken links say so" {
    try testing.expectError(error.UnsupportedScheme, config(testing.allocator, "H", &.{"hysteria2://pw@h.example.com:443#H"}));
    try testing.expectError(error.Malformed, config(testing.allocator, "M", &.{"vless://nohost"}));
}
