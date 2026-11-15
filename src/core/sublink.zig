//! Local parsing of subscription bodies and single connection links.
//! Nothing here touches the network or runs anything: text in, servers out.
//!
//! Supported link schemes: vless, trojan, ss, vmess, hysteria2 / hy2, tuic,
//! wireguard / wg. A body may be a plain list of links or the same list
//! wrapped in base64 (standard or URL-safe alphabet).

const std = @import("std");
const model = @import("model.zig");
const vmess = @import("vmess.zig");

pub const Parsed = struct {
    arena: std.heap.ArenaAllocator,
    servers: []model.State.NewServer,
    /// lines that looked like links but use a scheme we do not support
    unsupported: usize,
    /// lines that are neither links nor blank / comments
    malformed: usize,

    pub fn deinit(p: *Parsed) void {
        p.arena.deinit();
    }
};

pub const Error = error{ Empty, OutOfMemory };

pub fn parseBody(gpa: std.mem.Allocator, body: []const u8) Error!Parsed {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const text = try unwrap(a, body);
    if (looksLikeJson(text)) return parseXrayJson(arena, text);

    var list: std.ArrayList(model.State.NewServer) = .empty;
    var unsupported: usize = 0;
    var malformed: usize = 0;

    var it = std.mem.tokenizeAny(u8, text, "\r\n");
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0 or line[0] == '#' or std.mem.startsWith(u8, line, "//")) continue;
        if (parseLink(a, line)) |sv| {
            try list.append(a, sv);
        } else |err| switch (err) {
            error.UnsupportedScheme => unsupported += 1,
            error.Malformed => malformed += 1,
            error.OutOfMemory => return error.OutOfMemory,
        }
    }

    if (list.items.len == 0) return error.Empty;
    return .{
        .arena = arena,
        .servers = try list.toOwnedSlice(a),
        .unsupported = unsupported,
        .malformed = malformed,
    };
}

/// Returns the plain link list: the input itself, or its base64 payload.
fn unwrap(a: std.mem.Allocator, body: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, body, " \t\r\n");
    if (looksLikeJson(trimmed)) return trimmed;
    if (std.mem.indexOf(u8, trimmed, "://") != null) return trimmed;
    return (try decodeBase64(a, trimmed)) orelse trimmed;
}

fn decodeBase64(a: std.mem.Allocator, input: []const u8) !?[]u8 {
    // normalise: drop whitespace and padding, map URL-safe alphabet
    var clean = try a.alloc(u8, input.len);
    var n: usize = 0;
    for (input) |c| {
        switch (c) {
            ' ', '\t', '\r', '\n', '=' => {},
            '-' => {
                clean[n] = '+';
                n += 1;
            },
            '_' => {
                clean[n] = '/';
                n += 1;
            },
            else => {
                clean[n] = c;
                n += 1;
            },
        }
    }
    const dec = std.base64.standard_no_pad.Decoder;
    const size = dec.calcSizeForSlice(clean[0..n]) catch return null;
    const out = try a.alloc(u8, size);
    dec.decode(out, clean[0..n]) catch return null;
    return out;
}

fn looksLikeJson(text: []const u8) bool {
    return text.len > 1 and (text[0] == '[' or text[0] == '{');
}

// ---------------------------------------------------------------- Xray JSON

/// Subscriptions that answer with full Xray configs: one JSON object, or an
/// array of them, each with `remarks` and an `outbounds` list. The first
/// proxy outbound of every config becomes a server; its parameters are
/// re-encoded as a share link so the rest of the client has one format.
fn parseXrayJson(arena_in: std.heap.ArenaAllocator, text: []const u8) Error!Parsed {
    var arena = arena_in;
    errdefer arena.deinit();
    const a = arena.allocator();

    const root = std.json.parseFromSliceLeaky(std.json.Value, a, text, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Empty,
    };
    var list: std.ArrayList(model.State.NewServer) = .empty;
    var unsupported: usize = 0;
    var malformed: usize = 0;

    const configs: []const std.json.Value = switch (root) {
        .array => |arr| arr.items,
        .object => &.{root},
        else => return error.Empty,
    };
    for (configs) |cfg| {
        if (xrayServer(a, cfg)) |sv| {
            try list.append(a, sv);
        } else |err| switch (err) {
            error.UnsupportedScheme => unsupported += 1,
            error.Malformed => malformed += 1,
            error.OutOfMemory => return error.OutOfMemory,
        }
    }
    if (list.items.len == 0) return error.Empty;
    return .{ .arena = arena, .servers = try list.toOwnedSlice(a), .unsupported = unsupported, .malformed = malformed };
}

fn field(v: ?std.json.Value, key: []const u8) ?std.json.Value {
    const val = v orelse return null;
    return if (val == .object) val.object.get(key) else null;
}

fn first(v: ?std.json.Value) ?std.json.Value {
    const val = v orelse return null;
    return if (val == .array and val.array.items.len > 0) val.array.items[0] else null;
}

fn str(v: ?std.json.Value) []const u8 {
    const val = v orelse return "";
    return if (val == .string) val.string else "";
}

fn port16(v: ?std.json.Value) ?u16 {
    const val = v orelse return null;
    return switch (val) {
        .integer => |i| std.math.cast(u16, i),
        .string => |t| std.fmt.parseInt(u16, t, 10) catch null,
        else => null,
    };
}

fn xrayServer(a: std.mem.Allocator, cfg: std.json.Value) LinkError!model.State.NewServer {
    const outbounds = field(cfg, "outbounds") orelse return error.Malformed;
    if (outbounds != .array) return error.Malformed;

    var saw_proxy_like = false;
    for (outbounds.array.items) |ob| {
        const proto = str(field(ob, "protocol"));
        const protocol: model.Protocol = if (std.mem.eql(u8, proto, "vless"))
            .vless
        else if (std.mem.eql(u8, proto, "trojan"))
            .trojan
        else if (std.mem.eql(u8, proto, "shadowsocks"))
            .shadowsocks
        else if (std.mem.eql(u8, proto, "vmess"))
            .vmess
        else {
            // freedom / blackhole / dns are plumbing, anything else is a
            // proxy protocol this client does not know
            const plumbing = [_][]const u8{ "freedom", "blackhole", "dns", "loopback", "" };
            var is_plumbing = false;
            for (plumbing) |name| if (std.mem.eql(u8, proto, name)) {
                is_plumbing = true;
            };
            if (!is_plumbing) saw_proxy_like = true;
            continue;
        };

        const settings = field(ob, "settings");
        // classic layout nests the endpoint, newer Xray allows it flat
        const endpoint = first(field(settings, "vnext")) orelse first(field(settings, "servers")) orelse settings;
        const user = first(field(endpoint, "users")) orelse endpoint;
        const host = str(field(endpoint, "address"));
        const port = port16(field(endpoint, "port")) orelse return error.Malformed;
        if (host.len == 0) return error.Malformed;

        const stream = field(ob, "streamSettings");
        const network = blk: {
            const n = str(field(stream, "network"));
            break :blk if (n.len == 0) "tcp" else n;
        };
        const sec = str(field(stream, "security"));
        const security: model.Security = if (std.mem.eql(u8, sec, "reality")) .reality else if (std.mem.eql(u8, sec, "tls")) .tls else .none;

        var link: std.Io.Writer.Allocating = .init(a);
        const w = &link.writer;
        const secret = switch (protocol) {
            .vless, .vmess => str(field(user, "id")),
            else => str(field(user, "password")),
        };
        if (secret.len == 0) return error.Malformed;
        const scheme = switch (protocol) {
            .vless => "vless",
            .vmess => "vmess",
            .trojan => "trojan",
            else => "ss",
        };
        (blk: {
            w.print("{s}://", .{scheme}) catch break :blk error.OutOfMemory;
            if (protocol == .shadowsocks) w.print("{s}:", .{str(field(user, "method"))}) catch break :blk error.OutOfMemory;
            // a password may hold what a link gives a meaning to ('@', '/', '#')
            std.Uri.Component.percentEncode(w, secret, isUnreserved) catch break :blk error.OutOfMemory;
            w.writeByte('@') catch break :blk error.OutOfMemory;
            if (std.mem.indexOfScalar(u8, host, ':') != null) {
                w.print("[{s}]:{d}", .{ host, port }) catch break :blk error.OutOfMemory;
            } else {
                w.print("{s}:{d}", .{ host, port }) catch break :blk error.OutOfMemory;
            }
            w.print("?type={s}&security={s}", .{ network, if (sec.len == 0) "none" else sec }) catch break :blk error.OutOfMemory;
            param(w, "flow", str(field(user, "flow"))) catch break :blk error.OutOfMemory;
            // VMess names its cipher where VLESS names its encryption;
            // "none" is what a link without the parameter means
            const enc = str(field(user, if (protocol == .vmess) "security" else "encryption"));
            if (!std.mem.eql(u8, enc, "none")) param(w, "encryption", enc) catch break :blk error.OutOfMemory;
            const reality = field(stream, "realitySettings");
            const tls = field(stream, "tlsSettings");
            const sni = if (str(field(reality, "serverName")).len > 0) str(field(reality, "serverName")) else str(field(tls, "serverName"));
            param(w, "sni", sni) catch break :blk error.OutOfMemory;
            const fp = if (str(field(reality, "fingerprint")).len > 0) str(field(reality, "fingerprint")) else str(field(tls, "fingerprint"));
            param(w, "fp", fp) catch break :blk error.OutOfMemory;
            param(w, "pbk", str(field(reality, "publicKey"))) catch break :blk error.OutOfMemory;
            param(w, "sid", str(field(reality, "shortId"))) catch break :blk error.OutOfMemory;
            param(w, "spx", str(field(reality, "spiderX"))) catch break :blk error.OutOfMemory;
            // transport details live under "<network>Settings"
            var key_buf: [32]u8 = undefined;
            const key = std.fmt.bufPrint(&key_buf, "{s}Settings", .{network}) catch "";
            const transport = field(stream, key);
            param(w, "path", str(field(transport, "path"))) catch break :blk error.OutOfMemory;
            const th_host = if (str(field(transport, "host")).len > 0) str(field(transport, "host")) else str(field(field(transport, "headers"), "Host"));
            param(w, "host", th_host) catch break :blk error.OutOfMemory;
            const multi = if (field(transport, "multiMode")) |m| m == .bool and m.bool else false;
            param(w, "mode", if (multi) "multi" else str(field(transport, "mode"))) catch break :blk error.OutOfMemory;
            param(w, "serviceName", str(field(transport, "serviceName"))) catch break :blk error.OutOfMemory;
            param(w, "authority", str(field(transport, "authority"))) catch break :blk error.OutOfMemory;
            // XHTTP's further settings travel as JSON, as in Xray's own links
            if (field(transport, "extra")) |extra| if (extra == .object) {
                const text = std.json.Stringify.valueAlloc(a, extra, .{}) catch break :blk error.OutOfMemory;
                param(w, "extra", text) catch break :blk error.OutOfMemory;
            };
            break :blk {};
        }) catch return error.OutOfMemory;

        const remarks = str(field(cfg, "remarks"));
        const country = detectCountry(remarks);
        var name = try cleanName(a, remarks);
        if (name.len == 0) name = try a.dupe(u8, host);
        return .{
            .name = name,
            .host = try a.dupe(u8, host),
            .port = port,
            .protocol = protocol,
            .security = security,
            .country = country,
            .link = link.written(),
        };
    }
    return if (saw_proxy_like) error.UnsupportedScheme else error.Malformed;
}

fn param(w: *std.Io.Writer, key: []const u8, value: []const u8) !void {
    if (value.len == 0) return;
    try w.print("&{s}=", .{key});
    try std.Uri.Component.percentEncode(w, value, isUnreserved);
}

fn isUnreserved(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~';
}

pub const LinkError = error{ UnsupportedScheme, Malformed, OutOfMemory };

pub fn parseLink(a: std.mem.Allocator, link: []const u8) LinkError!model.State.NewServer {
    const sep = std.mem.indexOf(u8, link, "://") orelse return error.Malformed;
    const scheme = link[0..sep];
    var rest = link[sep + 3 ..];

    const protocol: model.Protocol = blk: {
        const map = [_]struct { []const u8, model.Protocol }{
            .{ "vless", .vless },         .{ "trojan", .trojan },
            .{ "ss", .shadowsocks },      .{ "hysteria2", .hysteria2 },
            .{ "hy2", .hysteria2 },       .{ "tuic", .tuic },
            .{ "wireguard", .wireguard }, .{ "wg", .wireguard },
            .{ "vmess", .vmess },
        };
        for (map) |m| if (std.ascii.eqlIgnoreCase(scheme, m[0])) break :blk m[1];
        for (scheme) |c| if (!std.ascii.isAlphanumeric(c) and c != '+' and c != '-' and c != '.') return error.Malformed;
        return error.UnsupportedScheme;
    };

    var fragment: []const u8 = "";
    if (std.mem.lastIndexOfScalar(u8, rest, '#')) |i| {
        fragment = rest[i + 1 ..];
        rest = rest[0..i];
    }
    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, '?')) |i| {
        query = rest[i + 1 ..];
        rest = rest[0..i];
    }

    // VMess as v2rayN writes it: base64 of a JSON object that names the
    // server; the other form reads like every other link.
    if (protocol == .vmess and std.mem.indexOfScalar(u8, rest, '@') == null) {
        const sum = vmess.linkSummary(link, try a.alloc(u8, 2 * link.len)) orelse return error.Malformed;
        return named(a, sum.name, .{
            .name = "",
            .host = try a.dupe(u8, sum.host),
            .port = sum.port,
            .protocol = protocol,
            .security = if (sum.tls) .tls else .none,
            .link = try a.dupe(u8, link),
        });
    }
    // Shadowsocks may wrap the whole "method:pass@host:port" in base64
    // (whose standard alphabet has a '/').
    if (protocol == .shadowsocks and std.mem.indexOfScalar(u8, rest, '@') == null) {
        rest = (try decodeBase64(a, std.mem.trimEnd(u8, rest, "/"))) orelse return error.Malformed;
    }

    const at = std.mem.lastIndexOfScalar(u8, rest, '@') orelse return error.Malformed;
    // a path after the address means nothing here; a '/' before the '@' is
    // part of a password (a base64 key, say) and stays
    var hostport = rest[at + 1 ..];
    if (std.mem.indexOfScalar(u8, hostport, '/')) |i| hostport = hostport[0..i];
    if (at == 0 or hostport.len == 0) return error.Malformed;

    var host: []const u8 = undefined;
    var port_str: []const u8 = "";
    if (hostport[0] == '[') {
        const close = std.mem.indexOfScalar(u8, hostport, ']') orelse return error.Malformed;
        host = hostport[1..close];
        if (close + 1 < hostport.len) {
            if (hostport[close + 1] != ':') return error.Malformed;
            port_str = hostport[close + 2 ..];
        }
    } else if (std.mem.lastIndexOfScalar(u8, hostport, ':')) |c| {
        host = hostport[0..c];
        port_str = hostport[c + 1 ..];
    } else {
        host = hostport;
    }
    if (host.len == 0) return error.Malformed;
    const port: u16 = if (port_str.len == 0)
        (if (protocol == .wireguard) 51820 else 443)
    else
        std.fmt.parseInt(u16, port_str, 10) catch return error.Malformed;

    var security: model.Security = switch (protocol) {
        .trojan, .hysteria2, .tuic => .tls,
        else => .none,
    };
    var qit = std.mem.tokenizeScalar(u8, query, '&');
    while (qit.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        if (std.ascii.eqlIgnoreCase(kv[0..eq], "security")) {
            const v = kv[eq + 1 ..];
            if (std.ascii.eqlIgnoreCase(v, "reality")) security = .reality;
            if (std.ascii.eqlIgnoreCase(v, "tls")) security = .tls;
            if (std.ascii.eqlIgnoreCase(v, "none")) security = .none;
        }
    }

    return named(a, try percentDecode(a, fragment), .{
        .name = "",
        .host = try a.dupe(u8, host),
        .port = port,
        .protocol = protocol,
        .security = security,
        .link = try a.dupe(u8, link),
    });
}

/// `sv` with its name and country taken from the remark a link carries.
fn named(a: std.mem.Allocator, remark: []const u8, sv: model.State.NewServer) LinkError!model.State.NewServer {
    var out = sv;
    out.country = detectCountry(remark);
    var name = try cleanName(a, remark);
    // "DE Frankfurt" -> "Frankfurt": the code is already shown as a tag
    if (name.len > 3 and out.country[0] != '?' and std.ascii.eqlIgnoreCase(name[0..2], &out.country) and
        (name[2] == ' ' or name[2] == '-' or name[2] == '_' or name[2] == '|'))
    {
        const rest_name = std.mem.trim(u8, name[3..], " -_|");
        if (rest_name.len > 0 and !std.ascii.isDigit(rest_name[0])) name = try a.dupe(u8, rest_name);
    }
    out.name = if (name.len == 0) out.host else name;
    return out;
}

fn percentDecode(a: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = try a.alloc(u8, s.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '%' and i + 2 < s.len) {
            if (std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16)) |b| {
                out[n] = b;
                n += 1;
                i += 2;
                continue;
            } else |_| {}
        }
        out[n] = s[i];
        n += 1;
    }
    return out[0..n];
}

/// Country from a flag emoji (pair of regional indicators) or a leading
/// two-letter code such as "NL-01" / "[DE] Frankfurt".
pub fn detectCountry(name: []const u8) [2]u8 {
    if (std.unicode.Utf8View.init(name)) |view| {
        var it = view.iterator();
        var prev: ?u8 = null;
        while (it.nextCodepoint()) |cp| {
            if (cp >= 0x1F1E6 and cp <= 0x1F1FF) {
                const letter: u8 = @intCast(cp - 0x1F1E6 + 'A');
                if (prev) |p| return .{ p, letter };
                prev = letter;
            } else prev = null;
        }
    } else |_| {}

    var i: usize = 0;
    while (i < name.len and !std.ascii.isAlphabetic(name[i])) i += 1;
    if (i + 2 <= name.len and std.ascii.isAlphabetic(name[i]) and std.ascii.isAlphabetic(name[i + 1]) and
        (i + 2 == name.len or !std.ascii.isAlphabetic(name[i + 2])))
    {
        const code = [2]u8{ std.ascii.toUpper(name[i]), std.ascii.toUpper(name[i + 1]) };
        if (isKnownCountry(code)) return code;
    }

    const words = [_]struct { []const u8, *const [2]u8 }{
        .{ "nether", "NL" },    .{ "нидерл", "NL" },   .{ "amsterdam", "NL" }, .{ "german", "DE" },
        .{ "герман", "DE" },   .{ "frankfurt", "DE" }, .{ "finland", "FI" },   .{ "финлян", "FI" },
        .{ "helsinki", "FI" },  .{ "france", "FR" },    .{ "франц", "FR" },    .{ "paris", "FR" },
        .{ "united states", "US" }, .{ "usa", "US" },   .{ "сша", "US" },      .{ "kingdom", "GB" },
        .{ "london", "GB" },    .{ "британ", "GB" },   .{ "sweden", "SE" },    .{ "швец", "SE" },
        .{ "poland", "PL" },    .{ "польш", "PL" },    .{ "turkey", "TR" },    .{ "турц", "TR" },
        .{ "japan", "JP" },     .{ "япон", "JP" },     .{ "singapore", "SG" }, .{ "сингапур", "SG" },
        .{ "switzerland", "CH" }, .{ "швейцар", "CH" }, .{ "latvia", "LV" },   .{ "латв", "LV" },
        .{ "estonia", "EE" },   .{ "эстон", "EE" },    .{ "kazakh", "KZ" },    .{ "казах", "KZ" },
        .{ "russia", "RU" },    .{ "росси", "RU" },    .{ "austria", "AT" },   .{ "австри", "AT" },
        .{ "spain", "ES" },     .{ "испан", "ES" },    .{ "italy", "IT" },     .{ "итал", "IT" },
        .{ "canada", "CA" },    .{ "канад", "CA" },    .{ "hong kong", "HK" }, .{ "гонконг", "HK" },
    };
    var buf: [256]u8 = undefined;
    const lower = lowerUtf8(&buf, name);
    for (words) |w| if (std.mem.indexOf(u8, lower, w[0]) != null) return w[1].*;
    return "??".*;
}

/// ASCII + basic Cyrillic lower-casing, enough for keyword matching.
fn lowerUtf8(buf: []u8, s: []const u8) []const u8 {
    const n = @min(buf.len, s.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const c = s[i];
        if (c == 0xD0 and i + 1 < n) {
            const d = s[i + 1];
            if (d >= 0x90 and d <= 0x9F) { // А..П -> а..п
                buf[i] = 0xD0;
                buf[i + 1] = d + 0x20;
            } else if (d >= 0xA0 and d <= 0xAF) { // Р..Я -> р..я
                buf[i] = 0xD1;
                buf[i + 1] = d - 0x20;
            } else {
                buf[i] = c;
                buf[i + 1] = d;
            }
            i += 1;
        } else buf[i] = std.ascii.toLower(c);
    }
    return buf[0..n];
}

fn isKnownCountry(code: [2]u8) bool {
    const list = "AEALAMARATAUAZBEBGBRBYCACHCLCNCYCZDEDKEEEGESFIFRGBGEGRHKHRHUIDIEILINISITJPKGKRKZLTLULVMDMXMYNLNONZPLPTRORSRUSESGSISKTHTRTWUAUSUZVNZA";
    var i: usize = 0;
    while (i < list.len) : (i += 2) {
        if (list[i] == code[0] and list[i + 1] == code[1]) return true;
    }
    return false;
}

/// Drop emoji / pictographs (the UI font is text-only) and tidy whitespace.
/// Display name: emoji and symbols the UI font has no glyph for are
/// dropped (flags become the country badge instead), the plain arrows it has
/// are kept, and the spaces they leave behind are tidied up.
fn cleanName(a: std.mem.Allocator, name: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    const view = std.unicode.Utf8View.init(name) catch return a.dupe(u8, name);
    var it = view.iterator();
    var last_space = true;
    while (it.nextCodepointSlice()) |slice| {
        const cp = std.unicode.utf8Decode(slice) catch continue;
        const arrow = cp >= 0x2190 and cp <= 0x2199;
        const drop = cp >= 0x1F000 or (cp >= 0x2190 and cp <= 0x2BFF and !arrow) or
            (cp >= 0xFE00 and cp <= 0xFE0F) or cp == 0x200D or cp < 0x20;
        if (drop) continue;
        if (cp == ' ') {
            if (last_space) continue;
            last_space = true;
        } else {
            // "[ x" -> "[x", "x ]" -> "x]"
            if ((cp == ']' or cp == ')') and last_space and out.items.len > 0) out.items.len -= 1;
            last_space = cp == '[' or cp == '(';
        }
        try out.appendSlice(a, slice);
    }
    const trimmed = std.mem.trim(u8, out.items, " -|·");
    return a.dupe(u8, trimmed);
}

test "names lose emoji but keep arrows, without stray spaces" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings("Auto → [Оптимальная]", try cleanName(a, "Auto → [🚀 Оптимальная]"));
    try std.testing.expectEqualStrings("Albania → [YouTube без рекламы]", try cleanName(a, "Albania 🇦🇱 → [🍿 YouTube без рекламы]"));
    try std.testing.expectEqualStrings("AI", try cleanName(a, "🤖 AI"));
    try std.testing.expectEqualStrings("Germany 92 → [Белые списки] CDN", try cleanName(a, "Germany 92 🇩🇪 → [📃 Белые списки] CDN"));
    try std.testing.expectEqualStrings("x (y)", try cleanName(a, "x ( y )"));
}

test "vless reality link" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const sv = try parseLink(arena.allocator(), "vless://11111111-2222-3333-4444-555555555555@nl1.example.com:8443?security=reality&sni=example.com&fp=chrome&pbk=abc&type=tcp#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam%2001");
    try std.testing.expectEqualStrings("nl1.example.com", sv.host);
    try std.testing.expectEqual(8443, sv.port);
    try std.testing.expectEqual(model.Protocol.vless, sv.protocol);
    try std.testing.expectEqual(model.Security.reality, sv.security);
    try std.testing.expectEqualStrings("NL", &sv.country);
    try std.testing.expectEqualStrings("Amsterdam 01", sv.name);
}

test "shadowsocks both encodings and ipv6" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // aes-256-gcm:pass
    const s1 = try parseLink(a, "ss://YWVzLTI1Ni1nY206cGFzcw@[2001:db8::1]:8388#DE%20Frankfurt");
    try std.testing.expectEqualStrings("2001:db8::1", s1.host);
    try std.testing.expectEqual(8388, s1.port);
    try std.testing.expectEqualStrings("DE", &s1.country);
    try std.testing.expectEqualStrings("Frankfurt", s1.name);
    // aes-256-gcm:pass@1.2.3.4:8388
    const s2 = try parseLink(a, "ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40OjgzODg=#test");
    try std.testing.expectEqualStrings("1.2.3.4", s2.host);
    try std.testing.expectEqual(8388, s2.port);
}

test "body: base64 list, unsupported and malformed lines are counted" {
    const plain =
        \\trojan://secret@fi.example.net:443?sni=fi.example.net#Finland
        \\hy2://auth@jp.example.net:8443#JP-01
        \\vmess://eyJ2IjoiMiJ9
        \\socks://dXNlcjpwYXNz@ru.example.net:1080#RU
        \\not a link
        \\tuic://uuid:pw@sg.example.net:443#Singapore
        \\wg://key@ch.example.net#CH
    ;
    var buf: [1024]u8 = undefined;
    const b64 = std.base64.standard.Encoder.encode(&buf, plain);
    var p = try parseBody(std.testing.allocator, b64);
    defer p.deinit();
    try std.testing.expectEqual(4, p.servers.len);
    try std.testing.expectEqual(1, p.unsupported);
    // "not a link", and the vmess body that names no server
    try std.testing.expectEqual(2, p.malformed);
    try std.testing.expectEqualStrings("FI", &p.servers[0].country);
    try std.testing.expectEqual(model.Security.tls, p.servers[0].security);
    try std.testing.expectEqualStrings("JP", &p.servers[1].country);
    try std.testing.expectEqual(51820, p.servers[3].port);
}

test "vmess: v2rayN's base64 JSON and the URL form" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{"v":"2","ps":"\ud83c\uddf3\ud83c\uddf1 Amsterdam 3","add":"nl.example.net","port":"8443","id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"auto","net":"ws","host":"cdn.example","path":"/v","tls":"tls"}
    ;
    var buf: [512]u8 = undefined;
    var link_buf: [600]u8 = undefined;
    const link = try std.fmt.bufPrint(&link_buf, "vmess://{s}", .{std.base64.standard.Encoder.encode(&buf, json)});
    const sv = try parseLink(a, link);
    try std.testing.expectEqual(model.Protocol.vmess, sv.protocol);
    try std.testing.expectEqualStrings("nl.example.net", sv.host);
    try std.testing.expectEqual(8443, sv.port);
    try std.testing.expectEqual(model.Security.tls, sv.security);
    try std.testing.expectEqualStrings("NL", &sv.country);
    try std.testing.expectEqualStrings("Amsterdam 3", sv.name);
    try std.testing.expectEqualStrings(link, sv.link);

    const url = try parseLink(a, "vmess://11111111-2222-3333-4444-555555555555@de.example.net:443?type=grpc&security=tls#DE%20Berlin");
    try std.testing.expectEqual(model.Protocol.vmess, url.protocol);
    try std.testing.expectEqualStrings("de.example.net", url.host);
    try std.testing.expectEqual(model.Security.tls, url.security);
    try std.testing.expectEqualStrings("Berlin", url.name);
}

test "a '/' in a password is not the end of the address" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // a 2022 key in standard base64, unescaped
    const ss = try parseLink(a, "ss://2022-blake3-aes-128-gcm:ab/cd+ef/0123456789AAAA==@1.2.3.4:8388/?x=1#k");
    try std.testing.expectEqualStrings("1.2.3.4", ss.host);
    try std.testing.expectEqual(8388, ss.port);
    const tj = try parseLink(a, "trojan://pa/ss@tj.example.net:8443/path?sni=x#t");
    try std.testing.expectEqualStrings("tj.example.net", tj.host);
    try std.testing.expectEqual(8443, tj.port);
    // the legacy form: all of it in standard base64 (this one has a '/')
    var buf: [128]u8 = undefined;
    var link_buf: [160]u8 = undefined;
    const b64 = std.base64.standard.Encoder.encode(&buf, "aes-256-gcm:pw?w@9.8.7.6:443");
    try std.testing.expect(std.mem.indexOfScalar(u8, b64, '/') != null);
    const legacy = try parseLink(a, try std.fmt.bufPrint(&link_buf, "ss://{s}#old", .{b64}));
    try std.testing.expectEqualStrings("9.8.7.6", legacy.host);
    try std.testing.expectEqual(443, legacy.port);
}

test "empty body is an error, not an empty success" {
    try std.testing.expectError(error.Empty, parseBody(std.testing.allocator, "   \n"));
    try std.testing.expectError(error.Empty, parseBody(std.testing.allocator, "<html>502</html>"));
}

test "xray json subscription: vmess, trojan over grpc, a password that needs escaping" {
    const body =
        \\[
        \\ {"remarks":"VM","outbounds":[
        \\   {"protocol":"vmess","settings":{"vnext":[{"address":"vm.example.net","port":443,
        \\      "users":[{"id":"11111111-2222-3333-4444-555555555555","alterId":0,"security":"chacha20-poly1305"}]}]},
        \\    "streamSettings":{"network":"httpupgrade","security":"tls","tlsSettings":{"serverName":"vm.example.net"},
        \\      "httpupgradeSettings":{"path":"/hu","host":"vm.example.net"}}}]},
        \\ {"remarks":"TJ","outbounds":[
        \\   {"protocol":"trojan","settings":{"servers":[{"address":"tj.example.net","port":443,"password":"p@ss/w#rd"}]},
        \\    "streamSettings":{"network":"grpc","security":"tls","grpcSettings":{"serviceName":"tun","multiMode":true,"authority":"a.example"}}}]},
        \\ {"remarks":"XH","outbounds":[
        \\   {"protocol":"vless","settings":{"vnext":[{"address":"xh.example.net","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none"}]}]},
        \\    "streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"serverName":"s.example","publicKey":"K"},
        \\      "xhttpSettings":{"path":"/x","mode":"stream-one","extra":{"xPaddingBytes":"100-200"}}}}]}
        \\]
    ;
    var p = try parseBody(std.testing.allocator, body);
    defer p.deinit();
    try std.testing.expectEqual(3, p.servers.len);
    try std.testing.expectEqual(model.Protocol.vmess, p.servers[0].protocol);
    try std.testing.expectEqualStrings(
        "vmess://11111111-2222-3333-4444-555555555555@vm.example.net:443?type=httpupgrade&security=tls&encryption=chacha20-poly1305&sni=vm.example.net&path=%2Fhu&host=vm.example.net",
        p.servers[0].link,
    );
    try std.testing.expectEqualStrings(
        "trojan://p%40ss%2Fw%23rd@tj.example.net:443?type=grpc&security=tls&mode=multi&serviceName=tun&authority=a.example",
        p.servers[1].link,
    );
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const again = try parseLink(arena.allocator(), p.servers[1].link);
    try std.testing.expectEqualStrings("tj.example.net", again.host);
    try std.testing.expect(std.mem.endsWith(u8, p.servers[2].link, "&path=%2Fx&mode=stream-one&extra=%7B%22xPaddingBytes%22%3A%22100-200%22%7D"));
}

test "xray json subscription: reality tcp, xhttp, ws+tls, unknown protocol" {
    const body =
        \\[
        \\ {"remarks":"🇩🇪 Германия","outbounds":[
        \\   {"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"de.example.net","port":443,
        \\      "users":[{"id":"11111111-2222-3333-4444-555555555555","flow":"xtls-rprx-vision","encryption":"none"}]}]},
        \\    "streamSettings":{"network":"tcp","security":"reality",
        \\      "realitySettings":{"serverName":"www.example.org","publicKey":"PUBKEY_x","shortId":"ab12","fingerprint":"chrome"}}},
        \\   {"protocol":"freedom","tag":"direct"}]},
        \\ {"remarks":"США","outbounds":[
        \\   {"protocol":"freedom","tag":"direct"},
        \\   {"protocol":"vless","settings":{"vnext":[{"address":"2001:db8::7","port":"8443","users":[{"id":"aaaaaaaa-2222-3333-4444-555555555555"}]}]},
        \\    "streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"serverName":"s.example","publicKey":"K","shortId":""},
        \\      "xhttpSettings":{"path":"/x y","mode":"auto"}}}]},
        \\ {"remarks":"Netherlands 42","outbounds":[
        \\   {"protocol":"vless","settings":{"address":"nl.example.net","port":443,"id":"bbbbbbbb-2222-3333-4444-555555555555"},
        \\    "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"cdn.example"},
        \\      "wsSettings":{"path":"/ws","headers":{"Host":"cdn.example"}}}}]},
        \\ {"remarks":"future","outbounds":[{"protocol":"quantumproxy","settings":{}}]},
        \\ {"remarks":"broken","outbounds":[{"protocol":"freedom"}]}
        \\]
    ;
    var p = try parseBody(std.testing.allocator, body);
    defer p.deinit();
    try std.testing.expectEqual(3, p.servers.len);
    try std.testing.expectEqual(1, p.unsupported);
    try std.testing.expectEqual(1, p.malformed);

    const de = p.servers[0];
    try std.testing.expectEqualStrings("Германия", de.name);
    try std.testing.expectEqualStrings("DE", &de.country);
    try std.testing.expectEqual(model.Security.reality, de.security);
    try std.testing.expectEqualStrings(
        "vless://11111111-2222-3333-4444-555555555555@de.example.net:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.example.org&fp=chrome&pbk=PUBKEY_x&sid=ab12",
        de.link,
    );
    // the synthesized link parses back to the same endpoint
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const again = try parseLink(arena.allocator(), de.link);
    try std.testing.expectEqualStrings("de.example.net", again.host);
    try std.testing.expectEqual(model.Security.reality, again.security);

    const us = p.servers[1];
    try std.testing.expectEqualStrings("US", &us.country);
    try std.testing.expectEqualStrings("2001:db8::7", us.host);
    try std.testing.expectEqual(8443, us.port);
    try std.testing.expect(std.mem.indexOf(u8, us.link, "@[2001:db8::7]:8443?type=xhttp") != null);
    try std.testing.expect(std.mem.indexOf(u8, us.link, "&path=%2Fx%20y&mode=auto") != null);

    const nl = p.servers[2];
    try std.testing.expectEqualStrings("NL", &nl.country);
    try std.testing.expectEqual(model.Security.tls, nl.security);
    try std.testing.expect(std.mem.indexOf(u8, nl.link, "type=ws&security=tls&sni=cdn.example&path=%2Fws&host=cdn.example") != null);
}
