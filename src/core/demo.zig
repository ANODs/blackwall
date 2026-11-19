//! Sample data shown until the user adds a real subscription, so the
//! interface is not empty on first launch. Never persisted.

const std = @import("std");
const model = @import("model.zig");

const S = struct { []const u8, *const [2]u8, model.Protocol, model.Security, u16 };

const servers = [_]S{
    .{ "Amsterdam", "NL", .vless, .reality, 38 },
    .{ "Frankfurt", "DE", .vless, .reality, 44 },
    .{ "Helsinki", "FI", .hysteria2, .tls, 29 },
    .{ "Stockholm", "SE", .trojan, .tls, 41 },
    .{ "Warsaw", "PL", .vless, .reality, 52 },
    .{ "Zurich", "CH", .wireguard, .none, 57 },
    .{ "London", "GB", .tuic, .tls, 63 },
    .{ "Istanbul", "TR", .shadowsocks, .none, 78 },
    .{ "New York", "US", .vless, .reality, 124 },
    .{ "Tokyo", "JP", .hysteria2, .tls, 212 },
};

/// `sub_name`: the demo subscription's title in the interface language.
pub fn load(s: *model.State, sub_name: []const u8) !void {
    s.demo = true;
    const sub = try s.addSubscription(sub_name, "");
    const sub_id = sub.id;
    s.subs.items[s.subs.items.len - 1].used_bytes = 48 << 30;
    s.subs.items[s.subs.items.len - 1].total_bytes = 200 << 30;
    // a provider's "Auto": several servers, chosen among by speed
    const m: model.State.NewMember = .{ .link = "", .host = "", .port = 443 };
    const auto = try s.addServer(sub_id, .{ .name = "Auto", .host = "", .port = 443, .protocol = .vless, .security = .reality, .members = &.{ m, m, m, m, m } });
    auto.ping_ms = 31;
    auto.ping_state = .ok;
    var ids: [servers.len]u32 = undefined;
    for (servers, 0..) |d, i| {
        const sv = try s.addServer(sub_id, .{ .name = d[0], .host = "", .port = 443, .protocol = d[2], .security = d[3], .country = d[1].* });
        sv.ping_ms = d[4];
        sv.ping_state = .ok;
        ids[i] = sv.id;
    }
    s.serverById(ids[0]).?.favorite = true;
    s.serverById(ids[2]).?.favorite = true;
    // where a few of them were seen to exit: as named, and one that is not
    s.serverById(ids[0]).?.exit = "NL".*;
    s.serverById(ids[2]).?.exit = "FI".*;
    s.serverById(ids[5]).?.exit = "DE".*;

    // Example rules on whatever is installed, mirroring the product brief.
    const rules = [_]struct { []const u8, model.Route }{
        .{ "Telegram", .{ .server = ids[1] } },
        .{ "Safari", .{ .server = ids[0] } },
        .{ "Google Chrome", .{ .server = ids[0] } },
        .{ "Discord", .dpi },
        .{ "Steam", .direct },
        .{ "Music", .direct },
        .{ "Mail", .auto },
    };
    // and a few sites, as one would set them
    const sites = [_]struct { []const u8, model.Route }{
        .{ "youtube.com", .{ .server = ids[0] } },
        .{ "gosuslugi.ru", .direct },
        .{ "ads.example.com", .block },
    };
    for (sites) |site| (s.addDomain(site[0]) catch continue).route = site[1];
    var online: usize = 0;
    for (s.apps.items) |*a| {
        for (rules) |r| {
            if (std.mem.eql(u8, a.name, r[0])) {
                a.route = r[1];
                a.online = true;
                online += 1;
            }
        }
    }
    // make sure a few rows are active even on a machine without those apps
    for (s.apps.items) |*a| {
        if (online >= 5) break;
        if (!a.online) {
            a.online = true;
            online += 1;
        }
    }
}
