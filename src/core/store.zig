//! Versioned JSON persistence of the user's configuration.
//! Written atomically (temp file, flushed to disk, then renamed) so a crash
//! or a power cut never leaves a half-written config. A file that cannot be
//! read is set aside (`setAside`) before anything is written over it.

const std = @import("std");
const model = @import("model.zig");

const version = 1;

const ServerDto = struct {
    id: u32,
    sub_id: u32,
    name: []const u8,
    host: []const u8,
    port: u16,
    protocol: model.Protocol,
    security: model.Security = .none,
    country: []const u8 = "??",
    /// where it really exits, once seen
    exit: []const u8 = "??",
    favorite: bool = false,
    available: bool = true,
    link: []const u8 = "",
    members: []const MemberDto = &.{},
};

const MemberDto = struct {
    link: []const u8,
    host: []const u8,
    port: u16,
    exit: []const u8 = "??",
};

const SubDto = struct {
    id: u32,
    name: []const u8,
    url: []const u8,
    updated_unix: i64 = 0,
    update_hours: u16 = 0,
    announce: []const u8 = "",
    support_url: []const u8 = "",
};

const RuleDto = struct {
    app_id: []const u8,
    name: []const u8,
    path: []const u8 = "",
    route: model.Route,
};

const DomainDto = struct {
    name: []const u8,
    route: model.Route,
};

const File = struct {
    version: u32 = version,
    next_id: u32 = 1,
    settings: model.Settings = .{},
    subs: []const SubDto = &.{},
    servers: []const ServerDto = &.{},
    rules: []const RuleDto = &.{},
    domains: []const DomainDto = &.{},
};

pub fn serialize(gpa: std.mem.Allocator, s: *const model.State) ![]u8 {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var subs: std.ArrayList(SubDto) = .empty;
    var servers: std.ArrayList(ServerDto) = .empty;
    var rules: std.ArrayList(RuleDto) = .empty;
    var domains: std.ArrayList(DomainDto) = .empty;
    if (!s.demo) {
        for (s.domains.items) |d| try domains.append(a, .{ .name = d.name, .route = d.route });
        for (s.subs.items) |sub| try subs.append(a, .{
            .id = sub.id,
            .name = sub.name,
            .url = sub.url,
            .updated_unix = sub.updated_unix,
            .update_hours = sub.update_hours,
            .announce = sub.announce,
            .support_url = sub.support_url,
        });
        for (s.servers.items) |*sv| try servers.append(a, .{
            .id = sv.id,
            .sub_id = sv.sub_id,
            .name = sv.name,
            .host = sv.host,
            .port = sv.port,
            .protocol = sv.protocol,
            .security = sv.security,
            .country = &sv.country,
            .exit = &sv.exit,
            .favorite = sv.favorite,
            .available = sv.available,
            .link = sv.link,
            .members = blk: {
                const ms = try a.alloc(MemberDto, sv.members.len);
                for (sv.members, ms) |*m, *d| d.* = .{ .link = m.link, .host = m.host, .port = m.port, .exit = &m.exit };
                break :blk ms;
            },
        });
        for (s.apps.items) |app| {
            if (app.route == .default) continue;
            try rules.append(a, .{ .app_id = app.id, .name = app.name, .path = app.path, .route = app.route });
        }
    }
    var settings = s.settings;
    if (s.demo) {
        settings.selected_server = null;
        settings.auto_server = null;
        settings.standby = false;
        if (settings.default_route == .server) settings.default_route = .auto;
    }
    const file: File = .{
        .next_id = s.next_id,
        .settings = settings,
        .subs = subs.items,
        .servers = servers.items,
        .rules = rules.items,
        .domains = domains.items,
    };
    return std.json.Stringify.valueAlloc(gpa, file, .{ .whitespace = .indent_2 });
}

pub fn deserialize(gpa: std.mem.Allocator, s: *model.State, bytes: []const u8) !void {
    var parsed = try std.json.parseFromSlice(File, gpa, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const f = parsed.value;
    if (f.version > version) return error.NewerVersion;

    s.settings = f.settings;
    s.next_id = @max(s.next_id, f.next_id);
    for (f.subs) |d| {
        try s.subs.append(s.gpa, .{
            .id = d.id,
            .name = try s.gpa.dupe(u8, d.name),
            .url = try s.gpa.dupe(u8, d.url),
            .updated_unix = d.updated_unix,
            .update_hours = d.update_hours,
            .announce = try s.gpa.dupe(u8, d.announce),
            .support_url = try s.gpa.dupe(u8, d.support_url),
        });
        s.next_id = @max(s.next_id, d.id + 1);
    }
    for (f.servers) |d| {
        var members: std.ArrayList(model.State.NewMember) = .empty;
        defer members.deinit(gpa);
        for (d.members) |m| try members.append(gpa, .{ .link = m.link, .host = m.host, .port = m.port });
        const sv = try s.addServer(d.sub_id, .{
            .name = d.name,
            .host = d.host,
            .port = d.port,
            .protocol = d.protocol,
            .security = d.security,
            .country = code(d.country),
            .link = d.link,
            .members = members.items,
        });
        sv.exit = code(d.exit);
        for (sv.members, d.members) |*m, dm| m.exit = code(dm.exit);
        sv.id = d.id;
        sv.favorite = d.favorite;
        sv.available = d.available;
        s.next_id = @max(s.next_id, d.id + 1);
    }
    for (f.rules) |d| {
        const app = try s.addApp(d.app_id, d.name, d.path);
        app.route = d.route;
    }
    for (f.domains) |d| {
        const dom = s.addDomain(d.name) catch continue;
        dom.route = d.route;
    }
}

/// A country code as kept, or "??".
fn code(text: []const u8) [2]u8 {
    return if (text.len == 2) text[0..2].* else "??".*;
}

/// Far above any real config (a thousand servers take about 1 MiB), and
/// checked on save too, so that what was saved can always be loaded.
const max_size = 64 << 20;

pub fn save(gpa: std.mem.Allocator, io: std.Io, dir_path: []const u8, s: *const model.State) !void {
    const bytes = try serialize(gpa, s);
    defer gpa.free(bytes);
    if (bytes.len > max_size) return error.FileTooBig;
    var dir = try std.Io.Dir.cwd().createDirPathOpen(io, dir_path, .{});
    defer dir.close(io);
    {
        var file = try dir.createFile(io, "config.json.tmp", .{ .permissions = private_file });
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
        // on disk before the rename, or a power cut can leave an empty file
        try file.sync(io);
    }
    try dir.rename("config.json.tmp", dir, "config.json", io);
}

/// Name a config that could not be read is kept under, for the user (or a
/// newer release, after a rollback) to take back.
pub const unreadable_name = "config.json.unreadable";

/// Move a config.json that failed to load out of the way, so the next save
/// does not replace the user's servers and rules with an empty list.
pub fn setAside(io: std.Io, dir_path: []const u8) !void {
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);
    try dir.rename("config.json", dir, unreadable_name, io);
}

const private_file: std.Io.File.Permissions = if (@hasDecl(std.Io.File.Permissions, "fromMode"))
    .fromMode(0o600)
else
    .default_file;

/// Returns false when there is no config yet. On an error `s` may hold
/// part of the file: start again from an empty state.
pub fn load(gpa: std.mem.Allocator, io: std.Io, dir_path: []const u8, s: *model.State) !bool {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{}) catch return false;
    defer dir.close(io);
    const bytes = dir.readFileAlloc(io, "config.json", gpa, .limited(max_size)) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer gpa.free(bytes);
    try deserialize(gpa, s, bytes);
    return true;
}

test "round trip keeps rules, pinned server and settings" {
    const gpa = std.testing.allocator;
    var a: model.State = .init(gpa);
    defer a.deinit();
    const sub = try a.addSubscription("Home", "https://example.invalid/s/token");
    const sv = try a.addServer(sub.id, .{ .name = "Amsterdam", .host = "nl.example", .port = 443, .protocol = .vless, .security = .reality, .country = "NL".* });
    sv.favorite = true;
    sv.exit = "DE".*;
    const sv_id = sv.id;
    a.settings.kill_switch = .strict;
    a.settings.check_exit = false;
    a.settings.selected_server = sv_id;
    (try a.addApp("org.telegram.desktop", "Telegram", "/Applications/Telegram.app")).route = .{ .server = sv_id };
    (try a.addApp("com.example.game", "Game", "")).route = .direct;
    _ = try a.addApp("com.example.norule", "No rule", "");
    (try a.addDomain("youtube.com")).route = .direct;
    (try a.addDomain("work.example")).route = .{ .server = sv_id };

    const bytes = try serialize(gpa, &a);
    defer gpa.free(bytes);

    var b: model.State = .init(gpa);
    defer b.deinit();
    try deserialize(gpa, &b, bytes);
    try std.testing.expectEqual(model.KillSwitch.strict, b.settings.kill_switch);
    try std.testing.expectEqual(sv_id, b.settings.selected_server.?);
    try std.testing.expectEqual(1, b.servers.items.len);
    try std.testing.expect(b.servers.items[0].favorite);
    try std.testing.expectEqualStrings("NL", &b.servers.items[0].country);
    try std.testing.expectEqualStrings("DE", &b.servers.items[0].exit);
    try std.testing.expect(!b.settings.check_exit);
    try std.testing.expectEqual(2, b.apps.items.len);
    try std.testing.expect(b.appById("org.telegram.desktop").?.route.eql(.{ .server = sv_id }));
    try std.testing.expectEqual(2, b.domains.items.len);
    try std.testing.expect(b.domainByName("youtube.com").?.route == .direct);
    try std.testing.expect(b.domainByName("work.example").?.route.eql(.{ .server = sv_id }));
    try std.testing.expect(b.newId() > sv_id);
}

test "demo data is never written to disk" {
    const gpa = std.testing.allocator;
    var a: model.State = .init(gpa);
    defer a.deinit();
    const sub = try a.addSubscription("Demo", "demo://");
    _ = try a.addServer(sub.id, .{ .name = "X", .host = "h", .port = 1, .protocol = .vless });
    a.demo = true;
    const bytes = try serialize(gpa, &a);
    defer gpa.free(bytes);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "demo://") == null);
}

test "round trip keeps groups and what the provider said" {
    const gpa = std.testing.allocator;
    var s: model.State = .init(gpa);
    defer s.deinit();
    const sub_id = (try s.addSubscription("free", "https://example.invalid/s/x")).id;
    try s.applyMeta(sub_id, .{ .update_hours = 1, .announce = "72 servers", .support_url = "https://t.me/x" });
    const g = try s.addServer(sub_id, .{
        .name = "Auto 1",
        .host = "1.example",
        .port = 443,
        .protocol = .vless,
        .link = "vless://a@1.example:443",
        .members = &.{ .{ .link = "vless://a@1.example:443", .host = "1.example", .port = 443 }, .{ .link = "vless://b@2.example:8443", .host = "2.example", .port = 8443 } },
    });
    g.favorite = true;
    g.members[1].exit = "FI".*;
    const id = g.id;
    const bytes = try serialize(gpa, &s);
    defer gpa.free(bytes);

    var back: model.State = .init(gpa);
    defer back.deinit();
    try deserialize(gpa, &back, bytes);
    const b = back.serverById(id).?;
    try std.testing.expect(b.favorite);
    try std.testing.expectEqual(2, b.members.len);
    try std.testing.expectEqual(8443, b.members[1].port);
    try std.testing.expectEqualStrings("vless://b@2.example:8443", b.members[1].link);
    try std.testing.expectEqualStrings("??", &b.members[0].exit);
    try std.testing.expectEqualStrings("FI", &b.members[1].exit);
    const sub = back.subById(sub_id).?;
    try std.testing.expectEqual(1, sub.update_hours);
    try std.testing.expectEqualStrings("72 servers", sub.announce);
    try std.testing.expectEqualStrings("https://t.me/x", sub.support_url);
}

test "a config that cannot be read is set aside, not overwritten" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &buf);
    const path = buf[0..n];
    try tmp.dir.writeFile(io, .{ .sub_path = "config.json", .data = "{\"version\": 99}" });

    var s: model.State = .init(gpa);
    defer s.deinit();
    try std.testing.expectError(error.NewerVersion, load(gpa, io, path, &s));
    try setAside(io, path);
    try save(gpa, io, path, &s);
    const kept = try tmp.dir.readFileAlloc(io, unreadable_name, gpa, .limited(1024));
    defer gpa.free(kept);
    try std.testing.expectEqualStrings("{\"version\": 99}", kept);
}

test "a config written by release 0.2.15 still loads" {
    const gpa = std.testing.allocator;
    var s: model.State = .init(gpa);
    defer s.deinit();
    // the field and enum names are the file's schema: renaming one in the
    // model breaks every user's config
    try deserialize(gpa, &s,
        \\{"version":1,"next_id":9,
        \\ "settings":{"tunnel_mode":"tun","kill_switch":"strict","default_route":{"auto":{}},
        \\   "protect_when_off":true,"ipv6":"block","auto_connect":true,"selected_server":3,
        \\   "notifications":true,"sounds":false},
        \\ "subs":[{"id":1,"name":"Home","url":"https://example.invalid/s","updated_unix":1700000000,"update_hours":12}],
        \\ "servers":[{"id":3,"sub_id":1,"name":"NL","host":"nl.example","port":443,"protocol":"vless",
        \\   "security":"reality","country":"NL","exit":"DE","favorite":true,"link":"vless://x@nl.example:443"}],
        \\ "rules":[{"app_id":"org.telegram.desktop","name":"Telegram","route":{"server":3}},
        \\   {"app_id":"com.valvesoftware.steam","name":"Steam","route":{"direct":{}}}],
        \\ "domains":[{"name":"youtube.com","route":{"block":{}}}]}
    );
    try std.testing.expectEqual(model.KillSwitch.strict, s.settings.kill_switch);
    try std.testing.expectEqual(3, s.settings.selected_server.?);
    try std.testing.expect(s.servers.items[0].favorite);
    try std.testing.expect(s.appById("org.telegram.desktop").?.route.eql(.{ .server = 3 }));
    try std.testing.expect(s.appById("com.valvesoftware.steam").?.route == .direct);
    try std.testing.expect(s.domainByName("youtube.com").?.route == .block);
}
