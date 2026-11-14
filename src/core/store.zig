//! Versioned JSON persistence of the user's configuration.
//! Written atomically (temp file + rename) so a crash never leaves a
//! half-written config; a failed load leaves the in-memory state untouched.

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
    favorite: bool = false,
    available: bool = true,
    link: []const u8 = "",
};

const SubDto = struct {
    id: u32,
    name: []const u8,
    url: []const u8,
    updated_unix: i64 = 0,
};

const RuleDto = struct {
    app_id: []const u8,
    name: []const u8,
    path: []const u8 = "",
    route: model.Route,
};

const File = struct {
    version: u32 = version,
    next_id: u32 = 1,
    settings: model.Settings = .{},
    subs: []const SubDto = &.{},
    servers: []const ServerDto = &.{},
    rules: []const RuleDto = &.{},
};

pub fn serialize(gpa: std.mem.Allocator, s: *const model.State) ![]u8 {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var subs: std.ArrayList(SubDto) = .empty;
    var servers: std.ArrayList(ServerDto) = .empty;
    var rules: std.ArrayList(RuleDto) = .empty;
    if (!s.demo) {
        for (s.subs.items) |sub| try subs.append(a, .{ .id = sub.id, .name = sub.name, .url = sub.url, .updated_unix = sub.updated_unix });
        for (s.servers.items) |*sv| try servers.append(a, .{
            .id = sv.id,
            .sub_id = sv.sub_id,
            .name = sv.name,
            .host = sv.host,
            .port = sv.port,
            .protocol = sv.protocol,
            .security = sv.security,
            .country = &sv.country,
            .favorite = sv.favorite,
            .available = sv.available,
            .link = sv.link,
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
        });
        s.next_id = @max(s.next_id, d.id + 1);
    }
    for (f.servers) |d| {
        try s.servers.append(s.gpa, .{
            .id = d.id,
            .sub_id = d.sub_id,
            .name = try s.gpa.dupe(u8, d.name),
            .host = try s.gpa.dupe(u8, d.host),
            .port = d.port,
            .protocol = d.protocol,
            .security = d.security,
            .country = if (d.country.len == 2) d.country[0..2].* else "??".*,
            .favorite = d.favorite,
            .available = d.available,
            .link = try s.gpa.dupe(u8, d.link),
        });
        s.next_id = @max(s.next_id, d.id + 1);
    }
    for (f.rules) |d| {
        const app = try s.addApp(d.app_id, d.name, d.path);
        app.route = d.route;
    }
}

pub fn save(gpa: std.mem.Allocator, io: std.Io, dir_path: []const u8, s: *const model.State) !void {
    const bytes = try serialize(gpa, s);
    defer gpa.free(bytes);
    var dir = try std.Io.Dir.cwd().createDirPathOpen(io, dir_path, .{});
    defer dir.close(io);
    try dir.writeFile(io, .{ .sub_path = "config.json.tmp", .data = bytes, .flags = .{ .permissions = private_file } });
    try dir.rename("config.json.tmp", dir, "config.json", io);
}

const private_file: std.Io.File.Permissions = if (@hasDecl(std.Io.File.Permissions, "fromMode"))
    .fromMode(0o600)
else
    .default_file;

/// Returns false when there is no config yet.
pub fn load(gpa: std.mem.Allocator, io: std.Io, dir_path: []const u8, s: *model.State) !bool {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{}) catch return false;
    defer dir.close(io);
    const bytes = dir.readFileAlloc(io, "config.json", gpa, .limited(8 << 20)) catch |err| switch (err) {
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
    const sv_id = sv.id;
    a.settings.kill_switch = .strict;
    a.settings.selected_server = sv_id;
    (try a.addApp("org.telegram.desktop", "Telegram", "/Applications/Telegram.app")).route = .{ .server = sv_id };
    (try a.addApp("com.example.game", "Game", "")).route = .direct;
    _ = try a.addApp("com.example.norule", "No rule", "");

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
    try std.testing.expectEqual(2, b.apps.items.len);
    try std.testing.expect(b.appById("org.telegram.desktop").?.route.eql(.{ .server = sv_id }));
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
