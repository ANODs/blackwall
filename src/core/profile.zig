//! A routing profile: the default route, the Russian list switch, and the
//! rules by site and by application, as JSON to export, import or start
//! over from (Settings "Routing"). A rule that names a server keeps its
//! name; on import it finds the server of that name, else it means "VPN".

const std = @import("std");
const model = @import("model.zig");

pub const version = 1;

const RuleDto = struct {
    route: []const u8,
    /// with route "server": the server's name
    server: ?[]const u8 = null,
};

const SiteDto = struct {
    name: []const u8,
    route: []const u8,
    server: ?[]const u8 = null,
};

const AppDto = struct {
    id: []const u8,
    name: []const u8 = "",
    path: []const u8 = "",
    route: []const u8,
    server: ?[]const u8 = null,
};

const File = struct {
    blackwall_routing: u32 = version,
    default: []const u8 = "vpn",
    ru_direct: bool = true,
    sites: []const SiteDto = &.{},
    apps: []const AppDto = &.{},
};

fn routeName(r: model.Route) []const u8 {
    return switch (r) {
        .default => "default",
        .auto => "vpn",
        .server => "server",
        .direct => "direct",
        .dpi => "dpi",
        .block => "block",
    };
}

fn serverName(s: *model.State, r: model.Route) ?[]const u8 {
    if (r != .server) return null;
    return if (s.serverById(r.server)) |sv| sv.name else null;
}

/// The profile of `s` as JSON (caller frees).
pub fn exportJson(gpa: std.mem.Allocator, s: *model.State) ![]u8 {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var sites: std.ArrayList(SiteDto) = .empty;
    for (s.domains.items) |d| {
        if (d.route == .default) continue;
        try sites.append(a, .{ .name = d.name, .route = routeName(d.route), .server = serverName(s, d.route) });
    }
    var apps: std.ArrayList(AppDto) = .empty;
    for (s.apps.items) |app| {
        if (app.route == .default) continue;
        try apps.append(a, .{ .id = app.id, .name = app.name, .path = app.path, .route = routeName(app.route), .server = serverName(s, app.route) });
    }
    const file: File = .{
        .default = if (s.settings.default_route == .direct) "direct" else "vpn",
        .ru_direct = s.settings.ru_direct,
        .sites = sites.items,
        .apps = apps.items,
    };
    return std.json.Stringify.valueAlloc(gpa, file, .{ .whitespace = .indent_2, .emit_null_optional_fields = false });
}

fn routeOf(s: *model.State, name: []const u8, server: ?[]const u8) ?model.Route {
    const tag = std.meta.stringToEnum(enum { default, vpn, server, direct, dpi, block }, name) orelse return null;
    return switch (tag) {
        .default => .default,
        .vpn => .auto,
        .direct => .direct,
        .dpi => .dpi,
        .block => .block,
        .server => blk: {
            const want = server orelse break :blk .auto;
            for (s.servers.items) |sv| if (std.mem.eql(u8, sv.name, want)) break :blk .{ .server = sv.id };
            break :blk .auto;
        },
    };
}

/// The routing of a fresh install: everything through the VPN, the Russian
/// list on, no rules of the user's.
pub fn reset(s: *model.State) void {
    s.settings.default_route = .auto;
    s.settings.ru_direct = true;
    for (s.domains.items) |d| s.gpa.free(d.name);
    s.domains.clearRetainingCapacity();
    for (s.apps.items) |*app| app.route = .default;
}

pub const Counts = struct { sites: usize = 0, apps: usize = 0 };

/// Replace the routing of `s` with the profile in `text`. Nothing changes
/// when it is not one.
pub fn importJson(gpa: std.mem.Allocator, s: *model.State, text: []const u8) !Counts {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, trimmed, .{}) catch return error.NotAProfile;
    defer parsed.deinit();
    if (parsed.value != .object or parsed.value.object.get("blackwall_routing") == null) return error.NotAProfile;
    const f = std.json.parseFromValueLeaky(File, parsed.arena.allocator(), parsed.value, .{ .ignore_unknown_fields = true }) catch return error.NotAProfile;
    if (f.blackwall_routing > version) return error.NewerVersion;

    reset(s);
    s.settings.default_route = if (std.mem.eql(u8, f.default, "direct")) .direct else .auto;
    s.settings.ru_direct = f.ru_direct;
    var n: Counts = .{};
    for (f.sites) |site| {
        const route = routeOf(s, site.route, site.server) orelse continue;
        const d = s.addDomain(site.name) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => continue,
        };
        d.route = route;
        n.sites += 1;
    }
    for (f.apps) |app| {
        const route = routeOf(s, app.route, app.server) orelse continue;
        if (app.id.len == 0) continue;
        const a = try s.addApp(app.id, if (app.name.len > 0) app.name else app.id, app.path);
        a.route = route;
        n.apps += 1;
    }
    return n;
}

test "profile: export, then import into another state" {
    const gpa = std.testing.allocator;
    var s: model.State = .init(gpa);
    defer s.deinit();
    s.settings.default_route = .direct;
    s.settings.ru_direct = false;
    (try s.addDomain("YouTube.com")).route = .dpi;
    (try s.addDomain("ads.example")).route = .block;
    (try s.addApp("/Applications/Telegram.app", "Telegram", "")).route = .auto;
    _ = try s.addApp("/Applications/Notes.app", "Notes", "");
    const json = try exportJson(gpa, &s);
    defer gpa.free(json);

    var t: model.State = .init(gpa);
    defer t.deinit();
    (try t.addDomain("old.example")).route = .direct;
    const n = try importJson(gpa, &t, json);
    try std.testing.expectEqual(2, n.sites);
    try std.testing.expectEqual(1, n.apps);
    try std.testing.expect(t.settings.default_route == .direct);
    try std.testing.expect(!t.settings.ru_direct);
    try std.testing.expect(t.domainByName("old.example") == null);
    try std.testing.expect(t.domainByName("youtube.com").?.route == .dpi);
    try std.testing.expect(t.appById("/Applications/Telegram.app").?.route == .auto);
    try std.testing.expect(t.appById("/Applications/Notes.app") == null);

    reset(&t);
    try std.testing.expect(t.settings.ru_direct and t.settings.default_route == .auto);
    try std.testing.expectEqual(0, t.domains.items.len);
    try std.testing.expect(t.appById("/Applications/Telegram.app").?.route == .default);
}

test "profile: anything else is refused and changes nothing" {
    const gpa = std.testing.allocator;
    var s: model.State = .init(gpa);
    defer s.deinit();
    (try s.addDomain("keep.example")).route = .direct;
    try std.testing.expectError(error.NotAProfile, importJson(gpa, &s, "vless://abc"));
    try std.testing.expectError(error.NotAProfile, importJson(gpa, &s, "{\"sites\":[]}"));
    try std.testing.expectError(error.NewerVersion, importJson(gpa, &s, "{\"blackwall_routing\": 9}"));
    try std.testing.expect(s.domainByName("keep.example") != null);
}
