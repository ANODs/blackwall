//! The Russian list: sites of Russia and the CIS that go direct, never
//! through a VPN server, so that the servers' addresses are not seen there
//! (Settings "Russia and the CIS direct"). Built by tools/ru_list.py into
//! lists/ru-direct.txt; a copy is bundled, a fresher one is fetched from the
//! repository into the config directory and read from there.

const std = @import("std");
const model = @import("model.zig");

pub const bundled: []const u8 = @embedFile("ru_direct");
/// in the config directory, beside config.json
pub const file_name = "ru-direct.txt";
pub const url = "https://raw.githubusercontent.com/ANODs/blackwall/main/lists/ru-direct.txt";
/// how often the window fetches it
pub const refresh_s = 24 * 3600;
/// no list is ever bigger (the current one is about 12 KB)
pub const max_bytes = 1 << 20;

const magic = "# BLACKWALL";

/// The names of a list, normalized; comments and blank lines skipped.
pub const Names = struct {
    lines: std.mem.SplitIterator(u8, .scalar),
    buf: [253]u8 = undefined,

    pub fn init(text: []const u8) Names {
        return .{ .lines = std.mem.splitScalar(u8, text, '\n') };
    }

    pub fn next(it: *Names) ?[]const u8 {
        while (it.lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            return model.normalizeDomain(line, &it.buf) orelse continue;
        }
        return null;
    }
};

/// Whether `text` is such a list (a download may be an error page).
pub fn valid(text: []const u8) bool {
    if (!std.mem.startsWith(u8, text, magic) or text.len > max_bytes) return false;
    var it: Names = .init(text);
    var n: usize = 0;
    while (it.next()) |_| n += 1;
    return n >= 10;
}

/// The list to use: the fetched one in `dir` when it is good, else the
/// bundled one. Caller frees.
pub fn load(gpa: std.mem.Allocator, io: std.Io, dir: []const u8) ![]u8 {
    if (dir.len > 0) {
        var d = std.Io.Dir.cwd().openDir(io, dir, .{}) catch return gpa.dupe(u8, bundled);
        defer d.close(io);
        if (d.readFileAlloc(io, file_name, gpa, .limited(max_bytes))) |text| {
            if (valid(text)) return text;
            gpa.free(text);
        } else |_| {}
    }
    return gpa.dupe(u8, bundled);
}

/// Names and everything under them, looked up by a host name.
pub const Set = struct {
    map: std.StringHashMapUnmanaged(void) = .empty,

    /// Every name of `text`, copied with `a` (an arena: nothing is freed
    /// one by one).
    pub fn fromText(a: std.mem.Allocator, text: []const u8) !Set {
        var s: Set = .{};
        var it: Names = .init(text);
        while (it.next()) |n| try s.map.put(a, try a.dupe(u8, n), {});
        return s;
    }

    /// Copies of `names` (normalized already), with `a`.
    pub fn fromNames(a: std.mem.Allocator, names: []const []const u8) !Set {
        var s: Set = .{};
        try s.map.ensureTotalCapacity(a, @intCast(names.len));
        for (names) |n| s.map.putAssumeCapacity(try a.dupe(u8, n), {});
        return s;
    }

    pub fn count(s: *const Set) usize {
        return s.map.count();
    }

    /// Whether `host` or a name above it is in the set.
    pub fn contains(s: *const Set, host: []const u8) bool {
        if (s.map.count() == 0 or host.len == 0 or host.len > 253) return false;
        var buf: [253]u8 = undefined;
        var rest: []const u8 = std.ascii.lowerString(&buf, std.mem.trimEnd(u8, host, "."));
        while (true) {
            if (s.map.contains(rest)) return true;
            const dot = std.mem.indexOfScalar(u8, rest, '.') orelse return false;
            rest = rest[dot + 1 ..];
        }
    }
};

test "rulist: the bundled list is good and covers what it should" {
    try std.testing.expect(valid(bundled));
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const s = try Set.fromText(arena.allocator(), bundled);
    for ([_][]const u8{ "gosuslugi.ru", "www.sberbank.ru", "xn--80aswg.xn--p1ai", "mail.yandex.com", "vk.com", "kaspi.kz", "Ozon.RU." }) |h|
        try std.testing.expect(s.contains(h));
    for ([_][]const u8{ "google.com", "youtube.com", "claude.ai", "anthropic.com", "telegram.org", "ru.example.com", "" }) |h|
        try std.testing.expect(!s.contains(h));
}

test "rulist: an error page is not a list" {
    try std.testing.expect(!valid("<html>404</html>"));
    try std.testing.expect(!valid("# BLACKWALL\nru\n"));
}
