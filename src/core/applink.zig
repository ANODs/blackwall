//! Links that open the app: `blackwall://add/<subscription address>`.
//!
//! A page (the provider's "add to app" button) or another program hands
//! the system such a link; the system starts the app with it, or gives it
//! to the app that runs. Everything after `add/` is the subscription's
//! address as it is, or the same percent-encoded; `import/` means the same
//! (other clients spell it that way).
//!
//!   blackwall://add/https://example.com/s/token
//!   blackwall://add/https%3A%2F%2Fexample.com%2Fs%2Ftoken
//!   blackwall://import/https://example.com/s/token
//!
//! Anyone can make such a link, so only a plain `http://` or `https://`
//! address of a sane length comes out of here; anything else is no link at
//! all, and the caller ignores it without a word.

const std = @import("std");

pub const scheme = "blackwall";

/// The longest subscription address a link may carry.
pub const max_url = 2048;
/// The longest link worth looking at: the address, percent-encoded at worst.
pub const max_link = 3 * max_url + 64;

/// Whether `text` is addressed to the app at all (a command line argument
/// may be anything).
pub fn isAppLink(text: []const u8) bool {
    const t = std.mem.trim(u8, text, " \t\r\n");
    return std.ascii.startsWithIgnoreCase(t, scheme ++ ":");
}

/// The subscription address in `link`, written to `buf`, or null when
/// `link` is not a link that adds a subscription.
pub fn subscriptionUrl(buf: *[max_url]u8, link: []const u8) ?[]const u8 {
    const text = std.mem.trim(u8, link, " \t\r\n");
    if (text.len > max_link) return null;
    var rest = after(text, scheme ++ "://") orelse return null;
    rest = after(rest, "add/") orelse after(rest, "import/") orelse return null;

    // as it is; its own percent signs belong to the address
    if (web(rest)) {
        if (rest.len > buf.len) return null;
        @memcpy(buf[0..rest.len], rest);
        return checked(buf[0..rest.len]);
    }
    // or encoded as a whole, once
    var n: usize = 0;
    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        if (n == buf.len) return null;
        if (rest[i] == '%') {
            if (i + 2 >= rest.len) return null;
            buf[n] = std.fmt.parseInt(u8, rest[i + 1 .. i + 3], 16) catch return null;
            i += 2;
        } else buf[n] = rest[i];
        n += 1;
    }
    if (!web(buf[0..n])) return null;
    return checked(buf[0..n]);
}

fn after(text: []const u8, prefix: []const u8) ?[]const u8 {
    return if (std.ascii.startsWithIgnoreCase(text, prefix)) text[prefix.len..] else null;
}

fn web(url: []const u8) bool {
    return std.ascii.startsWithIgnoreCase(url, "https://") or std.ascii.startsWithIgnoreCase(url, "http://");
}

/// An address the download can take: readable text without spaces or
/// control characters, with a host in it.
fn checked(url: []const u8) ?[]const u8 {
    for (url) |ch| if (ch <= ' ' or ch == 0x7f) return null;
    if (!std.unicode.utf8ValidateSlice(url)) return null;
    const uri = std.Uri.parse(url) catch return null;
    const host = uri.host orelse return null;
    if (host.isEmpty()) return null;
    return url;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn expectUrl(want: ?[]const u8, link: []const u8) !void {
    var buf: [max_url]u8 = undefined;
    const got = subscriptionUrl(&buf, link);
    if (want) |w| {
        try testing.expect(got != null);
        try testing.expectEqualStrings(w, got.?);
    } else try testing.expect(got == null);
}

test "the address after add/ is taken as it is" {
    try expectUrl("https://gram.ventures/s/AbCdEf0123456789abcdef", "blackwall://add/https://gram.ventures/s/AbCdEf0123456789abcdef");
    try expectUrl("http://127.0.0.1:8080/sub?x=1&y=2#f", "blackwall://add/http://127.0.0.1:8080/sub?x=1&y=2#f");
    // the way the system hands it over: spaces and a line end around it
    try expectUrl("https://example.com/s/t", "  blackwall://add/https://example.com/s/t\r\n");
    // the scheme and the word are not case sensitive, the address keeps its case
    try expectUrl("HTTPS://Example.com/S/Token", "BLACKWALL://Add/HTTPS://Example.com/S/Token");
}

test "import/ means the same as add/" {
    try expectUrl("https://example.com/s/t", "blackwall://import/https://example.com/s/t");
    try expectUrl("https://example.com/s/t", "blackwall://import/https%3A%2F%2Fexample.com%2Fs%2Ft");
}

test "an address encoded as a whole is decoded once" {
    try expectUrl("https://gram.ventures/s/AbCdEf", "blackwall://add/https%3A%2F%2Fgram.ventures%2Fs%2FAbCdEf");
    try expectUrl("https://gram.ventures/s/AbCdEf", "blackwall://add/https%3a%2f%2fgram.ventures%2fs%2fAbCdEf");
    // what was encoded twice inside it stays encoded once
    try expectUrl("https://example.com/s?name=a%20b", "blackwall://add/https%3A%2F%2Fexample.com%2Fs%3Fname%3Da%2520b");
}

test "an address given as it is keeps its own percent signs" {
    try expectUrl("https://example.com/s?name=a%20b&next=https%3A%2F%2Fx", "blackwall://add/https://example.com/s?name=a%20b&next=https%3A%2F%2Fx");
}

test "only http and https addresses are taken" {
    try expectUrl(null, "blackwall://add/ftp://example.com/s");
    try expectUrl(null, "blackwall://add/file:///etc/passwd");
    try expectUrl(null, "blackwall://add/file%3A%2F%2F%2Fetc%2Fpasswd");
    try expectUrl(null, "blackwall://add/vless://id@example.com:443");
    try expectUrl(null, "blackwall://add/javascript:alert(1)");
    try expectUrl(null, "blackwall://add/example.com/s/t");
    try expectUrl(null, "blackwall://add//example.com/s/t");
}

test "what is not a link that adds a subscription is refused" {
    try expectUrl(null, "");
    try expectUrl(null, "blackwall://");
    try expectUrl(null, "blackwall://add");
    try expectUrl(null, "blackwall://add/");
    try expectUrl(null, "blackwall://connect/https://example.com/s");
    try expectUrl(null, "blackwall://remove/https://example.com/s");
    try expectUrl(null, "blackwall:add/https://example.com/s");
    try expectUrl(null, "happ://add/https://example.com/s");
    try expectUrl(null, "https://example.com/s");
    try expectUrl(null, "/Users/someone/Downloads/file.txt");
    try expectUrl(null, "--add=https://example.com/s");
}

test "an address without a host, with spaces or control characters is refused" {
    try expectUrl(null, "blackwall://add/https://");
    try expectUrl(null, "blackwall://add/https:///s/t");
    try expectUrl(null, "blackwall://add/https://?x=1");
    try expectUrl(null, "blackwall://add/https://example.com/a b");
    try expectUrl(null, "blackwall://add/https%3A%2F%2Fexample.com%2Fa%20b");
    try expectUrl(null, "blackwall://add/https%3A%2F%2Fexample.com%2Fa%0Ab");
    try expectUrl(null, "blackwall://add/https%3A%2F%2Fexample.com%2Fa%00b");
    try expectUrl(null, "blackwall://add/https://example.com/\x01");
    // not text
    try expectUrl(null, "blackwall://add/https://example.com/\xff\xfe");
    try expectUrl(null, "blackwall://add/https%3A%2F%2Fexample.com%2F%FF");
    // a broken escape
    try expectUrl(null, "blackwall://add/https%3A%2F%2Fexample.com%2F%zz");
    try expectUrl(null, "blackwall://add/https%3A%2F%2Fexample.com%2F%4");
}

test "the address has a longest length" {
    const head = "blackwall://add/";
    const start = "https://example.com/";
    var link: [head.len + max_url + 1]u8 = undefined;
    @memcpy(link[0..head.len], head);
    @memcpy(link[head.len..][0..start.len], start);
    @memset(link[head.len + start.len ..], 'a');
    // exactly the longest
    try expectUrl(link[head.len .. head.len + max_url], link[0 .. head.len + max_url]);
    // one more
    try expectUrl(null, &link);
    // and something enormous is not even read
    const huge = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(huge);
    @memset(huge, 'a');
    @memcpy(huge[0..head.len], head);
    @memcpy(huge[head.len..][0..start.len], start);
    try expectUrl(null, huge);
}

test "an argument is told from a link by its scheme" {
    try testing.expect(isAppLink("blackwall://add/https://example.com/s"));
    try testing.expect(isAppLink("BLACKWALL:anything"));
    try testing.expect(!isAppLink("--help"));
    try testing.expect(!isAppLink("C:\\Users\\u\\blackwall.txt"));
    try testing.expect(!isAppLink(""));
}
