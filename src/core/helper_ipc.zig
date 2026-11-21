//! Service <-> root helper protocol (macOS).
//!
//! One JSON request line per connection over a Unix socket. Anyone may
//! connect; the helper answers only the user who installed it (and root),
//! told by the peer's uid. The reply to "up" is a
//! JSON line sent together with the utun descriptor (SCM_RIGHTS).
//!
//!   {"cmd":"up", ...UpRequest}   -> Reply + utun fd (when already up: the
//!                                   settings are applied again, same utun)
//!   {"cmd":"servers", ...}       -> Reply   (new VPN server addresses for the kill switch)
//!   {"cmd":"down"}               -> Reply   (routes, DNS and kill switch removed, utun closed)
//!   {"cmd":"upgrade","path":P,"sig":S} -> Reply   (a newer helper signed by the release key
//!                                   replaces this one; no administrator needed)
//!   {"cmd":"hold","hold":true} -> Reply   (from the next boot on, capture everything as soon
//!                                   as the network is there and hold it until a service
//!                                   takes over: nothing leaves between login and the VPN)
//!   {"cmd":"status"}             -> Reply
//!   {"cmd":"conflicts"}          -> Reply   (owners: the processes holding other VPNs'
//!                                   tunnels that capture traffic; pid 0 when unknown)
//!   {"cmd":"stop", pid, start_us, path, kill}
//!                                -> Reply   (asks one of those owners to quit: SIGTERM, or
//!                                   SIGKILL with kill. Refused unless pid, start time and
//!                                   path still match and it still holds a capturing tunnel;
//!                                   never for system processes; DPI tools such as
//!                                   zapret's tpws or ByeDPI also qualify)
//!   {"cmd":"stop_zapret"}        -> Reply   (zapret's own "stop", which also removes its pf
//!                                   rules; only from its standard, root-owned location)
//!
//! Every reply carries the helper's `version` and `build`.

/// Bumped whenever requests or replies change incompatibly; the window
/// reinstalls a helper that reports another one.
const std = @import("std");

pub const version: u32 = 2;

pub const socket_path = "/var/run/dev.blackwall.helper.sock";
pub const label = "dev.blackwall.helper";
pub const install_path = "/Library/PrivilegedHelperTools/" ++ label;
pub const plist_path = "/Library/LaunchDaemons/" ++ label ++ ".plist";

/// Address of the TUN itself, and of the DNS server the TUN answers as.
pub const tun_addr = [4]u8{ 198, 18, 0, 1 };
pub const tun_dns = [4]u8{ 198, 18, 0, 2 };

pub const Request = struct {
    cmd: []const u8,
    mtu: u16 = 1500,
    /// "tunnel": IPv6 goes into the TUN too; "block": IPv6 is captured and
    /// refused; "system": IPv6 is left alone
    ipv6: []const u8 = "tunnel",
    /// "off" | "selective" | "strict"
    killswitch: []const u8 = "selective",
    allow_lan: bool = true,
    /// IPv4 addresses of the VPN servers (the strict kill switch lets only these out)
    servers: []const []const u8 = &.{},
    /// take over even though another VPN captures traffic
    force: bool = false,
    /// "stop": the process, as the window saw it
    pid: i32 = 0,
    start_us: u64 = 0,
    path: []const u8 = "",
    /// "stop": SIGKILL instead of asking it to quit
    kill: bool = false,
    /// "hold": whether traffic is held from boot until a service takes over
    hold: bool = false,
    /// "upgrade": the text of the new helper's signature file (see `Signed`);
    /// the new helper itself is at `path`
    sig: []const u8 = "",
};

// ---------------------------------------------------------------- signed helpers
//
// A release signs the helper inside the app with the key that signs the
// release files. A running helper built with that public key accepts a
// newer helper carrying such a signature and replaces itself with it, so
// the administrator is asked once, at the first install, and never for an
// update. What is signed is a fixed word, the helper's release and its
// bytes: a signature of an old helper cannot pass for a newer one, nor a
// signature of a release file for a helper.

const Ed25519 = std.crypto.sign.Ed25519;
const b64 = std.base64.standard;

pub const sig_word = "blackwall-helper ";
/// The two programs signed under `sig_word`: the macOS helper and the
/// Windows service. The word is the same for both (installed services check
/// their upgrades with it), so each side also checks the file is its own
/// kind: a signed Windows service must never pass for the root helper.
pub const Program = enum { macos_helper, windows_service };

pub fn isProgram(kind: Program, bytes: []const u8) bool {
    if (bytes.len < 64) return false;
    return switch (kind) {
        // a 64-bit Mach-O for arm64 (MH_MAGIC_64, CPU_TYPE_ARM64)
        .macos_helper => std.mem.readInt(u32, bytes[0..4], .little) == 0xfeedfacf and
            std.mem.readInt(u32, bytes[4..8], .little) == 0x0100000c,
        // an MZ header pointing at a PE signature
        .windows_service => blk: {
            if (!std.mem.eql(u8, bytes[0..2], "MZ")) break :blk false;
            const pe = std.mem.readInt(u32, bytes[0x3c..0x40], .little);
            break :blk pe <= bytes.len - 4 and std.mem.eql(u8, bytes[pe..][0..4], "PE\x00\x00");
        },
    };
}

test "a signed program is checked to be the kind it replaces" {
    var macho: [64]u8 = @splat(0);
    std.mem.writeInt(u32, macho[0..4], 0xfeedfacf, .little);
    std.mem.writeInt(u32, macho[4..8], 0x0100000c, .little);
    var pe: [128]u8 = @splat(0);
    @memcpy(pe[0..2], "MZ");
    std.mem.writeInt(u32, pe[0x3c..0x40], 0x40, .little);
    @memcpy(pe[0x40..0x44], "PE\x00\x00");
    try std.testing.expect(isProgram(.macos_helper, &macho));
    try std.testing.expect(!isProgram(.macos_helper, &pe));
    try std.testing.expect(isProgram(.windows_service, &pe));
    try std.testing.expect(!isProgram(.windows_service, &macho));
    // a PE offset past the end
    std.mem.writeInt(u32, pe[0x3c..0x40], 0xffff_fff0, .little);
    try std.testing.expect(!isProgram(.windows_service, &pe));
}

/// Name of the signature file in the app's Resources folder.
pub const sig_file = "blackwall-helper.sig";

/// The signature file: "<release>\n<base64 signature>\n".
pub const Signed = struct {
    version: []const u8,
    sig: []const u8,

    pub fn parse(text: []const u8) ?Signed {
        var lines = std.mem.tokenizeAny(u8, text, "\r\n");
        const release = lines.next() orelse return null;
        const sig = lines.next() orelse return null;
        if (lines.next() != null) return null;
        return .{ .version = release, .sig = sig };
    }
};

/// Sign helper `bytes` of `release`; the caller writes
/// "<release>\n<result>\n" as the signature file.
pub fn signHelper(io: std.Io, kp: Ed25519.KeyPair, release: []const u8, bytes: []const u8, out: *[b64.Encoder.calcSize(Ed25519.Signature.encoded_length)]u8) ![]const u8 {
    var s = try kp.signer(null, io);
    s.update(sig_word);
    s.update(release);
    s.update("\n");
    s.update(bytes);
    return b64.Encoder.encode(out, &s.finalize().toBytes());
}

/// Whether `signed` is the release key's signature of these helper bytes.
pub fn verifyHelper(public_key_b64: []const u8, signed: Signed, bytes: []const u8) error{BadSignature}!void {
    var key: [Ed25519.PublicKey.encoded_length]u8 = undefined;
    const kt = std.mem.trim(u8, public_key_b64, " \t\r\n");
    if ((b64.Decoder.calcSizeForSlice(kt) catch 0) != key.len) return error.BadSignature;
    b64.Decoder.decode(&key, kt) catch return error.BadSignature;
    var raw: [Ed25519.Signature.encoded_length]u8 = undefined;
    if ((b64.Decoder.calcSizeForSlice(signed.sig) catch 0) != raw.len) return error.BadSignature;
    b64.Decoder.decode(&raw, signed.sig) catch return error.BadSignature;
    const pk = Ed25519.PublicKey.fromBytes(key) catch return error.BadSignature;
    var v = Ed25519.Signature.fromBytes(raw).verifier(pk) catch return error.BadSignature;
    v.update(sig_word);
    v.update(signed.version);
    v.update("\n");
    v.update(bytes);
    v.verify() catch return error.BadSignature;
}

test "a helper's signature covers its release and its bytes" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(9));
    var pub_text: [b64.Encoder.calcSize(Ed25519.PublicKey.encoded_length)]u8 = undefined;
    const public = b64.Encoder.encode(&pub_text, &kp.public_key.toBytes());
    var buf: [b64.Encoder.calcSize(Ed25519.Signature.encoded_length)]u8 = undefined;
    const sig = try signHelper(std.testing.io, kp, "0.2.0", "helper bytes", &buf);
    var file_buf: [160]u8 = undefined;
    const file = try std.fmt.bufPrint(&file_buf, "0.2.0\n{s}\n", .{sig});
    const signed = Signed.parse(file).?;
    try std.testing.expectEqualStrings("0.2.0", signed.version);
    try verifyHelper(public, signed, "helper bytes");
    // other bytes, another release, another key, a plain file signature
    try std.testing.expectError(error.BadSignature, verifyHelper(public, signed, "helper bytez"));
    try std.testing.expectError(error.BadSignature, verifyHelper(public, .{ .version = "0.3.0", .sig = signed.sig }, "helper bytes"));
    const other = try Ed25519.KeyPair.generateDeterministic(@splat(8));
    var other_text: [b64.Encoder.calcSize(Ed25519.PublicKey.encoded_length)]u8 = undefined;
    try std.testing.expectError(error.BadSignature, verifyHelper(b64.Encoder.encode(&other_text, &other.public_key.toBytes()), signed, "helper bytes"));
    var plain_buf: [b64.Encoder.calcSize(Ed25519.Signature.encoded_length)]u8 = undefined;
    const plain = b64.Encoder.encode(&plain_buf, &(try kp.sign("helper bytes", null)).toBytes());
    try std.testing.expectError(error.BadSignature, verifyHelper(public, .{ .version = "0.2.0", .sig = plain }, "helper bytes"));
    try std.testing.expectError(error.BadSignature, verifyHelper("", signed, "helper bytes"));
    try std.testing.expect(Signed.parse("0.2.0\n") == null);
    try std.testing.expect(Signed.parse("a\nb\nc\n") == null);
}

/// A process holding another VPN's tunnel.
pub const Owner = struct {
    ifname: []const u8 = "",
    /// 0 when nobody could be found holding it
    pid: i32 = 0,
    uid: u32 = 0,
    /// start time in microseconds: with pid and path, the process's identity
    start_us: u64 = 0,
    path: []const u8 = "",
};

pub const Reply = struct {
    version: u32 = 0,
    /// release of the helper binary: the root helper is updated with the app,
    /// so a window of another release reinstalls it ("" from older helpers)
    build: []const u8 = "",
    ok: bool = false,
    @"error": []const u8 = "",
    up: bool = false,
    ifname: []const u8 = "",
    /// the physical interface our own sockets must stay on
    bind_index: u32 = 0,
    bind_name: []const u8 = "",
    /// the real DNS servers, reachable through `bind_name`
    dns: []const []const u8 = &.{},
    /// interfaces of other VPNs that capture traffic (with error "conflict")
    conflicts: []const []const u8 = &.{},
    killswitch: []const u8 = "off",
    /// "conflicts": who holds them
    owners: []const Owner = &.{},
};
