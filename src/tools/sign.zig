//! Release signing for the updater (src/core/update.zig, docs/updates.md):
//!   blackwall-sign keygen          new key pair: seed (secret) and public key, base64
//!   blackwall-sign sign <file>...  writes <file>.sig; seed from $BLACKWALL_UPDATE_KEY
//!   blackwall-sign verify <file>...  checks <file>.sig against $BLACKWALL_UPDATE_PUBKEY
//! The seed never appears on the command line, so it stays out of CI logs.

const std = @import("std");
const update = @import("update");
const Ed25519 = std.crypto.sign.Ed25519;
const b64 = std.base64.standard;

const max_file_bytes = 512 << 20;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const cmd = if (args.len > 1) args[1] else "";
    const files = if (args.len > 2) args[2..] else &.{};
    if (std.mem.eql(u8, cmd, "keygen") and files.len == 0) return keygen(init.io);
    if (std.mem.eql(u8, cmd, "sign") and files.len > 0) {
        const kp = try keyPair(init.environ_map.get("BLACKWALL_UPDATE_KEY") orelse fail("BLACKWALL_UPDATE_KEY is not set"));
        for (files) |f| try signFile(init.gpa, init.io, kp, f);
        return;
    }
    if (std.mem.eql(u8, cmd, "verify") and files.len > 0) {
        const key = update.decodeKey(init.environ_map.get("BLACKWALL_UPDATE_PUBKEY") orelse fail("BLACKWALL_UPDATE_PUBKEY is not set")) catch
            fail("BLACKWALL_UPDATE_PUBKEY is not a base64 Ed25519 public key");
        for (files) |f| try verifyFile(init.gpa, init.io, key, f);
        return;
    }
    fail("usage: blackwall-sign keygen | sign <file>... | verify <file>...");
}

fn fail(msg: []const u8) noreturn {
    std.debug.print("blackwall-sign: {s}\n", .{msg});
    std.process.exit(1);
}

fn keygen(io: std.Io) !void {
    const kp = Ed25519.KeyPair.generate(io);
    var seed: [b64.Encoder.calcSize(Ed25519.KeyPair.seed_length)]u8 = undefined;
    var public: [b64.Encoder.calcSize(Ed25519.PublicKey.encoded_length)]u8 = undefined;
    _ = b64.Encoder.encode(&seed, &kp.secret_key.seed());
    _ = b64.Encoder.encode(&public, &kp.public_key.toBytes());
    var buf: [512]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(io, &buf);
    try out.interface.print(
        \\secret seed (GitHub secret BLACKWALL_UPDATE_KEY, keep it nowhere else):
        \\{s}
        \\public key (GitHub variable BLACKWALL_UPDATE_PUBKEY):
        \\{s}
        \\
    , .{ &seed, &public });
    try out.interface.flush();
}

fn keyPair(seed_text: []const u8) !Ed25519.KeyPair {
    const t = std.mem.trim(u8, seed_text, " \t\r\n");
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    if ((b64.Decoder.calcSizeForSlice(t) catch 0) != seed.len) fail("BLACKWALL_UPDATE_KEY is not a base64 32-byte seed");
    try b64.Decoder.decode(&seed, t);
    return Ed25519.KeyPair.generateDeterministic(seed);
}

fn signFile(gpa: std.mem.Allocator, io: std.Io, kp: Ed25519.KeyPair, path: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    const bytes = try cwd.readFileAlloc(io, path, gpa, .limited(max_file_bytes));
    defer gpa.free(bytes);
    const sig = try kp.sign(bytes, null);
    var text: [b64.Encoder.calcSize(Ed25519.Signature.encoded_length) + 1]u8 = undefined;
    _ = b64.Encoder.encode(text[0 .. text.len - 1], &sig.toBytes());
    text[text.len - 1] = '\n';
    const sig_path = try std.fmt.allocPrint(gpa, "{s}.sig", .{path});
    defer gpa.free(sig_path);
    try cwd.writeFile(io, .{ .sub_path = sig_path, .data = &text });
    std.debug.print("signed {s}\n", .{path});
}

fn verifyFile(gpa: std.mem.Allocator, io: std.Io, key: [Ed25519.PublicKey.encoded_length]u8, path: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    const bytes = try cwd.readFileAlloc(io, path, gpa, .limited(max_file_bytes));
    defer gpa.free(bytes);
    const sig_path = try std.fmt.allocPrint(gpa, "{s}.sig", .{path});
    defer gpa.free(sig_path);
    const sig = try cwd.readFileAlloc(io, sig_path, gpa, .limited(1024));
    defer gpa.free(sig);
    update.verify(key, bytes, sig) catch fail("signature does not match the public key");
    std.debug.print("ok {s}\n", .{path});
}
