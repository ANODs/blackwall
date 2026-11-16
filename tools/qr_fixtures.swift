// Writes src/core/qr_fixtures.zig: QR codes made by Apple's CoreImage,
// module by module, for qr.zig's reader to be checked against an
// encoder other than its own.  swift tools/qr_fixtures.swift > src/core/qr_fixtures.zig
import CoreImage
import Foundation

func modules(_ text: String, _ level: String) -> [String] {
    let f = CIFilter(name: "CIQRCodeGenerator")!
    f.setValue(text.data(using: .utf8), forKey: "inputMessage")
    f.setValue(level, forKey: "inputCorrectionLevel")
    let img = f.outputImage!
    let ctx = CIContext()
    let w = Int(img.extent.width), h = Int(img.extent.height)
    var px = [UInt8](repeating: 0, count: w * h * 4)
    ctx.render(img, toBitmap: &px, rowBytes: w * 4, bounds: img.extent, format: .RGBA8, colorSpace: CGColorSpaceCreateDeviceRGB())
    var rows: [String] = []
    for y in 0..<h {
        var s = ""
        for x in 0..<w { s += px[(y * w + x) * 4] < 128 ? "#" : "." }
        rows.append(s)
    }
    // drop the quiet zone
    let top = rows.firstIndex { $0.contains("#") }!, bottom = rows.lastIndex { $0.contains("#") }!
    let lefts = rows.compactMap { $0.firstIndex(of: "#")?.utf16Offset(in: $0) }
    let rights = rows.compactMap { $0.lastIndex(of: "#")?.utf16Offset(in: $0) }
    let l = lefts.min()!, r = rights.max()!
    return rows[top...bottom].map { String(Array($0)[l...r]) }
}

let link = "vless://11111111-2222-3333-4444-555555555555@nl.example.org:443?type=tcp&security=reality&sni=www.microsoft.com&flow=xtls-rprx-vision#Amsterdam"
let sub = "https://sub.example.org/api/v1/client/subscribe?token=" + String(repeating: "a1b2c3d4", count: 40)
let long = String(repeating: "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@203.0.113.7:8388#node\n", count: 18)
let cases: [(String, String)] = [("hello", "M"), (link, "L"), (link, "H"), (sub, "Q"), (long, "M"), ("Привет, QR", "L")]
print("//! QR codes made by Apple's CoreImage (tools/qr_fixtures.swift).\n")
print("pub const Fixture = struct { text: []const u8, rows: []const []const u8 };\n")
print("pub const all = [_]Fixture{")
for (text, level) in cases {
    let esc = text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"").replacingOccurrences(of: "\n", with: "\\n")
    print("    .{ .text = \"\(esc)\", .rows = &.{")
    for row in modules(text, level) { print("        \"\(row)\",") }
    print("    } },")
}
print("};")
