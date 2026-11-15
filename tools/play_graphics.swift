// Google Play's feature graphic (1024×500): the name beside the icon's rift.
//   swift tools/play_graphics.swift <rift.png (tools/icon.swift, bleed)> <out.png>
// Pure AppKit/CoreGraphics; the font is the app's own (assets/fonts).
import AppKit
import CoreGraphics
import CoreText

let args = CommandLine.arguments
let rift = NSImage(contentsOfFile: args[1])!.cgImage(forProposedRect: nil, context: nil, hints: nil)!
let out = args[2]
let w = 1024, h = 500

for name in ["Geist-SemiBold", "Geist-Regular"] {
    let url = URL(fileURLWithPath: "assets/fonts/\(name).ttf") as CFURL
    CTFontManagerRegisterFontsForURL(url, .process, nil)
}

let cs = CGColorSpace(name: CGColorSpace.sRGB)!
let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0,
                    space: cs, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
func gray(_ v: CGFloat, _ a: CGFloat = 1) -> CGColor { CGColor(colorSpace: cs, components: [v, v, v, a])! }

// the app's background
ctx.setFillColor(CGColor(colorSpace: cs, components: [10 / 255, 10 / 255, 12 / 255, 1])!)
ctx.fill(CGRect(x: 0, y: 0, width: w, height: h))

// the rift on the right, larger than the canvas so its light crosses the edge
let side: CGFloat = 760
ctx.draw(rift, in: CGRect(x: CGFloat(w) - side + 150, y: (CGFloat(h) - side) / 2, width: side, height: side))
// it fades into the background towards the name
let fade = CGGradient(colorsSpace: cs, colors: [
    CGColor(colorSpace: cs, components: [10 / 255, 10 / 255, 12 / 255, 1])!,
    CGColor(colorSpace: cs, components: [10 / 255, 10 / 255, 12 / 255, 0])!,
] as CFArray, locations: [0, 1])!
ctx.drawLinearGradient(fade, start: CGPoint(x: 400, y: 0), end: CGPoint(x: 660, y: 0), options: [.drawsBeforeStartLocation])

let ns = NSGraphicsContext(cgContext: ctx, flipped: false)
NSGraphicsContext.current = ns
func text(_ s: String, _ font: String, _ size: CGFloat, _ color: NSColor, _ kern: CGFloat, _ at: CGPoint) {
    let attrs: [NSAttributedString.Key: Any] = [
        .font: NSFont(name: font, size: size)!, .foregroundColor: color, .kern: kern,
    ]
    NSAttributedString(string: s, attributes: attrs).draw(at: at)
}
text("BLACKWALL", "Geist-SemiBold", 68, NSColor(white: 0.95, alpha: 1), 5, CGPoint(x: 72, y: 236))
text("A route for every app", "Geist-Regular", 27, NSColor(white: 0.56, alpha: 1), 0.4, CGPoint(x: 76, y: 186))

let rep = NSBitmapImageRep(cgImage: ctx.makeImage()!)
// Play takes no transparency: flatten by writing without alpha
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
