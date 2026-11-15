// App icon renderer, macOS 26 style: a black tile broken into two halves by a
// diagonal rift. White-hot light pours out of the middle of the rift, blooms over
// both halves and fades out well before the rift reaches the tile's edge, so it
// is never cut off — the ends are just see-through.
// Pure CoreGraphics, no dependencies.   swift tools/icon.swift <out.png> [size] [bleed]
// Drawn on Apple's 1024 grid (824 body) and scaled.
import AppKit
import CoreGraphics

let args = CommandLine.arguments
let out = args.count > 1 ? args[1] : "icon.png"
let size = args.count > 2 ? Int(args[2])! : 1024
let mode = args.count > 3 ? args[3] : ""
// "bleed": art for an Icon Composer (.icon) layer — the tile fills the whole canvas
// and the system applies its own mask, plate and glass (macOS 26)
let bleed = mode == "bleed"
let s = CGFloat(size) / 1024

let cs = CGColorSpace(name: CGColorSpace.sRGB)!
let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
                    space: cs, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
ctx.scaleBy(x: s, y: s)
// flip to top-left origin
ctx.translateBy(x: 0, y: 1024); ctx.scaleBy(x: 1, y: -1)
ctx.interpolationQuality = .high
ctx.setShouldAntialias(true)

func gray(_ v: CGFloat, _ a: CGFloat = 1) -> CGColor { CGColor(colorSpace: cs, components: [v, v, v, a])! }
func grad(_ stops: [(CGFloat, CGColor)]) -> CGGradient {
    CGGradient(colorsSpace: cs, colors: stops.map { $0.1 } as CFArray, locations: stops.map { $0.0 })!
}
func radial(_ g: CGGradient, _ at: CGPoint, _ r: CGFloat) {
    ctx.drawRadialGradient(g, startCenter: at, startRadius: 0, endCenter: at, endRadius: r, options: [])
}

let c = CGPoint(x: 512, y: 512)
let body = CGRect(x: 100, y: 100, width: 824, height: 824)
// macOS tile: continuous-corner rounded rect, radius ≈ 22.5% of the body
let tile = bleed ? CGPath(rect: body.insetBy(dx: -100, dy: -100), transform: nil)
                 : CGPath(roundedRect: body, cornerWidth: 185, cornerHeight: 185, transform: nil)
// shadow blur is in device pixels, so it follows every scale applied to the drawing
let k = s * (bleed ? 1024 / 824 : 1)
if bleed {   // same drawing, blown up so the 824 body covers the 1024 canvas
    ctx.translateBy(x: 512, y: 512); ctx.scaleBy(x: 1024 / 824, y: 1024 / 824); ctx.translateBy(x: -512, y: -512)
}

// the rift: a straight diagonal through the centre, rising to the right
let angle = -CGFloat.pi * 0.21
let u = CGPoint(x: cos(angle), y: sin(angle))
let gap: CGFloat = 30
let rift = CGMutablePath()
rift.move(to: CGPoint(x: c.x - u.x * 900, y: c.y - u.y * 900))
rift.addLine(to: CGPoint(x: c.x + u.x * 900, y: c.y + u.y * 900))
let riftBand = rift.copy(strokingWithWidth: gap, lineCap: .butt, lineJoin: .miter, miterLimit: 1)

// how far along the rift the light reaches; it is gone well before the tile's edge
let reach: CGFloat = 330

/// Mask the current transparency layer with the light's profile along the rift:
/// full in the middle, falling off smoothly (≈ inverse-square) to nothing at `reach`.
func lengthProfile() {
    ctx.saveGState()
    ctx.setBlendMode(.destinationIn)
    ctx.translateBy(x: c.x, y: c.y); ctx.rotate(by: angle); ctx.scaleBy(x: 1, y: 1.6)
    ctx.drawRadialGradient(grad([(0, gray(0, 1)), (0.25, gray(0, 0.85)), (0.5, gray(0, 0.45)),
                                 (0.75, gray(0, 0.14)), (1, gray(0, 0))]),
                           startCenter: .zero, startRadius: 0, endCenter: .zero, endRadius: reach, options: [.drawsAfterEndLocation])
    ctx.restoreGState()
}
/// A line parallel to the rift, offset by `d` across it.
func edge(_ d: CGFloat) -> CGPath {
    let n = CGPoint(x: -u.y, y: u.x), p = CGMutablePath()
    p.move(to: CGPoint(x: c.x - u.x * 900 + n.x * d, y: c.y - u.y * 900 + n.y * d))
    p.addLine(to: CGPoint(x: c.x + u.x * 900 + n.x * d, y: c.y + u.y * 900 + n.y * d))
    return p
}

// ── the two halves: the tile minus the rift, near-black for contrast
ctx.saveGState()
ctx.addPath(tile); ctx.clip()
ctx.addRect(body.insetBy(dx: -10, dy: -10)); ctx.addPath(riftBand); ctx.clip(using: .evenOdd)
ctx.drawLinearGradient(grad([(0, gray(0.13)), (1, gray(0.015))]),
                       start: CGPoint(x: 512, y: 100), end: CGPoint(x: 512, y: 924), options: [])
ctx.restoreGState()

// ── the light: one layer, built like a render's bloom, then shaped along the rift
ctx.saveGState()
ctx.addPath(tile); ctx.clip()
ctx.beginTransparencyLayer(auxiliaryInfo: nil)
// light hitting the surfaces of both halves, grazing away from the rift
for (blur, a) in [(300.0, 0.55), (150.0, 0.7), (60.0, 0.85), (20.0, 1.0)] as [(CGFloat, CGFloat)] {
    ctx.saveGState()
    ctx.setShadow(offset: .zero, blur: blur * k, color: gray(1, a))
    ctx.addPath(riftBand); ctx.setFillColor(gray(1, a)); ctx.fillPath()
    ctx.restoreGState()
}
// the broken faces: a thin hot lip on each side of the rift
for d in [gap / 2 + 2, -gap / 2 - 2] {
    ctx.saveGState()
    ctx.setShadow(offset: .zero, blur: 10 * k, color: gray(1, 0.9))
    ctx.addPath(edge(d)); ctx.setLineWidth(4); ctx.setStrokeColor(gray(1, 0.95)); ctx.strokePath()
    ctx.restoreGState()
}
// the rift itself: a white-hot core, tight bloom around it
ctx.saveGState()
ctx.addPath(riftBand); ctx.clip()
ctx.setFillColor(gray(1, 0.9)); ctx.fill(body)
ctx.restoreGState()
ctx.saveGState()
ctx.setShadow(offset: .zero, blur: 18 * k, color: gray(1, 1))
ctx.addPath(rift.copy(strokingWithWidth: 10, lineCap: .butt, lineJoin: .miter, miterLimit: 1))
ctx.setFillColor(gray(1)); ctx.fillPath()
ctx.restoreGState()
lengthProfile()
ctx.endTransparencyLayer()
ctx.restoreGState()

let img = ctx.makeImage()!
let rep = NSBitmapImageRep(cgImage: img)
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
