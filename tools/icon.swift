// App icon renderer: a glossy black "candy" tile cut through in one stroke,
// white light in the seam (breakthrough). Pure CoreGraphics, no dependencies.
//   swift tools/icon.swift <out.png> [size]
// Drawn on Apple's 1024 grid (824 body, shadow margin) and scaled.
import AppKit
import CoreGraphics

let args = CommandLine.arguments
let out = args.count > 1 ? args[1] : "icon.png"
let size = args.count > 2 ? Int(args[2])! : 1024
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
func vertical(_ g: CGGradient, _ top: CGFloat, _ bottom: CGFloat, x: CGFloat = 512) {
    ctx.drawLinearGradient(g, start: CGPoint(x: x, y: top), end: CGPoint(x: x, y: bottom), options: [])
}

// ── tile
let body = CGRect(x: 100, y: 100, width: 824, height: 824)
// macOS tile: continuous-corner rounded rect, radius ≈ 22.5% of the body
let tile = CGPath(roundedRect: body, cornerWidth: 185, cornerHeight: 185, transform: nil)

func tileShadow() {
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 28, color: gray(0, 0.45))
    ctx.addPath(tile); ctx.setFillColor(gray(0.05)); ctx.fillPath()
    ctx.restoreGState()
}

/// The glossy black tile (without its shadow).
func drawTile() {
    ctx.saveGState()
    ctx.addPath(tile); ctx.clip()
    vertical(grad([(0, gray(0.24)), (0.45, gray(0.08)), (1, gray(0.015))]), 100, 924)
    // light bouncing up from below: makes it read round, like a sweet
    ctx.drawRadialGradient(grad([(0, gray(1, 0.10)), (1, gray(1, 0))]),
                           startCenter: CGPoint(x: 512, y: 980), startRadius: 0,
                           endCenter: CGPoint(x: 512, y: 980), endRadius: 460, options: [])
    // candy gloss: a soft glow from the top…
    ctx.saveGState()
    ctx.translateBy(x: 512, y: 110); ctx.scaleBy(x: 1, y: 0.62)
    ctx.drawRadialGradient(grad([(0, gray(1, 0.26)), (0.6, gray(1, 0.06)), (1, gray(1, 0))]),
                           startCenter: .zero, startRadius: 0, endCenter: .zero, endRadius: 640, options: [])
    ctx.restoreGState()
    // …and a crisp specular cap that fades out before its lower edge
    ctx.saveGState()
    ctx.addPath(CGPath(roundedRect: CGRect(x: 138, y: 116, width: 748, height: 330),
                       cornerWidth: 160, cornerHeight: 150, transform: nil)); ctx.clip()
    vertical(grad([(0, gray(1, 0.24)), (0.5, gray(1, 0.06)), (0.9, gray(1, 0))]), 116, 446)
    ctx.restoreGState()
    // rim light along the top edge
    ctx.addPath(tile); ctx.setLineWidth(5); ctx.replacePathWithStrokedPath(); ctx.clip()
    vertical(grad([(0, gray(1, 0.35)), (0.35, gray(1, 0.06)), (1, gray(1, 0.02))]), 100, 924)
    ctx.restoreGState()
}

let c = CGPoint(x: 512, y: 512)
// one clean cut through the tile, white light in the seam. The tile's outline stays
// exactly Apple's: macOS 26 puts any other silhouette on a grey plate.
let a = CGPoint(x: 150, y: 790), b = CGPoint(x: 874, y: 234)
let len = hypot(b.x - a.x, b.y - a.y)
let u = CGPoint(x: (b.x - a.x) / len, y: (b.y - a.y) / len)   // along the cut
let n = CGPoint(x: u.y, y: -u.x)                               // towards the upper half
let angle = atan2(u.y, u.x)
let gap: CGFloat = 26
let cut = CGMutablePath()
cut.move(to: CGPoint(x: c.x - u.x * 800, y: c.y - u.y * 800))
cut.addLine(to: CGPoint(x: c.x + u.x * 800, y: c.y + u.y * 800))
/// A glow stretched along the cut.
func glow(_ stops: [(CGFloat, CGColor)], _ thickness: CGFloat, _ length: CGFloat) {
    ctx.saveGState()
    ctx.translateBy(x: c.x, y: c.y); ctx.rotate(by: angle); ctx.scaleBy(x: 1, y: thickness / length)
    ctx.drawRadialGradient(grad(stops), startCenter: .zero, startRadius: 0, endCenter: .zero, endRadius: length, options: [])
    ctx.restoreGState()
}
func band(_ width: CGFloat) {
    ctx.addPath(cut); ctx.setLineWidth(width); ctx.replacePathWithStrokedPath(); ctx.clip()
}

tileShadow()
drawTile()
ctx.saveGState()
ctx.addPath(tile); ctx.clip()
// halo: light spilling over both halves
glow([(0, gray(1, 0.45)), (0.3, gray(1, 0.12)), (1, gray(1, 0))], 110, 560)
// the cut faces: a lit bevel on each side of the seam, fading into the black
for side in [1.0, -1.0] as [CGFloat] {
    ctx.saveGState()
    band(gap + 40)
    let edge = CGPoint(x: c.x + side * n.x * gap / 2, y: c.y + side * n.y * gap / 2)
    let inward = CGPoint(x: edge.x + side * n.x * 20, y: edge.y + side * n.y * 20)
    ctx.drawLinearGradient(grad([(0, gray(1, 0.85)), (0.3, gray(1, 0.35)), (1, gray(1, 0))]),
                           start: edge, end: inward, options: [])
    ctx.restoreGState()
}
// the seam itself: solid light, edge to edge, hottest in the middle
band(gap)
ctx.setFillColor(gray(0.9)); ctx.fill(body)
glow([(0, gray(1)), (0.7, gray(1, 0.9)), (1, gray(1, 0))], 30, 560)
ctx.restoreGState()

let img = ctx.makeImage()!
let rep = NSBitmapImageRep(cgImage: img)
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
