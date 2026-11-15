#!/bin/sh
# Regenerates assets/icon/* from tools/icon.swift (macOS: swift, Xcode's actool, python3).
#   AppIcon.icon/  — macOS 26 Icon Composer source: full-bleed art on a system fill,
#                    so the system draws it at native size with its own plate and glass
#   Assets.car     — compiled from AppIcon.icon (macOS 26+)
#   AppIcon.icns   — compiled fallback for older macOS
#   blackwall.ico  — Windows exe icon (PNG entries 16…256)
#   window.png     — 256 px, set on the window at runtime (Linux/Windows title bar, taskbar)
# The compiled files are committed, so building the app never needs Xcode.
set -e
cd "$(dirname "$0")/.."
out=assets/icon
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$out/AppIcon.icon/Assets"

swiftc -O tools/icon.swift -o "$tmp/icon"
for s in 16 32 48 64 128 256; do "$tmp/icon" "$tmp/$s.png" $s; done
"$tmp/icon" "$out/AppIcon.icon/Assets/rift.png" 1024 bleed

# The fill shows through the ends of the rift.
cat > "$out/AppIcon.icon/icon.json" <<'EOF'
{
  "fill" : {
    "solid" : "extended-gray:0.86000,1.00000"
  },
  "groups" : [
    {
      "layers" : [
        {
          "glass" : false,
          "image-name" : "rift.png",
          "name" : "rift"
        }
      ],
      "shadow" : {
        "kind" : "neutral",
        "opacity" : 0.5
      },
      "translucency" : {
        "enabled" : false,
        "value" : 0.5
      }
    }
  ],
  "supported-platforms" : {
    "squares" : [
      "macOS"
    ]
  }
}
EOF
xcrun actool "$PWD/$out/AppIcon.icon" --compile "$tmp" --platform macosx --minimum-deployment-target 11.0 \
  --app-icon AppIcon --output-partial-info-plist "$tmp/partial.plist" >/dev/null
cp "$tmp/Assets.car" "$tmp/AppIcon.icns" "$out/"
cp "$tmp/256.png" "$out/window.png"

python3 -I - "$tmp" "$out/blackwall.ico" <<'EOF'
import struct, sys
src, dst = sys.argv[1], sys.argv[2]
sizes = [16, 32, 48, 64, 128, 256]
blobs = [open(f"{src}/{s}.png", "rb").read() for s in sizes]
head = struct.pack("<HHH", 0, 1, len(sizes))
off = 6 + 16 * len(sizes)
dirs = b""
for s, b in zip(sizes, blobs):
    dirs += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(b), off)
    off += len(b)
open(dst, "wb").write(head + dirs + b"".join(blobs))
EOF
ls -la "$out"
