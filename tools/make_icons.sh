#!/bin/sh
# Regenerates assets/icon/* from tools/icon.swift (macOS: swift, iconutil, python3).
#   blackwall.icns — macOS bundle icon
#   blackwall.ico  — Windows exe icon (PNG entries 16…256)
#   window.png     — 256 px, set on the window at runtime (Linux/Windows title bar, taskbar)
set -e
cd "$(dirname "$0")/.."
out=assets/icon
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$out" "$tmp/blackwall.iconset"

render() { swift tools/icon.swift "$2" "$1"; }
for s in 16 32 48 64 128 256 512 1024; do render $s "$tmp/$s.png"; done

set_=$tmp/blackwall.iconset
for s in 16 32 128 256 512; do
  cp "$tmp/$s.png" "$set_/icon_${s}x${s}.png"
  cp "$tmp/$((s * 2)).png" "$set_/icon_${s}x${s}@2x.png"
done
iconutil -c icns "$set_" -o "$out/blackwall.icns"
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
