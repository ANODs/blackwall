"""Builds the landing page's raster images (site/static) from the app's own icon and fonts.

    python3 tools/site_images.py

    icon-32.png              favicon fallback for browsers without SVG icons
    icon-180.png             apple-touch-icon: full bleed and opaque, iOS rounds it itself
    icon-192.png, -512.png   web manifest
    og-en.png, -ru, -zh      1200 x 630 link previews, with the page's headline

The icon is drawn by tools/icon.swift, the same renderer as the app's (macOS: swiftc).
Its rift is see-through at the ends; here it is laid over the light plate macOS puts
under it. Needs Pillow (pip install pillow). The results are committed, so the page
build needs neither.
"""

import json
import pathlib
import subprocess
import tempfile

from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "site" / "static"
FONTS = ROOT / "assets" / "fonts"
PLATE = (219, 219, 219, 255)  # extended-gray 0.86, the fill of AppIcon.icon
BG, TEXT, TEXT3, LINE = (11, 11, 13), (242, 242, 243), (106, 106, 115), (48, 48, 54)


def render_icon(tmp: pathlib.Path) -> tuple[Image.Image, Image.Image]:
    """-> (the tile on its plate with transparent corners, the full-bleed square), both 1024."""
    exe = tmp / "icon"
    subprocess.run(["swiftc", "-O", str(ROOT / "tools" / "icon.swift"), "-o", str(exe)], check=True)
    subprocess.run([str(exe), str(tmp / "tile.png"), "1024"], check=True)
    subprocess.run([str(exe), str(tmp / "bleed.png"), "1024", "bleed"], check=True)

    plate = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
    ImageDraw.Draw(plate).rounded_rectangle((100, 100, 924, 924), radius=185, fill=PLATE)
    tile = Image.alpha_composite(plate, Image.open(tmp / "tile.png").convert("RGBA"))
    bleed = Image.alpha_composite(Image.new("RGBA", (1024, 1024), PLATE), Image.open(tmp / "bleed.png").convert("RGBA"))
    return tile.crop((100, 100, 924, 924)), bleed


def og(lang: str, tile: Image.Image) -> Image.Image:
    strings = json.loads((ROOT / "site" / "i18n" / f"{lang}.json").read_text())
    face = FONTS / ("NotoSansSC-Regular.ttf" if lang == "zh" else "Geist-SemiBold.ttf")
    img = Image.new("RGB", (1200, 630), BG)
    d = ImageDraw.Draw(img)

    # the wall: hairlines rising from the bottom edge, with a gap
    for x in range(6, 1200, 14):
        if 846 <= x <= 934:
            continue
        for y in range(470, 630):
            k = 1 - (y - 470) / 160
            d.point((x, y), tuple(round(BG[i] + (LINE[i] - BG[i]) * k) for i in range(3)))
        d.line((x, 470, x, 475), fill=TEXT if x in (832, 944) else TEXT3)

    img.paste(tile.resize((104, 104), Image.LANCZOS), (80, 76), tile.resize((104, 104), Image.LANCZOS))
    d.text((208, 128), "BLACKWALL", font=ImageFont.truetype(str(FONTS / "Geist-SemiBold.ttf"), 30), fill=TEXT, anchor="lm")

    size = 92
    head = ImageFont.truetype(str(face), size)
    while max(d.textlength(strings[k], font=head) for k in ("h1_a", "h1_b")) > 1040:
        size -= 4
        head = ImageFont.truetype(str(face), size)
    d.text((76, 232), strings["h1_a"], font=head, fill=TEXT)
    d.text((76, 232 + round(size * 1.08)), strings["h1_b"], font=head, fill=TEXT3)

    mono = ImageFont.truetype(str(FONTS / "GeistMono-Regular.ttf"), 22)
    d.text((80, 548), "VLESS · Trojan · Shadowsocks · VMess", font=mono, fill=TEXT3)
    d.text((80, 580), "macOS · Windows · Linux · Android", font=mono, fill=TEXT3)
    return img


def main() -> None:
    with tempfile.TemporaryDirectory() as t:
        tile, bleed = render_icon(pathlib.Path(t))
    for size in (32, 192, 512):
        tile.resize((size, size), Image.LANCZOS).save(OUT / f"icon-{size}.png", optimize=True)
    bleed.resize((180, 180), Image.LANCZOS).convert("RGB").save(OUT / "icon-180.png", optimize=True)
    for lang in ("en", "ru", "zh"):
        og(lang, tile).save(OUT / f"og-{lang}.png", optimize=True)
    for p in sorted(OUT.glob("*.png")):
        print(f"{p.relative_to(ROOT)}  {p.stat().st_size / 1024:.1f} KB")


if __name__ == "__main__":
    main()
