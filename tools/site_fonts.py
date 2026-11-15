"""Builds the web fonts of the landing page (site/static/fonts) from assets/fonts.

The page uses the same faces as the app. To keep it light, every face is cut
down to what the three languages need: Latin, Cyrillic, punctuation and arrows
for Geist; ASCII for Geist Mono (it only draws numbers and code). Chinese text
uses the visitor's system font, so no CJK font is shipped.

    python3 tools/site_fonts.py

Needs fontTools (pip install fonttools). With the `brotli` module installed the
files come out as WOFF2, otherwise as WOFF; tools/site.py picks up whichever
is there. The results are committed, so the page build needs neither.
"""

import pathlib

from fontTools import subset
from fontTools.ttLib import TTFont

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "assets" / "fonts"
OUT = ROOT / "site" / "static" / "fonts"

TEXT = (
    list(range(0x20, 0x7F))  # ASCII
    + list(range(0xA0, 0x100))  # Latin-1
    + list(range(0x400, 0x460))  # Cyrillic
    + list(range(0x2010, 0x2027))  # dashes, quotes, ellipsis
    + [0x2190, 0x2191, 0x2192, 0x2193, 0x2212, 0x20BD]
)
MONO = list(range(0x20, 0x7F)) + [0xA0, 0xB7, 0x2014, 0x202F, 0x2192, 0x2193]

FACES = {
    "Geist-Regular": TEXT,
    "Geist-Medium": TEXT,
    "Geist-SemiBold": TEXT,
    "GeistMono-Regular": MONO,
}


def main() -> None:
    try:
        import brotli  # noqa: F401

        flavor = "woff2"
    except ImportError:
        flavor = "woff"

    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.woff*"):
        old.unlink()
    for name, unicodes in FACES.items():
        font = TTFont(SRC / f"{name}.ttf")
        options = subset.Options()
        options.layout_features = ["kern", "liga", "calt", "tnum", "zero", "ccmp", "locl", "mark", "mkmk"]
        options.name_IDs = [1, 2]
        options.hinting = False
        options.desubroutinize = True
        sub = subset.Subsetter(options)
        sub.populate(unicodes=unicodes)
        sub.subset(font)
        font.flavor = flavor
        path = OUT / f"{name}.{flavor}"
        font.save(path)
        print(f"{path.relative_to(ROOT)}  {path.stat().st_size / 1024:.1f} KB")


if __name__ == "__main__":
    main()
