"""Builds assets/fonts/NotoSansSC-Regular.ttf for the Chinese build (-Dlang=zh).

Geist has no CJK glyphs and DVUI has no per-glyph font fallback, so the zh
build swaps the UI font for Noto Sans SC. The upstream variable font is ~17 MB;
to keep the app light this script pins one weight (Regular) and keeps only
Latin, punctuation, the 3755 common hanzi (GB2312 level 1) and every character
of src/i18n.zig. The en/ru builds never embed this file.

    curl -L -o NotoSansSC.ttf "https://github.com/google/fonts/raw/main/ofl/notosanssc/NotoSansSC%5Bwght%5D.ttf"
    python3 tools/cjk_font.py NotoSansSC.ttf

Needs fontTools (pip install fonttools).
"""

import pathlib
import sys

from fontTools import subset
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

ROOT = pathlib.Path(__file__).resolve().parent.parent
WEIGHTS = {"Regular": 400}


def charset() -> str:
    chars = {chr(c) for c in range(0x20, 0x250)}  # ASCII, Latin-1, Latin Extended-A/B
    chars |= {chr(c) for c in range(0x2000, 0x2070)}  # general punctuation
    chars |= {chr(c) for c in range(0x3000, 0x3040)}  # CJK symbols and punctuation
    chars |= {chr(c) for c in range(0xFF00, 0xFFF0)}  # fullwidth forms
    for hi in range(0xB0, 0xD8):  # GB2312 hanzi, level 1
        for lo in range(0xA1, 0xFF):
            try:
                chars.add(bytes([hi, lo]).decode("gb2312"))
            except UnicodeDecodeError:
                pass
    chars |= set((ROOT / "src" / "i18n.zig").read_text(encoding="utf-8"))
    return "".join(sorted(c for c in chars if c.isprintable() or c == " "))


def main() -> None:
    src = sys.argv[1]
    text = charset()
    for name, wght in WEIGHTS.items():
        font = instancer.instantiateVariableFont(TTFont(src), {"wght": wght})
        opts = subset.Options()
        opts.layout_features = ["*"]
        opts.name_IDs = ["*"]
        opts.notdef_outline = True
        opts.hinting = False
        sub = subset.Subsetter(opts)
        sub.populate(text=text)
        sub.subset(font)
        out = ROOT / "assets" / "fonts" / f"NotoSansSC-{name}.ttf"
        font.save(out)
        print(f"{out.relative_to(ROOT)}: {out.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
