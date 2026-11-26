"""Write the extension's toolbar icons (16, 32, 48, 128 px) from the seal.

    python scripts/gen_extension_icons.py          # rewrite icons/icon*.png
    python scripts/gen_extension_icons.py --check  # exit 1 when they differ

The reticle seal is drawn once, in web/src/components/shield/shared.tsx
(`SealMark`: a ring and a core on a 32-unit grid). This script reads that
geometry and the two brand colours from web/src/styles/tokens.css, and draws
the same ring and core in seal blue on the seal's navy tile. Needs Pillow.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
SHARED = ROOT / "web" / "src" / "components" / "shield" / "shared.tsx"
TOKENS = ROOT / "web" / "src" / "styles" / "tokens.css"
ICONS = ROOT / "src" / "byoai" / "browser_extension" / "icons"
SIZES = (16, 32, 48, 128)
SS = 8  # supersampling, for clean edges at 16px


def _geometry() -> tuple[float, float, float]:
    mark = SHARED.read_text().split("export function SealMark", 1)[1].split("</svg>", 1)[0]
    ring_r = float(re.search(r'<circle[^>]*\br="(\d+(?:\.\d+)?)"[^>]*strokeWidth="(\d+(?:\.\d+)?)"', mark).group(1))
    stroke = float(re.search(r'strokeWidth="(\d+(?:\.\d+)?)"', mark).group(1))
    core_r = float(re.search(r'<circle[^>]*\br="(\d+(?:\.\d+)?)"[^>]*fill="currentColor"', mark).group(1))
    return ring_r, stroke, core_r


def _colour(name: str) -> tuple[int, int, int]:
    hexv = re.search(rf"{name}:\s*#([0-9A-Fa-f]{{6}})", TOKENS.read_text()).group(1)
    return tuple(int(hexv[i:i + 2], 16) for i in (0, 2, 4))


def render(size: int) -> Image.Image:
    ring_r, stroke, core_r = _geometry()
    seal, tile = _colour("--seal"), _colour("--seal-tile")
    n = size * SS
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, n - 1, n - 1], radius=n * 0.22, fill=tile + (255,))
    # The 32-unit seal fills 78% of the tile (88% at 16px, where the gap inside the ring must stay visible).
    k = n * (0.88 if size <= 16 else 0.78) / 32
    c = n / 2
    outer, inner = (ring_r + stroke / 2) * k, (ring_r - stroke / 2) * k
    d.ellipse([c - outer, c - outer, c + outer, c + outer], fill=seal)
    d.ellipse([c - inner, c - inner, c + inner, c + inner], fill=tile)
    d.ellipse([c - core_r * k, c - core_r * k, c + core_r * k, c + core_r * k], fill=seal)
    return img.resize((size, size), Image.LANCZOS)


def main(argv: list[str]) -> int:
    stale = False
    for size in SIZES:
        path = ICONS / f"icon{size}.png"
        img = render(size)
        if "--check" in argv:
            if not path.exists() or list(Image.open(path).convert("RGBA").getdata()) != list(img.getdata()):
                print(f"{path.name} is stale: run python scripts/gen_extension_icons.py")
                stale = True
        else:
            img.save(path)
    return 1 if stale else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
