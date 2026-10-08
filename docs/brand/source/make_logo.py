"""Draws the StackVet logo files (terracotta code bracket) from JetBrains Mono's outlines."""
import sys
from pathlib import Path
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.boundsPen import BoundsPen

root = Path(sys.argv[1]); out = root / "files"
INK, PAPER, DARK_BG = "#14201C", "#F3F4EF", "#12201B"
ACCENT, ACCENT_DARK = "#C2410C", "#FDBA74"

def glyphs(font_path, text, size, tracking_em, x, baseline, color):
    font = TTFont(font_path); gs = font.getGlyphSet(); cmap = font.getBestCmap()
    upm = font["head"].unitsPerEm; s = size / upm; parts = []
    for ch in text:
        name = cmap[ord(ch)]; pen = SVGPathPen(gs); gs[name].draw(pen)
        d = pen.getCommands()
        if d:
            parts.append(f'<path transform="translate({x:.2f} {baseline:.2f}) scale({s:.5f} {-s:.5f})" d="{d}" fill="{color}"/>')
        x += gs[name].width * s + tracking_em * size
    return "".join(parts), x

def mark(ink, accent, dx=0, dy=0, k=1.0):
    t = f'transform="translate({dx} {dy}) scale({k})"'
    return (f'<g {t}><path d="M20 10 H11 V54 H20" fill="none" stroke="{ink}" stroke-width="6"/>'
            f'<path d="M44 10 H53 V54 H44" fill="none" stroke="{ink}" stroke-width="6"/>'
            f'<path d="M22 33 L29 40 L43 24" fill="none" stroke="{accent}" stroke-width="6" '
            f'stroke-linecap="round" stroke-linejoin="round"/></g>')

def svg(w, h, body, bg=None, title="StackVet"):
    back = f'<rect width="{w}" height="{h}" fill="{bg}"/>' if bg else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
            f'role="img" aria-label="{title}"><title>{title}</title>{back}{body}</svg>\n')

bold = root / "font/fonts/ttf/JetBrainsMono-Bold.ttf"
medium = root / "font/fonts/ttf/JetBrainsMono-Medium.ttf"

def lockup(ink, accent, x0=0, y0=0, scale=1.0):
    # mark 64 units, a 14-unit gap, then the name at 40 units on a baseline of 46.
    a, x = glyphs(bold, "stack", 40 * scale, -0.03, x0 + 78 * scale, y0 + 46 * scale, ink)
    b, x = glyphs(bold, "vet", 40 * scale, -0.03, x, y0 + 46 * scale, accent)
    return mark(ink, accent, x0, y0, scale) + a + b, x

files = {}
files["stackvet-mark.svg"] = svg(64, 64, mark(INK, ACCENT))
files["stackvet-mark-dark.svg"] = svg(64, 64, mark(PAPER, ACCENT_DARK))
body, end = lockup(INK, ACCENT); w = round(end + 2)
files["stackvet-logo.svg"] = svg(w, 64, body)
body, _ = lockup(PAPER, ACCENT_DARK)
files["stackvet-logo-dark.svg"] = svg(w, 64, body)
# Tab icon: the mark on a light rounded square, so it shows on light and dark browser tabs alike.
files["favicon.svg"] = svg(64, 64, f'<rect width="64" height="64" rx="14" fill="{PAPER}"/>' + mark(INK, ACCENT, 3.2, 3.2, 0.9))
# Social preview, 1280 x 640, for GitHub's repository settings.
k = 3.2; body, end = lockup(PAPER, ACCENT_DARK, 0, 0, k); lw = end
x0 = (1280 - lw) / 2; body, _ = lockup(PAPER, ACCENT_DARK, x0, 190, k)
line1, l1 = glyphs(medium, "A security check for apps built with AI.", 30, 0, 0, 0, PAPER)
line2, l2 = glyphs(medium, "It says plainly what it checked, and what it didn't.", 30, 0, 0, 0, PAPER)
t1, _ = glyphs(medium, "A security check for apps built with AI.", 30, 0, (1280 - l1) / 2, 470, "#C9CEC7")
t2, _ = glyphs(medium, "It says plainly what it checked, and what it didn't.", 30, 0, (1280 - l2) / 2, 516, "#C9CEC7")
files["social-preview.svg"] = svg(1280, 640, body + t1 + t2, bg=DARK_BG)
for name, text in files.items():
    (out / name).write_text(text)
    print(name, len(text))
