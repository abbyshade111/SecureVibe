# StackVet logo files

The code-bracket logo in terracotta: a check mark inside square brackets, and the name in JetBrains Mono Bold
with "vet" in the accent color. The letters are drawn as outlines, so the logo looks the same everywhere,
whether or not the font is installed. JetBrains Mono is free to use under the SIL Open Font License.

| File | What it is | Where it goes |
| --- | --- | --- |
| `stackvet-logo.svg`, `stackvet-logo.png` | The full logo, for light backgrounds | The top of the README |
| `stackvet-logo-dark.svg`, `stackvet-logo-dark.png` | The full logo, for dark backgrounds | The README in dark mode, slides |
| `stackvet-mark.svg`, `stackvet-mark-512.png` | The bracket mark alone, for light backgrounds | Avatars, small spaces |
| `stackvet-mark-dark.svg`, `stackvet-mark-dark-512.png` | The bracket mark alone, for dark backgrounds | The same, on dark |
| `favicon.svg`, `favicon-32.png` | The mark on a light rounded square | The browser tab of stackvet.dev and stackvet.app |
| `apple-touch-icon.png` (180 x 180) | The same, larger | A phone's home screen, if someone saves the site |
| `social-preview.png` (1280 x 640) | The logo and a one-line description on dark | GitHub: the repository's Settings, then Social preview, then Upload an image |

Colors:

| Use | Light background | Dark background |
| --- | --- | --- |
| Accent ("vet" and the check) | `#C2410C` | `#FDBA74` |
| Brackets and "stack" | `#14201C` | `#F3F4EF` |
| Dark background | | `#12201B` |

To show the light or dark logo to match the reader's GitHub theme, the README can use:

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/brand/stackvet-logo-dark.svg">
  <img alt="StackVet" src="docs/brand/stackvet-logo.svg" width="320">
</picture>
```

## Making them again

`source/make_logo.py` draws every SVG here from the font's outlines, and `source/render.js` turns them into the
PNGs. Neither is part of `sv`, and nothing in the build or the tests runs them. To change a color or the line on
the preview image, edit `make_logo.py`. Then make a scratch folder with JetBrains Mono's release unpacked in
a `font` folder inside it (so `font/fonts/ttf/JetBrainsMono-Bold.ttf` and `-Medium.ttf`; the release is at
github.com/JetBrains/JetBrainsMono) and an empty `files` folder for the output, and run:

```bash
pip install fonttools
python3 docs/brand/source/make_logo.py <scratch folder>
NODE_PATH="$(npm root -g)" node docs/brand/source/render.js <scratch folder>   # needs Playwright
```

and copy what lands in `<scratch folder>/files` back here. Made on 8 October 2026, when the owner chose the name
StackVet and this logo (the code bracket, in terracotta) from six drafts.
