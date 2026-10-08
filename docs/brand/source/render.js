// Renders each SVG in files/ to PNG at the sizes the repository needs.
const { chromium } = require('playwright');
const fs = require('fs'); const path = require('path');
const dir = path.join(process.argv[2], 'files');
const jobs = [
  ['stackvet-mark.svg', 'stackvet-mark-512.png', 512, 512, null],
  ['stackvet-mark-dark.svg', 'stackvet-mark-dark-512.png', 512, 512, '#12201B'],
  ['stackvet-logo.svg', 'stackvet-logo.png', 1048, 256, null],
  ['stackvet-logo-dark.svg', 'stackvet-logo-dark.png', 1048, 256, null],
  ['favicon.svg', 'favicon-32.png', 32, 32, null],
  ['favicon.svg', 'apple-touch-icon.png', 180, 180, null],
  ['social-preview.svg', 'social-preview.png', 1280, 640, null],
];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  for (const [src, dst, w, h, bg] of jobs) {
    const svg = fs.readFileSync(path.join(dir, src), 'utf8')
      .replace(/width="[\d.]+" height="[\d.]+"/, `width="${w}" height="${h}"`);
    await page.setViewportSize({ width: w, height: h });
    await page.setContent(`<html><body style="margin:0;background:${bg || 'transparent'}">${svg}</body></html>`);
    await page.screenshot({ path: path.join(dir, dst), omitBackground: !bg, clip: { x: 0, y: 0, width: w, height: h } });
    console.log(dst, w + 'x' + h);
  }
  await browser.close();
})();
