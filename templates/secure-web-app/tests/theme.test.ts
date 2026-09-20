/**
 * Themes: a choice of look that cannot make the app harder to use.
 *
 * Each theme in public/css/app.css is nothing but a set of colour values. This reads those values straight out of
 * the stylesheet and checks every pair of colours that ends up on top of another one against the WCAG 2.2 AA
 * contrast ratios — 4.5:1 for text, 3:1 for the edge of a form field — in the light version and in the dark version
 * alike. A theme that reads badly fails the build, so "pick a different look" can never cost the person reading it.
 *
 * No requirement ids on these names, and that is the point of the file existing. They were named `UX-01`, which
 * appears in no framework file and no knowledge file — so it was credited to nothing, screened by nothing, and read
 * to anybody else as a citation. Readable colour is a real property worth testing and it is not an entry in ASVS,
 * AISVS or the Secure by Design checklist, so the honest thing is to say what the test shows and claim nothing.
 * The one theme test that does cite a requirement, AS-07, stayed in `tests/security/theme.test.ts`.
 */
import { after, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { THEMES, DEFAULT_THEME } from '../src/lib/themes.ts';
import { startApp, templateRoot, type RunningApp } from './helpers/app.ts';

const CSS = readFileSync(join(templateRoot, 'public', 'css', 'app.css'), 'utf8');

type Palette = Record<string, string>;

/** Every `--token: value;` inside one block. */
function tokensIn(block: string): Palette {
  const out: Palette = {};
  for (const m of block.matchAll(/--([a-z-]+)\s*:\s*([^;]+);/g)) out[m[1]!] = m[2]!.trim();
  return out;
}

/** The body of the rule whose selector list contains `selector`, optionally inside the dark-mode block. */
function block(selector: string, dark: boolean): string {
  const source = dark ? CSS.split('@media (prefers-color-scheme: dark)').slice(1).join('\n@media\n') : CSS;
  const index = source.indexOf(selector);
  assert.ok(index >= 0, `${selector} has no ${dark ? 'dark' : 'light'} rule in app.css`);
  const open = source.indexOf('{', index);
  const close = source.indexOf('}', open);
  return source.slice(open, close);
}

function paletteFor(theme: string, dark: boolean): Palette {
  return tokensIn(block(`html[data-theme='${theme}']`, dark));
}

function channel(value: number): number {
  return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
}

function luminance(hex: string): number {
  const m = /^#([0-9a-f]{6})$/i.exec(hex.trim());
  assert.ok(m, `${hex} is not a six-digit hex colour; themes only use those so contrast can be measured`);
  const n = parseInt(m![1]!, 16);
  const [r, g, b] = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((c) => channel(c / 255)) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [x, y] = [luminance(a), luminance(b)];
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

/** What sits on what, in the pages the template renders, and the ratio each pair has to reach. */
const PAIRS: { what: string; front: string; back: string; min: number }[] = [
  { what: 'body text on the page background', front: 'text', back: 'bg', min: 4.5 },
  { what: 'body text inside a card', front: 'text', back: 'surface', min: 4.5 },
  { what: 'hints and secondary text on a card', front: 'muted', back: 'surface', min: 4.5 },
  { what: 'hints and secondary text on the page background', front: 'muted', back: 'bg', min: 4.5 },
  { what: 'links on a card', front: 'accent', back: 'surface', min: 4.5 },
  { what: 'links on the page background', front: 'accent', back: 'bg', min: 4.5 },
  { what: 'the label on a button', front: 'accent-contrast', back: 'accent', min: 4.5 },
  { what: 'the label on a button being hovered', front: 'accent-contrast', back: 'accent-dark', min: 4.5 },
  { what: 'the label on a delete button', front: 'danger-contrast', back: 'danger', min: 4.5 },
  { what: 'the label on a delete button being hovered', front: 'danger-contrast', back: 'danger-dark', min: 4.5 },
  { what: 'an error message', front: 'danger', back: 'danger-bg', min: 4.5 },
  { what: 'a success message', front: 'success', back: 'success-bg', min: 4.5 },
  { what: 'text on an information message', front: 'text', back: 'info-bg', min: 4.5 },
  // Not text: WCAG 1.4.11 asks for 3:1 so the edge of a field and the focus ring are visible.
  { what: 'the edge of a form field', front: 'border-strong', back: 'surface', min: 3 },
  { what: 'the focus ring on a card', front: 'accent', back: 'surface', min: 3 },
  { what: 'the focus ring on the page background', front: 'accent', back: 'bg', min: 3 },
];

describe('themes', () => {
  test('every theme the app offers is fully defined, light and dark', () => {
    for (const theme of THEMES) {
      for (const dark of [false, true]) {
        const palette = paletteFor(theme, dark);
        for (const { front, back } of PAIRS) {
          assert.ok(palette[front], `${theme} (${dark ? 'dark' : 'light'}) does not set --${front}`);
          assert.ok(palette[back], `${theme} (${dark ? 'dark' : 'light'}) does not set --${back}`);
        }
      }
    }
  });

  test('every theme stays readable: WCAG AA contrast in the light and the dark version alike', () => {
    const failures: string[] = [];
    for (const theme of THEMES) {
      for (const dark of [false, true]) {
        const palette = paletteFor(theme, dark);
        for (const { what, front, back, min } of PAIRS) {
          const ratio = contrast(palette[front]!, palette[back]!);
          if (ratio < min) failures.push(`${theme} (${dark ? 'dark' : 'light'}): ${what} is ${ratio.toFixed(2)}:1, needs ${min}:1`);
        }
      }
    }
    assert.deepEqual(failures, [], `themes that would be hard to read:\n${failures.join('\n')}`);
  });

  test('no colour is named outside a theme, so choosing one really does change everything', () => {
    const themeBlocks = /(:root|html\[data-theme='[a-z]+'\])[^{]*\{[^}]*\}/g;
    const rest = CSS.replace(themeBlocks, '');
    const strays = [...rest.matchAll(/#[0-9a-fA-F]{3,8}\b|\brgba?\(/g)].map((m) => m[0]);
    assert.deepEqual(strays, [], 'colours must be tokens so every theme controls them');
  });

  describe('the rendered page', () => {
    let app: RunningApp | undefined;
    after(async () => {
      await app?.stop();
    });

    test('the page carries the chosen theme, and the default when nothing was chosen', async () => {
      app = await startApp({ env: { APP_THEME: 'forest' } });
      const html = await (await app.fetch('/login')).text();
      assert.match(html, /<html lang="en" data-theme="forest">/);
      assert.ok(!html.includes(`data-theme="${DEFAULT_THEME}"`), 'the chosen theme must win over the default');
      await app.stop();

      // The second half of this is the interesting one, and it was unreachable in a generated app until the
      // design snapshot stopped carrying a theme. With a theme in that file the app fell back to it instead of
      // to the default, so "nothing was chosen" could never be true and this failed in every app SecureVibe
      // built while passing in the bare template. If it fails here again, look for a third source of the colour
      // before changing the assertion: the only ones that should exist are APP_THEME and this default.
      app = await startApp();
      const plain = await (await app.fetch('/login')).text();
      assert.match(plain, new RegExp(`data-theme="${DEFAULT_THEME}"`));
    });

  });
});
