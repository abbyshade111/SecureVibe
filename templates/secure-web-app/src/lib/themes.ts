/**
 * The looks a person can choose for the app.
 *
 * A theme is color and nothing else: each name matches a set of color values in `public/css/app.css`, which the
 * layout selects with `<html data-theme="...">`. No theme can hide a control, change a message or turn a security
 * feature off, and every one of them is checked against the WCAG AA contrast ratios by `tests/security/theme.test.ts`
 * in its light and its dark version, so choosing a different look can never make the app harder to read.
 *
 * The list lives here rather than in `config.ts` so tests and tools can read it without loading the configuration.
 */
export const THEMES = ['calm', 'warm', 'forest', 'contrast'] as const;
export type Theme = (typeof THEMES)[number];
export const DEFAULT_THEME: Theme = 'calm';

/** What each look is called and looks like, in plain language (SecureVibe shows these when asking). */
export const THEME_DESCRIPTIONS: Record<Theme, string> = {
  calm: 'Calm — quiet grays and a blue for links and buttons. The default.',
  warm: 'Warm — soft cream and amber, with a clay-orange for links and buttons.',
  forest: 'Forest — pale green with a deep green for links and buttons.',
  contrast: 'High contrast — black on white with heavier edges, for anyone who finds the others hard to read.',
};
