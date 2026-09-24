/**
 * Changing how an app looks, without rebuilding it.
 *
 * A theme is color and nothing else (see the template's `src/lib/themes.ts`), so switching one does not need the
 * code to be written again, checked again, or approved again: SecureVibe sets `APP_THEME` in the app's own `.env`
 * and the app renders the new colors the next time it starts. The design profile is updated to match, so a later
 * rebuild keeps the look the owner chose.
 *
 * Only that one line of `.env` is touched. Everything else in the file — the app's secrets and its settings — is
 * written back exactly as it was.
 */
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ThemeSchema, type Theme } from '@shared/profile.js';

export class AppearanceError extends Error {}

/** Replaces (or adds) one `NAME=value` line, leaving every other line of the file untouched. */
export function setEnvValue(file: string, name: string, value: string): void {
  if (!existsSync(file)) throw new AppearanceError('That app does not have its settings file yet, so its look cannot be changed. Build it first.');
  const lines = readFileSync(file, 'utf8').split(/\r?\n/);
  let replaced = false;
  const out = lines.map((line) => {
    if (line.trim().startsWith('#') || !line.trim().startsWith(`${name}=`)) return line;
    replaced = true;
    return `${name}=${value}`;
  });
  if (!replaced) {
    while (out.length > 0 && out[out.length - 1]!.trim() === '') out.pop();
    out.push(`${name}=${value}`);
  }
  writeFileSync(file, `${out.join('\n').replace(/\n+$/, '')}\n`, { mode: 0o600 });
  chmodSync(file, 0o600);
}

/** Writes the chosen look into the app's settings file. Returns the theme that is now in force. */
export function setAppTheme(appDir: string, theme: string): Theme {
  const parsed = ThemeSchema.safeParse(theme);
  if (!parsed.success) throw new AppearanceError('That is not one of the looks SecureVibe offers.');
  setEnvValue(join(appDir, '.env'), 'APP_THEME', parsed.data);
  return parsed.data;
}
