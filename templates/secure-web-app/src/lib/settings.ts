/**
 * Runtime settings an administrator can change without restarting (stored in the `settings` table).
 */
import { get, nowIso, run } from '../db/index.ts';

export function getSetting(key: string): string | undefined {
  return get<{ value: string }>('SELECT value FROM settings WHERE key = ?', [key])?.value;
}

export function setSetting(key: string, value: string, updatedBy: string | null): void {
  run('INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by', [
    key,
    value,
    nowIso(),
    updatedBy,
  ]);
}

/** The AI assistant kill switch: AI_ENABLED=0 in the environment or an admin toggle both switch it off. */
export function aiRuntimeEnabled(envEnabled: boolean): boolean {
  if (!envEnabled) return false;
  return getSetting('ai_enabled') !== '0';
}
