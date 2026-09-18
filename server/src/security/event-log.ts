/**
 * Security event log (ASVS V16.2/V16.3): every log entry that carries an `event` name (sign-ins, refusals, build
 * approvals) is also appended to <SECUREVIBE_HOME>/logs/security-events.jsonl, readable only by the owner, so the
 * Dashboard can count them after a restart. The file is capped: at 5 MB it moves to `.1` (one old file is kept).
 */
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync } from 'node:fs';
import { dirname } from 'node:path';

export const EVENT_LOG_MAX_BYTES = 5 * 1024 * 1024;

export interface SecurityEvent {
  ts: string;
  event: string;
  level: number;
  status?: number;
  method?: string;
  path?: string;
  code?: string;
  reason?: string;
  projectId?: string;
}

/** Only these fields are kept: nothing that could hold a token, a cookie or free text from a request body. */
function pick(entry: Record<string, unknown>): SecurityEvent | undefined {
  if (typeof entry['event'] !== 'string' || entry['event'].length > 60) return undefined;
  const str = (k: string, max = 200) => (typeof entry[k] === 'string' ? (entry[k] as string).slice(0, max) : undefined);
  const out: SecurityEvent = {
    ts: str('time', 40) ?? new Date().toISOString(),
    event: entry['event'],
    level: typeof entry['level'] === 'number' ? entry['level'] : 30,
  };
  if (typeof entry['status'] === 'number') out.status = entry['status'];
  for (const k of ['method', 'code', 'reason', 'projectId'] as const) {
    const v = str(k, 60);
    if (v) out[k] = v;
  }
  const path = str('path');
  if (path) out.path = path;
  return out;
}

/** A pino destination that keeps the security events and ignores everything else. */
export function securityEventStream(file: string): { write(line: string): void } {
  let ready = false;
  return {
    write(line: string) {
      if (!line.includes('"event"')) return;
      let entry: Record<string, unknown>;
      try {
        entry = JSON.parse(line) as Record<string, unknown>;
      } catch {
        return;
      }
      const event = pick(entry);
      if (!event) return;
      try {
        if (!ready) {
          mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
          if (existsSync(file)) chmodSync(file, 0o600);
          ready = true;
        }
        if (existsSync(file) && statSync(file).size > EVENT_LOG_MAX_BYTES) renameSync(file, `${file}.1`);
        // A new file is created owner-only.
        appendFileSync(file, `${JSON.stringify(event)}\n`, { mode: 0o600 });
      } catch {
        // The main log still has the entry; a full disk must not break request handling.
      }
    },
  };
}

/** Events at or after `sinceMs`, oldest first (the current file and the one rotated file). */
export function readSecurityEvents(file: string, sinceMs: number): SecurityEvent[] {
  const out: SecurityEvent[] = [];
  for (const f of [`${file}.1`, file]) {
    if (!existsSync(f)) continue;
    for (const line of readFileSync(f, 'utf8').split('\n')) {
      if (!line) continue;
      try {
        const e = JSON.parse(line) as SecurityEvent;
        if (typeof e.event === 'string' && Date.parse(e.ts) >= sinceMs) out.push(e);
      } catch {
        // skip a damaged line
      }
    }
  }
  return out;
}
