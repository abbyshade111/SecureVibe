/**
 * "What only you can do": the things SecureVibe cannot finish for the owner, worked out from facts.
 *
 * Three sources, none of them prose:
 *   - the app's .env: a setting a switched-on feature needs, left empty (SMTP for email, the AI key, the
 *     outbound host list for an outside service). Only whether a key is empty is read; no value leaves this file.
 *   - the answers: an outside service named without an address, or without an account and key, which leaves
 *     its connection unbuilt (see ExternalApiSpec).
 *   - the plan check: a planned feature that came back not built, partly built, or files in place with no proof.
 * Each item says what to do and what stays switched off until it is done, in the shape going-online.ts already
 * uses for deployment, so the Results page and the reports show one list.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { PipelineRun } from '@shared/pipeline.js';
import type { DesignProfile } from '@shared/profile.js';

export type OwnerTask = NonNullable<PipelineRun['ownerTasks']>[number];

/** Which .env keys are empty, without keeping any value. A missing key counts as empty. */
export function emptyEnvKeys(appDir: string, keys: string[]): Set<string> {
  const file = join(appDir, '.env');
  const set = new Map<string, boolean>();
  if (existsSync(file)) {
    for (const raw of readFileSync(file, 'utf8').split('\n')) {
      const line = raw.trim();
      if (line === '' || line.startsWith('#')) continue;
      const eq = line.indexOf('=');
      if (eq <= 0) continue;
      const key = line.slice(0, eq).trim();
      const value = line.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
      set.set(key, value !== '');
    }
  }
  return new Set(keys.filter((k) => set.get(k) !== true));
}

export interface OwnerTaskInput {
  profile?: DesignProfile;
  appDir: string;
  planCoverage?: PipelineRun['planCoverage'];
}

export function ownerTasks(input: OwnerTaskInput): OwnerTask[] {
  const tasks: OwnerTask[] = [];
  const profile = input.profile;
  const caps = profile?.capabilities;

  if (caps) {
    const wanted: string[] = [];
    if (caps.email) wanted.push('SMTP_URL', 'MAIL_FROM');
    if (caps.aiAssistant.enabled) wanted.push('ANTHROPIC_API_KEY');
    if (caps.externalApis.some((a) => a.host.trim() !== '')) wanted.push('OUTBOUND_ALLOWED_HOSTS');
    const empty = emptyEnvKeys(input.appDir, wanted);

    if (caps.email && (empty.has('SMTP_URL') || empty.has('MAIL_FROM'))) {
      tasks.push({
        id: 'setting-email',
        source: 'setting',
        title: "Fill in SMTP_URL and MAIL_FROM in the app's .env file with your email provider's details.",
        because: 'You asked for email, and the mail settings are still empty.',
        staysOff: 'Until then the app writes every message to a file in its data folder instead of sending it, so nobody receives sign-in links or notifications.',
      });
    }
    if (caps.aiAssistant.enabled && empty.has('ANTHROPIC_API_KEY')) {
      tasks.push({
        id: 'setting-ai-key',
        source: 'setting',
        title: 'Give the app an AI key: set ANTHROPIC_API_KEY in the environment it runs in (not in a file you share).',
        because: 'You asked for an assistant, and the app has no key of its own to call the AI service with.',
        staysOff: 'Until then the assistant answers nothing.',
      });
    }
    for (const api of caps.externalApis) {
      const name = api.name.trim() || 'an outside service';
      if (api.host.trim() === '') {
        tasks.push({
          id: `service-address-${slug(name)}`,
          source: 'service',
          title: `Find out the address ${name} is called at (its host name, like api.example.com) and add it to your answers.`,
          because: `You named ${name} without an address, and SecureVibe does not guess one.`,
          staysOff: `Until then the connection to ${name} is not built.`,
        });
      } else if (empty.has('OUTBOUND_ALLOWED_HOSTS')) {
        tasks.push({
          id: `service-allow-${slug(name)}`,
          source: 'setting',
          title: `Add ${api.host.trim()} to OUTBOUND_ALLOWED_HOSTS in the app's .env file.`,
          because: `The app may only call hosts on that list, and it is empty.`,
          staysOff: `Until then every call to ${name} is refused.`,
        });
      }
      if (api.credentials !== 'have') {
        tasks.push({
          id: `service-key-${slug(name)}`,
          source: 'service',
          title: `Get an account and key for ${name}, then change your answer to say you have them.`,
          because: api.credentials === 'not-yet' ? `You said you do not have a key for ${name} yet.` : `You were not sure whether you have a key for ${name}.`,
          staysOff: `Until then the connection to ${name} is not built.`,
        });
      }
    }
  }

  for (const c of input.planCoverage ?? []) {
    if (c.status === 'built' || c.status === 'left-out') continue;
    const what = c.status === 'not-built' ? 'was not built' : c.status === 'partly' ? 'was only partly built' : 'has its files in place but nothing has shown it works';
    tasks.push({
      id: `feature-${c.featureId}`,
      source: 'feature',
      title: `Try "${c.title}" in the app. If it does not do what you expected, rebuild or ask for a fix.`,
      because: `The plan check found it ${what}: ${c.evidence}`,
      staysOff: c.status === 'not-built' ? 'Until then this feature does not exist in the app.' : 'Until then nobody has seen this feature work.',
    });
  }

  return tasks;
}

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'service';
}
