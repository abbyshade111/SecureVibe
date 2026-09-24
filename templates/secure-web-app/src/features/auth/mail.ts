/**
 * Delivery of account emails (reset links, invitations). When the optional mailer module is installed it is used;
 * otherwise messages are written as .eml files to DATA_DIR/outbox so a local owner can open them. Header values
 * are sanitized so nobody can inject extra headers through their email address or name.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { config } from '../../config.ts';
import { logger } from '../../lib/logger.ts';

export interface OutgoingMail {
  to: string;
  subject: string;
  text: string;
}

export function sanitiseHeader(value: string): string {
  return value.replace(/[\r\n\0]+/g, ' ').trim().slice(0, 500);
}

type Mailer = { sendMail(mail: OutgoingMail): Promise<void> };

let mailerPromise: Promise<Mailer | undefined> | undefined;

async function loadMailer(): Promise<Mailer | undefined> {
  if (!config.features.email) return undefined;
  if (!mailerPromise) {
    const modulePath = new URL('../../lib/mailer.ts', import.meta.url).href;
    mailerPromise = import(modulePath)
      .then((mod: Partial<Mailer>) => (typeof mod.sendMail === 'function' ? (mod as Mailer) : undefined))
      .catch(() => undefined);
  }
  return mailerPromise;
}

export function writeToOutbox(mail: OutgoingMail): string {
  const dir = resolve(config.dataDir, 'outbox');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = resolve(dir, `${Date.now()}-${Math.random().toString(36).slice(2, 8)}.eml`);
  const from = sanitiseHeader(config.MAIL_FROM ?? `no-reply@${config.appName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.local`);
  const content = [
    `From: ${from}`,
    `To: ${sanitiseHeader(mail.to)}`,
    `Subject: ${sanitiseHeader(mail.subject)}`,
    `Date: ${new Date().toUTCString()}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    mail.text,
    '',
  ].join('\r\n');
  writeFileSync(file, content, { mode: 0o600 });
  return file;
}

export async function deliver(mail: OutgoingMail): Promise<void> {
  const safe: OutgoingMail = { to: sanitiseHeader(mail.to), subject: sanitiseHeader(mail.subject), text: mail.text };
  const mailer = await loadMailer();
  if (mailer) {
    await mailer.sendMail(safe);
    return;
  }
  const file = writeToOutbox(safe);
  logger.info({ file, subject: safe.subject }, 'email written to the local outbox (no mail service configured)');
}
