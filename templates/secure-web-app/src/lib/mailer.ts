/**
 * Mail delivery for the optional email feature (contract "Mailer", TPL-EMAIL-01). `src/features/auth/mail.ts`
 * loads this module and calls `sendMail()` whenever `email` is switched on; when it is off, or this module fails
 * to load, that caller already falls back to writing a `.eml` file itself. `sendMail()` here makes the same
 * choice explicitly: with `SMTP_URL` set it sends over a minimal SMTP client (STARTTLS when the server offers
 * it); otherwise — the default, "development" mode — it writes the message to `DATA_DIR/outbox` so a local owner
 * can open the file directly. Header values are sanitised again here (CR/LF stripped, length capped) so this
 * module is safe to call on its own, not only through the caller that already does it.
 */
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { connect as netConnect, type Socket } from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { connect as tlsConnect, type TLSSocket } from 'node:tls';
import ejs from 'ejs';
import { config } from '../config.ts';
import { isHostAllowed } from './http-client.ts';
import { logger } from './logger.ts';
import { emit } from '../security/events.ts';

const EMAIL_VIEWS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'views', 'email');

/**
 * Renders `src/views/email/<name>.ejs` to plain text. Email bodies are never assembled by concatenating strings
 * with user input — a template file is the only source, exactly like page views, and `<%= %>` is the only tag
 * (this module refuses a template using `<%-`, the unescaped form, the same way `src/lib/views.ts` does for pages).
 */
export function renderEmailTemplate(name: string, locals: Record<string, unknown>): string {
  if (!/^[a-z0-9_-]+$/i.test(name)) throw new Error(`Invalid email template name "${name}".`);
  const file = resolve(EMAIL_VIEWS_DIR, `${name}.ejs`);
  const source = readFileSync(file, 'utf8');
  if (/<%-/.test(source)) throw new Error(`Email template ${name}.ejs uses an unescaped output tag; only <%= %> is allowed.`);
  return (ejs.compile(source, { filename: file, client: false, cache: false })(locals) as string).trim();
}

export interface OutgoingMail {
  to: string;
  subject: string;
  text: string;
}

const HEADER_MAX = 500;

/** Strips CR/LF and NUL (so a value can never start a new header or truncate one) and caps the length. */
function sanitiseHeaderValue(value: string): string {
  return value.replace(/[\r\n\0]+/g, ' ').trim().slice(0, HEADER_MAX);
}

function fromAddress(): string {
  return sanitiseHeaderValue(config.MAIL_FROM ?? `no-reply@${config.appName.toLowerCase().replace(/[^a-z0-9]+/g, '-') || 'app'}.local`);
}

function outboxDir(): string {
  const dir = resolve(config.dataDir, 'outbox');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

/** Writes the message as a `.eml` file (mode 0600) and returns its path. Used when SMTP_URL is not set. */
function sendViaFile(mail: OutgoingMail): string {
  // A message may hold a password-reset link, so the file name must not be guessable.
  const file = resolve(outboxDir(), `${Date.now()}-${randomBytes(6).toString('hex')}.eml`);
  const content = [
    `From: ${fromAddress()}`,
    `To: ${sanitiseHeaderValue(mail.to)}`,
    `Subject: ${sanitiseHeaderValue(mail.subject)}`,
    `Date: ${new Date().toUTCString()}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    mail.text,
    '',
  ].join('\r\n');
  writeFileSync(file, content, { mode: 0o600 });
  return file;
}

// ---------------------------------------------------------------------------------------------------
// A minimal SMTP client (node:net / node:tls only): connect, EHLO, optional STARTTLS, optional AUTH LOGIN,
// MAIL FROM / RCPT TO / DATA, QUIT. Enough for a typical local relay or provider SMTP endpoint; it does not
// attempt PLAIN/CRAM-MD5 auth, pipelining, or 8BITMIME/SMTPUTF8 negotiation.
// ---------------------------------------------------------------------------------------------------

interface SmtpTarget {
  host: string;
  port: number;
  secure: boolean;
  user?: string;
  pass?: string;
}

/** `smtp://[user:pass@]host[:port]` (STARTTLS if offered) or `smtps://[user:pass@]host[:port]` (TLS from the start). */
export function parseSmtpUrl(raw: string): SmtpTarget {
  const u = new URL(raw);
  const secure = u.protocol === 'smtps:';
  if (u.protocol !== 'smtp:' && u.protocol !== 'smtps:') throw new Error('SMTP_URL must start with smtp:// or smtps://.');
  return {
    host: u.hostname,
    port: u.port ? Number(u.port) : secure ? 465 : 587,
    secure,
    user: u.username ? decodeURIComponent(u.username) : undefined,
    pass: u.password ? decodeURIComponent(u.password) : undefined,
  };
}

/** Reads one full SMTP reply (a final line not followed by `-`) with a timeout. */
function readReply(socket: Socket | TLSSocket, timeoutMs = 10_000): Promise<{ code: number; text: string }> {
  return new Promise((resolvePromise, reject) => {
    let buf = '';
    const timer = setTimeout(() => {
      socket.off('data', onData);
      reject(new Error('SMTP server did not answer in time.'));
    }, timeoutMs);
    const onData = (chunk: Buffer) => {
      buf += chunk.toString('latin1');
      const lines = buf.split('\r\n').filter(Boolean);
      const last = lines[lines.length - 1];
      if (last && /^\d{3} /.test(last)) {
        clearTimeout(timer);
        socket.off('data', onData);
        resolvePromise({ code: Number(last.slice(0, 3)), text: lines.join('\n') });
      }
    };
    socket.on('data', onData);
    socket.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

function writeLine(socket: Socket | TLSSocket, line: string): void {
  socket.write(`${line}\r\n`, 'latin1');
}

async function command(socket: Socket | TLSSocket, line: string, expect: number[]): Promise<string> {
  writeLine(socket, line);
  const reply = await readReply(socket);
  if (!expect.includes(reply.code)) throw new Error(`SMTP command "${line.split(' ')[0]}" failed: ${reply.text}`);
  return reply.text;
}

function connectPlain(host: string, port: number): Promise<Socket> {
  return new Promise((resolvePromise, reject) => {
    const socket = netConnect({ host, port });
    socket.once('connect', () => resolvePromise(socket));
    socket.once('error', reject);
    socket.setTimeout(15_000, () => socket.destroy(new Error('SMTP connection timed out.')));
  });
}

function upgradeToTls(socket: Socket, host: string): Promise<TLSSocket> {
  return new Promise((resolvePromise, reject) => {
    const tlsSocket = tlsConnect({ socket, servername: host, minVersion: 'TLSv1.2' }, () => resolvePromise(tlsSocket));
    tlsSocket.once('error', reject);
  });
}

function connectTls(host: string, port: number): Promise<TLSSocket> {
  return new Promise((resolvePromise, reject) => {
    const socket = tlsConnect({ host, port, minVersion: 'TLSv1.2' }, () => resolvePromise(socket));
    socket.once('error', reject);
    socket.setTimeout(15_000, () => socket.destroy(new Error('SMTP connection timed out.')));
  });
}

async function sendViaSmtp(target: SmtpTarget, mail: OutgoingMail): Promise<void> {
  const localName = 'localhost';
  let socket: Socket | TLSSocket = target.secure ? await connectTls(target.host, target.port) : await connectPlain(target.host, target.port);
  try {
    const greeting = await readReply(socket);
    if (greeting.code !== 220) throw new Error(`SMTP server did not greet us: ${greeting.text}`);
    let caps = await command(socket, `EHLO ${localName}`, [250]);

    if (!target.secure && /STARTTLS/i.test(caps)) {
      await command(socket, 'STARTTLS', [220]);
      socket = await upgradeToTls(socket as Socket, target.host);
      caps = await command(socket, `EHLO ${localName}`, [250]);
    }

    if (target.user !== undefined) {
      await command(socket, 'AUTH LOGIN', [334]);
      await command(socket, Buffer.from(target.user, 'utf8').toString('base64'), [334]);
      await command(socket, Buffer.from(target.pass ?? '', 'utf8').toString('base64'), [235]);
    }
    void caps;

    const from = fromAddress();
    const to = sanitiseHeaderValue(mail.to);
    await command(socket, `MAIL FROM:<${from}>`, [250]);
    await command(socket, `RCPT TO:<${to}>`, [250, 251]);
    await command(socket, 'DATA', [354]);
    const body = [
      `From: ${from}`,
      `To: ${to}`,
      `Subject: ${sanitiseHeaderValue(mail.subject)}`,
      `Date: ${new Date().toUTCString()}`,
      'Content-Type: text/plain; charset=utf-8',
      '',
      // RFC 5321 dot-stuffing: a line that starts with '.' must be escaped as '..' so it is not read as the
      // end-of-data marker.
      ...mail.text.split(/\r\n|\n/).map((line) => (line.startsWith('.') ? `.${line}` : line)),
    ].join('\r\n');
    await command(socket, `${body}\r\n.`, [250]);
    await command(socket, 'QUIT', [221]).catch(() => undefined);
  } finally {
    socket.end();
    socket.destroy();
  }
}

/** Sends one message: SMTP when `SMTP_URL` is set, otherwise a `.eml` file in `DATA_DIR/outbox`. */
export async function sendMail(mail: OutgoingMail): Promise<void> {
  const safe: OutgoingMail = { to: sanitiseHeaderValue(mail.to), subject: sanitiseHeaderValue(mail.subject), text: mail.text };
  if (!config.SMTP_URL) {
    const file = sendViaFile(safe);
    logger.info({ file, subject: safe.subject }, 'email written to the local outbox (SMTP_URL is not set)');
    return;
  }
  const target = parseSmtpUrl(config.SMTP_URL);
  // The SMTP server is itself an outbound destination: this app's trust-zone model (contract §1.5, AS-01) is
  // deny-by-default egress, so an SMTP host must be on OUTBOUND_ALLOWED_HOSTS exactly like any other external
  // service, even though sending mail does not go through src/lib/http-client.ts (SMTP is not HTTP).
  if (!isHostAllowed(target.host, String(target.port), 'https:')) {
    emit('outbound.blocked', { host: target.host });
    const file = sendViaFile(safe);
    logger.warn({ host: target.host, file }, `SMTP_URL points at a host not on OUTBOUND_ALLOWED_HOSTS; add "${target.host}:${target.port}" to allow it. The message was written to the outbox instead.`);
    return;
  }
  try {
    await sendViaSmtp(target, safe);
    logger.info({ host: target.host, subject: safe.subject }, 'email sent via SMTP');
  } catch (err) {
    // A real mail failure must not silently disappear: fall back to the outbox so the message is not lost, and
    // log the SMTP failure (never the mail body, never SMTP credentials).
    const file = sendViaFile(safe);
    logger.error({ host: target.host, err: err instanceof Error ? err.message : String(err), file }, 'SMTP delivery failed; the message was written to the outbox instead');
  }
}
