/**
 * Talking to the ClamAV daemon: the wire format, and how its answer is read.
 *
 * Deliberately free of the app's configuration, so it can be exercised as plain functions with no `.env`, no
 * database and no running app. That is not tidiness. The first version of this lived beside the part that
 * reads `config`, and its test file could not run at all until an app had been started to write a `.env` —
 * which meant the wire format was only ever tested through a live upload. Same mistake as `db/limits.ts`
 * earlier the same day, same fix.
 *
 * Nothing here decides anything. It reports what the scanner said; `malware.ts` turns that into a policy, and
 * the upload route is what acts on it.
 */
import { createReadStream } from 'node:fs';
import { connect, type Socket } from 'node:net';

/** What a scan concluded. There is no fourth answer, and `unavailable` is never treated as `clean`. */
export type MalwareVerdict =
  | { kind: 'clean' }
  | { kind: 'infected'; signature: string }
  | { kind: 'unavailable'; reason: string };

/** clamd's INSTREAM replies, which are short and end in a NUL. Exported for tests: no daemon needed. */
export function parseClamdReply(raw: string): MalwareVerdict {
  const reply = raw.replace(/\0+$/, '').trim();
  if (reply === '') return { kind: 'unavailable', reason: 'The virus scanner answered with nothing.' };
  // "stream: OK"
  if (/\bOK$/.test(reply)) return { kind: 'clean' };
  // "stream: Eicar-Test-Signature FOUND"
  const found = /:\s*(.+?)\s+FOUND$/.exec(reply);
  if (found?.[1]) return { kind: 'infected', signature: found[1] };
  // "INSTREAM size limit exceeded. ERROR" and anything else ending ERROR.
  if (/size limit exceeded/i.test(reply)) {
    return { kind: 'unavailable', reason: 'The file is larger than the virus scanner will accept, so it could not be checked.' };
  }
  if (/\bERROR$/.test(reply)) {
    return { kind: 'unavailable', reason: 'The virus scanner could not read the file, so it was not checked.' };
  }
  return { kind: 'unavailable', reason: 'The virus scanner gave an answer this app did not understand, so the file was not checked.' };
}

/** The INSTREAM frame for one chunk: its length as four big-endian bytes, then the bytes. */
export function instreamChunk(chunk: Buffer): Buffer {
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(chunk.length, 0);
  return Buffer.concat([header, chunk]);
}

/** The zero-length frame that tells clamd the file is finished. */
export const INSTREAM_END = Buffer.from([0, 0, 0, 0]);

/**
 * Where the daemon is listening. A Unix socket is what ClamAV's own packages configure by default, so it is
 * supported first-class rather than making somebody edit clamd.conf to open a TCP port they did not ask for.
 * Either way it is this machine only: nothing here should ever be pointed at another host, because the file
 * would then travel the network to be checked.
 */
export type ClamdTarget = ({ socketPath: string } | { host: string; port: number }) & { timeoutMs: number };

/** Plain words for the reports and for an error message, without leaking anything useful to an attacker. */
export function describeTarget(target: ClamdTarget): string {
  return 'socketPath' in target ? target.socketPath : `${target.host}:${target.port}`;
}

/** Streams the file to clamd and reads its one-line answer. Never throws: a failure is an `unavailable`. */
export function clamdScan(filePath: string, target: ClamdTarget): Promise<MalwareVerdict> {
  return new Promise<MalwareVerdict>((resolve) => {
    let settled = false;
    const done = (verdict: MalwareVerdict): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(verdict);
    };

    const socket: Socket = connect('socketPath' in target ? { path: target.socketPath } : { host: target.host, port: target.port });
    socket.setTimeout(target.timeoutMs);

    socket.on('timeout', () =>
      done({ kind: 'unavailable', reason: 'The virus scanner did not answer in time, so the file was not checked.' }),
    );
    socket.on('error', () =>
      done({
        kind: 'unavailable',
        reason: `No virus scanner is answering on ${describeTarget(target)}, so uploaded files cannot be checked.`,
      }),
    );

    const reply: Buffer[] = [];
    socket.on('data', (chunk: Buffer) => {
      reply.push(chunk);
      // Replies are short and NUL-terminated; answer as soon as the terminator arrives.
      if (chunk.includes(0)) done(parseClamdReply(Buffer.concat(reply).toString('utf8')));
    });
    socket.on('close', () => {
      if (reply.length > 0) done(parseClamdReply(Buffer.concat(reply).toString('utf8')));
      else done({ kind: 'unavailable', reason: 'The virus scanner closed the connection without answering, so the file was not checked.' });
    });

    socket.on('connect', () => {
      socket.write('zINSTREAM\0');
      const file = createReadStream(filePath, { highWaterMark: 64 * 1024 });
      file.on('data', (chunk) => {
        if (!settled) socket.write(instreamChunk(chunk as Buffer));
      });
      file.on('end', () => {
        if (!settled) socket.write(INSTREAM_END);
      });
      file.on('error', () =>
        done({ kind: 'unavailable', reason: 'The file could not be read for checking, so it was not kept.' }),
      );
    });
  });
}

