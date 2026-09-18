/**
 * Atomic file writes: write to a sibling temp file, fsync, then rename over the target. A crash mid-write leaves the
 * previous file intact instead of a half-written JSON document.
 */
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { mkdir, open, rename, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { ZodType } from 'zod';

function tempNameFor(file: string): string {
  return join(dirname(file), `.${randomBytes(6).toString('hex')}.tmp`);
}

export function writeFileAtomicSync(file: string, content: string | Buffer, mode = 0o644): void {
  mkdirSync(dirname(file), { recursive: true });
  const tmp = tempNameFor(file);
  const fd = openSync(tmp, 'w', mode);
  try {
    if (typeof content === 'string') writeSync(fd, content);
    else writeSync(fd, content);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    renameSync(tmp, file);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      // nothing else to clean
    }
    throw err;
  }
}

export async function writeFileAtomic(file: string, content: string | Buffer, mode = 0o644): Promise<void> {
  await mkdir(dirname(file), { recursive: true });
  const tmp = tempNameFor(file);
  const handle = await open(tmp, 'w', mode);
  try {
    await handle.writeFile(content);
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(tmp, file);
  } catch (err) {
    await unlink(tmp).catch(() => undefined);
    throw err;
  }
}

export function writeJsonAtomicSync(file: string, value: unknown, mode = 0o644): void {
  writeFileAtomicSync(file, `${JSON.stringify(value, null, 2)}\n`, mode);
}

export async function writeJsonAtomic(file: string, value: unknown, mode = 0o644): Promise<void> {
  await writeFileAtomic(file, `${JSON.stringify(value, null, 2)}\n`, mode);
}

/** Reads and parses a JSON file; validates with `schema` when given. */
export function readJsonFile<T = unknown>(file: string, schema?: ZodType<T>): T {
  const raw = JSON.parse(readFileSync(file, 'utf8')) as unknown;
  return schema ? schema.parse(raw) : (raw as T);
}
