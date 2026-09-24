/**
 * Reading a .zip the owner uploads, with the care a file from outside deserves.
 *
 * Written here rather than taken from a library because the checks are the point, not the decoding:
 *   - every entry's path is checked before anything is written (no "..", no absolute path, no backslash, no NUL),
 *   - symbolic links are left out (an entry marked as one is never written, so nothing can point out of the folder),
 *   - the uncompressed size is capped before extracting, from what the archive declares, and then the real size
 *     is checked against the declaration while inflating, so a small file that unpacks to a huge one stops early,
 *   - the same skip list applies to what comes out (dependencies, secrets files, keys, databases),
 *   - encrypted entries and formats this reader does not know (ZIP64, other compression) are refused by name.
 * What lands in the staging folder is then what the virus scanner is pointed at, like any other uploaded file.
 *
 * Node has no zip container reader of its own; it has the two things that matter, inflateRawSync (with an output
 * cap) and crc32, and the container format is small: a local header per file, a central directory, and an end
 * record that says where the directory is.
 */
import { crc32, inflateRawSync } from 'node:zlib';
import { safeRelative } from '../store/index.js';

export interface ZipLimits {
  maxFiles: number;
  maxTotalBytes: number;
  maxFileBytes: number;
}

export interface UnpackedFile {
  path: string;
  data: Buffer;
}

export interface UnpackResult {
  files: UnpackedFile[];
  skipped: { path: string; reason: string }[];
}

export class ZipError extends Error {}

const SIG_EOCD = 0x06054b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;

interface Entry {
  name: string;
  method: number;
  flags: number;
  crc: number;
  compressedSize: number;
  uncompressedSize: number;
  localOffset: number;
  isDirectory: boolean;
  isSymlink: boolean;
}

function readEntries(buf: Buffer): Entry[] {
  // The end record is at the very end unless the archive has a comment (at most 65535 bytes).
  const minEocd = 22;
  if (buf.length < minEocd) throw new ZipError('That file is not a zip archive.');
  let eocd = -1;
  for (let i = buf.length - minEocd; i >= Math.max(0, buf.length - minEocd - 65535); i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new ZipError('That file is not a zip archive (its end record is missing).');
  if (eocd >= 20 && buf.readUInt32LE(eocd - 20) === SIG_ZIP64_LOCATOR) throw new ZipError('That zip uses the ZIP64 format, which SecureVibe cannot read. Unpack it first, then choose the folder.');
  const count = buf.readUInt16LE(eocd + 10);
  const dirSize = buf.readUInt32LE(eocd + 12);
  const dirOffset = buf.readUInt32LE(eocd + 16);
  if (count === 0xffff || dirSize === 0xffffffff || dirOffset === 0xffffffff) throw new ZipError('That zip uses the ZIP64 format, which SecureVibe cannot read. Unpack it first, then choose the folder.');
  if (dirOffset + dirSize > eocd) throw new ZipError('That zip archive is damaged (its directory points past its end).');

  const entries: Entry[] = [];
  let p = dirOffset;
  for (let i = 0; i < count; i++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== SIG_CENTRAL) throw new ZipError('That zip archive is damaged (a directory entry is missing).');
    const madeByHost = buf.readUInt8(p + 5);
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const compressedSize = buf.readUInt32LE(p + 20);
    const uncompressedSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const externalAttrs = buf.readUInt32LE(p + 38);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString('utf8');
    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localOffset === 0xffffffff) throw new ZipError('That zip uses the ZIP64 format, which SecureVibe cannot read. Unpack it first, then choose the folder.');
    const unixMode = madeByHost === 3 ? (externalAttrs >>> 16) & 0xf000 : 0;
    entries.push({
      name,
      method,
      flags,
      crc,
      compressedSize,
      uncompressedSize,
      localOffset,
      isDirectory: name.endsWith('/') || unixMode === 0x4000,
      isSymlink: unixMode === 0xa000,
    });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function entryData(buf: Buffer, e: Entry): Buffer {
  const p = e.localOffset;
  if (p + 30 > buf.length || buf.readUInt32LE(p) !== SIG_LOCAL) throw new ZipError('That zip archive is damaged (a file header is missing).');
  const nameLen = buf.readUInt16LE(p + 26);
  const extraLen = buf.readUInt16LE(p + 28);
  const start = p + 30 + nameLen + extraLen;
  if (start + e.compressedSize > buf.length) throw new ZipError('That zip archive is damaged (a file runs past its end).');
  const raw = buf.subarray(start, start + e.compressedSize);
  if (e.method === 0) return raw;
  // The cap is the declared size: an entry that inflates past what it declared is lying, and stops here.
  return inflateRawSync(raw, { maxOutputLength: Math.max(1, e.uncompressedSize) });
}

/** "app/src/x.js, app/README.md" → "app": the one folder everything is inside, when there is one. */
function commonTopFolder(paths: string[]): string | undefined {
  const tops = new Set(paths.map((p) => p.split('/')[0]));
  if (tops.size !== 1) return undefined;
  const [top] = tops;
  return paths.every((p) => p.includes('/')) ? top : undefined;
}

/**
 * Unpacks a zip into memory, applying the limits and the skip rule before a byte is inflated. Nothing here
 * touches the file system; the caller writes what comes back, through the same confined path as any upload.
 */
export function unpackZip(buf: Buffer, limits: ZipLimits, skipReason: (relPath: string, size: number) => string | undefined): UnpackResult {
  const entries = readEntries(buf).filter((e) => !e.isDirectory);
  if (entries.some((e) => (e.flags & 0x1) !== 0)) throw new ZipError('That zip is password-protected. Unpack it first, then choose the folder.');

  // Paths first: refused before anything is decoded. Backslashes are turned into slashes (some Windows tools
  // write them); anything that still escapes is left out and named.
  // An absolute path is refused outright: safeRelative would quietly drop the leading slash and accept it, and
  // the unit test for this file found exactly that.
  const named = entries.map((e) => {
    const name = e.name.replace(/\\/g, '/');
    return { e, rel: name.startsWith('/') ? undefined : safeRelative(name) };
  });
  const top = commonTopFolder(named.filter((n) => n.rel).map((n) => n.rel!));
  const withPaths = named.map((n) => ({ ...n, rel: n.rel && top ? n.rel.split('/').slice(1).join('/') : n.rel }));

  const declaredTotal = withPaths.reduce((sum, n) => sum + n.e.uncompressedSize, 0);
  if (declaredTotal > limits.maxTotalBytes) throw new ZipError('That zip unpacks to more than 50 MB. Choose the app’s own folder, without its dependencies, and zip that.');
  if (withPaths.length > limits.maxFiles) throw new ZipError(`That zip holds ${withPaths.length} files; the limit is ${limits.maxFiles}. Zip the app’s own folder, not a folder above it.`);

  const files: UnpackedFile[] = [];
  const skipped: UnpackResult['skipped'] = [];
  let total = 0;
  for (const { e, rel } of withPaths) {
    if (!rel) {
      skipped.push({ path: e.name, reason: 'a path that points outside the app folder' });
      continue;
    }
    if (e.isSymlink) {
      skipped.push({ path: rel, reason: 'a symbolic link' });
      continue;
    }
    if (e.method !== 0 && e.method !== 8) {
      skipped.push({ path: rel, reason: 'compressed in a way SecureVibe cannot read' });
      continue;
    }
    const reason = skipReason(rel, e.uncompressedSize);
    if (reason) {
      skipped.push({ path: rel, reason });
      continue;
    }
    let data: Buffer;
    try {
      data = entryData(buf, e);
    } catch (err) {
      if (err instanceof ZipError) throw err;
      skipped.push({ path: rel, reason: 'unpacks to more than it declares' });
      continue;
    }
    if (data.length !== e.uncompressedSize || crc32(data) !== e.crc) {
      skipped.push({ path: rel, reason: 'does not match what the archive says about it' });
      continue;
    }
    total += data.length;
    if (total > limits.maxTotalBytes) throw new ZipError('That zip unpacks to more than 50 MB. Choose the app’s own folder, without its dependencies, and zip that.');
    files.push({ path: rel, data });
  }
  return { files, skipped };
}
