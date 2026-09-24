/**
 * A small zip writer for tests: enough of the format to build the archives the reader must cope with, including
 * the ones a person would never make on purpose (a path that escapes, a link, an entry lying about its size).
 */
import { crc32, deflateRawSync } from 'node:zlib';

export interface ZipEntryInput {
  name: string;
  data: Buffer | string;
  /** 'deflate' (default) or 'store'. */
  method?: 'deflate' | 'store';
  /** Unix mode written into the external attributes, e.g. 0o120777 for a symbolic link. */
  mode?: number;
  /** Lie in the central directory about the uncompressed size (what a hostile archive does). */
  declaredSize?: number;
  /** Mark the entry as password-protected. */
  encrypted?: boolean;
}

export function writeZip(entries: ZipEntryInput[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data);
    const method = e.method === 'store' ? 0 : 8;
    const packed = method === 0 ? data : deflateRawSync(data);
    const name = Buffer.from(e.name, 'utf8');
    const crc = crc32(data);
    const flags = (e.encrypted ? 1 : 0) | 0x800;
    const declared = e.declaredSize ?? data.length;

    const local = Buffer.alloc(30 + name.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(declared, 22);
    local.writeUInt16LE(name.length, 26);
    name.copy(local, 30);
    locals.push(local, packed);

    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE((3 << 8) | 20, 4); // made on unix
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(packed.length, 20);
    central.writeUInt32LE(declared, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(((e.mode ?? 0o100644) << 16) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    name.copy(central, 46);
    centrals.push(central);
    offset += local.length + packed.length;
  }
  const dir = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(dir.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, dir, eocd]);
}
