/** The zip reader: what it unpacks, what it leaves out and names, and what it refuses outright. */
import { describe, expect, it } from 'vitest';
import { skipReason, UPLOAD_LIMITS } from '../../src/api/uploads.js';
import { unpackZip, ZipError } from '../../src/api/zip.js';
import { writeZip } from '../fixtures/zip-writer.js';

const unpack = (buf: Buffer, limits = UPLOAD_LIMITS) => unpackZip(buf, limits, skipReason);

describe('unpacking a zip', () => {
  it('unpacks deflated and stored files, drops the one folder everything is inside, and skips folders', () => {
    const zip = writeZip([
      { name: 'my-app/', data: '' },
      { name: 'my-app/src/index.js', data: 'console.log(1)' },
      { name: 'my-app/README.md', data: '# hi', method: 'store' },
    ]);
    const out = unpack(zip);
    expect(out.files.map((f) => [f.path, f.data.toString()])).toEqual([
      ['src/index.js', 'console.log(1)'],
      ['README.md', '# hi'],
    ]);
    expect(out.skipped).toEqual([]);
  });

  it('keeps paths as they are when there is no single top folder', () => {
    const out = unpack(writeZip([{ name: 'index.js', data: 'a' }, { name: 'lib/b.js', data: 'b' }]));
    expect(out.files.map((f) => f.path)).toEqual(['index.js', 'lib/b.js']);
  });

  it('leaves out, and names, a path that escapes, a link, a secrets file and dependencies', () => {
    const zip = writeZip([
      { name: 'app/src/ok.js', data: 'ok' },
      { name: 'app/../escape.js', data: 'x' },
      { name: '/etc/passwd', data: 'x' },
      { name: 'app/link', data: '../../outside', mode: 0o120777 },
      { name: 'app/.env', data: 'SECRET=1' },
      { name: 'app/node_modules/x/index.js', data: 'x' },
      { name: 'app\\win\\style.css', data: 'body{}' },
    ]);
    const out = unpack(zip);
    // The escaping paths are refused before the top folder is worked out, so "app" is still the one folder
    // everything accepted is inside, and it is dropped. (The first draft of the reader let "/etc/passwd" through
    // as "etc/passwd": safeRelative drops a leading slash, so absolute paths are now refused before it.)
    expect(out.files.map((f) => f.path)).toEqual(['src/ok.js', 'win/style.css']);
    expect(out.skipped).toEqual([
      { path: 'app/../escape.js', reason: 'a path that points outside the app folder' },
      { path: '/etc/passwd', reason: 'a path that points outside the app folder' },
      { path: 'link', reason: 'a symbolic link' },
      { path: '.env', reason: 'a secrets file (.env)' },
      { path: 'node_modules/x/index.js', reason: 'dependencies or build output' },
    ]);
  });

  it('stops an entry that unpacks to more than it declares, before it can grow', () => {
    const big = Buffer.alloc(200_000, 'a');
    const zip = writeZip([{ name: 'app/small.txt', data: big, declaredSize: 100 }, { name: 'app/fine.txt', data: 'fine' }]);
    const out = unpack(zip);
    expect(out.files.map((f) => f.path)).toEqual(['fine.txt']);
    expect(out.skipped).toEqual([{ path: 'small.txt', reason: 'unpacks to more than it declares' }]);
  });

  it('leaves out an entry whose contents do not match its checksum or size', () => {
    const zip = writeZip([{ name: 'a.txt', data: 'hello', method: 'store', declaredSize: 3 }]);
    const out = unpack(zip);
    expect(out.files).toEqual([]);
    expect(out.skipped[0]!.reason).toMatch(/does not match/);
  });

  it('refuses a password-protected zip, a zip past the size limit, and something that is not a zip', () => {
    expect(() => unpack(writeZip([{ name: 'a.txt', data: 'x', encrypted: true }]))).toThrow(/password-protected/);
    expect(() => unpack(writeZip([{ name: 'a.txt', data: 'x'.repeat(10), declaredSize: 60 * 1024 * 1024 }]))).toThrow(/more than 50 MB/);
    expect(() => unpack(writeZip([{ name: 'a.txt', data: 'x' }, { name: 'b.txt', data: 'y' }]), { ...UPLOAD_LIMITS, maxFiles: 1 })).toThrow(/limit is 1/);
    expect(() => unpack(Buffer.from('not a zip at all, just some bytes'))).toThrow(ZipError);
    expect(() => unpack(Buffer.alloc(0))).toThrow(/not a zip/);
  });

  it('applies the per-file size limit from the declared size, before inflating', () => {
    const zip = writeZip([{ name: 'app/huge.bin', data: Buffer.alloc(3 * 1024 * 1024, 'z') }, { name: 'app/ok.js', data: 'ok' }]);
    const out = unpack(zip);
    expect(out.files.map((f) => f.path)).toEqual(['ok.js']);
    expect(out.skipped).toEqual([{ path: 'huge.bin', reason: 'larger than 2 MB' }]);
  });
});
