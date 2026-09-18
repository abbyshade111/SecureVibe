import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { ZipArchive } from 'archiver';
import { afterAll, describe, expect, it } from 'vitest';
import { ZIP_EXCLUDE } from '../../src/api/artifacts.js';

const dir = mkdtempSync(join(tmpdir(), 'sv-zip-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('app.zip contents', () => {
  it('leaves out secrets, the one-time admin password and runtime data', async () => {
    for (const file of ['.env', '.env.local', '.env.example', 'FIRST-LOGIN.txt', 'package.json', 'src/app.ts', 'data/app.sqlite', 'node_modules/x/index.js']) {
      mkdirSync(join(dir, file, '..'), { recursive: true });
      writeFileSync(join(dir, file), 'x');
    }
    const names: string[] = [];
    const archive = new ZipArchive();
    archive.on('entry', (e) => names.push(e.name));
    archive.pipe(new PassThrough().resume());
    archive.glob('**/*', { cwd: dir, ignore: [...ZIP_EXCLUDE], dot: true });
    archive.file(join(dir, '.env.example'), { name: '.env.example' });
    await archive.finalize();
    expect(names.filter((n) => !n.endsWith('/')).sort()).toEqual(['.env.example', 'package.json', 'src/app.ts']);
  });
});
