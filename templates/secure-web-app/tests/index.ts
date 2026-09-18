/**
 * Suite entry point. `node --test tests/` resolves the directory through tests/package.json to this file,
 * which imports every security test and every generated feature test in a stable order. Each file wraps
 * its tests in a `describe` block, so per-file hooks stay scoped when everything runs in one process.
 */
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const here = import.meta.dirname;

function testFiles(dir: string): string[] {
  const full = join(here, dir);
  let entries: string[] = [];
  try {
    entries = readdirSync(full);
  } catch {
    return [];
  }
  return entries
    .filter((f) => f.endsWith('.test.ts'))
    .sort()
    .map((f) => join(full, f));
}

for (const file of [...testFiles('security'), ...testFiles('features')]) {
  await import(pathToFileURL(file).href);
}
