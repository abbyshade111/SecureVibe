/** Template upgrades: which files change, which are kept, and how new .env keys are added. */
import { describe, expect, it } from 'vitest';
import { mergeEnvKeys, planUpgrade, type OldEntry } from '../../src/generator/upgrade.js';

const entries = (o: Record<string, OldEntry>) => new Map(Object.entries(o));
const hashes = (o: Record<string, string>) => new Map(Object.entries(o));

describe('planUpgrade', () => {
  it('updates unchanged template files, keeps changed ones, adds new ones and removes dropped ones', () => {
    const plan = planUpgrade({
      oldEntries: entries({
        'src/lib/a.ts': { sha256: 'a1', origin: 'template' },
        'src/lib/b.ts': { sha256: 'b1', origin: 'template' },
        'src/features/index.ts': { sha256: 'i1', origin: 'template' },
        'src/features/habit/index.ts': { sha256: 'h1', origin: 'expanded' },
        'src/lib/old.ts': { sha256: 'o1', origin: 'template' },
        'src/lib/old-edited.ts': { sha256: 'e1', origin: 'template' },
      }),
      appHashes: hashes({
        'src/lib/a.ts': 'a1', // untouched since the build
        'src/lib/b.ts': 'b1',
        'src/features/index.ts': 'i2', // Claude appended the generated features
        'src/features/habit/index.ts': 'h1',
        'src/lib/old.ts': 'o1',
        'src/lib/old-edited.ts': 'e2',
        '.env': 'secret',
      }),
      newHashes: hashes({
        'src/lib/a.ts': 'a2', // the template improved it
        'src/lib/b.ts': 'b1', // unchanged
        'src/features/index.ts': 'i3', // improved too, but the app's copy carries changes
        'src/lib/new.ts': 'n1',
        '.env': 'fresh-secrets',
        'securevibe.provenance.json': 'x',
      }),
    });
    expect(plan.updated).toEqual(['src/lib/a.ts']);
    expect(plan.added).toEqual(['src/lib/new.ts']);
    expect(plan.removed).toEqual(['src/lib/old.ts']);
    expect(plan.kept).toEqual(['src/features/index.ts']);
    expect(plan.unchanged).toBe(1);
    // The edited file the template dropped stays; .env and provenance are never touched.
  });

  it('never overwrites files whose origin it does not know', () => {
    const plan = planUpgrade({
      oldEntries: entries({}),
      appHashes: hashes({ 'src/lib/a.ts': 'mine' }),
      newHashes: hashes({ 'src/lib/a.ts': 'theirs', 'src/lib/b.ts': 'new' }),
    });
    expect(plan.kept).toEqual(['src/lib/a.ts']);
    expect(plan.added).toEqual(['src/lib/b.ts']);
    expect(plan.updated).toEqual([]);
  });
});

describe('mergeEnvKeys', () => {
  it('adds only the keys the app lacks, keeping its values and secrets as they are', () => {
    const app = 'APP_NAME=Mine\nSESSION_SECRET=abc\nAI_ENABLED=1\n';
    const template = '# comment\nAPP_NAME=Template\nSESSION_SECRET=zzz\nAI_ENABLED=0\nAI_WEB_SEARCH=0\nNEW_FLAG=1\n';
    const merged = mergeEnvKeys(app, template);
    expect(merged.added).toEqual(['AI_WEB_SEARCH', 'NEW_FLAG']);
    expect(merged.text).toContain('SESSION_SECRET=abc');
    expect(merged.text).toContain('AI_ENABLED=1');
    expect(merged.text).not.toContain('SESSION_SECRET=zzz');
    expect(merged.text.endsWith('AI_WEB_SEARCH=0\nNEW_FLAG=1\n')).toBe(true);
  });

  it('leaves the file untouched when nothing is new', () => {
    const merged = mergeEnvKeys('A=1\n', 'A=2\n');
    expect(merged).toEqual({ text: 'A=1\n', added: [] });
  });
});
