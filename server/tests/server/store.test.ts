import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { confinePath, isWithin, PathConfinementError, safeRelative } from '../../src/store/paths.js';
import { isProjectId, isRunId, newProjectId, newRunId } from '../../src/store/ids.js';
import { ProjectNotFoundError, ProjectStore } from '../../src/store/project-store.js';

describe('path confinement', () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'securevibe-confine-'));
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it('resolves an ordinary path inside the root', () => {
    expect(confinePath(root, 'a', 'b.txt')).toBe(join(root, 'a', 'b.txt'));
  });

  it('rejects a .. escape', () => {
    expect(() => confinePath(root, '..', 'etc', 'passwd')).toThrow(PathConfinementError);
  });

  it('rejects an absolute segment', () => {
    expect(() => confinePath(root, '/etc/passwd')).toThrow(PathConfinementError);
  });

  it('rejects a NUL byte', () => {
    expect(() => confinePath(root, 'a\0b')).toThrow(PathConfinementError);
  });

  it('rejects a UNC-style path', () => {
    expect(() => confinePath(root, '\\\\attacker\\share')).toThrow(PathConfinementError);
  });

  it('isWithin agrees the root is within itself', () => {
    expect(isWithin(root, root)).toBe(true);
  });

  it('safeRelative rejects traversal and backslashes, keeps a clean relative path', () => {
    expect(safeRelative('a/b.txt')).toBe('a/b.txt');
    expect(safeRelative('../a')).toBeUndefined();
    expect(safeRelative('a\\b')).toBeUndefined();
  });
});

describe('identifiers', () => {
  it('generates ids matching their own patterns', () => {
    expect(isProjectId(newProjectId())).toBe(true);
    expect(isRunId(newRunId())).toBe(true);
    expect(isProjectId('not-an-id')).toBe(false);
  });
});

describe('ProjectStore', () => {
  let home: string;
  let store: ProjectStore;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'securevibe-store-'));
    store = new ProjectStore(home);
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));

  it('creates a project with atomic persistence and reads it back', () => {
    const project = store.create({ name: 'Test', mode: 'guided' });
    expect(project.status).toBe('draft');
    const read = store.get(project.id);
    expect(read?.name).toBe('Test');
  });

  it('throws ProjectNotFoundError for an unknown id via mustGet', () => {
    expect(() => store.mustGet('p_aaaaaaaaaa')).toThrow(ProjectNotFoundError);
  });

  it('confines project-relative paths to the project folder', () => {
    const project = store.create({ name: 'Confine me', mode: 'guided' });
    expect(() => store.projectPath(project.id, '..', '..', 'etc')).toThrow();
  });

  it('archives app/ to app-v<N>/ on rebuild and bumps appVersion', () => {
    const project = store.create({ name: 'Versioned', mode: 'guided' });
    const { appDir } = store.paths(project.id);
    mkdirSync(appDir, { recursive: true });
    writeFileSync(join(appDir, 'marker.txt'), 'v1');

    const archived = store.archiveApp(project.id);
    expect(archived.version).toBe(1);
    expect(archived.archivedTo).toBeDefined();
    expect(store.get(project.id)?.appVersion).toBe(1);
  });

  it('records and clears finding decisions', () => {
    const project = store.create({ name: 'Findings', mode: 'guided' });
    store.setFindingDecision(project.id, { fingerprint: 'fp1', status: 'accepted', triage: { reason: 'low risk', by: 'owner', at: new Date().toISOString() } });
    expect(store.get(project.id)?.findingDecisions).toHaveLength(1);
    store.setFindingDecision(project.id, { fingerprint: 'fp1', status: 'open' });
    expect(store.get(project.id)?.findingDecisions).toHaveLength(0);
  });
});
