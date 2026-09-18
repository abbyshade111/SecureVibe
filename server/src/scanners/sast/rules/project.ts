/**
 * Project-level rules that need the manifest or provenance: imports outside the allow-list and protected
 * files that changed after scaffolding.
 */
import { isBuiltin } from 'node:module';
import { join } from 'node:path';
import { positionOf } from '../engine.js';
import { globToRegex, sha256File } from '../files.js';
import { defineRule } from './base.js';

export function packageNameOf(specifier: string): string {
  if (specifier.startsWith('@')) {
    const [scope, name] = specifier.split('/');
    return name ? `${scope}/${name}` : specifier;
  }
  return specifier.split('/')[0] ?? specifier;
}

export function isImportAllowed(specifier: string, allowed: string[]): boolean {
  if (specifier.startsWith('.') || specifier.startsWith('/') || specifier.startsWith('#')) return true;
  const builtin = isBuiltin(specifier);
  if (builtin && (allowed.includes('node:*') || allowed.includes(specifier) || allowed.includes(specifier.replace(/^node:/, '')))) return true;
  const pkg = packageNameOf(specifier);
  return allowed.some((a) => a === specifier || a === pkg || (a.includes('*') && (globToRegex(a).test(specifier) || globToRegex(a).test(pkg))));
}

export const disallowedImport = defineRule({
  id: 'sast.disallowed-import',
  title: 'A package outside the allowed list is imported',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-1104'],
  asvs: ['V15.1.2'],
  sbd: ['RR-01'],
  exploitability: 'theoretical',
  description: 'Generated code imports a package that is not in the template’s locked dependency set.',
  impact: 'The package is not installed (the app will not start) or would have to be added without review, widening the supply-chain risk.',
  fix: 'Use the template’s own helpers or the allowed packages (express, zod, ejs, pino, node:*). Remove the import.',
  appliesTo: ['ts'],
  checkTree(tree, report) {
    const allowed = tree.ctx.manifest?.allowedImports ?? [];
    if (allowed.length === 0) return;
    for (const file of tree.files) {
      if (file.kind !== 'ts' || file.isProtected) continue;
      for (const imp of file.imports) {
        if (isImportAllowed(imp.specifier, allowed)) continue;
        const pos = positionOf(imp.node, file);
        report(file.relPath, { line: pos.line, column: pos.column, evidence: `${file.relPath} imports "${imp.specifier}", which is not in allowedImports`, fingerprintExtra: imp.specifier });
      }
    }
  },
});

export const protectedFileModified = defineRule({
  id: 'sast.protected-file-modified',
  title: 'A protected security file was changed',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-693'],
  asvs: ['V15.2.3'],
  aisvs: ['AC.4.4'],
  sbd: ['MT-03'],
  exploitability: 'theoretical',
  description: 'A file that the template marks as protected (security middleware, config, tests, package files) no longer matches the hash recorded when the app was scaffolded.',
  impact: 'The security controls the reports rely on may have been weakened or removed; their evidence is no longer trustworthy until reviewed.',
  fix: 'Review the change against the template version. If it was unintended, restore the file from the template.',
  appliesTo: ['ts'],
  checkTree(tree, report) {
    const hashes = tree.ctx.provenance?.protectedFileHashes;
    if (!hashes) return;
    for (const [relPath, expected] of Object.entries(hashes)) {
      const actual = sha256File(join(tree.ctx.appDir, relPath));
      if (actual === expected) continue;
      const what = actual === undefined ? 'is missing' : 'was modified';
      report(relPath, {
        line: 1,
        snippet: `${relPath} ${what} (expected sha256 ${expected.slice(0, 12)}…${actual ? `, found ${actual.slice(0, 12)}…` : ''})`,
        evidence: `${relPath} ${what} after scaffolding`,
        fingerprintExtra: relPath,
      });
    }
  },
});

export const projectRules = [disallowedImport, protectedFileModified];
