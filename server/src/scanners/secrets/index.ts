/**
 * The secrets scanner (CONTRACTS §4): regex + entropy rules over every text file in the app, plus one
 * tree-level check for a `.env` sitting inside a real git repository. `.env` itself is exempt from the
 * credential-pattern rules — it is expected to hold real, freshly generated secrets — but is still
 * covered by `secrets.env-file-committed`.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Evidence } from '@shared/compliance.js';
import type { Finding } from '@shared/findings.js';
import { buildEvidence, buildFinding, countBySeverityText, statusFromFindings } from '../sast/findings.js';
import { listAppFiles, originFor, readTextFile } from '../sast/files.js';
import type { ScanContext, ScanResult, Scanner } from '../types.js';
import { contentRules, envFileCommittedMeta, type SecretMatch, type SecretRuleDef } from './rules.js';

export const SECRETS_TOOL = { name: 'securevibe-secrets', version: '1.0.0' };

const IMAGE_EXT = /\.(png|jpe?g|gif|svg|ico|webp|bmp|avif|tiff?)$/i;
const LOCK_FILE = /(^|\/)(package-lock\.json|[^/]+\.lock)$/i;

function isEnvFile(relPath: string): boolean {
  const base = relPath.slice(relPath.lastIndexOf('/') + 1);
  return /^\.env(\.[^.]+)?$/.test(base) && !base.endsWith('.example');
}

function positionAt(text: string, index: number): { line: number; column: number } {
  let line = 1;
  let column = 1;
  const bound = Math.min(index, text.length);
  for (let i = 0; i < bound; i++) {
    if (text.charCodeAt(i) === 10) {
      line += 1;
      column = 1;
    } else {
      column += 1;
    }
  }
  return { line, column };
}

/** Shows the first 4 and last 2 characters of a matched secret so evidence stays readable without leaking it. */
export function redact(value: string): string {
  const v = value.trim();
  if (v.length <= 6) return '*'.repeat(Math.max(v.length, 3));
  return `${v.slice(0, 4)}${'*'.repeat(Math.min(12, v.length - 6))}${v.slice(-2)}`;
}

function lineSnippet(text: string, line: number): string {
  return (text.split('\n')[line - 1] ?? '').trim();
}

function findingsForFile(ctx: ScanContext, relPath: string, text: string): Finding[] {
  const findings: Finding[] = [];
  const envFile = isEnvFile(relPath);
  const origin = originFor(ctx, relPath, text);
  for (const rule of contentRules) {
    if (envFile && !rule.scanEnvFiles) continue;
    let matches: SecretMatch[];
    try {
      matches = rule.scan(text);
    } catch {
      continue;
    }
    for (const m of matches) {
      const { line, column } = positionAt(text, m.index);
      findings.push(
        buildFinding(ctx, {
          source: 'secrets',
          rule: rule.meta,
          file: relPath,
          line,
          column,
          snippet: redact(m.value),
          evidence: `${rule.meta.title} in ${relPath} (line ${line}): ${redact(m.value)}`,
          introducedBy: origin,
          tool: SECRETS_TOOL,
          fingerprintExtra: m.fingerprintExtra ?? `${line}:${column}`,
        }),
      );
    }
  }
  return findings;
}

/** `.env` next to an initialised git repository, not excluded by .gitignore: a real risk of it being committed. */
function envFileCommittedFindings(ctx: ScanContext, envFiles: string[]): Finding[] {
  if (!existsSync(join(ctx.appDir, '.git'))) return [];
  const gitignore = readTextFile(join(ctx.appDir, '.gitignore')) ?? '';
  const lines = gitignore
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  const covered = (relPath: string): boolean => {
    const base = relPath.slice(relPath.lastIndexOf('/') + 1);
    return lines.some((l) => l === base || l === `/${base}` || l === '.env*' || l === '.env.*' || (l.startsWith('.env') && base.startsWith(l.replace(/\*$/, ''))));
  };
  const findings: Finding[] = [];
  for (const relPath of envFiles) {
    if (covered(relPath)) continue;
    findings.push(
      buildFinding(ctx, {
        source: 'secrets',
        rule: envFileCommittedMeta,
        file: relPath,
        line: 1,
        snippet: relPath,
        evidence: `${relPath} exists next to a .git folder and .gitignore does not exclude it.`,
        introducedBy: originFor(ctx, relPath),
        tool: SECRETS_TOOL,
      }),
    );
  }
  return findings;
}

export const runSecrets: Scanner = async (ctx) => {
  ctx.log('Looking for leaked secrets: scanning files for keys, passwords and private keys…');
  const files = listAppFiles(ctx.appDir, ctx.ignore).filter((f) => !IMAGE_EXT.test(f.relPath) && !LOCK_FILE.test(f.relPath));

  const findings: Finding[] = [];
  const envFiles: string[] = [];
  let scanned = 0;

  for (const file of files) {
    if (ctx.abort.aborted) break;
    const text = readTextFile(file.absPath);
    if (text === undefined) continue;
    scanned += 1;
    if (isEnvFile(file.relPath)) envFiles.push(file.relPath);
    findings.push(...findingsForFile(ctx, file.relPath, text));
  }
  findings.push(...envFileCommittedFindings(ctx, envFiles));

  if (ctx.abort.aborted) {
    return {
      findings,
      evidence: [],
      coverage: { tool: SECRETS_TOOL.name, ran: false, version: SECRETS_TOOL.version, reason: 'The run was cancelled before the secrets scan finished.' },
      status: 'skipped',
      summary: 'The secrets scan was cancelled before it finished.',
    };
  }

  const evidence: Evidence[] = [
    buildEvidence({
      type: 'scanner',
      tier: 'medium',
      ref: 'secrets:no-leaked-credentials',
      summary: findings.length === 0 ? `No leaked credentials were found in ${scanned} files.` : `${findings.length} possible leaked credential${findings.length === 1 ? '' : 's'} found.`,
      passed: findings.length === 0,
      tool: SECRETS_TOOL.name,
      toolVersion: SECRETS_TOOL.version,
      runId: ctx.runId,
      capturedAt: new Date().toISOString(),
      producedBy: 'rules',
    }),
  ];

  const status = statusFromFindings(findings);
  const counts = countBySeverityText(findings);
  const summary =
    findings.length === 0
      ? `The secrets scan read ${scanned} files and found nothing that looks like a leaked credential.`
      : `The secrets scan read ${scanned} files and found ${findings.length} possible leaked credential${findings.length === 1 ? '' : 's'} (${counts}).`;
  ctx.log(summary);

  const result: ScanResult = {
    findings,
    evidence,
    coverage: {
      tool: SECRETS_TOOL.name,
      ran: true,
      version: SECRETS_TOOL.version,
      covers: 'Regex patterns for known API key/token formats plus a Shannon-entropy check for other secret-like values, over every text file except node_modules, data, dist and lockfiles.',
    },
    details: { filesScanned: scanned, byRule: byRuleCounts(findings) },
    status,
    summary,
  };
  return result;
};

function byRuleCounts(findings: Finding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) out[f.ruleId] = (out[f.ruleId] ?? 0) + 1;
  return out;
}
