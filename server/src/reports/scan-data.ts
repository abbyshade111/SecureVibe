/**
 * The scan-data pack (`scan-data.zip`): everything the checks produced for one build, in machine-readable form.
 *
 * The reports answer "is it safe to use?" for a person. This pack answers "show me the raw output" for a security
 * reviewer or a tool: the findings as data, what each scanner actually reported, which tools ran and which did not,
 * and the standard formats (SARIF, CycloneDX) other tools already understand.
 *
 * Nothing here is new evidence — it is the same run record the reports are written from, unpacked so it can be read
 * by a program. Files that hold secrets are never included.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding } from '@shared/findings.js';
import type { PipelineRun, StageId } from '@shared/pipeline.js';

/** A file written into the zip from a string. */
export interface ScanDataEntry {
  name: string;
  content: string;
}

/** A file copied into the zip from disk. */
export interface ScanDataFile {
  name: string;
  absolutePath: string;
}

export interface ScanDataBundle {
  entries: ScanDataEntry[];
  files: ScanDataFile[];
}

export interface ScanDataInput {
  project: { id: string; name: string };
  run: PipelineRun;
  /** The findings with the owner's decisions applied, as the results page shows them. */
  findings: Finding[];
  /** <project>/reports/<runId>, where the machine-readable report files live. */
  reportsDir: string;
  /** <project>/pipeline/<runId>, where a stage may have written raw output of its own. */
  runDir: string;
  securevibeVersion: string;
}

/** The stages whose structured output is worth keeping as raw scanner data. */
const SCAN_STAGES: { id: StageId; file: string; what: string }[] = [
  { id: 'typecheck', file: 'typecheck.json', what: 'whether the code compiles cleanly, with the compiler output' },
  { id: 'lint', file: 'lint.json', what: 'the code-quality and security linters' },
  { id: 'unit-tests', file: 'unit-tests.json', what: 'every test that ran, and whether it passed' },
  { id: 'sast', file: 'sast.json', what: 'static analysis: the rules that ran and what they matched' },
  { id: 'secrets', file: 'secrets.json', what: 'the search for passwords and keys written into the code' },
  { id: 'deps', file: 'deps.json', what: 'the package check: lockfile, advisories, licences, bill of materials' },
  { id: 'config', file: 'config.json', what: 'the configuration checks' },
  { id: 'dast', file: 'dast.json', what: 'the running app probes: every request made and what came back' },
  { id: 'external', file: 'external.json', what: 'extra scanners found on this computer (semgrep, trivy, …)' },
  { id: 'ai-review', file: 'ai-review.json', what: 'the AI review pass: how many assessments, how many citations did not check out' },
  { id: 'fix', file: 'fix.json', what: 'which findings the fix rounds attempted and which they resolved' },
];

/** The report files that are already machine-readable; copied in so the pack stands on its own. */
const REPORT_FILES = [
  { name: 'security-report.json', what: 'every finding with its severity, location, mappings and fix advice' },
  { name: 'compliance-report.json', what: 'every requirement, its status and the evidence behind it' },
  { name: 'findings.sarif', what: 'the findings in SARIF 2.1.0, which editors and CI tools read directly' },
  { name: 'sbom.cdx.json', what: 'the bill of materials (CycloneDX): every package and its version' },
  { name: 'provenance.json', what: 'what produced this build: versions, hashes, models, approvals' },
];

/** One line of the README's contents list, with the file names in a column of their own. */
function indexLine(name: string, what: string): string {
  return `  ${name.padEnd(26)}${what}`;
}

function json(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

/** A file name that is safe inside a zip and on every file system. */
export function scanDataFileName(projectName: string, runId: string): string {
  const safe = projectName.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'app';
  return `${safe}-scan-data-${runId}.zip`;
}

function readme(input: ScanDataInput, included: string[]): string {
  const { project, run, securevibeVersion } = input;
  const lines = [
    'SCAN DATA',
    '',
    `App: ${project.name}`,
    `Build: ${run.id} (${run.mode}), started ${run.startedAt}${run.finishedAt ? `, finished ${run.finishedAt}` : ''}, ${run.status}`,
    `Produced by SecureVibe ${securevibeVersion}`,
    '',
    'WHAT THIS IS',
    '',
    'This is the raw output of every check SecureVibe ran on this build, in formats a program can read.',
    'It is meant for a security reviewer or a tool. If you want to know whether the app is safe to use,',
    'read the reports instead — they say the same things in plain language.',
    '',
    'Nothing in here is extra evidence. It is the same record the reports were written from, unpacked.',
    'Files that hold passwords or keys are never included.',
    '',
    'WHAT IS IN HERE',
    '',
    ...included,
    '',
    'HOW TO READ IT',
    '',
    'findings.json is the list to start from. Each finding says which check reported it (source), how serious it is',
    '(severity is the adjusted severity, severityBase is what the tool said before the deployment context was taken',
    'into account), how sure the check is (confidence), where it is (location.file and location.line, relative to the',
    'app folder), and what the owner decided about it (status).',
    '',
    'tool-coverage.json says which tools actually ran. A tool that is not installed on this computer is listed with',
    'the reason it did not run, so nothing here implies coverage the build did not have.',
    '',
    'A WORD ON EVIDENCE',
    '',
    'SecureVibe does not treat an AI review as proof. A requirement the AI looked at but no test or scanner confirmed',
    'is recorded as "ai-assessed", not "pass", and a requirement nobody checked is recorded as "not-verified".',
    'compliance-report.json carries the status and the evidence for each requirement, so you can check this yourself.',
  ];
  return `${lines.join('\n')}\n`;
}

/** Everything that goes into `scan-data.zip` for one run. */
export function buildScanData(input: ScanDataInput): ScanDataBundle {
  const { run, findings, reportsDir, runDir } = input;
  const entries: ScanDataEntry[] = [];
  const files: ScanDataFile[] = [];
  const included: string[] = [];

  entries.push({ name: 'findings.json', content: json({ runId: run.id, generatedAt: new Date().toISOString(), count: findings.length, findings }) });
  included.push(indexLine('findings.json', 'every finding, with the decisions the owner has made since the build'));

  entries.push({ name: 'tool-coverage.json', content: json({ runId: run.id, coverage: run.coverage }) });
  included.push(indexLine('tool-coverage.json', 'which checks ran, their versions, and why any of them did not run'));

  // The run record itself: stage by stage, with timings, statuses and the reason for anything skipped.
  entries.push({
    name: 'run.json',
    content: json({
      id: run.id,
      projectId: run.projectId,
      mode: run.mode,
      status: run.status,
      startedAt: run.startedAt,
      ...(run.finishedAt ? { finishedAt: run.finishedAt } : {}),
      incomplete: run.incomplete,
      fixRounds: run.fixRounds,
      stages: run.stages,
      coverage: run.coverage,
      ...(run.planCoverage ? { planCoverage: run.planCoverage } : {}),
      ...(run.failure ? { failure: run.failure } : {}),
    }),
  });
  included.push(indexLine('run.json', 'the build itself: every stage, how long it took and how it ended'));

  for (const stage of SCAN_STAGES) {
    const result = run.stages.find((s) => s.id === stage.id);
    if (!result) continue;
    entries.push({
      name: `scanners/${stage.file}`,
      content: json({
        stage: result.id,
        status: result.status,
        summary: result.summary,
        ...(result.skippedReason ? { skippedReason: result.skippedReason } : {}),
        ...(result.startedAt ? { startedAt: result.startedAt } : {}),
        ...(result.finishedAt ? { finishedAt: result.finishedAt } : {}),
        ...(result.durationMs !== undefined ? { durationMs: result.durationMs } : {}),
        round: result.round,
        output: result.details ?? null,
      }),
    });
    included.push(indexLine(`scanners/${stage.file}`, stage.what));
  }

  for (const report of REPORT_FILES) {
    const absolute = join(reportsDir, report.name);
    if (!existsSync(absolute)) continue;
    files.push({ name: report.name, absolutePath: absolute });
    included.push(indexLine(report.name, report.what));
  }

  // The DAST stage saves its probe table next to the run; it is the fullest record of what was sent and received.
  const probes = join(runDir, 'dast', 'probes.json');
  if (existsSync(probes)) {
    files.push({ name: 'dast/probes.json', absolutePath: probes });
    included.push(indexLine('dast/probes.json', 'every probe sent to the running app, and what it answered'));
  }

  entries.unshift({ name: 'README.txt', content: readme(input, included) });
  return { entries, files };
}
