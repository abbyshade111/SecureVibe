/**
 * The container the app can be moved in (Dockerfile, compose.yaml).
 *
 * These are file checks, not a Docker run: they hold the promises the two files make, so nobody can quietly turn
 * them into something weaker. Two promises matter most. The image must never carry the owner's secrets or records,
 * and starting the container must not put the app in front of more people than running it directly does.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { templateRoot } from '../helpers/app.ts';

const dockerfile = readFileSync(join(templateRoot, 'Dockerfile'), 'utf8');
const dockerignore = readFileSync(join(templateRoot, '.dockerignore'), 'utf8');
const compose = readFileSync(join(templateRoot, 'compose.yaml'), 'utf8');
const workflow = readFileSync(join(templateRoot, '.github', 'workflows', 'security.yml'), 'utf8');

/**
 * One job's own lines, found by indentation. Reading the file as text keeps this test free of a YAML library:
 * the app ships no dependency it does not need to run.
 */
function job(name: string): string {
  const lines = workflow.split(/\r?\n/);
  const first = lines.findIndex((l) => l === `  ${name}:`);
  assert.ok(first >= 0, `the workflow has no job called ${name}`);
  const rest = lines.slice(first + 1);
  const next = rest.findIndex((l) => /^ {2}\S/.test(l));
  return (next === -1 ? rest : rest.slice(0, next)).join('\n');
}

/** Lines that are not comments, so a promise made only in a comment never counts as kept. */
function instructions(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#'));
}

describe('the container', () => {
  test('AC-01 the image keeps the owner\'s secrets and records out of it', () => {
    const ignored = instructions(dockerignore);
    for (const entry of ['.env', '.env.*', 'FIRST-LOGIN.txt', 'data', 'certs']) {
      assert.ok(ignored.includes(entry), `.dockerignore must exclude ${entry}, or an image could carry it`);
    }
    // The example file has no real values in it and is what "npm run setup" reads, so it is the one exception.
    assert.ok(ignored.includes('!.env.example'), '.env.example is needed inside the image');
    assert.ok(!/^COPY\s+\.env/m.test(dockerfile), 'the Dockerfile must never copy a settings file');
  });

  test('AC-01 the container is published to this computer only', () => {
    const ports = compose.match(/^\s*-\s*"([^"]+:)?\d+:\d+"/gm) ?? [];
    assert.ok(ports.length > 0, 'compose.yaml must publish a port');
    for (const line of ports) {
      assert.match(line, /"127\.0\.0\.1:/, `compose.yaml publishes ${line.trim()} to every address; it must bind 127.0.0.1`);
    }
  });

  test('AS-01 the app runs without privileges and cannot change its own code', () => {
    assert.match(dockerfile, /^USER node$/m, 'the image must run as the unprivileged "node" user, never as root');
    assert.match(dockerfile, /^ENV NODE_ENV=production$/m, 'the image must run in production mode');
    const composeLines = instructions(compose);
    assert.ok(composeLines.includes('read_only: true'), 'the container filesystem must be read-only apart from its data folder');
    assert.ok(composeLines.includes('- no-new-privileges:true'), 'the container must not be able to gain privileges');
    assert.ok(composeLines.includes('- ALL'), 'the container must drop every Linux capability');
    assert.ok(composeLines.some((l) => l.startsWith('- ./data:/app/data')), 'the data folder must live outside the container');
  });

  test('AS-07 packages are installed from the lockfile and may not run code of their own', () => {
    assert.match(dockerfile, /npm ci\b/, 'the image must install from package-lock.json (npm ci), not resolve versions afresh');
    assert.match(dockerfile, /--ignore-scripts/, 'no package may run its own scripts while the image is built');
    assert.match(dockerfile, /--omit=dev/, 'development-only packages do not belong in a running app');
  });
});

describe('the checks that keep running after the app is handed over', () => {
  test('MT-03 every change runs the security tests, the package check and the container scan', () => {
    const checks = job('checks');
    assert.match(checks, /npm ci --ignore-scripts/, 'packages must be installed from the lockfile with no package scripts');
    assert.match(checks, /run: npm test/, "the app's own security suite must run");
    assert.match(checks, /npm audit --audit-level=high/, 'the packages must be checked for known problems');
    assert.match(checks, /trivy-action/, 'the built container must be scanned');
    assert.match(checks, /exit-code: '1'/, 'the scan must fail the run when it finds something serious, not just report it');
    assert.match(workflow, /^ {2}schedule:$/m, 'the checks must also run on a schedule: packages go bad while an app sits still');
  });

  test('V15.1.2 a bill of materials is written for every build, in CycloneDX form', () => {
    assert.match(job('checks'), /npm sbom --sbom-format cyclonedx/, 'each run must write the list of everything inside the app');
    assert.match(job('checks'), /upload-artifact/, 'the bill of materials must be kept with the run');
    assert.match(job('publish'), /cosign attest .*--type cyclonedx/, 'a published image must carry its bill of materials');
  });

  test('V15.1.2 a published image is signed, and publishing stays off until it is turned on', () => {
    const publish = job('publish');
    assert.match(publish, /vars\.PUBLISH_IMAGE == 'true'/, 'publishing must be opt-in');
    assert.match(publish, /id-token: write/, 'keyless signing needs GitHub to vouch for the run');
    assert.match(publish, /cosign sign --yes/, 'a published image must be signed');
    assert.match(publish, /attest-build-provenance/, 'a published image must record how it was built');
    assert.match(publish, /provenance: true/, 'the image build must record its own provenance');
  });

  test('V15.1.1 every ready-made step is pinned to an exact fingerprint, not a version name', () => {
    const uses = [...workflow.matchAll(/uses: (\S+)/g)].map((m) => m[1]!);
    assert.ok(uses.length > 0, 'the workflow uses ready-made steps');
    for (const step of uses) {
      // A version name like @v4 can be moved to point at different code later; a 40-character fingerprint cannot.
      assert.match(step, /^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/, `${step} must be pinned to a commit fingerprint`);
    }
    // And each one says which release that fingerprint is, so a person can read the file.
    for (const line of workflow.split(/\r?\n/).filter((l) => l.includes('uses:'))) {
      assert.match(line, /# v?\d+\.\d+/, `${line.trim()} must name the release it pins`);
    }
  });

  test('MT-04 the workflow itself may not write to the repository', () => {
    // The top-level permissions, before any job asks for more.
    assert.match(workflow, /^permissions:\n {2}contents: read$/m, 'the workflow must start with read-only access');
    assert.doesNotMatch(job('checks'), /permissions:/, 'the checks job needs no extra permissions at all');
  });
});
