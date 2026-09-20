/**
 * Which package ecosystems an application actually uses, so SecureVibe stops asking npm questions of apps that
 * have no npm (ADR-012).
 *
 * The Flask app that prompted this was told `deps.lockfile-missing` — meaning no `package-lock.json` — and was
 * marked down for not setting `ignore-scripts=true` in an `.npmrc` it has no reason to own. Those are not
 * coverage gaps, which are honest and visible; they are **wrong statements in a report**, and an owner acting
 * on them would add npm configuration to a Python application.
 *
 * A check that does not apply is not a check that failed. That is the same distinction as a scan that did not
 * run not being a clean result, and a requirement that was not assessed not being a failed one — the third face
 * of the rule this project keeps rediscovering.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';

export interface Ecosystem {
  /** What a person calls it. */
  name: string;
  /** The file whose presence says this ecosystem is in use. */
  manifest: string;
  /**
   * Files that pin exact versions. An ecosystem in use with none of these present means nobody can say what is
   * actually installed — worth reporting in its own right, in any language.
   */
  lockfiles: string[];
}

export const ECOSYSTEMS: Ecosystem[] = [
  { name: 'npm', manifest: 'package.json', lockfiles: ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'] },
  { name: 'Python', manifest: 'requirements.txt', lockfiles: ['poetry.lock', 'Pipfile.lock', 'requirements.lock'] },
  { name: 'Python', manifest: 'pyproject.toml', lockfiles: ['poetry.lock', 'pdm.lock', 'uv.lock'] },
  { name: 'Go', manifest: 'go.mod', lockfiles: ['go.sum'] },
  { name: 'Rust', manifest: 'Cargo.toml', lockfiles: ['Cargo.lock'] },
  { name: 'Ruby', manifest: 'Gemfile', lockfiles: ['Gemfile.lock'] },
  { name: 'PHP', manifest: 'composer.json', lockfiles: ['composer.lock'] },
  { name: 'Java (Maven)', manifest: 'pom.xml', lockfiles: [] },
  { name: 'Java (Gradle)', manifest: 'build.gradle', lockfiles: ['gradle.lockfile'] },
];

export interface DetectedEcosystem {
  name: string;
  manifest: string;
  /** The lockfile found, when one was. */
  lockfile?: string;
}

/** Every ecosystem whose manifest is in the app folder, in the order listed above. */
export function detectEcosystems(appDir: string): DetectedEcosystem[] {
  const found: DetectedEcosystem[] = [];
  for (const eco of ECOSYSTEMS) {
    if (!existsSync(join(appDir, eco.manifest))) continue;
    const lockfile = eco.lockfiles.find((f) => existsSync(join(appDir, f)));
    found.push({ name: eco.name, manifest: eco.manifest, ...(lockfile ? { lockfile } : {}) });
  }
  return found;
}

/**
 * Whether this app uses npm at all. The presence of `package.json` is the signal, not the absence of anything
 * else: an app can be both (a Python service with a JavaScript front end) and both sets of checks should run.
 */
export function usesNpm(appDir: string): boolean {
  return existsSync(join(appDir, 'package.json'));
}

/** Ecosystems in use that pin nothing, so what is installed cannot be known. Plain names, for a finding. */
export function unpinnedEcosystems(appDir: string): DetectedEcosystem[] {
  return detectEcosystems(appDir).filter((e) => e.lockfile === undefined);
}
