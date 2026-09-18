/**
 * Builds the text handed to the generation agent: the deterministic brief the design engine already wrote
 * (`design.buildSpec.brief` — purpose, entities, roles, security contract) plus the template's own conventions
 * (from `securevibe.manifest.json`), so the model sees both "what to build" and "how this codebase is shaped".
 */
import type { DesignArtifacts } from '@shared/design.js';
import type { TemplateManifest } from '@shared/knowledge.js';
import type { BuildPlan } from '@shared/project.js';

export function buildGenerationBrief(design: DesignArtifacts, manifest: TemplateManifest, plan?: BuildPlan): string {
  const parts = [design.buildSpec.brief];
  const wanted = plan?.features.filter((f) => f.wanted) ?? [];
  if (plan && wanted.length > 0) {
    parts.push(
      [
        '',
        '## The plan the owner approved — build exactly these features, in this order, and nothing else',
        ...wanted.flatMap((f, i) => [
          `${i + 1}. ${f.title} (${f.id}): ${f.whatItDoes}`,
          ...(f.pages.length ? [`   Pages: ${f.pages.join(', ')}`] : []),
          ...(f.records.length ? [`   Record types: ${f.records.join(', ')}`] : []),
          ...(f.tests.length ? [`   Tests to write: ${f.tests.join('; ')}`] : []),
        ]),
        '',
        'Use the page paths, record names and test names exactly as written: they are what the build is checked',
        'against afterwards. Finish one feature, run the checks, then start the next. If the budget runs short,',
        'finish the features you started rather than beginning another; say in your final summary which ones you',
        'did not get to.',
      ].join('\n'),
    );
  }
  const leftOut = plan?.features.filter((f) => !f.wanted) ?? [];
  if (leftOut.length > 0) parts.push(['', '## Left out by the owner — do not build these', ...leftOut.map((f) => `- ${f.title}`)].join('\n'));
  if (manifest.conventions.length > 0) {
    parts.push(['', '## Template conventions you must follow', ...manifest.conventions.map((c) => `- ${c}`)].join('\n'));
  }
  return parts.join('\n');
}

/** Same idea for a fix round: the brief plus which findings need to be addressed, in the model's own words. */
export function buildFixBrief(design: DesignArtifacts, manifest: TemplateManifest, round: number): string {
  return [
    buildGenerationBrief(design, manifest),
    '',
    `## This is fix round ${round}`,
    'Fix only the findings you were given. Do not rewrite unrelated code, and do not touch any protected path.',
  ].join('\n');
}
