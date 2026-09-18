/**
 * going-online.md + .html: shown when the audience is customers/public or the deployment target is
 * internet-later (CONTRACTS §13.12). A plain checklist of what changes before this app leaves this computer.
 */
import { escapeHtml } from './escape.js';
import { htmlList } from './html-table.js';
import { mdBullets } from './md.js';
import { glossaryHtml, glossaryMarkdown } from './glossary.js';
import { renderPage, type TocEntry } from './page.js';
import type { ReportModel } from './types.js';

/** Whether the going-online checklist should be produced at all for this build. */
export function needsGoingOnline(input: ReportModel): boolean {
  const audience = input.profile?.users.audience;
  const target = input.profile?.deployment.target;
  return audience === 'customers' || audience === 'public' || target === 'internet-later';
}

interface ChecklistItem {
  id: string;
  text: string;
  who: string;
  dueBy?: string;
}

function buildChecklist(input: ReportModel): ChecklistItem[] {
  const items: ChecklistItem[] = [];
  for (const e of input.compliance.sbd.entries) {
    for (const a of e.actions) {
      if (!/internet|online|deploy|network|expos/i.test(`${a.dueBy ?? ''} ${a.text}`)) continue;
      items.push({ id: e.id, text: a.text, who: a.owner, ...(a.dueBy ? { dueBy: a.dueBy } : {}) });
    }
  }
  // De-duplicate identical actions referenced by several controls.
  const seen = new Set<string>();
  return items.filter((i) => {
    const key = i.text;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function renderGoingOnline(input: ReportModel): { md: string; html: string } {
  const items = buildChecklist(input);
  const appName = input.profile?.app.name ?? 'Your app';

  const md: string[] = [
    `# Going online safely — ${appName}`,
    '',
    "This app currently runs on your own computer. Before you let customers, the public, or anyone outside your team reach it over a network, work through this list. Nothing here happens automatically.",
    '',
    '## Checklist',
    '',
    mdBullets(items.map((i) => `\`[ ]\` **${i.id}** — ${i.text} (who: ${i.who}${i.dueBy ? `, due: ${i.dueBy}` : ''})`)),
    '',
    '## Deployment-time view of the Secure by Design checklist',
    '',
    mdBullets(input.compliance.sbd.deploymentTime.filter((d) => d.status === 'no' || d.status === 'deferred').map((d) => `**${d.id}**: ${d.status} — ${d.note}`)),
    '',
    glossaryMarkdown(input.knowledge.glossary),
  ];

  const toc: TocEntry[] = [
    { id: 'checklist', label: 'Checklist' },
    { id: 'deployment-time', label: 'Deployment-time view' },
  ];
  const body = [
    `<section id="checklist" class="chapter"><h2>Checklist</h2>${htmlList(
      items.map((i) => `<strong>${escapeHtml(i.id)}</strong> — ${escapeHtml(i.text)} <span class="muted">(who: ${escapeHtml(i.who)}${i.dueBy ? `, due: ${escapeHtml(i.dueBy)}` : ''})</span>`),
    )}</section>`,
    `<section id="deployment-time" class="chapter"><h2>Deployment-time view of the Secure by Design checklist</h2>${htmlList(
      input.compliance.sbd.deploymentTime.filter((d) => d.status === 'no' || d.status === 'deferred').map((d) => `<strong>${escapeHtml(d.id)}</strong>: ${escapeHtml(d.status)} — ${escapeHtml(d.note)}`),
    )}</section>`,
  ].join('\n');

  const html = renderPage({
    title: `Going online safely — ${appName}`,
    subtitle: 'What to do before this app is reachable beyond this computer',
    generatedAt: input.compliance.generatedAt,
    toc,
    bodyHtml: body,
    glossaryHtml: glossaryHtml(input.knowledge.glossary),
  });

  return { md: md.join('\n'), html };
}
