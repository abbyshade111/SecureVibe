/**
 * Architecture decision records in the compliance report: the design's ADRs (structured, from the design step)
 * and the starter application's own ADRs (docs/adr/*.md in the app folder), each with an anchor the rest of the
 * report links to. The app's files are shown as escaped text: they are generated from code and never trusted as HTML.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Adr } from '@shared/design.js';
import { escapeHtml } from './escape.js';
import { htmlList } from './html-table.js';
import { mdBullets } from './md.js';

export interface AppAdr {
  anchor: string;
  file: string;
  title: string;
  text: string;
}

export function adrAnchor(id: string): string {
  const slug = id.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  return slug.startsWith('adr-') ? slug : `adr-${slug}`;
}

/** The app's docs/adr/*.md files, in file-name order. */
export function readAppAdrs(appDir: string): AppAdr[] {
  const dir = join(appDir, 'docs', 'adr');
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.md'))
    .sort()
    .map((file) => {
      const text = readFileSync(join(dir, file), 'utf8');
      const title = /^#\s+(.+)$/m.exec(text)?.[1]?.trim() ?? file;
      return { anchor: `app-adr-${file.replace(/\.md$/, '').toLowerCase().replace(/[^a-z0-9]+/g, '-')}`, file, title, text };
    });
}

/** Markdown headings, paragraphs, bullets and `code`, rendered from escaped text only. */
export function safeMarkdownHtml(markdown: string): string {
  const inline = (s: string) => escapeHtml(s).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/\*([^*]+)\*/g, '<em>$1</em>');
  const out: string[] = [];
  let paragraph: string[] = [];
  let bullets: string[] = [];
  const flush = () => {
    if (paragraph.length) out.push(`<p>${inline(paragraph.join(' '))}</p>`);
    if (bullets.length) out.push(`<ul>${bullets.map((b) => `<li>${inline(b)}</li>`).join('')}</ul>`);
    paragraph = [];
    bullets = [];
  };
  for (const raw of markdown.split(/\r?\n/)) {
    const line = raw.trim();
    const heading = /^(#{1,6})\s+(.+)$/.exec(line);
    if (heading) {
      flush();
      // The file's own title is shown by the caller; deeper headings become h5 inside the entry.
      if (heading[1]!.length > 1) out.push(`<h5>${inline(heading[2]!)}</h5>`);
    } else if (/^[-*]\s+/.test(line)) {
      if (paragraph.length) flush();
      bullets.push(line.replace(/^[-*]\s+/, ''));
    } else if (line === '' || line === '---') {
      flush();
    } else {
      if (bullets.length) flush();
      paragraph.push(line);
    }
  }
  flush();
  return out.join('\n');
}

export function adrSectionHtml(adrs: Adr[], appAdrs: AppAdr[], sectionNumber: number): string {
  const designEntries = adrs.map(
    (a) => `<article class="adr" id="${adrAnchor(a.id)}">
<h3>${escapeHtml(a.id)}: ${escapeHtml(a.title)}</h3>
<p class="muted">Status: ${escapeHtml(a.status)} · ${escapeHtml(a.date)}</p>
<h4>Context</h4><p>${escapeHtml(a.context)}</p>
<h4>Decision</h4><p>${escapeHtml(a.decision)}</p>
${a.alternatives.length ? `<h4>Alternatives considered</h4>${htmlList(a.alternatives.map(escapeHtml))}` : ''}
<h4>Consequences</h4><p>${escapeHtml(a.consequences)}</p>
${a.relatedControls.length || a.relatedRequirements.length ? `<p class="muted">Related: ${escapeHtml([...a.relatedControls, ...a.relatedRequirements].join(', '))}</p>` : ''}
<p><a href="#design-summary">Back to the design summary</a></p>
</article>`,
  );
  const appEntries = appAdrs.map(
    (a) => `<article class="adr" id="${a.anchor}">
<h3>${escapeHtml(a.title)}</h3>
<p class="muted">From the app folder: <code>docs/adr/${escapeHtml(a.file)}</code></p>
${safeMarkdownHtml(a.text)}
</article>`,
  );
  return `<section id="adrs" class="chapter"><h2>${sectionNumber}. Architecture decision records</h2>
<p>Why the app is built the way it is. The first group was decided while designing your app; the second comes with the hardened starter application.</p>
<h3 class="adr-group">Decisions from your design</h3>
${designEntries.length ? designEntries.join('\n') : '<p class="muted">No design decisions were recorded.</p>'}
<h3 class="adr-group">Decisions built into the starter application</h3>
${appEntries.length ? appEntries.join('\n') : '<p class="muted">No starter-application decision records were found in the app folder.</p>'}
</section>`;
}

export function adrSectionMarkdown(adrs: Adr[], appAdrs: AppAdr[], sectionNumber: number): string[] {
  const md: string[] = ['', `## ${sectionNumber}. Architecture decision records`, '', '### Decisions from your design'];
  for (const a of adrs) {
    md.push(
      '',
      `<a id="${adrAnchor(a.id)}"></a>`,
      `#### ${a.id}: ${a.title}`,
      '',
      `Status: ${a.status} · ${a.date}`,
      '',
      `**Context.** ${a.context}`,
      '',
      `**Decision.** ${a.decision}`,
      ...(a.alternatives.length ? ['', '**Alternatives considered.**', '', mdBullets(a.alternatives)] : []),
      '',
      `**Consequences.** ${a.consequences}`,
      ...(a.relatedControls.length || a.relatedRequirements.length ? ['', `Related: ${[...a.relatedControls, ...a.relatedRequirements].join(', ')}`] : []),
    );
  }
  md.push('', '### Decisions built into the starter application');
  if (appAdrs.length === 0) md.push('', '_No starter-application decision records were found in the app folder._');
  for (const a of appAdrs) md.push('', `<a id="${a.anchor}"></a>`, `#### ${a.title}`, '', `From the app folder: \`docs/adr/${a.file}\``, '', a.text.replace(/^#\s+.+$/m, '').trim());
  return md;
}
