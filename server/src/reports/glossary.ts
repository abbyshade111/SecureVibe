/** The glossary section appended to every HTML report, built from data/knowledge/glossary.json. */
import { escapeHtml } from './escape.js';
import { mdBullets } from './md.js';

export interface GlossaryLike {
  term: string;
  plain: string;
  seeAlso?: string[];
}

export function glossaryHtml(entries: GlossaryLike[]): string {
  if (entries.length === 0) return '';
  const sorted = [...entries].sort((a, b) => a.term.localeCompare(b.term));
  const rows = sorted
    .map(
      (e) =>
        `<dt id="term-${escapeHtml(e.term.toLowerCase().replace(/[^a-z0-9]+/g, '-'))}">${escapeHtml(e.term)}</dt><dd>${escapeHtml(e.plain)}${
          e.seeAlso && e.seeAlso.length ? ` <span class="muted">See also: ${escapeHtml(e.seeAlso.join(', '))}</span>` : ''
        }</dd>`,
    )
    .join('\n');
  return `<section id="glossary" class="chapter"><h2>Glossary</h2><dl>${rows}</dl></section>`;
}

export function glossaryMarkdown(entries: GlossaryLike[]): string {
  if (entries.length === 0) return '';
  const sorted = [...entries].sort((a, b) => a.term.localeCompare(b.term));
  return ['## Glossary', '', mdBullets(sorted.map((e) => `**${e.term}** — ${e.plain}`))].join('\n');
}
