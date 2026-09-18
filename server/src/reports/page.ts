/**
 * The self-contained HTML shell shared by overview.html, compliance-report.html, security-report.html and
 * going-online.html: inline CSS only, a table of contents, collapsible `<details>` chapters, a JS-free filter
 * toggle (CSS-only, via a leading checkbox and the `~` sibling combinator) and a print stylesheet that expands
 * every collapsed section. No script tags, no external resources.
 */
import { escapeHtml } from './escape.js';

export interface TocEntry {
  id: string;
  label: string;
}

export interface Banner {
  kind: 'ai-disclaimer' | 'preview' | 'note';
  text: string;
}

export interface PageOptions {
  title: string;
  subtitle?: string;
  generatedAt: string;
  banners?: Banner[];
  toc: TocEntry[];
  bodyHtml: string;
  glossaryHtml?: string;
  filterLabel?: string;
  footerHtml?: string;
}

/** The report stylesheet; also applied to older saved reports when SecureVibe shows them. */
export const REPORT_CSS = `
:root {
  --bg: #ffffff; --fg: #1a1d21; --muted: #5b6470; --border: #d8dee4; --panel: #f6f8fa;
  --accent: #0b5fff; --good: #0a7a3d; --warn: #8a5a00; --bad: #b3261e; --link: #0b57d0;
  font-size: 16px;
}
a { color: var(--link); }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; }
.skip-link { position: absolute; left: -999px; top: 0; }
.skip-link:focus { left: 8px; top: 8px; background: var(--accent); color: #fff; padding: 8px 12px; border-radius: 6px; z-index: 10; }
.page { max-width: 980px; margin: 0 auto; padding: 24px 20px 80px; }
header.report-header { border-bottom: 3px solid var(--border); padding-bottom: 16px; margin-bottom: 20px; }
header.report-header h1 { margin: 0 0 4px; font-size: 1.7rem; }
header.report-header p.subtitle { margin: 0; color: var(--muted); }
header.report-header p.generated { margin: 4px 0 0; color: var(--muted); font-size: 0.9rem; }
.banner { border-radius: 8px; padding: 12px 16px; margin: 0 0 14px; font-weight: 600; }
.banner-ai-disclaimer { background: #fff4e5; border: 1px solid #e0a300; color: #6b4a00; }
.banner-preview { background: #eef2ff; border: 1px solid #6a7bd6; color: #2c3a8f; }
.banner-note { background: var(--panel); border: 1px solid var(--border); color: var(--fg); font-weight: 400; }
nav.toc { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; margin-bottom: 22px; }
nav.toc h2 { margin: 0 0 8px; font-size: 1rem; }
nav.toc ol { margin: 0; padding-left: 20px; }
nav.toc li { margin: 2px 0; }
.filter-toggle { margin: 0 6px 0 2px; }
.filter-label { display: inline-block; margin: 0 0 18px; padding: 10px 14px; border: 1px dashed var(--border); border-radius: 8px; background: var(--panel); font-size: 0.92rem; cursor: pointer; }
section.chapter { margin-bottom: 22px; }
section.chapter > h2 { border-bottom: 2px solid var(--border); padding-bottom: 6px; }
details { border: 1px solid var(--border); border-radius: 8px; margin: 10px 0; padding: 4px 14px; background: #fff; }
details > summary { cursor: pointer; font-weight: 600; padding: 8px 0; }
details[open] > summary { border-bottom: 1px solid var(--border); margin-bottom: 8px; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 0.92rem; }
th, td { border: 1px solid var(--border); padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: var(--panel); }
.badge { display: inline-block; white-space: nowrap; padding: 1px 8px; border-radius: 999px; border: 1px solid var(--border); font-size: 0.85rem; }
.status-pass, .rating-good, .sbd-yes { background: #e7f6ec; border-color: var(--good); }
.status-fail, .rating-at-risk, .sbd-no { background: #fbe9e7; border-color: var(--bad); }
.status-partial, .rating-needs-attention, .status-not-verified { background: #fff6df; border-color: var(--warn); }
.status-ai-assessed, .status-documented, .status-attested { background: #eef2ff; border-color: #6a7bd6; }
.status-not-applicable, .status-out-of-level, .sbd-n-a { background: var(--panel); }
.priority-P1 { background: #fbe9e7; border-color: var(--bad); }
.priority-P2 { background: #fff1e0; border-color: #c96a00; }
.priority-P3 { background: #fff6df; border-color: var(--warn); }
.priority-P4 { background: var(--panel); }
.critical-flag { color: var(--bad); font-weight: 700; }
.muted { color: var(--muted); }
.scorecard { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 10px 0 18px; }
.scorecard .cell { border: 1px solid var(--border); border-radius: 8px; padding: 10px; text-align: center; }
.scorecard .cell .n { font-size: 1.4rem; font-weight: 700; display: block; }
.finding-card { border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; margin: 12px 0; }
.finding-card h4 { margin: 0 0 6px; }
.finding-card dl { display: grid; grid-template-columns: 160px 1fr; gap: 4px 10px; margin: 8px 0; }
.finding-card dt { font-weight: 600; color: var(--muted); }
.finding-card dd { margin: 0; }
.adr { border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; margin: 12px 0; background: var(--panel); scroll-margin-top: 12px; }
.adr h3 { margin: 0 0 4px; }
.adr h4, .adr h5 { margin: 12px 0 4px; }
h3.adr-group { margin-top: 22px; }
code, pre { font-family: SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.88rem; }
pre { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 10px; overflow-x: auto; white-space: pre-wrap; }
footer.report-footer { margin-top: 40px; padding-top: 14px; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.85rem; }
.hideable.default-hidden { display: none; }
#filter-all:checked ~ main tr.hideable.default-hidden { display: table-row; }
#filter-all:checked ~ main li.hideable.default-hidden { display: list-item; }
#filter-all:checked ~ main .hideable.default-hidden:not(tr):not(li) { display: block; }
@media screen and (prefers-color-scheme: dark) {
  :root { --bg: #0f1115; --fg: #e7e9ec; --muted: #a2acb8; --border: #30353d; --panel: #171a20; --link: #8ab4f8; --good: #5cc98a; --warn: #e0b04d; --bad: #f28b82; }
  details, .finding-card { background: #12151a; }
  th { background: #1b1f26; }
  .status-pass, .rating-good, .sbd-yes { background: #12301f; }
  .status-fail, .rating-at-risk, .sbd-no, .priority-P1 { background: #3a1714; }
  .status-partial, .rating-needs-attention, .status-not-verified, .priority-P3 { background: #33280f; }
  .priority-P2 { background: #3a2410; }
  .status-ai-assessed, .status-documented, .status-attested { background: #1c2340; }
  .banner-ai-disclaimer { background: #33280f; border-color: #e0a300; color: #f5d78e; }
  .banner-preview { background: #1c2340; border-color: #6a7bd6; color: #c3cbf5; }
}
@media print {
  /* Saved as PDF: always light, everything expanded, no on-screen controls. */
  :root { --bg: #ffffff; --fg: #1a1d21; --muted: #4a525c; --border: #c9d1d9; --panel: #f6f8fa; --link: #0b57d0; }
  body { font-size: 11pt; }
  .page { max-width: none; padding: 0; }
  .filter-bar, .skip-link, .filter-toggle, .filter-label { display: none; }
  .adr, .finding-card, tr { break-inside: avoid; }
  section.chapter > h2 { break-after: avoid; }
  a[href^="#"]::after { content: ""; }
  details { border: none; padding: 0; }
  details > summary { display: none; }
  details > *:not(summary) { display: block !important; }
}
@media (max-width: 640px) {
  .scorecard { grid-template-columns: repeat(2, 1fr); }
  .finding-card dl { grid-template-columns: 1fr; }
}
`;

function bannerHtml(b: Banner): string {
  return `<div class="banner banner-${b.kind}" role="note">${escapeHtml(b.text)}</div>`;
}

function tocHtml(toc: TocEntry[]): string {
  if (toc.length === 0) return '';
  const items = toc.map((t) => `<li><a href="#${escapeHtml(t.id)}">${escapeHtml(t.label)}</a></li>`).join('\n');
  return `<nav class="toc" aria-label="Table of contents"><h2>Contents</h2><ol>${items}</ol></nav>`;
}

export function renderPage(opts: PageOptions): string {
  const banners = (opts.banners ?? []).map(bannerHtml).join('\n');
  // The checkbox must be a direct sibling of <main> (both children of .page), in that order, for the
  // CSS-only "~" sibling combinator below to reveal .hideable.default-hidden rows without any script.
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${escapeHtml(opts.title)}</title>
<style>${REPORT_CSS}</style>
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
<div class="page">
<header class="report-header">
  <h1>${escapeHtml(opts.title)}</h1>
  ${opts.subtitle ? `<p class="subtitle">${escapeHtml(opts.subtitle)}</p>` : ''}
  <p class="generated">Generated by SecureVibe on ${escapeHtml(opts.generatedAt.slice(0, 10))}. Automated and AI-assisted assessment — not a certification.</p>
</header>
${banners}
<input type="checkbox" id="filter-all" class="filter-toggle" />
<label for="filter-all" class="filter-label">${escapeHtml(opts.filterLabel ?? 'Show everything, including items not applicable to this app')}</label>
${tocHtml(opts.toc)}
<main id="main">
${opts.bodyHtml}
</main>
${opts.glossaryHtml ?? ''}
<footer class="report-footer">
  ${opts.footerHtml ?? 'SecureVibe — local-first, AI-assisted secure app builder.'}
</footer>
</div>
</body>
</html>`;
}
