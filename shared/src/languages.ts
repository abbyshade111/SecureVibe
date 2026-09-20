/**
 * Which languages SecureVibe's own code rules understand, and what that means for what it can say.
 *
 * Shared between the server and the web UI on purpose. The web side uses it to tell somebody what they are
 * going to get **before** they upload, from the folder they have just picked; the server uses it to work out
 * what was actually read. If those two disagreed, the page would promise something the report then withheld,
 * which is a worse failure than either one being wrong alone.
 *
 * See ADR-012. The boundary is settled: SecureVibe does not grow its own static rules for other languages.
 * Other languages are checked by the external scanners and the AI review, and are never scored.
 */

export interface LanguageDef {
  /** What a person calls it. */
  name: string;
  extensions: string[];
  /** True when SecureVibe's own rules parse it. False means it is read by the other tools and nothing else. */
  analysed: boolean;
}

export const LANGUAGES: LanguageDef[] = [
  { name: 'TypeScript', extensions: ['.ts', '.tsx'], analysed: true },
  { name: 'JavaScript', extensions: ['.js', '.jsx', '.mjs', '.cjs'], analysed: true },
  { name: 'EJS templates', extensions: ['.ejs'], analysed: true },
  { name: 'Python', extensions: ['.py'], analysed: false },
  { name: 'Ruby', extensions: ['.rb'], analysed: false },
  { name: 'Go', extensions: ['.go'], analysed: false },
  { name: 'Rust', extensions: ['.rs'], analysed: false },
  { name: 'Java', extensions: ['.java'], analysed: false },
  { name: 'Kotlin', extensions: ['.kt', '.kts'], analysed: false },
  { name: 'C#', extensions: ['.cs'], analysed: false },
  { name: 'PHP', extensions: ['.php'], analysed: false },
  { name: 'Swift', extensions: ['.swift'], analysed: false },
  { name: 'Shell scripts', extensions: ['.sh', '.bash', '.zsh'], analysed: false },
];

/**
 * Below this share of an app's code being readable by SecureVibe's own rules, no compliance score is reported.
 * It lives here rather than beside the report so that the promise made on the upload page and the answer given
 * in the report are decided by the same number. They were not, for about ten minutes, and the page cheerfully
 * offered a partial check on an app the report then refused to score.
 */
export const ASSESSABLE_SHARE = 0.5;

export interface LanguageCount {
  language: string;
  files: number;
  analysed: boolean;
}

export function extensionOf(relPath: string): string {
  const name = relPath.slice(relPath.lastIndexOf('/') + 1);
  const dot = name.lastIndexOf('.');
  return dot <= 0 ? '' : name.slice(dot).toLowerCase();
}

/** One row per language present, most files first. Files that are not code in any listed language are ignored. */
export function languageBreakdown(relPaths: string[]): LanguageCount[] {
  const counts = new Map<string, { files: number; analysed: boolean }>();
  for (const relPath of relPaths) {
    const ext = extensionOf(relPath);
    const lang = LANGUAGES.find((l) => l.extensions.includes(ext));
    if (!lang) continue;
    const entry = counts.get(lang.name) ?? { files: 0, analysed: lang.analysed };
    entry.files += 1;
    counts.set(lang.name, entry);
  }
  return [...counts.entries()]
    .map(([language, v]) => ({ language, files: v.files, analysed: v.analysed }))
    .sort((a, b) => b.files - a.files || a.language.localeCompare(b.language));
}

function list(names: string[]): string {
  if (names.length <= 1) return names[0] ?? '';
  return `${names.slice(0, -1).join(', ')} and ${names.at(-1)!}`;
}

/**
 * What SecureVibe will be able to say about this code, in the words it will say it in. Written for somebody
 * looking at a folder they are about to hand over, so it promises exactly what the report will deliver and
 * nothing more.
 */
export function whatWeCanSay(relPaths: string[]): { headline: string; detail: string } {
  const breakdown = languageBreakdown(relPaths);
  const analysed = breakdown.filter((l) => l.analysed);
  const unanalysed = breakdown.filter((l) => !l.analysed);
  const analysedFiles = analysed.reduce((n, l) => n + l.files, 0);
  const totalFiles = breakdown.reduce((n, l) => n + l.files, 0);

  const everythingElse =
    'Whatever it is written in, every file is searched for passwords and keys, checked for known-bad content by the virus scanner, checked for publicly known problems in the packages it uses, and read by the AI reviewer.';

  if (totalFiles === 0) {
    return {
      headline: 'No code was found in this folder.',
      detail: `SecureVibe could not see any files it recognises as code, so there may be nothing here to check — make sure you picked the folder that holds the app itself. ${everythingElse}`,
    };
  }
  if (unanalysed.length === 0) {
    return {
      headline: `This looks like ${list(analysed.map((l) => l.language))}, which SecureVibe checks in full.`,
      detail: `Its own security rules read all ${totalFiles} code files, and it will give this app a compliance score. ${everythingElse}`,
    };
  }
  // The same threshold the report uses, so the page cannot promise a score the run will refuse to give.
  if (analysedFiles / totalFiles < ASSESSABLE_SHARE) {
    const mostly = analysedFiles === 0 ? '' : `, apart from ${analysedFiles} file${analysedFiles === 1 ? '' : 's'}`;
    return {
      headline: `This looks like ${list(unanalysed.map((l) => l.language))}${mostly}, which SecureVibe does not read with its own rules.`,
      detail: `You will get a real security check and no compliance score: the report will say "not assessed" rather than giving this app a mark it has not earned. ${everythingElse}`,
    };
  }
  return {
    headline: `This is mostly ${list(analysed.map((l) => l.language))}, with ${totalFiles - analysedFiles} file${totalFiles - analysedFiles === 1 ? '' : 's'} in ${list(unanalysed.map((l) => l.language))}.`,
    detail: `The ${analysedFiles} SecureVibe reads will be checked in full and scored. The rest will not, and the report will say so rather than scoring them. ${everythingElse}`,
  };
}
