/**
 * What SecureVibe could actually read, as a fact the reports can print beside the score.
 *
 * This exists because of one run. On 20 September 2026 the first application anybody handed SecureVibe from
 * outside was a Python Flask app: seven `.py` files holding the authentication, the database access and the
 * application logic. The static analysis read one JavaScript file and one HTML template, found ten issues in
 * them, and the compliance report then said **0 of 106 applicable requirements verified**.
 *
 * Every number in that sentence was arithmetically correct and the sentence as a whole was false. "0 of 106
 * verified" reads as *this app failed 106 requirements*. What happened is that 106 requirements were never
 * assessed, because the code they are about was never read.
 *
 * It is the same mistake this project spends all its effort avoiding, pointing the other way. A scan that did
 * not run is not a clean result; a requirement that was not assessed is not a failed one. The second follows
 * from the first and was missing.
 */

/** The file types SecureVibe's own code scanners parse. Everything else is read by nothing but the AI review. */
const READ_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.ejs']);

/** Extensions that are code somebody wrote, grouped under the name a person would use for them. */
const LANGUAGES: { name: string; extensions: string[] }[] = [
  { name: 'TypeScript', extensions: ['.ts', '.tsx'] },
  { name: 'JavaScript', extensions: ['.js', '.jsx', '.mjs', '.cjs'] },
  { name: 'EJS templates', extensions: ['.ejs'] },
  { name: 'Python', extensions: ['.py'] },
  { name: 'Ruby', extensions: ['.rb'] },
  { name: 'Go', extensions: ['.go'] },
  { name: 'Rust', extensions: ['.rs'] },
  { name: 'Java', extensions: ['.java'] },
  { name: 'Kotlin', extensions: ['.kt', '.kts'] },
  { name: 'C#', extensions: ['.cs'] },
  { name: 'PHP', extensions: ['.php'] },
  { name: 'Swift', extensions: ['.swift'] },
  { name: 'Shell scripts', extensions: ['.sh', '.bash', '.zsh'] },
];

export interface LanguageCoverage {
  language: string;
  files: number;
  /** True when SecureVibe's own scanners parse this language; false when nothing but the AI review sees it. */
  read: boolean;
}

export interface CodeCoverage {
  /** Code files in the app, after the ignore list has removed dependencies and build output. */
  codeFiles: number;
  /** Of those, how many SecureVibe's scanners can parse. */
  filesRead: number;
  languages: LanguageCoverage[];
  /** Languages present in the app that nothing here can read, most files first. */
  unreadLanguages: string[];
  /**
   * Whether it is honest to give this application a compliance score at all. False when most of its code was
   * never read: the requirements were not assessed, and reporting them as unmet would be a verdict we did not
   * earn. Not a quality judgement about the app — a statement about this run.
   */
  assessable: boolean;
  /** One plain sentence for the reports, always present. */
  summary: string;
}

function extensionOf(relPath: string): string {
  const name = relPath.slice(relPath.lastIndexOf('/') + 1);
  const dot = name.lastIndexOf('.');
  return dot <= 0 ? '' : name.slice(dot).toLowerCase();
}

/**
 * Below this share of an application's code being readable, a score is not reported. Set at a half rather than
 * at something stricter because the point is to catch "we read almost none of it", not to withhold a score from
 * an app with a few shell scripts in it.
 */
export const ASSESSABLE_SHARE = 0.5;

export function summariseCodeCoverage(relPaths: string[]): CodeCoverage {
  const byLanguage = new Map<string, { files: number; read: boolean }>();
  let codeFiles = 0;
  let filesRead = 0;

  for (const relPath of relPaths) {
    const ext = extensionOf(relPath);
    const language = LANGUAGES.find((l) => l.extensions.includes(ext));
    if (!language) continue;
    codeFiles += 1;
    const read = READ_EXTENSIONS.has(ext);
    if (read) filesRead += 1;
    const entry = byLanguage.get(language.name) ?? { files: 0, read };
    entry.files += 1;
    byLanguage.set(language.name, entry);
  }

  const languages = [...byLanguage.entries()]
    .map(([language, v]) => ({ language, files: v.files, read: v.read }))
    .sort((a, b) => b.files - a.files || a.language.localeCompare(b.language));
  const unreadLanguages = languages.filter((l) => !l.read).map((l) => l.language);

  // An app with no code files at all is not assessable either, and saying "0 of 0" would be the same lie.
  const assessable = codeFiles > 0 && filesRead / codeFiles >= ASSESSABLE_SHARE;

  return { codeFiles, filesRead, languages, unreadLanguages, assessable, summary: describe(codeFiles, filesRead, unreadLanguages) };
}

function list(names: string[]): string {
  if (names.length <= 1) return names[0] ?? '';
  return `${names.slice(0, -1).join(', ')} and ${names.at(-1)!}`;
}

function describe(codeFiles: number, filesRead: number, unreadLanguages: string[]): string {
  if (codeFiles === 0) return 'No code files were found in this app, so nothing was read.';
  const read = `SecureVibe read ${filesRead} of this app's ${codeFiles} code file${codeFiles === 1 ? '' : 's'}.`;
  if (unreadLanguages.length === 0) return read;
  return `${read} It cannot read ${list(unreadLanguages)}, so ${
    filesRead === 0 ? 'none of this app was examined' : 'the rest was not examined'
  } by the code checks. The virus scan, the secrets scan and the AI review still read every file.`;
}
