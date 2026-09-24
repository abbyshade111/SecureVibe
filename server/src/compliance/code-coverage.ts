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

import { ASSESSABLE_SHARE, languageBreakdown } from '@shared/languages.js';

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
   * earn. Not a quality judgment about the app — a statement about this run.
   */
  assessable: boolean;
  /** One plain sentence for the reports, always present. */
  summary: string;
}

export function summariseCodeCoverage(relPaths: string[]): CodeCoverage {
  // The language table lives in shared/ so that the upload page and this agree. They tell a person the same
  // thing at two different moments, and a page promising what the report then withholds is worse than either
  // being wrong on its own.
  const breakdown = languageBreakdown(relPaths);
  const languages: LanguageCoverage[] = breakdown.map((l) => ({ language: l.language, files: l.files, read: l.analysed }));
  const codeFiles = breakdown.reduce((n, l) => n + l.files, 0);
  const filesRead = breakdown.filter((l) => l.analysed).reduce((n, l) => n + l.files, 0);
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
