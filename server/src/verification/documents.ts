/**
 * The documents a human check asks you to read.
 *
 * Every manual check is written as plain instructions ("Does docs/sessions.md state the idle and maximum session
 * times?"), so the file it refers to is already in the text. This finds those references, works out where the file
 * actually is — in the app, in the project's design folder, or in SecureVibe itself — and lets the wizard put the
 * document in front of the person instead of making them go looking for it.
 *
 * Files that hold secrets (`.env`, the one-time administrator password) are named but never opened.
 */
import { existsSync, readFileSync, statSync } from 'node:fs';
import { extname } from 'node:path';
import { confinePath, PathConfinementError } from '../store/paths.js';

/**
 * Paths the checks mention: `docs/x.md`, `design/adr/ADR-001-x.md`, `securevibe.manifest.json`, `FIRST-LOGIN.txt`,
 * `.env`. Each alternative carries its own boundary: a leading `\b` would never match `.env` (a dot is not a word
 * character), and `.env` must not swallow the first half of `.env.example`.
 */
const REFERENCE =
  /(?<![\w./-])((?:docs|design|reports|src|tests)\/[A-Za-z0-9._/-]+\.(?:md|json)(?![\w/-])|[A-Za-z][A-Za-z0-9._-]*\.(?:md|json)(?![\w/-])|FIRST-LOGIN\.txt(?![\w/-])|\.env(?![\w.-]))/g;

/** Never served, whatever a check's wording says: these hold keys and passwords. */
const SECRET = /(^|\/)(\.env(\..*)?|FIRST-LOGIN\.txt)$/;

/** Only text documents are ever served, and only up to this size. */
const READABLE_EXTENSIONS = new Set(['.md', '.json']);
export const MAX_DOCUMENT_BYTES = 512 * 1024;

export type DocumentWhere = 'app' | 'project' | 'securevibe';

export interface DocumentRef {
  /** The path exactly as the check names it. */
  path: string;
  /** Which folder it was found in, for the label ("in your app", "in the design folder"…). */
  where: DocumentWhere;
  /** False when the file holds secrets, or is not a document: the wizard names it but offers no link. */
  openable: boolean;
}

export interface DocumentRoots {
  appDir: string;
  projectDir: string;
  repoRoot: string;
}

const ROOT_ORDER: { where: DocumentWhere; key: keyof DocumentRoots }[] = [
  { where: 'app', key: 'appDir' },
  { where: 'project', key: 'projectDir' },
  { where: 'securevibe', key: 'repoRoot' },
];

/** Resolves one referenced path to a real file, or undefined when nothing of that name exists. */
export function resolveDocument(path: string, roots: DocumentRoots): { absolute: string; where: DocumentWhere } | undefined {
  for (const { where, key } of ROOT_ORDER) {
    let absolute: string;
    try {
      absolute = confinePath(roots[key], ...path.split('/'));
    } catch (err) {
      if (err instanceof PathConfinementError) continue;
      throw err;
    }
    if (existsSync(absolute) && statSync(absolute).isFile()) return { absolute, where };
  }
  return undefined;
}

/** True when a file may be handed to the browser: a document, not a secret, not enormous. */
export function isReadableDocument(path: string, absolute: string): boolean {
  if (SECRET.test(path)) return false;
  if (!READABLE_EXTENSIONS.has(extname(absolute).toLowerCase())) return false;
  try {
    return statSync(absolute).size <= MAX_DOCUMENT_BYTES;
  } catch {
    return false;
  }
}

/**
 * The documents one check refers to, in the order they are mentioned. Text that names a file which is not there
 * (a document for a feature this app does not have) is left out, so the wizard never offers a dead link.
 */
export function documentsFor(texts: (string | undefined)[], roots: DocumentRoots): DocumentRef[] {
  const seen = new Set<string>();
  const out: DocumentRef[] = [];
  for (const text of texts) {
    if (!text) continue;
    for (const match of text.matchAll(REFERENCE)) {
      const path = match[1]!;
      if (seen.has(path)) continue;
      seen.add(path);
      if (SECRET.test(path)) {
        // Named so the person knows which file to look at themselves; never opened by SecureVibe.
        const found = resolveDocument(path, roots);
        if (found) out.push({ path, where: found.where, openable: false });
        continue;
      }
      const found = resolveDocument(path, roots);
      if (!found) continue;
      out.push({ path, where: found.where, openable: isReadableDocument(path, found.absolute) });
    }
  }
  return out;
}

/** Reads a document for the wizard. Throws when the path is not one of this project's documents. */
export function readDocument(path: string, roots: DocumentRoots): { text: string; where: DocumentWhere } {
  const found = resolveDocument(path, roots);
  if (!found) throw new DocumentNotAvailable('That document could not be found.');
  if (!isReadableDocument(path, found.absolute)) throw new DocumentNotAvailable('That file is not one SecureVibe will open: it may hold secrets, or it is not a document.');
  return { text: readFileSync(found.absolute, 'utf8'), where: found.where };
}

export class DocumentNotAvailable extends Error {}
