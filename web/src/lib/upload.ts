/**
 * Uploading an app folder, one file per request. The skip rules match server/src/api/uploads.ts (the server checks
 * again); filtering here just saves sending files that would be refused.
 */
import type { Project } from '@shared/project.js';
import { beginUpload, finishUpload, uploadFile } from './api';

export const MAX_FILE_BYTES = 2 * 1024 * 1024;
export const MAX_FILES = 5_000;
export const MAX_TOTAL_BYTES = 50 * 1024 * 1024;

const SKIPPED_FOLDERS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit', '.cache', '.turbo',
  'coverage', '.venv', 'venv', '__pycache__', '.idea', '.vscode', 'vendor', 'target',
]);

/** ".env" and ".env.<anything>", except the example files that are meant to be shared. */
function isSecretsEnvFile(name: string): boolean {
  const lower = name.toLowerCase();
  if (lower !== '.env' && !lower.startsWith('.env.')) return false;
  return !['.env.example', '.env.sample', '.env.template'].includes(lower);
}

export function skipReason(relPath: string, size: number): string | undefined {
  const parts = relPath.split('/');
  if (parts.some((p) => SKIPPED_FOLDERS.has(p))) return 'dependencies or build output';
  const name = parts.at(-1) ?? '';
  if (isSecretsEnvFile(name)) return 'a secrets file (.env)';
  if (/\.(pem|key|p12|pfx|jks|keystore)$/i.test(name) || /^id_(rsa|dsa|ecdsa|ed25519)$/.test(name)) return 'a private key';
  if (/\.(sqlite3?|db)$/i.test(name)) return 'a database file';
  if (name === '.DS_Store' || name === 'Thumbs.db') return 'a system file';
  if (size > MAX_FILE_BYTES) return 'larger than 2 MB';
  return undefined;
}

export interface PlannedFile {
  file: File;
  /** Path inside the app folder (the chosen folder's own name removed). */
  path: string;
}

export interface UploadPlan {
  folderName: string;
  files: PlannedFile[];
  bytes: number;
  skipped: { path: string; reason: string }[];
  problem?: string;
}

/** Works out what to send from a folder picked with <input webkitdirectory>. */
export function planUpload(list: FileList | File[]): UploadPlan {
  const all = Array.from(list);
  const first = (all[0]?.webkitRelativePath || all[0]?.name || '').split('/')[0] ?? '';
  const files: PlannedFile[] = [];
  const skipped: UploadPlan['skipped'] = [];
  let bytes = 0;
  for (const file of all) {
    const rel = (file.webkitRelativePath || file.name).split('/').slice(first && file.webkitRelativePath ? 1 : 0).join('/');
    if (!rel) continue;
    const reason = skipReason(rel, file.size);
    if (reason) {
      skipped.push({ path: rel, reason });
      continue;
    }
    files.push({ file, path: rel });
    bytes += file.size;
  }
  let problem: string | undefined;
  if (files.length === 0) problem = 'There is nothing to check in that folder. Choose the folder that holds your app’s code.';
  else if (files.length > MAX_FILES) problem = `That folder has ${files.length} files to check; the limit is ${MAX_FILES}. Choose the app’s own folder, not a folder above it.`;
  else if (bytes > MAX_TOTAL_BYTES) problem = 'That folder is larger than 50 MB without its dependencies. Choose the app’s own folder, not a folder above it.';
  return { folderName: first, files, bytes, skipped, ...(problem ? { problem } : {}) };
}

/** Sends the planned files (four at a time) and finishes the upload. */
export async function runUpload(projectId: string, plan: UploadPlan, onProgress: (done: number) => void, signal: AbortSignal): Promise<Project> {
  await beginUpload(projectId);
  let next = 0;
  let done = 0;
  const worker = async () => {
    while (next < plan.files.length) {
      if (signal.aborted) throw new Error('The upload was cancelled.');
      const item = plan.files[next++]!;
      await uploadFile(projectId, item.path, item.file);
      onProgress(++done);
    }
  };
  await Promise.all([worker(), worker(), worker(), worker()]);
  return finishUpload(projectId);
}
