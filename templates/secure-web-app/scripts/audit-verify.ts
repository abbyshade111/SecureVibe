/**
 * Checks the hash chain of the security event log. Exit code 0 when every row links to the previous one and
 * matches its own hash; 1 when a row was edited, removed or inserted.
 */
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { closeDb, openDb } from '../src/db/index.ts';
import { runMigrations } from '../src/db/migrate.ts';
import { verifyChain } from '../src/security/audit.ts';

const isMain = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    openDb();
    runMigrations();
    const result = verifyChain();
    if (result.ok) {
      process.stdout.write(`Security event log is intact: ${result.checkedRows} entries checked, every entry links to the one before it.\n`);
      closeDb();
      process.exit(0);
    }
    process.stdout.write(
      `Security event log is NOT intact. The chain breaks at entry ${result.brokenAtSeq} after ${result.checkedRows} good entries.\n${result.reason ?? ''}\nTreat this as a security incident and follow docs/incident-response.md.\n`,
    );
    closeDb();
    process.exit(1);
  } catch (err) {
    process.stderr.write(`\nThe security event log could not be checked.\n${(err as Error).message}\n\n`);
    closeDb();
    process.exit(2);
  }
}
