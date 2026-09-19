/**
 * Fixture: prose that mentions secrets is not a secret. A rotation script explaining itself in template literals
 * was reported as "a secret written to the log" in every app SecureVibe builds, because quoted strings were
 * skipped by that rule and backticked ones were not.
 */
const logger = { info: (..._args: unknown[]): void => {} };

export function explainRotation(keys: string[]): void {
  logger.info(`Rotate ${keys.join(' and ')} where they are kept.\n` + `Your password is not changed and no data is touched.`);
}
