// Fixture: a password logged and console.log used instead of the structured logger (CONTRACTS §3).
const logger = { info: (..._args: unknown[]): void => {} };

export function auditLogin(user: { email: string; password: string }): void {
  logger.info('login attempt', { email: user.email, password: user.password });
}

export function debugDump(value: unknown): void {
  console.log('debug', value);
}
