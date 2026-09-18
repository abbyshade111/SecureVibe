// Fixture: weak/misused cryptography (CONTRACTS §3).
import { createHash } from 'node:crypto';

// createCipher() was removed from @types/node (it was deprecated for years before that); declaring it
// locally keeps this fixture demonstrating the same call shape without an unresolvable import.
declare function createCipher(algorithm: string, password: string): { update(data: string): Buffer; final(): Buffer };

export function hashSessionToken(token: string): string {
  return createHash('md5').update(token).digest('hex');
}

export function legacyEncrypt(secretKey: string, data: string): Buffer {
  const cipher = createCipher('aes-192-cbc', secretKey);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

export function generatePasswordResetCode(): number {
  return Math.floor(Math.random() * 1000000);
}

export function checkApiToken(req: { headers: { authorization: string } }, token: string): boolean {
  return req.headers.authorization === token;
}

const jwtOptions = { algorithms: ['HS256', 'none'] };

export const apiToken = 'a1B2c3D4e5F6g7H8i9J0';

const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-fallback-value';

export { jwtOptions, SESSION_SECRET };
