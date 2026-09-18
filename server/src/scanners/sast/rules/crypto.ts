/**
 * Cryptography and secrets rules: weak hashes in security contexts, Math.random for security values,
 * deprecated ciphers, timing-unsafe comparisons, JWT "none", hard-coded secrets and default fallbacks.
 */
import ts from 'typescript';
import { calleeTail, enclosingFunction, enclosingStatement, functionName, isLiteralish, isTainted, propertyName, REQ_TAINT, stringValue, text, type TsFile } from '../engine.js';
import { assignedName, defineRule, looksLikeSecretValue, SECRET_ENV_NAME, SECRET_NAME, SECURITY_CONTEXT, stringArg } from './base.js';

const WEAK_HASH = /^(md5|md-5|sha1|sha-1|ripemd160|md4)$/i;
const WEAK_CIPHER = /^(des|des-ede|des-ede3|des3|rc4|rc2|bf|blowfish|cast|cast5|idea|seed|aes-?\d+-ecb)/i;
const SECRET_COMPARE = /(token|secret|hmac|signature|api_?key|otp|totp|password|passwd|recovery|csrf|_hash\b|Hash\b)/;

function contextText(node: ts.Node, file: TsFile): string {
  const fn = enclosingFunction(node);
  return `${text(enclosingStatement(node), file)} ${functionName(fn)} ${assignedName(node) ?? ''}`;
}

export const weakHashSecurityContext = defineRule({
  id: 'sast.weak-hash-security-context',
  title: 'A weak hash (MD5/SHA-1) protects something security-relevant',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-328'],
  asvs: ['V11.4.1'],
  exploitability: 'theoretical',
  description: 'MD5 or SHA-1 is used where the value is a token, password, session id, signature or similar.',
  impact: 'These algorithms are broken: collisions are cheap and brute force is fast, so the protection can be undone.',
  fix: 'Use SHA-256 (createHash("sha256")), HMAC-SHA-256 for signatures, and the password helpers (argon2id/scrypt) for passwords.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (!ts.isCallExpression(node)) return;
    const tail = calleeTail(node);
    if (tail !== 'createHash' && tail !== 'createHmac') return;
    const algo = stringArg(node, 0);
    if (!algo || !WEAK_HASH.test(algo)) return;
    const ctx = contextText(node, file);
    // RFC 6238 one-time codes are defined over HMAC-SHA1; that is not a weakness.
    if (/totp|hotp/i.test(file.relPath) || /totp|hotp/i.test(ctx)) return;
    if (tail === 'createHmac' || SECURITY_CONTEXT.test(ctx)) report(node, { evidence: `${tail}('${algo}') used for: ${text(enclosingStatement(node), file).slice(0, 120)}` });
  },
});

export const mathRandomSecurity = defineRule({
  id: 'sast.math-random-security',
  title: 'Math.random() is used for a security value',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-338'],
  asvs: ['V11.5.1', 'V7.2.3'],
  exploitability: 'requires-network-exposure',
  description: 'Math.random() produces a token, code, password, session id or similar value.',
  impact: 'Math.random() is predictable, so an attacker can guess the value and impersonate someone or bypass a check.',
  fix: 'Use crypto.randomBytes(), crypto.randomUUID() or crypto.randomInt() from node:crypto.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (!ts.isCallExpression(node) || text(node.expression, file) !== 'Math.random') return;
    const ctx = contextText(node, file);
    if (SECURITY_CONTEXT.test(ctx)) report(node, { evidence: `Math.random() in: ${text(enclosingStatement(node), file).slice(0, 120)}` });
  },
});

export const cryptoCreateCipher = defineRule({
  id: 'sast.crypto-createcipher',
  title: 'A deprecated or weak cipher is used',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-327'],
  asvs: ['V11.3.2', 'V11.3.1'],
  sbd: ['DM-02'],
  exploitability: 'theoretical',
  description: 'The code calls createCipher()/createDecipher() (removed, password-derived, no IV) or picks a weak algorithm such as DES, RC4 or AES in ECB mode.',
  impact: 'Encrypted data can be recovered or tampered with.',
  fix: 'Use the field-encryption helper (AES-256-GCM with a random IV and a versioned key) from src/db/field-crypto.ts.',
  appliesTo: ['ts'],
  visit(node, _file, report) {
    if (!ts.isCallExpression(node)) return;
    const tail = calleeTail(node);
    if (tail === 'createCipher' || tail === 'createDecipher') {
      report(node, { evidence: `${tail}() is deprecated and derives the key from a password without a salt or IV` });
      return;
    }
    if (tail === 'createCipheriv' || tail === 'createDecipheriv') {
      const algo = stringArg(node, 0);
      if (algo && WEAK_CIPHER.test(algo)) report(node, { evidence: `${tail}('${algo}') uses a weak algorithm or mode` });
    }
  },
});

export const timingUnsafeCompare = defineRule({
  id: 'sast.timing-unsafe-compare',
  title: 'A secret is compared with === instead of a constant-time check',
  severity: 'medium',
  confidence: 'medium',
  cwe: ['CWE-208'],
  asvs: ['V6.4.3', 'V11.5.1'],
  exploitability: 'theoretical',
  description: 'A token, code or hash from a request is compared with a stored secret using === or !==.',
  impact: 'The comparison stops at the first different character, and the tiny timing difference can be measured to guess the secret piece by piece.',
  fix: 'Hash both values with SHA-256 and compare the digests with crypto.timingSafeEqual().',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (!ts.isBinaryExpression(node)) return;
    const op = node.operatorToken.kind;
    if (
      op !== ts.SyntaxKind.EqualsEqualsEqualsToken &&
      op !== ts.SyntaxKind.ExclamationEqualsEqualsToken &&
      op !== ts.SyntaxKind.EqualsEqualsToken &&
      op !== ts.SyntaxKind.ExclamationEqualsToken
    ) {
      return;
    }
    const sides = [node.left, node.right];
    if (sides.some((s) => isLiteralish(s) || /\.length$/.test(text(s, file)))) return;
    if (/timingSafeEqual/.test(text(enclosingStatement(node), file))) return;
    const tainted = sides.map((s) => isTainted(s, file, REQ_TAINT));
    if (tainted[0] === tainted[1]) return; // both inputs, or neither: not an input-vs-secret comparison
    const secretSide = tainted[0] ? node.right : node.left;
    if (!SECRET_COMPARE.test(text(secretSide, file))) return;
    report(node, { evidence: `${text(node, file).slice(0, 120)} compares request data with a stored secret` });
  },
});

export const jwtNoneAlg = defineRule({
  id: 'sast.jwt-none-alg',
  title: 'A token can be accepted without a signature (alg "none")',
  severity: 'critical',
  confidence: 'high',
  cwe: ['CWE-347'],
  asvs: ['V9.1.2', 'V9.1.1'],
  exploitability: 'trivial',
  description: 'The "none" algorithm is allowed when creating or verifying signed tokens.',
  impact: 'Anyone can forge a token with any content and the app will trust it.',
  fix: 'Remove "none" from the algorithm list and pin one strong algorithm (for example HS256 with a 32-byte key, or ES256).',
  appliesTo: ['ts'],
  visit(node, _file, report) {
    if (!ts.isPropertyAssignment(node)) return;
    const name = propertyName(node.name);
    if (!name || !/^(alg|algorithm|algorithms)$/.test(name)) return;
    const init = node.initializer;
    const isNone = (e: ts.Expression): boolean => stringValue(e)?.toLowerCase() === 'none';
    if (isNone(init) || (ts.isArrayLiteralExpression(init) && init.elements.some(isNone))) report(node);
  },
});

const AUTH_HEADER_VALUE = /^(Bearer|Basic|Token)\s+\S{8,}$/i;

export const hardcodedSecret = defineRule({
  id: 'sast.hardcoded-secret',
  title: 'A secret is written directly in the code',
  severity: 'critical',
  confidence: 'high',
  cwe: ['CWE-798'],
  asvs: ['V13.3.1', 'V13.2.3'],
  sbd: ['AC-05'],
  exploitability: 'requires-auth',
  description: 'A password, API key or token is assigned as a literal string in a source file.',
  impact: 'Everyone with the code (and every backup, zip and repository) has the secret, and rotating it requires a code change.',
  fix: 'Move the value to .env, read it through src/config.ts, and rotate the exposed secret now.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (file.isTest) return;
    let name: string | undefined;
    let value: ts.Expression | undefined;
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      name = node.name.text;
      value = node.initializer;
    } else if (ts.isPropertyAssignment(node)) {
      name = propertyName(node.name);
      value = node.initializer;
    } else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isPropertyAccessExpression(node.left)) {
      name = node.left.name.text;
      value = node.right;
    }
    if (!name || !value) return;
    const literal = stringValue(value);
    if (literal === undefined) return;
    if (/^authorization$/i.test(name)) {
      if (AUTH_HEADER_VALUE.test(literal)) report(node, { snippet: `${name}: '${literal.slice(0, 4)}…'`, evidence: `Authorization header value written in code (${literal.slice(0, 4)}…)` });
      return;
    }
    if (!SECRET_NAME.test(name)) return;
    if (!looksLikeSecretValue(literal, name)) return;
    report(node, { snippet: `${name} = '${literal.slice(0, 4)}…'`, evidence: `${name} is assigned a literal value (${literal.slice(0, 4)}…, ${literal.length} characters)` });
  },
});

export const defaultSecretFallback = defineRule({
  id: 'sast.default-secret-fallback',
  title: 'A secret has a built-in default value',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-798', 'CWE-1188'],
  asvs: ['V13.2.3', 'V13.3.1'],
  sbd: ['AC-05'],
  exploitability: 'requires-network-exposure',
  description: 'A secret is read from the environment with a fallback literal (process.env.X || "..." or a zod .default("...")).',
  impact: 'When the variable is missing, the app silently runs with a secret everyone can read in the code.',
  fix: 'Remove the fallback and let src/config.ts refuse to start when the secret is missing or weak.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind;
      if (op !== ts.SyntaxKind.BarBarToken && op !== ts.SyntaxKind.QuestionQuestionToken) return;
      const left = text(node.left, file);
      const m = /^process\.env(?:\.([A-Z0-9_]+)|\[['"]([A-Z0-9_]+)['"]\])$/.exec(left);
      const envName = m?.[1] ?? m?.[2];
      if (!envName || !SECRET_ENV_NAME.test(envName)) return;
      const fallback = stringValue(node.right);
      if (fallback === undefined || fallback.length === 0) return;
      report(node, { evidence: `${envName} falls back to a literal when unset` });
      return;
    }
    if (ts.isPropertyAssignment(node)) {
      const name = propertyName(node.name);
      if (!name || !SECRET_ENV_NAME.test(name)) return;
      // z.string().default('literal') on a secret-named environment key
      let cur: ts.Expression = node.initializer;
      for (let i = 0; i < 6 && ts.isCallExpression(cur); i++) {
        if (calleeTail(cur) === 'default' && stringValue(cur.arguments[0]) !== undefined && (stringValue(cur.arguments[0]) ?? '').length > 0) {
          report(node, { evidence: `${name} has a literal default in its schema` });
          return;
        }
        if (ts.isPropertyAccessExpression(cur.expression)) cur = cur.expression.expression;
        else break;
      }
    }
  },
});

export const cryptoRules = [weakHashSecurityContext, mathRandomSecurity, cryptoCreateCipher, timingUnsafeCompare, jwtNoneAlg, hardcodedSecret, defaultSecretFallback];
