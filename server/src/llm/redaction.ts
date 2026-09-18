/**
 * Secret redaction applied to everything the LLM layer writes to disk (audit log, stored prompts/responses,
 * run logs). Better to lose a token of context than to persist a credential.
 */

interface RedactionRule {
  kind: string;
  re: RegExp;
  /** Which capture group holds the secret (default: whole match). */
  group?: number;
  /** Extra check on the matched secret (used for the entropy rule). */
  accept?: (secret: string) => boolean;
}

const HIGH_ENTROPY_MIN_LENGTH = 32;
const HIGH_ENTROPY_THRESHOLD = 4.2; // hex strings (sha256 hashes) cannot exceed 4.0, so they survive

const RULES: RedactionRule[] = [
  { kind: 'anthropic-key', re: /sk-ant-[A-Za-z0-9_-]{8,}/g },
  {
    kind: 'private-key',
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  },
  { kind: 'private-key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*$/g },
  { kind: 'aws-access-key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { kind: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { kind: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g },
  { kind: 'stripe-key', re: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { kind: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { kind: 'bearer-token', re: /\bBearer\s+([A-Za-z0-9._~+/=-]{16,})/g, group: 1 },
  {
    kind: 'assigned-secret',
    re: /\b(?:api[_-]?key|secret|token|password|passwd|pwd|authorization)["']?\s*[:=]\s*["']?([^\s"',;]{8,})/gi,
    group: 1,
  },
  {
    kind: 'high-entropy-token',
    re: /\b[A-Za-z0-9+/_=-]{32,}\b/g,
    accept: (s) => s.length >= HIGH_ENTROPY_MIN_LENGTH && /[A-Za-z]/.test(s) && /[0-9]/.test(s) && shannonEntropy(s) >= HIGH_ENTROPY_THRESHOLD,
  },
];

export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function placeholder(kind: string): string {
  return `[REDACTED:${kind}]`;
}

/** Replace anything that looks like a credential with `[REDACTED:<kind>]`. Idempotent. */
export function redactSecrets(text: string): string {
  let out = text;
  for (const rule of RULES) {
    out = out.replace(rule.re, (match: string, ...args: unknown[]) => {
      const groupIndex = rule.group ?? 0;
      const secret = groupIndex === 0 ? match : String(args[groupIndex - 1] ?? '');
      if (!secret || secret.startsWith('[REDACTED:')) return match;
      if (rule.accept && !rule.accept(secret)) return match;
      return groupIndex === 0 ? placeholder(rule.kind) : match.replace(secret, placeholder(rule.kind));
    });
  }
  return out;
}

/** Walk any JSON-like value and redact every string in it. Non-string leaves are returned as-is. */
export function redactDeep<T>(value: T): T {
  if (typeof value === 'string') return redactSecrets(value) as unknown as T;
  if (Array.isArray(value)) return value.map((v) => redactDeep(v)) as unknown as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = redactDeep(v);
    return out as T;
  }
  return value;
}
