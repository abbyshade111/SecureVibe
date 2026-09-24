/**
 * Helpers shared by the probe families: route lookup, path filling, outcome builders and text checks.
 */
import type { HttpResponse } from '../http.js';
import type { ProbeContext, ProbeFailure, ProbeOutcome, RouteInfo } from '../types.js';

export function routesOf(ctx: ProbeContext): RouteInfo[] {
  return ctx.routes?.routes ?? [];
}

export function findRoute(ctx: ProbeContext, pred: (r: RouteInfo) => boolean): RouteInfo | undefined {
  return routesOf(ctx).find(pred);
}

export function hasParams(route: RouteInfo): boolean {
  return /:[A-Za-z0-9_]+/.test(route.path);
}

/** Replaces `:param` segments; unknown params get `fallback`. */
export function fillPath(path: string, values: Record<string, string> = {}, fallback = '1'): string {
  return path.replace(/:([A-Za-z0-9_]+)\??/g, (_m, name: string) => encodeURIComponent(values[name] ?? fallback));
}

export function isTestEndpoint(path: string): boolean {
  return path.startsWith('/__securevibe');
}

export function pass(expected: string, observed: string, res?: HttpResponse, extra: Partial<ProbeOutcome> = {}): ProbeOutcome {
  return { passed: true, expected, observed, ...excerpts(res), ...extra };
}

export function fail(expected: string, observed: string, res?: HttpResponse, extra: Partial<ProbeOutcome> = {}): ProbeOutcome {
  return { passed: false, expected, observed, ...excerpts(res), ...extra };
}

export function excerpts(res?: HttpResponse): { requestExcerpt?: string; responseExcerpt?: string; endpoint?: string } {
  if (!res) return {};
  return { requestExcerpt: res.requestExcerpt(), responseExcerpt: res.responseExcerpt(), endpoint: `${res.request.method} ${res.request.path}` };
}

export function failureFrom(res: HttpResponse, observed: string): ProbeFailure {
  return {
    endpoint: `${res.request.method} ${res.request.path}`,
    observed,
    requestExcerpt: res.requestExcerpt(),
    responseExcerpt: res.responseExcerpt(),
  };
}

/** Builds the outcome for a probe that checked many endpoints. */
export function summarize(expected: string, checked: number, failures: ProbeFailure[], inconclusive = 0, extra: Partial<ProbeOutcome> = {}): ProbeOutcome {
  if (checked === 0 && failures.length === 0) return { passed: null, expected, observed: 'no endpoint to check', reason: 'no matching route in the registry export', ...extra };
  if (failures.length > 0) {
    const first = failures[0];
    return {
      passed: false,
      expected,
      observed: `${failures.length} of ${checked} checks failed; first: ${first?.endpoint ?? ''} — ${first?.observed ?? ''}`,
      failures,
      requestExcerpt: first?.requestExcerpt,
      responseExcerpt: first?.responseExcerpt,
      endpoint: first?.endpoint,
      ...extra,
    };
  }
  if (checked === inconclusive) {
    return { passed: null, expected, observed: `${checked} checks were inconclusive`, reason: 'every request was rejected before the check under test could be observed', ...extra };
  }
  return { passed: true, expected, observed: `${checked - inconclusive} checks passed${inconclusive ? `, ${inconclusive} inconclusive` : ''}`, ...extra };
}

const STACK_PATTERNS: { re: RegExp; what: string }[] = [
  { re: /\n\s+at [^\n]+\(?[^\n]*:\d+:\d+\)?/, what: 'a stack trace line' },
  { re: /node_modules[\\/]/, what: 'a node_modules path' },
  { re: /\/(?:src|lib)\/[\w./-]+\.(?:ts|js|mjs):\d+/, what: 'a source file path with line number' },
  { re: /SQLITE_[A-Z]+|SqliteError|syntax error near/i, what: 'a database error' },
  { re: /\b(?:TypeError|ReferenceError|SyntaxError|RangeError|ZodError):/, what: 'a JavaScript error name' },
  { re: /Cannot (?:GET|POST|PUT|PATCH|DELETE) \//, what: "Express's default 'Cannot GET' page" },
  { re: /"stack"\s*:/, what: 'a stack field in JSON' },
];

/** Returns what technical detail a response body leaks, or undefined when it looks generic. */
export function leaksTechnicalDetail(body: string): string | undefined {
  for (const p of STACK_PATTERNS) if (p.re.test(body)) return p.what;
  return undefined;
}

/** Strips per-request values so two rendered pages can be compared. */
export function normalizeHtml(html: string): string {
  return html
    .replace(/nonce-[A-Za-z0-9+/=_-]+/g, 'nonce-X')
    .replace(/nonce=["'][^"']*["']/g, 'nonce="X"')
    .replace(/name=["']_csrf["'][^>]*value=["'][^"']*["']/g, 'csrf')
    .replace(/value=["'][^"']*["'][^>]*name=["']_csrf["']/g, 'csrf')
    .replace(/content=["'][^"']*["'][^>]*name=["']csrf-token["']/g, 'csrf')
    .replace(/name=["']csrf-token["'][^>]*content=["'][^"']*["']/g, 'csrf')
    .replace(/value=["'][^"'@]+@[^"']+["']/g, 'value="email"')
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, 'uuid')
    .replace(/\s+/g, ' ')
    .trim();
}

/** A POST JSON route a signed-in user may call without path parameters (the example notes API when present). */
export function jsonCreateRoute(ctx: ProbeContext): { route: RouteInfo; body: Record<string, unknown> } | undefined {
  const routes = routesOf(ctx).filter(
    (r) => r.method === 'POST' && (r.kind === 'api' || r.path.startsWith('/api/')) && r.auth === 'user' && !hasParams(r) && !isTestEndpoint(r.path),
  );
  const notes = routes.find((r) => /notes?$/.test(r.path));
  const route = notes ?? routes.find((r) => !/\/(ai|uploads?|confirm|reset|revoke|logout)\b/.test(r.path));
  if (!route) return undefined;
  return { route, body: bodyGuess(route) };
}

/** A plausible valid body for a create route: built from its exported body schema when there is one. */
export function bodyGuess(route: RouteInfo): Record<string, unknown> {
  const fromSchema = sampleFromSchema(route.bodySchema, 'Runtime check');
  if (fromSchema && typeof fromSchema === 'object' && !Array.isArray(fromSchema)) return fromSchema as Record<string, unknown>;
  if (/notes?$/.test(route.path)) return { title: 'Runtime check note', body: 'Created by the SecureVibe runtime scanner.' };
  return { title: 'Runtime check', name: 'Runtime check' };
}

interface JsonSchema {
  type?: string | string[];
  properties?: Record<string, JsonSchema>;
  required?: string[];
  enum?: unknown[];
  const?: unknown;
  anyOf?: JsonSchema[];
  oneOf?: JsonSchema[];
  allOf?: JsonSchema[];
  default?: unknown;
  format?: string;
  pattern?: string;
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  exclusiveMinimum?: number;
  items?: JsonSchema;
  minItems?: number;
}

/**
 * Builds a value that satisfies a JSON Schema (as exported by zod): every required property, the first enum
 * option, formats and the date patterns the generated forms use. `text` is used for free-text strings so the
 * caller can recognize (or inject into) them. Returns undefined when there is no usable schema.
 */
export function sampleFromSchema(schema: unknown, text: string, depth = 0): unknown {
  if (!schema || typeof schema !== 'object' || depth > 6) return undefined;
  const s = schema as JsonSchema;
  if (s.const !== undefined) return s.const;
  if (Array.isArray(s.enum) && s.enum.length > 0) return s.enum.find((v) => v !== null && v !== '') ?? s.enum[0];
  const variants = s.anyOf ?? s.oneOf;
  if (variants?.length) {
    const usable = variants.find((v) => v.type !== 'null' && !(v.type === 'string' && v.maxLength === 0) && v.const !== '') ?? variants[0];
    return sampleFromSchema(usable, text, depth + 1);
  }
  if (s.allOf?.length) return sampleFromSchema(s.allOf[0], text, depth + 1);
  const type = Array.isArray(s.type) ? s.type.find((t) => t !== 'null') : s.type;
  switch (type ?? (s.properties ? 'object' : undefined)) {
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [key, prop] of Object.entries(s.properties ?? {})) {
        if (!(s.required ?? []).includes(key)) continue;
        const value = sampleFromSchema(prop, text, depth + 1);
        if (value !== undefined) out[key] = value;
      }
      return out;
    }
    case 'string':
      return sampleString(s, text);
    case 'integer':
    case 'number': {
      const min = s.minimum ?? (s.exclusiveMinimum !== undefined ? s.exclusiveMinimum + 1 : undefined);
      const value = Math.max(min ?? 1, 1);
      return s.maximum !== undefined ? Math.min(value, s.maximum) : value;
    }
    case 'boolean':
      return typeof s.default === 'boolean' ? s.default : false;
    case 'array': {
      const item = sampleFromSchema(s.items, text, depth + 1);
      return item === undefined ? [] : Array.from({ length: Math.max(s.minItems ?? 0, 1) }, () => item);
    }
    default:
      return s.default;
  }
}

function sampleString(s: JsonSchema, text: string): string {
  const soon = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
  let value: string;
  if (s.format === 'email') value = 'runtime-check@example.com';
  else if (s.format === 'uri' || s.format === 'url') value = 'https://example.com/';
  else if (s.format === 'date-time' || s.pattern?.includes('T\\d{2}')) value = soon.slice(0, 16);
  else if (s.format === 'date' || s.pattern?.includes('\\d{4}-\\d{2}-\\d{2}')) value = soon.slice(0, 10);
  else if (s.format === 'uuid') value = '00000000-0000-4000-8000-000000000000';
  else if (s.pattern && /^\^?(\[0-9\]|\\d)/.test(s.pattern)) value = '1';
  else value = text;
  if (s.format === 'date-time' && !s.pattern) value = soon;
  if (s.maxLength !== undefined && value.length > s.maxLength) value = value.slice(0, s.maxLength);
  if (s.minLength !== undefined && value.length < s.minLength) value = value.padEnd(s.minLength, 'x');
  return value;
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
