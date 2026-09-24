/**
 * Small HTTP client for the runtime probes: a cookie jar, manual redirects, same-origin headers on state-changing
 * requests by default, and redacted request/response excerpts for evidence. Requests only ever go to the loopback
 * port SecureVibe itself started.
 */
import http from 'node:http';
import https from 'node:https';
import { randomBytes } from 'node:crypto';

/** Cookie names treated as the session cookie, most specific first. */
const SESSION_COOKIE_NAMES: string[] = ['__Host-sid', 'sid'];

/** Lets a caller probing an app with a different session cookie name (SecureVibe itself) have it recognized. */
export function addSessionCookieName(name: string): void {
  if (!SESSION_COOKIE_NAMES.includes(name)) SESSION_COOKIE_NAMES.push(name);
}

/** True for a Set-Cookie line that sets the session cookie. */
export function isSessionSetCookie(line: string): boolean {
  const name = line.slice(0, line.indexOf('=')).trim();
  return SESSION_COOKIE_NAMES.includes(name);
}

export class CookieJar {
  readonly cookies = new Map<string, string>();

  absorb(setCookies: string[]): void {
    for (const line of setCookies) {
      const [pair = '', ...attrs] = line.split(';');
      const eq = pair.indexOf('=');
      if (eq < 0) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const expired = attrs.some((a) => {
        const [k = '', v = ''] = a.trim().split('=');
        const key = k.toLowerCase();
        if (key === 'max-age') return Number(v) <= 0;
        if (key === 'expires') return new Date(v).getTime() < Date.now();
        return false;
      });
      if (expired || value === '') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }

  header(): string {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  get(name: string): string | undefined {
    return this.cookies.get(name);
  }

  /** The session cookie value (`__Host-sid` in TLS modes, `sid` otherwise, or a name added with addSessionCookieName). */
  sessionId(): string | undefined {
    const name = this.sessionCookieName();
    return name ? this.cookies.get(name) : undefined;
  }

  sessionCookieName(): string | undefined {
    return SESSION_COOKIE_NAMES.find((name) => this.cookies.has(name));
  }

  clone(): CookieJar {
    const j = new CookieJar();
    for (const [k, v] of this.cookies) j.cookies.set(k, v);
    return j;
  }
}

export interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array | FormData;
  jar?: CookieJar;
  /** Adds Origin + Sec-Fetch-Site: same-origin on state-changing requests (default true). */
  sameOrigin?: boolean;
  timeoutMs?: number;
}

export interface HttpResponse {
  status: number;
  headers: Headers;
  body: string;
  setCookies: string[];
  request: { method: string; path: string; headers: Record<string, string>; body?: string };
  header(name: string): string | undefined;
  requestExcerpt(): string;
  responseExcerpt(maxBody?: number): string;
  isRedirect(): boolean;
  location(): string;
  contentType(): string;
  json<T = unknown>(): T | undefined;
}

const REDACTED_HEADERS = new Set(['cookie', 'set-cookie', 'authorization', 'x-csrf-token']);
const INTERESTING_RESPONSE_HEADERS = [
  'content-type',
  'content-security-policy',
  'strict-transport-security',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'x-frame-options',
  'cache-control',
  'clear-site-data',
  'access-control-allow-origin',
  'allow',
  'location',
  'retry-after',
  'set-cookie',
  'content-disposition',
  'idempotent-replayed',
];

export function redactHeaderValue(name: string, value: string): string {
  if (!REDACTED_HEADERS.has(name.toLowerCase())) return value;
  if (name.toLowerCase() === 'set-cookie') {
    // Keep the attributes (they are what the probes look at), hide the value.
    return value.replace(/^([^=]+)=([^;]*)/, (_m, n: string) => `${n}=[redacted]`);
  }
  if (name.toLowerCase() === 'cookie') return value.replace(/=([^;]+)/g, '=[redacted]');
  return '[redacted]';
}

export function redactBody(body: string): string {
  return body
    .replace(/(password[^=&"'\s]*)=([^&\s]*)/gi, '$1=[redacted]')
    .replace(/("password[^"]*"\s*:\s*")[^"]*(")/gi, '$1[redacted]$2')
    .replace(/(_csrf=)[^&\s]*/g, '$1[redacted]')
    .replace(/(name=["']_csrf["'][^>]*value=["'])[^"']+(["'])/g, '$1[redacted]$2')
    .replace(/nonce-[A-Za-z0-9+/=_-]+/g, 'nonce-[value]');
}

/** Query parameters whose values are credentials (a startup token, an API key, a reset code) are never recorded. */
const SECRET_QUERY_PARAMS = /^(t|token|key|api_?key|access_?token|password|code|secret)$/i;

export function redactPath(path: string): string {
  const q = path.indexOf('?');
  if (q < 0) return path;
  const query = path
    .slice(q + 1)
    .split('&')
    .map((pair) => {
      const eq = pair.indexOf('=');
      if (eq < 0) return pair;
      let name = pair.slice(0, eq);
      try {
        name = decodeURIComponent(name);
      } catch {
        // keep the raw name
      }
      return SECRET_QUERY_PARAMS.test(name) ? `${pair.slice(0, eq)}=[redacted]` : pair;
    })
    .join('&');
  return `${path.slice(0, q)}?${query}`;
}

export function excerpt(text: string, max = 600): string {
  const clean = text.replace(/\r/g, '');
  return clean.length > max ? `${clean.slice(0, max)}…` : clean;
}

function buildResponse(
  method: string,
  path: string,
  reqHeaders: Record<string, string>,
  reqBody: string | undefined,
  status: number,
  headers: Headers,
  body: string,
  setCookies: string[],
): HttpResponse {
  // Only the redacted path is kept: it ends up in reports.
  const shownPath = redactPath(path);
  const request = { method, path: shownPath, headers: reqHeaders, body: reqBody };
  return {
    status,
    headers,
    body,
    setCookies,
    request,
    header: (name) => headers.get(name) ?? undefined,
    requestExcerpt: () => {
      const lines = [`${method} ${shownPath}`];
      for (const [k, v] of Object.entries(reqHeaders)) lines.push(`${k}: ${redactHeaderValue(k, v)}`);
      if (reqBody !== undefined) lines.push('', excerpt(redactBody(reqBody), 300));
      return lines.join('\n');
    },
    responseExcerpt: (maxBody = 500) => {
      const lines = [`HTTP ${status}`];
      for (const name of INTERESTING_RESPONSE_HEADERS) {
        if (name === 'set-cookie') {
          for (const c of setCookies) lines.push(`set-cookie: ${redactHeaderValue('set-cookie', c)}`);
          continue;
        }
        const v = headers.get(name);
        if (v !== null) lines.push(`${name}: ${v}`);
      }
      if (body) lines.push('', excerpt(redactBody(body), maxBody));
      return lines.join('\n');
    },
    isRedirect: () => status >= 300 && status < 400,
    location: () => headers.get('location') ?? '',
    contentType: () => headers.get('content-type') ?? '',
    json: <T,>() => {
      try {
        return JSON.parse(body) as T;
      } catch {
        return undefined;
      }
    },
  };
}

/** What a transport returns before the cookie jar and the excerpt helpers are applied. */
export interface RawHttpResponse {
  status: number;
  headers: Headers;
  body: string;
  setCookies: string[];
}

/** The only hosts the probes may talk to: an app SecureVibe started on this computer. */
export function isLoopbackHost(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return h === 'localhost' || h === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

/** One request over node:http / node:https. Redirects are never followed: the probes inspect them. */
export function sendOverNodeHttp(
  url: URL,
  method: string,
  headers: Record<string, string>,
  body: string | Uint8Array | undefined,
  timeoutMs: number,
): Promise<RawHttpResponse> {
  const mod = url.protocol === 'https:' ? https : http;
  // The certificate check below is off, which is only right for a self-signed app on loopback. That used to hold
  // because of who called this function; now it holds because the function refuses anything else.
  if (!isLoopbackHost(url.hostname)) {
    return Promise.reject(new Error(`The runtime probes only talk to an app on this computer (got ${url.hostname}).`));
  }
  return new Promise((resolveRequest, reject) => {
    const req = mod.request(
      {
        host: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        method,
        headers,
        timeout: timeoutMs,
        // A self-signed certificate on loopback (the guard above allows nothing else); the certificate itself is
        // inspected by its own probe.
        rejectUnauthorized: false,
      } as http.RequestOptions,
      (res) => resolveRequest(collectResponse(res)),
    );
    req.on('timeout', () => req.destroy(new Error(`timed out after ${timeoutMs}ms`)));
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

export function collectResponse(res: http.IncomingMessage): Promise<RawHttpResponse> {
  return new Promise((resolveBody, reject) => {
    const chunks: Buffer[] = [];
    res.on('data', (c: Buffer) => chunks.push(c));
    res.on('error', reject);
    res.on('end', () => {
      const headers = new Headers();
      const setCookies: string[] = [];
      for (const [name, value] of Object.entries(res.headers)) {
        if (value === undefined) continue;
        if (name.toLowerCase() === 'set-cookie') {
          for (const line of Array.isArray(value) ? value : [value]) setCookies.push(line);
          continue;
        }
        headers.set(name, Array.isArray(value) ? value.join(', ') : value);
      }
      resolveBody({ status: res.statusCode ?? 0, headers, body: Buffer.concat(chunks).toString('utf8'), setCookies });
    });
  });
}

export class HttpClient {
  constructor(readonly baseUrl: string) {}

  get origin(): string {
    return this.baseUrl;
  }

  /**
   * The transport seam. The default talks to the loopback port SecureVibe started; SecureVibe's own
   * self-assessment and the scanner's tests replace it to reach an app that is already running in this process.
   */
  protected send(
    method: string,
    path: string,
    headers: Record<string, string>,
    body: string | Uint8Array | undefined,
    timeoutMs: number,
  ): Promise<RawHttpResponse> {
    const url = new URL(path.startsWith('http') ? path : `${this.baseUrl}${path}`);
    return sendOverNodeHttp(url, method, headers, body, timeoutMs);
  }

  /** Headers every request gets: the jar's cookies and, on state-changing methods, same-origin markers. */
  buildHeaders(method: string, opts: RequestOptions): Record<string, string> {
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    const lower = new Set(Object.keys(headers).map((k) => k.toLowerCase()));
    if (opts.jar && opts.jar.header() && !lower.has('cookie')) headers['Cookie'] = opts.jar.header();
    if ((opts.sameOrigin ?? true) && method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      if (!lower.has('origin')) headers['Origin'] = this.baseUrl;
      if (!lower.has('sec-fetch-site')) headers['Sec-Fetch-Site'] = 'same-origin';
    }
    return headers;
  }

  async request(path: string, opts: RequestOptions = {}): Promise<HttpResponse> {
    const method = (opts.method ?? 'GET').toUpperCase();
    const headers = this.buildHeaders(method, opts);
    const body = opts.body instanceof FormData ? undefined : opts.body;
    if (body !== undefined && !Object.keys(headers).some((k) => k.toLowerCase() === 'content-length')) {
      headers['Content-Length'] = String(typeof body === 'string' ? Buffer.byteLength(body) : body.byteLength);
    }
    const res = await this.send(method, path, headers, body, opts.timeoutMs ?? 15_000);
    opts.jar?.absorb(res.setCookies);
    const reqBody = typeof body === 'string' ? body : body ? '[binary]' : undefined;
    return buildResponse(method, path, headers, reqBody, res.status, res.headers, res.body, res.setCookies);
  }

  get(path: string, opts: Omit<RequestOptions, 'method' | 'body'> = {}): Promise<HttpResponse> {
    return this.request(path, { ...opts, method: 'GET' });
  }

  /** application/x-www-form-urlencoded POST (the way browsers submit the app's forms). */
  form(
    path: string,
    data: Record<string, string | number | boolean | undefined>,
    opts: Omit<RequestOptions, 'body'> = {},
  ): Promise<HttpResponse> {
    return this.request(path, {
      ...opts,
      method: opts.method ?? 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'text/html', ...(opts.headers ?? {}) },
      body: formBody(data),
    });
  }

  /** JSON request; the CSRF token goes in the X-CSRF-Token header. */
  json(path: string, body: unknown, opts: Omit<RequestOptions, 'body'> & { csrfToken?: string; raw?: string } = {}): Promise<HttpResponse> {
    const { csrfToken, raw, ...rest } = opts;
    return this.request(path, {
      ...rest,
      method: rest.method ?? 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
        ...(rest.headers ?? {}),
      },
      body: raw ?? (body === undefined ? undefined : JSON.stringify(body)),
    });
  }

  /** A request with an unusual method (TRACE) or a hand-written header set, and no cookie jar. */
  raw(method: string, path: string, headers: Record<string, string> = {}): Promise<HttpResponse> {
    return this.request(path, { method, headers, sameOrigin: false, timeoutMs: 10_000 });
  }
}

export function formBody(data: Record<string, string | number | boolean | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(data)) if (v !== undefined) p.append(k, String(v));
  return p.toString();
}

/** Extracts the CSRF token from a rendered page (hidden `_csrf` field or a csrf-token meta tag). */
export function extractCsrfToken(html: string): string | undefined {
  const patterns = [
    /name=["']_csrf["'][^>]*value=["']([^"']+)["']/,
    /value=["']([^"']+)["'][^>]*name=["']_csrf["']/,
    /<meta[^>]+name=["']csrf-token["'][^>]+content=["']([^"']+)["']/,
    /<meta[^>]+content=["']([^"']+)["'][^>]+name=["']csrf-token["']/,
  ];
  for (const re of patterns) {
    const m = html.match(re);
    if (m?.[1]) return m[1];
  }
  return undefined;
}

/** Parses a Set-Cookie line into its name, value and lower-cased attribute map. */
export function parseSetCookie(line: string): { name: string; value: string; attrs: Record<string, string> } {
  const [pair = '', ...rest] = line.split(';');
  const eq = pair.indexOf('=');
  const name = eq >= 0 ? pair.slice(0, eq).trim() : pair.trim();
  const value = eq >= 0 ? pair.slice(eq + 1).trim() : '';
  const attrs: Record<string, string> = {};
  for (const a of rest) {
    const [k = '', ...v] = a.trim().split('=');
    attrs[k.toLowerCase()] = v.join('=');
  }
  return { name, value, attrs };
}

export function randomToken(bytes = 8): string {
  return randomBytes(bytes).toString('hex');
}

/** Builds a multipart/form-data body for uploads without relying on FormData quirks. */
export function multipart(
  fields: Record<string, string>,
  file: { field: string; name: string; type: string; bytes: Uint8Array },
): { body: Uint8Array; contentType: string } {
  const boundary = `----securevibe${randomToken(12)}`;
  const parts: Uint8Array[] = [];
  const enc = new TextEncoder();
  for (const [k, v] of Object.entries(fields)) {
    parts.push(enc.encode(`--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`));
  }
  parts.push(
    enc.encode(`--${boundary}\r\nContent-Disposition: form-data; name="${file.field}"; filename="${file.name}"\r\nContent-Type: ${file.type}\r\n\r\n`),
  );
  parts.push(file.bytes);
  parts.push(enc.encode(`\r\n--${boundary}--\r\n`));
  const total = parts.reduce((n, p) => n + p.length, 0);
  const body = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    body.set(p, offset);
    offset += p.length;
  }
  return { body, contentType: `multipart/form-data; boundary=${boundary}` };
}

/** A minimal valid 1x1 PNG. */
export const PNG_1X1 = Uint8Array.from(
  Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64'),
);
