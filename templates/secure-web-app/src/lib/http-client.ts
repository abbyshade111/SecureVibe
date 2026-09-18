/**
 * The only way the app talks to other servers. Hosts must be on the OUTBOUND_ALLOWED_HOSTS allow-list
 * (empty = nothing allowed), redirects are never followed automatically, every call has a 10 second timeout and a
 * 1 MB response cap, certificates are always verified (Node's defaults are never relaxed), and a circuit breaker
 * pauses calls to a host that keeps failing or answering with server errors so one broken service cannot stall
 * the whole app. Calls are never retried automatically: the caller decides whether a retry is safe.
 */
import { config } from '../config.ts';
import { emit } from '../security/events.ts';

export const OUTBOUND_TIMEOUT_MS = 10_000;
export const OUTBOUND_MAX_BYTES = 1024 * 1024;
export const BREAKER_FAILURES = 5;
export const BREAKER_OPEN_MS = 30_000;

export class OutboundError extends Error {
  readonly code: 'blocked' | 'timeout' | 'too_large' | 'breaker_open' | 'network' | 'invalid_url';
  readonly host: string;
  constructor(code: OutboundError['code'], host: string, message: string) {
    super(message);
    this.name = 'OutboundError';
    this.code = code;
    this.host = host;
  }
}

export interface OutboundResponse {
  status: number;
  ok: boolean;
  headers: Headers;
  body: string;
  text(): string;
  json<T = unknown>(): T;
}

interface BreakerState {
  failures: number;
  openUntil: number;
}

const breakers = new Map<string, BreakerState>();

export function isHostAllowed(host: string, port: string, protocol: string): boolean {
  const defaultPort = protocol === 'https:' ? '443' : '80';
  const effectivePort = port || defaultPort;
  return config.outboundAllowedHosts.some((entry) => {
    const [h, p] = entry.split(':');
    if (h !== host) return false;
    return p === undefined || p === effectivePort;
  });
}

function breakerFor(host: string): BreakerState {
  let b = breakers.get(host);
  if (!b) {
    b = { failures: 0, openUntil: 0 };
    breakers.set(host, b);
  }
  return b;
}

function recordFailure(host: string): void {
  const b = breakerFor(host);
  b.failures += 1;
  emit('outbound.failure', { host });
  if (b.failures >= BREAKER_FAILURES) {
    b.openUntil = Date.now() + BREAKER_OPEN_MS;
    b.failures = 0;
    emit('breaker.open', { host });
  }
}

function recordSuccess(host: string): void {
  breakerFor(host).failures = 0;
}

async function readCapped(response: globalThis.Response, host: string): Promise<string> {
  const declared = Number(response.headers.get('content-length') ?? '0');
  if (declared > OUTBOUND_MAX_BYTES) throw new OutboundError('too_large', host, 'The response from the external service was larger than 1 MB.');
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > OUTBOUND_MAX_BYTES) {
      await reader.cancel();
      throw new OutboundError('too_large', host, 'The response from the external service was larger than 1 MB.');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export interface OutboundInit {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}

export async function outboundFetch(url: string, init: OutboundInit = {}): Promise<OutboundResponse> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new OutboundError('invalid_url', '', 'The address to call is not a valid URL.');
  }
  const host = parsed.hostname.toLowerCase();
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') throw new OutboundError('invalid_url', host, 'Only http and https addresses can be called.');
  if (parsed.username || parsed.password) throw new OutboundError('invalid_url', host, 'Credentials in URLs are not allowed.');
  if (!isHostAllowed(host, parsed.port, parsed.protocol)) {
    emit('outbound.blocked', { host });
    throw new OutboundError('blocked', host, `The app is not allowed to contact ${host}. Add it to OUTBOUND_ALLOWED_HOSTS if this is intended.`);
  }
  const breaker = breakerFor(host);
  if (breaker.openUntil > Date.now()) {
    throw new OutboundError('breaker_open', host, `${host} failed repeatedly; calls are paused for a short while.`);
  }
  const method = init.method ?? 'GET';
  let response: globalThis.Response;
  try {
    response = await fetch(parsed, {
      method,
      headers: init.headers,
      body: init.body,
      redirect: 'manual',
      signal: AbortSignal.timeout(init.timeoutMs ?? OUTBOUND_TIMEOUT_MS),
    });
  } catch (err) {
    recordFailure(host);
    const isTimeout = (err as Error).name === 'TimeoutError' || (err as Error).name === 'AbortError';
    throw new OutboundError(isTimeout ? 'timeout' : 'network', host, isTimeout ? `${host} did not answer within the time limit.` : `Could not reach ${host}.`);
  }
  let body: string;
  try {
    body = await readCapped(response, host);
  } catch (err) {
    recordFailure(host);
    if (err instanceof OutboundError) throw err;
    throw new OutboundError('network', host, `The answer from ${host} could not be read.`);
  }
  // A server error counts against the breaker; the response is still handed back so the caller can decide.
  if (response.status >= 500) recordFailure(host);
  else recordSuccess(host);
  return {
    status: response.status,
    ok: response.ok,
    headers: response.headers,
    body,
    text: () => body,
    json: <T>() => JSON.parse(body) as T,
  };
}

/** For docs and tests. */
export function breakerStatus(host: string): { open: boolean; failures: number } {
  const b = breakers.get(host);
  return { open: (b?.openUntil ?? 0) > Date.now(), failures: b?.failures ?? 0 };
}

export function resetBreakers(): void {
  breakers.clear();
}
