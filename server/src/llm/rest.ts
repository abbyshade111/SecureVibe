/**
 * Shared plumbing for the providers that talk to their service over plain HTTPS (OpenAI, Google): one JSON POST
 * with a timeout, the abort signal, and the service's error turned into an `LlmError` kind the pipeline reacts to.
 * The API key travels in a header and never appears in a message.
 */
import { LlmError } from './types.js';

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface PostJsonOptions {
  fetchImpl?: FetchLike;
  timeoutMs: number;
  abort?: AbortSignal;
  /** Plain name of the service for messages ("OpenAI", "Google"). */
  service: string;
}

function errorText(body: unknown): string {
  if (body && typeof body === 'object') {
    const err = (body as { error?: unknown }).error;
    if (err && typeof err === 'object') {
      const e = err as { message?: unknown; code?: unknown; status?: unknown; type?: unknown };
      const parts = [e.code, e.status, e.type, e.message].filter((p) => typeof p === 'string') as string[];
      if (parts.length) return parts.join(': ').slice(0, 300);
    }
    if (typeof err === 'string') return err.slice(0, 300);
  }
  return '';
}

export function llmErrorForStatus(service: string, status: number, body: unknown): LlmError {
  const text = errorText(body);
  const lower = text.toLowerCase();
  if (status === 401 || status === 403) return new LlmError('auth', `the ${service} API key was not accepted`);
  if (status === 402 || /insufficient_quota|billing|exceeded your current quota|resource_exhausted.*quota/.test(lower)) {
    return new LlmError('billing', `the ${service} account has no credit or quota left`);
  }
  if (status === 429) return new LlmError('rate-limit', `the ${service} API rate limit was reached`);
  if (status === 400 || status === 404 || status === 422) return new LlmError('bad-request', text || `${service} rejected the request (${status})`);
  return new LlmError('api', text || `${service} answered with status ${status}`);
}

/** POSTs JSON and returns the parsed JSON body; throws an LlmError for anything but a 2xx answer. */
export async function postJson(url: string, headers: Record<string, string>, body: unknown, opts: PostJsonOptions): Promise<unknown> {
  const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as FetchLike);
  const signals: AbortSignal[] = [AbortSignal.timeout(opts.timeoutMs)];
  if (opts.abort) signals.push(opts.abort);
  let res: Response;
  try {
    res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
      signal: AbortSignal.any(signals),
    });
  } catch (err) {
    if (opts.abort?.aborted) throw new LlmError('aborted', 'the step was cancelled');
    const message = err instanceof Error ? err.message : String(err);
    if (/timeout|timed out/i.test(message)) throw new LlmError('network', `the ${opts.service} API did not answer in time`);
    throw new LlmError('network', `the connection to the ${opts.service} API failed`);
  }
  let parsed: unknown;
  const text = await res.text();
  try {
    parsed = text === '' ? {} : JSON.parse(text);
  } catch {
    parsed = { error: { message: text.slice(0, 200) } };
  }
  if (!res.ok) throw llmErrorForStatus(opts.service, res.status, parsed);
  return parsed;
}

/** Plain-language message for the person using SecureVibe — never a stack trace, never a credential. */
export function userMessageFor(service: string, err: LlmError): string {
  switch (err.kind) {
    case 'auth':
      return `The ${service} API key was not accepted. Check the key in Settings → "Your AI service", then try again.`;
    case 'billing':
      return `Your ${service} account has no credit or quota left. Add credit with ${service}, then try again.`;
    case 'rate-limit':
      return `${service} is rate-limiting this key right now. Wait a few minutes and try again.`;
    case 'network':
      return `SecureVibe could not reach the ${service} API. Check your internet connection and try again.`;
    case 'aborted':
      return 'The step was cancelled.';
    case 'bad-request':
      return `${service} rejected the request: ${err.message}`;
    default:
      return `The AI step could not be completed: ${err.message}`;
  }
}

/**
 * JSON schema in the strict shape both services accept for structured output and tool inputs: every object closed
 * (`additionalProperties: false`) with every property required, and without zod's `$schema` marker.
 */
export function strictJsonSchema(schema: Record<string, unknown>): Record<string, unknown> {
  const walk = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(walk);
    if (!node || typeof node !== 'object') return node;
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (key === '$schema') continue;
      out[key] = walk(value);
    }
    if (out['type'] === 'object' && out['properties'] && typeof out['properties'] === 'object') {
      out['additionalProperties'] = false;
      out['required'] = Object.keys(out['properties'] as Record<string, unknown>);
    }
    return out;
  };
  return walk(schema) as Record<string, unknown>;
}
