/**
 * Types for the fixture app (plain JavaScript) so the scanner's tests can import it without `any`.
 */
import type { RequestListener } from 'node:http';

/** The Express app, which is also a plain Node request listener. */
export function createApp(env?: Record<string, string | undefined>): RequestListener;
export function escapeHtml(value: unknown): string;
export function readCookies(header: string | undefined): Record<string, string>;
