/**
 * Security headers. The Content-Security-Policy is nonce based: only scripts and styles carrying the per-request
 * nonce run, nothing may frame the app, forms only post back to this app, and there is no CORS at all.
 */
import { randomBytes } from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import helmet from 'helmet';
import { config } from '../config.ts';

export const PERMISSIONS_POLICY = 'camera=(), microphone=(), geolocation=()';
export const HSTS_VALUE = 'max-age=31536000; includeSubDomains';

/** The exact policy for a given nonce (also used by docs and tests). */
export function cspFor(nonce: string, tls: boolean = config.tlsEnabled): string {
  const directives = [
    "default-src 'self'",
    `script-src 'nonce-${nonce}' 'strict-dynamic'`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ];
  if (tls) directives.push('upgrade-insecure-requests');
  return directives.join('; ');
}

function nonceMiddleware(_req: Request, res: Response, next: NextFunction): void {
  res.locals.nonce = randomBytes(16).toString('base64');
  next();
}

export function securityHeaders(): RequestHandler[] {
  const tls = config.tlsEnabled;
  const helmetMiddleware = helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        'default-src': ["'self'"],
        'script-src': [(_req, res) => `'nonce-${(res as Response).locals.nonce}'`, "'strict-dynamic'"],
        'style-src': ["'self'", (_req, res) => `'nonce-${(res as Response).locals.nonce}'`],
        'img-src': ["'self'", 'data:'],
        'font-src': ["'self'"],
        'connect-src': ["'self'"],
        'object-src': ["'none'"],
        'base-uri': ["'none'"],
        'frame-ancestors': ["'none'"],
        'form-action': ["'self'"],
        ...(tls ? { 'upgrade-insecure-requests': [] } : {}),
      },
    },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    strictTransportSecurity: tls ? { maxAge: 31536000, includeSubDomains: true } : false,
    xContentTypeOptions: true,
    xFrameOptions: { action: 'deny' },
    xPoweredBy: false,
    xDnsPrefetchControl: { allow: false },
    originAgentCluster: true,
    xDownloadOptions: true,
    xPermittedCrossDomainPolicies: { permittedPolicies: 'none' },
    xXssProtection: true,
  });
  const extras: RequestHandler = (_req, res, next) => {
    res.setHeader('Permissions-Policy', PERMISSIONS_POLICY);
    next();
  };
  return [nonceMiddleware, helmetMiddleware, extras];
}

/** Responses for signed-in users (or sessions waiting for a one-time code) must never be cached. */
export function authenticatedCacheControl(req: Request, res: Response, next: NextFunction): void {
  if (req.user || req.session?.userId) {
    res.setHeader('Cache-Control', 'no-store, private');
    res.setHeader('Pragma', 'no-cache');
  }
  next();
}

/** Logout responses tell the browser to drop everything it kept for this site. */
export function clearSiteData(res: Response): void {
  res.setHeader('Clear-Site-Data', '"cookies", "storage"');
}
