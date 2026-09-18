/**
 * Payments placeholder (contract "Payments" requirement, pattern PAT-PROVIDER-HOSTED-PAYMENTS). This app never
 * collects card numbers, expiry dates or CVV codes itself — that is exactly the kind of secret SecureVibe's own
 * rules forbid handling in code the AI generated. Instead this page explains provider-hosted checkout and links
 * to it. See docs/payments.md for how to point CHECKOUT_LINKS at a real Stripe or Square payment link.
 */
import type { Router } from 'express';
import { renderPage } from '../../lib/views.ts';
import { defineRoute } from '../../security/routes.ts';

/**
 * Provider-hosted checkout links, keyed by a short product/plan id. Nothing here is a secret — a "Payment Link"
 * (Stripe) or "Checkout Link" (Square) is a public URL the provider's own hosted page reads; replace the empty
 * string with that URL once the deploying developer has created one, per docs/payments.md.
 */
export const CHECKOUT_LINKS: Record<string, string> = {
  default: '',
};

export function register(router: Router): void {
  defineRoute(router, { method: 'GET', path: '/checkout', auth: 'user', summary: 'Provider-hosted checkout' }, (req, res) => {
    const link = CHECKOUT_LINKS['default'];
    renderPage(req, res, 'payments/checkout', { title: 'Checkout', checkoutLink: link || null });
  });
}
