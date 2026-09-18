// Fixture: route-registry rules (CONTRACTS §3) — a raw DB row sent to the client, a route with no auth,
// a route reading req.body without a schema, a GET route with a sensitive query field, and a route that
// bypasses defineRoute() entirely.
import { Router } from 'express';
import { z } from 'zod';
import { get } from '../../db/index.js';
import { defineRoute } from '../../security/routes.js';

export const router = Router();

defineRoute(
  router,
  { method: 'GET', path: '/notes/:id', auth: 'user', schema: { params: z.object({ id: z.string() }) } },
  async (req, res) => {
    const row = get('SELECT * FROM notes WHERE id = ?', [req.valid.params.id]);
    res.json(row);
  },
);

defineRoute(router, { method: 'GET', path: '/notes/public-missing-auth', schema: {} }, async (_req, res) => {
  res.json({ ok: true });
});

defineRoute(router, { method: 'POST', path: '/notes/raw-body', auth: 'user' }, async (req, res) => {
  const title = req.body.title;
  res.json({ title });
});

defineRoute(
  router,
  { method: 'GET', path: '/notes/search', auth: 'user', schema: { query: z.object({ password: z.string() }) } },
  async (_req, res) => {
    res.json({ ok: true });
  },
);

router.get('/legacy', (_req, res) => {
  res.send('ok');
});
