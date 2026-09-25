// Clean fixture: a route that asks the assistant, on a page that says it is working.
import { Router } from 'express';
import { z } from 'zod';
import { defineRoute } from '../../security/routes.js';
import { getClient } from '../ai/providers.js';

export const router = Router();

defineRoute(router, { method: 'POST', path: '/research/run', auth: 'user', schema: { body: z.object({ topic: z.string() }) } }, async (req, res) => {
  const answer = await getClient().complete({ question: req.valid.body.topic });
  res.json({ answer: String(answer) });
});
