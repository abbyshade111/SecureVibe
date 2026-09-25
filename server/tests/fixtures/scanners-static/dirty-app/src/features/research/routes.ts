// Fixture: sast.assistant-form-no-working-state — a route that asks the assistant. Its view (src/views/research)
// has one form that says it is working, one that does not, and a form that posts somewhere else entirely.
import { Router } from 'express';
import { z } from 'zod';
import { defineRoute } from '../../security/routes.js';
import { getClient } from '../ai/providers.js';

export const router = Router();

async function askForTopic(topic: string): Promise<string> {
  const answer = await getClient().complete({ question: topic });
  return String(answer);
}

defineRoute(router, { method: 'POST', path: '/research/run', auth: 'user', schema: { body: z.object({ topic: z.string() }) } }, async (req, res) => {
  res.json({ answer: await askForTopic(req.valid.body.topic) });
});

// The assistant is used directly in the handler, not through a helper.
defineRoute(router, { method: 'POST', path: '/research/quick', auth: 'user', schema: { body: z.object({ topic: z.string() }) } }, async (req, res) => {
  res.json({ answer: String(await getClient().complete({ question: req.valid.body.topic })) });
});

// A path parameter: the view fills in the id.
defineRoute(router, { method: 'POST', path: '/research/:id/rerun', auth: 'user', schema: { params: z.object({ id: z.string() }) } }, async (req, res) => {
  res.json({ answer: await askForTopic(req.valid.params.id) });
});

// The same path answers two ways: showing it asks the assistant, and the button on it only clears the list.
defineRoute(router, { method: 'GET', path: '/research/history', auth: 'user', schema: {} }, async (_req, res) => {
  res.json({ answer: await askForTopic('what was asked before') });
});
defineRoute(router, { method: 'POST', path: '/research/history', auth: 'user', schema: {} }, async (_req, res) => {
  res.json({ cleared: true });
});
