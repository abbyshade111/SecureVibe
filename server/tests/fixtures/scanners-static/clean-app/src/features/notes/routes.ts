// Clean fixture: routes registered through defineRoute() with an explicit auth value, a validated
// schema, and a DTO on the way out (CONTRACTS §1 conventions).
import { Router } from 'express';
import { z } from 'zod';
import { defineRoute } from '../../security/routes.js';
import { findNoteById } from './repo.js';
import { toPublicDto } from './dto.js';

export const router = Router();

defineRoute(
  router,
  { method: 'GET', path: '/notes/:id', auth: 'user', schema: { params: z.object({ id: z.string() }) } },
  async (req, res) => {
    const row = findNoteById(req.valid.params.id!);
    if (!row) {
      res.status(404).json({ error: { code: 'not_found', message: 'Note not found' } });
      return;
    }
    res.json(toPublicDto(row));
  },
);

defineRoute(
  router,
  { method: 'POST', path: '/notes', auth: 'user', schema: { body: z.object({ title: z.string().min(1).max(200) }) } },
  async (req, res) => {
    const { title } = req.valid.body;
    res.status(201).json({ title });
  },
);
