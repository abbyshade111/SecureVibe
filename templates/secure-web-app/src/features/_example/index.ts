/**
 * Reference feature: "notes". It shows every convention a generated feature must follow:
 *  - pages and a JSON API registered through defineRoute with explicit auth, strict schemas and owner checks,
 *  - DTOs instead of raw rows, a per-user quota inside a transaction, optimistic concurrency on update,
 *  - a two-step flow (publish) whose state lives in the server-side session, never in hidden form fields,
 *  - Idempotency-Key support on the API create call.
 * Mounted only when EXAMPLE_FEATURE=1.
 */
import type { Request, Response, Router } from 'express';
import { z } from 'zod';
import { clampLimit } from '../../db/index.ts';
import { errors } from '../../lib/errors.ts';
import { renderPage } from '../../lib/views.ts';
import { defineRoute } from '../../security/routes.ts';
import { schemas, type FieldErrors } from '../../security/validate.ts';
import {
  NOTE_QUOTA_PER_USER,
  createNote,
  deleteNote,
  listAllNotes,
  listNotesForOwner,
  publishNote,
  registerNotesEntity,
  toAdminDto,
  toOwnerDto,
  toPublicDto,
  updateNote,
  type NoteRow,
} from './repo.ts';

const NoteParams = z.strictObject({ id: schemas.id });
const ListQuery = z.strictObject({ page: schemas.page, limit: schemas.limit });
const NoteBody = z.strictObject({ title: z.string().trim().min(1).max(120), body: z.string().max(10000).default('') });
const NoteUpdateBody = NoteBody.extend({ updatedAt: schemas.isoDate });
const ApiPatchBody = z.strictObject({ title: z.string().trim().min(1).max(120).optional(), body: z.string().max(10000).optional(), updatedAt: schemas.isoDate });
const PublishStepBody = z.strictObject({ publishNote: z.string().trim().max(200).default(''), notify: schemas.bool.optional() });

interface PublishFlowState {
  publishNote: string;
  notify: boolean;
  startedAt: string;
}

const OWNER = { entity: 'note', param: 'id' } as const;

function noteFromRequest(req: Request): NoteRow {
  const row = req.entity as unknown as NoteRow | undefined;
  if (!row) throw errors.notFound();
  return row;
}

function dtoFor(req: Request, row: NoteRow) {
  return req.user?.isAdmin ? toAdminDto(row) : toOwnerDto(row);
}

function flowKey(noteId: string): string {
  return `flow:publish:${noteId}`;
}

function renderForm(req: Request, res: Response, fields: FieldErrors, status = 400): void {
  const body = (req.body ?? {}) as Record<string, unknown>;
  renderPage(req, res, '_example/form', {
    title: 'Note',
    errors: fields,
    values: { title: typeof body['title'] === 'string' ? body['title'] : '', body: typeof body['body'] === 'string' ? body['body'] : '' },
    note: req.entity ? toOwnerDto(req.entity as unknown as NoteRow) : null,
    quota: NOTE_QUOTA_PER_USER,
  }, status);
}

export function register(router: Router): void {
  registerNotesEntity();

  // ---------- Pages ----------
  defineRoute(router, { method: 'GET', path: '/notes', auth: 'user', entity: 'note', schema: { query: ListQuery }, summary: 'Your notes' }, (req, res) => {
    const { page, limit } = req.valid.query;
    const size = clampLimit(limit);
    const rows = req.user!.isAdmin ? listAllNotes(size, (page - 1) * size) : listNotesForOwner(req.user!.id, size, (page - 1) * size);
    renderPage(req, res, '_example/list', { title: 'Notes', notes: rows.map((r) => dtoFor(req, r)), page, hasMore: rows.length === size, quota: NOTE_QUOTA_PER_USER });
  });

  defineRoute(router, { method: 'GET', path: '/notes/new', auth: 'user', entity: 'note', summary: 'New note form' }, (req, res) => {
    renderPage(req, res, '_example/form', { title: 'New note', note: null, values: { title: '', body: '' }, quota: NOTE_QUOTA_PER_USER });
  });

  defineRoute(
    router,
    { method: 'POST', path: '/notes', auth: 'user', entity: 'note', schema: { body: NoteBody }, onInvalid: (req, res, fields) => renderForm(req, res, fields), summary: 'Create a note' },
    (req, res) => {
      const result = createNote(req.user!.id, req.valid.body);
      if (!result.ok) {
        const message = result.reason === 'quota' ? `You can keep up to ${NOTE_QUOTA_PER_USER} notes. Delete one to make room.` : 'You already have a note with this title.';
        return renderForm(req, res, { title: message }, 409);
      }
      req.session.flash('success', 'Note created.');
      res.redirect(303, `/notes/${result.note.id}`);
    },
  );

  defineRoute(router, { method: 'GET', path: '/notes/:id', auth: 'user', owner: OWNER, entity: 'note', schema: { params: NoteParams }, summary: 'View a note' }, (req, res) => {
    renderPage(req, res, '_example/show', { title: 'Note', note: dtoFor(req, noteFromRequest(req)) });
  });

  defineRoute(router, { method: 'GET', path: '/notes/:id/edit', auth: 'user', owner: OWNER, entity: 'note', schema: { params: NoteParams }, summary: 'Edit a note' }, (req, res) => {
    const note = toOwnerDto(noteFromRequest(req));
    renderPage(req, res, '_example/form', { title: 'Edit note', note, values: { title: note.title, body: note.body }, quota: NOTE_QUOTA_PER_USER });
  });

  defineRoute(
    router,
    {
      method: 'POST',
      path: '/notes/:id',
      auth: 'user',
      owner: OWNER,
      entity: 'note',
      schema: { params: NoteParams, body: NoteUpdateBody },
      onInvalid: (req, res, fields) => renderForm(req, res, fields),
      summary: 'Save changes to a note (optimistic concurrency)',
    },
    (req, res) => {
      const note = noteFromRequest(req);
      const { updatedAt, ...input } = req.valid.body;
      const result = updateNote(note.id, input, updatedAt);
      if (!result.ok) {
        const message =
          result.reason === 'conflict'
            ? 'This note was changed since you opened it. Reload the page to see the latest version, then apply your change again.'
            : result.reason === 'duplicate'
              ? 'You already have a note with this title.'
              : 'This note no longer exists.';
        return renderForm(req, res, { _: message }, result.reason === 'not-found' ? 404 : 409);
      }
      req.session.flash('success', 'Note saved.');
      res.redirect(303, `/notes/${note.id}`);
    },
  );

  defineRoute(router, { method: 'POST', path: '/notes/:id/delete', auth: 'user', owner: OWNER, entity: 'note', schema: { params: NoteParams }, summary: 'Delete a note' }, (req, res) => {
    deleteNote(noteFromRequest(req).id);
    req.session.delete(flowKey(req.valid.params.id));
    req.session.flash('success', 'Note deleted.');
    res.redirect(303, '/notes');
  });

  // ---------- Two-step flow with server-side state ----------
  defineRoute(router, { method: 'GET', path: '/notes/:id/publish', auth: 'user', owner: OWNER, entity: 'note', schema: { params: NoteParams }, summary: 'Publish a note: step 1' }, (req, res) => {
    const note = toOwnerDto(noteFromRequest(req));
    const state = req.session.get<PublishFlowState>(flowKey(note.id));
    renderPage(req, res, '_example/publish-step1', { title: 'Publish note — step 1 of 2', note, values: { publishNote: state?.publishNote ?? '', notify: state?.notify ?? false } });
  });

  defineRoute(
    router,
    {
      method: 'POST',
      path: '/notes/:id/publish',
      auth: 'user',
      owner: OWNER,
      entity: 'note',
      schema: { params: NoteParams, body: PublishStepBody },
      onInvalid: (req, res, fields) => renderPage(req, res, '_example/publish-step1', { title: 'Publish note — step 1 of 2', note: toOwnerDto(noteFromRequest(req)), errors: fields, values: {} }, 400),
      summary: 'Publish a note: store step 1 choices in the session',
    },
    (req, res) => {
      const note = noteFromRequest(req);
      const state: PublishFlowState = { publishNote: req.valid.body.publishNote, notify: req.valid.body.notify ?? false, startedAt: new Date().toISOString() };
      req.session.set(flowKey(note.id), state);
      res.redirect(303, `/notes/${note.id}/publish/confirm`);
    },
  );

  defineRoute(router, { method: 'GET', path: '/notes/:id/publish/confirm', auth: 'user', owner: OWNER, entity: 'note', schema: { params: NoteParams }, summary: 'Publish a note: step 2 (confirm)' }, (req, res) => {
    const note = toOwnerDto(noteFromRequest(req));
    // The choices live in the server-side session, never in hidden fields; without them the page asks to start at step 1.
    const state = req.session.get<PublishFlowState>(flowKey(note.id)) ?? null;
    renderPage(req, res, '_example/publish-confirm', { title: 'Publish note — step 2 of 2', note, state });
  });

  defineRoute(
    router,
    { method: 'POST', path: '/notes/:id/publish/confirm', auth: 'user', owner: OWNER, entity: 'note', schema: { params: NoteParams }, summary: 'Publish a note: apply the choices stored in the session' },
    (req, res) => {
      const note = noteFromRequest(req);
      const state = req.session.get<PublishFlowState>(flowKey(note.id));
      if (!state) return res.redirect(303, `/notes/${note.id}/publish`);
      publishNote(note.id, state.publishNote || null);
      req.session.delete(flowKey(note.id));
      req.session.flash('success', state.notify ? 'Note published. (Notifications would be sent here.)' : 'Note published.');
      res.redirect(303, `/notes/${note.id}`);
    },
  );

  // ---------- JSON API ----------
  defineRoute(router, { method: 'GET', path: '/api/notes', auth: 'user', kind: 'api', entity: 'note', schema: { query: ListQuery }, summary: 'List your notes' }, (req, res) => {
    const { page, limit } = req.valid.query;
    const size = clampLimit(limit);
    const rows = req.user!.isAdmin ? listAllNotes(size, (page - 1) * size) : listNotesForOwner(req.user!.id, size, (page - 1) * size);
    res.json({ notes: rows.map((r) => (req.user!.isAdmin ? toAdminDto(r) : toPublicDto(r))), page, limit: size });
  });

  defineRoute(
    router,
    { method: 'POST', path: '/api/notes', auth: 'user', kind: 'api', entity: 'note', idempotent: true, schema: { body: NoteBody }, summary: 'Create a note (supports Idempotency-Key)' },
    (req, res) => {
      const result = createNote(req.user!.id, req.valid.body);
      if (!result.ok) throw result.reason === 'quota' ? errors.quota(`You can keep up to ${NOTE_QUOTA_PER_USER} notes.`) : errors.conflict('You already have a note with this title.');
      // Single records are returned as their DTO; lists are wrapped ({ notes, page, limit }).
      res.status(201).json(toOwnerDto(result.note));
    },
  );

  defineRoute(router, { method: 'GET', path: '/api/notes/:id', auth: 'user', kind: 'api', owner: OWNER, entity: 'note', schema: { params: NoteParams }, summary: 'Read one note' }, (req, res) => {
    res.json(dtoFor(req, noteFromRequest(req)));
  });

  defineRoute(
    router,
    { method: 'PATCH', path: '/api/notes/:id', auth: 'user', kind: 'api', owner: OWNER, entity: 'note', schema: { params: NoteParams, body: ApiPatchBody }, summary: 'Update a note (send the updatedAt you last saw)' },
    (req, res) => {
      const note = noteFromRequest(req);
      const { updatedAt, ...input } = req.valid.body;
      const result = updateNote(note.id, input, updatedAt);
      if (!result.ok) {
        if (result.reason === 'not-found') throw errors.notFound();
        throw errors.conflict(result.reason === 'duplicate' ? 'You already have a note with this title.' : undefined);
      }
      res.json(toOwnerDto(result.note));
    },
  );

  defineRoute(router, { method: 'DELETE', path: '/api/notes/:id', auth: 'user', kind: 'api', owner: OWNER, entity: 'note', schema: { params: NoteParams }, summary: 'Delete a note' }, (req, res) => {
    deleteNote(noteFromRequest(req).id);
    res.status(204).end();
  });
}
