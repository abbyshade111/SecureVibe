/**
 * The fixed list of things the assistant is allowed to touch. This file and prompt.ts are the two files of the
 * AI feature the generation agent may change, so an app can offer its own actions here.
 *
 * Two rules hold for every entry, and the rest of the feature enforces them:
 *  - Reading runs straight away, but only through a repository function that is scoped to the signed-in person.
 *  - Changing anything never runs from the model's reply. It becomes a proposal (ai_proposals) that the person
 *    confirms with POST /ai/confirm/:id, after which the app performs it through the ordinary repository
 *    function with that person's own authorization. The model never carries anything out.
 *
 * Inputs and outputs are validated against the schemas below, both when a proposal is made and again when it is
 * carried out — a stored proposal is data like any other and is checked before it is used.
 */
import { z, type ZodType } from 'zod';
import { getEntity, listEntities } from '../../security/authz.ts';
import type { SessionUser } from '../auth/repo.ts';

export interface ToolDefinition {
  name: string;
  /** One plain sentence; this is what the assistant is told the tool does. */
  description: string;
  /** Mutating tools become proposals; reading tools run immediately when the context is assembled. */
  mutates: boolean;
  input: ZodType;
  output: ZodType;
  /** Whether this tool exists for this app and this person at all. */
  available(user: SessionUser): boolean;
  /** Plain-language sentence shown on the confirmation card. */
  summarise(input: unknown): string;
  run(user: SessionUser, input: unknown): Promise<unknown>;
}

// ---------------------------------------------------------------------------------------------------------
// Reading: the person's own records, through each feature's own export function
// ---------------------------------------------------------------------------------------------------------

const ListInput = z.strictObject({
  entity: z.string().regex(/^[A-Za-z0-9_-]{1,40}$/).optional(),
  limit: z.number().int().min(1).max(50).optional(),
});
const ListOutput = z.strictObject({
  records: z.array(z.strictObject({ entity: z.string(), label: z.string(), data: z.unknown() })),
});

const listMyRecords: ToolDefinition = {
  name: 'list_my_records',
  description: 'Lists the records that belong to the person asking, so their question can be answered from them.',
  mutates: false,
  input: ListInput,
  output: ListOutput,
  available: () => listEntities().some((e) => typeof e.exportForUser === 'function'),
  summarise: () => 'Read your own records.',
  run: (user, input) => {
    const parsed = ListInput.parse(input);
    const records: { entity: string; label: string; data: unknown }[] = [];
    for (const entity of listEntities()) {
      if (parsed.entity && entity.name !== parsed.entity) continue;
      if (typeof entity.exportForUser !== 'function') continue;
      // exportForUser is the feature's own, user-scoped query: it can only ever return this person's rows.
      const data = entity.exportForUser(user.id);
      const limited = Array.isArray(data) ? data.slice(0, parsed.limit ?? 20) : data;
      records.push({ entity: entity.name, label: entity.label ?? entity.name, data: limited });
    }
    return Promise.resolve(ListOutput.parse({ records }));
  },
};

// ---------------------------------------------------------------------------------------------------------
// Changing: a proposal the person confirms
// ---------------------------------------------------------------------------------------------------------

const CreateNoteInput = z.strictObject({
  title: z.string().trim().min(1).max(120),
  body: z.string().max(10000).default(''),
});
const CreateNoteOutput = z.strictObject({ id: z.string(), title: z.string() });

/**
 * The reference feature's repository, loaded only when it is really there. The path is built at runtime so the
 * app still starts (and still type-checks) in an app where the reference feature was removed.
 */
async function notesRepository(): Promise<{ createNote(ownerId: string, input: { title: string; body: string }): { ok: boolean; note?: { id: string; title: string }; reason?: string } }> {
  const url = new URL('../_example/repo.ts', import.meta.url).href;
  return (await import(url)) as { createNote(ownerId: string, input: { title: string; body: string }): { ok: boolean; note?: { id: string; title: string }; reason?: string } };
}

const createNote: ToolDefinition = {
  name: 'create_note',
  description: 'Proposes a new note for the person asking. Nothing is saved until they confirm it.',
  mutates: true,
  input: CreateNoteInput,
  output: CreateNoteOutput,
  available: () => getEntity('note') !== undefined,
  summarise: (input) => {
    const parsed = CreateNoteInput.safeParse(input);
    return parsed.success ? `Create a note called “${parsed.data.title}”.` : 'Create a note.';
  },
  run: async (user, input) => {
    const parsed = CreateNoteInput.parse(input);
    const repo = await notesRepository();
    // The ordinary repository function, with this person as the owner: quota, uniqueness and the transaction
    // all apply exactly as they do when the person uses the form themselves.
    const result = repo.createNote(user.id, { title: parsed.title, body: parsed.body });
    if (!result.ok || !result.note) throw new Error(result.reason === 'quota' ? 'You have reached the limit for notes.' : 'You already have a note with this title.');
    return CreateNoteOutput.parse({ id: result.note.id, title: result.note.title });
  },
};

// ---------------------------------------------------------------------------------------------------------
// The allow-list
// ---------------------------------------------------------------------------------------------------------

const ALL_TOOLS: ToolDefinition[] = [listMyRecords, createNote];

/** Every tool defined for this app (used by docs/ai.md). */
export function allTools(): ToolDefinition[] {
  return [...ALL_TOOLS];
}

/** The tools that exist for this person right now. `withActions` is false when the ai-actions feature is off. */
export function toolsFor(user: SessionUser, withActions: boolean): ToolDefinition[] {
  return ALL_TOOLS.filter((tool) => (tool.mutates ? withActions : true) && tool.available(user));
}

export function findTool(name: string): ToolDefinition | undefined {
  return ALL_TOOLS.find((tool) => tool.name === name);
}

/** Validates a tool input against its schema. Used when a proposal is made and again before it is carried out. */
export function validateToolInput(tool: ToolDefinition, input: unknown): { ok: true; input: unknown } | { ok: false; message: string } {
  const parsed = tool.input.safeParse(input);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const where = first && first.path.length > 0 ? `${first.path.map(String).join('.')}: ` : '';
    return { ok: false, message: `${where}${first?.message ?? 'the details of this action are not valid'}` };
  }
  return { ok: true, input: parsed.data };
}
