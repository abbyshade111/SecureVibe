import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { bodyGuess, sampleFromSchema } from '../../src/scanners/dast/probes/util.js';

// Mirrors the shapes the CRUD expander emits (generator/expand-templates/fields.ts).
const optional = (rule: z.ZodType) => z.union([rule, z.literal('')]).optional().default('');
const number = (rule: z.ZodType) => z.preprocess((v) => (v === '' || v === null ? undefined : v), rule);
const Body = z.strictObject({
  customerName: z.string().trim().min(1, 'Please fill this in.').max(200),
  startsAt: z.string().trim().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/),
  day: optional(z.string().trim().regex(/^\d{4}-\d{2}-\d{2}$/)),
  dueOn: z.string().trim().regex(/^\d{4}-\d{2}-\d{2}$/),
  service: z.enum(['Cut', 'Color']),
  price: number(z.coerce.number().finite().min(0).max(99999999)),
  colour: z.union([z.enum(['Red', 'Blue']), z.literal('')]).optional(),
  reminder: z.boolean().optional().default(false),
  contact: z.string().email(),
  code: z.string().max(4),
});
const schema = z.toJSONSchema(Body, { io: 'input', unrepresentable: 'any' });

describe('DAST create-body sampling', () => {
  it('builds a body that the route schema accepts', () => {
    const sample = sampleFromSchema(schema, 'Runtime check');
    const parsed = Body.safeParse(sample);
    expect(parsed.error?.issues ?? []).toEqual([]);
  });

  it('bodyGuess prefers the schema and falls back to the generic shape', () => {
    const route = { method: 'POST' as const, path: '/api/appointments', auth: 'user', bodySchema: schema };
    expect(Body.safeParse(bodyGuess(route)).success).toBe(true);
    expect(bodyGuess({ ...route, bodySchema: null })).toEqual({ title: 'Runtime check', name: 'Runtime check' });
  });

  it('carries a probe payload only in free-text fields', () => {
    const sample = sampleFromSchema(schema, '<script>x</script>') as Record<string, unknown>;
    expect(sample.customerName).toBe('<script>x</script>');
    expect(sample.service).toBe('Cut');
    expect(sample.contact).toBe('runtime-check@example.com');
  });
});

describe('recorded request paths', () => {
  it('hide credential-like query values and keep the rest', async () => {
    const { redactPath } = await import('../../src/scanners/dast/http.js');
    expect(redactPath('/auth/token?t=abc123')).toBe('/auth/token?t=[redacted]');
    expect(redactPath('/x?api_key=k&page=2&Token=v')).toBe('/x?api_key=[redacted]&page=2&Token=[redacted]');
    expect(redactPath('/login?next=%2Fa')).toBe('/login?next=%2Fa');
    expect(redactPath('/plain')).toBe('/plain');
  });
});
