/**
 * The Security Contract: the rules the code generator must obey (CONTRACTS §6, SC-01..SC-25). Wording adapts to
 * the features that are on, but the ids and count never change.
 */
import type { SecurityContract, SecurityContractRule } from '@shared/design.js';
import type { ProfileFacts } from './conditions.js';

export const SECURITY_CONTRACT_VERSION = '1.0';

type Draft = Omit<SecurityContractRule, 'asvs' | 'aisvs' | 'enforcedBy'> & {
  asvs?: string[];
  aisvs?: string[];
  enforcedBy?: SecurityContractRule['enforcedBy'];
};

export function securityContractFor(f: ProfileFacts): SecurityContract {
  const rules: Draft[] = [
    {
      id: 'SC-01',
      rule: 'Register every route with defineRoute() and an explicit auth value (public, user or role:<name>). Never call app.get/router.post directly.',
      rationale: 'Deny-by-default authorization: a route without a declaration cannot exist, so nothing is exposed by accident.',
      asvs: ['V8.2.1', 'V8.3.1'],
      enforcedBy: ['template', 'sast', 'dast', 'tests'],
    },
    {
      id: 'SC-02',
      rule: 'Give every route strict zod schemas for params, query and body (z.object().strict()); the body schema is mandatory for POST, PUT and PATCH.',
      rationale: 'Server-side validation with unknown fields rejected stops injection, mass assignment and type confusion.',
      asvs: ['V2.2.1', 'V2.2.2', 'V15.3.3'],
      enforcedBy: ['template', 'sast', 'dast'],
    },
    {
      id: 'SC-03',
      rule: 'Access the database only through the src/db helpers (q, get, all, run, withTransaction) with parameters. Never build SQL from strings.',
      rationale: 'Parameterised queries are the only reliable protection against SQL injection.',
      asvs: ['V1.2.4'],
      enforcedBy: ['sast', 'template'],
    },
    {
      id: 'SC-04',
      rule: 'Return DTOs built with toPublicDto/toOwnerDto/toAdminDto; never send a raw database row to a view or JSON response.',
      rationale: 'Field-level shaping keeps hidden columns (hashes, internal flags, other people\'s data) out of responses.',
      asvs: ['V15.3.1', 'V8.2.3'],
      enforcedBy: ['sast', 'tests'],
    },
    {
      id: 'SC-05',
      rule: 'For records that belong to a person, declare owner: { entity, param, ownerField } on the route so the registry enforces ownership (administrators bypass).',
      rationale: 'Prevents one person reading or changing another person\'s records by changing an id (IDOR).',
      asvs: ['V8.2.2'],
      enforcedBy: ['template', 'dast', 'tests'],
    },
    {
      id: 'SC-06',
      rule: 'In EJS views use <%= %> only; never <%- %> for data. No inline <script> or event handlers: put scripts in public/js/features/ and include them through the layout nonce helper.',
      rationale: 'Auto-escaping plus the nonce-based Content-Security-Policy blocks cross-site scripting.',
      asvs: ['V1.2.1', 'V3.4.3'],
      enforcedBy: ['sast', 'dast'],
    },
    {
      id: 'SC-07',
      rule: 'Never use eval, new Function, the vm module or child_process.',
      rationale: 'Dynamic code execution turns any input bug into full compromise of the computer.',
      asvs: ['V1.3.2'],
      enforcedBy: ['sast'],
    },
    {
      id: 'SC-08',
      rule: 'Add no dependencies. Import only express, zod, ejs, pino, node:* and the template\'s own modules; package.json is protected.',
      rationale: 'The dependency set is locked and tested; unknown packages could carry vulnerabilities or install scripts.',
      asvs: ['V15.2.1', 'V15.1.2'],
      enforcedBy: ['sast', 'config', 'template'],
    },
    {
      id: 'SC-09',
      rule: 'Read secrets and settings only through the typed config module; never process.env directly, never a literal fallback secret.',
      rationale: 'Config validation refuses weak or placeholder secrets at startup and keeps secrets out of code.',
      asvs: ['V13.3.2'],
      enforcedBy: ['sast', 'config'],
    },
    {
      id: 'SC-10',
      rule: 'Log through logger and events.emit() only; never console.log; never log passwords, tokens, session ids or fields marked sensitive.',
      rationale: 'Structured logs with redaction are evidence in an incident; leaked secrets in logs are a breach.',
      asvs: ['V16.2.1', 'V16.2.5', 'V16.3.1'],
      enforcedBy: ['sast', 'tests'],
    },
    {
      id: 'SC-11',
      rule: f.externalApis || f.ai || f.email
        ? 'Make outbound HTTP calls only through lib/http-client outboundFetch(); the allowed hosts come from OUTBOUND_ALLOWED_HOSTS.'
        : 'Make no outbound HTTP calls; this app has no outside services.',
      rationale: 'The allow-list, timeouts and manual redirects stop server-side request forgery and hung requests.',
      asvs: ['V13.2.4', 'V15.3.2', 'V16.5.2'],
      enforcedBy: ['sast', 'tests'],
    },
    {
      id: 'SC-12',
      rule: f.uploads
        ? 'Accept files only through the uploads module (src/features/uploads); never parse multipart bodies yourself or write user-named files.'
        : 'Do not accept file uploads; the uploads module is not installed.',
      rationale: 'The uploads module enforces size, type, storage location and download headers.',
      asvs: ['V5.2.1', 'V5.2.2', 'V5.3.2'],
      enforcedBy: ['template', 'sast', 'dast'],
    },
    {
      id: 'SC-13',
      rule: f.ai
        ? 'Call the AI model only through the ai module (src/features/ai). You may edit prompt.ts and tools.ts; never call the SDK elsewhere or put secrets in prompts.'
        : 'Do not call any AI service; the AI module is not installed.',
      rationale: 'The AI module carries the input screening, output validation, logging, budgets and kill switch.',
      aisvs: ['C2.1.3', 'C7.1.1', 'C9.5.4', 'C12.1.1'],
      enforcedBy: ['template', 'sast', 'dast'],
    },
    {
      id: 'SC-14',
      rule: 'Redirect only with safeRedirect(res, target) to allow-listed local paths; never res.redirect(req.query.*).',
      rationale: 'Open redirects are used in phishing.',
      asvs: ['V3.7.2'],
      enforcedBy: ['sast', 'dast'],
    },
    {
      id: 'SC-15',
      rule: 'Wrap writes that touch more than one row or table in withTransaction().',
      rationale: 'Either the whole change happens or none of it; no half-updated records.',
      asvs: ['V2.3.3'],
      enforcedBy: ['sast', 'tests'],
    },
    {
      id: 'SC-16',
      rule: 'Add migrations as src/db/migrations/1NN_<name>.sql (numbers 100 and up), additive only; every list query has a LIMIT.',
      rationale: 'Template migrations stay intact; unbounded queries are a denial-of-service path.',
      asvs: ['V15.2.2'],
      enforcedBy: ['template', 'sast'],
    },
    {
      id: 'SC-17',
      rule: 'Write tests/features/<name>.test.ts for every feature with at least: anonymous denied, wrong role denied, invalid input rejected, and owner check (when the entity has an owner).',
      rationale: 'Tests are the strong evidence the compliance report relies on; without them a control is "not verified".',
      asvs: ['V8.2.1', 'V2.2.1'],
      enforcedBy: ['tests', 'ai-review'],
    },
    {
      id: 'SC-18',
      rule: 'Add an entry to routes.manifest.json for every route you create (method, path, auth, roles, owner, entity, kind, csrf).',
      rationale: 'The runtime scan probes every declared route as anonymous, wrong role and non-owner; an undeclared live route is a high finding.',
      asvs: ['V8.1.1'],
      enforcedBy: ['dast'],
    },
    {
      id: 'SC-19',
      rule: f.fieldEncryption
        ? 'Store fields marked sensitive with encryptField()/decryptField() from src/db/field-crypto; never store them in clear text.'
        : 'No field is marked sensitive. If you add one, use encryptField()/decryptField() from src/db/field-crypto.',
      rationale: 'Field-level encryption protects sensitive values if the database file is copied.',
      asvs: ['V11.3.2', 'V14.2.4'],
      enforcedBy: ['template', 'ai-review'],
    },
    {
      id: 'SC-20',
      rule: 'Never modify or delete protected paths (src/app.ts, src/server.ts, src/config.ts, src/db/*, src/security/**, src/lib/**, auth/account/admin/uploads/ai/apikeys features, layouts, tests/security/**, manifest, package files, scripts, docs).',
      rationale: 'These files implement the verified controls; their hashes are checked after generation.',
      asvs: ['V15.2.1'],
      enforcedBy: ['template', 'config', 'sast'],
    },
    {
      id: 'SC-21',
      rule: 'Use erasable TypeScript only (no enum, namespace, parameter properties), explicit .ts extensions in relative imports and "import type" for types.',
      rationale: 'The app runs with node --experimental-strip-types and no build step.',
      enforcedBy: ['template', 'lint'],
    },
    {
      id: 'SC-22',
      rule: 'Never put sensitive data (ids of sensitive records, emails, tokens, keys) in URLs or query strings; use POST bodies.',
      rationale: 'URLs end up in logs, browser history and referrers.',
      asvs: ['V14.2.1'],
      enforcedBy: ['sast', 'tests'],
    },
    {
      id: 'SC-23',
      rule: 'Enforce a per-person quota on records a person can create (as in src/features/_example) and check it inside the transaction.',
      rationale: 'Stops one account from filling the database.',
      asvs: ['V2.3.2', 'V2.4.1'],
      enforcedBy: ['tests', 'ai-review'],
    },
    {
      id: 'SC-24',
      rule: 'Keep the state of multi-step flows on the server (session or table), never in hidden form fields or client storage; validate the step order.',
      rationale: 'Client-held state can be edited to skip steps or change amounts.',
      asvs: ['V2.3.2'],
      enforcedBy: ['ai-review'],
    },
    {
      id: 'SC-25',
      rule: 'Start every generated code file with the provenance header comment: // Generated by SecureVibe (AI-generated) — run <runId>.',
      rationale: 'Provenance lets the reports and future reviewers tell generated code from template code.',
      aisvs: ['C12.1.1'],
      enforcedBy: ['config', 'sast'],
    },
  ];
  return {
    version: SECURITY_CONTRACT_VERSION,
    rules: rules.map((r) => ({ ...r, asvs: r.asvs ?? [], aisvs: r.aisvs ?? [], enforcedBy: r.enforcedBy ?? [] })),
  };
}
