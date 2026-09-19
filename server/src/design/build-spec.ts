/**
 * Feature toggles, session policy, package name and the generation brief for Claude. Everything here is a pure
 * function of the profile, so the same answers always produce the same brief (stable prompt caching, reproducible
 * runs, and a diff-able design).
 *
 * Feature decisions (documented here because the profile does not ask for them directly):
 *  - auth: on when the user asked for sign-in, when anyone beyond the owner uses the app, or when a feature needs an
 *    account to attribute records, quotas and budgets to a person (uploads, AI assistant, API keys, payments).
 *  - adminMfa: on with auth when the user kept the default, or forced on for sensitive data / sensitive fields.
 *  - userMfa: on with auth at target level 2 (every person may enrol an authenticator app).
 *  - aiModeration: on when the assistant is used by customers or the public.
 *  - email: on when asked for, or when accounts are created by invitation / open sign-up (those flows send links).
 *  - scheduler: on when asked for, or when records auto-delete (the retention job runs on the scheduler).
 *  - fieldEncryption: on for sensitive data categories or any entity field marked sensitive.
 *  - tlsMode: local-only → off, local-network → selfsigned, internet-later → proxy (set when deployed).
 */
import type { BuildSpec } from '@shared/design.js';
import type { DesignProfile, EntityField, EntitySpec } from '@shared/profile.js';
import {
  DATA_CATEGORY_LABELS,
  audiencePhrase,
  deploymentPhrase,
  listWords,
  profileFacts,
  type ProfileFacts,
} from './conditions.js';
import { securityContractFor } from './contract.js';

export function buildSpecFor(profile: DesignProfile): BuildSpec {
  const f = profileFacts(profile);
  return {
    features: featuresFor(f),
    packageName: packageNameFor(profile.app.name),
    sessionPolicy: sessionPolicyFor(f.level),
    brief: renderBrief(profile, f),
  };
}

export function featuresFor(f: ProfileFacts): BuildSpec['features'] {
  return {
    auth: f.auth,
    adminMfa: f.adminMfa,
    userMfa: f.userMfa,
    uploads: f.uploads,
    ai: f.ai,
    aiActions: f.aiActions,
    aiWebSearch: f.aiWebSearch,
    aiModeration: f.aiModeration,
    email: f.email,
    scheduler: f.scheduler,
    publicApi: f.publicApi,
    payments: f.payments,
    fieldEncryption: f.fieldEncryption,
    retentionJobs: f.retentionJobs,
    lanBinding: f.lanBinding,
    tlsMode: f.tlsMode,
  };
}

/** Session constants from CONTRACTS §1.3: 30 / 12 / 5 at level 1, 15 / 8 / 5 at level 2. */
export function sessionPolicyFor(level: 1 | 2): BuildSpec['sessionPolicy'] {
  return level === 2
    ? { idleMinutes: 15, absoluteHours: 8, maxConcurrent: 5 }
    : { idleMinutes: 30, absoluteHours: 12, maxConcurrent: 5 };
}

/** A valid npm package name derived from the app name ("Clinic Notes!" → "clinic-notes"). */
export function packageNameFor(appName: string): string {
  const base = appName
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60)
    .replace(/-+$/g, '');
  return /^[a-z0-9]/.test(base) ? base : 'generated-app';
}

const FIELD_TYPE_NOTES: Record<EntityField['type'], string> = {
  text: 'short text (zod string, max 200)',
  longtext: 'long text (zod string, max 10000)',
  number: 'number (zod number)',
  money: 'money amount stored as an integer in minor units (cents); never a float',
  date: 'date (ISO yyyy-mm-dd string, validated)',
  datetime: 'date and time (ISO string, validated)',
  boolean: 'yes/no (zod boolean)',
  email: 'email address (zod email, max 120)',
  url: 'web address (zod url, http/https only)',
  phone: 'phone number (zod string with a digits/+/spaces pattern, max 30)',
  choice: 'one of a fixed list (zod enum)',
  file: 'an uploaded file: store the upload id from the uploads module, never a path',
};

function accessRules(entity: EntitySpec, f: ProfileFacts): string {
  const admin = f.adminRole?.name ?? 'admin';
  if (!f.auth) {
    return 'This app has no sign-in: every route for this record uses auth "public". There are no owner checks.';
  }
  switch (entity.access) {
    case 'all-signed-in':
      return 'Any signed-in person may list, view, create, edit and delete these records. Routes use auth "user" with no owner check.';
    case 'owner-only':
      return `Each record belongs to the person who created it (owner_id column). Routes use auth "user" and declare owner: { entity: "${entity.name}", param: "id", ownerField: "owner_id" } so the registry enforces ownership; administrators see everything.`;
    case 'admin-only':
      return `Only administrators may see or change these records. Every route uses auth "role:${admin}".`;
    case 'public-read':
      return 'Anyone may list and view these records (auth "public" on GET routes); creating, editing and deleting require sign-in (auth "user"). Return the public DTO on public routes.';
  }
}

function fieldLine(field: EntityField): string {
  const bits = [`${field.name} (${field.label}): ${FIELD_TYPE_NOTES[field.type]}`];
  bits.push(field.required ? 'required' : 'optional');
  if (field.type === 'choice' && field.choices?.length) bits.push(`choices: ${field.choices.join(' | ')}`);
  if (field.sensitive) bits.push('SENSITIVE: store with encryptField()/decryptField(), redact from logs, never in URLs');
  if (field.description) bits.push(field.description);
  return `  - ${bits.join('; ')}`;
}

function entitySection(entity: EntitySpec, f: ProfileFacts): string[] {
  const lines = [`### ${entity.name} — ${entity.label}${entity.pluralLabel ? ` (plural: ${entity.pluralLabel})` : ''}`];
  if (entity.description) lines.push(entity.description);
  lines.push(`Access: ${accessRules(entity, f)}`);
  if (entity.fields.length === 0) {
    lines.push('Fields: none given beyond id, created_at, updated_at. Add a "title" text field and keep the record simple.');
  } else {
    lines.push('Fields (plus id, created_at, updated_at and, for owner-only records, owner_id):');
    for (const field of entity.fields) lines.push(fieldLine(field));
  }
  lines.push(
    `Build: migration src/db/migrations/1NN_${entity.name.replace(/-/g, '_')}.sql, module src/features/${entity.name}/ (routes.ts, repository.ts, dto.ts, views), pages under src/views/${entity.name}/, JSON API under /api/${entity.name}s, tests in tests/features/${entity.name}.test.ts. Mirror src/features/_example exactly (registry routes, strict schemas, DTOs, per-person quota, LIMIT on lists).`,
  );
  return lines;
}

function registrationPhrase(profile: DesignProfile): string {
  switch (profile.users.registration) {
    case 'open':
      return 'open sign-up (rate limited; provided by the template)';
    case 'invite-only':
      return 'invitation links sent by an administrator (provided by the template)';
    case 'admin-created':
      return 'accounts created by an administrator (provided by the template)';
  }
}

function featuresToBuild(profile: DesignProfile, f: ProfileFacts): string[] {
  const caps = profile.capabilities;
  const lines: string[] = [];
  if (profile.app.keyFeatures.length) {
    lines.push('Requested features (build each one on top of the records above):');
    for (const feature of profile.app.keyFeatures) lines.push(`- ${feature}`);
  } else {
    lines.push('No extra features were requested beyond managing the records above.');
  }
  if (f.ai) {
    const ai = caps.aiAssistant;
    const sees = {
      nothing: 'no stored records; it only sees the message typed by the person',
      'users-own-records': "only the signed-in person's own records, fetched through the repository functions scoped to req.user",
      'all-records': 'only records the signed-in person is allowed to see, fetched through the repository functions scoped to req.user',
    }[ai.dataItCanSee];
    lines.push(
      `- AI assistant: purpose "${ai.purpose || 'help people with this app'}". Edit only src/features/ai/prompt.ts (the system prompt, with the fixed instruction hierarchy kept intact) and src/features/ai/tools.ts. Data it may see: ${sees}. ${
        ai.canTakeActions
          ? 'It may take actions: define allow-listed tools in tools.ts with zod input/output schemas; every mutating tool returns a proposal the person confirms in the UI before the app executes it with req.user authorization.'
          : 'It may not take actions: tools.ts exports an empty tool list.'
      } ${ai.storesHistory ? 'Conversation history is kept per person (provided) and can be reset.' : 'No conversation history is stored.'}`,
    );
  }
  if (f.uploads) {
    const fileFields = profile.app.entities.flatMap((e) => e.fields.filter((fl) => fl.type === 'file').map((fl) => `${e.name}.${fl.name}`));
    lines.push(
      `- File uploads: use the provided uploads module for every file (kinds: ${listWords(caps.uploadKinds.length ? caps.uploadKinds : ['documents'])}). ${
        fileFields.length ? `Link uploads to records through these fields: ${listWords(fileFields)} (store the upload id).` : 'Link uploads to records with an upload id column where a feature needs them.'
      }`,
    );
  }
  if (f.email) {
    lines.push(
      `- Email: send notifications only through lib/mailer (templates from disk, header sanitisation). ${caps.email ? 'Add the notifications the requested features need.' : 'Only the account emails the template already sends (invitations, password reset) are required.'}`,
    );
  }
  if (f.scheduler) {
    lines.push(
      `- Scheduled jobs: declare jobs through lib/scheduler (registry-declared, locked, no user input in schedules). ${f.retentionJobs ? 'The data-retention job is provided; do not write another one.' : ''} ${caps.scheduledJobs ? 'Add the jobs the requested features need.' : ''}`.trim(),
    );
  }
  if (f.publicApi) {
    lines.push(
      '- Public API: expose the records as JSON routes under /api/v1 with kind "api", auth "user" and csrf false; the provided apikeys feature authenticates them with Bearer API keys. Add Idempotency-Key handling (idempotent: true) on mutations.',
    );
  }
  if (f.payments) {
    lines.push(
      '- Payments: use the provided placeholder checkout page in src/features/payments. Record orders with an amount in minor units and a status; never store, log or handle card numbers; only mark an order paid after the provider callback is verified through the app.',
    );
  }
  if (caps.externalApis.length) {
    for (const api of caps.externalApis) {
      // The host and whether a key exists are told to the agent plainly, because both decide what it can build.
      // Without a host there is nothing to put in OUTBOUND_ALLOWED_HOSTS, and the agent used to guess one or
      // quietly leave the connection unbuilt — while the reports told the owner her app only talks to the
      // services she named. An unbuildable connection must be left unbuilt *and said*, not invented.
      const reach = api.host
        ? `Its host is ${api.host}: add exactly that to OUTBOUND_ALLOWED_HOSTS in .env.example, with a comment.`
        : 'The owner did not give its address, so there is no host to allow: do not guess one and do not call it. Build everything else and say in the README that this connection is not set up yet.';
      const key =
        api.credentials === 'have'
          ? 'The owner has an account and key for it; read the key from the environment, never from code.'
          : 'The owner does not have an account or key for it yet, so the call cannot work: leave the code path in place, read the key from the environment, and fail cleanly with a message saying the service is not set up.';
      lines.push(
        `- Outside service "${api.name}": ${api.purpose || 'used by the app'}. Call it only through lib/http-client outboundFetch(). ${reach} ${key} ${
          api.sendsPersonalData ? 'It receives personal data: send the minimum fields and list them in the feature README section.' : 'Send no personal data to it.'
        }`,
      );
    }
  }
  return lines;
}

function providedByTemplate(f: ProfileFacts): string[] {
  const items = [
    'Express app with security headers (nonce CSP), body limits, request ids, structured logging, generic error pages, health endpoints, timeouts, graceful shutdown',
    'Route registry (defineRoute) with deny-by-default authorization, strict zod validation, CSRF protection, rate-limit presets, idempotency keys',
    'SQLite wrapper with parameterised queries, migrations runner, transactions, DTO helpers, per-person quota example (src/features/_example)',
    'Hash-chained audit log, security event catalog, log redaction',
    'Config module (typed, validated env), generated secrets, .env handling',
    'Outbound HTTP client with host allow-list, timeouts, circuit breaker',
    'Generated docs (docs:build), security tests (tests/security/**), routes:export, SBOM, incident-response and deployment guides',
  ];
  if (f.auth) {
    items.push(
      `Accounts: registration (${f.authReasons.length ? 'sign-in is on because ' + listWords(f.authReasons) : 'sign-in'}), login with lockout, logout, password change/reset, sessions with idle and absolute timeouts, account page (profile, sessions, data export/delete), admin pages (user management, audit log viewer)`,
    );
  }
  if (f.adminMfa) items.push('Authenticator-app (TOTP) enrolment, enforced for administrators' + (f.userMfa ? ' and available to every person' : ''));
  if (f.uploads) items.push('Uploads module: streaming size cap, magic-byte type checks, random names outside the web root, attachment downloads, quotas');
  if (f.ai) items.push('AI module: input normalisation and screening, instruction hierarchy, output validation, usage logging, budgets, kill switch' + (f.aiModeration ? ', content moderation' : '') + (f.aiActions ? ', confirmed tool proposals' : '') + (f.aiHistory ? ', per-person conversation history' : ''));
  if (f.email) items.push('Mailer (local outbox in development, SMTP via env) with header sanitisation');
  if (f.scheduler) items.push('Scheduler with a jobs table, locking and overlap protection' + (f.retentionJobs ? ', including the data-retention job' : ''));
  if (f.publicApi) items.push('API keys feature (/api/v1 Bearer keys, hashed at rest, revocable, per-key rate limit)');
  if (f.payments) items.push('Payments placeholder checkout page and provider setup guide');
  if (f.fieldEncryption) items.push('Field encryption helpers (AES-256-GCM, versioned keys, rotation command)');
  return items;
}

function dataRules(profile: DesignProfile, f: ProfileFacts): string[] {
  const lines: string[] = [];
  const categories = profile.data.categories.map((c) => DATA_CATEGORY_LABELS[c]);
  lines.push(`Information handled: ${categories.length ? listWords(categories) : 'business records only'}.${profile.data.aboutOtherPeople ? ' Some of it is about people other than the users.' : ''}`);
  if (f.sensitiveCategories.length) {
    lines.push(
      `Sensitive categories (${listWords(f.sensitiveCategories.map((c) => DATA_CATEGORY_LABELS[c]))}): store such values only in fields marked sensitive (encryptField), never log them, never put them in URLs, and return them only in the owner/admin DTOs.`,
    );
  }
  if (f.personalData) {
    lines.push(
      profile.data.retention === 'auto-delete-after-period'
        ? `Retention: records about people are deleted or pseudonymised after ${profile.data.retentionMonths ?? 12} months (RETENTION_MONTHS=${profile.data.retentionMonths ?? 12}); make sure every new table that stores personal data has a created_at column the retention job can use.`
        : 'Retention: records are kept until deleted; the account page export/delete functions must include every new table that stores personal data (add them to the export and delete hooks).',
    );
  }
  if (f.payments) lines.push('Card numbers are never stored or logged; the provider-hosted checkout handles them.');
  lines.push(`Target verification level: ${f.level} (${f.levelRule})`);
  return lines;
}

export function renderBrief(profile: DesignProfile, f: ProfileFacts): string {
  const app = profile.app;
  const contract = securityContractFor(f);
  const roles = f.roles.length
    ? f.roles.map((r) => `- ${r.name} (${r.label})${r.isAdmin ? ' — administrator' : ''}${r.description ? `: ${r.description}` : ''}`)
    : ['- (no accounts: this app has no sign-in)'];
  const sections: string[] = [];

  sections.push(`# Generation brief: ${app.name}`);
  sections.push(
    [
      '## Purpose',
      app.tagline ? `${app.tagline}` : '',
      app.description,
      `Kind of app: ${app.category}. Used by ${audiencePhrase(profile)}. Runs ${deploymentPhrase(profile)}.`,
    ]
      .filter(Boolean)
      .join('\n'),
  );
  sections.push(
    [
      '## People and roles',
      `Sign-in: ${f.auth ? `on (${listWords(f.authReasons)})` : 'off (single person on this computer; no accounts)'}.`,
      ...(f.auth ? [`Registration: ${registrationPhrase(profile)}.`, `Expected number of people: ${profile.users.expectedUserCount}.`] : []),
      ...(f.adminMfa ? ['Administrators must use an authenticator app (provided).'] : []),
      'Roles:',
      ...roles,
    ].join('\n'),
  );
  sections.push(['## Information and data rules', ...dataRules(profile, f)].join('\n'));
  sections.push(
    [
      '## Records to build',
      app.entities.length
        ? app.entities.map((e) => entitySection(e, f).join('\n')).join('\n\n')
        : 'No records were specified. Build one simple record type that fits the purpose above (for example "item" with title, notes and status) following src/features/_example.',
    ].join('\n'),
  );
  sections.push(['## Features to build', ...featuresToBuild(profile, f)].join('\n'));
  sections.push(['## Already provided by the template (do not rebuild, do not modify)', ...providedByTemplate(f).map((i) => `- ${i}`)].join('\n'));
  sections.push(
    [
      '## Where your code goes',
      '- Writable: src/features/<name>/**, src/features/index.ts (registration list only), src/views/<name>/**, src/db/migrations/1NN_*.sql (numbers 100 and up), tests/features/**, public/css/**, public/js/features/**, routes.manifest.json, README.md (append a section).',
      '- Everything else is protected and verified by hash after generation.',
      '- Allowed imports: express, zod, ejs, pino, node:* and the template\'s own modules. package.json is fixed.',
      `- Feature toggles in force: ${Object.entries(featuresFor(f))
        .map(([k, v]) => `${k}=${String(v)}`)
        .join(', ')}.`,
    ].join('\n'),
  );
  sections.push(
    [
      '## Security contract (every rule is checked after generation)',
      ...contract.rules.map((r) => `- ${r.id}: ${r.rule}`),
    ].join('\n'),
  );
  sections.push(
    [
      '## Definition of done',
      '- `npm run typecheck` and `npm test` pass (run_checks tool).',
      '- Every route is registered with defineRoute and listed in routes.manifest.json.',
      '- tests/features/<name>.test.ts exists for every feature with the four minimum tests (SC-17).',
      '- Each page renders through the base layout with the nonce helper; no inline scripts.',
      '- README.md gains a short section describing the features you added and how to use them.',
      '- Call the done tool with a one-paragraph summary when finished.',
    ].join('\n'),
  );
  return sections.join('\n\n') + '\n';
}
