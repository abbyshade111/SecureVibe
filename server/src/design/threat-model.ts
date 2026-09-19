/**
 * SbD step 7: a rule-based STRIDE threat model. One threat set per data flow that crosses a trust boundary,
 * plus per-component threats. Mitigations reference template controls (TPL-*) or patterns (PAT-*) and the
 * ASVS / AISVS requirements that verify them. An LLM-generated model may replace this one later
 * (the caller keeps a Claude model for the same profile hash).
 */
import type { Threat, ThreatModel } from '@shared/design.js';
import type { Architecture } from '@shared/design.js';
import type { DesignProfile } from '@shared/profile.js';
import { COMPONENT_IDS, FLOW_IDS, externalApiComponentId, externalApiFlowId } from './architecture.js';
import { DATA_CATEGORY_LABELS, listWords, type ProfileFacts } from './conditions.js';

type Level = 'low' | 'medium' | 'high';
type Mitigation = Threat['mitigations'][number];

interface Draft {
  stride: Threat['stride'];
  target: string;
  description: string;
  likelihood: Level;
  impact: Level;
  mitigations: Mitigation[];
  status: Threat['status'];
  actionItems?: string[];
}

const LEVEL_VALUE: Record<Level, number> = { low: 1, medium: 2, high: 3 };
const LEVELS: Level[] = ['low', 'medium', 'high'];

function shift(level: Level, by: number): Level {
  const index = Math.min(2, Math.max(0, LEVELS.indexOf(level) + by));
  return LEVELS[index] ?? level;
}

export function riskLevel(likelihood: Level, impact: Level): Level {
  const product = LEVEL_VALUE[likelihood] * LEVEL_VALUE[impact];
  if (product >= 6) return 'high';
  if (product >= 3) return 'medium';
  return 'low';
}

const m = (control: string, description: string, requirementIds: string[] = []): Mitigation => ({
  control,
  description,
  requirementIds,
});

export function buildThreatModel(profile: DesignProfile, f: ProfileFacts, arch: Architecture, now: Date): ThreatModel {
  const name = f.appName;
  const dataImpact: Level = shift(f.sensitiveData || f.sensitiveFields ? 'high' : f.personalData ? 'medium' : 'low', f.highImpact ? 1 : 0);
  const exposure: Level = shift(
    profile.users.audience === 'public' ? 'high' : profile.users.audience === 'customers' ? 'medium' : 'low',
    f.internet ? 1 : f.deployment === 'local-only' ? -1 : 0,
  );
  const drafts: Draft[] = [];
  const add = (d: Draft) => drafts.push(d);

  // Browser -> app (always crosses the boundary)
  if (f.auth) {
    add({
      stride: 'spoofing',
      target: FLOW_IDS.browserToApp,
      description: 'Someone signs in as another person by guessing a password, reusing a leaked one, or stealing a session cookie.',
      likelihood: exposure,
      impact: dataImpact,
      mitigations: [
        m('TPL-AUTH-01', '12+ character passwords checked against common-password lists', ['V6.2.1', 'V6.2.4']),
        m('TPL-AUTH-05', 'Sign-in attempts are limited per account and address with backoff', ['V6.3.1']),
        m('TPL-SESSION-01', 'Random session ids stored hashed; verified on the server', ['V7.2.1']),
        m('TPL-COOKIE-01', 'Session cookie HttpOnly and SameSite=Strict', ['V3.3.2']),
        ...(f.adminMfa ? [m('TPL-MFA-01', 'Administrators need an authenticator app code', ['V6.5.1', 'V6.5.3'])] : []),
        ...(f.userMfa ? [m('TPL-MFA-04', 'Every person can turn on an authenticator app', ['V6.3.3'])] : []),
      ],
      status: 'mitigated',
    });
    add({
      stride: 'elevation-of-privilege',
      target: FLOW_IDS.browserToApp,
      description: "A signed-in person opens administrator pages or other people's records by changing a web address.",
      likelihood: exposure,
      impact: dataImpact,
      mitigations: [
        m('TPL-AUTHZ-01', 'Every route declares who may call it; anything else is denied', ['V8.2.1', 'V8.3.1']),
        m('TPL-AUTHZ-02', 'Owner checks on records that belong to a person', ['V8.2.2']),
        m('TPL-DTO-01', 'Only the fields a person may see are returned', ['V15.3.1', 'V8.2.3']),
      ],
      status: 'mitigated',
    });
    add({
      stride: 'repudiation',
      target: FLOW_IDS.browserToApp,
      description: 'Someone denies having signed in or changed something, and there is no reliable record.',
      likelihood: 'low',
      impact: f.personalData ? 'medium' : 'low',
      mitigations: [
        m('TPL-LOG-03', 'Sign-ins, denials and administrator actions are logged', ['V16.3.1', 'V16.3.2']),
        m('TPL-LOG-05', 'Hash-chained audit log kept for at least 12 months', ['V16.4.2']),
      ],
      status: 'mitigated',
    });
  }
  add({
    stride: 'tampering',
    target: FLOW_IDS.browserToApp,
    description: 'Crafted input (injection, cross-site request forgery, oversized or unexpected fields) changes data or behaviour.',
    likelihood: exposure,
    impact: dataImpact,
    mitigations: [
      m('TPL-VALIDATION-01', 'Strict server-side schemas; unknown fields rejected', ['V2.2.1', 'V2.2.2', 'V15.3.3']),
      m('TPL-DB-01', 'Parameterised queries only', ['V1.2.4']),
      m('TPL-VIEWS-01', 'Auto-escaped templates, no inline scripts', ['V1.2.1', 'V3.4.3']),
      ...(f.auth ? [m('TPL-CSRF-01', 'Synchronizer token plus Origin check on every state change', ['V3.5.1'])] : []),
      m('TPL-BODY-01', 'Body size limits, parameter and prototype pollution rejected', ['V15.3.6']),
    ],
    status: 'mitigated',
  });
  const transitOpen = f.internet;
  add({
    stride: 'information-disclosure',
    target: FLOW_IDS.browserToApp,
    description:
      f.deployment === 'local-only'
        ? 'Pages or error messages reveal internal details, or a shared computer keeps pages in its cache.'
        : 'Traffic is read on the network, or pages and error messages reveal internal details.',
    likelihood: f.deployment === 'local-only' ? 'low' : exposure,
    impact: dataImpact,
    mitigations: [
      m('TPL-ERRORS-01', 'Generic error pages; no stack traces', ['V16.5.1']),
      m('TPL-HEADERS-01', 'Strict Content-Security-Policy and security headers', ['V3.4.3']),
      ...(f.auth ? [m('TPL-CACHE-01', 'No caching of signed-in pages', ['V14.3.2']), m('TPL-CLEAR-01', 'Browser data cleared on logout', ['V14.3.1'])] : []),
      ...(f.tlsMode === 'selfsigned' ? [m('TPL-TLS-01', 'TLS 1.2+ with a self-signed certificate on the local network', ['V12.1.1'])] : []),
      ...(f.tlsMode === 'proxy' ? [m('TPL-HEADERS-03', 'HSTS and secure cookies once behind the HTTPS proxy', ['V3.4.1', 'V3.3.1'])] : []),
      ...(f.deployment === 'local-only' ? [m('TPL-TRUSTZONES-01', 'Listens on 127.0.0.1 only; no network path', [])] : []),
    ],
    status: transitOpen ? 'open' : 'mitigated',
    actionItems: transitOpen ? [`Put ${name} behind an HTTPS reverse proxy with a real certificate before it goes online (docs/deployment.md).`] : [],
  });
  add({
    stride: 'denial-of-service',
    target: FLOW_IDS.browserToApp,
    description: 'Floods of requests, slow connections or huge bodies make the app unavailable.',
    likelihood: shift(exposure, -1),
    impact: f.highImpact ? 'high' : 'medium',
    mitigations: [
      m('TPL-RATE-01', 'Rate limits on sign-in, sign-up, reset and general traffic', ['V2.4.1']),
      m('TPL-BODY-01', 'Request body size limits', []),
      m('TPL-RESILIENCE-01', 'Request timeouts, health checks and graceful shutdown', ['V15.2.2']),
    ],
    status: 'mitigated',
  });

  // App -> AI provider
  if (f.ai) {
    add({
      stride: 'tampering',
      target: FLOW_IDS.appToAi,
      description: 'Text typed by a person (or hidden inside a record) tricks the assistant into ignoring its rules (prompt injection).',
      likelihood: shift(exposure, 1),
      impact: f.aiActions ? 'high' : dataImpact,
      mitigations: [
        m('TPL-AI-03', 'Injection patterns are blocked and logged', ['C2.1.3', 'C12.2.1']),
        m('TPL-AI-04', 'Instruction hierarchy; records wrapped as untrusted data', ['C2.1.6']),
        m('TPL-AI-01', 'Input normalised; control characters and reserved tokens rejected', ['C2.1.1', 'C2.1.5', 'C2.1.7']),
      ],
      status: 'mitigated',
    });
    add({
      stride: 'information-disclosure',
      target: FLOW_IDS.appToAi,
      description: "The assistant reveals other people's records, or its own instructions.",
      likelihood: profile.capabilities.aiAssistant.dataItCanSee === 'nothing' ? 'low' : 'medium',
      impact: dataImpact,
      mitigations: [
        m('TPL-AI-04', "Data is fetched only through the signed-in person's permissions", ['C5.2.1', 'C9.5.3']),
        m('TPL-AI-05', 'Answers are schema-checked, filtered for private data and rendered as plain text', ['C7.1.1', 'C7.3.2', 'C5.2.4']),
      ],
      status: 'mitigated',
    });
    add({
      stride: 'denial-of-service',
      target: FLOW_IDS.appToAi,
      description: 'Runaway or abusive use runs up the AI bill or exhausts the provider quota.',
      likelihood: exposure,
      impact: 'medium',
      mitigations: [
        m('TPL-AI-06', 'Per-person daily token budget and usage logging', ['C9.1.2', 'C12.2.5']),
        m('TPL-AI-07', 'Administrator kill switch', ['C9.6.1', 'C12.4.3']),
        m('TPL-RATE-01', '20 requests per hour per person', ['C11.2.2']),
      ],
      status: 'mitigated',
    });
    add({
      stride: 'spoofing',
      target: FLOW_IDS.appToAi,
      description: 'The provider API key leaks (in logs, in a prompt or in generated text) and someone else uses it.',
      likelihood: 'low',
      impact: 'medium',
      mitigations: [
        m('TPL-AI-08', 'Key read from the environment only; never in the model context', ['C9.5.4']),
        m('TPL-SECRETS-01', 'Secrets only in .env with strict permissions', ['V13.3.2']),
        m('TPL-LOG-02', 'Secrets redacted from logs', ['V16.2.5']),
      ],
      status: 'mitigated',
    });
    if (f.aiActions) {
      add({
        stride: 'elevation-of-privilege',
        target: FLOW_IDS.appToAi,
        description: 'The assistant performs a change the person did not intend, or one they are not allowed to make.',
        likelihood: 'medium',
        impact: 'high',
        mitigations: [
          m('TPL-AI-ACTIONS-01', 'Fixed tool list; every change is a proposal the person confirms; app logic checks permissions', ['C9.2.1', 'C9.3.2', 'C9.5.1']),
        ],
        status: 'mitigated',
      });
    }
    if (f.aiModeration) {
      add({
        stride: 'tampering',
        target: FLOW_IDS.appToAi,
        description: 'The assistant is used to produce or spread harmful content.',
        likelihood: 'medium',
        impact: 'medium',
        mitigations: [m('TPL-AI-10', 'Input and output screened by a content classifier', ['C2.2.1', 'C7.3.1'])],
        status: 'mitigated',
      });
    }
  }

  // Uploads
  if (f.uploads) {
    add({
      stride: 'tampering',
      target: FLOW_IDS.appToFiles,
      description: 'A harmful file (a script disguised as an image, an SVG with code) is uploaded and later opened by someone else.',
      likelihood: exposure,
      impact: 'high',
      mitigations: [
        m('TPL-UPLOAD-02', 'File type checked by content, extension and declared type; SVG/HTML/ZIP refused', ['V5.2.2']),
        m('TPL-UPLOAD-03', 'Random names, stored outside the web folder', ['V5.3.1', 'V5.3.2']),
        m('TPL-UPLOAD-04', 'Downloads served as attachments with a sandboxed policy', ['V5.4.1', 'V5.4.2']),
      ],
      status: 'mitigated',
    });
    add({
      stride: 'denial-of-service',
      target: FLOW_IDS.appToFiles,
      description: 'Oversized or endless uploads fill the disk.',
      likelihood: shift(exposure, -1),
      impact: 'medium',
      mitigations: [
        m('TPL-UPLOAD-01', 'Streaming size cap; upload aborted at the limit', ['V5.2.1']),
        m('TPL-UPLOAD-05', 'Per-person quota on count and size', ['V2.3.2']),
      ],
      status: 'mitigated',
    });
    add({
      stride: 'information-disclosure',
      target: FLOW_IDS.appToFiles,
      description: "Someone downloads another person's file by guessing its address.",
      likelihood: 'medium',
      impact: dataImpact,
      mitigations: [m('TPL-UPLOAD-05', 'Owner or administrator check on every download', ['V8.2.2'])],
      status: 'mitigated',
    });
  }

  // Email
  if (f.email) {
    add({
      stride: 'tampering',
      target: FLOW_IDS.appToEmail,
      description: 'Someone adds hidden recipients or content to an email through a form field.',
      likelihood: 'low',
      impact: 'medium',
      mitigations: [m('TPL-EMAIL-01', 'Mail headers sanitised; templates only from disk', ['V1.3.11'])],
      status: 'mitigated',
    });
    add({
      stride: 'spoofing',
      target: FLOW_IDS.appToEmail,
      description: 'Password reset emails are abused to take over an account.',
      likelihood: exposure,
      impact: dataImpact,
      mitigations: [
        m('TPL-AUTH-08', 'Random reset token stored hashed, 15-minute expiry, single use; MFA still required', ['V6.4.3', 'V11.5.1']),
        m('TPL-RATE-01', 'Reset requests limited per account and address', ['V2.4.1']),
      ],
      status: 'mitigated',
    });
  }

  // Payments
  if (f.payments) {
    add({
      stride: 'information-disclosure',
      target: FLOW_IDS.appToPayments,
      description: 'Card numbers end up stored or logged by the app.',
      likelihood: 'low',
      impact: 'high',
      mitigations: [
        m('PAT-PROVIDER-HOSTED-PAYMENTS', "Payment happens on the provider's page; the app never receives card data", []),
        m('TPL-DATA-02', 'Sensitive values never in URLs; redacted from logs', ['V14.2.1']),
      ],
      status: 'open',
      actionItems: ['Create the payment provider account and follow the setup guide (src/features/payments) before taking real payments.'],
    });
    add({
      stride: 'tampering',
      target: FLOW_IDS.appToPayments,
      description: 'A fake "payment succeeded" message marks an order as paid.',
      likelihood: 'medium',
      impact: 'high',
      mitigations: [m('TPL-OUTBOUND-01', 'Provider callbacks verified with the provider before an order changes state', ['V13.2.4'])],
      status: 'mitigated',
    });
  }

  // Public API
  if (f.publicApi) {
    add({
      stride: 'spoofing',
      target: FLOW_IDS.apiClientToApp,
      description: 'A leaked API key is used by someone else.',
      likelihood: exposure,
      impact: dataImpact,
      mitigations: [
        m('TPL-APIKEY-01', 'Keys stored hashed, sent only in a header, revocable, per-key limits', ['V14.2.1', 'V11.5.1']),
        m('TPL-LOG-02', 'Keys never logged', ['V16.2.5']),
      ],
      status: 'mitigated',
    });
    add({
      stride: 'denial-of-service',
      target: FLOW_IDS.apiClientToApp,
      description: 'A program hammers the API.',
      likelihood: 'medium',
      impact: 'medium',
      mitigations: [m('TPL-RATE-01', '120 requests per minute per key', ['V2.4.1'])],
      status: 'mitigated',
    });
  }

  // External APIs
  profile.capabilities.externalApis.forEach((api, i) => {
    const flow = externalApiFlowId(i);
    add({
      stride: 'information-disclosure',
      target: flow,
      description: `${api.sendsPersonalData ? 'Personal data' : 'Data'} sent to ${api.name} is exposed if that service is breached or the connection is intercepted.`,
      likelihood: 'low',
      impact: api.sendsPersonalData ? dataImpact : 'low',
      mitigations: [
        m('TPL-OUTBOUND-01', 'HTTPS with certificate checks; only this host is reachable', ['V12.3.2', 'V13.2.4']),
        m('TPL-OUTBOUND-02', 'What is sent is documented in docs/communications.md', ['V13.1.1']),
      ],
      status: api.sendsPersonalData ? 'open' : 'mitigated',
      actionItems: api.sendsPersonalData ? [`Check ${api.name}'s privacy terms and note them in docs/data-protection.md.`] : [],
    });
    add({
      stride: 'denial-of-service',
      target: flow,
      description: `${api.name} is slow or down and takes ${name} down with it.`,
      likelihood: 'medium',
      impact: f.highImpact ? 'high' : 'low',
      mitigations: [m('TPL-OUTBOUND-01', '10-second timeout, circuit breaker, feature degrades instead of failing', ['V16.5.2'])],
      status: 'mitigated',
    });
    add({
      stride: 'tampering',
      target: flow,
      description: `${name} is tricked into calling a different address than ${api.name} (server-side request forgery).`,
      likelihood: 'low',
      impact: 'medium',
      mitigations: [m('TPL-OUTBOUND-01', 'Outbound allow-list; no automatic redirects', ['V13.2.4', 'V15.3.2'])],
      status: 'mitigated',
    });
  });

  // Components
  const diskEncryptionAction = 'Turn on disk encryption on this computer (FileVault on macOS, BitLocker on Windows) and keep backups encrypted.';
  add({
    stride: 'information-disclosure',
    target: COMPONENT_IDS.db,
    description: 'Someone with access to this computer (or a backup) copies the database file.',
    likelihood: f.deployment === 'local-only' ? 'low' : 'medium',
    impact: dataImpact,
    mitigations: [
      m('TPL-DB-02', 'Database file readable only by the app user (0600)', ['V16.4.2']),
      ...(f.fieldEncryption ? [m('TPL-CRYPTO-01', 'Sensitive fields encrypted with AES-256-GCM; key rotation command', ['V11.3.2', 'V11.3.3'])] : []),
      ...(f.auth ? [m('TPL-AUTH-04', 'Passwords stored with a slow hash (argon2id or scrypt)', ['V11.4.2'])] : []),
    ],
    status: f.fieldEncryption || !f.personalData ? 'mitigated' : 'open',
    actionItems: f.fieldEncryption || !f.personalData ? [] : [diskEncryptionAction],
  });
  add({
    stride: 'tampering',
    target: COMPONENT_IDS.db,
    description: 'A form submitted twice, or two people editing at once, corrupts or duplicates a record.',
    likelihood: 'medium',
    impact: 'low',
    mitigations: [
      m('TPL-IDEMPOTENCY-01', 'Idempotency keys on API changes; unique constraints; updated_at checks', []),
      m('TPL-DB-02', 'Transactions for multi-row writes', ['V2.3.3']),
    ],
    status: 'mitigated',
  });
  add({
    stride: 'tampering',
    target: COMPONENT_IDS.app,
    description: 'A package the app depends on has a known vulnerability or a malicious update.',
    likelihood: 'medium',
    impact: dataImpact,
    mitigations: [
      m('TPL-DEPS-01', 'Locked versions, install scripts disabled, inventory (SBOM) and update policy', ['V15.1.2', 'V15.2.1']),
    ],
    status: 'open',
    actionItems: ['Run `npm audit` in the app folder every month and rebuild when a fix is available (docs/dependencies.md).'],
  });
  add({
    stride: 'information-disclosure',
    target: COMPONENT_IDS.app,
    description: 'Secrets (session key, encryption key, API keys) leak through code, logs or error pages.',
    likelihood: 'low',
    impact: 'high',
    mitigations: [
      m('TPL-SECRETS-01', 'Secrets only from the environment; weak or placeholder values refused', ['V13.3.2']),
      m('TPL-LOG-02', 'Redaction of secrets and sensitive fields in logs', ['V16.2.5']),
      m('TPL-STATIC-01', 'Dotfiles and .env never served', ['V13.4.1']),
    ],
    status: 'mitigated',
  });
  add({
    stride: 'repudiation',
    target: COMPONENT_IDS.app,
    description: 'Log entries are altered or deleted to hide what happened.',
    likelihood: 'low',
    impact: 'medium',
    mitigations: [
      m('TPL-LOG-05', 'Hash-chained audit table with a verify command', ['V16.4.2']),
      m('TPL-LOG-04', 'Log injection prevented by JSON encoding', ['V16.4.1']),
    ],
    status: f.internet ? 'open' : 'mitigated',
    actionItems: f.internet ? ['Ship logs to a separate system once the app is online (docs/deployment.md).'] : [],
  });
  if (f.scheduler) {
    add({
      stride: 'tampering',
      target: COMPONENT_IDS.scheduler,
      description: 'A job runs twice at the same time or with input it should not trust.',
      likelihood: 'low',
      impact: f.retentionJobs ? 'medium' : 'low',
      mitigations: [m('TPL-SCHED-01', 'Jobs declared in code, locked while running, no user input in schedules', ['V15.2.2'])],
      status: 'mitigated',
    });
  }

  const threats = drafts
    .map((d, i) => toThreat(d, i))
    .sort((a, b) => LEVEL_VALUE[b.riskLevel] - LEVEL_VALUE[a.riskLevel] || a.id.localeCompare(b.id));

  const entryPoints = ['Web pages and forms', 'JSON API under /api'];
  if (f.auth) entryPoints.push('Sign-in, sign-up/invitation and password reset');
  if (f.uploads) entryPoints.push('File upload and download routes');
  if (f.ai) entryPoints.push('AI assistant chat endpoint');
  if (f.publicApi) entryPoints.push('/api/v1 with API keys');
  if (f.payments) entryPoints.push('Payment result callback');
  if (f.email) entryPoints.push('Links in emails (reset, invitation)');
  if (f.scheduler) entryPoints.push('Scheduled jobs (internal, no external input)');

  const assets = [
    ...(profile.app.entities.length ? [`Records: ${listWords(profile.app.entities.map((e) => e.pluralLabel ?? e.label))}`] : []),
    ...(profile.data.categories.length ? [`Data: ${listWords(profile.data.categories.map((c) => DATA_CATEGORY_LABELS[c]))}`] : []),
    ...(f.auth ? ['Account passwords and sessions'] : []),
    'Configuration secrets (.env)',
    'Audit log',
    ...(f.uploads ? ['Uploaded files'] : []),
    ...(f.ai ? ['AI provider API key and usage budget'] : []),
    ...(f.publicApi ? ['API keys'] : []),
  ];

  const trustBoundaries = arch.dataFlows
    .filter((fl) => fl.crossesTrustBoundary)
    .map((fl) => `${fl.id}: ${componentName(arch, fl.from)} → ${componentName(arch, fl.to)} (${fl.protocol})`);
  trustBoundaries.push('Application zone → data zone (file permissions on the data folder)');

  const open = threats.filter((t) => t.status !== 'mitigated');
  const summary = `${threats.length} threats identified with STRIDE (${threats.filter((t) => t.riskLevel === 'high').length} high, ${threats.filter((t) => t.riskLevel === 'medium').length} medium, ${threats.filter((t) => t.riskLevel === 'low').length} low). ${threats.length - open.length} are covered by built-in template controls. ${open.length === 0 ? 'No actions are needed before use.' : `${open.length} need an action: ${listWords(open.map((t) => t.id))}.`}`;

  return {
    method: 'STRIDE',
    performedBy: 'rules',
    performedAt: now.toISOString(),
    scope: `${name}: the web application, its database and files on this computer, and its connections to ${arch.components.filter((c) => c.trustZone === 'vendor').length ? 'outside services' : 'browsers'}. Out of scope: the operating system, the network, and the vendors' own systems.`,
    assets,
    entryPoints,
    trustBoundaries,
    threats,
    summary,
  };
}

function toThreat(d: Draft, index: number): Threat {
  const level = riskLevel(d.likelihood, d.impact);
  return {
    id: `T-${String(index + 1).padStart(2, '0')}`,
    stride: d.stride,
    target: d.target,
    description: d.description,
    likelihood: d.likelihood,
    impact: d.impact,
    riskLevel: level,
    mitigations: d.mitigations,
    residualRisk: d.status === 'mitigated' ? shift(level, -1) : level,
    status: d.status,
    actionItems: d.actionItems ?? [],
  };
}

function componentName(arch: Architecture, id: string): string {
  return arch.components.find((c) => c.id === id)?.name ?? id;
}

export { externalApiComponentId };
