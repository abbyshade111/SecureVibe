/**
 * The fixed list of architecture decision records. Every app gets the same eight decisions; the content of
 * each depends on the profile. When a previous design is supplied and a decision's text is unchanged, its
 * original date is kept so re-deriving does not rewrite history.
 */
import type { Adr, DesignArtifacts } from '@shared/design.js';
import type { DesignProfile } from '@shared/profile.js';
import { DATA_CATEGORY_LABELS, listWords, type ProfileFacts } from './conditions.js';

export const ADR_FILES: Record<string, string> = {
  'ADR-001': 'ADR-001-authentication-model.md',
  'ADR-002': 'ADR-002-session-store.md',
  'ADR-003': 'ADR-003-data-encryption-and-keys.md',
  'ADR-004': 'ADR-004-file-uploads.md',
  'ADR-005': 'ADR-005-ai-boundary.md',
  'ADR-006': 'ADR-006-deployment-and-exposure.md',
  'ADR-007': 'ADR-007-logging-and-retention.md',
  'ADR-008': 'ADR-008-dependency-policy.md',
};

type Draft = Omit<Adr, 'status' | 'date'>;

export function deriveAdrs(profile: DesignProfile, f: ProfileFacts, now: Date, previous?: DesignArtifacts): Adr[] {
  const date = now.toISOString().slice(0, 10);
  const drafts: Draft[] = [
    authenticationModel(profile, f),
    sessionStore(f),
    encryption(profile, f),
    uploads(f),
    aiBoundary(profile, f),
    deployment(profile, f),
    logging(profile, f),
    dependencies(),
  ];
  return drafts.map((d) => {
    const prior = previous?.adrs.find((a) => a.id === d.id);
    const unchanged = prior && prior.decision === d.decision && prior.context === d.context;
    return { ...d, status: 'accepted', date: unchanged ? prior.date : date };
  });
}

function authenticationModel(profile: DesignProfile, f: ProfileFacts): Draft {
  if (!f.auth) {
    return {
      id: 'ADR-001',
      title: 'Authentication model: no accounts (single-user local tool)',
      context: `Only ${profile.deployment.owner.name} uses ${f.appName}, on this computer, with no feature that needs a user account.`,
      decision:
        'The app has no sign-in. Access is protected by the computer itself: it listens on 127.0.0.1 only, so only someone logged in to this computer can open it.',
      alternatives: ['Local accounts with passwords (adds friction for a one-person tool)', 'A shared secret in the URL (easy to leak)'],
      consequences:
        'Anyone who can use this computer can use the app. If the app is ever shared with other people or put on a network, sign-in must be turned on and the design re-derived.',
      relatedControls: ['TPL-TRUSTZONES-01'],
      relatedRequirements: ['AS-01'],
    };
  }
  const registration = {
    'invite-only': 'people join only through an invitation link sent by an administrator',
    'admin-created': 'an administrator creates every account',
    open: 'anyone can sign up (limited to a few sign-ups per hour per address)',
  }[profile.users.registration];
  return {
    id: 'ADR-001',
    title: 'Authentication model: local accounts with passwords' + (f.adminMfa ? ' and administrator MFA' : ''),
    context: `${f.appName} is used by ${listWords(f.roles.map((r) => r.label.toLowerCase()))}. Sign-in is required because ${listWords(f.authReasons)}. There is no company identity provider to connect to.`,
    decision: `Local accounts with passwords of at least 12 characters, hashed with argon2id (or scrypt), rate-limited sign-in with temporary lockout, and ${registration}. ${f.adminMfa ? 'Administrators must enrol an authenticator app (TOTP) on first sign-in.' : 'Administrators are encouraged, but not forced, to use an authenticator app.'}${f.userMfa ? ' Every person may enrol an authenticator app.' : ''} Roles: ${listWords(f.roles.map((r) => `${r.label}${r.isAdmin ? ' (administrator)' : ''}`))}. The first administrator receives a one-time password that must be changed.`,
    alternatives: [
      'Sign in with Google/Microsoft (OAuth/OIDC): recommended later if the organization has one; out of scope for v1',
      'Magic links by email only: depends on email delivery being set up',
      'No accounts: not acceptable because ' + listWords(f.authReasons),
    ],
    consequences: `People need a password${f.adminMfa ? ', and administrators need an authenticator app on their phone' : ''}. Forgotten passwords are reset with a 15-minute link${f.email ? ' sent by email' : ' written to the local outbox folder'}. The SbD control AC-02 (central identity provider) is answered "No" with a plan.`,
    relatedControls: ['TPL-AUTH-01', 'TPL-AUTH-05', 'TPL-AUTH-06', 'TPL-AUTHZ-01', ...(f.adminMfa ? ['TPL-MFA-01', 'TPL-MFA-04'] : [])],
    relatedRequirements: ['V6.2.1', 'V6.3.1', 'V8.2.1', 'AC-02', 'AC-03'],
  };
}

function sessionStore(f: ProfileFacts): Draft {
  return {
    id: 'ADR-002',
    title: 'Session store: server-side sessions in SQLite',
    context: f.auth
      ? 'Signed-in people need a session that can be ended on the server (logout, disable, "log out everywhere").'
      : 'The app has no accounts, but the same session and CSRF machinery protects forms.',
    decision: `Sessions are opaque 256-bit random ids stored hashed in the SQLite sessions table, delivered in an HttpOnly, SameSite=Strict cookie${f.tls ? ' with the Secure flag and __Host- prefix' : ''}. Idle timeout ${f.level === 2 ? 15 : 30} minutes, absolute lifetime ${f.level === 2 ? 8 : 12} hours, at most 5 sessions per person. A new id is issued on sign-in.`,
    alternatives: ['Signed tokens (JWT) in cookies: cannot be revoked on the server', 'In-memory sessions: lost on restart'],
    consequences: 'Logout and account changes take effect immediately. Sessions survive a restart. The sessions table grows with use and is pruned on expiry.',
    relatedControls: ['TPL-SESSION-01', 'TPL-SESSION-02', 'TPL-SESSION-03', 'TPL-SESSION-04', 'TPL-COOKIE-01'],
    relatedRequirements: ['V7.2.1', 'V7.3.1', 'V7.4.1', 'V3.3.2'],
  };
}

function encryption(profile: DesignProfile, f: ProfileFacts): Draft {
  const sensitiveWords = listWords(f.sensitiveCategories.map((c) => DATA_CATEGORY_LABELS[c]));
  const sensitiveFields = profile.app.entities.flatMap((e) => e.fields.filter((fl) => fl.sensitive).map((fl) => `${e.label}.${fl.label}`));
  return {
    id: 'ADR-003',
    title: f.fieldEncryption ? 'Data encryption: field-level AES-256-GCM with keys in the environment' : 'Data encryption: file permissions and disk encryption; no field encryption',
    context: f.fieldEncryption
      ? `${f.appName} stores ${sensitiveWords || 'fields marked sensitive'}${sensitiveFields.length ? ` (${listWords(sensitiveFields)})` : ''}. The database is a file on this computer; anyone who can copy the file could read it.`
      : `${f.appName} stores no sensitive categories and no field is marked sensitive. The database is a file on this computer.`,
    decision: f.fieldEncryption
      ? 'Fields marked sensitive are encrypted with AES-256-GCM (versioned keys, per-row associated data) before they are written. Keys are 32 random bytes generated at setup and stored in the .env file (mode 0600); `npm run rotate-field-key` re-encrypts with a new key. Passwords are hashed, never encrypted.'
      : 'No field-level encryption. The database file is created with mode 0600 inside a 0700 data folder. Passwords are hashed. Disk encryption on the computer is recommended in the deployment guide.',
    alternatives: [
      'Whole-database encryption (SQLCipher): needs a native module, which the locked dependency set avoids',
      'A cloud key manager: not available for an app on one computer',
      ...(f.fieldEncryption ? [] : ['Field-level encryption anyway: extra complexity without sensitive fields to protect']),
    ],
    consequences: f.fieldEncryption
      ? 'Encrypted fields cannot be searched with SQL. The key lives on the same computer as the data, which the report states plainly; losing the .env file makes encrypted fields unreadable, so it must be backed up securely.'
      : 'A copied database file is readable. If sensitive data is added later, mark the field sensitive and re-derive the design.',
    relatedControls: f.fieldEncryption ? ['TPL-CRYPTO-01', 'TPL-SECRETS-01', 'TPL-DB-02'] : ['TPL-DB-02', 'TPL-AUTH-04'],
    relatedRequirements: f.fieldEncryption ? ['V11.3.2', 'V11.3.3', 'V11.2.2', 'DM-02', 'AC-05'] : ['V11.4.2', 'DM-02'],
  };
}

function uploads(f: ProfileFacts): Draft {
  if (!f.uploads) {
    return {
      id: 'ADR-004',
      title: 'File uploads: not included',
      context: 'No feature or record needs uploaded files.',
      decision: 'The uploads module is not installed. The generated code must not accept file uploads.',
      alternatives: ['Install the uploads module anyway: more attack surface for no benefit'],
      consequences: 'Adding uploads later means turning the capability on and rebuilding, so the validated upload module and its tests are included.',
      relatedControls: [],
      relatedRequirements: [],
    };
  }
  return {
    id: 'ADR-004',
    title: 'File uploads: streamed, type-checked, stored outside the web folder',
    context: `${f.appName} accepts uploaded files. Files are a classic way to smuggle scripts or exhaust disk space.`,
    decision:
      'Uploads go through the template uploads module only: streamed with a hard size cap (10 MB), type checked by content (magic bytes), extension and declared type against an allow-list (PNG, JPEG, GIF, WebP, PDF; never SVG/HTML/XML/ZIP), stored as random names under the data folder (mode 0600), served only as attachments with a sandboxed policy, with owner checks and a per-person quota.',
    alternatives: ['Store files in the database: bloats the database and complicates backups', 'Serve files from the public folder: files could be executed or interpreted by the browser'],
    consequences: 'Only the allow-listed types can be uploaded. Files are never opened in the browser directly. Disk usage is bounded per person.',
    relatedControls: ['TPL-UPLOAD-01', 'TPL-UPLOAD-02', 'TPL-UPLOAD-03', 'TPL-UPLOAD-04', 'TPL-UPLOAD-05'],
    relatedRequirements: ['V5.2.1', 'V5.2.2', 'V5.3.1', 'V5.4.1', 'V8.2.2'],
  };
}

function aiBoundary(profile: DesignProfile, f: ProfileFacts): Draft {
  if (!f.ai) {
    return {
      id: 'ADR-005',
      title: 'AI boundary: no AI features in the app',
      context: 'The profile has no AI assistant.',
      decision: 'The generated app contains no AI feature and makes no calls to AI services. The AI-specific standard (AISVS) is not applied to the app.',
      alternatives: ['Include the assistant module unused: unnecessary code and an extra outside connection'],
      consequences: 'Adding an assistant later means turning it on and rebuilding, which adds the AI guard-rails and AISVS verification.',
      relatedControls: [],
      relatedRequirements: [],
    };
  }
  const ai = profile.capabilities.aiAssistant;
  return {
    id: 'ADR-005',
    title: 'AI boundary: the assistant advises, application code decides',
    context: `${f.appName} includes an AI assistant${ai.purpose ? ` to ${ai.purpose}` : ''}. The model reads text from people, which can contain instructions meant to trick it, and its answers cannot be trusted blindly.`,
    decision: `All AI calls go through the template AI module. Input is normalized, length-limited and screened for injection; the system prompt is fixed and sets an instruction hierarchy; application data is fetched only through the signed-in person's permissions (${ai.dataItCanSee === 'nothing' ? 'no records are shared' : ai.dataItCanSee === 'users-own-records' ? "only the person's own records" : 'only records the person may see'}) and wrapped as untrusted data; answers are schema-validated, length-bounded, filtered and rendered as plain text. ${ai.canTakeActions ? 'The assistant may propose changes through a fixed list of tools; nothing runs until the person confirms, and the app enforces permissions.' : 'The assistant cannot change data.'} ${ai.storesHistory ? 'Conversation history is stored per person and can be cleared.' : 'No conversation history is stored.'} Every request is logged with token counts; each person has a daily budget; an administrator kill switch stops the feature at once.${f.aiModeration ? ' A content classifier screens input and output.' : ''}`,
    alternatives: ['Let the model call tools freely: the model could be tricked into harmful actions', 'Render model output as HTML/markdown: opens a path for script injection'],
    consequences: 'The assistant needs an Anthropic API key in .env. Messages leave this computer and go to the provider. The feature costs money per use, bounded by the budget.',
    relatedControls: ['TPL-AI-01', 'TPL-AI-03', 'TPL-AI-04', 'TPL-AI-05', 'TPL-AI-06', 'TPL-AI-07', 'TPL-AI-08', ...(ai.canTakeActions ? ['TPL-AI-ACTIONS-01'] : [])],
    relatedRequirements: ['C2.1.3', 'C2.1.6', 'C5.2.1', 'C7.1.1', 'C9.1.2', 'C9.6.1', ...(ai.canTakeActions ? ['C9.2.1'] : [])],
  };
}

function deployment(profile: DesignProfile, f: ProfileFacts): Draft {
  const byTarget = {
    'local-only': {
      title: 'Deployment and exposure: this computer only (loopback)',
      decision: 'The app binds to 127.0.0.1 only (BIND_LAN=0) with TLS_MODE=off. Plain HTTP is acceptable because the traffic never leaves the computer. Outbound connections are limited to the allow-list.',
      consequences: 'Nothing on the network can reach the app. If it is ever shared, change the deployment answer and rebuild: the design, TLS mode and checklist change.',
    },
    'local-network': {
      title: 'Deployment and exposure: local network with a self-signed certificate',
      decision: 'The app binds to all interfaces (BIND_LAN=1) with TLS_MODE=selfsigned: `npm run gen-cert` creates a certificate, TLS 1.2+ only, HSTS on, cookies Secure with the __Host- prefix. Outbound connections are limited to the allow-list.',
      consequences: 'Browsers warn about the self-signed certificate the first time. The network is treated as untrusted: sign-in and rate limits protect the app. A firewall should still block access from outside the network.',
    },
    'internet-later': {
      title: 'Deployment and exposure: behind an HTTPS reverse proxy before going online',
      decision: 'The app runs locally now (TLS_MODE=off, loopback). Before going online it must run with TLS_MODE=proxy behind a reverse proxy that terminates HTTPS with a real certificate (TRUST_PROXY_HOPS=1); the app then sets Secure cookies and HSTS. docs/deployment.md and the "Going online safely" checklist describe the steps.',
      consequences: 'Until the proxy is in place, the app must not be exposed. Rate limits, logging to a separate system, backups and monitoring become the hosting provider\'s and owner\'s tasks; the checklist marks those controls as deferred.',
    },
  }[profile.deployment.target];
  return {
    id: 'ADR-006',
    ...byTarget,
    context: `${f.appName} will run ${profile.deployment.target === 'local-only' ? 'on this computer only' : profile.deployment.target === 'local-network' ? 'on the local network' : 'on this computer first and on the internet later'}. Business impact: ${profile.deployment.businessImpact}.`,
    alternatives: ['Expose the Node process directly to the internet: no TLS termination, no protection layer', 'Cloud deployment automation: out of scope for v1'],
    relatedControls: ['TPL-TRUSTZONES-01', 'TPL-RESILIENCE-01', ...(f.tls ? ['TPL-HEADERS-03', 'TPL-COOKIE-02'] : []), ...(f.tlsMode === 'selfsigned' ? ['TPL-TLS-01'] : []), ...(f.tlsMode === 'proxy' ? ['TPL-PROXY-01'] : [])],
    relatedRequirements: ['AS-01', 'AC-01', 'RR-06', ...(f.tls ? ['V12.1.1', 'V3.4.1'] : [])],
  };
}

function logging(profile: DesignProfile, f: ProfileFacts): Draft {
  const retention =
    profile.data.retention === 'auto-delete-after-period'
      ? `Records about people are deleted or pseudonymised after ${profile.data.retentionMonths ?? 12} months by a scheduled job (RETENTION_MONTHS).`
      : 'Records are kept until deleted; administrators can export or delete a person\'s data on request.';
  return {
    id: 'ADR-007',
    title: 'Logging, audit and data retention',
    context: `Security events must be reconstructable later, and ${f.personalData ? 'information about people must not be kept longer than needed' : 'logs must not become a liability'}.`,
    decision: `Structured JSON logs (pino) with UTC timestamps, request ids and outcome; secrets and sensitive fields redacted; security events also written to an append-only hash-chained audit table kept for 400 days (AUDIT_RETENTION_DAYS) with a verify command. ${retention} Owner and security contact: ${profile.deployment.owner.name} (${profile.deployment.owner.contactEmail}). docs/incident-response.md describes what to do when something goes wrong.`,
    alternatives: ['Plain text logs: hard to search, easy to inject into', 'Keep everything forever: privacy risk and larger breach impact'],
    consequences: `Logs are tamper-evident on this computer but live on the same machine as the app${f.internet ? '; they must be shipped elsewhere once online' : ''}. ${f.retentionJobs ? 'Deleted data cannot be recovered after the retention period.' : 'Someone must act on deletion requests.'}`,
    relatedControls: ['TPL-LOG-01', 'TPL-LOG-02', 'TPL-LOG-03', 'TPL-LOG-05', 'TPL-DATA-01', 'TPL-IR-01'],
    relatedRequirements: ['V16.2.1', 'V16.4.2', 'V14.2.4', 'MT-01', 'MT-06', 'MT-07', 'DM-05'],
  };
}

function dependencies(): Draft {
  return {
    id: 'ADR-008',
    title: 'Dependency policy: locked, script-free, inventoried',
    context: 'Every package is code from strangers that runs with the app\'s permissions. The generator (an AI) must not be able to add packages.',
    decision:
      'The app ships a tested package-lock.json with a fixed set (express, helmet, ejs, zod, pino, busboy, @anthropic-ai/sdk). Installs run with `npm ci --ignore-scripts`. The generator may only import allow-listed modules; package.json is a protected file. An inventory (SBOM) is produced with each build, and docs/dependencies.md states update time frames (critical 7 days, high 30 days, medium 90 days).',
    alternatives: ['Let the generator add packages as needed: unreviewed code and install scripts could run', 'No lockfile: builds would drift'],
    consequences: 'New capabilities that need other packages require a template update. The owner should run `npm audit` regularly and rebuild when fixes appear.',
    relatedControls: ['TPL-DEPS-01', 'TPL-EXAMPLE-01'],
    relatedRequirements: ['V15.1.1', 'V15.1.2', 'V15.2.1', 'RR-01'],
  };
}
