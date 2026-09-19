/**
 * SbD step 2: components, trust zones, data flows, external dependencies, assumptions, a Mermaid diagram and a
 * plain-language walkthrough. Component and flow ids are stable so patterns and threats can reference them.
 */
import type { Architecture, Component, DataFlow, ExternalDependency, TrustZone } from '@shared/design.js';
import type { DesignProfile } from '@shared/profile.js';
import { DATA_CATEGORY_LABELS, listWords, type ProfileFacts } from './conditions.js';

export const COMPONENT_IDS = {
  browser: 'browser',
  app: 'app',
  db: 'db',
  files: 'files',
  scheduler: 'scheduler',
  ai: 'ai-provider',
  email: 'email-service',
  payments: 'payment-provider',
  apiClient: 'api-client',
} as const;

export const FLOW_IDS = {
  browserToApp: 'F-01',
  appToDb: 'F-02',
  appToFiles: 'F-03',
  appToAi: 'F-04',
  appToEmail: 'F-05',
  appToPayments: 'F-06',
  apiClientToApp: 'F-07',
  schedulerToDb: 'F-08',
} as const;

export function externalApiComponentId(index: number): string {
  return `external-api-${index + 1}`;
}
export function externalApiFlowId(index: number): string {
  return `F-${String(20 + index + 1).padStart(2, '0')}`;
}

export function deriveArchitecture(profile: DesignProfile, f: ProfileFacts): Architecture {
  const name = f.appName;
  const components: Component[] = [];
  const dataFlows: DataFlow[] = [];
  const externalDependencies: ExternalDependency[] = [];
  const allData = profile.data.categories.length ? [...profile.data.categories] : ['application records'];

  components.push({
    id: COMPONENT_IDS.browser,
    name: 'Web browser',
    kind: 'browser',
    trustZone: 'browser',
    description: `The browser of each person who uses ${name}. Everything it sends is treated as untrusted.`,
  });
  components.push({
    id: COMPONENT_IDS.app,
    name: `${name} application`,
    kind: 'web-app',
    trustZone: 'app',
    description:
      'One Node.js process (Express) that renders pages, serves the JSON API, checks every input, enforces sign-in and roles, and writes the logs.',
  });
  components.push({
    id: COMPONENT_IDS.db,
    name: 'SQLite database',
    kind: 'database',
    trustZone: 'data',
    description: `A single database file in the data folder (file permissions 0600).${f.fieldEncryption ? ' Sensitive fields are encrypted inside it.' : ''}`,
  });
  if (f.uploads) {
    components.push({
      id: COMPONENT_IDS.files,
      name: 'Uploaded files',
      kind: 'file-storage',
      trustZone: 'data',
      description: 'Files stored under the data folder with random names, outside the web folder.',
    });
  }
  if (f.scheduler) {
    components.push({
      id: COMPONENT_IDS.scheduler,
      name: 'Scheduled jobs',
      kind: 'scheduler',
      trustZone: 'app',
      description: `Background jobs inside the same process${f.retentionJobs ? ' (including the data retention job)' : ''}, run one at a time with a lock.`,
    });
  }
  if (f.publicApi) {
    components.push({
      id: COMPONENT_IDS.apiClient,
      name: 'API clients',
      kind: 'api-client',
      trustZone: 'browser',
      description: 'Other programs that call the JSON API with an API key created by a signed-in person.',
    });
  }
  if (f.ai) {
    components.push({
      id: COMPONENT_IDS.ai,
      name: 'Anthropic Claude API',
      kind: 'ai-provider',
      trustZone: 'vendor',
      description: 'The hosted AI model behind the assistant. Reached over HTTPS with an API key kept in configuration.',
    });
    externalDependencies.push({
      name: 'Anthropic API',
      purpose: `Powers the AI assistant${profile.capabilities.aiAssistant.purpose ? ` (${profile.capabilities.aiAssistant.purpose})` : ''}.`,
      trust: 'vendor',
      dataShared: aiDataShared(profile),
      mitigations: [
        'Only the allowed host is reachable (outbound allow-list)',
        'Data is scoped to what the signed-in person may see',
        'Requests and responses are validated and logged with token counts',
        'Daily budget per person and an administrator kill switch',
      ],
    });
  }
  if (f.email) {
    components.push({
      id: COMPONENT_IDS.email,
      name: 'Email delivery',
      kind: 'email-service',
      trustZone: 'vendor',
      description: 'Sends sign-up, invitation and password reset emails. Locally, emails are written to an outbox folder until an email server is configured.',
    });
    externalDependencies.push({
      name: 'Email server (SMTP)',
      purpose: 'Delivers account emails. Optional: without it, emails are saved to a local folder.',
      trust: 'vendor',
      dataShared: ['email addresses', 'one-time links'],
      mitigations: ['Headers are sanitised', 'Only configured server is used', 'Reset links expire in 15 minutes'],
    });
  }
  if (f.payments) {
    components.push({
      id: COMPONENT_IDS.payments,
      name: 'Payment provider',
      kind: 'payment-provider',
      trustZone: 'vendor',
      description: 'A provider-hosted checkout page. Card numbers go directly from the browser to the provider and never touch the app.',
    });
    externalDependencies.push({
      name: 'Payment provider (to be chosen)',
      purpose: 'Takes payments on a hosted checkout page.',
      trust: 'vendor',
      dataShared: ['order amount and reference', 'payer email (if the provider requires it)'],
      mitigations: ['Card data is never stored or logged by the app', 'Provider callbacks are verified before an order is marked paid'],
    });
  }
  profile.capabilities.externalApis.forEach((api, i) => {
    components.push({
      id: externalApiComponentId(i),
      name: api.name,
      kind: 'external-api',
      trustZone: 'vendor',
      description: `${api.purpose || 'An outside service the app calls.'}${api.sendsPersonalData ? ' Receives personal data.' : ''}`,
    });
    externalDependencies.push({
      name: api.name,
      purpose: api.purpose || 'Outside service used by the app.',
      trust: 'vendor',
      dataShared: api.sendsPersonalData ? f.personalCategories.map((c) => DATA_CATEGORY_LABELS[c]) : [],
      mitigations: [
        'Only this host is reachable (outbound allow-list)',
        '10-second timeout, no automatic redirects, circuit breaker',
        ...(api.sendsPersonalData ? ['Data sent is listed in docs/data-protection.md'] : []),
      ],
    });
  });
  externalDependencies.push({
    name: 'npm registry',
    purpose: 'Installs the locked set of packages once (no install scripts).',
    trust: 'platform',
    dataShared: [],
    mitigations: ['Locked versions (package-lock.json)', 'Install scripts disabled', 'Inventory (SBOM) and update policy'],
  });
  externalDependencies.push({
    name: 'Node.js runtime',
    purpose: 'Runs the app on this computer.',
    trust: 'platform',
    dataShared: [],
    mitigations: ['Version pinned (22.13 or newer)', 'No native add-ons'],
  });

  const trustZones: TrustZone[] = [
    {
      id: 'browser',
      name: 'Browser zone',
      level: 'untrusted',
      description: 'Browsers and API clients. Every request from here is checked, validated and rate-limited.',
    },
    {
      id: 'app',
      name: 'Application zone',
      level: 'trusted',
      description: `The ${name} process on this computer. ${zoneExposure(f)}`,
    },
    {
      id: 'data',
      name: 'Data zone',
      level: 'trusted',
      description: 'The data folder on the same computer, protected by file permissions (0600/0700).',
    },
  ];
  if (components.some((c) => c.trustZone === 'vendor')) {
    trustZones.push({
      id: 'vendor',
      name: 'Outside services',
      level: 'semi-trusted',
      description: 'Vendors reached over HTTPS. Only hosts on the outbound allow-list can be contacted.',
    });
  }

  const browserProtocol =
    f.tlsMode === 'off' ? 'HTTP (localhost)' : f.tlsMode === 'selfsigned' ? 'HTTPS (self-signed, local network)' : 'HTTPS (via reverse proxy)';
  const browserControls = ['TPL-HEADERS-01', 'TPL-VALIDATION-01', 'TPL-BODY-01', 'TPL-RATE-01', 'TPL-ERRORS-01'];
  if (f.auth) browserControls.push('TPL-AUTHZ-01', 'TPL-CSRF-01', 'TPL-COOKIE-01', 'TPL-SESSION-01');
  if (f.tls) browserControls.push('TPL-HEADERS-03', 'TPL-COOKIE-02');
  if (f.tlsMode === 'selfsigned') browserControls.push('TPL-TLS-01');
  if (f.tlsMode === 'proxy') browserControls.push('TPL-PROXY-01');
  dataFlows.push({
    id: FLOW_IDS.browserToApp,
    from: COMPONENT_IDS.browser,
    to: COMPONENT_IDS.app,
    description: `People use ${name}: pages, forms${f.auth ? ', sign-in' : ''} and the JSON API.`,
    data: allData,
    protocol: browserProtocol,
    crossesTrustBoundary: true,
    controls: browserControls,
  });
  dataFlows.push({
    id: FLOW_IDS.appToDb,
    from: COMPONENT_IDS.app,
    to: COMPONENT_IDS.db,
    description: 'Reads and writes records with parameterised queries only.',
    data: allData,
    protocol: 'SQLite file',
    crossesTrustBoundary: false,
    controls: ['TPL-DB-01', 'TPL-DB-02', 'TPL-DB-04', 'TPL-DTO-01', ...(f.fieldEncryption ? ['TPL-CRYPTO-01'] : [])],
  });
  if (f.uploads) {
    dataFlows.push({
      id: FLOW_IDS.appToFiles,
      from: COMPONENT_IDS.app,
      to: COMPONENT_IDS.files,
      description: 'Stores checked uploads and serves them back as attachments.',
      data: ['files'],
      protocol: 'Local file system',
      crossesTrustBoundary: false,
      controls: ['TPL-UPLOAD-01', 'TPL-UPLOAD-02', 'TPL-UPLOAD-03', 'TPL-UPLOAD-04', 'TPL-UPLOAD-05'],
    });
  }
  if (f.ai) {
    dataFlows.push({
      id: FLOW_IDS.appToAi,
      from: COMPONENT_IDS.app,
      to: COMPONENT_IDS.ai,
      description: 'Sends the screened message and permitted context to the model; validates the answer.',
      data: aiDataShared(profile),
      protocol: 'HTTPS (vendor API)',
      crossesTrustBoundary: true,
      controls: ['TPL-AI-03', 'TPL-AI-04', 'TPL-AI-05', 'TPL-AI-06', 'TPL-AI-08', 'TPL-OUTBOUND-01'],
    });
  }
  if (f.email) {
    dataFlows.push({
      id: FLOW_IDS.appToEmail,
      from: COMPONENT_IDS.app,
      to: COMPONENT_IDS.email,
      description: 'Sends account emails (invitations, password resets).',
      data: ['contact'],
      protocol: 'SMTP (or local outbox folder)',
      crossesTrustBoundary: true,
      controls: ['TPL-EMAIL-01', 'TPL-AUTH-08', 'TPL-OUTBOUND-01'],
    });
  }
  if (f.payments) {
    dataFlows.push({
      id: FLOW_IDS.appToPayments,
      from: COMPONENT_IDS.browser,
      to: COMPONENT_IDS.payments,
      description: "The person pays on the provider's page; the app only receives a verified result.",
      data: ['payment-card'],
      protocol: 'HTTPS (provider-hosted checkout)',
      crossesTrustBoundary: true,
      controls: ['PAT-PROVIDER-HOSTED-PAYMENTS', 'TPL-DATA-02', 'TPL-OUTBOUND-01'],
    });
  }
  if (f.publicApi) {
    dataFlows.push({
      id: FLOW_IDS.apiClientToApp,
      from: COMPONENT_IDS.apiClient,
      to: COMPONENT_IDS.app,
      description: 'Programs call /api/v1 with an API key in the Authorization header.',
      data: allData,
      protocol: `${f.tls ? 'HTTPS' : 'HTTP (localhost)'} + API key`,
      crossesTrustBoundary: true,
      controls: ['TPL-APIKEY-01', 'TPL-VALIDATION-01', 'TPL-RATE-01', 'TPL-AUTHZ-01'],
    });
  }
  if (f.scheduler) {
    dataFlows.push({
      id: FLOW_IDS.schedulerToDb,
      from: COMPONENT_IDS.scheduler,
      to: COMPONENT_IDS.db,
      description: `Runs registered jobs${f.retentionJobs ? ', including deleting expired records' : ''}.`,
      data: allData,
      protocol: 'In-process (SQLite file)',
      crossesTrustBoundary: false,
      controls: ['TPL-SCHED-01', ...(f.retentionJobs ? ['TPL-DATA-01'] : [])],
    });
  }
  profile.capabilities.externalApis.forEach((api, i) => {
    dataFlows.push({
      id: externalApiFlowId(i),
      from: COMPONENT_IDS.app,
      to: externalApiComponentId(i),
      description: api.purpose ? `Calls ${api.name}: ${api.purpose}` : `Calls ${api.name}.`,
      data: api.sendsPersonalData ? [...f.personalCategories] : [],
      protocol: 'HTTPS (vendor API)',
      crossesTrustBoundary: true,
      controls: ['TPL-OUTBOUND-01', 'TPL-OUTBOUND-02'],
    });
  });

  const assumptions = deriveAssumptions(profile, f);
  const mermaid = renderMermaid(components, trustZones, dataFlows);
  const plainLanguage = walkthrough(profile, f, components, dataFlows);

  return { components, trustZones, dataFlows, externalDependencies, assumptions, mermaid, plainLanguage };
}

function zoneExposure(f: ProfileFacts): string {
  if (f.deployment === 'local-only') return 'It listens on 127.0.0.1 only, so nothing else on the network can reach it.';
  if (f.deployment === 'local-network') return 'It listens on the local network with a self-signed HTTPS certificate.';
  return 'It listens locally now; before going online it must sit behind an HTTPS reverse proxy.';
}

function aiDataShared(profile: DesignProfile): string[] {
  const shared = ['messages typed by the person'];
  const see = profile.capabilities.aiAssistant.dataItCanSee;
  if (see === 'users-own-records') shared.push("the person's own records (as context)");
  if (see === 'all-records') shared.push('records the person may see (as context)');
  if (profile.capabilities.aiAssistant.storesHistory) shared.push("the person's earlier messages");
  return shared;
}

function deriveAssumptions(profile: DesignProfile, f: ProfileFacts): string[] {
  const out: string[] = [];
  out.push(`${f.appName} runs as one process on one computer with one SQLite database file. No other program writes to that file.`);
  if (f.deployment === 'local-only') out.push('Only this computer can reach the app. Anyone who can log in to this computer can open it.');
  if (f.deployment === 'local-network') out.push('Anyone on the local network can reach the sign-in page. The network itself is not trusted.');
  if (f.deployment === 'internet-later') out.push('Until a TLS reverse proxy is in front of it, the app stays on this computer or a private network.');
  if (f.auth) out.push(`${profile.deployment.owner.name} is the first administrator and creates or invites the other accounts.`);
  else out.push(`${profile.deployment.owner.name} is the only person who uses the app; there are no accounts.`);
  out.push(
    f.fieldEncryption
      ? 'Whoever can read files on this computer can read the database, except the encrypted fields. The encryption key lives in the .env file on the same computer.'
      : 'Whoever can read files on this computer can read the database. Disk encryption on the computer is recommended.',
  );
  if (f.ai) out.push('The AI provider is reached over the internet. Anything sent to it leaves this computer.');
  if (f.externalApis)
    out.push(`The outside services (${listWords(profile.capabilities.externalApis.map((a) => a.name))}) are trusted to handle the data sent to them.`);
  if (f.payments) out.push('The payment provider handles card data; the app never sees a card number.');
  out.push('There is no security team. Reviews are done by rules and an AI second opinion, and the owner acknowledges the results.');
  return out;
}

function renderMermaid(components: Component[], zones: TrustZone[], flows: DataFlow[]): string {
  const lines: string[] = ['flowchart LR'];
  for (const zone of zones) {
    const members = components.filter((c) => c.trustZone === zone.id);
    if (members.length === 0) continue;
    lines.push(`  subgraph zone_${mermaidId(zone.id)}["${escapeLabel(zone.name)} (${zone.level})"]`);
    for (const c of members) lines.push(`    ${mermaidId(c.id)}${shape(c)}`);
    lines.push('  end');
  }
  for (const flow of flows) {
    const controls = flow.controls.length ? ` · ${flow.controls.join(', ')}` : '';
    const arrow = flow.crossesTrustBoundary ? '-->' : '-.->';
    lines.push(`  ${mermaidId(flow.from)} ${arrow}|"${escapeLabel(`${flow.id} ${flow.protocol}${controls}`)}"| ${mermaidId(flow.to)}`);
  }
  return lines.join('\n');
}

function shape(c: Component): string {
  const label = escapeLabel(c.name);
  switch (c.kind) {
    case 'database':
      return `[("${label}")]`;
    case 'file-storage':
      return `[["${label}"]]`;
    case 'browser':
    case 'api-client':
      return `(["${label}"])`;
    default:
      return `["${label}"]`;
  }
}

function mermaidId(id: string): string {
  return id.replace(/[^a-zA-Z0-9_]/g, '_');
}

function escapeLabel(text: string): string {
  return text.replace(/"/g, "'");
}

function walkthrough(profile: DesignProfile, f: ProfileFacts, components: Component[], flows: DataFlow[]): string {
  const name = f.appName;
  const p: string[] = [];
  p.push(
    `${name} is one program running on ${f.deployment === 'local-only' ? 'this computer' : f.deployment === 'local-network' ? 'a computer on your local network' : 'this computer for now'}. People open it in a web browser. The browser is the untrusted side: everything it sends is checked before it is used${f.auth ? ', and every page or action first checks that the person is signed in and allowed to do it' : ''}.`,
  );
  p.push(
    `Records are kept in one database file in a data folder that only the app's user account can read.${f.fieldEncryption ? ' Sensitive fields are encrypted inside that file, so a copied file does not reveal them.' : ''}${f.uploads ? ' Uploaded files are stored in the same folder with random names and are never served as web pages.' : ''}`,
  );
  const vendors = components.filter((c) => c.trustZone === 'vendor');
  if (vendors.length) {
    p.push(
      `The app talks to ${vendors.length === 1 ? 'one outside service' : `${vendors.length} outside services`}: ${listWords(vendors.map((v) => v.name))}. It can only reach the addresses on its allow-list, waits at most 10 seconds for an answer, and keeps working (with that feature paused) if a service is down.`,
    );
  } else {
    p.push('The app does not talk to any outside service. Nothing leaves this computer.');
  }
  const crossing = flows.filter((fl) => fl.crossesTrustBoundary);
  p.push(
    `${crossing.length} connection${crossing.length === 1 ? '' : 's'} cross${crossing.length === 1 ? 'es' : ''} a trust boundary (${listWords(crossing.map((c) => c.id))}). Each one is labelled on the diagram with the protections that guard it. The ids starting with TPL- are protections already built and tested in the base template.`,
  );
  if (f.scheduler) p.push('Background jobs run inside the same program, one at a time, so they cannot pile up.');
  if (f.publicApi) p.push('Other programs can call the API with a key that a signed-in person creates. Keys can be revoked at any time.');
  p.push(`Security contact: ${profile.deployment.owner.name} (${profile.deployment.owner.contactEmail}).`);
  return p.join('\n\n');
}
