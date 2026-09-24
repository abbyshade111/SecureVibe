/** Design profiles + build specs used by the frameworks tests. */
import type { BuildSpec } from '@shared/design.js';
import { DesignProfileSchema, type DesignProfile } from '@shared/profile.js';

type Overrides = {
  app?: Partial<DesignProfile['app']>;
  users?: Partial<DesignProfile['users']>;
  data?: Partial<DesignProfile['data']>;
  capabilities?: Partial<DesignProfile['capabilities']>;
  deployment?: Partial<DesignProfile['deployment']>;
};

export function makeProfile(overrides: Overrides = {}): DesignProfile {
  return DesignProfileSchema.parse({
    app: { name: 'Test App', description: 'A test application', category: 'tracker', ...overrides.app },
    users: { audience: 'just-me', requiresSignIn: false, ...overrides.users },
    data: { categories: ['business-confidential'], ...overrides.data },
    capabilities: { ...overrides.capabilities },
    deployment: {
      target: 'local-only',
      owner: { name: 'Pat Owner', contactEmail: 'pat@example.com' },
      ...overrides.deployment,
    },
    meta: {},
  });
}

export function makeBuildSpec(features: Partial<BuildSpec['features']> = {}): BuildSpec {
  return {
    features: {
      auth: false,
      adminMfa: false,
      userMfa: false,
      uploads: false,
      ai: false,
      aiActions: false,
      aiWebSearch: false,
      aiModeration: false,
      email: false,
      scheduler: false,
      publicApi: false,
      payments: false,
      fieldEncryption: false,
      retentionJobs: false,
      lanBinding: false,
      tlsMode: 'off',
      ...features,
    },
    packageName: 'test-app',
    sessionPolicy: { idleMinutes: 30, absoluteHours: 12, maxConcurrent: 5 },
    brief: '',
  };
}

/** Local-only personal tracker, no sign-in, no personal data: level 1. */
export const localNoAuth = {
  profile: makeProfile(),
  buildSpec: makeBuildSpec(),
};

/** Customer-facing app with health data, uploads and an AI assistant that keeps history: level 2. */
export const customersHealthAi = {
  profile: makeProfile({
    app: { name: 'Clinic Notes', category: 'crm' },
    users: {
      audience: 'customers',
      requiresSignIn: true,
      roles: [
        { name: 'admin', label: 'Administrator', isAdmin: true },
        { name: 'member', label: 'Member', isAdmin: false },
      ],
    },
    data: { categories: ['contact', 'health', 'files'], aboutOtherPeople: true },
    capabilities: {
      fileUploads: true,
      uploadKinds: ['documents'],
      aiAssistant: {
        enabled: true,
        purpose: 'help staff summarize notes',
        dataItCanSee: 'users-own-records',
        canTakeActions: false,
        storesHistory: true,
        canSearchWeb: false,
        webSearchSites: [],
      },
    },
    deployment: { target: 'internet-later', businessImpact: 'high' },
  }),
  buildSpec: makeBuildSpec({
    auth: true,
    adminMfa: true,
    userMfa: true,
    uploads: true,
    ai: true,
    fieldEncryption: true,
    tlsMode: 'proxy',
  }),
};

/** Same app but the assistant may take actions (adds AISVS C9.2/C9.3/C9.5). */
export const customersHealthAiActions = {
  profile: makeProfile({
    ...customersHealthAi.profile,
    capabilities: {
      ...customersHealthAi.profile.capabilities,
      aiAssistant: { ...customersHealthAi.profile.capabilities.aiAssistant, canTakeActions: true },
    },
  }),
  buildSpec: makeBuildSpec({ ...customersHealthAi.buildSpec.features, aiActions: true }),
};

/** SecureVibe assessing itself (self-assessment/profile.json shape). */
export const selfAssessment = {
  profile: makeProfile({
    app: { name: 'SecureVibe', category: 'internal-tool', description: 'Local vibe-coding tool' },
    users: { audience: 'just-me', requiresSignIn: false },
    data: { categories: ['credentials', 'business-confidential'] },
    capabilities: {
      aiAssistant: {
        enabled: true,
        purpose: 'design and generate code',
        dataItCanSee: 'all-records',
        canTakeActions: true,
        storesHistory: false,
        canSearchWeb: false,
        webSearchSites: [],
      },
      externalApis: [
        { name: 'Anthropic API', purpose: 'code generation and review', sendsPersonalData: false },
        { name: 'npm registry', purpose: 'installing packages', sendsPersonalData: false },
      ],
    },
    deployment: { target: 'local-only' },
  }),
  buildSpec: makeBuildSpec({ ai: true, aiActions: true }),
};
