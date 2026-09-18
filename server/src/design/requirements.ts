/**
 * SbD step 1: security requirements derived from the profile, each traceable to the answer that caused it and
 * mapped to the ASVS / AISVS requirements and SbD checklist controls that verify it.
 */
import type { SecurityRequirement } from '@shared/design.js';
import type { DesignProfile } from '@shared/profile.js';
import { DATA_CATEGORY_LABELS, listWords, type ProfileFacts } from './conditions.js';

type Draft = Omit<SecurityRequirement, 'id' | 'asvs' | 'aisvs' | 'sbd'> & {
  asvs?: string[];
  aisvs?: string[];
  sbd?: string[];
};

export function deriveSecurityRequirements(profile: DesignProfile, f: ProfileFacts): SecurityRequirement[] {
  const drafts: Draft[] = [];
  const add = (d: Draft) => drafts.push(d);
  const name = f.appName;

  add({
    statement:
      f.deployment === 'local-only'
        ? `${name} only listens on this computer. Nothing on the network can reach it.`
        : f.deployment === 'local-network'
          ? `${name} is reachable on your local network only, over an encrypted connection.`
          : `${name} stays on this computer until it is put behind an HTTPS proxy. It never goes online unencrypted.`,
    category: 'confidentiality',
    drivenBy: ['deployment.target'],
    asvs: f.tls ? ['V12.1.1', 'V12.2.1', 'V3.4.1'] : [],
    sbd: ['AS-01', 'AC-01'],
  });
  add({
    statement: 'Every piece of input is checked on the server before it is used. Unexpected fields are rejected.',
    category: 'integrity',
    drivenBy: ['app.entities'],
    asvs: ['V2.2.1', 'V2.2.2', 'V15.3.3', 'V1.2.4', 'V1.2.1'],
    sbd: ['AS-05'],
  });
  add({
    statement: 'The browser is protected: strict security headers, no cross-site request forgery, no inline scripts.',
    category: 'integrity',
    drivenBy: ['app.category'],
    asvs: ['V3.4.3', 'V3.5.1', 'V3.3.2'],
    sbd: ['AS-01'],
  });
  add({
    statement: 'When something goes wrong, people see a short generic message. Technical details never leak.',
    category: 'confidentiality',
    drivenBy: ['app.category'],
    asvs: ['V16.5.1', 'V16.5.3'],
    sbd: ['RR-01'],
  });
  add({
    statement:
      'Security-relevant actions (sign-ins, denied access, changes by administrators) are recorded in a tamper-evident log kept for at least 12 months.',
    category: 'accountability',
    drivenBy: ['users.roles', 'deployment.owner'],
    asvs: ['V16.2.1', 'V16.3.1', 'V16.3.2', 'V16.4.2'],
    sbd: ['MT-01', 'MT-07'],
  });
  add({
    statement:
      'The app limits how many requests one person or address can make, stops slow requests, and reports whether it is healthy.',
    category: 'availability',
    drivenBy: ['users.audience', 'users.expectedUserCount'],
    asvs: ['V2.4.1', 'V15.2.2'],
    sbd: ['RR-06', 'RR-07'],
  });
  add({
    statement: 'Secrets and keys live only in the configuration file, never in code, logs or reports.',
    category: 'confidentiality',
    drivenBy: ['deployment.target'],
    asvs: ['V13.3.2', 'V16.2.5'],
    sbd: ['AC-05'],
  });
  add({
    statement: 'Third-party packages are locked to tested versions, inventoried, and checked for known problems.',
    category: 'integrity',
    drivenBy: ['app.category'],
    asvs: ['V15.1.1', 'V15.1.2', 'V15.2.1'],
    sbd: ['RR-01'],
  });
  add({
    statement: `A written incident plan names ${profile.deployment.owner.name} as the security contact and says what to do when something goes wrong.`,
    category: 'compliance',
    drivenBy: ['deployment.owner'],
    asvs: ['V6.1.1'],
    sbd: ['MT-06'],
  });
  add({
    statement: 'Saving the same form twice, or two people editing at once, never corrupts a record.',
    category: 'integrity',
    drivenBy: ['app.entities'],
    asvs: ['V2.3.3'],
    sbd: ['DM-03', 'RR-05'],
  });

  if (f.auth) {
    add({
      statement: `People must sign in with a password of at least 12 characters before using ${name}. Guessing attempts are slowed down and locked temporarily.`,
      category: 'confidentiality',
      drivenBy: ['users.requiresSignIn', 'users.audience'],
      asvs: ['V6.2.1', 'V6.2.4', 'V6.3.1', 'V6.3.2', 'V11.4.2'],
      sbd: ['AC-02'],
    });
    add({
      statement: `Each role only gets what it needs (${listWords(f.roles.map((r) => r.label))}). Records with an owner are visible only to that owner and administrators.`,
      category: 'confidentiality',
      drivenBy: ['users.roles', 'app.entities'],
      asvs: ['V8.2.1', 'V8.2.2', 'V8.3.1', 'V15.3.1'],
      sbd: ['AC-03'],
    });
    add({
      statement: `Sessions end after ${f.level === 2 ? '15' : '30'} minutes of inactivity and after ${f.level === 2 ? '8' : '12'} hours at most. Logging out works on every page and ends the session on the server.`,
      category: 'confidentiality',
      drivenBy: ['users.requiresSignIn'],
      asvs: ['V7.2.1', 'V7.2.4', 'V7.3.1', 'V7.3.2', 'V7.4.1', 'V7.4.2'],
      sbd: ['AC-02'],
    });
    add({
      statement: 'No account exists with a default password. The first administrator gets a one-time password that must be changed.',
      category: 'confidentiality',
      drivenBy: ['users.roles'],
      asvs: ['V6.3.2', 'V6.4.1'],
      sbd: ['AC-02'],
    });
    if (f.adminMfa) {
      add({
        statement: 'Administrators must confirm sign-in with an authenticator app (a second factor).',
        category: 'confidentiality',
        drivenBy: f.sensitiveData || f.sensitiveFields ? ['data.categories', 'users.adminMfa'] : ['users.adminMfa'],
        asvs: ['V6.5.1', 'V6.5.3', 'V6.3.3'],
        sbd: ['AC-02'],
      });
    }
    if (f.userMfa) {
      add({
        statement: 'Every person may turn on an authenticator app for their own account.',
        category: 'confidentiality',
        drivenBy: ['data.categories', 'users.audience'],
        asvs: ['V6.5.1', 'V6.5.3'],
        sbd: ['AC-02'],
      });
    }
    if (profile.users.registration === 'open') {
      add({
        statement: 'Anyone can create an account, but sign-ups are limited per address so robots cannot flood the app.',
        category: 'availability',
        drivenBy: ['users.registration'],
        asvs: ['V2.4.1'],
        sbd: ['RR-07'],
      });
    }
    add({
      statement: 'Changing an email address or the authenticator setting requires the password again.',
      category: 'integrity',
      drivenBy: ['users.requiresSignIn'],
      asvs: ['V7.5.1'],
      sbd: ['AC-02'],
    });
  }

  if (f.personalData) {
    add({
      statement: `Information about people (${listWords(f.personalCategories.map((c) => DATA_CATEGORY_LABELS[c])) || 'personal details'}) is listed with what it is used for, who owns it, and how long it is kept.`,
      category: 'privacy',
      drivenBy: ['data.categories', 'data.aboutOtherPeople'],
      asvs: ['V14.1.1', 'V14.1.2'],
      sbd: ['DM-01'],
    });
    add({
      statement:
        profile.data.retention === 'auto-delete-after-period'
          ? `Records about people are deleted automatically after ${profile.data.retentionMonths ?? 12} months. A person's data can also be exported or deleted on request.`
          : "Records are kept until deleted. Administrators can export or delete a person's data on request.",
      category: 'privacy',
      drivenBy: ['data.retention'],
      asvs: ['V14.2.4'],
      sbd: ['DM-05'],
    });
    add({
      statement: 'The privacy rules that may apply (for example GDPR, CCPA or HIPAA) are named in the data protection note.',
      category: 'compliance',
      drivenBy: ['data.region', 'data.categories'],
      asvs: ['V14.1.2'],
      sbd: ['AC-06'],
    });
  }

  if (f.fieldEncryption) {
    add({
      statement: `Sensitive fields${f.sensitiveCategories.length ? ` (${listWords(f.sensitiveCategories.map((c) => DATA_CATEGORY_LABELS[c]))})` : ''} are encrypted in the database with a key that can be rotated.`,
      category: 'confidentiality',
      drivenBy: f.sensitiveFields ? ['data.categories', 'app.entities.fields.sensitive'] : ['data.categories'],
      asvs: ['V11.3.1', 'V11.3.2', 'V11.3.3', 'V11.2.2'],
      sbd: ['DM-02'],
    });
  }
  if (f.personalData || f.fieldEncryption) {
    add({
      statement: 'Sensitive values never appear in web addresses or in log files.',
      category: 'confidentiality',
      drivenBy: ['data.categories'],
      asvs: ['V14.2.1', 'V16.2.5'],
      sbd: ['DM-01'],
    });
  }

  if (f.uploads) {
    add({
      statement:
        'Uploaded files are checked for type and size, renamed, stored outside the web folder, and downloaded as attachments.',
      category: 'integrity',
      drivenBy: ['capabilities.fileUploads'],
      asvs: ['V5.2.1', 'V5.2.2', 'V5.3.1', 'V5.3.2', 'V5.4.1'],
      sbd: ['DM-01'],
    });
  }

  if (f.ai) {
    add({
      statement:
        'The AI assistant treats everything typed into it as untrusted, screens it for trickery, and checks every answer before showing it.',
      category: 'integrity',
      drivenBy: ['capabilities.aiAssistant.enabled'],
      aisvs: ['C2.1.1', 'C2.1.3', 'C2.1.4', 'C2.1.6', 'C7.1.1', 'C7.1.2'],
      sbd: ['AS-01'],
    });
    add({
      statement: `The assistant only sees ${aiDataPhrase(profile)}, always through the signed-in person's own permissions.`,
      category: 'confidentiality',
      drivenBy: ['capabilities.aiAssistant.dataItCanSee'],
      aisvs: ['C5.2.1', 'C5.2.4', 'C9.5.3', 'C9.5.4'],
      sbd: ['AC-03'],
    });
    add({
      statement:
        'Every AI request is logged with its cost. Each person has a daily budget, and an administrator can switch the assistant off at once.',
      category: 'accountability',
      drivenBy: ['capabilities.aiAssistant.enabled'],
      aisvs: ['C12.1.1', 'C12.1.3', 'C9.1.2', 'C9.6.1', 'C12.4.3'],
      sbd: ['MT-01', 'RR-07'],
    });
    if (f.aiActions) {
      add({
        statement: 'The assistant can propose a change, but nothing happens until the person confirms it.',
        category: 'integrity',
        drivenBy: ['capabilities.aiAssistant.canTakeActions'],
        aisvs: ['C9.2.1', 'C9.3.2', 'C9.5.1'],
        sbd: ['AC-03'],
      });
    }
    if (f.aiModeration) {
      add({
        statement: 'Messages to and from the assistant are screened for harmful content.',
        category: 'compliance',
        drivenBy: ['capabilities.aiAssistant.enabled', 'users.audience'],
        aisvs: ['C2.2.1', 'C7.3.1'],
      });
    }
    if (f.aiHistory) {
      add({
        statement: 'Conversation history belongs to one person, is never shown to others, and can be cleared.',
        category: 'privacy',
        drivenBy: ['capabilities.aiAssistant.storesHistory'],
        aisvs: ['C8.1.3', 'C8.3.2'],
        sbd: ['DM-05'],
      });
    }
  }

  if (f.externalApis || f.ai || f.email) {
    add({
      statement: `${name} only talks to the outside services named in its configuration. Each call has a time limit and a failure never takes the app down.`,
      category: 'availability',
      drivenBy: ['capabilities.externalApis', 'capabilities.aiAssistant.enabled', 'capabilities.email'],
      asvs: ['V13.2.4', 'V13.2.5', 'V12.3.2', 'V15.3.2', 'V16.5.2', 'V13.1.1'],
      sbd: ['RR-02', 'AS-01'],
    });
  }
  const sharingApis = profile.capabilities.externalApis.filter((a) => a.sendsPersonalData);
  if (sharingApis.length) {
    add({
      statement: `Personal data sent to ${listWords(sharingApis.map((a) => a.name))} is kept to the minimum and listed in the data protection note.`,
      category: 'privacy',
      drivenBy: ['capabilities.externalApis'],
      asvs: ['V14.2.3', 'V14.1.2'],
      sbd: ['DM-01', 'AC-06'],
    });
  }
  if (f.email) {
    add({
      statement: 'Email addresses and subjects are cleaned before sending so nobody can add hidden recipients.',
      category: 'integrity',
      drivenBy: ['capabilities.email'],
      asvs: ['V1.3.11'],
    });
  }
  if (f.scheduler) {
    add({
      statement: 'Scheduled jobs run one at a time, never overlap, and record what they did.',
      category: 'integrity',
      drivenBy: f.retentionJobs ? ['capabilities.scheduledJobs', 'data.retention'] : ['capabilities.scheduledJobs'],
      asvs: ['V15.2.2'],
      sbd: ['RR-03'],
    });
  }
  if (f.publicApi) {
    add({
      statement:
        'Other programs use API keys that a person creates and can revoke. Keys are stored hashed, rate-limited, and never accepted in a web address.',
      category: 'confidentiality',
      drivenBy: ['capabilities.publicApi'],
      asvs: ['V14.2.1', 'V11.5.1', 'V8.2.1'],
      sbd: ['AC-03'],
    });
  }
  if (f.payments) {
    add({
      statement: `${name} never sees or stores card numbers. Payments happen on the provider's own page.`,
      category: 'compliance',
      drivenBy: ['capabilities.payments'],
      asvs: ['V14.2.1', 'V14.2.3'],
      sbd: ['AC-06', 'DM-01'],
    });
  }
  if (f.highImpact) {
    add({
      statement:
        'Because an outage would seriously hurt the business, the app reports its health, restarts cleanly, and every missing protection is treated as more serious.',
      category: 'availability',
      drivenBy: ['deployment.businessImpact'],
      asvs: ['V15.2.2'],
      sbd: ['RR-06', 'MT-06'],
    });
  }
  if (f.internet) {
    add({
      statement:
        'Before going online: HTTPS with a real certificate, a reverse proxy in front, secure cookies, and logs shipped to a separate place.',
      category: 'confidentiality',
      drivenBy: ['deployment.target'],
      asvs: ['V12.1.1', 'V3.4.1', 'V3.3.1', 'V4.1.3', 'V16.4.3'],
      sbd: ['AC-01', 'DM-02', 'MT-07'],
    });
  }

  return drafts.map((d, i) => ({
    id: `SR-${String(i + 1).padStart(2, '0')}`,
    statement: d.statement,
    category: d.category,
    drivenBy: d.drivenBy,
    asvs: d.asvs ?? [],
    aisvs: d.aisvs ?? [],
    sbd: d.sbd ?? [],
  }));
}

export function aiDataPhrase(profile: DesignProfile): string {
  switch (profile.capabilities.aiAssistant.dataItCanSee) {
    case 'nothing':
      return 'the message a person types (no stored records)';
    case 'users-own-records':
      return "the signed-in person's own records";
    case 'all-records':
      return 'the records the signed-in person is allowed to see';
  }
}
