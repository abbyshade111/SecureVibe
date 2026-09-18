/**
 * Built-in wizard copy used only when GET /api/knowledge/wizard-copy is unreachable or malformed.
 * It is deliberately plainer than data/knowledge/wizard-copy.json (the normal source) but keeps
 * the wizard usable: every question the profile schema requires is covered.
 */
import type { WizardCopy, WizardOption } from './wizardCopyTypes';

function opts(pairs: [string, string, string?][]): WizardOption<string>[] {
  return pairs.map(([value, label, description]) => ({ value, label, description }));
}

export const FALLBACK_WIZARD_COPY: WizardCopy = {
  version: 'fallback',
  description: 'Built-in wizard copy (the usual copy file could not be loaded).',
  common: {
    notSureLabel: 'Not sure',
    notSureExplanation: 'We will pick the safer answer for you and note it as an assumption. You can change it later.',
    recommendedBadge: 'Recommended',
    whyWeAskLabel: 'Why we ask',
    whatThisChangesLabel: 'What this changes',
    assumptionPrefix: 'We assumed',
    authenticatorNotice:
      'Some answers turn on two-step sign-in for administrators, which needs a free authenticator app on a phone.',
    freeTextNotice: 'Free text is checked for attempts to give the AI hidden instructions before it is used.',
    scopeNotice: 'SecureVibe builds web apps that run on your own computer first.',
  },
  steps: [
    { id: 'about', title: 'What are you building?', intro: 'Tell us about the app in your own words.', sbdStep: 1, estimatedMinutes: 3 },
    { id: 'users', title: 'Who will use it?', intro: 'Who uses the app decides how we protect sign-in.', sbdStep: 1, estimatedMinutes: 2 },
    { id: 'data', title: 'What information will it handle?', intro: 'The information you keep decides how strongly we protect it.', sbdStep: 1, estimatedMinutes: 2 },
    { id: 'features', title: 'Features & connections', intro: 'Turn on only what you need.', sbdStep: 1, estimatedMinutes: 3 },
    { id: 'deployment', title: 'Where will it run?', intro: 'Where the app runs decides how exposed it is.', sbdStep: 1, estimatedMinutes: 1 },
    { id: 'summary', title: "Here's what we'll build", intro: 'Check the summary before we build.', sbdStep: 2, estimatedMinutes: 3 },
    { id: 'build', title: 'Build', intro: 'We write, install, test and check your app.', sbdStep: 9, estimatedMinutes: 10 },
    { id: 'results', title: 'Results', intro: 'How to run your app and what we found.', sbdStep: 10, estimatedMinutes: 5 },
  ],
  questions: [
    {
      id: 'app.name', step: 'about', inputType: 'text', required: true, title: 'Name your app',
      question: 'What should we call your app?', helpText: 'A short, friendly name.',
      whyWeAsk: 'The name appears on every page and in the reports.', maxLength: 60,
      notSure: { available: false }, whatThisChanges: {},
    },
    {
      id: 'app.tagline', step: 'about', inputType: 'text', required: false, title: 'One-line summary',
      question: 'In one line, what does it do?', whyWeAsk: 'It becomes the first line of the design document.',
      maxLength: 120, notSure: { available: false }, whatThisChanges: {},
    },
    {
      id: 'app.description', step: 'about', inputType: 'longtext', required: true, title: 'Describe your app',
      question: 'What should your app do, in your own words?',
      helpText: 'Say who uses it, what they do, and what information it keeps.',
      whyWeAsk: 'This guides the AI that writes your app. Security decisions come only from your other answers.',
      maxLength: 4000, screenedForInjection: true, notSure: { available: false }, whatThisChanges: {},
    },
    {
      id: 'app.category', step: 'about', inputType: 'single-choice', required: true, title: 'Type of app',
      question: 'Which of these is closest to your app?', whyWeAsk: 'It helps us suggest sensible starting points.',
      options: opts([
        ['tracker', 'Tracker'], ['booking', 'Booking or appointments'], ['inventory', 'Inventory or assets'],
        ['content', 'Content or knowledge'], ['dashboard', 'Dashboard or reports'], ['intake-form', 'Forms or applications'],
        ['crm', 'Customers and contacts'], ['ai-assistant', 'AI assistant'], ['marketplace', 'Marketplace or listings'],
        ['internal-tool', 'Internal tool'], ['other', 'Something else'],
      ]),
      notSure: { available: true, choosesValue: 'other', behaviour: 'We treat it as a general app.' },
      whatThisChanges: {},
    },
    {
      id: 'app.entities', step: 'about', inputType: 'entities', required: false, title: 'What it keeps track of',
      question: 'What kinds of things will your app keep track of?',
      helpText: 'For example: Appointment, Customer, Product.',
      whyWeAsk: 'Each kind of record becomes its own protected pages.', maxEntities: 20, maxFieldsPerEntity: 40,
      notSure: { available: true, behaviour: 'We suggest typical records for your type of app.' },
      whatThisChanges: {},
      sub: {
        field: {
          title: 'Details of a record', nameLabel: 'Detail name', namePlaceholder: 'customer name',
          typeLabel: 'What kind of value is it?',
          types: opts([
            ['text', 'Short text'], ['longtext', 'Long text'], ['number', 'Number'], ['money', 'Money amount'],
            ['date', 'Date'], ['datetime', 'Date and time'], ['boolean', 'Yes / No'], ['email', 'Email address'],
            ['url', 'Web address'], ['phone', 'Phone number'], ['choice', 'One of a list'], ['file', 'Attached file'],
          ]),
          requiredLabel: 'Must be filled in', sensitiveLabel: 'This is sensitive',
          sensitiveHelp: 'Tick this for details like health notes, ID numbers or bank details.',
          sensitiveWhatThisChanges: ['Sensitive details are encrypted and hidden from logs.'],
        },
        access: {
          title: 'Who can see these records?',
          options: opts([
            ['all-signed-in', 'Everyone who is signed in'], ['owner-only', 'Only the person who created it'],
            ['admin-only', 'Only administrators'], ['public-read', 'Anyone can view, only signed-in people can edit'],
          ]),
          notSure: { available: true, choosesValue: 'owner-only', behaviour: 'We choose the least-access option.' },
          whatThisChanges: {},
        },
      },
    },
    {
      id: 'app.keyFeatures', step: 'about', inputType: 'list', required: false, title: 'Key features',
      question: 'What are the main things people should be able to do?', maxItems: 30, maxLength: 200,
      screenedForInjection: true, whyWeAsk: 'This is the to-do list for the AI that builds your app.',
      notSure: { available: true, behaviour: 'We build the standard pages for each record.' }, whatThisChanges: {},
    },
    {
      id: 'app.theme', step: 'about', inputType: 'single-choice', required: false, title: 'How it should look',
      question: 'Which look would you like for your app?',
      whyWeAsk: 'Only the colours change. Every look is tested to stay readable, so the choice cannot make your app harder to use.',
      options: opts([
        ['calm', 'Calm (default)'], ['warm', 'Warm'], ['forest', 'Forest'], ['contrast', 'High contrast'],
      ]),
      notSure: { available: true, choosesValue: 'calm', behaviour: 'We use the calm look.' }, whatThisChanges: {},
    },
    {
      id: 'users.audience', step: 'users', inputType: 'single-choice', required: true, title: 'Who will use it',
      question: 'Who will use this app?', whyWeAsk: 'This sets how strict sign-in and anti-abuse limits are.',
      options: opts([
        ['just-me', 'Only me'], ['my-team', 'Me and my team'], ['customers', 'My customers or clients'],
        ['public', 'Anyone on the internet'],
      ]),
      notSure: { available: true, choosesValue: 'customers', behaviour: 'We assume customers will use it (the safer choice).' },
      whatThisChanges: {},
    },
    {
      id: 'users.requiresSignIn', step: 'users', inputType: 'boolean', required: true, title: 'Sign-in',
      question: 'Should people have to sign in to use it?', whyWeAsk: 'Sign-in is how the app knows who is doing what.',
      options: [
        { value: true, label: 'Yes, require sign-in', recommended: true },
        { value: false, label: 'No sign-in' },
      ],
      notSure: { available: true, choosesValue: true, behaviour: 'We require sign-in (the safer choice).' },
      whatThisChanges: {},
    },
    {
      id: 'users.roles', step: 'users', inputType: 'roles', required: false, title: 'Kinds of users',
      question: 'What kinds of users are there, and what may each kind do?',
      whyWeAsk: 'Every page checks the user kind before doing anything.', maxRoles: 8,
      templates: [
        { name: 'owner', label: 'Owner', description: 'Manages accounts and settings.', isAdmin: true },
        { name: 'staff', label: 'Staff', description: 'Does the day-to-day work.', isAdmin: false },
        { name: 'customer', label: 'Customers', description: 'Sees only their own records.', isAdmin: false },
      ],
      notSure: { available: true, behaviour: 'We create an Owner role plus Staff.' }, whatThisChanges: {},
    },
    {
      id: 'users.expectedUserCount', step: 'users', inputType: 'single-choice', required: true, title: 'How many people',
      question: 'Roughly how many people will use it?', whyWeAsk: 'This affects performance and rate-limit defaults.',
      options: opts([['1', 'Just 1'], ['2-20', '2 to 20'], ['21-500', '21 to 500'], ['500+', 'More than 500']]),
      notSure: { available: true, choosesValue: '2-20', behaviour: 'We assume a small team.' }, whatThisChanges: {},
    },
    {
      id: 'users.registration', step: 'users', inputType: 'single-choice', required: true, title: 'Signing up',
      question: 'How do people get an account?', whyWeAsk: 'This decides whether sign-up is open to anyone.',
      options: opts([
        ['invite-only', 'By invitation only'], ['admin-created', 'An administrator creates accounts'],
        ['open', 'Anyone can sign up'],
      ]),
      notSure: { available: true, choosesValue: 'admin-created', behaviour: 'An administrator creates accounts (the safer choice).' },
      whatThisChanges: {},
    },
    {
      id: 'users.adminMfa', step: 'users', inputType: 'boolean', required: true, title: 'Administrator two-step sign-in',
      question: 'Should administrators use two-step sign-in (an authenticator app)?',
      whyWeAsk: 'Administrator accounts are the most valuable target.',
      options: [{ value: true, label: 'Yes', recommended: true }, { value: false, label: 'No' }],
      notSure: { available: true, choosesValue: true, behaviour: 'We turn it on (the safer choice).' }, whatThisChanges: {},
    },
    {
      id: 'data.categories', step: 'data', inputType: 'multi-choice', required: true, title: 'Kinds of information',
      question: 'Which kinds of information will the app keep?',
      whyWeAsk: 'Some information can harm people if it leaks.',
      options: opts([
        ['contact', 'Contact details'], ['financial', 'Financial information'], ['payment-card', 'Payment card details'],
        ['health', 'Health information'], ['government-id', 'Government ID numbers'], ['credentials', 'Passwords or secrets of users'],
        ['children', 'Information about children'], ['location', 'Precise location'], ['files', 'Uploaded files'],
        ['business-confidential', 'Confidential business information'], ['other-personal', 'Other personal information'],
      ]),
      sensitiveValues: ['financial', 'payment-card', 'health', 'government-id', 'children'],
      notSure: { available: true, choosesValue: ['contact', 'other-personal'], behaviour: 'We assume contact and other personal information (the safer choice).' },
      whatThisChanges: {},
    },
    {
      id: 'data.aboutOtherPeople', step: 'data', inputType: 'boolean', required: true, title: 'About other people',
      question: 'Is any of this information about people other than the person signed in (customers, patients, pupils…)?',
      whyWeAsk: 'Information about other people needs extra care and export/delete tools.',
      options: [{ value: true, label: 'Yes' }, { value: false, label: 'No', recommended: true }],
      notSure: { available: true, choosesValue: true, behaviour: 'We assume yes (the safer choice).' }, whatThisChanges: {},
    },
    {
      id: 'data.retention', step: 'data', inputType: 'single-choice', required: true, title: 'Keeping records',
      question: 'How long should records be kept?', whyWeAsk: 'This drives an automatic clean-up job.',
      options: opts([['keep-until-deleted', 'Keep until someone deletes it'], ['auto-delete-after-period', 'Automatically delete after a period']]),
      notSure: { available: true, choosesValue: 'keep-until-deleted', behaviour: 'We keep records until deleted.' },
      whatThisChanges: {},
    },
    {
      id: 'data.retentionMonths', step: 'data', inputType: 'number', required: false,
      showWhen: { path: 'data.retention', equals: 'auto-delete-after-period' },
      title: 'Retention period', question: 'After how many months should old records be removed?',
      whyWeAsk: 'This number goes into the automatic clean-up job.', min: 1, max: 120,
      notSure: { available: true, choosesValue: 24, behaviour: 'We use 24 months.' }, whatThisChanges: {},
    },
    {
      id: 'data.region', step: 'data', inputType: 'single-choice', required: true, title: 'Region',
      question: 'Where are most of the people whose information you keep?',
      whyWeAsk: 'This suggests which privacy rules may apply, in plain language.',
      options: opts([['eu-uk', 'UK or EU'], ['us', 'United States'], ['other', 'Somewhere else'], ['unsure', 'Not sure']]),
      notSure: { available: true, choosesValue: 'unsure', behaviour: 'We leave it unsure.' }, whatThisChanges: {},
    },
    {
      id: 'capabilities.fileUploads', step: 'features', inputType: 'boolean', required: true, title: 'File uploads',
      question: 'Do people need to upload files (photos, documents)?', whyWeAsk: 'Uploads need their own protections.',
      options: [{ value: true, label: 'Yes' }, { value: false, label: 'No', recommended: true }],
      notSure: { available: true, choosesValue: false, behaviour: 'We leave uploads off.' }, whatThisChanges: {},
    },
    {
      id: 'capabilities.uploadKinds', step: 'features', inputType: 'multi-choice', required: false,
      showWhen: { path: 'capabilities.fileUploads', equals: true },
      title: 'Kinds of files', question: 'What kinds of files?', whyWeAsk: 'This sets which file types are allowed.',
      options: opts([['images', 'Images'], ['documents', 'Documents'], ['spreadsheets', 'Spreadsheets'], ['other', 'Other']]),
      notSure: { available: true, choosesValue: ['images', 'documents'], behaviour: 'We allow images and documents.' },
      whatThisChanges: {},
    },
    {
      id: 'capabilities.aiAssistant.enabled', step: 'features', inputType: 'boolean', required: true, title: 'AI assistant',
      question: 'Do you want an AI assistant inside the app?', whyWeAsk: 'An assistant that reads your data is a new way in for attackers.',
      options: [{ value: true, label: 'Yes' }, { value: false, label: 'No', recommended: true }],
      notSure: { available: true, choosesValue: false, behaviour: 'We leave the assistant off.' }, whatThisChanges: {},
    },
    {
      id: 'capabilities.aiAssistant.purpose', step: 'features', inputType: 'text', required: false,
      showWhen: { path: 'capabilities.aiAssistant.enabled', equals: true },
      title: 'Assistant purpose', question: 'What should the assistant help with?',
      whyWeAsk: 'This becomes part of the instructions given to the assistant.', maxLength: 500,
      notSure: { available: false }, whatThisChanges: {},
    },
    {
      id: 'capabilities.aiAssistant.dataItCanSee', step: 'features', inputType: 'single-choice', required: false,
      showWhen: { path: 'capabilities.aiAssistant.enabled', equals: true },
      title: 'What the assistant may read', question: 'Which of your app’s records may the assistant read?',
      whyWeAsk: 'The less it can read, the less it can be tricked into revealing.',
      options: opts([
        ['nothing', 'Nothing from the app'], ['users-own-records', "The person's own records"],
        ['all-records', 'Everything the person can see'],
      ]),
      notSure: { available: true, choosesValue: 'nothing', behaviour: 'We let it read nothing from the app.' },
      whatThisChanges: {},
    },
    {
      id: 'capabilities.aiAssistant.canTakeActions', step: 'features', inputType: 'boolean', required: false,
      showWhen: { path: 'capabilities.aiAssistant.enabled', equals: true },
      title: 'Assistant actions', question: 'May the assistant change data, not just answer questions?',
      whyWeAsk: 'Actions always need the person to confirm first.',
      options: [{ value: true, label: 'Yes' }, { value: false, label: 'No', recommended: true }],
      notSure: { available: true, choosesValue: false, behaviour: 'We leave actions off.' }, whatThisChanges: {},
    },
    {
      id: 'capabilities.aiAssistant.storesHistory', step: 'features', inputType: 'boolean', required: false,
      showWhen: { path: 'capabilities.aiAssistant.enabled', equals: true },
      title: 'Conversation history', question: 'Should the assistant remember past conversations?',
      whyWeAsk: 'Stored history is more data that could leak.',
      options: [{ value: true, label: 'Yes' }, { value: false, label: 'No', recommended: true }],
      notSure: { available: true, choosesValue: false, behaviour: 'We leave history off.' }, whatThisChanges: {},
    },
    {
      id: 'capabilities.email', step: 'features', inputType: 'boolean', required: true, title: 'Email notifications',
      question: 'Does the app need to send emails?', whyWeAsk: 'Outgoing email needs safe templates.',
      options: [{ value: true, label: 'Yes' }, { value: false, label: 'No', recommended: true }],
      notSure: { available: true, choosesValue: false, behaviour: 'We leave email off.' }, whatThisChanges: {},
    },
    {
      id: 'capabilities.externalApis', step: 'features', inputType: 'external-apis', required: false,
      title: 'Other online services', question: 'Does the app need to talk to other online services?',
      whyWeAsk: 'We only allow the app to contact the services you list.', maxItems: 10,
      fields: {
        name: { label: 'Service name' }, purpose: { label: 'What it is for' },
        sendsPersonalData: { label: 'It will receive people’s personal details' },
      },
      notSure: { available: true, choosesValue: [], behaviour: 'We connect to nothing.' }, whatThisChanges: {},
    },
    {
      id: 'capabilities.scheduledJobs', step: 'features', inputType: 'boolean', required: true, title: 'Scheduled tasks',
      question: 'Does the app need to run anything on a schedule (daily reminders, clean-up)?',
      whyWeAsk: 'Scheduled jobs run without anyone watching, so they follow strict rules.',
      options: [{ value: true, label: 'Yes' }, { value: false, label: 'No', recommended: true }],
      notSure: { available: true, choosesValue: false, behaviour: 'We leave scheduled jobs off.' }, whatThisChanges: {},
    },
    {
      id: 'capabilities.publicApi', step: 'features', inputType: 'boolean', required: true, title: 'Other software',
      question: 'Will other software connect to this app directly (not through a browser)?',
      whyWeAsk: 'This turns on API keys instead of a browser sign-in.',
      options: [{ value: true, label: 'Yes' }, { value: false, label: 'No', recommended: true }],
      notSure: { available: true, choosesValue: false, behaviour: 'We leave this off.' }, whatThisChanges: {},
    },
    {
      id: 'capabilities.payments', step: 'features', inputType: 'boolean', required: true, title: 'Payments',
      question: 'Does the app need to take payments?', whyWeAsk: 'Card details are never stored by SecureVibe; a provider handles checkout.',
      options: [{ value: true, label: 'Yes' }, { value: false, label: 'No', recommended: true }],
      notSure: { available: true, choosesValue: false, behaviour: 'We leave payments off.' }, whatThisChanges: {},
    },
    {
      id: 'deployment.target', step: 'deployment', inputType: 'single-choice', required: true, title: 'Where it runs',
      question: 'Where will the app run?', whyWeAsk: 'Where it runs decides how exposed it is.',
      options: opts([
        ['local-only', 'Only on this computer'], ['local-network', 'On my office network'],
        ['internet-later', 'On the internet (now or later)'],
      ]),
      notSure: { available: true, choosesValue: 'local-only', behaviour: 'We keep it on this computer (the safer choice).' },
      whatThisChanges: {},
    },
    {
      id: 'deployment.owner.name', step: 'deployment', inputType: 'text', required: true, title: 'Owner name',
      question: 'Who is responsible for this app?', whyWeAsk: 'This name goes into the reports and the SECURITY file.',
      maxLength: 80, notSure: { available: false }, whatThisChanges: {},
    },
    {
      id: 'deployment.owner.contactEmail', step: 'deployment', inputType: 'email', required: true, title: 'Contact email',
      question: 'Which email address should people use to report a security problem?',
      whyWeAsk: 'A clear way to report problems is a basic OWASP requirement.', maxLength: 120,
      notSure: { available: false }, whatThisChanges: {},
    },
    {
      id: 'deployment.businessImpact', step: 'deployment', inputType: 'single-choice', required: true, title: 'How much it matters',
      question: 'If this app were down for a day, what would happen?',
      whyWeAsk: 'This tells us how carefully to treat problems.',
      options: [
        { value: 'low', label: 'Low', description: 'Mildly inconvenient.' },
        { value: 'normal', label: 'Normal', description: 'Some work would be disrupted.' },
        { value: 'high', label: 'High', description: 'It would seriously hurt the business.' },
      ],
      notSure: { available: true, choosesValue: 'normal', behaviour: 'We assume normal impact.' }, whatThisChanges: {},
    },
  ],
  summary: {
    headline: "Here's what we'll build",
    sections: {
      app: 'Your app', protections: 'How it will be protected', assumptions: 'Things we assumed (please check)',
      extraCare: 'Extra care level', authenticator: 'You will need an authenticator app',
      technical: 'Technical details for your developer',
    },
    extraCareLevels: {
      low: { label: 'Standard care', text: 'Your answers do not point to unusual risks.' },
      normal: { label: 'Standard care with a threat model', text: 'Some answers mean we also write a threat model.' },
      high: { label: 'Extra care', text: 'Your app handles sensitive information or matters a lot to your business.' },
    },
    approveButton: 'Build my app',
    approveNote: 'Building uses the AI service and costs money (an estimate is shown first).',
    quickModeNote: "Because you used Quick mode, answers marked 'We assumed' were guessed from your description.",
  },
  whatThisChanges: {},
};
