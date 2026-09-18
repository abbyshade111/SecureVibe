/**
 * Shape of data/knowledge/wizard-copy.json, served by GET /api/knowledge/wizard-copy.
 * This is plain-language content, not a security contract, so it is typed here (web-only)
 * rather than in shared/src.
 */

export interface WizardOption<V = unknown> {
  value: V;
  label: string;
  description?: string;
  recommended?: boolean;
}

export interface WizardNotSure {
  available: boolean;
  choosesValue?: unknown;
  behaviour?: string;
}

export type WizardInputType =
  | 'text'
  | 'longtext'
  | 'email'
  | 'number'
  | 'boolean'
  | 'single-choice'
  | 'multi-choice'
  | 'list'
  | 'entities'
  | 'roles'
  | 'external-apis';

export interface WizardFieldTypeOption extends WizardOption<string> {}

export interface WizardEntitySub {
  field: {
    title: string;
    nameLabel: string;
    namePlaceholder: string;
    typeLabel: string;
    types: WizardFieldTypeOption[];
    requiredLabel: string;
    sensitiveLabel: string;
    sensitiveHelp: string;
    sensitiveWhatThisChanges: string[];
  };
  access: {
    title: string;
    options: WizardOption<string>[];
    notSure?: WizardNotSure;
    whatThisChanges: Record<string, string[]>;
  };
}

export interface WizardRoleTemplate {
  name: string;
  label: string;
  description?: string;
  isAdmin: boolean;
}

export interface WizardExternalApiFields {
  name: { label: string; placeholder?: string };
  purpose: { label: string; placeholder?: string };
  sendsPersonalData: { label: string; help?: string };
}

export interface WizardQuestion {
  id: string;
  step: string;
  inputType: WizardInputType;
  required: boolean;
  showWhen?: { path: string; equals: unknown };
  title: string;
  question: string;
  helpText?: string;
  whyWeAsk: string;
  options?: WizardOption<unknown>[];
  placeholder?: string;
  example?: string;
  maxLength?: number;
  min?: number;
  max?: number;
  maxItems?: number;
  maxEntities?: number;
  maxFieldsPerEntity?: number;
  maxRoles?: number;
  screenedForInjection?: boolean;
  sensitiveValues?: string[];
  notSure: WizardNotSure;
  whatThisChanges: Record<string, string[]>;
  sub?: WizardEntitySub;
  templates?: WizardRoleTemplate[];
  fields?: WizardExternalApiFields;
}

export interface WizardStepCopy {
  id: string;
  title: string;
  intro: string;
  sbdStep: number;
  estimatedMinutes: number;
}

export interface WizardCommonCopy {
  notSureLabel: string;
  notSureExplanation: string;
  recommendedBadge: string;
  whyWeAskLabel: string;
  whatThisChangesLabel: string;
  assumptionPrefix: string;
  authenticatorNotice: string;
  freeTextNotice: string;
  scopeNotice: string;
  [key: string]: string;
}

export interface WizardSummaryCopy {
  headline: string;
  sections: Record<string, string>;
  extraCareLevels: Record<string, { label: string; text: string }>;
  approveButton: string;
  approveNote: string;
  quickModeNote: string;
}

export interface WizardCopy {
  version: string;
  description: string;
  common: WizardCommonCopy;
  steps: WizardStepCopy[];
  questions: WizardQuestion[];
  summary: WizardSummaryCopy;
  whatThisChanges: Record<string, string[]>;
}
