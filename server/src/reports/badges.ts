/**
 * Status as icon + word, never color alone (DESIGN §13.12). Every badge function returns a self-contained
 * `<span>` whose text alone tells you the status; CSS color is decoration, not the only signal.
 */
import type { RequirementStatus, StandardSummary } from '@shared/compliance.js';
import type { Confidence, Priority, Severity } from '@shared/findings.js';
import type { SbdChecklistStatus } from '@shared/design.js';
import { escapeHtml } from './escape.js';

export const STATUS_ICON: Record<RequirementStatus, string> = {
  pass: '✅',
  'ai-assessed': '\u{1F916}',
  documented: '\u{1F4C4}',
  attested: '✍️',
  partial: '\u{1F7E1}',
  fail: '❌',
  'not-applicable': '➖',
  'not-verified': '❓',
  'out-of-level': '⬜',
};

export const STATUS_WORD: Record<RequirementStatus, string> = {
  pass: 'Pass',
  'ai-assessed': 'AI-assessed',
  documented: 'Documented',
  attested: 'Attested',
  partial: 'Partial',
  fail: 'Fail',
  'not-applicable': 'Not applicable',
  'not-verified': 'Not verified',
  'out-of-level': 'Out of level',
};

export function statusBadge(status: RequirementStatus): string {
  return `<span class="badge status-${status}">${STATUS_ICON[status]} ${STATUS_WORD[status]}</span>`;
}

export function statusText(status: RequirementStatus): string {
  return `${STATUS_ICON[status]} ${STATUS_WORD[status]}`;
}

const SBD_ICON: Record<SbdChecklistStatus, string> = { yes: '✅', no: '❌', 'n-a': '➖' };
const SBD_WORD: Record<SbdChecklistStatus, string> = { yes: 'Yes', no: 'No', 'n-a': 'N-A' };

export function sbdBadge(status: SbdChecklistStatus): string {
  return `<span class="badge sbd-${status}">${SBD_ICON[status]} ${SBD_WORD[status]}</span>`;
}

export function sbdText(status: SbdChecklistStatus): string {
  return `${SBD_ICON[status]} ${SBD_WORD[status]}`;
}

const PRIORITY_ICON: Record<Priority, string> = { P1: '\u{1F534}', P2: '\u{1F7E0}', P3: '\u{1F7E1}', P4: '⚪' };
const PRIORITY_LABEL: Record<Priority, string> = { P1: 'P1 — fix first', P2: 'P2 — fix soon', P3: 'P3 — fix when convenient', P4: 'P4 — low priority' };

export function priorityBadge(priority: Priority): string {
  return `<span class="badge priority-${priority}">${PRIORITY_ICON[priority]} ${escapeHtml(PRIORITY_LABEL[priority])}</span>`;
}

export function priorityText(priority: Priority): string {
  return `${PRIORITY_ICON[priority]} ${PRIORITY_LABEL[priority]}`;
}

const SEVERITY_WORD: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

export function severityText(severity: Severity): string {
  return SEVERITY_WORD[severity];
}

const CONFIDENCE_WORD: Record<Confidence, string> = { high: 'High confidence', medium: 'Medium confidence', low: 'Low confidence' };

export function confidenceText(confidence: Confidence): string {
  return CONFIDENCE_WORD[confidence];
}

const RATING_ICON: Record<StandardSummary['rating'], string> = { good: '✅', 'needs-attention': '\u{1F7E1}', 'at-risk': '\u{1F534}' };
const RATING_WORD: Record<StandardSummary['rating'], string> = { good: 'Good', 'needs-attention': 'Needs attention', 'at-risk': 'At risk' };

export function ratingBadge(rating: StandardSummary['rating']): string {
  return `<span class="badge rating-${rating}">${RATING_ICON[rating]} ${RATING_WORD[rating]}</span>`;
}

export function ratingText(rating: StandardSummary['rating']): string {
  return `${RATING_ICON[rating]} ${RATING_WORD[rating]}`;
}
