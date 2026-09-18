/**
 * Build approval (AISVS C9.2.1, Appendix C AC.4 / AC.8.1): a build starts only from an approval the owner gave on
 * the build page. Showing the estimate issues a one-time approval code bound to the signed-in session, the project
 * and the exact design; starting the build must present it. The run then records who approved, when, and what they
 * were shown, instead of a name the server made up.
 */
import { createHash, randomBytes } from 'node:crypto';

/** How long the owner may look at the estimate before approving. */
export const APPROVAL_TTL_MS = 60 * 60 * 1000;
const MAX_OPEN_APPROVALS = 200;

interface OpenApproval {
  projectId: string;
  sessionId: string;
  designHash: string;
  estimateUsdHigh: number;
  issuedAt: number;
}

export interface GrantedApproval {
  /** Who approved, as recorded on the run: the owner, identified by a short, non-reversible session reference. */
  approvedBy: string;
  approvedAt: string;
  sessionRef: string;
  designHash: string;
  estimateUsdHigh: number;
  estimateShownAt: string;
}

export type ApprovalRefusal = 'missing' | 'expired' | 'wrong-project' | 'wrong-session' | 'design-changed';

/** A short reference to a session that can be logged and stored without revealing the session id. */
export function sessionRef(sessionId: string): string {
  return createHash('sha256').update(sessionId).digest('hex').slice(0, 12);
}

export class BuildApprovals {
  private readonly open = new Map<string, OpenApproval>();

  constructor(private readonly now: () => number = Date.now) {}

  issue(input: Omit<OpenApproval, 'issuedAt'>): string {
    this.prune();
    const code = randomBytes(24).toString('base64url');
    this.open.set(code, { ...input, issuedAt: this.now() });
    return code;
  }

  /** Checks and uses up an approval code. A code works once, only for the session, project and design it was shown for. */
  consume(code: string, projectId: string, sessionId: string, designHash: string): GrantedApproval | ApprovalRefusal {
    const entry = this.open.get(code);
    if (!entry) return 'missing';
    if (this.now() - entry.issuedAt > APPROVAL_TTL_MS) {
      this.open.delete(code);
      return 'expired';
    }
    // Checked before using the code up, so a request from elsewhere cannot burn the owner's approval.
    if (entry.sessionId !== sessionId) return 'wrong-session';
    if (entry.projectId !== projectId) return 'wrong-project';
    this.open.delete(code);
    if (entry.designHash !== designHash) return 'design-changed';
    const ref = sessionRef(sessionId);
    return {
      approvedBy: `owner (signed-in session ${ref})`,
      approvedAt: new Date(this.now()).toISOString(),
      sessionRef: ref,
      designHash: entry.designHash,
      estimateUsdHigh: entry.estimateUsdHigh,
      estimateShownAt: new Date(entry.issuedAt).toISOString(),
    };
  }

  private prune(): void {
    const cutoff = this.now() - APPROVAL_TTL_MS;
    for (const [code, entry] of this.open) if (entry.issuedAt < cutoff) this.open.delete(code);
    while (this.open.size >= MAX_OPEN_APPROVALS) {
      const oldest = this.open.keys().next().value;
      if (oldest === undefined) break;
      this.open.delete(oldest);
    }
  }
}

export const APPROVAL_REFUSAL_TEXT: Record<ApprovalRefusal, string> = {
  missing: 'This build was not approved on the build page (or the approval was already used). Review the estimate and approve again.',
  expired: 'Your approval is more than an hour old. Review the estimate again and approve.',
  'wrong-project': 'That approval was given for a different app.',
  'wrong-session': 'That approval was given in a different SecureVibe session. Review the estimate and approve again.',
  'design-changed': 'The design changed after you approved. Review the estimate again and approve.',
};
