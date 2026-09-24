import type { ReactNode } from 'react';

/**
 * The six faces of the padlock, one per state the app already computes (../securevibe-brand, drawn 19 Sep 2026).
 * A state with a face is recognizable at a glance and the same face everywhere stops "at risk" on one page reading
 * as a different thing from "at risk" on another. The picture never replaces the sentence beside it: the image is
 * decorative to assistive technology, and the words carry the meaning.
 */
export type MascotState = 'good' | 'needs-attention' | 'at-risk' | 'building' | 'stopped' | 'failed';

/** The single mapping from a run's status to a face; a finished build's face comes from its verdict, not from here. */
export function mascotForRunStatus(status: string): MascotState | undefined {
  switch (status) {
    case 'running':
      return 'building';
    case 'failed':
      return 'failed';
    case 'canceled':
    case 'interrupted':
      return 'stopped';
    default:
      return undefined;
  }
}

export function mascotForRating(rating: 'good' | 'needs-attention' | 'at-risk'): MascotState {
  return rating;
}

export function Mascot({ state, size = 56, children }: { state: MascotState; size?: number; children?: ReactNode }) {
  return (
    <span className="sv-verdict">
      <img className="sv-mascot" src={`/brand/securevibe-mascot-${state}.svg`} alt="" width={size} height={size} />
      {children}
    </span>
  );
}
