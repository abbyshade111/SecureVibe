import { useEffect, useState } from 'react';
import type { WizardCopy } from '../lib/wizardCopyTypes';
import { getWizardCopy } from '../lib/api';

let cached: Promise<WizardCopy> | null = null;

function load(): Promise<WizardCopy> {
  if (!cached) cached = getWizardCopy();
  return cached;
}

export function useWizardCopy(): { copy: WizardCopy | null; loading: boolean } {
  const [copy, setCopy] = useState<WizardCopy | null>(null);
  useEffect(() => {
    let cancelled = false;
    void load().then((c) => {
      if (!cancelled) setCopy(c);
    });
    return () => {
      cancelled = true;
    };
  }, []);
  return { copy, loading: copy === null };
}
