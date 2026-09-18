import { useCallback, useEffect, useRef, useState } from 'react';
import type { Project } from '@shared/project.js';
import type { PartialDesignProfile } from '@shared/profile.js';
import { getProject, saveProfile, saveProfileOnExit } from '../lib/api';
import { getPath, setPath } from '../lib/paths';

const AUTOSAVE_DELAY_MS = 700;

export interface UseProjectResult {
  project: Project | null;
  loading: boolean;
  error: string | null;
  saving: boolean;
  saveError: string | null;
  /** When the latest answers reached the server (undefined until the first save in this visit). */
  savedAt: Date | undefined;
  /** True while a change is waiting to be saved. */
  unsaved: boolean;
  /** Set one field of the profile by dotted path (e.g. "app.name") and schedule an autosave. */
  setField: (path: string, value: unknown) => void;
  /** Replace the whole profile (e.g. after Quick mode inference) and save immediately. */
  replaceProfile: (profile: PartialDesignProfile, wizardStep?: number) => Promise<Project | undefined>;
  setWizardStep: (step: number) => void;
  /** Force any pending change to be written now (used before navigating away). */
  flush: () => Promise<void>;
  reload: () => Promise<void>;
}

export function useProject(id: string | undefined): UseProjectResult {
  const [project, setProject] = useState<Project | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<Date | undefined>(undefined);
  const [unsaved, setUnsaved] = useState(false);

  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pendingRef = useRef<{ profile: PartialDesignProfile; wizardStep?: number } | null>(null);
  const projectRef = useRef<Project | null>(null);
  projectRef.current = project;

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const p = await getProject(id);
      setProject(p);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load this app.');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    void load();
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [load]);

  const flush = useCallback(async () => {
    if (!id || !pendingRef.current) return;
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    const { profile, wizardStep } = pendingRef.current;
    pendingRef.current = null;
    setSaving(true);
    setSaveError(null);
    try {
      const updated = await saveProfile(id, { profile, wizardStep });
      // Answers typed while this save was on its way are newer than the server's copy: keep them on screen.
      if (!pendingRef.current) {
        setProject(updated);
        setUnsaved(false);
      } else {
        setProject((prev) => (prev ? { ...updated, profile: prev.profile, wizardStep: prev.wizardStep } : updated));
      }
      setSavedAt(new Date());
    } catch (e) {
      // Keep the answers queued so the next change (or leaving the page) tries again.
      pendingRef.current = pendingRef.current ?? { profile, ...(wizardStep !== undefined ? { wizardStep } : {}) };
      setSaveError(e instanceof Error ? e.message : 'Could not save your answer. It is kept on this screen; try again.');
    } finally {
      setSaving(false);
    }
  }, [id]);

  // Closing the tab or the window: send anything not yet saved.
  useEffect(() => {
    if (!id) return;
    const onLeave = () => {
      if (!pendingRef.current) return;
      const { profile, wizardStep } = pendingRef.current;
      saveProfileOnExit(id, { profile, ...(wizardStep !== undefined ? { wizardStep } : {}) });
      pendingRef.current = null;
    };
    const onHidden = () => {
      if (document.visibilityState === 'hidden') onLeave();
    };
    window.addEventListener('pagehide', onLeave);
    document.addEventListener('visibilitychange', onHidden);
    return () => {
      window.removeEventListener('pagehide', onLeave);
      document.removeEventListener('visibilitychange', onHidden);
    };
  }, [id]);

  const scheduleSave = useCallback(
    (profile: PartialDesignProfile, wizardStep?: number) => {
      pendingRef.current = { profile, wizardStep: wizardStep ?? pendingRef.current?.wizardStep };
      setUnsaved(true);
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => {
        void flush();
      }, AUTOSAVE_DELAY_MS);
    },
    [flush],
  );

  const setField = useCallback(
    (path: string, value: unknown) => {
      setProject((prev) => {
        if (!prev) return prev;
        const nextProfile = setPath(prev.profile as object, path, value) as PartialDesignProfile;
        const next = { ...prev, profile: nextProfile };
        scheduleSave(nextProfile);
        return next;
      });
    },
    [scheduleSave],
  );

  const setWizardStep = useCallback(
    (step: number) => {
      setProject((prev) => {
        if (!prev) return prev;
        const next = { ...prev, wizardStep: step };
        scheduleSave(prev.profile as PartialDesignProfile, step);
        return next;
      });
    },
    [scheduleSave],
  );

  const replaceProfile = useCallback(
    async (profile: PartialDesignProfile, wizardStep?: number) => {
      if (!id) return undefined;
      setSaving(true);
      setSaveError(null);
      try {
        const updated = await saveProfile(id, { profile, wizardStep });
        setProject(updated);
        return updated;
      } catch (e) {
        setSaveError(e instanceof Error ? e.message : 'Could not save.');
        return undefined;
      } finally {
        setSaving(false);
      }
    },
    [id],
  );

  return { project, loading, error, saving, saveError, savedAt, unsaved, setField, replaceProfile, setWizardStep, flush, reload: load };
}

export { getPath };
