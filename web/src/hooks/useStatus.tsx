import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import type { StatusResponse } from '@shared/api.js';
import { getStatus, setCsrfToken } from '../lib/api';

interface StatusContextValue {
  status: StatusResponse | null;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
}

const StatusContext = createContext<StatusContextValue | null>(null);

export function StatusProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const s = await getStatus();
      setCsrfToken(s.csrfToken);
      setStatus(s);
    } catch {
      setError('SecureVibe could not be reached. Make sure the app is still running, then reload this page.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const value = useMemo(() => ({ status, loading, error, refresh }), [status, loading, error, refresh]);
  return <StatusContext.Provider value={value}>{children}</StatusContext.Provider>;
}

export function useStatus(): StatusContextValue {
  const ctx = useContext(StatusContext);
  if (!ctx) throw new Error('useStatus must be used inside StatusProvider');
  return ctx;
}
