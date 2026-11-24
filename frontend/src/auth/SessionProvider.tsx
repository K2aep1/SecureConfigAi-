/**
 * Session context.
 *
 * Token policy (requirement 3, contract §2):
 *  - access token: memory only (`tokenStore`), attached by the API client;
 *  - refresh token: `localStorage`, used once per page load to re-establish the
 *    session through the single-flight `POST /auth/refresh`;
 *  - when a refresh fails the client calls `tokenStore.notifyForcedSignOut()`,
 *    which flips this provider to `anonymous` and lets the router send the user
 *    to sign-in (with the attempted path preserved).
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import {
  getCurrentUser,
  login as loginRequest,
  logout as logoutRequest,
  refreshSession,
  register as registerRequest,
} from '../api';
import { tokenStore } from './tokenStore';
import type { User } from '../types';

export type SessionStatus = 'loading' | 'authenticated' | 'anonymous';

export interface SessionContextValue {
  status: SessionStatus;
  user: User | null;
  isAdmin: boolean;
  signIn: (email: string, password: string) => Promise<User>;
  register: (email: string, password: string, fullName?: string) => Promise<User>;
  signOut: () => Promise<void>;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<SessionStatus>('loading');
  const [user, setUser] = useState<User | null>(null);

  // A dead refresh token (expired, revoked, reuse-detected) ends the session.
  useEffect(
    () =>
      tokenStore.onForcedSignOut(() => {
        setUser(null);
        setStatus('anonymous');
      }),
    [],
  );

  // Session restore: the access token is never persisted, so a reload must
  // exchange the stored refresh token for a fresh pair before calling /auth/me.
  useEffect(() => {
    let cancelled = false;

    async function restore() {
      if (!tokenStore.getRefreshToken()) {
        if (!cancelled) setStatus('anonymous');
        return;
      }
      try {
        await refreshSession();
        const me = await getCurrentUser();
        if (cancelled) return;
        setUser(me);
        setStatus('authenticated');
      } catch {
        tokenStore.clear();
        if (cancelled) return;
        setUser(null);
        setStatus('anonymous');
      }
    }

    void restore();
    return () => {
      cancelled = true;
    };
  }, []);

  const signIn = useCallback(async (email: string, password: string): Promise<User> => {
    const tokens = await loginRequest({ email, password });
    tokenStore.setAccessToken(tokens.access_token, tokens.expires_in);
    tokenStore.setRefreshToken(tokens.refresh_token);
    const me = await getCurrentUser();
    setUser(me);
    setStatus('authenticated');
    return me;
  }, []);

  const register = useCallback(
    async (email: string, password: string, fullName?: string): Promise<User> => {
      await registerRequest({ email, password, full_name: fullName?.trim() || undefined });
      // Registration never returns tokens, so sign in immediately afterwards.
      return signIn(email, password);
    },
    [signIn],
  );

  const signOut = useCallback(async (): Promise<void> => {
    const refreshToken = tokenStore.getRefreshToken();
    try {
      if (refreshToken) await logoutRequest({ refresh_token: refreshToken });
    } catch {
      // Revocation is best-effort: the local session is cleared either way.
    } finally {
      tokenStore.clear();
      setUser(null);
      setStatus('anonymous');
    }
  }, []);

  const value = useMemo<SessionContextValue>(
    () => ({
      status,
      user,
      isAdmin: user?.role === 'admin',
      signIn,
      register,
      signOut,
    }),
    [status, user, signIn, register, signOut],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionContextValue {
  const context = useContext(SessionContext);
  if (!context) {
    throw new Error('useSession must be used inside <SessionProvider>.');
  }
  return context;
}
