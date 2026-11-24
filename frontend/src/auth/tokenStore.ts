/**
 * Token storage boundary.
 *
 * Security posture (contract §2, §9):
 *  - The **access token lives in memory only** — it never touches
 *    `localStorage`/`sessionStorage`, so a successful XSS cannot lift a live
 *    bearer token out of persistent storage.
 *  - The **refresh token is persisted in `localStorage`** so a page reload can
 *    silently re-establish a session via `POST /auth/refresh`.
 *  - Storage access is wrapped: private-mode browsers throw on `localStorage`.
 */

const REFRESH_TOKEN_KEY = 'secureconfigai.refresh_token';

let accessToken: string | null = null;
let expiresAtMs: number | null = null;

/** Subscribers notified when the session is force-terminated (refresh failed). */
type ForcedSignOutListener = () => void;
const forcedSignOutListeners = new Set<ForcedSignOutListener>();

function safeStorage(): Storage | null {
  try {
    const probe = '__secureconfigai_probe__';
    window.localStorage.setItem(probe, '1');
    window.localStorage.removeItem(probe);
    return window.localStorage;
  } catch {
    return null;
  }
}

export const tokenStore = {
  getAccessToken(): string | null {
    return accessToken;
  },

  /** Absolute expiry timestamp derived from `expires_in`, when known. */
  getAccessTokenExpiresAt(): number | null {
    return expiresAtMs;
  },

  setAccessToken(token: string | null, expiresInSeconds?: number): void {
    accessToken = token;
    expiresAtMs =
      token && typeof expiresInSeconds === 'number' && Number.isFinite(expiresInSeconds)
        ? Date.now() + expiresInSeconds * 1000
        : null;
  },

  getRefreshToken(): string | null {
    const storage = safeStorage();
    if (!storage) return null;
    try {
      return storage.getItem(REFRESH_TOKEN_KEY);
    } catch {
      return null;
    }
  },

  setRefreshToken(token: string | null): void {
    const storage = safeStorage();
    if (!storage) return;
    try {
      if (token) storage.setItem(REFRESH_TOKEN_KEY, token);
      else storage.removeItem(REFRESH_TOKEN_KEY);
    } catch {
      /* storage unavailable — session simply will not survive a reload */
    }
  },

  /** Drops both tokens. Does not notify listeners. */
  clear(): void {
    accessToken = null;
    expiresAtMs = null;
    this.setRefreshToken(null);
  },

  /** Registers a listener for forced sign-out; returns an unsubscribe function. */
  onForcedSignOut(listener: ForcedSignOutListener): () => void {
    forcedSignOutListeners.add(listener);
    return () => {
      forcedSignOutListeners.delete(listener);
    };
  },

  /** Called by the API client when a refresh attempt fails permanently. */
  notifyForcedSignOut(): void {
    this.clear();
    for (const listener of forcedSignOutListeners) {
      try {
        listener();
      } catch {
        /* a broken listener must not break sign-out */
      }
    }
  },
};
