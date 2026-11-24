/**
 * Contract §2 — Authentication.
 *
 * `POST /auth/refresh` is implemented here for completeness, but the running
 * application always goes through `refreshSession()` in `./client`, which
 * guarantees the single-flight property required by requirement 3. Both call
 * exactly this endpoint with `{refresh_token}` in the JSON body — never a query
 * string (contract §2: query-string refreshes are rejected).
 */

import { API_PREFIX, apiRequest } from './client';
import type {
  AuthPolicy,
  LoginRequest,
  LogoutRequest,
  MessageResponse,
  RefreshRequest,
  RegisterRequest,
  TokenPair,
  User,
} from '../types';

const AUTH = `${API_PREFIX}/auth`;

/** `GET /auth/policy` — password and session rules for the UI. */
export function getAuthPolicy(signal?: AbortSignal): Promise<AuthPolicy> {
  return apiRequest<AuthPolicy>(`${AUTH}/policy`, { authenticated: false, signal });
}

/** `POST /auth/register` → `201 UserOut` (always `role="user"`). */
export function register(request: RegisterRequest): Promise<User> {
  return apiRequest<User>(`${AUTH}/register`, {
    method: 'POST',
    body: request,
    authenticated: false,
  });
}

/** `POST /auth/login` → token pair. */
export function login(request: LoginRequest): Promise<TokenPair> {
  return apiRequest<TokenPair>(`${AUTH}/login`, {
    method: 'POST',
    body: request,
    authenticated: false,
  });
}

/** `POST /auth/refresh` → token pair (rotates the refresh token). */
export function refreshTokens(request: RefreshRequest): Promise<TokenPair> {
  return apiRequest<TokenPair>(`${AUTH}/refresh`, {
    method: 'POST',
    body: request,
    authenticated: false,
  });
}

/** `POST /auth/logout` — revokes the presented refresh-token family. */
export function logout(request: LogoutRequest = {}): Promise<MessageResponse> {
  return apiRequest<MessageResponse>(`${AUTH}/logout`, { method: 'POST', body: request });
}

/** `GET /auth/me` */
export function getCurrentUser(signal?: AbortSignal): Promise<User> {
  return apiRequest<User>(`${AUTH}/me`, { signal });
}
