/**
 * The single place in the application that talks HTTP.
 *
 * Responsibilities (contract §Conventions, §2, §9):
 *  - Build the base URL: `VITE_API_BASE_URL` when set, otherwise same-origin so
 *    the vite dev proxy (`/api`, `/health`) forwards to the backend with no CORS.
 *  - Attach `Authorization: Bearer <access_token>` from the in-memory token store.
 *  - On `401`, perform **one** single-flight `POST /auth/refresh` (JSON body —
 *    never a query string) and retry the original request exactly once.
 *  - If the refresh fails, clear the session and notify listeners so the router
 *    can send the user to sign-in.
 *  - Translate `{detail}` / 422 / 429 (`Retry-After`) / network failures into a
 *    typed `ApiError` with a message that is safe to show to a user.
 */

import { tokenStore } from '../auth/tokenStore';
import type { ApiErrorBody, Page, TokenPair, ValidationErrorItem } from '../types';

/** Every contract route is relative to `/api/v1` (contract header). */
export const API_PREFIX = '/api/v1';

/** Routes that must never trigger the refresh-and-retry cycle. */
const NO_REFRESH_PATHS = new Set<string>([
  `${API_PREFIX}/auth/login`,
  `${API_PREFIX}/auth/refresh`,
  `${API_PREFIX}/auth/register`,
]);

export function apiBaseUrl(): string {
  const configured = import.meta.env.VITE_API_BASE_URL;
  return typeof configured === 'string' ? configured.trim().replace(/\/+$/, '') : '';
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export type QueryValue = string | number | boolean | null | undefined;

export class ApiError extends Error {
  readonly status: number;
  /** Parsed `Retry-After` header (seconds) for `429` responses. */
  readonly retryAfterSeconds: number | null;
  readonly requestId: string | null;

  constructor(
    message: string,
    status: number,
    options: { retryAfterSeconds?: number | null; requestId?: string | null } = {},
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.retryAfterSeconds = options.retryAfterSeconds ?? null;
    this.requestId = options.requestId ?? null;
  }

  get isUnauthorized(): boolean {
    return this.status === 401;
  }

  get isForbidden(): boolean {
    return this.status === 403;
  }

  get isNotFound(): boolean {
    return this.status === 404;
  }

  get isRateLimited(): boolean {
    return this.status === 429;
  }

  /** `0` marks a transport failure (server unreachable, DNS, offline). */
  get isNetworkError(): boolean {
    return this.status === 0;
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

export function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError';
}

/** `0` is used for transport errors so `isNetworkError` has a single meaning. */
export const NETWORK_ERROR_STATUS = 0;

function buildQuery(query: Record<string, QueryValue> | undefined): string {
  if (!query) return '';
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') continue;
    params.set(key, String(value));
  }
  const serialized = params.toString();
  return serialized ? `?${serialized}` : '';
}

function parseRetryAfter(response: Response): number | null {
  const header = response.headers.get('Retry-After');
  if (!header) return null;
  const seconds = Number.parseInt(header, 10);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
}

/** Extracts a human-readable message from a contract error body. */
function detailMessage(body: unknown, status: number): string | null {
  if (typeof body === 'string' && body.trim()) return body.trim();
  if (!body || typeof body !== 'object') return null;

  const detail = (body as ApiErrorBody).detail;
  if (typeof detail === 'string' && detail.trim()) return detail.trim();

  // FastAPI 422: {"detail":[{"loc":[...],"msg":"...","type":"..."}]}
  if (Array.isArray(detail)) {
    const items = detail as ValidationErrorItem[];
    const messages = items
      .map((item) => {
        const location = Array.isArray(item.loc)
          ? item.loc.filter((part) => part !== 'body').join('.')
          : '';
        const text = typeof item.msg === 'string' ? item.msg : '';
        return location ? `${location}: ${text}` : text;
      })
      .filter((text) => text.trim().length > 0);
    if (messages.length > 0) return messages.join('; ');
  }

  if (status === 403) return 'You do not have permission to perform this action.';
  return null;
}

function fallbackMessage(status: number): string {
  switch (status) {
    case 400:
      return 'The request was rejected as invalid.';
    case 401:
      return 'Your session has expired. Sign in again to continue.';
    case 403:
      return 'You do not have permission to perform this action.';
    case 404:
      return 'The requested resource was not found.';
    case 409:
      return 'The request conflicts with the current state of the resource.';
    case 422:
      return 'Some submitted values were rejected by the server.';
    case 429:
      return 'Too many requests. Wait a moment and try again.';
    case 500:
      return 'The server reported an internal error.';
    case 502:
    case 503:
    case 504:
      return 'The API is temporarily unavailable.';
    default:
      return `The request failed with status ${status}.`;
  }
}

async function readBody(response: Response): Promise<unknown> {
  if (response.status === 204 || response.status === 205) return null;
  const contentType = response.headers.get('Content-Type') ?? '';
  try {
    if (contentType.includes('application/json')) return await response.json();
    const text = await response.text();
    return text.length > 0 ? text : null;
  } catch {
    return null;
  }
}

async function toApiError(response: Response): Promise<ApiError> {
  const body = await readBody(response);
  const message = detailMessage(body, response.status) ?? fallbackMessage(response.status);
  return new ApiError(message, response.status, {
    retryAfterSeconds: parseRetryAfter(response),
    requestId: response.headers.get('X-Request-ID'),
  });
}

/* ------------------------------------------------------------------ *
 * Single-flight refresh
 * ------------------------------------------------------------------ */

let inFlightRefresh: Promise<TokenPair> | null = null;

async function requestRefreshToken(): Promise<TokenPair> {
  const refreshToken = tokenStore.getRefreshToken();
  if (!refreshToken) {
    throw new ApiError('No stored session to refresh.', 401);
  }

  // Refresh tokens are accepted only in the JSON body (contract §2). A query
  // string form is explicitly rejected by the server.
  const response = await fetch(`${apiBaseUrl()}${API_PREFIX}/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!response.ok) {
    throw await toApiError(response);
  }

  const tokens = (await response.json()) as TokenPair;
  tokenStore.setAccessToken(tokens.access_token, tokens.expires_in);
  tokenStore.setRefreshToken(tokens.refresh_token);
  return tokens;
}

/**
 * Single-flight refresh: concurrent 401s share one request, so a burst of
 * failing calls cannot rotate the refresh token several times (which would trip
 * the reuse-detection rule and revoke the whole token family).
 */
export function refreshSession(): Promise<TokenPair> {
  if (!inFlightRefresh) {
    inFlightRefresh = requestRefreshToken().finally(() => {
      inFlightRefresh = null;
    });
  }
  return inFlightRefresh;
}

/* ------------------------------------------------------------------ *
 * Request plumbing
 * ------------------------------------------------------------------ */

export interface RequestOptions {
  method?: HttpMethod;
  query?: Record<string, QueryValue>;
  /** JSON request body. Mutually exclusive with `formData`. */
  body?: unknown;
  /** multipart body for `POST /scans/upload`. */
  formData?: FormData;
  signal?: AbortSignal;
  /** Set `false` for the three unauthenticated routes. Defaults to `true`. */
  authenticated?: boolean;
  /** Return the raw `Response` (reports: HTML/PDF/ETag). */
  raw?: boolean;
  /**
   * Fetch cache mode. Defaults to `'default'` so report artefacts keep their
   * `ETag` revalidation behaviour (a `304` is served from the browser cache
   * instead of re-rendering on the server). `'reload'` is only used as a
   * recovery path when a `304` arrives with no cached body.
   */
  cache?: RequestCache;
  /** Internal: blocks a second refresh-and-retry cycle. */
  allowRefresh?: boolean;
}

async function send(path: string, options: RequestOptions, allowRefresh: boolean): Promise<Response> {
  const headers = new Headers({ Accept: 'application/json' });
  const authenticated = options.authenticated !== false;

  if (authenticated) {
    const accessToken = tokenStore.getAccessToken();
    if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
  }

  let body: BodyInit | undefined;
  if (options.formData) {
    body = options.formData;
  } else if (options.body !== undefined) {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(options.body);
  }

  const url = `${apiBaseUrl()}${path}${buildQuery(options.query)}`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: options.method ?? 'GET',
      headers,
      body,
      signal: options.signal,
      // No cache-busting query strings: report artefacts are ETag-validated.
      cache: options.cache ?? 'default',
      credentials: 'omit',
    });
  } catch (error) {
    if (isAbortError(error)) throw error;
    const target = apiBaseUrl() || window.location.origin;
    throw new ApiError(
      `Cannot reach the API at ${target}. Check that the backend is running and that the dev proxy is configured.`,
      NETWORK_ERROR_STATUS,
    );
  }

  if (response.status === 401 && authenticated && allowRefresh && !NO_REFRESH_PATHS.has(path)) {
    try {
      await refreshSession();
    } catch {
      // Refresh token is dead (expired, revoked, or reuse detected): end the
      // session and let the session provider route to sign-in.
      tokenStore.notifyForcedSignOut();
      throw await toApiError(response);
    }
    return send(path, options, false);
  }

  // A raw (artefact) request may legitimately see a `304`: the ETag matched and
  // the browser serves the body itself. The caller inspects the status.
  if (response.status === 304 && options.raw) return response;

  if (!response.ok) throw await toApiError(response);
  return response;
}

/** JSON request returning a parsed body. */
export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const response = await send(path, options, options.allowRefresh !== false);
  const contentType = response.headers.get('Content-Type') ?? '';
  const parsed = await readBody(response);

  // A 200 that is not JSON usually means the request never reached the API —
  // for example a dev-proxy path that fell through to the SPA fallback and
  // returned index.html. Surfacing it as an error is far better than letting a
  // null body render as an endless row of "—".
  const bodyless = response.status === 204 || response.status === 205;
  if (!bodyless && parsed === null && !contentType.includes('application/json')) {
    throw new ApiError(
      `Expected a JSON response from ${path} but received ${
        contentType || 'an unknown content type'
      }. In development, confirm the vite proxy forwards this path to the API.`,
      response.status,
      { requestId: response.headers.get('X-Request-ID') },
    );
  }

  return parsed as T;
}

/** Raw request for non-JSON artefacts (`text/html`, `application/pdf`). */
export async function apiRequestRaw(path: string, options: RequestOptions = {}): Promise<Response> {
  return send(path, { ...options, raw: true }, options.allowRefresh !== false);
}

/* ------------------------------------------------------------------ *
 * Pagination envelope
 * ------------------------------------------------------------------ */

/**
 * Narrows a list response to `Page<T>`.
 *
 * The contract mandates `{items,next_cursor,has_more,limit}` for every list
 * endpoint. A small number of endpoints in the contract are documented as bare
 * arrays (`GET /ai/chat/{session_id}` returns `[ChatMessageOut]`), and partial
 * deployments may still answer with a bare array, so both are accepted here and
 * normalised in exactly one place. Nothing outside `src/api/` sees the union.
 */
export function toPage<T>(payload: Page<T> | T[] | null | undefined, limit: number): Page<T> {
  if (Array.isArray(payload)) {
    return { items: payload, next_cursor: null, has_more: false, limit: payload.length || limit };
  }
  if (payload && typeof payload === 'object' && Array.isArray(payload.items)) {
    return {
      items: payload.items,
      next_cursor: payload.next_cursor ?? null,
      has_more: Boolean(payload.has_more),
      limit: typeof payload.limit === 'number' ? payload.limit : limit,
    };
  }
  return { items: [], next_cursor: null, has_more: false, limit };
}
