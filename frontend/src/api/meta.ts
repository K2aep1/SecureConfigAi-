/**
 * Contract §1 — Meta.
 *
 * The backend now serves the documented `GET /api/v1/meta` route and retains
 * `GET /meta` for older clients. The fallback below is deliberately limited to
 * 404 responses so authentication, rate-limit, server and transport errors are
 * not hidden by silently switching endpoints. `/health` remains at the root.
 */

import { apiRequest, isApiError } from './client';
import type { HealthResponse, MetaResponse } from '../types';

const HEALTH_PATH = '/health';

/** Documented in the contract. */
const META_CONTRACT_PATH = '/api/v1/meta';

/** Legacy root endpoint retained by the backend for backward compatibility. */
const META_ROOT_FALLBACK_PATH = '/meta';

/** `GET /health` — unauthenticated. */
export function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return apiRequest<HealthResponse>(HEALTH_PATH, { authenticated: false, signal });
}

/** `GET /api/v1/meta` — footer versions (baseline + scoring model). */
export async function getMeta(signal?: AbortSignal): Promise<MetaResponse> {
  try {
    return await apiRequest<MetaResponse>(META_CONTRACT_PATH, { authenticated: false, signal });
  } catch (error) {
    if (isApiError(error) && error.isNotFound) {
      return apiRequest<MetaResponse>(META_ROOT_FALLBACK_PATH, {
        authenticated: false,
        signal,
      });
    }
    throw error;
  }
}
