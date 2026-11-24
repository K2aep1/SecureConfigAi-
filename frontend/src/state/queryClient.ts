/**
 * React Query client configuration.
 *
 * Retry policy is status-aware: rate limits are retried after the server's own
 * `Retry-After`, transient 5xx/network failures are retried twice with backoff,
 * and 401/403/404/422 are never retried — retrying them only multiplies the
 * noise in front of the user.
 */

import { QueryClient } from '@tanstack/react-query';
import { isApiError } from '../api';

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 15_000,
        gcTime: 5 * 60_000,
        refetchOnWindowFocus: false,
        retry: (failureCount, error) => {
          if (isApiError(error)) {
            if ([400, 401, 403, 404, 409, 422].includes(error.status)) return false;
            if (error.status === 429) return failureCount < 2;
            if (error.status === 0) return failureCount < 2;
            if (error.status >= 500) return failureCount < 2;
            return false;
          }
          return failureCount < 1;
        },
        retryDelay: (attempt, error) => {
          if (isApiError(error) && error.retryAfterSeconds !== null) {
            return Math.min(error.retryAfterSeconds * 1000, 30_000);
          }
          return Math.min(1000 * 2 ** attempt, 8_000);
        },
      },
      mutations: {
        // Mutations are never retried automatically: a retried write can double
        // apply a state change (for example toggling a policy twice).
        retry: false,
      },
    },
  });
}
