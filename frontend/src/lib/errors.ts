/**
 * Error presentation.
 *
 * Turns anything thrown by the API layer (or by a component) into a title,
 * a body message and the few flags a caller needs to render the right action.
 * Covers the statuses the brief calls out explicitly: 429 (`Retry-After`),
 * 401, 403, 404 and transport failures.
 */

import { ApiError, isApiError } from '../api/client';

export interface ErrorPresentation {
  title: string;
  message: string;
  retryAfterSeconds: number | null;
  requestId: string | null;
  isRateLimited: boolean;
  isUnauthorized: boolean;
  isForbidden: boolean;
  isNotFound: boolean;
  isNetworkError: boolean;
  isValidationError: boolean;
  status: number | null;
}

export function presentError(error: unknown): ErrorPresentation {
  if (isApiError(error)) {
    return {
      title: titleForStatus(error.status),
      message: error.message,
      retryAfterSeconds: error.retryAfterSeconds,
      requestId: error.requestId,
      isRateLimited: error.isRateLimited,
      isUnauthorized: error.isUnauthorized,
      isForbidden: error.isForbidden,
      isNotFound: error.isNotFound,
      isNetworkError: error.isNetworkError,
      isValidationError: error.status === 422,
      status: error.status,
    };
  }

  if (error instanceof Error) {
    return {
      title: 'Something went wrong',
      message: error.message || 'An unexpected client error occurred.',
      retryAfterSeconds: null,
      requestId: null,
      isRateLimited: false,
      isUnauthorized: false,
      isForbidden: false,
      isNotFound: false,
      isNetworkError: false,
      isValidationError: false,
      status: null,
    };
  }

  return {
    title: 'Something went wrong',
    message: 'An unexpected error occurred.',
    retryAfterSeconds: null,
    requestId: null,
    isRateLimited: false,
    isUnauthorized: false,
    isForbidden: false,
    isNotFound: false,
    isNetworkError: false,
    isValidationError: false,
    status: null,
  };
}

function titleForStatus(status: number): string {
  switch (status) {
    case 400:
      return 'Request rejected';
    case 401:
      return 'Session expired';
    case 403:
      return 'Not permitted';
    case 404:
      return 'Not found';
    case 409:
      return 'Conflict';
    case 422:
      return 'Invalid values';
    case 423:
      return 'Account locked';
    case 429:
      return 'Rate limited';
    case 500:
      return 'Server error';
    case 502:
    case 503:
    case 504:
      return 'API unavailable';
    case 0:
      return 'Cannot reach the API';
    default:
      return `Request failed (${status})`;
  }
}

/** One-line summary for a toast. */
export function errorToastMessage(error: unknown): string {
  const presentation = presentError(error);
  if (presentation.isRateLimited && presentation.retryAfterSeconds !== null) {
    return `${presentation.title}: ${presentation.message} Try again in ${presentation.retryAfterSeconds}s.`;
  }
  return `${presentation.title}: ${presentation.message}`;
}

/** Narrowing helper for callers that only care about `ApiError`. */
export function asApiError(error: unknown): ApiError | null {
  return isApiError(error) ? error : null;
}
