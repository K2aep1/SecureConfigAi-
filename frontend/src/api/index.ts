/**
 * Public surface of the API layer.
 *
 * The contract rule from §9 — "no hard-coded API paths outside `src/api/`" —
 * is enforced by convention: every request path literal in the application lives
 * in this directory, and pages/components import only these functions.
 */

export * from './client';
export * from './meta';
export * from './auth';
export * from './scans';
export * from './devices';
export * from './policies';
export * from './admin';
export * from './ai';
export { queryKeys } from './queryKeys';
