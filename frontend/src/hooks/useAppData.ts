/**
 * Meta, health and small shared hooks.
 */

import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getHealth, getMeta, queryKeys } from '../api';
import type { HealthResponse, MetaResponse } from '../types';

/** `GET /api/v1/meta` — footer versions, control counts. Unauthenticated. */
export function useMeta() {
  return useQuery<MetaResponse>({
    queryKey: queryKeys.meta.app(),
    queryFn: ({ signal }) => getMeta(signal),
    staleTime: 10 * 60 * 1000,
    gcTime: 30 * 60 * 1000,
    retry: 1,
  });
}

/** `GET /health` — connectivity probe for the shell indicator. */
export function useHealth() {
  return useQuery<HealthResponse>({
    queryKey: queryKeys.meta.health(),
    queryFn: ({ signal }) => getHealth(signal),
    staleTime: 30 * 1000,
    retry: 0,
  });
}

/** Debounces fast-changing filter input so typing does not hammer the API. */
export function useDebouncedValue<T>(value: T, delayMs = 350): T {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delayMs);
    return () => window.clearTimeout(timer);
  }, [value, delayMs]);

  return debounced;
}

/** A ticking clock for elapsed-time and relative-time rendering. */
export function useNow(intervalMs = 1000, enabled = true): number {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!enabled) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs, enabled]);

  return now;
}

/** Keeps the document title in step with the active route. */
export function useDocumentTitle(title: string): void {
  useEffect(() => {
    const previous = document.title;
    document.title = title;
    return () => {
      document.title = previous;
    };
  }, [title]);
}
