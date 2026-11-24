/**
 * Client-side windowing for payloads the contract returns in one shot.
 *
 * `/scans/{id}/results`, `/baseline` and `/policies/effective` are single objects,
 * not paged endpoints, so the UI reveals their collections in bounded windows
 * instead of rendering hundreds of rows at once. This is presentation-level
 * paging only — it adds no endpoint and no query parameter.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';

export interface ClientWindowResult<T> {
  visible: T[];
  /** Rows not yet revealed. */
  remaining: number;
  hasMore: boolean;
  total: number;
  loadMore: () => void;
  showAll: () => void;
  reset: () => void;
}

export function useClientWindow<T>(items: T[], pageSize = 25): ClientWindowResult<T> {
  const [limit, setLimit] = useState(pageSize);

  // A new dataset (different filter, different scan) starts from the first page.
  useEffect(() => {
    setLimit(pageSize);
  }, [items, pageSize]);

  const visible = useMemo(() => items.slice(0, limit), [items, limit]);

  const loadMore = useCallback(() => {
    setLimit((current) => current + pageSize);
  }, [pageSize]);

  const showAll = useCallback(() => {
    setLimit(items.length);
  }, [items.length]);

  const reset = useCallback(() => {
    setLimit(pageSize);
  }, [pageSize]);

  return {
    visible,
    remaining: Math.max(0, items.length - visible.length),
    hasMore: items.length > visible.length,
    total: items.length,
    loadMore,
    showAll,
    reset,
  };
}
