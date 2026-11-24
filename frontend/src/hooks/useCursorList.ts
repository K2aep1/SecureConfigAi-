/**
 * Cursor pagination over the contract envelope.
 *
 * Wraps React Query's infinite query so a table can render `items`, a
 * `Load more` button and the loading/error states without each page
 * re-implementing cursor bookkeeping. `Load more` is the only way a list grows —
 * there is no "fetch everything" path.
 */

import { useCallback, useMemo } from 'react';
import { useInfiniteQuery, type InfiniteData } from '@tanstack/react-query';
import type { Page } from '../types';

export interface CursorListOptions<T> {
  queryKey: readonly unknown[];
  fetchPage: (cursor: string | null, signal: AbortSignal) => Promise<Page<T>>;
  enabled?: boolean;
  staleTime?: number;
  pageSize?: number;
}

export interface CursorListResult<T> {
  items: T[];
  count: number;
  hasMore: boolean;
  isLoading: boolean;
  isFetching: boolean;
  isLoadingMore: boolean;
  isError: boolean;
  error: unknown;
  loadMore: () => void;
  reload: () => void;
}

export function useCursorList<T>(options: CursorListOptions<T>): CursorListResult<T> {
  const { queryKey, fetchPage, enabled = true, staleTime } = options;

  const query = useInfiniteQuery<
    Page<T>,
    unknown,
    InfiniteData<Page<T>>,
    readonly unknown[],
    string | null
  >({
    queryKey,
    enabled,
    initialPageParam: null,
    staleTime,
    queryFn: ({ pageParam, signal }) => fetchPage(pageParam, signal),
    getNextPageParam: (lastPage) => (lastPage.has_more ? (lastPage.next_cursor ?? null) : null),
  });

  const items = useMemo<T[]>(
    () => (query.data ? query.data.pages.flatMap((page) => page.items) : []),
    [query.data],
  );

  const hasMore = useMemo(() => {
    const pages = query.data?.pages;
    if (!pages || pages.length === 0) return false;
    const last = pages[pages.length - 1];
    return Boolean(last.has_more && last.next_cursor);
  }, [query.data]);

  const loadMore = useCallback(() => {
    if (query.hasNextPage && !query.isFetchingNextPage) {
      void query.fetchNextPage();
    }
  }, [query]);

  const reload = useCallback(() => {
    void query.refetch();
  }, [query]);

  return {
    items,
    count: items.length,
    hasMore,
    isLoading: query.isLoading,
    isFetching: query.isFetching,
    isLoadingMore: query.isFetchingNextPage,
    isError: query.isError,
    error: query.error,
    loadMore,
    reload,
  };
}

export { useCursorList as usePagedList };

/** Default page size used by every paged table (contract allows 1..200). */
export const DEFAULT_PAGE_SIZE = 25;
