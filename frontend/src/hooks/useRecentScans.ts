/**
 * The newest few scans, fetched as a single bounded page.
 *
 * Used by Overview and Controls. It never loads scan history in full: the
 * request is always capped by `limit`, and paging beyond it is the job of the
 * Scans page (requirement 5).
 */

import { useQuery } from '@tanstack/react-query';
import { listScans, queryKeys } from '../api';
import type { Page, ScanStatus, ScanSummary } from '../types';

export function useRecentScans(limit = 5, status?: ScanStatus) {
  return useQuery<Page<ScanSummary>>({
    queryKey: queryKeys.scans.list({ limit, status, scope: 'recent' }),
    queryFn: ({ signal }) => listScans({ limit, status }, signal),
    staleTime: 10_000,
  });
}

/** Newest scan matching the given statuses, or `null` when there is none. */
export function pickNewest(
  scans: ScanSummary[] | undefined,
  statuses: ScanStatus[] = ['completed'],
): ScanSummary | null {
  if (!scans || scans.length === 0) return null;
  const matches = scans.filter((scan) => statuses.includes(scan.status));
  if (matches.length === 0) return null;
  return matches.reduce((newest, candidate) => {
    const newestAt = newest.completed_at ?? newest.started_at ?? '';
    const candidateAt = candidate.completed_at ?? candidate.started_at ?? '';
    return candidateAt > newestAt ? candidate : newest;
  });
}
