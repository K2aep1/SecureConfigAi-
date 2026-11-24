/**
 * Scan status polling for a specific scan view.
 *
 * The tracker polls the scan *it* started; this hook covers the case where a
 * user opens an older scan that is still queued or running. Same cadence as the
 * tracker: 1 s while young, 3 s after 30 s, stopped on terminal status.
 */

import { useQuery } from '@tanstack/react-query';
import { getScanStatus, queryKeys } from '../api';
import { isTerminalScanStatus } from '../lib/format';
import { FAST_POLL_MS, FAST_POLL_WINDOW_MS, SLOW_POLL_MS } from '../state/ScanProvider';

export function useScanStatusPoll({
  scanId,
  enabled,
  startedAtMs,
}: {
  scanId: string | null;
  /** Pass `false` when the global tracker is already polling this scan. */
  enabled: boolean;
  startedAtMs: number;
}) {
  return useQuery({
    queryKey: scanId ? queryKeys.scans.status(scanId) : (['scans', 'status', 'idle'] as const),
    enabled: Boolean(scanId) && enabled,
    retry: 2,
    refetchIntervalInBackground: true,
    queryFn: ({ signal }) => {
      if (!scanId) throw new Error('No scan selected.');
      return getScanStatus(scanId, signal);
    },
    refetchInterval: (query) => {
      const data = query.state.data;
      if (data && isTerminalScanStatus(data.status)) return false;
      return Date.now() - startedAtMs > FAST_POLL_WINDOW_MS ? SLOW_POLL_MS : FAST_POLL_MS;
    },
  });
}
