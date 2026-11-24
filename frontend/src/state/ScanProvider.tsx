/**
 * Scan tracking — the headline feature.
 *
 * `POST /scans/start` answers `202` immediately, so nothing here ever awaits a
 * finished scan:
 *
 *   1. `startScan()` records the returned `scan_id` and returns to the caller
 *      straight away; the user keeps using the dashboard.
 *   2. `GET /scans/{id}/status` is polled every **1 s** while the status is
 *      `queued`/`running`, backing off to **3 s** once the scan has been running
 *      for more than 30 s. Polling stops on any terminal status.
 *   3. On a terminal status the tracker loads `GET /scans/{id}/results` and
 *      invalidates the scan and device lists, so every mounted table refreshes.
 *   4. Cancel issues `POST /scans/{id}/cancel` and keeps polling until the
 *      backend reports `cancelled`.
 *
 * Elapsed time is exposed (`startedAtMs`) so the progress panel can show a
 * live clock: a five-minute wait must never look like a frozen page.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  cancelScan,
  getScanResults,
  getScanStatus,
  queryKeys,
  startScan as startScanRequest,
} from '../api';
import { useToast } from '../components/Toast';
import { errorToastMessage } from '../lib/errors';
import { isTerminalScanStatus } from '../lib/format';
import type { ScanResults, ScanStartRequest, ScanStatus } from '../types';

/** Poll cadence before and after the 30-second mark. */
export const FAST_POLL_MS = 1000;
export const SLOW_POLL_MS = 3000;
export const FAST_POLL_WINDOW_MS = 30_000;

export type TrackedScanStatus = ScanStatus | 'cancelling';

export interface TrackedScan {
  scanId: string;
  /** Raw status last reported by the server. */
  status: ScanStatus;
  stage: string;
  progress: number;
  heartbeatAt: string | null;
  errorMessage: string | null;
  durationMs: number | null;
  startedAtMs: number;
  cancelRequested: boolean;
}

export interface ScanTrackerValue {
  tracked: TrackedScan | null;
  /** Display status: `cancelling` while a cancel request is outstanding. */
  displayStatus: TrackedScanStatus | null;
  isTerminal: boolean;
  results: ScanResults | null;
  isStarting: boolean;
  isCancelling: boolean;
  /** Milliseconds between status polls for the current scan. */
  pollIntervalMs: number;
  startScan: (request?: Partial<ScanStartRequest>) => Promise<string | null>;
  cancelTrackedScan: () => Promise<void>;
  /** Hides the panel; the loaded results remain available. */
  dismiss: () => void;
}

const ScanTrackerContext = createContext<ScanTrackerValue | null>(null);

export function ScanTrackerProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const toast = useToast();

  const [tracked, setTracked] = useState<TrackedScan | null>(null);
  const [results, setResults] = useState<ScanResults | null>(null);
  const [isStarting, setIsStarting] = useState(false);
  const [isCancelling, setIsCancelling] = useState(false);

  const trackedRef = useRef<TrackedScan | null>(null);
  trackedRef.current = tracked;

  /** Guards the terminal-status side effects to once per scan. */
  const settledScanId = useRef<string | null>(null);

  const scanId = tracked?.scanId ?? null;
  const isTerminal = tracked !== null && isTerminalScanStatus(tracked.status);

  const statusQuery = useQuery({
    queryKey: scanId ? queryKeys.scans.status(scanId) : (['scans', 'status', 'idle'] as const),
    enabled: scanId !== null && !isTerminal,
    gcTime: 0,
    retry: 2,
    refetchIntervalInBackground: true,
    queryFn: ({ signal }) => {
      if (!scanId) throw new Error('No scan is being tracked.');
      return getScanStatus(scanId, signal);
    },
    // 1 s while young, 3 s after 30 s — measured from the scan's start time, not
    // from the previous response, so a slow poll cannot stretch the cadence.
    refetchInterval: (query) => {
      const data = query.state.data;
      if (data && isTerminalScanStatus(data.status)) return false;
      const startedAt = trackedRef.current?.startedAtMs ?? Date.now();
      return Date.now() - startedAt > FAST_POLL_WINDOW_MS ? SLOW_POLL_MS : FAST_POLL_MS;
    },
  });

  const statusData = statusQuery.data;

  // Fold each status response into the tracked scan.
  useEffect(() => {
    if (!statusData) return;
    setTracked((current) => {
      if (!current || current.scanId !== statusData.scan_id) return current;
      return {
        ...current,
        status: statusData.status,
        stage: statusData.stage,
        progress: statusData.progress,
        heartbeatAt: statusData.heartbeat_at,
        errorMessage: statusData.error_message,
        durationMs: statusData.duration_ms,
      };
    });
  }, [statusData]);

  // A status poll that fails hard (after retries) is surfaced, not swallowed.
  useEffect(() => {
    if (!statusQuery.isError) return;
    toast.push({
      tone: 'warning',
      title: 'Lost contact with the scan status endpoint',
      message: `${errorToastMessage(statusQuery.error)} The scan may still be running on the endpoint.`,
    });
  }, [statusQuery.isError, statusQuery.error, toast]);

  // Terminal status → load results, refresh lists, report the outcome once.
  useEffect(() => {
    if (!tracked || !isTerminal) return;
    if (settledScanId.current === tracked.scanId) return;
    settledScanId.current = tracked.scanId;

    const { scanId: finishedScanId, status, errorMessage } = tracked;

    void (async () => {
      // Refresh the scan list and any device posture as soon as the scan ends.
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.scans.all }),
        queryClient.invalidateQueries({ queryKey: queryKeys.devices.all }),
      ]);

      if (status === 'completed') {
        try {
          const loaded = await getScanResults(finishedScanId);
          setResults(loaded);
          queryClient.setQueryData(queryKeys.scans.results(finishedScanId), loaded);
          const coverage = loaded.results.assessment_coverage;
          toast.push({
            tone: 'success',
            title: 'Scan completed',
            message: `Security score ${loaded.results.security_score ?? '—'}/100 · coverage ${
              coverage === null || coverage === undefined ? '—' : `${coverage}%`
            }`,
          });
        } catch (error) {
          toast.push({
            tone: 'error',
            title: 'Scan finished, but its results could not be loaded',
            message: errorToastMessage(error),
          });
        }
      } else if (status === 'failed') {
        toast.push({
          tone: 'error',
          title: 'Scan failed',
          message: errorMessage ?? 'The scanner reported a failure without an error message.',
        });
      } else if (status === 'cancelled') {
        toast.push({
          tone: 'info',
          title: 'Scan cancelled',
          message: 'No assessment was produced for this scan.',
        });
      }
    })();
  }, [tracked, isTerminal, queryClient, toast]);

  const startScan = useCallback(
    async (request?: Partial<ScanStartRequest>): Promise<string | null> => {
      setIsStarting(true);
      try {
        const started = await startScanRequest({
          source: request?.source ?? 'local_agent',
          device_id: request?.device_id,
          collectors: request?.collectors,
          inventory: request?.inventory,
        });

        settledScanId.current = null;
        setResults(null);
        setTracked({
          scanId: started.scan_id,
          status: started.status,
          stage: started.stage,
          progress: started.progress,
          heartbeatAt: null,
          errorMessage: null,
          durationMs: null,
          startedAtMs: Date.now(),
          cancelRequested: false,
        });
        void queryClient.invalidateQueries({ queryKey: queryKeys.scans.all });
        toast.push({
          tone: 'info',
          title: 'Scan queued',
          message:
            'Collection runs on the endpoint. Progress stays visible at the top of every page.',
        });
        return started.scan_id;
      } catch (error) {
        toast.push({
          tone: 'error',
          title: 'Could not start the scan',
          message: errorToastMessage(error),
        });
        return null;
      } finally {
        setIsStarting(false);
      }
    },
    [queryClient, toast],
  );

  const cancelTrackedScan = useCallback(async (): Promise<void> => {
    const current = trackedRef.current;
    if (!current) return;
    setIsCancelling(true);
    try {
      await cancelScan(current.scanId);
      setTracked((scan) => (scan ? { ...scan, cancelRequested: true } : scan));
      toast.push({
        tone: 'info',
        title: 'Cancellation requested',
        message: 'The scan stops at the next checkpoint; polling continues until it reports cancelled.',
      });
    } catch (error) {
      toast.push({
        tone: 'error',
        title: 'Could not cancel the scan',
        message: errorToastMessage(error),
      });
    } finally {
      setIsCancelling(false);
    }
  }, [toast]);

  const dismiss = useCallback(() => {
    setTracked(null);
  }, []);

  const elapsedMs = tracked ? Date.now() - tracked.startedAtMs : 0;
  const pollIntervalMs = elapsedMs > FAST_POLL_WINDOW_MS ? SLOW_POLL_MS : FAST_POLL_MS;

  const displayStatus: TrackedScanStatus | null = tracked
    ? tracked.cancelRequested && !isTerminalScanStatus(tracked.status)
      ? 'cancelling'
      : tracked.status
    : null;

  const value = useMemo<ScanTrackerValue>(
    () => ({
      tracked,
      displayStatus,
      isTerminal,
      results,
      isStarting,
      isCancelling,
      pollIntervalMs,
      startScan,
      cancelTrackedScan,
      dismiss,
    }),
    [
      tracked,
      displayStatus,
      isTerminal,
      results,
      isStarting,
      isCancelling,
      pollIntervalMs,
      startScan,
      cancelTrackedScan,
      dismiss,
    ],
  );

  return <ScanTrackerContext.Provider value={value}>{children}</ScanTrackerContext.Provider>;
}

export function useScanTracker(): ScanTrackerValue {
  const context = useContext(ScanTrackerContext);
  if (!context) {
    throw new Error('useScanTracker must be used inside <ScanTrackerProvider>.');
  }
  return context;
}
