/**
 * Scan progress panel.
 *
 * The visible half of the scan UX (requirement 4). While a scan is queued or
 * running this panel shows: the server-reported stage, a progress bar driven by
 * `progress`, a live elapsed clock, the last heartbeat, the current poll cadence
 * and a Cancel button. It stays mounted across route changes, so navigating away
 * from the Scans page never hides a running assessment.
 *
 * On a terminal status the panel switches to a summary with a link to the
 * finished scan; the loaded results live in the tracker.
 */

import { Link } from 'react-router-dom';
import clsx from 'clsx';
import { ScanStatusBadge } from './Badges';
import { ProgressBar } from './MetricCard';
import { useScanTracker } from '../state/ScanProvider';
import { useNow } from '../hooks/useAppData';
import { formatElapsed, formatRelative } from '../lib/format';

export function ScanProgressPanel({ variant = 'full' }: { variant?: 'full' | 'inline' }) {
  const { tracked, displayStatus, isTerminal, isCancelling, pollIntervalMs, cancelTrackedScan, dismiss } =
    useScanTracker();
  const now = useNow(1000, tracked !== null && !isTerminal);

  if (!tracked) return null;

  const elapsedMs = Math.max(0, now - tracked.startedAtMs);
  const status = displayStatus ?? tracked.status;
  const polling = !isTerminal;
  const stage = tracked.stage || (polling ? 'Collecting endpoint evidence…' : 'Finished');

  if (variant === 'inline') {
    return (
      <div className={clsx('scan-panel', 'scan-panel-inline', isTerminal && 'scan-panel-terminal')}>
        <ScanStatusBadge status={status} />
        <span className="scan-panel-stage-inline">{stage}</span>
        <span className="scan-panel-elapsed-inline">{formatElapsed(elapsedMs)}</span>
      </div>
    );
  }

  return (
    <section
      className={clsx('scan-panel', isTerminal ? 'scan-panel-terminal' : 'scan-panel-active')}
      aria-label="Scan progress"
    >
      <div className="scan-panel-main">
        <div className="scan-panel-head">
          <ScanStatusBadge status={status} />
          <h2 className="scan-panel-title">{stage}</h2>
          {polling ? <span className="spinner" aria-hidden="true" /> : null}
        </div>

        <div className="scan-panel-progress">
          <ProgressBar
            value={polling ? tracked.progress : 100}
            tone={tracked.status === 'failed' ? 'risk' : tracked.status === 'cancelled' ? 'unknown' : 'info'}
            label="Scan progress"
            showValue
          />
        </div>

        <dl className="scan-panel-meta">
          <div>
            <dt>Elapsed</dt>
            <dd className="mono">{formatElapsed(elapsedMs)}</dd>
          </div>
          <div>
            <dt>Last heartbeat</dt>
            <dd>{tracked.heartbeatAt ? formatRelative(tracked.heartbeatAt, now) : '—'}</dd>
          </div>
          <div>
            <dt>Status checks</dt>
            <dd>{polling ? `every ${pollIntervalMs / 1000} s` : 'stopped'}</dd>
          </div>
          <div>
            <dt>Scan ID</dt>
            <dd className="mono scan-panel-id">{tracked.scanId}</dd>
          </div>
        </dl>

        {tracked.errorMessage ? (
          <p className="scan-panel-error" role="alert">
            {tracked.errorMessage}
          </p>
        ) : null}

        {polling ? (
          <p className="scan-panel-note">
            Full-fidelity collection can legitimately take several minutes. Progress is reported by
            the scanner, so a slow stage means real work is still running — not a frozen page.
          </p>
        ) : (
          <p className="scan-panel-note">
            {tracked.status === 'completed'
              ? 'Results were loaded and the scan and device lists were refreshed.'
              : tracked.status === 'cancelled'
                ? 'No assessment was produced for this scan.'
                : 'The scanner reported a failure. The error above is the reported cause.'}
          </p>
        )}
      </div>

      <div className="scan-panel-actions">
        {polling ? (
          <button
            type="button"
            className="button button-light"
            onClick={() => void cancelTrackedScan()}
            disabled={isCancelling || tracked.cancelRequested}
          >
            {tracked.cancelRequested ? 'Cancelling…' : isCancelling ? 'Requesting…' : 'Cancel scan'}
          </button>
        ) : null}
        <Link className="button button-light" to={`/scans/${tracked.scanId}`}>
          Open scan
        </Link>
        <button
          type="button"
          className="text-button"
          onClick={dismiss}
          aria-label="Hide the scan progress panel"
        >
          {isTerminal ? 'Dismiss' : 'Hide'}
        </button>
      </div>
    </section>
  );
}
