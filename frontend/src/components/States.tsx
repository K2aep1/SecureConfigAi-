/**
 * Shared empty / loading / error / notice surfaces.
 *
 * Every page uses these so that "nothing here yet", "still loading" and "this
 * failed" are never confused with each other — a distinction that matters on a
 * security dashboard where an empty table must not read as "all clear".
 */

import { useEffect, useState, type ReactNode } from 'react';
import clsx from 'clsx';
import { presentError } from '../lib/errors';

export function EmptyState({
  title,
  description,
  action,
  compact = false,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  compact?: boolean;
}) {
  return (
    <div className={clsx('state-block', compact && 'state-block-compact')}>
      <div className="state-mark" aria-hidden="true">
        ∅
      </div>
      <div>
        <p className="state-title">{title}</p>
        {description ? <p className="state-text">{description}</p> : null}
      </div>
      {action ? <div className="state-action">{action}</div> : null}
    </div>
  );
}

/** Counting-down retry affordance for `429` + `Retry-After`. */
function useRetryCountdown(seconds: number | null): number {
  const [remaining, setRemaining] = useState(seconds ?? 0);

  useEffect(() => {
    setRemaining(seconds ?? 0);
    if (seconds === null || seconds <= 0) return;
    const timer = window.setInterval(() => {
      setRemaining((current) => (current <= 1 ? 0 : current - 1));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [seconds]);

  return remaining;
}

export function ErrorState({
  error,
  onRetry,
  scope,
  compact = false,
}: {
  error: unknown;
  onRetry?: () => void;
  /** Names the thing that failed, e.g. "Scan history". */
  scope?: string;
  compact?: boolean;
}) {
  const presentation = presentError(error);
  const remaining = useRetryCountdown(presentation.retryAfterSeconds);
  const retryBlocked = presentation.isRateLimited && remaining > 0;

  return (
    <div className={clsx('state-block', 'state-block-error', compact && 'state-block-compact')} role="alert">
      <div className="state-mark" aria-hidden="true">
        !
      </div>
      <div>
        <p className="state-title">
          {scope ? `${scope}: ` : ''}
          {presentation.title}
        </p>
        <p className="state-text">{presentation.message}</p>
        {retryBlocked ? (
          <p className="state-text state-text-subtle">
            The API asked for a pause before the next attempt ({remaining}s remaining).
          </p>
        ) : null}
        {presentation.isNetworkError ? (
          <p className="state-text state-text-subtle">
            In development, run the backend on <code>127.0.0.1:8001</code>; the vite dev server
            proxies <code>/api</code> and <code>/health</code> to it.
          </p>
        ) : null}
        {presentation.requestId ? (
          <p className="state-text state-text-subtle">
            Request ID <code>{presentation.requestId}</code>
          </p>
        ) : null}
      </div>
      {onRetry ? (
        <div className="state-action">
          <button
            type="button"
            className="button button-light"
            onClick={onRetry}
            disabled={retryBlocked}
          >
            {retryBlocked ? `Retry in ${remaining}s` : 'Retry'}
          </button>
        </div>
      ) : null}
    </div>
  );
}

export function LoadingState({
  label = 'Loading…',
  rows = 3,
  compact = false,
}: {
  label?: string;
  rows?: number;
  compact?: boolean;
}) {
  return (
    <div
      className={clsx('state-block', 'state-block-loading', compact && 'state-block-compact')}
      role="status"
      aria-live="polite"
    >
      <span className="spinner" aria-hidden="true" />
      <div className="skeleton-group" aria-hidden="true">
        <span className="skeleton skeleton-line" />
        {Array.from({ length: Math.max(0, rows - 1) }).map((_, index) => (
          <span key={index} className="skeleton skeleton-line skeleton-line-short" />
        ))}
      </div>
      <span className="visually-hidden">{label}</span>
    </div>
  );
}

export function Notice({
  tone = 'info',
  title,
  children,
  onDismiss,
}: {
  tone?: 'info' | 'warning' | 'error' | 'success';
  title?: string;
  children: ReactNode;
  onDismiss?: () => void;
}) {
  return (
    <div className={clsx('notice', `notice-${tone}`)} role={tone === 'error' ? 'alert' : 'status'}>
      <div className="notice-body">
        {title ? <strong className="notice-title">{title}</strong> : null}
        <div className="notice-text">{children}</div>
      </div>
      {onDismiss ? (
        <button type="button" className="notice-dismiss" onClick={onDismiss} aria-label="Dismiss">
          <span aria-hidden="true">×</span>
        </button>
      ) : null}
    </div>
  );
}
