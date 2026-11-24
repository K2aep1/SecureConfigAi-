/**
 * Metric cards and small presentation primitives shared by every page.
 */

import type { ReactNode } from 'react';
import clsx from 'clsx';
import type { Tone } from '../lib/verdict';

export function MetricGrid({
  children,
  columns = 4,
}: {
  children: ReactNode;
  columns?: 2 | 3 | 4;
}) {
  return <div className={clsx('metric-grid', `metric-grid-${columns}`)}>{children}</div>;
}

export function MetricCard({
  label,
  value,
  note,
  hint,
  tone = 'neutral',
  emphasis = false,
}: {
  label: string;
  value: ReactNode;
  note?: ReactNode;
  /** Longer explanation surfaced as a tooltip on the label. */
  hint?: string;
  /** Verdict tones map 1:1 onto the accent stripe; `na` is muted, `error` hatched. */
  tone?: Tone;
  emphasis?: boolean;
}) {
  return (
    <div className={clsx('metric-card', `metric-card-${tone}`, emphasis && 'metric-card-emphasis')}>
      <span className="metric-label" title={hint}>
        {label}
        {hint ? (
          <span className="metric-hint-mark" aria-hidden="true">
            ?
          </span>
        ) : null}
      </span>
      <span className="metric-value">{value}</span>
      {note ? <span className="metric-note">{note}</span> : null}
    </div>
  );
}

/** Horizontal progress bar. `value` may be null (renders as undetermined). */
export function ProgressBar({
  value,
  tone = 'info',
  label,
  showValue = false,
}: {
  value: number | null | undefined;
  tone?: 'ok' | 'risk' | 'warn' | 'info' | 'unknown';
  label: string;
  showValue?: boolean;
}) {
  const known = value !== null && value !== undefined && Number.isFinite(value);
  const percent = known ? Math.max(0, Math.min(100, Math.round(value))) : 0;

  return (
    <div className="progress-row">
      <div
        className={clsx('progress', `progress-${tone}`, !known && 'progress-undetermined')}
        role="progressbar"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={known ? percent : undefined}
        aria-valuetext={known ? `${percent}%` : 'not available'}
      >
        <span className="progress-fill" style={{ width: `${percent}%` }} />
      </div>
      {showValue ? <span className="progress-value">{known ? `${percent}%` : '—'}</span> : null}
    </div>
  );
}

/** Compact label/value row used in detail panels. */
export function DetailRow({
  label,
  value,
  hint,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
}) {
  return (
    <div className="detail-row">
      <span className="detail-label" title={hint}>
        {label}
      </span>
      <span className="detail-value">{value}</span>
    </div>
  );
}

export function DetailList({ children }: { children: ReactNode }) {
  return <div className="detail-list">{children}</div>;
}
