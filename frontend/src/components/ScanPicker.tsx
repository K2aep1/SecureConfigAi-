/**
 * Scan selector.
 *
 * Lists the newest scans in a bounded window (one page at a time, with "Load
 * older scans" pulling the next cursor) so a scan can be chosen without ever
 * fetching the whole history.
 */

import { useCursorList } from '../hooks/useCursorList';
import { listScans, queryKeys } from '../api';
import { formatDateTime, formatScore } from '../lib/format';
import type { ScanStatus, ScanSummary } from '../types';

export const SCAN_PICKER_PAGE_SIZE = 25;

export function scanOptionLabel(scan: ScanSummary): string {
  const when = formatDateTime(scan.completed_at ?? scan.started_at);
  const where = scan.hostname ?? scan.device_id ?? 'unknown host';
  const score = scan.security_score === null ? 'not scored' : `${formatScore(scan.security_score)}/100`;
  return `${when} · ${where} · ${scan.status} · ${score}`;
}

export function ScanPicker({
  value,
  onChange,
  label = 'Scan',
  status,
  placeholder = 'Newest completed scan',
  id,
}: {
  value: string | null;
  onChange: (scanId: string | null) => void;
  label?: string;
  status?: ScanStatus;
  placeholder?: string;
  id?: string;
}) {
  const list = useCursorList<ScanSummary>({
    queryKey: queryKeys.scans.list({ limit: SCAN_PICKER_PAGE_SIZE, status, scope: 'picker' }),
    fetchPage: (cursor, signal) =>
      listScans({ limit: SCAN_PICKER_PAGE_SIZE, cursor, status }, signal),
    staleTime: 15_000,
  });

  return (
    <div className="scan-picker">
      <label className="field" htmlFor={id}>
        <span className="field-label">{label}</span>
        <select
          id={id}
          value={value ?? ''}
          onChange={(event) => onChange(event.target.value === '' ? null : event.target.value)}
          disabled={list.isLoading}
        >
          <option value="">{list.isLoading ? 'Loading scans…' : placeholder}</option>
          {list.items.map((scan) => (
            <option key={scan.id} value={scan.id}>
              {scanOptionLabel(scan)}
            </option>
          ))}
        </select>
      </label>
      {list.hasMore ? (
        <button
          type="button"
          className="text-button"
          onClick={list.loadMore}
          disabled={list.isLoadingMore}
        >
          {list.isLoadingMore ? 'Loading…' : 'Load older scans'}
        </button>
      ) : null}
      {list.isError ? <span className="field-hint">Scan list unavailable.</span> : null}
    </div>
  );
}
