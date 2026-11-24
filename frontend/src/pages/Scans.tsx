/**
 * Scans.
 *
 * Paged history with the contract's filters (`status`, `device_id`, `source`,
 * `q`) and a `Load more` control driven by the `{items,next_cursor,has_more,limit}`
 * envelope. Starting a scan never blocks this page: the request returns `202`
 * and the global progress panel takes over.
 */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { listScans, queryKeys } from '../api';
import { DEFAULT_PAGE_SIZE, useCursorList } from '../hooks/useCursorList';
import { useDebouncedValue, useDocumentTitle } from '../hooks/useAppData';
import { useScanTracker } from '../state/ScanProvider';
import { DataTable, LoadMore, type Column } from '../components/DataTable';
import { ScanStatusBadge } from '../components/Badges';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { formatDateTime, formatDurationMs, formatPercent, formatScore, SCAN_STATUSES } from '../lib/format';
import { useOpenReport } from '../hooks/useOpenReport';
import type { ScanStatus, ScanSummary } from '../types';

export default function ScansPage() {
  useDocumentTitle('Scans · SecureConfigAI');
  const { startScan, isStarting, tracked } = useScanTracker();
  const { openReport, isPending } = useOpenReport();

  const [status, setStatus] = useState<ScanStatus | ''>('');
  const [deviceId, setDeviceId] = useState('');
  const [source, setSource] = useState('');
  const [query, setQuery] = useState('');

  const debouncedQuery = useDebouncedValue(query, 350);
  const debouncedDeviceId = useDebouncedValue(deviceId, 350);
  const debouncedSource = useDebouncedValue(source, 350);

  const filters = {
    limit: DEFAULT_PAGE_SIZE,
    status: status === '' ? undefined : status,
    device_id: debouncedDeviceId.trim() || undefined,
    source: debouncedSource.trim() || undefined,
    q: debouncedQuery.trim() || undefined,
  };

  const scans = useCursorList<ScanSummary>({
    queryKey: queryKeys.scans.list(filters),
    fetchPage: (cursor, signal) => listScans({ ...filters, cursor }, signal),
    staleTime: 10_000,
  });

  const hasFilters =
    status !== '' || deviceId.trim() !== '' || source.trim() !== '' || query.trim() !== '';

  function resetFilters() {
    setStatus('');
    setDeviceId('');
    setSource('');
    setQuery('');
  }

  const columns: Column<ScanSummary>[] = [
    {
      id: 'scan',
      header: 'Scan',
      width: '20%',
      cell: (row) => (
        <Link className="cell-primary" to={`/scans/${row.id}`}>
          <span className="cell-title">{row.hostname ?? 'Unknown host'}</span>
          <code className="cell-code">{row.id}</code>
        </Link>
      ),
    },
    {
      id: 'status',
      header: 'Status',
      width: '12%',
      cell: (row) => <ScanStatusBadge status={row.status} />,
    },
    {
      id: 'stage',
      header: 'Stage',
      hideBelow: 'lg',
      width: '13%',
      cell: (row) => <span className="muted">{row.stage || '—'}</span>,
    },
    {
      id: 'source',
      header: 'Source',
      hideBelow: 'md',
      width: '10%',
      cell: (row) => row.source,
    },
    {
      id: 'started',
      header: 'Started',
      width: '15%',
      cell: (row) => formatDateTime(row.started_at),
    },
    {
      id: 'duration',
      header: 'Duration',
      align: 'right',
      hideBelow: 'lg',
      width: '9%',
      cell: (row) => formatDurationMs(row.duration_ms),
    },
    {
      id: 'score',
      header: 'Score',
      align: 'right',
      width: '8%',
      cell: (row) => (row.security_score === null ? '—' : `${formatScore(row.security_score)}/100`),
    },
    {
      id: 'coverage',
      header: 'Coverage',
      align: 'right',
      width: '9%',
      cell: (row) => formatPercent(row.assessment_coverage),
    },
    {
      id: 'findings',
      header: 'Findings',
      align: 'right',
      hideBelow: 'lg',
      width: '9%',
      cell: (row) => (
        <span
          title={
            row.total_findings === null
              ? 'Findings are only recorded once the scan completes.'
              : `${row.critical_count ?? 0} critical · ${row.high_count ?? 0} high`
          }
        >
          {row.total_findings ?? '—'}
        </span>
      ),
    },
    {
      id: 'actions',
      header: 'Report',
      align: 'right',
      hideBelow: 'md',
      width: '12%',
      cell: (row) =>
        row.status === 'completed' ? (
          <span className="inline-actions">
            <button
              type="button"
              className="text-button"
              onClick={() => void openReport(row.id, 'html')}
              disabled={isPending(row.id, 'html')}
            >
              {isPending(row.id, 'html') ? '…' : 'HTML'}
            </button>
            <button
              type="button"
              className="text-button"
              onClick={() => void openReport(row.id, 'pdf')}
              disabled={isPending(row.id, 'pdf')}
            >
              {isPending(row.id, 'pdf') ? '…' : 'PDF'}
            </button>
          </span>
        ) : (
          <span className="muted">—</span>
        ),
    },
  ];

  return (
    <div className="page">
      <div className="page-intro">
        <div>
          <span className="eyebrow">Assessment history</span>
          <h2>Scans</h2>
          <p>
            Every scan keeps its own evidence and deterministic results. Starting a scan returns
            immediately; progress is reported separately.
          </p>
        </div>
        <div className="inline-actions">
          <button type="button" className="button button-light" onClick={scans.reload}>
            Refresh
          </button>
          <button
            type="button"
            className="button button-primary"
            onClick={() => void startScan()}
            disabled={isStarting || (tracked !== null && tracked.status === 'running')}
          >
            {isStarting ? 'Queueing…' : 'Start scan'}
          </button>
        </div>
      </div>

      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>Filters</h2>
            <p>Filters map directly onto the documented query parameters of `GET /scans`.</p>
          </div>
          {hasFilters ? (
            <button type="button" className="text-button" onClick={resetFilters}>
              Clear filters
            </button>
          ) : null}
        </div>
        <div className="filter-grid">
          <label className="field">
            <span className="field-label">Status</span>
            <select
              value={status}
              onChange={(event) => setStatus(event.target.value as ScanStatus | '')}
            >
              <option value="">Any status</option>
              {SCAN_STATUSES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span className="field-label">Hostname contains</span>
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="e.g. WIN-DEV-01"
            />
          </label>
          <label className="field">
            <span className="field-label">Source</span>
            <input
              type="text"
              value={source}
              onChange={(event) => setSource(event.target.value)}
              placeholder="local_agent"
            />
          </label>
          <label className="field">
            <span className="field-label">Device ID</span>
            <input
              type="text"
              value={deviceId}
              onChange={(event) => setDeviceId(event.target.value)}
              placeholder="Exact device UUID"
              spellCheck={false}
            />
          </label>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>Scan records</h2>
            <p>
              {scans.count} loaded{scans.hasMore ? ' · more available' : ' · end of history'}
            </p>
          </div>
        </div>

        {scans.isError ? (
          <ErrorState error={scans.error} onRetry={scans.reload} scope="Scan history" />
        ) : (
          <>
            <DataTable
              columns={columns}
              rows={scans.items}
              rowKey={(row) => row.id}
              caption="Scan history"
              busy={scans.isLoading}
              busyLabel="Loading scans…"
              empty={
                <EmptyState
                  title={hasFilters ? 'No scans match these filters' : 'No scans recorded yet'}
                  description={
                    hasFilters
                      ? 'Clear the filters, or widen the hostname search.'
                      : 'Queue a scan to collect endpoint evidence.'
                  }
                  action={
                    hasFilters ? (
                      <button type="button" className="button button-light" onClick={resetFilters}>
                        Clear filters
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="button button-primary"
                        onClick={() => void startScan()}
                        disabled={isStarting}
                      >
                        Start scan
                      </button>
                    )
                  }
                />
              }
            />
            <LoadMore
              hasMore={scans.hasMore}
              isLoading={scans.isLoadingMore}
              onLoadMore={scans.loadMore}
              loadedCount={scans.count}
              pageSize={DEFAULT_PAGE_SIZE}
              unit="scans"
            />
          </>
        )}
      </section>

      {scans.isLoading && scans.items.length === 0 ? (
        <LoadingState label="Loading scan history…" rows={4} />
      ) : null}
    </div>
  );
}
