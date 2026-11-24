/**
 * Reports.
 *
 * Both artefacts are served by the API with an `ETag`, so the client fetches the
 * report with its normal cache mode and adds no cache-busting query string:
 * opening the same report twice revalidates (`If-None-Match` → `304`) instead of
 * re-rendering it on the server.
 */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { listScans, queryKeys } from '../api';
import { DEFAULT_PAGE_SIZE, useCursorList } from '../hooks/useCursorList';
import { useDebouncedValue, useDocumentTitle } from '../hooks/useAppData';
import { DataTable, LoadMore, type Column } from '../components/DataTable';
import { ScanStatusBadge } from '../components/Badges';
import { EmptyState, ErrorState, Notice } from '../components/States';
import { useOpenReport } from '../hooks/useOpenReport';
import { formatDateTime, formatPercent, formatScore, SCAN_STATUSES } from '../lib/format';
import type { ScanStatus, ScanSummary } from '../types';

export default function ReportsPage() {
  useDocumentTitle('Reports · SecureConfigAI');
  const { openReport, isPending } = useOpenReport();
  const [status, setStatus] = useState<ScanStatus | ''>('completed');
  const [query, setQuery] = useState('');
  const debouncedQuery = useDebouncedValue(query, 350);

  const filters = {
    limit: DEFAULT_PAGE_SIZE,
    status: status === '' ? undefined : status,
    q: debouncedQuery.trim() || undefined,
  };

  const scans = useCursorList<ScanSummary>({
    queryKey: queryKeys.scans.list({ ...filters, scope: 'reports' }),
    fetchPage: (cursor, signal) => listScans({ ...filters, cursor }, signal),
    staleTime: 15_000,
  });

  const columns: Column<ScanSummary>[] = [
    {
      id: 'scan',
      header: 'Scan',
      width: '26%',
      cell: (row) => (
        <Link className="cell-primary" to={`/scans/${row.id}`}>
          <span className="cell-title">{row.hostname ?? row.device_id ?? 'Unlinked scan'}</span>
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
      id: 'completed',
      header: 'Completed',
      width: '17%',
      cell: (row) => formatDateTime(row.completed_at),
    },
    {
      id: 'score',
      header: 'Score',
      align: 'right',
      hideBelow: 'lg',
      width: '10%',
      cell: (row) => (row.security_score === null ? '—' : `${formatScore(row.security_score)}/100`),
    },
    {
      id: 'coverage',
      header: 'Coverage',
      align: 'right',
      hideBelow: 'md',
      width: '10%',
      cell: (row) => formatPercent(row.assessment_coverage),
    },
    {
      id: 'actions',
      header: 'Artefacts',
      align: 'right',
      width: '25%',
      cell: (row) => {
        const ready = row.status === 'completed';
        if (!ready) {
          return (
            <span className="muted" title="Reports are produced from a completed assessment.">
              unavailable
            </span>
          );
        }
        return (
          <span className="inline-actions">
            <button
              type="button"
              className="button button-light button-sm"
              onClick={() => void openReport(row.id, 'html')}
              disabled={isPending(row.id, 'html')}
            >
              {isPending(row.id, 'html') ? 'Opening…' : 'Open HTML'}
            </button>
            <button
              type="button"
              className="button button-primary button-sm"
              onClick={() => void openReport(row.id, 'pdf')}
              disabled={isPending(row.id, 'pdf')}
            >
              {isPending(row.id, 'pdf') ? 'Opening…' : 'Open PDF'}
            </button>
          </span>
        );
      },
    },
  ];

  return (
    <div className="page">
      <div className="page-intro">
        <div>
          <span className="eyebrow">Evidence reporting</span>
          <h2>Reports</h2>
          <p>
            HTML and PDF artefacts rendered by the API from stored scan evidence. The dashboard never
            regenerates a report locally.
          </p>
        </div>
        <div className="inline-actions">
          <button type="button" className="button button-light" onClick={scans.reload}>
            Refresh
          </button>
        </div>
      </div>

      <Notice tone="info" title="Reopening a report is cheap">
        Report responses carry an <code>ETag</code>. The client requests the documented URL as-is —
        no cache-busting parameters — so a repeat open revalidates with{' '}
        <code>If-None-Match</code> and the API answers <code>304</code> without re-rendering.
      </Notice>

      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>Report artefacts</h2>
            <p>
              {scans.count} scans loaded{scans.hasMore ? ' · more available' : ''}
            </p>
          </div>
          <div className="table-tools">
            <label className="field field-inline">
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
            <label className="field field-inline">
              <span className="visually-hidden">Filter by hostname</span>
              <input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Hostname contains"
              />
            </label>
          </div>
        </div>

        {scans.isError ? (
          <ErrorState error={scans.error} onRetry={scans.reload} scope="Reports" />
        ) : (
          <>
            <DataTable
              columns={columns}
              rows={scans.items}
              rowKey={(row) => row.id}
              caption="Scan report artefacts"
              busy={scans.isLoading}
              busyLabel="Loading scans…"
              empty={
                <EmptyState
                  title="No scans to report on"
                  description="Reports exist for completed scans. Change the status filter, or run a scan first."
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
    </div>
  );
}
