/**
 * Reports.
 *
 * Both artefacts are served by the API with an `ETag`, so the client fetches the
 * report with its normal cache mode and adds no cache-busting query string:
 * opening the same report twice revalidates (`If-None-Match` → `304`) instead of
 * re-rendering it on the server.
 */

import { useMemo, useState } from 'react';
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

/* ---------- Types ---------- */

type ReportActions = ReturnType<typeof useOpenReport>;
type ReportFormat = 'html' | 'pdf';

interface FormatButton {
  format: ReportFormat;
  label: string;
  className: string;
}

/* ---------- Constants ---------- */

const SEARCH_DEBOUNCE_MS = 350;
const LIST_STALE_MS = 15_000;
const DEFAULT_STATUS: ScanStatus | '' = 'completed';

const FORMAT_BUTTONS: readonly FormatButton[] = [
  { format: 'html', label: 'HTML', className: 'button button-light button-sm' },
  { format: 'pdf', label: 'PDF', className: 'button button-primary button-sm' },
];

/* ---------- Pure helpers ---------- */

function scanLabel(scan: ScanSummary): string {
  return scan.hostname ?? scan.device_id ?? 'Unlinked scan';
}

/**
 * Treats a missing score the same as a null one. The original only checked for
 * null, so an absent field would have reached `formatScore` as `undefined`.
 */
function scoreLabel(score: number | null | undefined): string {
  return score === null || score === undefined ? '—' : `${formatScore(score)}/100`;
}

/* ---------- Page ---------- */

export default function ReportsPage() {
  useDocumentTitle('Reports · SecureConfigAI');
  const reports = useOpenReport();

  const [status, setStatus] = useState<ScanStatus | ''>(DEFAULT_STATUS);
  const [query, setQuery] = useState('');
  const debouncedQuery = useDebouncedValue(query, SEARCH_DEBOUNCE_MS);

  const filters = useMemo(
    () => ({
      limit: DEFAULT_PAGE_SIZE,
      status: status === '' ? undefined : status,
      q: debouncedQuery.trim() || undefined,
    }),
    [status, debouncedQuery],
  );

  const scans = useCursorList<ScanSummary>({
    queryKey: queryKeys.scans.list({ ...filters, scope: 'reports' }),
    fetchPage: (cursor, signal) => listScans({ ...filters, cursor }, signal),
    staleTime: LIST_STALE_MS,
  });

  return (
    <div className="page">
      <PageIntro onRefresh={scans.reload} />

      <Notice tone="info" title="Reopening a report is cheap">
        Report responses carry an <code>ETag</code>. The client requests the documented URL as-is,
        with no cache-busting parameters, so a repeat open revalidates with{' '}
        <code>If-None-Match</code> and the API answers <code>304</code> without re-rendering.
      </Notice>

      <ReportsPanel
        scans={scans}
        reports={reports}
        status={status}
        onStatusChange={setStatus}
        query={query}
        onQueryChange={setQuery}
      />
    </div>
  );
}

/* ---------- Sections ---------- */

function PageIntro({ onRefresh }: { onRefresh: () => void }) {
  return (
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
        <button type="button" className="button button-light" onClick={onRefresh}>
          Refresh
        </button>
      </div>
    </div>
  );
}

function ReportsPanel({
  scans,
  reports,
  status,
  onStatusChange,
  query,
  onQueryChange,
}: {
  scans: ReturnType<typeof useCursorList<ScanSummary>>;
  reports: ReportActions;
  status: ScanStatus | '';
  onStatusChange: (next: ScanStatus | '') => void;
  query: string;
  onQueryChange: (next: string) => void;
}) {
  const columns = buildReportColumns(reports);

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Report artefacts</h2>
          <p>
            {scans.count} scans loaded{scans.hasMore ? ' · more available' : ''}
          </p>
        </div>
        <div className="table-tools">
          <StatusFilter value={status} onChange={onStatusChange} />
          <label className="field field-inline">
            <span className="visually-hidden">Filter by hostname</span>
            <input
              type="search"
              value={query}
              onChange={(event) => onQueryChange(event.target.value)}
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
  );
}

function StatusFilter({
  value,
  onChange,
}: {
  value: ScanStatus | '';
  onChange: (next: ScanStatus | '') => void;
}) {
  return (
    <label className="field field-inline">
      <span className="field-label">Status</span>
      <select value={value} onChange={(event) => onChange(event.target.value as ScanStatus | '')}>
        <option value="">Any status</option>
        {SCAN_STATUSES.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}

/* ---------- Artefact actions ---------- */

function ArtefactActions({ scan, reports }: { scan: ScanSummary; reports: ReportActions }) {
  if (scan.status !== 'completed') {
    return (
      <span className="muted" title="Reports are produced from a completed assessment.">
        unavailable
      </span>
    );
  }

  return (
    <span className="inline-actions">
      {FORMAT_BUTTONS.map(({ format, label, className }) => {
        const pending = reports.isPending(scan.id, format);
        return (
          <button
            key={format}
            type="button"
            className={className}
            onClick={() => void reports.openReport(scan.id, format)}
            disabled={pending}
          >
            {pending ? 'Opening…' : `Open ${label}`}
          </button>
        );
      })}
    </span>
  );
}

/* ---------- Columns ---------- */

function buildReportColumns(reports: ReportActions): Column<ScanSummary>[] {
  return [
    {
      id: 'scan',
      header: 'Scan',
      width: '26%',
      cell: (row) => (
        <Link className="cell-primary" to={`/scans/${row.id}`}>
          <span className="cell-title">{scanLabel(row)}</span>
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
      cell: (row) => scoreLabel(row.security_score),
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
      cell: (row) => <ArtefactActions scan={row} reports={reports} />,
    },
  ];
}