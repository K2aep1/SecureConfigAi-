/**
 * Controls table.
 *
 * Used by ScanDetail and the Controls page. Verdicts come from the deterministic
 * engine only — nothing in this component recomputes or reinterprets a score.
 * Rows are opened through a real button in the first cell, so the table is fully
 * keyboard operable.
 */

import { useMemo, useState } from 'react';
import { DataTable, LoadMore, type Column, type SortState } from './DataTable';
import { ControlStatusBadge, SeverityBadge } from './Badges';
import { EmptyState } from './States';
import { useClientWindow } from '../hooks/useClientWindow';
import { formatJsonInline, humanize } from '../lib/format';
import { safeExternalHref } from '../lib/url';
import { controlDetailFromResult, type ControlDetail } from './ControlDrawer';
import type { ControlResult } from '../types';

export function ControlTable({
  controls,
  onInspect,
  pageSize = 25,
  emptyTitle = 'No controls were evaluated',
  emptyDescription = 'Run a scan to produce deterministic control verdicts.',
}: {
  controls: ControlResult[];
  onInspect: (detail: ControlDetail) => void;
  pageSize?: number;
  emptyTitle?: string;
  emptyDescription?: string;
}) {
  const [sort, setSort] = useState<SortState | null>(null);

  // Sort the whole set first, then reveal it in bounded windows: sorting must
  // never be limited to the rows that happen to be visible already.
  const sortedAll = useMemo(() => {
    if (!sort) return controls;
    const direction = sort.direction === 'asc' ? 1 : -1;
    return [...controls].sort((left, right) => {
      switch (sort.columnId) {
        case 'control':
          return left.control_id.localeCompare(right.control_id) * direction;
        case 'category':
          return left.category.localeCompare(right.category) * direction;
        case 'weight':
          return (left.weight - right.weight) * direction;
        case 'severity':
          return String(left.severity).localeCompare(String(right.severity)) * direction;
        case 'status':
          return left.status.localeCompare(right.status) * direction;
        default:
          return 0;
      }
    });
  }, [controls, sort]);

  const windowed = useClientWindow(sortedAll, pageSize);

  const columns: Column<ControlResult>[] = [
    {
      id: 'control',
      header: 'Control',
      sortValue: (row) => row.control_id,
      width: '26%',
      cell: (row) => (
        <button type="button" className="cell-primary" onClick={() => onInspect(controlDetailFromResult(row))}>
          <code className="cell-code">{row.control_id}</code>
          <span className="cell-title">{row.title}</span>
        </button>
      ),
    },
    {
      id: 'status',
      header: 'Verdict',
      sortValue: (row) => row.status,
      width: '12%',
      cell: (row) => <ControlStatusBadge status={row.status} exempted={row.exempted} />,
    },
    {
      id: 'severity',
      header: 'Severity',
      sortValue: (row) => row.severity,
      width: '10%',
      cell: (row) => <SeverityBadge severity={row.severity} />,
    },
    {
      id: 'category',
      header: 'Category',
      sortValue: (row) => row.category,
      width: '14%',
      cell: (row) => row.category,
    },
    {
      id: 'weight',
      header: 'Weight',
      align: 'right',
      sortValue: (row) => row.weight,
      width: '7%',
      cell: (row) => row.weight,
    },
    {
      id: 'states',
      header: 'Expected vs observed',
      hideBelow: 'lg',
      cell: (row) => (
        <span className="cell-states">
          <span className="cell-state">
            <span className="cell-state-label">exp</span>
            {formatJsonInline(row.expected_state, 40)}
          </span>
          <span className="cell-state">
            <span className="cell-state-label">obs</span>
            {formatJsonInline(row.actual_state, 40)}
          </span>
        </span>
      ),
    },
    {
      id: 'standards',
      header: 'Standards',
      hideBelow: 'lg',
      width: '14%',
      cell: (row) => {
        const refs = row.standard_refs ?? [];
        if (refs.length === 0) return <span className="muted">—</span>;
        return (
          <span className="ref-inline">
            {refs.slice(0, 2).map((reference, index) => {
              const href = safeExternalHref(reference.url);
              const label = reference.standard;
              return href ? (
                <a
                  key={`${reference.standard}-${index}`}
                  href={href}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {label}
                </a>
              ) : (
                <span key={`${reference.standard}-${index}`}>{label}</span>
              );
            })}
            {refs.length > 2 ? <span className="muted">+{refs.length - 2}</span> : null}
          </span>
        );
      },
    },
    {
      id: 'applicability',
      header: 'Applicability',
      hideBelow: 'lg',
      width: '11%',
      cell: (row) => <span className="muted">{humanize(row.applicability)}</span>,
    },
  ];

  return (
    <>
      <DataTable
        columns={columns}
        rows={windowed.visible}
        rowKey={(row) => row.control_id}
        caption="Control verdicts from the deterministic assessment engine"
        sort={sort}
        onSortChange={setSort}
        empty={
          <EmptyState title={emptyTitle} description={emptyDescription} compact />
        }
      />
      <LoadMore
        hasMore={windowed.hasMore}
        isLoading={false}
        onLoadMore={windowed.loadMore}
        loadedCount={windowed.visible.length}
        pageSize={pageSize}
        unit={`of ${windowed.total} controls`}
      />
    </>
  );
}
