/**
 * Findings table.
 *
 * Findings are shown with their deterministic severity and control state, plus
 * an optional advisory action ("Explain") that opens AI output in a drawer. The
 * AI never edits a finding: the drawer presents it alongside the recorded values
 * so the difference between evidence and commentary stays obvious.
 */

import { EmptyState } from './States';
import { DataTable, LoadMore, type Column } from './DataTable';
import { ControlStatusBadge, SeverityBadge } from './Badges';
import { useClientWindow } from '../hooks/useClientWindow';
import { truncate } from '../lib/format';
import type { Finding } from '../types';

export function FindingTable({
  findings,
  onExplain,
  pageSize = 25,
  caption = 'Findings from the deterministic assessment',
  emptyTitle = 'No findings recorded',
  emptyDescription = 'A completed assessment with no findings has nothing to review here.',
}: {
  findings: Finding[];
  /** Omit to render a read-only table. */
  onExplain?: (finding: Finding) => void;
  pageSize?: number;
  caption?: string;
  emptyTitle?: string;
  emptyDescription?: string;
}) {
  const windowed = useClientWindow(findings, pageSize);

  const columns: Column<Finding>[] = [
    {
      id: 'severity',
      header: 'Severity',
      width: '10%',
      cell: (row) => <SeverityBadge severity={row.severity} />,
    },
    {
      id: 'control',
      header: 'Control',
      width: '12%',
      cell: (row) => <code className="cell-code">{row.control_id ?? '—'}</code>,
    },
    {
      id: 'finding',
      header: 'Finding',
      cell: (row) => (
        <span className="cell-stack">
          <span className="cell-title">{row.title}</span>
          {row.description ? (
            <span className="cell-subtle">{truncate(row.description, 120)}</span>
          ) : null}
        </span>
      ),
    },
    {
      id: 'category',
      header: 'Category',
      hideBelow: 'lg',
      width: '13%',
      cell: (row) => row.category,
    },
    {
      id: 'status',
      header: 'State',
      width: '11%',
      cell: (row) => <ControlStatusBadge status={row.status} />,
    },
    {
      id: 'priority',
      header: 'Priority',
      hideBelow: 'md',
      width: '10%',
      cell: (row) => <span className="muted">{row.recommendation?.priority ?? '—'}</span>,
    },
  ];

  if (onExplain) {
    columns.push({
      id: 'actions',
      header: 'Advisory',
      align: 'right',
      width: '12%',
      cell: (row) => (
        <button type="button" className="text-button" onClick={() => onExplain(row)}>
          Explain
        </button>
      ),
    });
  }

  return (
    <>
      <DataTable
        columns={columns}
        rows={windowed.visible}
        rowKey={(row) => row.id}
        caption={caption}
        empty={<EmptyState title={emptyTitle} description={emptyDescription} compact />}
      />
      <LoadMore
        hasMore={windowed.hasMore}
        isLoading={false}
        onLoadMore={windowed.loadMore}
        loadedCount={windowed.visible.length}
        pageSize={pageSize}
        unit={`of ${windowed.total} findings`}
      />
    </>
  );
}
