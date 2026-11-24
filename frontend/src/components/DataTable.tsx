/**
 * Accessible data table.
 *
 * Conventions enforced here:
 *  - `caption` is always supplied (visible or visually hidden) so the table has
 *    an accessible name.
 *  - Row-level navigation is performed by a real `<button>`/`<Link>` inside a
 *    cell — never an `onClick` on `<tr>` — so rows are reachable and operable
 *    from the keyboard.
 *  - Sortable headers are `<button>`s carrying `aria-sort` on the `<th>`.
 */

import type { ReactNode } from 'react';
import clsx from 'clsx';
import { LoadingState } from './States';

export interface Column<T> {
  id: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  align?: 'left' | 'center' | 'right';
  /** CSS width applied to the header cell. */
  width?: string;
  /** Provide to make the column sortable. */
  sortValue?: (row: T) => string | number;
  /** Hide on narrow viewports to keep 1024px usable. */
  hideBelow?: 'md' | 'lg';
  /** Extra class on both `th` and `td`. */
  className?: string;
}

export interface SortState {
  columnId: string;
  direction: 'asc' | 'desc';
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  caption,
  hideCaption = true,
  empty,
  sort,
  onSortChange,
  busy = false,
  busyLabel,
  footer,
}: {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T, index: number) => string;
  caption: string;
  hideCaption?: boolean;
  empty?: ReactNode;
  sort?: SortState | null;
  onSortChange?: (next: SortState) => void;
  busy?: boolean;
  busyLabel?: string;
  footer?: ReactNode;
}) {
  const showEmpty = rows.length === 0 && !busy;

  return (
    <div className={clsx('table-wrap', busy && 'table-wrap-busy')} aria-busy={busy || undefined}>
      <table className="data-table">
        <caption className={hideCaption ? 'visually-hidden' : 'table-caption'}>{caption}</caption>
        <thead>
          <tr>
            {columns.map((column) => {
              const isSorted = sort?.columnId === column.id;
              const sortable = Boolean(column.sortValue && onSortChange);
              const ariaSort = isSorted ? (sort?.direction === 'asc' ? 'ascending' : 'descending') : sortable ? 'none' : undefined;

              return (
                <th
                  key={column.id}
                  scope="col"
                  style={column.width ? { width: column.width } : undefined}
                  className={clsx(
                    'table-head-cell',
                    column.align && `align-${column.align}`,
                    column.hideBelow === 'md' && 'hide-below-md',
                    column.hideBelow === 'lg' && 'hide-below-lg',
                    column.className,
                  )}
                  aria-sort={ariaSort}
                >
                  {sortable ? (
                    <button
                      type="button"
                      className="table-sort"
                      onClick={() =>
                        onSortChange?.({
                          columnId: column.id,
                          direction: isSorted && sort?.direction === 'asc' ? 'desc' : 'asc',
                        })
                      }
                    >
                      <span>{column.header}</span>
                      <span className="table-sort-glyph" aria-hidden="true">
                        {isSorted ? (sort?.direction === 'asc' ? '↑' : '↓') : '↕'}
                      </span>
                    </button>
                  ) : (
                    column.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={rowKey(row, index)} className="table-row">
              {columns.map((column) => (
                <td
                  key={column.id}
                  className={clsx(
                    'table-cell',
                    column.align && `align-${column.align}`,
                    column.hideBelow === 'md' && 'hide-below-md',
                    column.hideBelow === 'lg' && 'hide-below-lg',
                    column.className,
                  )}
                >
                  {column.cell(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
        {footer ? <tfoot>{footer}</tfoot> : null}
      </table>

      {busy ? <LoadingState label={busyLabel ?? 'Loading table data…'} rows={3} compact /> : null}
      {showEmpty ? empty : null}
    </div>
  );
}

/**
 * "Load more" control for the contract's `{items,next_cursor,has_more,limit}`
 * envelope. Every table that talks to a paged endpoint renders exactly one of
 * these, so no list is ever unbounded.
 */
export function LoadMore({
  hasMore,
  isLoading,
  onLoadMore,
  loadedCount,
  pageSize,
  unit = 'rows',
}: {
  hasMore: boolean;
  isLoading: boolean;
  onLoadMore: () => void;
  loadedCount: number;
  pageSize?: number;
  unit?: string;
}) {
  return (
    <div className="load-more">
      <span className="load-more-count" aria-live="polite">
        {loadedCount} {unit} loaded
        {hasMore ? '' : ' · end of list'}
      </span>
      {hasMore ? (
        <button
          type="button"
          className="button button-light"
          onClick={onLoadMore}
          disabled={isLoading}
        >
          {isLoading ? 'Loading…' : `Load ${pageSize ? `${pageSize} more` : 'more'}`}
        </button>
      ) : null}
    </div>
  );
}
