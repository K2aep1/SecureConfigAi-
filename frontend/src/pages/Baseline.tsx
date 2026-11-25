/**
 * Baseline.
 *
 * Renders the shipped baseline pack in full: every control with its weight,
 * severity, category, rationale, expected state and standard references (each a
 * link, and only when the URL is a safe http(s) target). Nothing here is
 * scan-specific. This is the definition every assessment is measured against.
 */

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getBaseline, queryKeys } from '../api';
import { useDocumentTitle } from '../hooks/useAppData';
import { useClientWindow } from '../hooks/useClientWindow';
import { DataTable, LoadMore, type Column } from '../components/DataTable';
import { SeverityBadge } from '../components/Badges';
import {
  ControlDrawer,
  controlDetailFromBaseline,
  type ControlDetail,
} from '../components/ControlDrawer';
import { MetricCard, MetricGrid } from '../components/MetricCard';
import { JsonFacts } from '../components/JsonFacts';
import { EmptyState, ErrorState, LoadingState, Notice } from '../components/States';
import { formatDate, formatJsonInline, humanize } from '../lib/format';
import { safeExternalHref } from '../lib/url';
import type { BaselineControl, JsonValue } from '../types';

/* ---------- Types derived from the API ---------- */

type Baseline = Awaited<ReturnType<typeof getBaseline>>;
type ControlReference = NonNullable<BaselineControl['references']>[number];
type PackReference = NonNullable<Baseline['references']>[number];

interface Filters {
  category: string;
  severity: string;
  search: string;
}

/* ---------- Constants ---------- */

const PAGE_SIZE = 25;
const BASELINE_STALE_MS = 5 * 60 * 1000;
const NO_FILTERS: Filters = { category: '', severity: '', search: '' };

/* ---------- Pure helpers ---------- */

function uniqueSorted(values: string[]): string[] {
  return Array.from(new Set(values)).sort((left, right) => left.localeCompare(right));
}

function sumWeights(controls: readonly BaselineControl[]): number {
  return controls.reduce((total, control) => total + (Number(control.weight) || 0), 0);
}

function matchesFilters(control: BaselineControl, filters: Filters): boolean {
  if (filters.category && control.category !== filters.category) return false;
  if (filters.severity && String(control.severity) !== filters.severity) return false;

  const needle = filters.search.trim().toLowerCase();
  if (!needle) return true;
  return `${control.control_id} ${control.title} ${control.category}`
    .toLowerCase()
    .includes(needle);
}

/**
 * In the shipped pack `applicability` is an object of conditions rather than a
 * single word, so both shapes are rendered without assuming one.
 */
function applicabilityText(value: JsonValue): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return humanize(value);
  if (typeof value === 'boolean') return value ? 'always' : 'never';
  if (typeof value === 'number') return String(value);
  return formatJsonInline(value, 60);
}

/** Trims a pack-level reference and resolves its link target. */
function cleanPackReference(reference: PackReference) {
  const standard = String(reference.standard ?? '').trim();
  const control = String(reference.control ?? '').trim();
  const url = String(reference.url ?? '').trim();
  return {
    standard,
    control,
    isEmpty: !(standard || control || url),
    href: safeExternalHref(url),
    label: [standard, control].filter(Boolean).join(' · ') || url,
  };
}

/* ---------- Page ---------- */

export default function BaselinePage() {
  useDocumentTitle('Baseline · SecureConfigAI');
  const [inspected, setInspected] = useState<ControlDetail | null>(null);

  const baseline = useQuery({
    queryKey: queryKeys.policies.baseline(),
    staleTime: BASELINE_STALE_MS,
    queryFn: ({ signal }) => getBaseline(signal),
  });

  const data = baseline.data;
  const controls = useMemo(() => data?.controls ?? [], [data]);

  return (
    <div className="page">
      <PageIntro />

      {baseline.isLoading ? <LoadingState label="Loading baseline pack…" rows={4} /> : null}

      {baseline.isError ? (
        <ErrorState error={baseline.error} onRetry={() => void baseline.refetch()} scope="Baseline" />
      ) : null}

      {data ? (
        <>
          <BaselineSummary baseline={data} controls={controls} />

          {controls.length === 0 ? (
            <Notice tone="warning" title="Empty baseline">
              The baseline pack returned no controls. Assessments would have nothing to evaluate, so
              check the backend&apos;s baseline data before trusting any score.
            </Notice>
          ) : null}

          <ControlsSection controls={controls} onInspect={setInspected} />
        </>
      ) : null}

      <ControlDrawer detail={inspected} onClose={() => setInspected(null)} />
    </div>
  );
}

/* ---------- Sections ---------- */

function PageIntro() {
  return (
    <div className="page-intro">
      <div>
        <span className="eyebrow">Shipped control pack</span>
        <h2>Baseline</h2>
        <p>
          The frozen control definitions every assessment is measured against: weight, severity,
          rationale, expected state and the standards each control maps to.
        </p>
      </div>
    </div>
  );
}

function BaselineSummary({
  baseline,
  controls,
}: {
  baseline: Baseline;
  controls: readonly BaselineControl[];
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>{baseline.title}</h2>
          <p>{baseline.description}</p>
        </div>
        <span className="badge badge-outline badge-mono">{baseline.baseline_id}</span>
      </div>

      <MetricGrid columns={4}>
        <MetricCard label="Baseline version" value={baseline.version} />
        <MetricCard label="Published" value={formatDate(baseline.published_at)} />
        <MetricCard label="Controls" value={baseline.control_count ?? controls.length} />
        <MetricCard
          label="Total weight"
          value={baseline.control_weight_total ?? sumWeights(controls)}
          note="Sum of the per-control weights used by the scoring model"
        />
      </MetricGrid>

      {baseline.severity_impact ? (
        <Subsection title="Severity impact">
          <div className="count-chip-row">
            {Object.entries(baseline.severity_impact).map(([severity, impact]) => (
              <span className="count-chip" key={severity}>
                <span className="count-chip-value">{impact}</span>
                <span className="count-chip-label">{humanize(severity)}</span>
              </span>
            ))}
          </div>
        </Subsection>
      ) : null}

      <Subsection title="Pack references">
        <PackReferences references={baseline.references} />
      </Subsection>

      <Subsection title="Thresholds">
        <JsonFacts
          data={baseline.thresholds}
          emptyLabel="The pack records no thresholds."
          labelFormatter={(key) => humanize(key)}
        />
      </Subsection>

      <Subsection title="Categories">
        <JsonFacts
          data={baseline.categories}
          emptyLabel="The pack records no category metadata."
          labelFormatter={(key) => humanize(key)}
        />
      </Subsection>
    </section>
  );
}

function Subsection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="baseline-subsection">
      <h3 className="drawer-section-title">{title}</h3>
      {children}
    </div>
  );
}

function PackReferences({ references }: { references: Baseline['references'] }) {
  // Incomplete reference objects are ignored rather than rendered as "undefined · undefined".
  const valid = (references ?? []).map(cleanPackReference).filter((ref) => !ref.isEmpty);

  if (valid.length === 0) {
    return <p className="muted">No valid pack-level references recorded.</p>;
  }

  return (
    <ul className="ref-list">
      {valid.map((ref, index) => (
        <li key={`${ref.standard}-${ref.control}-${index}`}>
          {ref.href ? (
            <a href={ref.href} target="_blank" rel="noopener noreferrer">
              {ref.label}
            </a>
          ) : (
            <span>{ref.label}</span>
          )}
        </li>
      ))}
    </ul>
  );
}

function ControlsSection({
  controls,
  onInspect,
}: {
  controls: readonly BaselineControl[];
  onInspect: (detail: ControlDetail) => void;
}) {
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);

  const categories = useMemo(
    () => uniqueSorted(controls.flatMap((control) => (control.category ? [control.category] : []))),
    [controls],
  );
  const severities = useMemo(
    () =>
      uniqueSorted(controls.flatMap((control) => (control.severity ? [String(control.severity)] : []))),
    [controls],
  );
  const filtered = useMemo(
    () => controls.filter((control) => matchesFilters(control, filters)),
    [controls, filters],
  );
  const windowed = useClientWindow(filtered, PAGE_SIZE);
  const columns = useMemo(() => buildControlColumns(onInspect), [onInspect]);

  const filteredNote =
    filtered.length !== controls.length ? ` (filtered from ${controls.length})` : '';

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Controls in the pack</h2>
          <p>
            {windowed.visible.length} of {filtered.length} shown{filteredNote}
          </p>
        </div>
      </div>

      <ControlFilters
        filters={filters}
        categories={categories}
        severities={severities}
        onChange={setFilters}
      />

      <DataTable
        columns={columns}
        rows={windowed.visible}
        rowKey={(row) => row.control_id}
        caption="Baseline control definitions"
        empty={
          <EmptyState
            title="No controls match"
            description="Clear the filters to see the whole pack."
            compact
          />
        }
      />

      <LoadMore
        hasMore={windowed.hasMore}
        isLoading={false}
        onLoadMore={windowed.loadMore}
        loadedCount={windowed.visible.length}
        pageSize={PAGE_SIZE}
        unit={`of ${windowed.total} controls`}
      />
    </section>
  );
}

function ControlFilters({
  filters,
  categories,
  severities,
  onChange,
}: {
  filters: Filters;
  categories: string[];
  severities: string[];
  onChange: (next: Filters) => void;
}) {
  const isClear = filters.category === '' && filters.severity === '' && filters.search === '';

  return (
    <div className="filter-grid">
      <label className="field">
        <span className="field-label">Category</span>
        <select
          value={filters.category}
          onChange={(event) => onChange({ ...filters, category: event.target.value })}
        >
          <option value="">Any category</option>
          {categories.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </label>

      <label className="field">
        <span className="field-label">Severity</span>
        <select
          value={filters.severity}
          onChange={(event) => onChange({ ...filters, severity: event.target.value })}
        >
          <option value="">Any severity</option>
          {severities.map((value) => (
            <option key={value} value={value}>
              {humanize(value)}
            </option>
          ))}
        </select>
      </label>

      <label className="field">
        <span className="field-label">Search</span>
        <input
          type="search"
          value={filters.search}
          onChange={(event) => onChange({ ...filters, search: event.target.value })}
          placeholder="Control ID, title or category"
        />
      </label>

      <div className="field">
        <span className="field-label">&nbsp;</span>
        <button
          type="button"
          className="button button-light"
          onClick={() => onChange(NO_FILTERS)}
          disabled={isClear}
        >
          Clear filters
        </button>
      </div>
    </div>
  );
}

function ControlReferences({ references }: { references: readonly ControlReference[] }) {
  if (references.length === 0) return <span className="muted">—</span>;

  return (
    <span className="ref-inline">
      {references.map((reference, index) => {
        const href = safeExternalHref(reference.url);
        const label = `${reference.standard} ${reference.control}`;
        const key = `${reference.standard}-${index}`;
        return href ? (
          <a key={key} href={href} target="_blank" rel="noopener noreferrer" title={reference.url ?? undefined}>
            {label}
          </a>
        ) : (
          <span key={key} title={reference.url ?? undefined}>
            {label}
          </span>
        );
      })}
    </span>
  );
}

/* ---------- Table columns ---------- */

/** Built from the inspect callback, so the table is only rebuilt when that callback changes. */
function buildControlColumns(
  onInspect: (detail: ControlDetail) => void,
): Column<BaselineControl>[] {
  return [
    {
      id: 'control',
      header: 'Control',
      width: '24%',
      cell: (row) => (
        <button
          type="button"
          className="cell-primary"
          onClick={() => onInspect(controlDetailFromBaseline(row))}
        >
          <code className="cell-code">{row.control_id}</code>
          <span className="cell-title">{row.title}</span>
        </button>
      ),
    },
    {
      id: 'category',
      header: 'Category',
      width: '13%',
      cell: (row) => row.category,
    },
    {
      id: 'severity',
      header: 'Severity',
      width: '11%',
      cell: (row) => <SeverityBadge severity={row.severity} />,
    },
    {
      id: 'weight',
      header: 'Weight',
      align: 'right',
      width: '8%',
      cell: (row) => row.weight,
    },
    {
      id: 'expected',
      header: 'Expected state',
      width: '17%',
      cell: (row) => (
        <code className="cell-code" title={formatJsonInline(row.expected_state, 400)}>
          {formatJsonInline(row.expected_state, 40)}
        </code>
      ),
    },
    {
      id: 'collector',
      header: 'Collector',
      hideBelow: 'lg',
      width: '10%',
      cell: (row) =>
        row.collector ? <code className="cell-code">{row.collector}</code> : <span className="muted">—</span>,
    },
    {
      id: 'applicability',
      header: 'Applicability',
      hideBelow: 'lg',
      width: '12%',
      cell: (row) => <span className="muted">{applicabilityText(row.applicability)}</span>,
    },
    {
      id: 'rationale',
      header: 'Rationale',
      hideBelow: 'lg',
      cell: (row) => <span className="cell-subtle">{row.rationale}</span>,
    },
    {
      id: 'references',
      header: 'References',
      width: '15%',
      cell: (row) => <ControlReferences references={row.references ?? []} />,
    },
  ];
}