/**
 * Controls.
 *
 * Shows the deterministic control verdicts of one scan, with an explicit
 * five-state tally so `unknown` and `error` are counted separately and never
 * folded into passes or failures. Filtering happens in the browser over the
 * loaded assessment payload, which the contract returns as a single object; the
 * table still reveals rows in bounded pages.
 */

import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getScanResults, queryKeys } from '../api';
import { useDocumentTitle } from '../hooks/useAppData';
import { pickNewest, useRecentScans } from '../hooks/useRecentScans';
import { ScanPicker } from '../components/ScanPicker';
import { PostureHeadline, countsFrom } from '../components/PosturePanel';
import { MetricCard, MetricGrid } from '../components/MetricCard';
import { ControlTable } from '../components/ControlTable';
import { ControlDrawer, type ControlDetail } from '../components/ControlDrawer';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { ControlStatusBadge } from '../components/Badges';
import { CONTROL_STATUSES, formatPercent, humanize } from '../lib/format';
import type { ControlStatus } from '../types';

/* ---------- Types derived from the API ---------- */

type Assessment = NonNullable<Awaited<ReturnType<typeof getScanResults>>['results']>;
type ControlRow = Assessment['controls'][number];
type Tally = Record<ControlStatus, number>;

interface Filters {
  status: ControlStatus | '';
  category: string;
  severity: string;
  search: string;
}

/* ---------- Constants ---------- */

const RECENT_LOOKUP_LIMIT = 5;
const RESULTS_STALE_MS = 30_000;
const NO_FILTERS: Filters = { status: '', category: '', severity: '', search: '' };

/* ---------- Pure helpers ---------- */

function isControlStatus(value: string): value is ControlStatus {
  return (CONTROL_STATUSES as readonly string[]).includes(value);
}

/**
 * Counts every frozen state. Unrecognised values are ignored rather than
 * written to an arbitrary key, so they can never inflate a count.
 */
function tallyControls(controls: readonly ControlRow[]): Tally {
  const tally: Tally = {
    compliant: 0,
    non_compliant: 0,
    not_applicable: 0,
    unknown: 0,
    error: 0,
  };
  for (const control of controls) {
    if (isControlStatus(control.status)) tally[control.status] += 1;
  }
  return tally;
}

function uniqueSorted(values: string[]): string[] {
  return Array.from(new Set(values)).sort((left, right) => left.localeCompare(right));
}

function matchesControlFilters(control: ControlRow, filters: Filters): boolean {
  if (filters.status && control.status !== filters.status) return false;
  if (filters.category && control.category !== filters.category) return false;
  if (filters.severity && String(control.severity) !== filters.severity) return false;

  const needle = filters.search.trim().toLowerCase();
  if (!needle) return true;
  return `${control.control_id} ${control.title} ${control.category}`
    .toLowerCase()
    .includes(needle);
}

function hasActiveFilters(filters: Filters): boolean {
  return (
    filters.status !== '' ||
    filters.category !== '' ||
    filters.severity !== '' ||
    filters.search.trim() !== ''
  );
}

/* ---------- Hooks ---------- */

/**
 * The scan comes from the `?scan=` query parameter. Without one, the newest
 * completed scan is used. Choosing a scan writes the parameter back, replacing
 * the history entry.
 */
function useScanSelection() {
  const [searchParams, setSearchParams] = useSearchParams();
  const selected = searchParams.get('scan');

  const recent = useRecentScans(RECENT_LOOKUP_LIMIT, 'completed');
  const fallbackScan = pickNewest(recent.data?.items, ['completed']);
  const scanId = selected ?? fallbackScan?.id ?? null;

  function choose(next: string | null) {
    const params = new URLSearchParams(searchParams);
    if (next) params.set('scan', next);
    else params.delete('scan');
    setSearchParams(params, { replace: true });
  }

  return { selected, scanId, recent, choose };
}

function useScanResults(scanId: string | null) {
  return useQuery({
    queryKey: queryKeys.scans.results(scanId ?? 'none'),
    enabled: scanId !== null,
    staleTime: RESULTS_STALE_MS,
    queryFn: () => {
      if (!scanId) throw new Error('No scan selected.');
      return getScanResults(scanId);
    },
  });
}

/* ---------- Page ---------- */

export default function ControlsPage() {
  useDocumentTitle('Controls · SecureConfigAI');

  const { selected, scanId, recent, choose } = useScanSelection();
  const results = useScanResults(scanId);

  // Filters live on the page, not inside the panels, so they survive a scan change.
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [inspected, setInspected] = useState<ControlDetail | null>(null);

  const assessment = results.data?.results;

  return (
    <div className="page">
      <PageIntro selected={selected} onChoose={choose} />

      {recent.isError && scanId === null ? (
        <ErrorState error={recent.error} onRetry={() => void recent.refetch()} scope="Scan lookup" />
      ) : null}

      {scanId === null && !recent.isLoading ? <NoCompletedScan /> : null}

      {scanId !== null && results.isLoading ? (
        <LoadingState label="Loading control verdicts…" rows={4} />
      ) : null}

      {scanId !== null && results.isError ? (
        <ErrorState
          error={results.error}
          onRetry={() => void results.refetch()}
          scope="Control verdicts"
        />
      ) : null}

      {assessment && scanId !== null ? (
        <>
          <PostureHeadline
            values={{
              security_score: assessment.security_score,
              compliance_score: assessment.compliance_score,
              assessment_coverage: assessment.assessment_coverage,
              risk_score: assessment.risk_score,
              risk_level: assessment.risk_level,
              evidence_quality: assessment.evidence_quality,
            }}
            controls={countsFrom(assessment)}
          />

          <VerdictTally scanId={scanId} assessment={assessment} />

          <ControlVerdictsPanel
            controls={assessment.controls}
            filters={filters}
            onFiltersChange={setFilters}
            onInspect={setInspected}
          />
        </>
      ) : null}

      <ControlDrawer detail={inspected} onClose={() => setInspected(null)} />
    </div>
  );
}

/* ---------- Sections ---------- */

function PageIntro({
  selected,
  onChoose,
}: {
  selected: string | null;
  onChoose: (scanId: string | null) => void;
}) {
  return (
    <div className="page-intro">
      <div>
        <span className="eyebrow">Deterministic decision engine</span>
        <h2>Controls</h2>
        <p>
          Verdicts produced by the backend from stored evidence. The dashboard never recalculates a
          score, and never turns an undecided control into a pass.
        </p>
      </div>
      <div className="page-intro-tools">
        <ScanPicker
          value={selected}
          onChange={onChoose}
          status={undefined}
          placeholder="Newest completed scan"
        />
      </div>
    </div>
  );
}

function NoCompletedScan() {
  return (
    <EmptyState
      title="No completed assessment to inspect"
      description="Control verdicts come from a completed scan. Run one from the Overview or Scans page, then return here."
      action={
        <Link className="button button-primary" to="/scans">
          Go to scans
        </Link>
      }
    />
  );
}

function VerdictTally({
  scanId,
  assessment,
}: {
  scanId: string;
  assessment: Assessment;
}) {
  const controls = assessment.controls;
  const tally = useMemo(() => tallyControls(controls), [controls]);
  const exemptedCount = useMemo(
    () => controls.filter((control) => control.exempted).length,
    [controls],
  );

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Verdict tally</h2>
          <p>
            Every frozen control state is counted separately. Unknown and error are not passes and not
            failures. They are gaps in the assessment.
          </p>
        </div>
        <Link className="text-button" to={`/scans/${scanId}`}>
          Open scan detail
        </Link>
      </div>

      <MetricGrid columns={4}>
        <MetricCard
          label="Compliant"
          value={tally.compliant}
          tone="ok"
          hint="Assessed controls that match the expected state."
        />
        <MetricCard
          label="Non-compliant"
          value={tally.non_compliant}
          tone="risk"
          hint="Assessed controls that do not match the expected state."
        />
        <MetricCard
          label="Not applicable"
          value={tally.not_applicable}
          tone="neutral"
          hint="Controls outside this endpoint's scope, including recorded exemptions."
        />
        <MetricCard
          label="Unknown"
          value={tally.unknown}
          tone="unknown"
          hint="Evidence was missing, so no decision was possible. Counts against coverage."
        />
        <MetricCard
          label="Error"
          value={tally.error}
          tone="unknown"
          hint="The engine could not evaluate the control. Not a failure of the endpoint."
        />
        <MetricCard
          label="Total controls"
          value={controls.length}
          note={`${tally.compliant + tally.non_compliant} decided · coverage ${formatPercent(assessment.assessment_coverage)}`}
        />
        <MetricCard
          label="Exempted"
          value={exemptedCount}
          note="Excluded from scoring with a recorded reason"
        />
        <MetricCard
          label="Showing"
          value={`${controls.length}`}
          note="All controls in this assessment"
        />
      </MetricGrid>
    </section>
  );
}

function ControlVerdictsPanel({
  controls,
  filters,
  onFiltersChange,
  onInspect,
}: {
  controls: readonly ControlRow[];
  filters: Filters;
  onFiltersChange: (next: Filters) => void;
  onInspect: (detail: ControlDetail) => void;
}) {
  const categories = useMemo(
    () => uniqueSorted(controls.flatMap((control) => (control.category ? [control.category] : []))),
    [controls],
  );
  const severities = useMemo(
    () =>
      uniqueSorted(
        controls.flatMap((control) => (control.severity ? [String(control.severity)] : [])),
      ),
    [controls],
  );
  const filtered = useMemo(
    () => controls.filter((control) => matchesControlFilters(control, filters)),
    [controls, filters],
  );
  const active = hasActiveFilters(filters);

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Control verdicts</h2>
          <p>Sortable columns. Open a control for rationale, states, references and remediation.</p>
        </div>
      </div>

      <ControlFilters
        filters={filters}
        categories={categories}
        severities={severities}
        onChange={onFiltersChange}
      />

      {active ? (
        <div className="filter-summary">
          <span>
            Showing {filtered.length} of {controls.length} controls
          </span>
          <button
            type="button"
            className="text-button"
            onClick={() => onFiltersChange(NO_FILTERS)}
          >
            Clear filters
          </button>
        </div>
      ) : null}

      {active && filtered.length > 0 ? <FilteredTally rows={filtered} /> : null}

      <ControlTable
        controls={filtered}
        onInspect={onInspect}
        emptyTitle={active ? 'No controls match these filters' : 'No controls evaluated'}
        emptyDescription={
          active
            ? 'Clear the filters to see the full set of verdicts.'
            : 'The assessment returned no control verdicts.'
        }
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
  return (
    <div className="filter-grid">
      <label className="field">
        <span className="field-label">State</span>
        <select
          value={filters.status}
          onChange={(event) => onChange({ ...filters, status: event.target.value as ControlStatus | '' })}
        >
          <option value="">Any state</option>
          {CONTROL_STATUSES.map((status) => (
            <option key={status} value={status}>
              {humanize(status)}
            </option>
          ))}
        </select>
      </label>

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
          placeholder="Control ID or title"
        />
      </label>
    </div>
  );
}

/** Per-state counts for the filtered subset. Zero-count states are omitted. */
function FilteredTally({ rows }: { rows: readonly ControlRow[] }) {
  const tally = useMemo(() => tallyControls(rows), [rows]);

  return (
    <div className="tally-inline">
      {CONTROL_STATUSES.map((status) => {
        const count = tally[status];
        if (count === 0) return null;
        return (
          <span className="tally-inline-item" key={status}>
            <ControlStatusBadge status={status} /> <strong>{count}</strong>
          </span>
        );
      })}
    </div>
  );
}