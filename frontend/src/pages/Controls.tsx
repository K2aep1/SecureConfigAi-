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
import { formatPercent, humanize } from '../lib/format';
import { CONTROL_STATUSES } from '../lib/format';
import type { ControlStatus } from '../types';

export default function ControlsPage() {
  useDocumentTitle('Controls · SecureConfigAI');
  const [searchParams, setSearchParams] = useSearchParams();
  const selected = searchParams.get('scan');
  const [inspected, setInspected] = useState<ControlDetail | null>(null);

  const [statusFilter, setStatusFilter] = useState<ControlStatus | ''>('');
  const [category, setCategory] = useState('');
  const [severity, setSeverity] = useState('');
  const [search, setSearch] = useState('');

  // Bounded lookup of the newest completed scan, used when no scan is chosen.
  const recent = useRecentScans(5, 'completed');
  const fallbackScan = pickNewest(recent.data?.items, ['completed']);
  const scanId = selected ?? fallbackScan?.id ?? null;

  const results = useQuery({
    queryKey: queryKeys.scans.results(scanId ?? 'none'),
    enabled: scanId !== null,
    staleTime: 30_000,
    queryFn: () => {
      if (!scanId) throw new Error('No scan selected.');
      return getScanResults(scanId);
    },
  });

  const assessment = results.data?.results;
  const controls = useMemo(() => assessment?.controls ?? [], [assessment]);

  const tally = useMemo(() => {
    const counts: Record<ControlStatus, number> = {
      compliant: 0,
      non_compliant: 0,
      not_applicable: 0,
      unknown: 0,
      error: 0,
    };
    for (const control of controls) {
      if (control.status in counts) counts[control.status] += 1;
    }
    return counts;
  }, [controls]);

  const categories = useMemo(() => {
    const unique = new Set<string>();
    for (const control of controls) if (control.category) unique.add(control.category);
    return Array.from(unique).sort((left, right) => left.localeCompare(right));
  }, [controls]);

  const severities = useMemo(() => {
    const unique = new Set<string>();
    for (const control of controls) if (control.severity) unique.add(String(control.severity));
    return Array.from(unique).sort((left, right) => left.localeCompare(right));
  }, [controls]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return controls.filter((control) => {
      if (statusFilter && control.status !== statusFilter) return false;
      if (category && control.category !== category) return false;
      if (severity && String(control.severity) !== severity) return false;
      if (needle) {
        const haystack = `${control.control_id} ${control.title} ${control.category}`.toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
  }, [controls, statusFilter, category, severity, search]);

  const hasFilters = statusFilter !== '' || category !== '' || severity !== '' || search.trim() !== '';

  return (
    <div className="page">
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
            onChange={(next) => {
              const params = new URLSearchParams(searchParams);
              if (next) params.set('scan', next);
              else params.delete('scan');
              setSearchParams(params, { replace: true });
            }}
            status={undefined}
            placeholder="Newest completed scan"
          />
        </div>
      </div>

      {recent.isError && scanId === null ? (
        <ErrorState error={recent.error} onRetry={() => void recent.refetch()} scope="Scan lookup" />
      ) : null}

      {scanId === null && !recent.isLoading ? (
        <EmptyState
          title="No completed assessment to inspect"
          description="Control verdicts come from a completed scan. Run one from the Overview or Scans page, then return here."
          action={
            <Link className="button button-primary" to="/scans">
              Go to scans
            </Link>
          }
        />
      ) : null}

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

      {assessment ? (
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

          <section className="panel">
            <div className="panel-head">
              <div>
                <h2>Verdict tally</h2>
                <p>
                  Every frozen control state is counted separately. Unknown and error are not passes
                  and not failures — they are gaps in the assessment.
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
                value={controls.filter((control) => control.exempted).length}
                note="Excluded from scoring with a recorded reason"
              />
              <MetricCard
                label="Showing"
                value={`${filtered.length}`}
                note={hasFilters ? 'Filtered subset' : 'All controls in this assessment'}
              />
            </MetricGrid>
          </section>

          <section className="panel">
            <div className="panel-head">
              <div>
                <h2>Control verdicts</h2>
                <p>Sortable columns; open a control for rationale, states, references and remediation.</p>
              </div>
            </div>

            <div className="filter-grid">
              <label className="field">
                <span className="field-label">State</span>
                <select
                  value={statusFilter}
                  onChange={(event) => setStatusFilter(event.target.value as ControlStatus | '')}
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
                <select value={category} onChange={(event) => setCategory(event.target.value)}>
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
                <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
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
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Control ID or title"
                />
              </label>
            </div>

            {hasFilters ? (
              <div className="filter-summary">
                <span>
                  Showing {filtered.length} of {controls.length} controls
                </span>
                <button
                  type="button"
                  className="text-button"
                  onClick={() => {
                    setStatusFilter('');
                    setCategory('');
                    setSeverity('');
                    setSearch('');
                  }}
                >
                  Clear filters
                </button>
              </div>
            ) : null}

            {hasFilters && filtered.length > 0 ? (
              <div className="tally-inline">
                {CONTROL_STATUSES.map((status) => {
                  const count = filtered.filter((control) => control.status === status).length;
                  if (count === 0) return null;
                  return (
                    <span className="tally-inline-item" key={status}>
                      <ControlStatusBadge status={status} /> <strong>{count}</strong>
                    </span>
                  );
                })}
              </div>
            ) : null}

            <ControlTable
              controls={filtered}
              onInspect={setInspected}
              emptyTitle={hasFilters ? 'No controls match these filters' : 'No controls evaluated'}
              emptyDescription={
                hasFilters
                  ? 'Clear the filters to see the full set of verdicts.'
                  : 'The assessment returned no control verdicts.'
              }
            />
          </section>
        </>
      ) : null}

      <ControlDrawer detail={inspected} onClose={() => setInspected(null)} />
    </div>
  );
}
