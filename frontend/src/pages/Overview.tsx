/**
 * Overview.
 *
 * Composed from two bounded requests: the newest few scans (one page, `limit=5`)
 * and the results of the newest completed one. Nothing loads the whole scan
 * history, and a running scan is never awaited — the global tracker owns that.
 */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getScanResults, queryKeys } from '../api';
import { useDocumentTitle } from '../hooks/useAppData';
import { pickNewest, useRecentScans } from '../hooks/useRecentScans';
import { useScanTracker } from '../state/ScanProvider';
import { PostureHeadline, ScoreBlock, countsFrom } from '../components/PosturePanel';
import { MetricCard, MetricGrid } from '../components/MetricCard';
import { ScanStatusBadge } from '../components/Badges';
import { DataTable, type Column } from '../components/DataTable';
import { EmptyState, ErrorState, LoadingState, Notice } from '../components/States';
import { FindingTable } from '../components/FindingTable';
import { FindingAiDrawer } from '../components/FindingAiDrawer';
import { formatDateTime, formatDurationMs, formatPercent, formatScore } from '../lib/format';
import type { Finding, ScanSummary } from '../types';

export default function OverviewPage() {
  useDocumentTitle('Overview · SecureConfigAI');
  const { startScan, isStarting } = useScanTracker();
  const [explained, setExplained] = useState<Finding | null>(null);

  const recent = useRecentScans(5);
  const newestCompleted = pickNewest(recent.data?.items, ['completed']);

  const results = useQuery({
    queryKey: queryKeys.scans.results(newestCompleted?.id ?? 'none'),
    enabled: newestCompleted !== null,
    staleTime: 30_000,
    queryFn: () => {
      if (!newestCompleted) throw new Error('No completed scan to load.');
      return getScanResults(newestCompleted.id);
    },
  });

  const assessment = results.data?.results;
  const controlStates = {
    compliant: assessment?.controls.filter((control) => control.status === 'compliant').length ?? 0,
    nonCompliant: assessment?.controls.filter((control) => control.status === 'non_compliant').length ?? 0,
    unknown: assessment?.controls.filter((control) => control.status === 'unknown').length ?? 0,
    errors: assessment?.controls.filter((control) => control.status === 'error').length ?? 0,
    notApplicable: assessment?.controls.filter((control) => control.status === 'not_applicable').length ?? 0,
  };

  return (
    <div className="page">
      <div className="page-intro">
        <div>
          <span className="eyebrow">Security posture</span>
          <h2>Overview</h2>
          <p>
            Deterministic control results from the most recent completed assessment. Scores are
            computed by the backend and are never recalculated here.
          </p>
        </div>
        <div className="inline-actions">
          <Link className="button button-light" to="/scans">
            Scan history
          </Link>
          <button
            type="button"
            className="button button-primary"
            onClick={() => void startScan()}
            disabled={isStarting}
          >
            {isStarting ? 'Queueing…' : 'Run assessment'}
          </button>
        </div>
      </div>

      {recent.isError ? (
        <ErrorState error={recent.error} onRetry={() => void recent.refetch()} scope="Scan history" />
      ) : null}

      {recent.isLoading ? <LoadingState label="Loading recent scans…" rows={3} /> : null}

      {!recent.isLoading && !recent.isError && recent.data?.items.length === 0 ? (
        <EmptyState
          title="No assessments yet"
          description="Queue a scan to collect endpoint evidence. The scan runs in the background and its progress stays visible at the top of every page."
          action={
            <button
              type="button"
              className="button button-primary"
              onClick={() => void startScan()}
              disabled={isStarting}
            >
              Start the first scan
            </button>
          }
        />
      ) : null}

      {!recent.isLoading && !recent.isError && recent.data && recent.data.items.length > 0 && !newestCompleted ? (
        <Notice tone="warning" title="No completed assessment">
          Scans exist but none has completed yet. Scores are only shown for a completed assessment —
          queued, running, failed and cancelled scans produce no posture.
        </Notice>
      ) : null}

      {newestCompleted ? (
        <>
          {results.isLoading ? (
            <LoadingState label="Loading assessment results…" rows={2} />
          ) : results.isError ? (
            <ErrorState error={results.error} onRetry={() => void results.refetch()} scope="Assessment results" />
          ) : assessment ? (
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
                    <h2>Assessment source</h2>
                    <p>Every number above is traceable to this scan and its stored evidence.</p>
                  </div>
                  <Link className="text-button" to={`/scans/${newestCompleted.id}`}>
                    Open scan detail
                  </Link>
                </div>
                <MetricGrid columns={4}>
                  <MetricCard
                    label="Host"
                    value={results.data?.device?.hostname ?? newestCompleted.hostname ?? 'Unknown host'}
                    note={newestCompleted.device_id ? `Device ${newestCompleted.device_id}` : 'No device linked'}
                  />
                  <MetricCard
                    label="Completed"
                    value={formatDateTime(newestCompleted.completed_at)}
                    note={`Duration ${formatDurationMs(newestCompleted.duration_ms)}`}
                  />
                  <MetricCard
                    label="Scanner version"
                    value={newestCompleted.scanner_version ?? 'Unknown'}
                    note={`Source: ${newestCompleted.source || 'not recorded'}`}
                  />
                  <MetricCard
                    label="Baseline / scoring"
                    value={newestCompleted.baseline_version ?? 'Unknown baseline'}
                    note={`Scoring model ${newestCompleted.scoring_model_version ?? 'not recorded'}`}
                  />
                </MetricGrid>
              </section>

              <section className="section-grid">
                <div className="panel">
                  <div className="panel-head">
                    <div>
                      <h2>Category posture</h2>
                      <p>Weighted control results grouped by baseline category.</p>
                    </div>
                    <Link className="text-button" to={`/controls?scan=${newestCompleted.id}`}>
                      All controls
                    </Link>
                  </div>
                  {assessment.categories.length === 0 ? (
                    <EmptyState
                      title="No category rollup"
                      description="This assessment did not return per-category scores."
                      compact
                    />
                  ) : (
                    <div className="category-list">
                      {assessment.categories.map((category, index) => {
                        const label = category.category ?? category.label ?? `Category ${index + 1}`;
                        const normalizedStatus = (category.status ?? '').toLowerCase();
                        const incomplete = /incomplete|unknown|error|partial|not[_ ]assessed/.test(normalizedStatus);
                        const statusTone = incomplete
                          ? 'unknown'
                          : /assessed|complete/.test(normalizedStatus)
                            ? 'assessed'
                            : 'neutral';
                        const scoreTone = category.score === null || incomplete
                          ? 'unknown'
                          : category.score >= 85
                            ? 'ok'
                            : category.score >= 60
                              ? 'warn'
                              : 'risk';
                        return (
                          <div className="category-row" key={`${label}-${index}`}>
                            <div className="category-row-head">
                              <strong>{label}</strong>
                              <span className={`category-status category-status-${statusTone}`}>
                                {category.count} controls <span aria-hidden="true">·</span> {category.status || 'status unknown'}
                              </span>
                            </div>
                            <ScoreBlock
                              score={category.score}
                              label={`${label} score`}
                              tone={scoreTone}
                            />
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                <div className="panel">
                  <div className="panel-head">
                    <div>
                      <h2>Control evidence state</h2>
                      <p>Counts come from stored control results; unknown and error are not treated as passes.</p>
                    </div>
                    <Link className="text-button" to={`/controls?scan=${newestCompleted.id}`}>
                      Review controls
                    </Link>
                  </div>
                  <MetricGrid columns={2}>
                    <MetricCard label="Compliant controls" value={controlStates.compliant} tone="ok" />
                    <MetricCard label="Non-compliant controls" value={controlStates.nonCompliant} tone="risk" />
                    <MetricCard label="Unknown evidence" value={controlStates.unknown} tone="warn" note="Could not determine a verdict" />
                    <MetricCard label="Collection / evaluation errors" value={controlStates.errors} tone="risk" note="Inspect collector status and evidence" />
                  </MetricGrid>
                  <p className="muted">Not applicable: {controlStates.notApplicable} control(s). These are excluded from applicable scoring.</p>
                </div>
              </section>

              <section className="panel">
                <div className="panel-head">
                  <div>
                    <h2>Priority findings</h2>
                    <p>The first findings as recorded by the engine, unedited by the UI.</p>
                  </div>
                  <Link className="text-button" to={`/scans/${newestCompleted.id}`}>
                    All findings
                  </Link>
                </div>
                <FindingTable
                  findings={results.data?.findings ?? []}
                  onExplain={setExplained}
                  pageSize={5}
                  emptyTitle="No findings in this assessment"
                  emptyDescription="A clean assessment records no findings. Confirm coverage before treating it as conclusive."
                />
              </section>
            </>
          ) : null}
        </>
      ) : null}

      {recent.data && recent.data.items.length > 0 ? (
        <section className="panel">
          <div className="panel-head">
            <div>
              <h2>Latest scans</h2>
              <p>The five most recent scan records. Older history lives on the Scans page.</p>
            </div>
            <Link className="text-button" to="/scans">
              Full history
            </Link>
          </div>
          <RecentScanTable scans={recent.data.items} />
        </section>
      ) : null}

      <FindingAiDrawer finding={explained} onClose={() => setExplained(null)} />
    </div>
  );
}

function RecentScanTable({ scans }: { scans: ScanSummary[] }) {
  const columns: Column<ScanSummary>[] = [
    {
      id: 'scan',
      header: 'Scan',
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
      id: 'started',
      header: 'Started',
      width: '16%',
      cell: (row) => formatDateTime(row.started_at),
    },
    {
      id: 'score',
      header: 'Score',
      align: 'right',
      width: '9%',
      cell: (row) => (row.security_score === null ? '—' : formatScore(row.security_score)),
    },
    {
      id: 'coverage',
      header: 'Coverage',
      align: 'right',
      width: '10%',
      cell: (row) => formatPercent(row.assessment_coverage),
    },
    {
      id: 'findings',
      header: 'Findings',
      align: 'right',
      width: '10%',
      cell: (row) => row.total_findings ?? '—',
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={scans}
      rowKey={(row) => row.id}
      caption="The five most recent scans"
      empty={<EmptyState title="No scans yet" compact />}
    />
  );
}
