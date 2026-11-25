/**
 * Overview.
 *
 * Composed from two bounded requests: the newest few scans (one page, `limit=5`)
 * and the results of the newest completed one. Nothing loads the whole scan
 * history, and a running scan is never awaited. The global tracker owns that.
 */

import { useState, type ReactNode } from 'react';
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

/* ---------- Types derived from the API, so no unseen type names are needed ---------- */

type Assessment = NonNullable<Awaited<ReturnType<typeof getScanResults>>['results']>;
type CategoryRollup = Assessment['categories'][number];

type ControlStatus = 'compliant' | 'non_compliant' | 'unknown' | 'error' | 'not_applicable';
type ControlTally = Record<ControlStatus, number>;
type ScoreTone = 'ok' | 'warn' | 'risk' | 'unknown';
type StatusTone = 'assessed' | 'unknown' | 'neutral';

/* ---------- Constants ---------- */

const RECENT_LIMIT = 5;
const RESULTS_STALE_MS = 30_000;
const CONTROL_STATUSES: readonly ControlStatus[] = [
  'compliant',
  'non_compliant',
  'unknown',
  'error',
  'not_applicable',
];
const INCOMPLETE_STATUS = /incomplete|unknown|error|partial|not[_ ]assessed/;
const ASSESSED_STATUS = /assessed|complete/;

/* ---------- Pure helpers ---------- */

function isControlStatus(value: string): value is ControlStatus {
  return (CONTROL_STATUSES as readonly string[]).includes(value);
}

/** Unrecognised statuses are ignored, never counted as a pass or a fail. */
function tallyControls(controls: readonly { status: string }[]): ControlTally {
  const tally: ControlTally = {
    compliant: 0,
    non_compliant: 0,
    unknown: 0,
    error: 0,
    not_applicable: 0,
  };
  for (const control of controls) {
    if (isControlStatus(control.status)) tally[control.status] += 1;
  }
  return tally;
}

function categoryLabel(category: { category?: string | null; label?: string | null }, index: number) {
  return category.category ?? category.label ?? `Category ${index + 1}`;
}

function categoryStatusTone(status: string | null | undefined): StatusTone {
  const normalized = (status ?? '').toLowerCase();
  if (INCOMPLETE_STATUS.test(normalized)) return 'unknown';
  if (ASSESSED_STATUS.test(normalized)) return 'assessed';
  return 'neutral';
}

function categoryScoreTone(score: number | null, incomplete: boolean): ScoreTone {
  if (score === null || incomplete) return 'unknown';
  if (score >= 85) return 'ok';
  if (score >= 60) return 'warn';
  return 'risk';
}

/* ---------- Page ---------- */

export default function OverviewPage() {
  useDocumentTitle('Overview · SecureConfigAI');

  const { startScan, isStarting } = useScanTracker();
  const [explained, setExplained] = useState<Finding | null>(null);

  const recent = useRecentScans(RECENT_LIMIT);
  const newestCompleted = pickNewest(recent.data?.items, ['completed']);
  const completedId = newestCompleted?.id;

  const results = useQuery({
    queryKey: queryKeys.scans.results(completedId ?? 'none'),
    enabled: Boolean(completedId),
    staleTime: RESULTS_STALE_MS,
    queryFn: () => {
      if (!completedId) throw new Error('No completed scan to load.');
      return getScanResults(completedId);
    },
  });

  const assessment = results.data?.results;
  const recentReady = !recent.isLoading && !recent.isError;
  const runButton = (label?: string) => (
    <RunAssessmentButton onStart={startScan} busy={isStarting} label={label} />
  );

  return (
    <div className="page">
      <PageIntro action={runButton()} />

      {recent.isError ? (
        <ErrorState error={recent.error} onRetry={() => void recent.refetch()} scope="Scan history" />
      ) : null}

      {recent.isLoading ? <LoadingState label="Loading recent scans…" rows={3} /> : null}

      {recentReady && recent.data?.items.length === 0 ? (
        <EmptyState
          title="No assessments yet"
          description="Queue a scan to collect endpoint evidence. The scan runs in the background and its progress stays visible at the top of every page."
          action={runButton('Start the first scan')}
        />
      ) : null}

      {recentReady && recent.data && recent.data.items.length > 0 && !newestCompleted ? (
        <Notice tone="warning" title="No completed assessment">
          Scans exist but none has completed yet. Scores are only shown for a completed assessment —
          queued, running, failed and cancelled scans produce no posture.
        </Notice>
      ) : null}

      {newestCompleted ? (
        <>
          {results.isLoading ? <LoadingState label="Loading assessment results…" rows={2} /> : null}

          {results.isError ? (
            <ErrorState
              error={results.error}
              onRetry={() => void results.refetch()}
              scope="Assessment results"
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

              <AssessmentSource scan={newestCompleted} hostname={results.data?.device?.hostname} />

              <section className="section-grid">
                <CategoryPosture scanId={newestCompleted.id} categories={assessment.categories} />
                <ControlEvidence
                  scanId={newestCompleted.id}
                  tally={tallyControls(assessment.controls)}
                />
              </section>

              <PriorityFindings
                scanId={newestCompleted.id}
                findings={results.data?.findings ?? []}
                onExplain={setExplained}
              />
            </>
          ) : null}
        </>
      ) : null}

      {recent.data && recent.data.items.length > 0 ? <LatestScans scans={recent.data.items} /> : null}

      <FindingAiDrawer finding={explained} onClose={() => setExplained(null)} />
    </div>
  );
}

/* ---------- Sections ---------- */

function PageIntro({ action }: { action: ReactNode }) {
  return (
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
        {action}
      </div>
    </div>
  );
}

function RunAssessmentButton({
  onStart,
  busy,
  label = 'Run assessment',
}: {
  onStart: () => Promise<unknown> | void;
  busy: boolean;
  label?: string;
}) {
  return (
    <button
      type="button"
      className="button button-primary"
      onClick={() => void onStart()}
      disabled={busy}
    >
      {busy ? 'Queueing…' : label}
    </button>
  );
}

function AssessmentSource({
  scan,
  hostname,
}: {
  scan: ScanSummary;
  hostname: string | null | undefined;
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Assessment source</h2>
          <p>Every number above is traceable to this scan and its stored evidence.</p>
        </div>
        <Link className="text-button" to={`/scans/${scan.id}`}>
          Open scan detail
        </Link>
      </div>
      <MetricGrid columns={4}>
        <MetricCard
          label="Host"
          value={hostname ?? scan.hostname ?? 'Unknown host'}
          note={scan.device_id ? `Device ${scan.device_id}` : 'No device linked'}
        />
        <MetricCard
          label="Completed"
          value={formatDateTime(scan.completed_at)}
          note={`Duration ${formatDurationMs(scan.duration_ms)}`}
        />
        <MetricCard
          label="Scanner version"
          value={scan.scanner_version ?? 'Unknown'}
          note={`Source: ${scan.source || 'not recorded'}`}
        />
        <MetricCard
          label="Baseline / scoring"
          value={scan.baseline_version ?? 'Unknown baseline'}
          note={`Scoring model ${scan.scoring_model_version ?? 'not recorded'}`}
        />
      </MetricGrid>
    </section>
  );
}

function CategoryPosture({
  scanId,
  categories,
}: {
  scanId: string;
  categories: readonly CategoryRollup[];
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Category posture</h2>
          <p>Weighted control results grouped by baseline category.</p>
        </div>
        <Link className="text-button" to={`/controls?scan=${scanId}`}>
          All controls
        </Link>
      </div>

      {categories.length === 0 ? (
        <EmptyState
          title="No category rollup"
          description="This assessment did not return per-category scores."
          compact
        />
      ) : (
        <div className="category-list">
          {categories.map((category, index) => (
            <CategoryRow
              key={`${categoryLabel(category, index)}-${index}`}
              category={category}
              index={index}
            />
          ))}
        </div>
      )}
    </section>
  );
}

function CategoryRow({ category, index }: { category: CategoryRollup; index: number }) {
  const label = categoryLabel(category, index);
  const statusTone = categoryStatusTone(category.status);
  const scoreTone = categoryScoreTone(category.score, statusTone === 'unknown');

  return (
    <div className="category-row">
      <div className="category-row-head">
        <strong>{label}</strong>
        <span className={`category-status category-status-${statusTone}`}>
          {category.count} controls <span aria-hidden="true">·</span>{' '}
          {category.status || 'status unknown'}
        </span>
      </div>
      <ScoreBlock score={category.score} label={`${label} score`} tone={scoreTone} />
    </div>
  );
}

function ControlEvidence({ scanId, tally }: { scanId: string; tally: ControlTally }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Control evidence state</h2>
          <p>Counts come from stored control results; unknown and error are not treated as passes.</p>
        </div>
        <Link className="text-button" to={`/controls?scan=${scanId}`}>
          Review controls
        </Link>
      </div>
      <MetricGrid columns={2}>
        <MetricCard label="Compliant controls" value={tally.compliant} tone="ok" />
        <MetricCard label="Non-compliant controls" value={tally.non_compliant} tone="risk" />
        <MetricCard
          label="Unknown evidence"
          value={tally.unknown}
          tone="warn"
          note="Could not determine a verdict"
        />
        <MetricCard
          label="Collection / evaluation errors"
          value={tally.error}
          tone="risk"
          note="Inspect collector status and evidence"
        />
      </MetricGrid>
      <p className="muted">
        Not applicable: {tally.not_applicable} control(s). These are excluded from applicable scoring.
      </p>
    </section>
  );
}

function PriorityFindings({
  scanId,
  findings,
  onExplain,
}: {
  scanId: string;
  findings: Finding[];
  onExplain: (finding: Finding) => void;
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Priority findings</h2>
          <p>The first findings as recorded by the engine, unedited by the UI.</p>
        </div>
        <Link className="text-button" to={`/scans/${scanId}`}>
          All findings
        </Link>
      </div>
      <FindingTable
        findings={findings}
        onExplain={onExplain}
        pageSize={5}
        emptyTitle="No findings in this assessment"
        emptyDescription="A clean assessment records no findings. Confirm coverage before treating it as conclusive."
      />
    </section>
  );
}

function LatestScans({ scans }: { scans: ScanSummary[] }) {
  return (
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
      <DataTable
        columns={RECENT_SCAN_COLUMNS}
        rows={scans}
        rowKey={(row) => row.id}
        caption="The five most recent scans"
        empty={<EmptyState title="No scans yet" compact />}
      />
    </section>
  );
}

/* ---------- Table columns (module level, built once) ---------- */

const RECENT_SCAN_COLUMNS: Column<ScanSummary>[] = [
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