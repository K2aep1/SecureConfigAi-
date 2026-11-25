/**
 * Scan detail.
 *
 * Three deliberate behaviours:
 *  1. A scan that is still `queued`/`running` is polled here too (1 s → 3 s),
 *     unless the global tracker already owns that scan — the two never poll the
 *     same id twice.
 *  2. `GET /scans/{id}/results` is requested only once the scan is `completed`;
 *     a running or failed scan has no assessment to show.
 *  3. `GET /scans/{id}/document` is requested **only** when the evidence drawer
 *     is opened (requirement 5) — never as part of loading this page.
 */

import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  cancelScan,
  deleteScan,
  getScan,
  getScanDocument,
  getScanResults,
  isApiError,
  queryKeys,
} from '../api';
import { useDocumentTitle, useNow } from '../hooks/useAppData';
import { useScanStatusPoll } from '../hooks/useScanStatusPoll';
import { useOpenReport } from '../hooks/useOpenReport';
import { useScanTracker } from '../state/ScanProvider';
import { PostureHeadline, countsFrom } from '../components/PosturePanel';
import { MetricCard, MetricGrid, ProgressBar } from '../components/MetricCard';
import { ScanStatusBadge, EvidenceQualityBadge } from '../components/Badges';
import { ControlTable } from '../components/ControlTable';
import { ControlDrawer, type ControlDetail } from '../components/ControlDrawer';
import { FindingTable } from '../components/FindingTable';
import { FindingAiDrawer } from '../components/FindingAiDrawer';
import { Drawer } from '../components/Drawer';
import { JsonFacts } from '../components/JsonFacts';
import { EmptyState, ErrorState, LoadingState, Notice } from '../components/States';
import { useConfirm } from '../components/ConfirmDialog';
import { useToast } from '../components/Toast';
import { errorToastMessage } from '../lib/errors';
import {
  formatDateTime,
  formatDurationMs,
  formatElapsed,
  formatJsonValue,
  formatPercent,
  isTerminalScanStatus,
} from '../lib/format';
import type { Finding } from '../types';

export default function ScanDetailPage() {
  const { id = '' } = useParams<{ id: string }>();
  useDocumentTitle(`Scan ${id.slice(0, 8)} · SecureConfigAI`);

  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const { openReport, isPending } = useOpenReport();
  const { tracked, cancelTrackedScan, isCancelling } = useScanTracker();

  const [explained, setExplained] = useState<Finding | null>(null);
  const [inspected, setInspected] = useState<ControlDetail | null>(null);
  const [evidenceOpen, setEvidenceOpen] = useState(false);

  useEffect(() => {
    setEvidenceOpen(false);
  }, [id]);

  const detail = useQuery({
    queryKey: queryKeys.scans.detail(id),
    enabled: Boolean(id),
    staleTime: 5_000,
    queryFn: ({ signal }) => getScan(id, signal),
  });

  const scan = detail.data;
  const trackedHere = tracked?.scanId === id;
  // Keep the fallback stable for queued scans that do not have started_at yet.
  const [fallbackStartedAtMs] = useState(() => Date.now());
  const hasStartedAt = Boolean(scan?.started_at);
  const startedAtMs = hasStartedAt
    ? new Date(scan!.started_at!).getTime()
    : fallbackStartedAtMs;
  const looksActive = scan?.status === 'queued' || scan?.status === 'running';

  // Only poll locally when the tracker is not already polling this exact scan.
  const poll = useScanStatusPoll({
    scanId: id,
    enabled: Boolean(scan) && looksActive && !trackedHere,
    startedAtMs,
  });

  const effectiveStatus = trackedHere ? tracked.status : (poll.data?.status ?? scan?.status);
  const effectiveStage = trackedHere ? tracked.stage : (poll.data?.stage ?? scan?.stage ?? '');
  const effectiveProgress = trackedHere
    ? tracked.progress
    : (poll.data?.progress ?? scan?.progress ?? 0);
  const effectiveError = trackedHere
    ? tracked.errorMessage
    : (poll.data?.error_message ?? scan?.error_message ?? null);

  const active = Boolean(effectiveStatus) && !isTerminalScanStatus(effectiveStatus);
  // Drives the live elapsed clock while this scan is still running.
  const now = useNow(1000, active);

  // When a locally-polled scan reaches a terminal status, refresh the summary.
  const polledStatus = poll.data?.status;
  const { refetch: refetchDetail } = detail;
  useEffect(() => {
    if (polledStatus && isTerminalScanStatus(polledStatus)) void refetchDetail();
  }, [polledStatus, refetchDetail]);

  const results = useQuery({
    queryKey: queryKeys.scans.results(id),
    enabled: Boolean(id) && effectiveStatus === 'completed',
    staleTime: 60_000,
    queryFn: () => getScanResults(id),
  });

  // Evidence is fetched on demand only.
  const evidence = useQuery({
    queryKey: queryKeys.scans.document(id),
    enabled: evidenceOpen && Boolean(id),
    staleTime: 5 * 60 * 1000,
    retry: 1,
    queryFn: ({ signal }) => getScanDocument(id, signal),
  });

  async function onCancel() {
    if (trackedHere) {
      await cancelTrackedScan();
      return;
    }
    try {
      await cancelScan(id);
      toast.push({
        tone: 'info',
        title: 'Cancellation requested',
        message: 'This view keeps polling until the scan reports a terminal status.',
      });
      void poll.refetch();
    } catch (error) {
      toast.push({
        tone: 'error',
        title: 'Could not cancel the scan',
        message: errorToastMessage(error),
      });
    }
  }

  async function onDelete() {
    const confirmed = await confirm({
      title: 'Delete this scan?',
      message: (
        <>
          The scan record and its stored artefacts are deleted. This cannot be undone, and any report
          link to this scan stops working.
        </>
      ),
      confirmLabel: 'Delete scan',
      destructive: true,
    });
    if (!confirmed) return;
    try {
      await deleteScan(id);
      toast.push({ tone: 'success', title: 'Scan deleted' });
      await queryClient.invalidateQueries({ queryKey: queryKeys.scans.all });
      navigate('/scans', { replace: true });
    } catch (error) {
      toast.push({
        tone: 'error',
        title: 'Could not delete the scan',
        message: errorToastMessage(error),
      });
    }
  }

  if (!id) return <EmptyState title="No scan selected" />;

  if (detail.isLoading) return <LoadingState label="Loading scan…" rows={3} />;

  if (detail.isError) {
    const notFound = isApiError(detail.error) && detail.error.isNotFound;
    if (notFound) {
      return (
        <div className="page">
          <EmptyState
            title="This scan no longer exists"
            description="It may have been deleted, or the link may be stale."
            action={
              <Link className="button button-light" to="/scans">
                Back to scan history
              </Link>
            }
          />
        </div>
      );
    }

    return (
      <div className="page">
        <ErrorState
          error={detail.error}
          onRetry={() => void refetchDetail()}
          scope="Scan"
        />
      </div>
    );
  }

  const assessment = results.data?.results;

  return (
    <div className="page">
      <div className="page-intro">
        <div>
          <span className="eyebrow">Scan detail</span>
          <h2>{scan?.hostname ?? results.data?.device?.hostname ?? 'Endpoint assessment'}</h2>
          <p className="mono">{id}</p>
        </div>
        <div className="inline-actions">
          <Link className="button button-light" to="/scans">
            All scans
          </Link>
          <button
            type="button"
            className="button button-light"
            onClick={() => setEvidenceOpen(true)}
          >
            Open evidence
          </button>
          <button
            type="button"
            className="button button-light"
            onClick={() => void openReport(id, 'html')}
            disabled={effectiveStatus !== 'completed' || isPending(id, 'html')}
          >
            {isPending(id, 'html') ? 'Opening…' : 'HTML report'}
          </button>
          <button
            type="button"
            className="button button-primary"
            onClick={() => void openReport(id, 'pdf')}
            disabled={effectiveStatus !== 'completed' || isPending(id, 'pdf')}
          >
            {isPending(id, 'pdf') ? 'Opening…' : 'PDF report'}
          </button>
          <button type="button" className="text-button danger-text" onClick={() => void onDelete()}>
            Delete scan
          </button>
        </div>
      </div>

      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>Status</h2>
            <p>
              Reported by <code>GET /scans/{'{id}'}/status</code>
              {active ? ' — polled every 1 s, backing off to 3 s after 30 s.' : ' (terminal).'}
            </p>
          </div>
          <ScanStatusBadge status={effectiveStatus ?? 'unknown'} />
        </div>

        {active ? (
          <div className="scan-live">
            <ProgressBar value={effectiveProgress} tone="info" label="Scan progress" showValue />
            <p className="scan-live-stage">
              <strong>{effectiveStage || 'Working…'}</strong>
              {hasStartedAt ? (
                <span className="muted"> · elapsed {formatElapsed(now - startedAtMs)}</span>
              ) : null}
            </p>
            <div className="inline-actions">
              <button
                type="button"
                className="button button-light"
                onClick={() => void onCancel()}
                disabled={trackedHere && (isCancelling || tracked?.cancelRequested === true)}
              >
                {trackedHere && isCancelling ? 'Requesting…' : 'Cancel scan'}
              </button>
            </div>
            <p className="scan-panel-note">
              Collection can take several minutes. The stage text and progress come from the scanner,
              so slow progress means real work is still running.
            </p>
          </div>
        ) : null}

        {effectiveError && effectiveStatus !== 'failed' ? (
          <Notice tone="error" title="Scanner error">
            {effectiveError}
          </Notice>
        ) : null}

        {effectiveStatus === 'failed' ? (
          <Notice tone="error" title="Scan failed">
            {effectiveError ?? 'The scanner reported a failure. No assessment results or reports were produced.'}
          </Notice>
        ) : null}

        {/* `scanner_error` reports a limitation the assessment survived. */}
        {results.data?.scanner_error ? (
          <Notice tone="warning" title="Collection reported a limitation">
            {results.data.scanner_error}
          </Notice>
        ) : null}

        <MetricGrid columns={4}>
          <MetricCard label="Started" value={formatDateTime(scan?.started_at)} />
          <MetricCard label="Completed" value={formatDateTime(scan?.completed_at)} />
          <MetricCard label="Duration" value={formatDurationMs(scan?.duration_ms)} />
          <MetricCard label="Source" value={scan?.source ?? '—'} note={scan?.stage} />
          <MetricCard
            label="Scanner version"
            value={scan?.scanner_version ?? '—'}
            hint="Version of the collector that produced the evidence."
          />
          <MetricCard
            label="Scoring model"
            value={scan?.scoring_model_version ?? '—'}
            hint="Scoring model version used for this scan's numbers — stored per scan so old scores stay reproducible."
          />
          <MetricCard
            label="Baseline version"
            value={scan?.baseline_version ?? '—'}
            hint="Baseline pack version the controls were evaluated against."
          />
          <MetricCard
            label="Coverage"
            value={formatPercent(scan?.assessment_coverage)}
            hint="Share of controls the engine could decide; unknown and error controls lower it."
          />
          <MetricCard
            label="Evidence quality"
            value={<EvidenceQualityBadge quality={scan?.evidence_quality ?? null} />}
          />
        </MetricGrid>
      </section>

      {effectiveStatus === 'cancelled' ? (
        <EmptyState
          title="This scan was cancelled"
          description="Cancellation is terminal: no results or reports were produced for this scan."
        />
      ) : null}

      {active ? (
        <EmptyState
          title="Results are not available yet"
          description="Scores and control verdicts appear here as soon as the scan reaches a terminal status. The progress panel stays visible across the dashboard."
        />
      ) : null}

      {effectiveStatus === 'completed' ? (
        <>
          {results.isLoading ? <LoadingState label="Loading assessment results…" rows={3} /> : null}
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
                status={effectiveStatus}
                controls={countsFrom(assessment)}
              />

              <section className="panel">
                <div className="panel-head">
                  <div>
                    <h2>Controls</h2>
                    <p>
                      {assessment.controls.length} control verdicts, revealed in pages of 25. Open a row
                      for its rationale, expected state, standard references and remediation.
                    </p>
                  </div>
                </div>
                <ControlTable
                  controls={assessment.controls}
                  onInspect={setInspected}
                  emptyTitle="No controls in this assessment"
                  emptyDescription="The results payload contained no control verdicts."
                />
              </section>

              <section className="panel">
                <div className="panel-head">
                  <div>
                    <h2>Findings</h2>
                    <p>
                      Findings recorded by the engine. &ldquo;Explain&rdquo; requests advisory AI
                      commentary, which cannot change any score.
                    </p>
                  </div>
                </div>
                <FindingTable
                  findings={results.data?.findings ?? []}
                  onExplain={setExplained}
                  emptyTitle="No findings recorded"
                  emptyDescription="Confirm assessment coverage before reading an empty finding list as a clean bill of health."
                />
              </section>
            </>
          ) : null}
        </>
      ) : null}

      <ControlDrawer detail={inspected} onClose={() => setInspected(null)} />
      <FindingAiDrawer finding={explained} onClose={() => setExplained(null)} />

      <Drawer
        open={evidenceOpen}
        onClose={() => setEvidenceOpen(false)}
        width="wide"
        title="Stored evidence"
        subtitle={
          <span className="drawer-subtitle-row">
            <code>{id}</code>
            <span><code>GET /scans/{'{id}'}/document</code> — requested only because you opened this panel</span>
          </span>
        }
      >
        {evidence.isLoading ? <LoadingState label="Loading stored evidence…" rows={3} /> : null}
        {evidence.isError ? (
          <ErrorState
            error={evidence.error}
            onRetry={() => void evidence.refetch()}
            scope="Stored evidence"
          />
        ) : null}
        {evidence.data ? (
          <div className="drawer-sections">
            <Notice tone="info" title="Raw stored evidence">
              This is the normalised document the assessment was computed from. It is shown verbatim —
              the dashboard never rewrites evidence.
            </Notice>
            <section className="drawer-section">
              <h3 className="drawer-section-title">Document metadata</h3>
              <MetricGrid columns={2}>
                <MetricCard label="Schema version" value={evidence.data.schema_version ?? '—'} />
                <MetricCard label="Scan" value={evidence.data.scan_id} />
                <MetricCard
                  label="Baseline version"
                  value={evidence.data.baseline_version ?? '—'}
                />
                <MetricCard
                  label="Scoring model"
                  value={evidence.data.scoring_model_version ?? '—'}
                />
              </MetricGrid>
            </section>
            <section className="drawer-section">
              <h3 className="drawer-section-title">Normalised data</h3>
              <JsonFacts data={evidence.data.normalized_data} emptyLabel="The document contains no normalised data." />
              <details className="drawer-disclosure">
                <summary>Full JSON document</summary>
                <pre className="json-block">{formatJsonValue(evidence.data.normalized_data)}</pre>
              </details>
            </section>
          </div>
        ) : null}
      </Drawer>
    </div>
  );
}
