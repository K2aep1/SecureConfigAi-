/**
 * Advisory drawer for a single finding.
 *
 * Opens AI explanation output (`POST /ai/findings/{id}/explain`) and can request
 * a recommendation (`POST /ai/findings/{id}/recommend`). The drawer states
 * plainly that the output is advisory and cannot change a score — and it repeats
 * the recorded values next to the prose so the two are never confused.
 */

import { useMutation, useQuery } from '@tanstack/react-query';
import { Drawer } from './Drawer';
import { EmptyState, ErrorState, LoadingState, Notice } from './States';
import { SeverityBadge, ControlStatusBadge } from './Badges';
import { DetailList, DetailRow } from './MetricCard';
import { explainFinding, queryKeys, recommendForFinding } from '../api';
import { errorToastMessage } from '../lib/errors';
import { formatJsonValue } from '../lib/format';
import { useToast } from './Toast';
import type { Finding } from '../types';

export const AI_ADVISORY_NOTICE =
  'AI output is advisory commentary generated from the stored evidence. It is not a control verdict, it cannot change scores, coverage or risk, and it is not a substitute for the deterministic result shown above it.';

export function FindingAiDrawer({
  finding,
  onClose,
}: {
  finding: Finding | null;
  onClose: () => void;
}) {
  const toast = useToast();

  const explanation = useQuery({
    queryKey: queryKeys.ai.explain(finding?.id ?? 'none'),
    enabled: finding !== null,
    staleTime: 5 * 60 * 1000,
    retry: 1,
    queryFn: () => {
      if (!finding) throw new Error('No finding selected.');
      return explainFinding(finding.id);
    },
  });

  const recommendation = useMutation({
    mutationFn: (findingId: string) => recommendForFinding(findingId),
    onError: (error) => {
      toast.push({
        tone: 'error',
        title: 'Recommendation unavailable',
        message: errorToastMessage(error),
      });
    },
  });

  return (
    <Drawer
      open={finding !== null}
      onClose={() => {
        recommendation.reset();
        onClose();
      }}
      width="wide"
      title={finding?.title ?? 'Finding'}
      subtitle={
        finding ? (
          <span className="drawer-subtitle-row">
            <code>{finding.control_id ?? 'no control'}</code>
            <SeverityBadge severity={finding.severity} />
            <ControlStatusBadge status={finding.status} />
            <span>{finding.category}</span>
          </span>
        ) : null
      }
      footer={
        finding ? (
          <div className="inline-actions inline-actions-end">
            <button
              type="button"
              className="button button-light"
              onClick={() => recommendation.mutate(finding.id)}
              disabled={recommendation.isPending}
            >
              {recommendation.isPending ? 'Requesting…' : 'Request AI recommendation'}
            </button>
          </div>
        ) : null
      }
    >
      {finding ? (
        <div className="drawer-sections">
          <Notice tone="info" title="Advisory only">
            {AI_ADVISORY_NOTICE}
          </Notice>

          <section className="drawer-section">
            <h3 className="drawer-section-title">Recorded result (authoritative)</h3>
            <DetailList>
              <DetailRow label="Description" value={finding.description ?? '—'} />
              <DetailRow
                label="Observed value"
                value={<code className="inline-code">{formatJsonValue(finding.current_value)}</code>}
              />
              <DetailRow
                label="Expected value"
                value={<code className="inline-code">{formatJsonValue(finding.expected_value)}</code>}
              />
              <DetailRow label="Priority" value={finding.recommendation?.priority ?? '—'} />
              <DetailRow
                label="Remediation type"
                value={finding.recommendation?.remediation_type ?? '—'}
              />
            </DetailList>
            <p className="drawer-text">
              <strong>What is wrong. </strong>
              {finding.recommendation?.what_is_wrong ?? '—'}
            </p>
            <p className="drawer-text">
              <strong>Why it matters. </strong>
              {finding.recommendation?.why_it_matters ?? '—'}
            </p>
            <p className="drawer-text">
              <strong>What should be done. </strong>
              {finding.recommendation?.what_should_be_done ?? '—'}
            </p>
          </section>

          <section className="drawer-section">
            <h3 className="drawer-section-title">AI explanation (advisory)</h3>
            {explanation.isLoading ? <LoadingState label="Requesting explanation…" rows={2} /> : null}
            {explanation.isError ? (
              <ErrorState
                error={explanation.error}
                onRetry={() => void explanation.refetch()}
                scope="Explanation"
              />
            ) : null}
            {explanation.data ? (
              <>
                <p className="drawer-text ai-text">{explanation.data.explanation}</p>
                <p className="drawer-text drawer-text-subtle">
                  Model {explanation.data.model_used}
                  {explanation.data.cached ? ' · served from cache' : ''}
                </p>
              </>
            ) : null}
          </section>

          {recommendation.data ? (
            <section className="drawer-section">
              <h3 className="drawer-section-title">AI recommendation (advisory)</h3>
              <DetailList>
                <DetailRow label="Priority" value={recommendation.data.priority} />
                <DetailRow
                  label="What is wrong"
                  value={recommendation.data.recommendation.what_is_wrong}
                />
                <DetailRow
                  label="Why it matters"
                  value={recommendation.data.recommendation.why_it_matters}
                />
                <DetailRow
                  label="What should be done"
                  value={recommendation.data.recommendation.what_should_be_done}
                />
              </DetailList>
              <p className="drawer-text drawer-text-subtle">
                Model {recommendation.data.model_used}
                {recommendation.data.cached ? ' · served from cache' : ''}
              </p>
            </section>
          ) : null}

          {!explanation.isLoading && !explanation.data && !explanation.isError ? (
            <EmptyState
              title="No explanation requested"
              description="Open this drawer to request advisory commentary for the finding."
              compact
            />
          ) : null}
        </div>
      ) : null}
    </Drawer>
  );
}
