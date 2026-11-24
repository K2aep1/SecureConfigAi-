/**
 * Posture block.
 *
 * Requirement 6: `assessment_coverage` and `evidence_quality` are rendered next
 * to posture *always* — never as an optional extra. A missing score renders as
 * "Not assessed", never as `0`, so an unfinished scan cannot look like a failing
 * one (and vice versa).
 */

import clsx from 'clsx';
import { MetricCard, ProgressBar } from './MetricCard';
import { EvidenceQualityBadge, RiskLevelBadge } from './Badges';
import { COVERAGE_EXPLANATION, EVIDENCE_QUALITY_EXPLANATION, riskLevelTone } from '../lib/verdict';
import { clampPercent, formatPercent, formatScore } from '../lib/format';
import type { AssessmentCounts } from '../types';

export interface PostureValues {
  security_score: number | null;
  compliance_score: number | null;
  assessment_coverage: number | null;
  risk_score: number | null;
  risk_level: string | null;
  evidence_quality: string | null;
}

export interface PostureCounts {
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  informational_count?: number;
  total_findings?: number;
  controls_assessed?: number;
  controls_total?: number;
}

/**
 * Headline score with its coverage caveat directly underneath.
 */
export function PostureHeadline({
  values,
  status,
  controls,
}: {
  values: PostureValues;
  /** Scan status; a null score on a running scan reads differently to a failed one. */
  status?: string;
  controls?: PostureCounts;
}) {
  const assessed = values.security_score !== null && values.security_score !== undefined;
  const coverage = values.assessment_coverage;
  const controlsAssessed = controls?.controls_assessed;
  const controlsTotal = controls?.controls_total;

  return (
    <section className="posture" aria-label="Security posture">
      <div className="posture-score">
        <span className="eyebrow">Security posture</span>
        <div className={clsx('posture-number', !assessed && 'posture-number-empty')}>
          {assessed ? (
            <>
              {formatScore(values.security_score)}
              <span className="posture-number-suffix">/100</span>
            </>
          ) : (
            <span className="posture-not-assessed">Not assessed</span>
          )}
        </div>
        {assessed ? (
          <ProgressBar
            value={values.security_score}
            tone="info"
            label="Security score"
            showValue={false}
          />
        ) : null}
        <p className="posture-caption">
          {status === 'running' || status === 'queued'
            ? 'The assessment is still running. Scores become final only when the scan completes.'
            : assessed
              ? 'Weighted deterministic control score from stored endpoint evidence.'
              : 'No completed assessment yet. Run a scan to produce a score.'}
        </p>
      </div>

      <div className="posture-details">
        <div className="posture-grid">
          <MetricCard
            label="Assessment coverage"
            value={formatPercent(coverage)}
            hint={COVERAGE_EXPLANATION}
            note={
              controlsAssessed !== undefined && controlsTotal !== undefined
                ? `${controlsAssessed} of ${controlsTotal} controls decided`
                : 'Share of controls the engine could decide'
            }
            tone={
              coverage === null || coverage === undefined
                ? 'unknown'
                : coverage >= 95
                  ? 'ok'
                  : coverage >= 75
                    ? 'warn'
                    : 'risk'
            }
          />
          <MetricCard
            label="Evidence quality"
            value={<EvidenceQualityBadge quality={values.evidence_quality} />}
            hint={EVIDENCE_QUALITY_EXPLANATION}
            note="Grades how complete the evidence is"
            tone="neutral"
          />
          <MetricCard
            label="Compliance"
            value={formatPercent(values.compliance_score)}
            note="Share of applicable controls that pass"
            tone={
              values.compliance_score === null || values.compliance_score === undefined
                ? 'unknown'
                : 'neutral'
            }
          />
          <MetricCard
            label="Risk"
            value={
              <>
                {formatScore(values.risk_score)}
                <span className="metric-value-sub">
                  <RiskLevelBadge level={values.risk_level} score={values.risk_score} />
                </span>
              </>
            }
            note="Scaled by device criticality"
            tone={riskLevelTone(values.risk_level)}
          />
        </div>

        <div className="posture-counts">
          <CountChip label="Critical" value={controls?.critical_count} tone="risk" />
          <CountChip label="High" value={controls?.high_count} tone="risk" />
          <CountChip label="Medium" value={controls?.medium_count} tone="warn" />
          <CountChip label="Low" value={controls?.low_count} tone="info" />
          <CountChip label="Informational" value={controls?.informational_count} tone="neutral" />
          <CountChip label="Findings" value={controls?.total_findings} tone="neutral" emphasis />
        </div>
      </div>
    </section>
  );
}

function CountChip({
  label,
  value,
  tone,
  emphasis = false,
}: {
  label: string;
  value: number | undefined;
  tone: 'risk' | 'warn' | 'info' | 'neutral';
  emphasis?: boolean;
}) {
  const display = value === undefined ? '—' : value;
  return (
    <span className={clsx('count-chip', `count-chip-${tone}`, emphasis && 'count-chip-emphasis')}>
      <span className="count-chip-value">{display}</span>
      <span className="count-chip-label">{label}</span>
    </span>
  );
}

/** Small score block used in category rollups and comparison rows. */
export function ScoreBlock({
  score,
  label,
  tone = 'info',
}: {
  score: number | null | undefined;
  label: string;
  tone?: 'ok' | 'risk' | 'warn' | 'info' | 'unknown';
}) {
  const known = score !== null && score !== undefined && Number.isFinite(score);
  return (
    <div className="score-block">
      <div className="score-block-head">
        <span className="score-block-label">{label}</span>
        <span className="score-block-value">{known ? `${formatScore(score)}%` : 'N/A'}</span>
      </div>
      <ProgressBar value={known ? clampPercent(score) : null} tone={tone} label={label} />
    </div>
  );
}

/** Convenience adapter so a plain `AssessmentCounts` can feed `PostureHeadline`. */
export function countsFrom(assessment: AssessmentCounts | undefined): PostureCounts {
  if (!assessment) return {};
  return {
    critical_count: assessment.critical_count,
    high_count: assessment.high_count,
    medium_count: assessment.medium_count,
    low_count: assessment.low_count,
    informational_count: assessment.informational_count,
    total_findings: assessment.total_findings,
    controls_assessed: assessment.controls_assessed,
    controls_total: assessment.controls_total,
  };
}
