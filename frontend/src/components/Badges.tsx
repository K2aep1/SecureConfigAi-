/**
 * Badges.
 *
 * Verdict badges (control states, scan statuses) always carry the full
 * explanation in `title` and `aria-label`, and use a distinct tone + glyph per
 * state. `unknown` and `error` never share a tone with `compliant` or
 * `non_compliant` (requirement 6).
 */

import clsx from 'clsx';
import {
  controlVerdict,
  evidenceQualityTone,
  outcomeTone,
  policyLayerTone,
  riskLevelTone,
  scanVerdict,
  severityTone,
  type Tone,
  type Verdict,
} from '../lib/verdict';
import { humanize } from '../lib/format';
import type { ControlStatus, ScanStatus } from '../types';

function VerdictBadge({ verdict, className }: { verdict: Verdict; className?: string }) {
  return (
    <span
      className={clsx('badge', `badge-${verdict.tone}`, 'badge-verdict', className)}
      title={verdict.description}
      aria-label={`${verdict.label}. ${verdict.description}`}
    >
      <span className="badge-glyph" aria-hidden="true">
        {verdict.glyph}
      </span>
      <span className="badge-label">{verdict.label}</span>
    </span>
  );
}

/** Control verdict — the honest five-state vocabulary. */
export function ControlStatusBadge({
  status,
  exempted = false,
  className,
}: {
  status: ControlStatus | string;
  exempted?: boolean;
  className?: string;
}) {
  const verdict = controlVerdict(status);
  if (exempted) {
    return (
      <span
        className={clsx('badge', 'badge-na', 'badge-verdict', className)}
        title="An exemption is recorded for this control on this device; it is excluded from scoring."
        aria-label="Exempted. An exemption is recorded for this control on this device; it is excluded from scoring."
      >
        <span className="badge-glyph" aria-hidden="true">
          –
        </span>
        <span className="badge-label">Exempt</span>
      </span>
    );
  }
  return <VerdictBadge verdict={verdict} className={className} />;
}

/** Scan lifecycle status. */
export function ScanStatusBadge({
  status,
  className,
}: {
  status: ScanStatus | 'cancelling' | string;
  className?: string;
}) {
  return <VerdictBadge verdict={scanVerdict(status)} className={className} />;
}

/**
 * Generic tone + label badge. Exported so pages can express a neutral fact
 * (a count, a state, a policy value) without inventing a new style.
 */
export function Badge({
  tone,
  label,
  title,
  className,
}: {
  tone: Tone;
  label: string;
  title?: string;
  className?: string;
}) {
  return (
    <span className={clsx('badge', `badge-${tone}`, className)} title={title} aria-label={title ?? label}>
      <span className="badge-label">{label}</span>
    </span>
  );
}

function ToneBadge({
  tone,
  label,
  title,
  className,
}: {
  tone: Tone;
  label: string;
  title?: string;
  className?: string;
}) {
  return <Badge tone={tone} label={label} title={title} className={className} />;
}

export function SeverityBadge({
  severity,
  className,
}: {
  severity: string | null | undefined;
  className?: string;
}) {
  return (
    <ToneBadge
      tone={severityTone(severity)}
      label={humanize(severity)}
      title={`Severity: ${humanize(severity)}`}
      className={clsx('badge-severity', className)}
    />
  );
}

export function RiskLevelBadge({
  level,
  score,
  className,
}: {
  level: string | null | undefined;
  score?: number | null;
  className?: string;
}) {
  const tone = riskLevelTone(level);
  const label = level ? humanize(level) : 'Risk unknown';
  const title =
    score === null || score === undefined
      ? `${label} risk. Risk score is not available yet.`
      : `${label} risk (risk_score ${score}). Risk is scaled by device criticality.`;
  return <ToneBadge tone={tone} label={label} title={title} className={className} />;
}

export function EvidenceQualityBadge({
  quality,
  className,
}: {
  quality: string | null | undefined;
  className?: string;
}) {
  const tone = evidenceQualityTone(quality);
  const label = quality ? humanize(quality) : 'Evidence unknown';
  return (
    <ToneBadge
      tone={tone}
      label={label}
      title={`Evidence quality: ${label}. This grades how complete the underlying evidence is, and is shown next to every score.`}
      className={clsx('badge-quality', className)}
    />
  );
}

export function OutcomeBadge({ outcome, className }: { outcome: string | null; className?: string }) {
  const tone = outcomeTone(outcome);
  const label = outcome ? humanize(outcome) : 'Unknown';
  return <ToneBadge tone={tone} label={label} title={`Audit outcome: ${label}`} className={className} />;
}

export function PolicyLayerBadge({ layer, className }: { layer: string | null; className?: string }) {
  const tone = policyLayerTone(layer);
  const label = layer ? humanize(layer) : 'Unknown layer';
  return (
    <ToneBadge
      tone={tone}
      label={label}
      title={`Resolved by the ${label.toLowerCase()} layer (baseline → override → device).`}
      className={className}
    />
  );
}

export function EnabledBadge({ enabled, className }: { enabled: boolean; className?: string }) {
  return (
    <ToneBadge
      tone={enabled ? 'ok' : 'neutral'}
      label={enabled ? 'Enabled' : 'Disabled'}
      title={enabled ? 'This override is enabled and participates in resolution.' : 'This override is disabled and is skipped during resolution.'}
      className={className}
    />
  );
}

export function NeutralBadge({
  label,
  title,
  className,
}: {
  label: string;
  title?: string;
  className?: string;
}) {
  return <ToneBadge tone="neutral" label={label} title={title} className={className} />;
}

export function MonoTechBadge({ label, title }: { label: string; title?: string }) {
  return (
    <span className="badge badge-outline badge-mono" title={title}>
      {label}
    </span>
  );
}
