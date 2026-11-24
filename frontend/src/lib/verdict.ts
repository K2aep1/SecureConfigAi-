/**
 * Verdict presentation.
 *
 * Requirement 6 — "honest verdicts": the five frozen control states must be
 * visually distinct, and `unknown` / `error` must never look like a pass or a
 * failure. Everything that turns a status string into a tone, glyph and
 * explanation lives here so no page can invent its own semantics.
 *
 * Tones map to CSS classes in `src/index.css`:
 *   ok      — compliant (restrained green, solid)
 *   risk    — non_compliant (restrained red, solid)
 *   na      — not_applicable (neutral grey, muted)
 *   unknown — indeterminate (amber, dashed outline, "?" glyph)
 *   error   — assessment error (slate hatch, "!" glyph, visually unlike `risk`)
 *   neutral / info / warn — non-verdict metadata
 */

import { CRITICALITY_LABELS, type Criticality, type ControlStatus, type ScanStatus } from '../types';

export type Tone = 'ok' | 'risk' | 'na' | 'unknown' | 'error' | 'warn' | 'info' | 'neutral';

export interface Verdict {
  /** Human-readable label shown in the badge. */
  label: string;
  tone: Tone;
  /** Short text glyph (never an emoji font dependency). */
  glyph: string;
  /** Longer explanation exposed via `title`/`aria-label` and detail views. */
  description: string;
}

const CONTROL_VERDICTS: Record<ControlStatus, Verdict> = {
  compliant: {
    label: 'Compliant',
    tone: 'ok',
    glyph: '✓',
    description: 'The control was assessed and the endpoint matches the expected state.',
  },
  non_compliant: {
    label: 'Non-compliant',
    tone: 'risk',
    glyph: '✕',
    description: 'The control was assessed and the endpoint does not match the expected state.',
  },
  not_applicable: {
    label: 'Not applicable',
    tone: 'na',
    glyph: '–',
    description:
      'The control does not apply to this endpoint, or an exemption was recorded. It is excluded from scoring rather than counted as a pass.',
  },
  unknown: {
    label: 'Unknown',
    tone: 'unknown',
    glyph: '?',
    description:
      'The evidence needed to decide was not collected. This is not a pass and not a failure — it lowers assessment coverage.',
  },
  error: {
    label: 'Error',
    tone: 'error',
    glyph: '!',
    description:
      'The control engine could not evaluate this control (evaluation error). This is not a failure of the endpoint and not a pass.',
  },
};

/** Falls back to `unknown` for any value outside the frozen vocabulary. */
export function controlVerdict(status: ControlStatus | string | null | undefined): Verdict {
  if (status && status in CONTROL_VERDICTS) {
    return CONTROL_VERDICTS[status as ControlStatus];
  }
  return {
    label: 'Unknown',
    tone: 'unknown',
    glyph: '?',
    description: `Unrecognised control state "${String(status ?? '')}" treated as unknown.`,
  };
}

const SCAN_VERDICTS: Record<ScanStatus, Verdict> = {
  queued: {
    label: 'Queued',
    tone: 'info',
    glyph: '·',
    description: 'The scan request was accepted and is waiting for a worker.',
  },
  running: {
    label: 'Running',
    tone: 'info',
    glyph: '▸',
    description: 'Collectors are running on the endpoint. Results are not final yet.',
  },
  completed: {
    label: 'Completed',
    tone: 'ok',
    glyph: '✓',
    description: 'The assessment finished and its scores are final.',
  },
  failed: {
    label: 'Failed',
    tone: 'error',
    glyph: '!',
    description: 'The scan stopped with an error. Read `error_message` before trusting any partial data.',
  },
  cancelled: {
    label: 'Cancelled',
    tone: 'neutral',
    glyph: '⨯',
    description: 'The scan was cancelled by a user and produced no assessment.',
  },
};

/** `cancelling` is a contract-only transitional value (see `ScanCancelResponse`). */
export function scanVerdict(status: ScanStatus | 'cancelling' | string | null | undefined): Verdict {
  if (status === 'cancelling') {
    return {
      label: 'Cancelling',
      tone: 'warn',
      glyph: '…',
      description: 'Cancellation was requested; the scan stops at the next checkpoint.',
    };
  }
  if (status && status in SCAN_VERDICTS) {
    return SCAN_VERDICTS[status as ScanStatus];
  }
  return {
    label: status ? String(status) : 'Unknown',
    tone: 'neutral',
    glyph: '·',
    description: 'Unrecognised scan status.',
  };
}

export function severityTone(severity: string | null | undefined): Tone {
  switch ((severity ?? '').toLowerCase()) {
    case 'critical':
      return 'risk';
    case 'high':
      return 'risk';
    case 'medium':
      return 'warn';
    case 'low':
      return 'info';
    case 'informational':
      return 'neutral';
    default:
      return 'neutral';
  }
}

export function riskLevelTone(level: string | null | undefined): Tone {
  switch ((level ?? '').toLowerCase()) {
    case 'critical':
    case 'high':
      return 'risk';
    case 'medium':
    case 'moderate':
      return 'warn';
    case 'low':
      return 'ok';
    case 'informational':
    case 'none':
      return 'neutral';
    default:
      return 'unknown';
  }
}

export function outcomeTone(outcome: string | null | undefined): Tone {
  switch ((outcome ?? '').toLowerCase()) {
    case 'success':
    case 'succeeded':
    case 'ok':
      return 'ok';
    case 'failure':
    case 'failed':
    case 'error':
      return 'risk';
    case 'denied':
    case 'forbidden':
      return 'warn';
    default:
      return 'neutral';
  }
}

export function policyLayerTone(layer: string | null | undefined): Tone {
  switch ((layer ?? '').toLowerCase()) {
    case 'override':
      return 'warn';
    case 'device':
      return 'info';
    case 'baseline':
      return 'neutral';
    default:
      return 'unknown';
  }
}

/* ------------------------------------------------------------------ *
 * Device criticality (contract §4: label ∈ low..critical, mapping 1..5)
 * ------------------------------------------------------------------ */

export interface CriticalityChoice {
  value: Criticality;
  label: string;
  description: string;
}

/**
 * Shown inline next to the criticality control so the consequence of raising a
 * device's criticality is never a mystery.
 */
export const CRITICALITY_EXPLANATION =
  'Criticality scales the risk calculation: every finding on this device is weighted by this value, so a critical host produces a higher risk_score than the same finding on a low-criticality host. It does not change control verdicts or compliance.';

export const CRITICALITY_CHOICES: CriticalityChoice[] = ([1, 2, 3, 4, 5] as Criticality[]).map(
  (value) => ({
    value,
    label: CRITICALITY_LABELS[value],
    description:
      value >= 5
        ? 'Business-critical host: risk weight ×5.'
        : value === 1
          ? 'Low-impact host: risk weight ×1.'
          : `Risk weight ×${value}.`,
  }),
);

export function criticalityChoice(value: number | null | undefined): CriticalityChoice | null {
  if (value === 1 || value === 2 || value === 3 || value === 4 || value === 5) {
    return CRITICALITY_CHOICES[value - 1] ?? null;
  }
  return null;
}

/* ------------------------------------------------------------------ *
 * Evidence quality
 * ------------------------------------------------------------------ */

/**
 * `evidence_quality` is an open string in the contract. It grades how complete
 * the collected evidence is, so the UI always renders it next to posture and
 * never turns it into a score.
 */
export const EVIDENCE_QUALITY_EXPLANATION =
  'Evidence quality grades how complete the collected endpoint evidence is. A low grade means the score rests on partial evidence, regardless of how good the score looks.';

export function evidenceQualityTone(quality: string | null | undefined): Tone {
  switch ((quality ?? '').toLowerCase()) {
    case 'high':
    case 'strong':
    case 'complete':
    case 'good':
      return 'ok';
    case 'medium':
    case 'moderate':
    case 'partial':
      return 'warn';
    case 'low':
    case 'weak':
    case 'poor':
      return 'risk';
    case 'insufficient':
    case 'none':
      return 'unknown';
    default:
      return 'neutral';
  }
}

/** Coverage is only trustworthy alongside the counts it was computed from. */
export const COVERAGE_EXPLANATION =
  'Assessment coverage is the share of controls the engine could actually decide. Controls left unknown or in error reduce coverage and are never counted as passing.';
