/**
 * Control detail drawer.
 *
 * One normalised shape serves both sources:
 *   - `ControlResult` (a control as evaluated in a scan, `GET /scans/{id}/results`)
 *   - `BaselineControl` (the shipped definition, `GET /baseline`)
 *
 * Render rules worth stating: the expected/actual states are rendered as text,
 * never as HTML; standard references become links only when the URL passes
 * `safeExternalHref`; and the verdict badge is the same component used in tables
 * so a control cannot look like a pass in one place and something else in another.
 */

import type { ReactNode } from 'react';
import { Drawer } from './Drawer';
import { ControlStatusBadge, SeverityBadge } from './Badges';
import { DetailList, DetailRow } from './MetricCard';
import { formatJsonInline, formatJsonValue, humanize } from '../lib/format';
import { safeExternalHref } from '../lib/url';
import type {
  BaselineControl,
  ControlResult,
  ControlStatus,
  JsonValue,
  Remediation,
  StandardReference,
} from '../types';

export interface ControlDetail {
  control_id: string;
  title: string;
  category: string;
  weight: number | null;
  severity: string | null;
  /** `null` for baseline definitions, which have no verdict of their own. */
  status: ControlStatus | null;
  /** A string in assessments; an object of conditions in the baseline pack. */
  applicability: JsonValue | null;
  expected_state: JsonValue | undefined;
  actual_state: JsonValue | undefined;
  rationale: string | null;
  references: StandardReference[];
  remediation: Remediation | null;
  evidence: JsonValue | undefined;
  evidence_paths: string[];
  collector: string | null;
  exempted: boolean;
  exemption_reason: string | null;
}

export function controlDetailFromResult(control: ControlResult): ControlDetail {
  return {
    control_id: control.control_id,
    title: control.title,
    category: control.category,
    weight: control.weight,
    severity: control.severity,
    status: control.status,
    applicability: control.applicability,
    expected_state: control.expected_state,
    actual_state: control.actual_state,
    rationale: control.rationale,
    references: control.standard_refs ?? [],
    remediation: control.remediation ?? null,
    evidence: control.evidence,
    evidence_paths: [],
    collector: null,
    exempted: Boolean(control.exempted),
    exemption_reason: control.exemption_reason ?? null,
  };
}

export function controlDetailFromBaseline(control: BaselineControl): ControlDetail {
  return {
    control_id: control.control_id,
    title: control.title,
    category: control.category,
    weight: control.weight,
    severity: control.severity,
    status: null,
    applicability: control.applicability ?? null,
    expected_state: control.expected_state,
    actual_state: undefined,
    rationale: control.rationale,
    references: control.references ?? [],
    remediation: control.remediation ?? null,
    evidence: undefined,
    evidence_paths: control.evidence_paths ?? [],
    collector: control.collector ?? null,
    exempted: false,
    exemption_reason: null,
  };
}

/** Applicability arrives as a plain string in assessments and an object in the pack. */
function renderApplicability(value: JsonValue | null): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return humanize(value);
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return formatJsonInline(value, 120);
}

function ReferenceList({ references }: { references: StandardReference[] }) {
  if (references.length === 0) return <span className="muted">No standard references recorded.</span>;
  return (
    <ul className="ref-list">
      {references.map((reference, index) => {
        const href = safeExternalHref(reference.url);
        const label = `${reference.standard} · ${reference.control}`;
        return (
          <li key={`${reference.standard}-${reference.control}-${index}`}>
            {href ? (
              <a href={href} target="_blank" rel="noopener noreferrer">
                {label}
              </a>
            ) : (
              <span title={reference.url ? 'Reference URL was not a safe http(s) link' : undefined}>
                {label}
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

function StateBlock({ title, value }: { title: string; value: JsonValue | undefined }) {
  return (
    <div className="state-block-json">
      <span className="state-block-json-title">{title}</span>
      <pre className="json-block">{formatJsonValue(value)}</pre>
    </div>
  );
}

export function ControlDrawer({
  detail,
  onClose,
  footer,
}: {
  detail: ControlDetail | null;
  onClose: () => void;
  footer?: ReactNode;
}) {
  return (
    <Drawer
      open={detail !== null}
      onClose={onClose}
      width="wide"
      title={detail?.title ?? 'Control'}
      subtitle={
        detail ? (
          <span className="drawer-subtitle-row">
            <code>{detail.control_id}</code>
            <span>{detail.category}</span>
            {detail.severity ? <SeverityBadge severity={detail.severity} /> : null}
            {detail.weight !== null ? <span>weight {detail.weight}</span> : null}
          </span>
        ) : null
      }
      footer={footer}
    >
      {detail ? (
        <div className="drawer-sections">
          <section className="drawer-section">
            <h3 className="drawer-section-title">Verdict</h3>
            <div className="verdict-row">
              {detail.status ? (
                <ControlStatusBadge status={detail.status} exempted={detail.exempted} />
              ) : (
                <span className="badge badge-outline">Baseline definition — no verdict</span>
              )}
              {detail.exempted && detail.exemption_reason ? (
                <span className="exemption-note">Exemption: {detail.exemption_reason}</span>
              ) : null}
            </div>
            <DetailList>
              <DetailRow label="Applicability" value={renderApplicability(detail.applicability)} />
              <DetailRow label="Category" value={detail.category} />
              {detail.collector ? (
                <DetailRow label="Collector" value={<code className="inline-code">{detail.collector}</code>} />
              ) : null}
              <DetailRow
                label="Weight"
                value={detail.weight === null ? '—' : `${detail.weight} (scales the score)`}
              />
            </DetailList>
          </section>

          <section className="drawer-section">
            <h3 className="drawer-section-title">Rationale</h3>
            <p className="drawer-text">
              {detail.rationale || 'The baseline pack records no rationale for this control.'}
            </p>
          </section>

          <section className="drawer-section">
            <h3 className="drawer-section-title">State</h3>
            <div className="state-block-grid">
              <StateBlock title="Expected state" value={detail.expected_state} />
              {detail.actual_state !== undefined ? (
                <StateBlock title="Observed state" value={detail.actual_state} />
              ) : null}
            </div>
            {detail.evidence_paths.length > 0 ? (
              <p className="drawer-text drawer-text-subtle">
                Evidence paths: <code>{detail.evidence_paths.join(', ')}</code>
              </p>
            ) : null}
          </section>

          {detail.remediation ? (
            <section className="drawer-section">
              <h3 className="drawer-section-title">Remediation</h3>
              <DetailList>
                <DetailRow label="What is wrong" value={detail.remediation.what_is_wrong} />
                <DetailRow label="Why it matters" value={detail.remediation.why_it_matters} />
                <DetailRow
                  label="What should be done"
                  value={detail.remediation.what_should_be_done}
                />
                {detail.remediation.verify ? (
                  <DetailRow label="How to verify" value={detail.remediation.verify} />
                ) : null}
              </DetailList>
            </section>
          ) : null}

          <section className="drawer-section">
            <h3 className="drawer-section-title">Standard references</h3>
            <ReferenceList references={detail.references} />
          </section>

          {detail.evidence !== undefined ? (
            <details className="drawer-disclosure">
              <summary>Collected evidence for this control</summary>
              <pre className="json-block">{formatJsonValue(detail.evidence)}</pre>
            </details>
          ) : null}
        </div>
      ) : null}
    </Drawer>
  );
}
