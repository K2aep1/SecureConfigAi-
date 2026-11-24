"""The deterministic decision engine (scoring model 2.0.0).

This is the authoritative layer: controls are evaluated from collected evidence, and
posture, coverage, compliance, risk and findings are all derived from the same control
list so the UI cannot drift from the assessment.

Correctness rules that this implementation enforces
---------------------------------------------------
1. **Only a definite value produces a verdict.** ``compliant`` and ``non_compliant``
   are reachable only from a real boolean or a real number in range. A missing key, a
   ``null``, a string where a number is expected, or a collector that reported nothing
   produces ``unknown``. Absence of evidence is never silently converted into a
   security failure *or* into a pass.
2. **``not_applicable`` requires evidence.** It comes from an explicit scanner verdict
   (feature genuinely absent) or from a recorded policy exemption — never from silence.
3. **Collector health gates every control.** A collector that errored or timed out
   yields ``error``; one that was skipped or reported ``unavailable`` yields ``unknown``.
4. **Risk is bounded and reachable.** Per-control impact is normalised to 0..1, impacts
   are combined with a noisy-OR (independent-failure) model, and asset criticality is a
   real per-device input rather than a constant.

Scoring model version 2.0.0 — see SCORING_METHODOLOGY.md for the derivation.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.services.baseline import EffectiveControl, EffectiveSet

logger = logging.getLogger("secureconfigai.scoring")

SCORING_MODEL_VERSION = "2.0.0"

#: Evidence embedded in a finding is projected, never copied wholesale.
MAX_EVIDENCE_ITEMS = 25
MAX_EVIDENCE_CHARS = 4000

COLLECTOR_ERROR_STATES = {"error", "timeout"}
COLLECTOR_UNKNOWN_STATES = {"unavailable", "skipped", "not_applicable", "missing"}
COLLECTOR_OK_STATES = {"completed", "success", "ok"}


# --------------------------------------------------------------------------- results
@dataclass
class ControlResult:
    control_id: str
    title: str
    category: str
    weight: int
    severity: str
    status: str
    applicability: str
    expected_state: Any
    actual_state: Any
    evidence: Any
    standard_refs: list[Mapping[str, Any]]
    rationale: str
    remediation: Mapping[str, str]
    collector: str
    collector_status: str
    notes: list[str] = field(default_factory=list)
    exempted: bool = False
    exemption_reason: str | None = None
    risk_impact: float = 0.0
    risk_contribution: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "category": self.category,
            "weight": self.weight,
            "severity": self.severity,
            "status": self.status,
            "applicability": self.applicability,
            "expected_state": self.expected_state,
            "actual_state": self.actual_state,
            "evidence": self.evidence,
            "standard_refs": list(self.standard_refs),
            "rationale": self.rationale,
            "remediation": dict(self.remediation),
            "collector": self.collector,
            "collector_status": self.collector_status,
            "notes": list(self.notes),
            "exempted": self.exempted,
            "exemption_reason": self.exemption_reason,
            "risk_impact": round(self.risk_impact, 4),
            "risk_contribution": round(self.risk_contribution, 2),
        }


# --------------------------------------------------------------------------- paths
def resolve_path(document: Any, path: str) -> list[Any]:
    """Resolve a dotted path with optional ``[*]`` fan-out.

    ``checks.firewall.profiles[*].enabled`` returns the ``enabled`` value of every
    profile. ``[*]`` fans out over a list *or* over the values of a mapping, because
    collectors may key a set of records by name (for example firewall logging keyed by
    profile). A missing key resolves to ``[]`` (no values) rather than raising, so the
    caller can distinguish "no evidence" from "false".
    """
    if not isinstance(path, str) or not path:
        return []
    missing = object()
    current: list[Any] = [document]
    for segment in path.split("."):
        fan_out = segment.endswith("[*]")
        name = segment[:-3] if fan_out else segment
        collected: list[Any] = []
        for node in current:
            value = node.get(name, missing) if isinstance(node, Mapping) else missing
            if value is missing:
                continue  # absent key contributes no value at all
            if fan_out:
                if isinstance(value, Mapping):
                    collected.extend(value.values())
                elif isinstance(value, (list, tuple)):
                    collected.extend(value)
                else:
                    collected.append(value)  # e.g. None: present but not fannable
            else:
                collected.append(value)
        current = collected
        if not current:
            return []
    return current


def _project(value: Any, *, depth: int = 0) -> Any:
    """Bound an evidence value so findings cannot bloat the database."""
    if depth > 3:
        return "..."
    if isinstance(value, Mapping):
        items = list(value.items())[:MAX_EVIDENCE_ITEMS]
        return {str(k): _project(v, depth=depth + 1) for k, v in items}
    if isinstance(value, (list, tuple)):
        return [_project(v, depth=depth + 1) for v in value[:MAX_EVIDENCE_ITEMS]]
    if isinstance(value, str) and len(value) > MAX_EVIDENCE_CHARS:
        return value[:MAX_EVIDENCE_CHARS] + "...[truncated]"
    return value


def project_values(values: Sequence[Any]) -> Any:
    if not values:
        return None
    if len(values) == 1:
        return _project(values[0])
    return [_project(v) for v in values]


# --------------------------------------------------------------------------- collectors
def collector_status(document: Mapping[str, Any], collector: str) -> tuple[str, Any]:
    """Return ``(normalised_status, payload)`` for one collector.

    Legacy documents that stored the payload directly (a dict without ``status``) are
    treated as ``completed``; anything that is not a mapping is ``unknown``. This keeps
    old snapshots readable without inventing evidence.
    """
    checks = document.get("checks") if isinstance(document, Mapping) else None
    if not isinstance(checks, Mapping):
        return "missing", None
    if collector not in checks:
        return "missing", None
    payload = checks.get(collector)
    if not isinstance(payload, Mapping):
        return "unknown", payload  # e.g. the legacy "updates": "healthy" shape
    raw_status = payload.get("status")
    if raw_status is None:
        # Legacy payload without an explicit status: acceptable only if it has content.
        return ("completed" if payload else "unknown"), payload
    status = str(raw_status).strip().lower()
    if status in COLLECTOR_OK_STATES:
        return "completed", payload
    if status in COLLECTOR_ERROR_STATES:
        return "error", payload
    if status in COLLECTOR_UNKNOWN_STATES:
        return "unknown", payload
    logger.debug("unrecognised collector status %r for %s", status, collector)
    return "unknown", payload


# --------------------------------------------------------------------------- ops
def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def evaluate_predicate(
    op: str,
    values: Sequence[Any],
    evaluation: Mapping[str, Any],
) -> tuple[str, list[str]]:
    """Apply an evaluation predicate. Returns ``(status, notes)``.

    The contract: anything ambiguous yields ``unknown``.
    """
    notes: list[str] = []

    if op == "bool_is":
        expected = bool(evaluation.get("value"))
        if not values or any(not isinstance(v, bool) for v in values):
            return "unknown", ["no boolean evidence collected"]
        return ("compliant" if all(v is expected for v in values) else "non_compliant"), notes

    if op == "all_bool_true":
        if not values:
            return "unknown", ["no values resolved for the evidence paths"]
        if any(not isinstance(v, bool) for v in values):
            return "unknown", ["at least one value is not a boolean"]
        return ("compliant" if all(values) else "non_compliant"), notes

    if op == "int_is":
        if not values or any(not _is_number(v) for v in values):
            return "unknown", ["no numeric evidence collected"]
        target = evaluation.get("value")
        return ("compliant" if all(v == target for v in values) else "non_compliant"), notes

    if op == "int_between":
        if not values or any(not _is_number(v) for v in values):
            return "unknown", ["no numeric evidence collected"]
        low, high = evaluation.get("min"), evaluation.get("max")
        ok = all(low <= v <= high for v in values)
        if not ok and any(v == 0 for v in values):
            notes.append("a value of 0 disables the setting entirely")
        return ("compliant" if ok else "non_compliant"), notes

    if op == "int_at_least":
        if not values or any(not _is_number(v) for v in values):
            return "unknown", ["no numeric evidence collected"]
        minimum = evaluation.get("min")
        return ("compliant" if all(v >= minimum for v in values) else "non_compliant"), notes

    if op == "int_at_most":
        if not values or any(not _is_number(v) for v in values):
            return "unknown", ["no numeric evidence collected"]
        maximum = evaluation.get("max")
        return ("compliant" if all(v <= maximum for v in values) else "non_compliant"), notes

    if op == "all_int_at_least":
        if not values or any(not _is_number(v) for v in values):
            return "unknown", ["at least one value is missing or not numeric"]
        minimum = evaluation.get("min")
        return ("compliant" if all(v >= minimum for v in values) else "non_compliant"), notes

    if op == "enum_in":
        if not values or any(v is None for v in values):
            return "unknown", ["no value collected"]
        allowed = {str(v).strip().lower() for v in evaluation.get("values", [])}
        return (
            "compliant" if all(str(v).strip().lower() in allowed for v in values) else "non_compliant"
        ), notes

    if op == "list_empty":
        if not values or any(not isinstance(v, list) for v in values):
            return "unknown", ["expected a list of findings from the collector"]
        empty = all(len(v) == 0 for v in values)
        return ("compliant" if empty else "non_compliant"), notes

    return "error", [f"unsupported evaluation op {op!r}"]


def evaluate_applicability(
    applicability: Mapping[str, Any],
    document: Mapping[str, Any],
) -> tuple[str, list[str]]:
    """Return ``(applicability, notes)`` where applicability ∈ applicable/not_applicable/unknown."""
    kind = str(applicability.get("type", "always"))
    if kind == "always":
        return "applicable", []
    values: list[Any] = []
    for path in applicability.get("paths", []) or []:
        values.extend(resolve_path(document, path))
    if not values or any(not isinstance(v, bool) for v in values):
        return "unknown", ["applicability could not be determined from evidence"]
    if all(values):
        return "applicable", []
    return "not_applicable", ["the feature is reported as not supported or not present"]


# --------------------------------------------------------------------------- controls
def evaluate_control(
    document: Mapping[str, Any],
    effective: EffectiveControl,
    *,
    criticality: int,
    baseline: Any,
) -> ControlResult:
    """Evaluate one control. Never raises for missing or malformed evidence."""
    spec = effective.spec
    severity_impact = int(baseline.severity_impact.get(effective.severity, 3))
    exposure = int(baseline.categories.get(spec.category, {}).get("exposure", 3))
    impact = (severity_impact * exposure * max(1, min(5, int(criticality)))) / 125.0

    result = ControlResult(
        control_id=spec.control_id,
        title=effective.title,
        category=spec.category,
        weight=effective.weight,
        severity=effective.severity,
        status="unknown",
        applicability="applicable",
        expected_state=spec.expected_state,
        actual_state=None,
        evidence=None,
        standard_refs=list(spec.references),
        rationale=spec.rationale,
        remediation=dict(effective.remediation),
        collector=spec.collector,
        collector_status="missing",
        risk_impact=impact,
    )

    evidence_values: list[Any] = []
    for path in spec.evidence_paths or spec.paths:
        evidence_values.extend(resolve_path(document, path))
    result.evidence = project_values(evidence_values)

    # 1. Explicit policy exemption wins over everything.
    if effective.exempted:
        result.status = "not_applicable"
        result.applicability = "not_applicable"
        result.exempted = True
        result.exemption_reason = effective.exemption_reason
        result.notes.append(
            "exempted by policy" + (f": {effective.exemption_reason}" if effective.exemption_reason else "")
        )
        return result

    # 2. A disabled control is out of scope, and says so.
    if not effective.enabled:
        result.status = "not_applicable"
        result.applicability = "not_applicable"
        result.notes.append("disabled by a global policy override")
        return result

    # 3. Collector health gates the verdict.
    status, payload = collector_status(document, spec.collector)
    result.collector_status = status
    if status == "error":
        result.status = "error"
        error = payload.get("error") if isinstance(payload, Mapping) else None
        result.notes.append(
            f"collector reported an error: {error}" if error else "collector reported an error"
        )
        return result
    if status != "completed":
        result.status = "unknown"
        result.notes.append(
            "collector did not report" if status == "missing" else f"collector status is {status}"
        )
        return result

    # 4. Applicability, only from explicit evidence.
    applicability, notes = evaluate_applicability(spec.applicability, document)
    if applicability == "not_applicable":
        result.status = "not_applicable"
        result.applicability = "not_applicable"
        result.notes.extend(notes)
        return result
    if applicability == "unknown":
        result.status = "unknown"
        result.notes.extend(notes)
        return result

    # 5. The predicate.
    values: list[Any] = []
    for path in spec.paths:
        values.extend(resolve_path(document, path))
    status, notes = evaluate_predicate(spec.op, values, spec.evaluation)
    result.status = status
    result.actual_state = project_values(values)
    result.notes.extend(notes)
    if status == "unknown" and values and any(v is None for v in values):
        result.notes.append("the value is explicitly null in the collected evidence")
    return result


def build_controls(
    document: Mapping[str, Any] | None,
    effective: EffectiveSet,
    *,
    criticality: int | None = None,
    baseline: Any | None = None,
) -> list[ControlResult]:
    """Evaluate every control in the effective set against one evidence document."""
    doc = document if isinstance(document, Mapping) else {}
    baseline = baseline or effective.baseline
    level = criticality if criticality is not None else 3
    return [
        evaluate_control(doc, control, criticality=level, baseline=baseline) for control in effective.controls
    ]


# --------------------------------------------------------------------------- aggregate
def aggregate_risk(impacts: Iterable[float], likelihood: float) -> tuple[int, float]:
    """Noisy-OR combination of per-control impacts.

    ``risk = 100 * (1 - Π(1 - L·impact_i))`` — bounded to 0..100, monotonic in both the
    number and the severity of failures. ``L`` is the probability that a single failing
    control is actually exploited, published in the baseline pack so it is tunable
    without touching code.
    """
    remaining = 1.0
    for impact in impacts:
        contribution = min(0.95, max(0.0, likelihood * float(impact)))
        remaining *= 1.0 - contribution
    return int(round(100 * (1 - remaining))), remaining


def build_scan_result(
    controls: Sequence[ControlResult],
    findings: Sequence[Mapping[str, Any]],
    effective: EffectiveSet,
    *,
    criticality: int = 3,
) -> dict[str, Any]:
    """Derive every headline metric from one control list."""
    baseline = effective.baseline
    applicable = [c for c in controls if c.status != "not_applicable"]
    assessed = [c for c in applicable if c.status in {"compliant", "non_compliant"}]
    unresolved = [c for c in applicable if c.status in {"unknown", "error"}]
    non_compliant = [c for c in applicable if c.status == "non_compliant"]

    total_weight = sum(c.weight for c in applicable)
    assessed_weight = sum(c.weight for c in assessed)
    compliant_weight = sum(c.weight for c in assessed if c.status == "compliant")

    posture = int(round(compliant_weight / assessed_weight * 100)) if assessed_weight else 0
    coverage = int(round(assessed_weight / total_weight * 100)) if total_weight else 0
    compliance = (
        int(round(sum(1 for c in assessed if c.status == "compliant") / len(assessed) * 100))
        if assessed
        else 0
    )

    likelihood = baseline.risk_likelihood
    risk_score, remaining = aggregate_risk([c.risk_impact for c in non_compliant], likelihood)
    for control in controls:
        if control.status == "non_compliant":
            control.risk_contribution = round(
                100 * (1 - (1 - min(0.95, likelihood * control.risk_impact))), 2
            )
    risk_level = baseline.risk_level(risk_score)

    if coverage >= 100 and not unresolved:
        evidence_quality = "high"
    elif coverage >= baseline.thresholds.get("evidence_quality", {}).get("medium_coverage", 75):
        evidence_quality = "medium"
    elif coverage > 0:
        evidence_quality = "low"
    else:
        evidence_quality = "unavailable"

    counts = {
        sev: sum(1 for f in findings if str(f.get("severity", "")).lower() == sev)
        for sev in ("critical", "high", "medium", "low", "informational")
    }

    category_rows: list[dict[str, Any]] = []
    for category in sorted({c.category for c in controls}):
        group = [c for c in controls if c.category == category]
        group_applicable = [c for c in group if c.status != "not_applicable"]
        group_assessed = [c for c in group_applicable if c.status in {"compliant", "non_compliant"}]
        group_weight = sum(c.weight for c in group_assessed)
        score = (
            int(round(sum(c.weight for c in group_assessed if c.status == "compliant") / group_weight * 100))
            if group_weight
            else None
        )
        category_rows.append(
            {
                "label": category,
                "score": score,
                "count": len(group),
                "non_compliant": sum(1 for c in group if c.status == "non_compliant"),
                "unknown": sum(1 for c in group if c.status in {"unknown", "error"}),
                "weight": sum(c.weight for c in group_applicable),
                "status": (
                    "incomplete"
                    if any(c.status in {"unknown", "error"} for c in group)
                    else ("not_applicable" if not group_applicable else "assessed")
                ),
                "exposure": baseline.categories.get(category, {}).get("exposure", 3),
                "description": "Weighted control posture from the deterministic decision engine",
            }
        )

    return {
        "security_score": posture,
        "compliance_score": compliance,
        "assessment_coverage": coverage,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "evidence_quality": evidence_quality,
        "posture_band": baseline.posture_band(posture),
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "informational_count": counts["informational"],
        "categories": category_rows,
        "assessment": {
            "scoring_model_version": SCORING_MODEL_VERSION,
            "baseline_id": baseline.baseline_id,
            "baseline_version": baseline.version,
            "asset_criticality": criticality,
            "total_controls": len(controls),
            "applicable_controls": len(applicable),
            "assessed_controls": len(assessed),
            "compliant_controls": sum(1 for c in assessed if c.status == "compliant"),
            "non_compliant_controls": len(non_compliant),
            "not_applicable_controls": sum(1 for c in controls if c.status == "not_applicable"),
            "unknown_or_error_controls": len(unresolved),
            "unknown_controls": sum(1 for c in applicable if c.status == "unknown"),
            "error_controls": sum(1 for c in applicable if c.status == "error"),
            "total_weight": total_weight,
            "assessed_weight": assessed_weight,
            "compliant_weight": compliant_weight,
            "risk_likelihood_factor": likelihood,
            "risk_remaining_probability": round(remaining, 4),
        },
    }


def build_findings(
    controls: Sequence[ControlResult],
    *,
    include_unknown: bool = False,
) -> list[dict[str, Any]]:
    """Derive findings from controls. Only non-compliant controls produce failures."""
    wanted = {"non_compliant"} | ({"unknown", "error"} if include_unknown else set())
    findings: list[dict[str, Any]] = []
    for control in controls:
        if control.status not in wanted:
            continue
        findings.append(
            {
                "control_id": control.control_id,
                "category": control.category,
                "title": control.title,
                "description": (
                    control.remediation.get("what_is_wrong")
                    or f"Control {control.control_id} is not satisfied."
                ),
                "severity": control.severity,
                "status": control.status,
                "current_value": control.actual_state,
                "expected_value": control.expected_state,
                "evidence": control.evidence,
                "risk_impact": round(control.risk_impact, 4),
                "standard_refs": list(control.standard_refs),
                "remediation": dict(control.remediation),
                "collector_status": control.collector_status,
                "notes": list(control.notes),
            }
        )
    return findings


def explain_risk(
    controls: Sequence[ControlResult], effective: EffectiveSet, criticality: int
) -> dict[str, Any]:
    """Transparent risk arithmetic for the report and the UI tooltip."""
    baseline = effective.baseline
    likelihood = baseline.risk_likelihood
    failing = [c for c in controls if c.status == "non_compliant"]
    score, remaining = aggregate_risk([c.risk_impact for c in failing], likelihood)
    return {
        "score": score,
        "level": baseline.risk_level(score),
        "criticality": criticality,
        "likelihood_factor": likelihood,
        "remaining_probability": round(remaining, 4),
        "formula": baseline.thresholds.get("risk_model", {}).get("formula", ""),
        "contributions": [
            {
                "control_id": c.control_id,
                "severity": c.severity,
                "category": c.category,
                "impact": round(c.risk_impact, 4),
                "contribution": round(100 * min(0.95, likelihood * c.risk_impact), 2),
            }
            for c in sorted(failing, key=lambda x: -x.risk_impact)
        ],
    }
