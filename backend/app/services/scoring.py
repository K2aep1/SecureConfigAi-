"""The deterministic decision engine (scoring model 2.1.0).

This is the authoritative layer. Controls are evaluated from collected evidence, and
posture, coverage, compliance, risk and findings are all derived from the same control
list, so the UI cannot drift from the assessment.

Correctness rules
-----------------
1. **Only a definite value produces a verdict.** ``compliant`` and ``non_compliant``
   are reachable only from a real boolean or a real number in range. A missing key, a
   ``null``, a string where a number is expected, or a collector that reported nothing
   produces ``unknown``. Absence of evidence is never converted into a failure or a pass.
2. **``not_applicable`` requires evidence.** It comes from an explicit scanner verdict
   (the feature is absent) or from a disabled control. It never comes from silence.
3. **Collector health gates every control.** A collector that errored or timed out
   yields ``error``. One that was skipped or reported ``unavailable`` yields ``unknown``.
4. **Exemptions do not improve the score.** An accepted deviation keeps its real verdict,
   so posture and compliance stay honest. It is excluded only from the open-risk
   aggregate and is reported separately as accepted risk.
5. **Risk is bounded and reachable.** Per-control impact is normalised to 0..1 against
   the largest value the baseline allows. Impacts are combined with a noisy-OR model, and
   asset criticality is a real per-device input.

Every threshold, exposure and default that this module reads must be present in the
validated baseline pack. Nothing here falls back to a hard-coded value silently.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.services.baseline import Baseline, EffectiveControl, EffectiveSet

logger = logging.getLogger("secureconfigai.scoring")

SCORING_MODEL_VERSION = "2.1.0"

#: Criticality is a 1..5 scale. Values outside it are clamped, never trusted.
MIN_CRITICALITY = 1
MAX_CRITICALITY = 5
DEFAULT_CRITICALITY = 3

#: Cap on any single control's probability contribution, so one control cannot saturate risk.
MAX_CONTRIBUTION = 0.95

#: Evidence embedded in a finding is projected, never copied wholesale.
MAX_EVIDENCE_ITEMS = 25
MAX_EVIDENCE_CHARS = 4000
MAX_EVIDENCE_DEPTH = 3

COLLECTOR_ERROR_STATES = frozenset({"error", "timeout"})
COLLECTOR_UNKNOWN_STATES = frozenset({"unavailable", "skipped", "not_applicable", "missing"})
COLLECTOR_OK_STATES = frozenset({"completed", "success", "ok"})

ASSESSED_STATES = frozenset({"compliant", "non_compliant"})
UNRESOLVED_STATES = frozenset({"unknown", "error"})


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

    @property
    def accepted_risk(self) -> bool:
        """A real failure that a policy exemption has accepted. Excluded from open risk."""
        return self.status == "non_compliant" and self.exempted

    @property
    def open_failure(self) -> bool:
        return self.status == "non_compliant" and not self.exempted

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
            "accepted_risk": self.accepted_risk,
            "risk_impact": round(self.risk_impact, 4),
            "risk_contribution": round(self.risk_contribution, 2),
        }


# --------------------------------------------------------------------------- paths
def resolve_path(document: Any, path: str) -> list[Any]:
    """Resolve a dotted path with optional ``[*]`` fan-out.

    ``checks.firewall.profiles[*].enabled`` returns the ``enabled`` value of every
    profile. ``[*]`` fans out over a list or over the values of a mapping, because
    collectors may key records by name. A missing key resolves to ``[]``, which lets the
    caller tell "no evidence" apart from ``False``.
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
                continue  # an absent key contributes no value at all
            if fan_out:
                if isinstance(value, Mapping):
                    collected.extend(value.values())
                elif isinstance(value, (list, tuple)):
                    collected.extend(value)
                else:
                    collected.append(value)  # present but not fannable, e.g. None
            else:
                collected.append(value)
        current = collected
        if not current:
            return []
    return current


def _project(value: Any, *, depth: int = 0) -> Any:
    """Bound an evidence value so findings cannot bloat the database."""
    if depth > MAX_EVIDENCE_DEPTH:
        return "..."
    if isinstance(value, Mapping):
        return {str(k): _project(v, depth=depth + 1) for k, v in list(value.items())[:MAX_EVIDENCE_ITEMS]}
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


def _evidence_values(document: Mapping[str, Any], spec_paths: Iterable[str]) -> list[Any]:
    values: list[Any] = []
    for path in spec_paths:
        values.extend(resolve_path(document, path))
    return values


# --------------------------------------------------------------------------- collectors
def collector_status(document: Mapping[str, Any], collector: str) -> tuple[str, Any]:
    """Return ``(normalised_status, payload)`` for one collector.

    A legacy payload with no ``status`` field counts as ``completed`` only if it has
    content. A payload that is not a mapping is ``unknown``. Old snapshots stay readable
    without inventing evidence.
    """
    checks = document.get("checks") if isinstance(document, Mapping) else None
    if not isinstance(checks, Mapping) or collector not in checks:
        return "missing", None
    payload = checks.get(collector)
    if not isinstance(payload, Mapping):
        return "unknown", payload  # e.g. a legacy scalar such as "healthy"
    raw_status = payload.get("status")
    if raw_status is None:
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


# --------------------------------------------------------------------------- predicates
def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _all_numbers(values: Sequence[Any]) -> bool:
    return bool(values) and all(_is_number(v) for v in values)


def _all_bools(values: Sequence[Any]) -> bool:
    return bool(values) and all(isinstance(v, bool) for v in values)


def evaluate_predicate(op: str, values: Sequence[Any], evaluation: Mapping[str, Any]) -> tuple[str, list[str]]:
    """Apply an evaluation predicate. Returns ``(verdict, notes)``.

    Anything ambiguous yields ``unknown``. ``all_int_at_least`` and ``int_at_least`` have
    the same semantics: every value must meet the minimum. Both are kept because packs
    use both names.
    """
    notes: list[str] = []

    if op == "bool_is":
        if not _all_bools(values):
            return "unknown", ["no boolean evidence collected"]
        expected = bool(evaluation["value"])
        return ("compliant" if all(v is expected for v in values) else "non_compliant"), notes

    if op == "all_bool_true":
        if not _all_bools(values):
            return "unknown", ["no boolean evidence, or at least one value is not a boolean"]
        return ("compliant" if all(values) else "non_compliant"), notes

    if op == "int_is":
        if not _all_numbers(values):
            return "unknown", ["no numeric evidence collected"]
        target = evaluation["value"]
        return ("compliant" if all(v == target for v in values) else "non_compliant"), notes

    if op == "int_between":
        if not _all_numbers(values):
            return "unknown", ["no numeric evidence collected"]
        low, high = evaluation["min"], evaluation["max"]
        ok = all(low <= v <= high for v in values)
        if not ok and any(v == 0 for v in values):
            notes.append("a value of 0 disables the setting entirely")
        return ("compliant" if ok else "non_compliant"), notes

    if op in {"int_at_least", "all_int_at_least"}:
        if not _all_numbers(values):
            return "unknown", ["no numeric evidence, or at least one value is missing or not numeric"]
        minimum = evaluation["min"]
        return ("compliant" if all(v >= minimum for v in values) else "non_compliant"), notes

    if op == "int_at_most":
        if not _all_numbers(values):
            return "unknown", ["no numeric evidence collected"]
        maximum = evaluation["max"]
        return ("compliant" if all(v <= maximum for v in values) else "non_compliant"), notes

    if op == "enum_in":
        if not values or any(v is None for v in values):
            return "unknown", ["no value collected"]
        allowed = {str(v).strip().lower() for v in evaluation["values"]}
        ok = all(str(v).strip().lower() in allowed for v in values)
        return ("compliant" if ok else "non_compliant"), notes

    if op == "list_empty":
        if not values or any(not isinstance(v, list) for v in values):
            return "unknown", ["expected a list of findings from the collector"]
        return ("compliant" if all(len(v) == 0 for v in values) else "non_compliant"), notes

    return "error", [f"unsupported evaluation op {op!r}"]


def evaluate_applicability(applicability: Mapping[str, Any], document: Mapping[str, Any]) -> tuple[str, list[str]]:
    """Return ``(applicability, notes)``, where applicability is applicable, not_applicable or unknown."""
    kind = str(applicability.get("type", "always"))
    if kind == "always":
        return "applicable", []
    values = _evidence_values(document, applicability.get("paths") or [])
    if not _all_bools(values):
        return "unknown", ["applicability could not be determined from evidence"]
    if all(values):
        return "applicable", []
    return "not_applicable", ["the feature is reported as not supported or not present"]


# --------------------------------------------------------------------------- impact
def _clamp_criticality(value: int) -> int:
    return max(MIN_CRITICALITY, min(MAX_CRITICALITY, int(value)))


def _impact_scale(baseline: Baseline) -> float:
    """The largest impact the baseline can produce. Dividing by it bounds impact to 0..1."""
    max_severity = max(baseline.severity_impact.values())
    max_exposure = max(int(category["exposure"]) for category in baseline.categories.values())
    return float(max_severity * max_exposure * MAX_CRITICALITY)


def control_impact(baseline: Baseline, severity: str, category: str, criticality: int) -> float:
    """Normalised impact in 0..1: severity x exposure x criticality, over the maximum possible."""
    raw = (
        baseline.severity_impact[severity]
        * int(baseline.categories[category]["exposure"])
        * _clamp_criticality(criticality)
    )
    return min(1.0, raw / _impact_scale(baseline))


def standalone_contribution(impact: float, likelihood: float) -> float:
    """A control's risk on its own, 0..100. Contributions are not additive; see aggregate_risk."""
    return round(100 * min(MAX_CONTRIBUTION, likelihood * impact), 2)


def aggregate_risk(impacts: Iterable[float], likelihood: float) -> tuple[int, float]:
    """Noisy-OR combination of independent per-control impacts.

    ``risk = 100 * (1 - Π(1 - L·impact_i))``. The result is bounded to 0..100, and it rises
    with both the number and the severity of failures. ``L`` is the probability that one
    failing control is exploited, and it is published in the baseline pack.
    """
    remaining = 1.0
    for impact in impacts:
        remaining *= 1.0 - min(MAX_CONTRIBUTION, max(0.0, likelihood * float(impact)))
    return int(round(100 * (1 - remaining))), remaining


def _pct(numerator: float, denominator: float) -> int:
    return int(round(100 * numerator / denominator)) if denominator else 0


# --------------------------------------------------------------------------- controls
def evaluate_control(
    document: Mapping[str, Any],
    effective: EffectiveControl,
    *,
    criticality: int,
    baseline: Baseline,
) -> ControlResult:
    """Evaluate one control. Never raises for missing or malformed evidence."""
    spec = effective.spec
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
        evidence=project_values(_evidence_values(document, spec.evidence_paths or spec.paths)),
        standard_refs=list(spec.references),
        rationale=spec.rationale,
        remediation=dict(effective.remediation),
        collector=spec.collector,
        collector_status="missing",
        risk_impact=control_impact(baseline, effective.severity, spec.category, criticality),
    )

    # An exemption is recorded on the result, but the real verdict is still computed below.
    # That keeps posture honest when a failure is accepted.
    if effective.exempted:
        result.exempted = True
        result.exemption_reason = effective.exemption_reason
        result.notes.append(
            "deviation accepted by policy"
            + (f": {effective.exemption_reason}" if effective.exemption_reason else "")
        )

    # A disabled control is out of scope, and says so.
    if not effective.enabled:
        result.status = "not_applicable"
        result.applicability = "not_applicable"
        result.notes.append("disabled by a global policy override")
        return result

    collector_state, payload = collector_status(document, spec.collector)
    result.collector_status = collector_state
    if collector_state == "error":
        result.status = "error"
        error = payload.get("error") if isinstance(payload, Mapping) else None
        result.notes.append(f"collector reported an error: {error}" if error else "collector reported an error")
        return result
    if collector_state != "completed":
        result.status = "unknown"
        result.notes.append(
            "collector did not report" if collector_state == "missing" else f"collector status is {collector_state}"
        )
        return result

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

    values = _evidence_values(document, spec.paths)
    verdict, predicate_notes = evaluate_predicate(spec.op, values, spec.evaluation)
    result.status = verdict
    result.actual_state = project_values(values)
    result.notes.extend(predicate_notes)
    if verdict == "unknown" and any(v is None for v in values):
        result.notes.append("the value is explicitly null in the collected evidence")
    return result


def build_controls(
    document: Mapping[str, Any] | None,
    effective: EffectiveSet,
    *,
    criticality: int | None = None,
    baseline: Baseline | None = None,
) -> list[ControlResult]:
    """Evaluate every control in the effective set against one evidence document."""
    doc = document if isinstance(document, Mapping) else {}
    resolved_baseline = baseline or effective.baseline
    level = _clamp_criticality(criticality if criticality is not None else DEFAULT_CRITICALITY)
    return [
        evaluate_control(doc, control, criticality=level, baseline=resolved_baseline)
        for control in effective.controls
    ]


# --------------------------------------------------------------------------- aggregate
def build_scan_result(
    controls: Sequence[ControlResult],
    findings: Sequence[Mapping[str, Any]],
    effective: EffectiveSet,
    *,
    criticality: int = DEFAULT_CRITICALITY,
) -> dict[str, Any]:
    """Derive every headline metric from one control list."""
    baseline = effective.baseline
    applicable = [c for c in controls if c.status != "not_applicable"]
    assessed = [c for c in applicable if c.status in ASSESSED_STATES]
    unresolved = [c for c in applicable if c.status in UNRESOLVED_STATES]
    non_compliant = [c for c in applicable if c.status == "non_compliant"]
    open_failures = [c for c in non_compliant if c.open_failure]
    accepted = [c for c in non_compliant if c.accepted_risk]

    total_weight = sum(c.weight for c in applicable)
    assessed_weight = sum(c.weight for c in assessed)
    compliant_weight = sum(c.weight for c in assessed if c.status == "compliant")
    compliant_count = sum(1 for c in assessed if c.status == "compliant")

    posture = _pct(compliant_weight, assessed_weight)
    coverage = _pct(assessed_weight, total_weight)
    compliance = _pct(compliant_count, len(assessed))

    likelihood = baseline.risk_likelihood
    risk_score, remaining = aggregate_risk((c.risk_impact for c in open_failures), likelihood)
    for control in controls:
        control.risk_contribution = standalone_contribution(control.risk_impact, likelihood) if control.open_failure else 0.0
    risk_level = baseline.risk_level(risk_score)

    medium_coverage = baseline.thresholds["evidence_quality"]["medium_coverage"]
    if coverage >= 100 and not unresolved:
        evidence_quality = "high"
    elif coverage >= medium_coverage:
        evidence_quality = "medium"
    elif coverage > 0:
        evidence_quality = "low"
    else:
        evidence_quality = "unavailable"

    # Severity counts describe open findings. Accepted deviations are listed, not counted.
    open_findings = [f for f in findings if not f.get("exempted")]
    counts = {
        severity: sum(1 for f in open_findings if str(f.get("severity", "")).lower() == severity)
        for severity in ("critical", "high", "medium", "low", "informational")
    }

    category_rows: list[dict[str, Any]] = []
    for category in sorted({c.category for c in controls}):
        group = [c for c in controls if c.category == category]
        group_applicable = [c for c in group if c.status != "not_applicable"]
        group_assessed = [c for c in group_applicable if c.status in ASSESSED_STATES]
        group_weight = sum(c.weight for c in group_assessed)
        group_compliant_weight = sum(c.weight for c in group_assessed if c.status == "compliant")
        category_rows.append(
            {
                "label": category,
                "score": _pct(group_compliant_weight, group_weight) if group_weight else None,
                "count": len(group),
                "non_compliant": sum(1 for c in group if c.status == "non_compliant"),
                "accepted_risk": sum(1 for c in group if c.accepted_risk),
                "unknown": sum(1 for c in group if c.status in UNRESOLVED_STATES),
                "weight": sum(c.weight for c in group_applicable),
                "status": (
                    "incomplete"
                    if any(c.status in UNRESOLVED_STATES for c in group)
                    else ("not_applicable" if not group_applicable else "assessed")
                ),
                "exposure": int(baseline.categories[category]["exposure"]),
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
            "asset_criticality": _clamp_criticality(criticality),
            "total_controls": len(controls),
            "applicable_controls": len(applicable),
            "assessed_controls": len(assessed),
            "compliant_controls": compliant_count,
            "non_compliant_controls": len(non_compliant),
            "open_non_compliant_controls": len(open_failures),
            "accepted_risk_controls": len(accepted),
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


def build_findings(controls: Sequence[ControlResult], *, include_unknown: bool = False) -> list[dict[str, Any]]:
    """Derive findings from controls.

    Non-compliant controls always produce a finding, including accepted ones, so the
    deviation stays visible. Accepted findings carry ``exempted=True``. Unknown and
    error controls are included only when ``include_unknown`` is set.
    """
    wanted = {"non_compliant"} | (set(UNRESOLVED_STATES) if include_unknown else set())
    findings: list[dict[str, Any]] = []
    for control in controls:
        if control.status not in wanted:
            continue
        findings.append(
            {
                "control_id": control.control_id,
                "category": control.category,
                "title": control.title,
                "description": control.remediation.get("what_is_wrong")
                or f"Control {control.control_id} is not satisfied.",
                "severity": control.severity,
                "status": control.status,
                "current_value": control.actual_state,
                "expected_value": control.expected_state,
                "evidence": control.evidence,
                "risk_impact": round(control.risk_impact, 4),
                "exempted": control.exempted,
                "exemption_reason": control.exemption_reason,
                "standard_refs": list(control.standard_refs),
                "remediation": dict(control.remediation),
                "collector_status": control.collector_status,
                "notes": list(control.notes),
            }
        )
    return findings


def explain_risk(controls: Sequence[ControlResult], effective: EffectiveSet, criticality: int) -> dict[str, Any]:
    """Transparent risk arithmetic for the report and the UI tooltip. Open failures only."""
    baseline = effective.baseline
    likelihood = baseline.risk_likelihood
    failing = [c for c in controls if c.open_failure]
    score, remaining = aggregate_risk((c.risk_impact for c in failing), likelihood)
    return {
        "score": score,
        "level": baseline.risk_level(score),
        "criticality": _clamp_criticality(criticality),
        "likelihood_factor": likelihood,
        "remaining_probability": round(remaining, 4),
        "formula": baseline.thresholds["risk_model"].get("formula", ""),
        "contributions": [
            {
                "control_id": c.control_id,
                "severity": c.severity,
                "category": c.category,
                "impact": round(c.risk_impact, 4),
                "contribution": standalone_contribution(c.risk_impact, likelihood),
            }
            for c in sorted(failing, key=lambda x: -x.risk_impact)
        ],
        "accepted_risk": [
            {"control_id": c.control_id, "reason": c.exemption_reason}
            for c in controls
            if c.accepted_risk
        ],
    }