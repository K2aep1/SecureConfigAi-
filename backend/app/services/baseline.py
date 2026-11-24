"""The versioned Global Security Baseline: loading, validation and effective resolution.

The baseline is *data*. This module validates it at startup (so a malformed pack fails
loudly rather than producing silent verdicts), and resolves the effective control set by
layering, highest priority last:

1. **baseline** — shipped, immutable, versioned.
2. **global override** — a ``policies`` row managed by an administrator (weight,
   severity, enable/disable, remediation text).
3. **device exemption** — a documented, per-device decision to accept a deviation.

Every resolved field records which layer supplied it, so the API can explain *why* a
control has the weight it has.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import settings

logger = logging.getLogger("secureconfigai.baseline")

KNOWN_OPS = {
    "bool_is",
    "all_bool_true",
    "int_is",
    "int_between",
    "int_at_least",
    "int_at_most",
    "all_int_at_least",
    "enum_in",
    "list_empty",
}
KNOWN_APPLICABILITY = {"always", "when_supported", "when_present"}
CONTROL_STATES = {"compliant", "non_compliant", "not_applicable", "unknown", "error"}


class BaselineError(RuntimeError):
    """The shipped baseline pack is unusable."""


@dataclass(frozen=True)
class BaselineControl:
    control_id: str
    title: str
    category: str
    weight: int
    severity: str
    collector: str
    expected_state: str
    applicability: Mapping[str, Any]
    evaluation: Mapping[str, Any]
    evidence_paths: tuple[str, ...]
    rationale: str
    remediation: Mapping[str, str]
    references: tuple[Mapping[str, str], ...]

    @property
    def op(self) -> str:
        return str(self.evaluation.get("op"))

    @property
    def paths(self) -> tuple[str, ...]:
        evaluation_paths = self.evaluation.get("paths")
        if isinstance(evaluation_paths, str):
            return (evaluation_paths,)
        if isinstance(evaluation_paths, list):
            return tuple(str(p) for p in evaluation_paths)
        single = self.evaluation.get("path")
        return (str(single),) if single else ()


@dataclass(frozen=True)
class Baseline:
    baseline_id: str
    version: str
    schema_version: str
    title: str
    description: str
    published_at: str
    reference_policy: str
    references: tuple[Mapping[str, Any], ...]
    thresholds: Mapping[str, Any]
    categories: Mapping[str, Mapping[str, Any]]
    severity_impact: Mapping[str, int]
    controls: tuple[BaselineControl, ...]
    source_path: str

    @property
    def by_id(self) -> dict[str, BaselineControl]:
        return {c.control_id: c for c in self.controls}

    @property
    def total_weight(self) -> int:
        return sum(c.weight for c in self.controls)

    @property
    def risk_likelihood(self) -> float:
        return float(self.thresholds.get("risk_model", {}).get("single_control_likelihood", 0.5))

    def risk_level(self, score: int | float) -> str:
        risk = self.thresholds.get("risk", {})
        if score <= risk.get("low_max", 15):
            return "low"
        if score <= risk.get("moderate_max", 39):
            return "moderate"
        if score <= risk.get("high_max", 69):
            return "high"
        return "critical"

    def posture_band(self, score: int | float) -> str:
        bands = self.thresholds.get("posture_bands", {})
        if score >= bands.get("strong", 90):
            return "strong"
        if score >= bands.get("adequate", 75):
            return "adequate"
        if score >= bands.get("weak", 50):
            return "weak"
        return "critical"

    def as_dict(self) -> dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "version": self.version,
            "schema_version": self.schema_version,
            "title": self.title,
            "description": self.description,
            "published_at": self.published_at,
            "reference_policy": self.reference_policy,
            "references": list(self.references),
            "thresholds": dict(self.thresholds),
            "categories": dict(self.categories),
            "severity_impact": dict(self.severity_impact),
            "control_count": len(self.controls),
            "control_weight_total": self.total_weight,
            "controls": [
                {
                    "control_id": c.control_id,
                    "title": c.title,
                    "category": c.category,
                    "weight": c.weight,
                    "severity": c.severity,
                    "collector": c.collector,
                    "expected_state": c.expected_state,
                    "applicability": dict(c.applicability),
                    "evaluation": dict(c.evaluation),
                    "evidence_paths": list(c.evidence_paths),
                    "rationale": c.rationale,
                    "remediation": dict(c.remediation),
                    "references": list(c.references),
                }
                for c in self.controls
            ],
        }


def validate_pack(pack: Mapping[str, Any]) -> list[str]:
    """Return a list of human-readable problems; empty means the pack is usable."""
    problems: list[str] = []
    for key in ("baseline_id", "version", "title", "controls", "categories", "severity_impact", "thresholds"):
        if key not in pack:
            problems.append(f"missing required key: {key}")
    controls = pack.get("controls") or []
    if not isinstance(controls, list) or not controls:
        problems.append("controls must be a non-empty list")
        return problems

    seen: set[str] = set()
    categories = pack.get("categories") or {}
    severities = pack.get("severity_impact") or {}
    for index, control in enumerate(controls):
        label = control.get("control_id") or f"controls[{index}]"
        if not control.get("control_id"):
            problems.append(f"{label}: missing control_id")
        elif control["control_id"] in seen:
            problems.append(f"{label}: duplicate control_id")
        else:
            seen.add(control["control_id"])
        for key in (
            "title",
            "category",
            "weight",
            "severity",
            "collector",
            "expected_state",
            "applicability",
            "evaluation",
            "rationale",
            "remediation",
            "references",
        ):
            if key not in control:
                problems.append(f"{label}: missing {key}")
        if control.get("category") and control["category"] not in categories:
            problems.append(f"{label}: unknown category {control['category']!r}")
        if control.get("severity") and control["severity"] not in severities:
            problems.append(f"{label}: unknown severity {control['severity']!r}")
        weight = control.get("weight")
        if not isinstance(weight, int) or not 1 <= weight <= 100:
            problems.append(f"{label}: weight must be an int in 1..100")
        evaluation = control.get("evaluation") or {}
        if evaluation.get("op") not in KNOWN_OPS:
            problems.append(f"{label}: unknown evaluation op {evaluation.get('op')!r}")
        # V4 fix (3.3): per-op required-key validation. evaluate_predicate unpacks
        # these keys directly, so a pack that passed the old op-name-only check could
        # blow up per scan/upload with a TypeError instead of failing fast here.
        op = evaluation.get("op")
        if op == "int_between" and ("min" not in evaluation or "max" not in evaluation):
            problems.append(f"{label}: int_between requires integer 'min' and 'max'")
        if op in {"int_at_least", "all_int_at_least"} and "min" not in evaluation:
            problems.append(f"{label}: {op} requires integer 'min'")
        if op == "int_at_most" and "max" not in evaluation:
            problems.append(f"{label}: int_at_most requires integer 'max'")
        if op in {"bool_is", "int_is"} and "value" not in evaluation:
            problems.append(f"{label}: {op} requires 'value'")
        if op == "enum_in" and not evaluation.get("values"):
            problems.append(f"{label}: enum_in requires a non-empty 'values' list")
        if not evaluation.get("paths") and not evaluation.get("path"):
            problems.append(f"{label}: evaluation needs at least one path")
        applicability = control.get("applicability") or {}
        if applicability.get("type") not in KNOWN_APPLICABILITY:
            problems.append(f"{label}: unknown applicability type {applicability.get('type')!r}")
        if applicability.get("type") in {"when_supported", "when_present"} and not applicability.get("paths"):
            problems.append(f"{label}: applicability {applicability.get('type')} needs paths")
        remediation = control.get("remediation") or {}
        for key in ("what_is_wrong", "why_it_matters", "what_should_be_done", "verify"):
            if not remediation.get(key):
                problems.append(f"{label}: remediation.{key} is required")
        if not control.get("references"):
            problems.append(f"{label}: at least one standard reference is required")
    return problems


def _parse_control(raw: Mapping[str, Any]) -> BaselineControl:
    return BaselineControl(
        control_id=str(raw["control_id"]),
        title=str(raw["title"]),
        category=str(raw["category"]),
        weight=int(raw["weight"]),
        severity=str(raw["severity"]),
        collector=str(raw["collector"]),
        expected_state=str(raw["expected_state"]),
        applicability=dict(raw["applicability"]),
        evaluation=dict(raw["evaluation"]),
        evidence_paths=tuple(str(p) for p in raw.get("evidence_paths", [])),
        rationale=str(raw["rationale"]),
        remediation={k: str(v) for k, v in (raw.get("remediation") or {}).items()},
        references=tuple(dict(r) for r in raw.get("references", [])),
    )


@lru_cache(maxsize=4)
def load_baseline(path: str | None = None) -> Baseline:
    """Load and validate the baseline pack. Raises :class:`BaselineError`."""
    resolved = Path(path) if path else settings.baseline_path
    if not resolved.exists():
        raise BaselineError(f"baseline pack not found: {resolved}")
    try:
        pack = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline pack is not valid JSON: {exc}") from exc

    problems = validate_pack(pack)
    if problems:
        raise BaselineError("baseline pack failed validation:\n  - " + "\n  - ".join(problems))

    baseline = Baseline(
        baseline_id=str(pack["baseline_id"]),
        version=str(pack["version"]),
        schema_version=str(pack.get("schema_version", "1.0")),
        title=str(pack["title"]),
        description=str(pack.get("description", "")),
        published_at=str(pack.get("published_at", "")),
        reference_policy=str(pack.get("reference_policy", "")),
        references=tuple(dict(r) for r in pack.get("references", [])),
        thresholds=dict(pack["thresholds"]),
        categories={k: dict(v) for k, v in pack["categories"].items()},
        severity_impact={k: int(v) for k, v in pack["severity_impact"].items()},
        controls=tuple(_parse_control(c) for c in pack["controls"]),
        source_path=str(resolved),
    )
    logger.info(
        "baseline loaded id=%s version=%s controls=%d weight=%d",
        baseline.baseline_id,
        baseline.version,
        len(baseline.controls),
        baseline.total_weight,
    )
    return baseline


def reload_baseline() -> Baseline:
    load_baseline.cache_clear()
    return load_baseline()


# --------------------------------------------------------------------------- effective
@dataclass
class EffectiveControl:
    """A baseline control after global and device-level policy has been applied."""

    spec: BaselineControl
    weight: int
    severity: str
    enabled: bool
    title: str
    remediation: Mapping[str, str]
    sources: dict[str, str] = field(default_factory=dict)
    exempted: bool = False
    exemption_reason: str | None = None
    exemption_expires_at: Any | None = None

    @property
    def control_id(self) -> str:
        return self.spec.control_id

    @property
    def category(self) -> str:
        return self.spec.category

    @property
    def override_applied(self) -> bool:
        return any(
            v != "baseline"
            for k, v in self.sources.items()
            if k in {"weight", "severity", "enabled", "remediation", "title"}
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "category": self.category,
            "weight": self.weight,
            "severity": self.severity,
            "enabled": self.enabled,
            "baseline_weight": self.spec.weight,
            "baseline_severity": self.spec.severity,
            "expected_state": self.spec.expected_state,
            "collector": self.spec.collector,
            "rationale": self.spec.rationale,
            "remediation": dict(self.remediation),
            "references": list(self.spec.references),
            "sources": dict(self.sources),
            "exempted": self.exempted,
            "exemption_reason": self.exemption_reason,
        }


@dataclass
class EffectiveSet:
    baseline: Baseline
    controls: tuple[EffectiveControl, ...]

    @property
    def by_id(self) -> dict[str, EffectiveControl]:
        return {c.control_id: c for c in self.controls}

    @property
    def total_weight(self) -> int:
        return sum(c.weight for c in self.controls if c.enabled and not c.exempted)

    def version(self) -> str:
        return self.baseline.version


def resolve_effective(
    baseline: Baseline,
    overrides: Iterable[Any] | None = None,
    exemptions: Iterable[Any] | None = None,
) -> EffectiveSet:
    """Layer global overrides and device exemptions onto the baseline."""
    override_map: dict[str, Any] = {}
    for override in overrides or ():
        key = getattr(override, "control_id", None) or getattr(override, "rule_key", None)
        if key:
            override_map[str(key)] = override

    exemption_map: dict[str, Any] = {}
    for exemption in exemptions or ():
        key = getattr(exemption, "control_id", None)
        if key:
            exemption_map[str(key)] = exemption

    resolved: list[EffectiveControl] = []
    for spec in baseline.controls:
        sources = {
            "weight": "baseline",
            "severity": "baseline",
            "enabled": "baseline",
            "title": "baseline",
            "remediation": "baseline",
        }
        weight, severity = spec.weight, spec.severity
        enabled = True
        title = spec.title
        remediation = dict(spec.remediation)

        override = override_map.get(spec.control_id)
        if override is not None:
            if getattr(override, "weight", None):
                weight = int(override.weight)
                sources["weight"] = "override"
            if getattr(override, "severity", None):
                severity = str(override.severity)
                sources["severity"] = "override"
            if getattr(override, "is_enabled", None) is not None:
                enabled = bool(override.is_enabled)
                sources["enabled"] = "override"
            if getattr(override, "name", None):
                title = str(override.name)
                sources["title"] = "override"
            if getattr(override, "recommendation_template", None):
                remediation = {**remediation, "what_should_be_done": str(override.recommendation_template)}
                sources["remediation"] = "override"

        exemption = exemption_map.get(spec.control_id)
        exempted = exemption is not None
        if exempted:
            sources["enabled"] = "device-exemption"

        resolved.append(
            EffectiveControl(
                spec=spec,
                weight=weight,
                severity=severity,
                enabled=enabled,
                title=title,
                remediation=remediation,
                sources=sources,
                exempted=exempted,
                exemption_reason=getattr(exemption, "reason", None),
                exemption_expires_at=getattr(exemption, "expires_at", None),
            )
        )
    return EffectiveSet(baseline=baseline, controls=tuple(resolved))
