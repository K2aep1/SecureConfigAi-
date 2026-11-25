"""The versioned Global Security Baseline: loading, validation and effective resolution.

The baseline is *data*. This module validates it at load time so a malformed pack fails
loudly instead of producing silent verdicts. It then resolves the effective control set
by layering, highest priority last:

1. **baseline**: shipped, versioned, and integrity-checked by SHA-256 at load time.
2. **global override**: a ``policies`` row managed by an administrator (weight,
   severity, enable/disable, remediation text). Values are validated before use.
3. **device exemption**: a documented, per-device decision to accept a deviation. An
   exemption that has passed its ``expires_at`` is ignored.

Every resolved field records which layer supplied it, so the API can explain why a
control has the weight it has. Overrides that reference a control the baseline no
longer contains are reported in ``EffectiveSet.orphaned_overrides``, not dropped.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import settings

logger = logging.getLogger("secureconfigai.baseline")

KNOWN_OPS = frozenset(
    {
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
)
KNOWN_APPLICABILITY = frozenset({"always", "when_supported", "when_present"})
CONTROL_STATES = frozenset({"compliant", "non_compliant", "not_applicable", "unknown", "error"})
# The states a control may declare as its expected result. The scanner produces the
# rest; a control cannot expect them.
EXPECTABLE_STATES = frozenset({"compliant"})

REQUIRED_PACK_KEYS = (
    "baseline_id",
    "version",
    "title",
    "controls",
    "categories",
    "severity_impact",
    "thresholds",
)
REQUIRED_CONTROL_KEYS = (
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
)
REQUIRED_REMEDIATION_KEYS = ("what_is_wrong", "why_it_matters", "what_should_be_done", "verify")
REQUIRED_THRESHOLDS = {
    "risk": ("low_max", "moderate_max", "high_max"),
    "posture_bands": ("weak", "adequate", "strong"),
    "risk_model": ("single_control_likelihood",),
}
OVERRIDABLE_FIELDS = frozenset({"weight", "severity", "is_enabled", "name", "recommendation_template"})


class BaselineError(RuntimeError):
    """The baseline pack, or a value derived from it, is unusable."""


# --------------------------------------------------------------------------- model
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
    content_sha256: str = ""

    @property
    def by_id(self) -> dict[str, BaselineControl]:
        return {control.control_id: control for control in self.controls}

    @property
    def total_weight(self) -> int:
        return sum(c.weight for c in self.controls)

    @property
    def risk_likelihood(self) -> float:
        return float(self.thresholds["risk_model"]["single_control_likelihood"])

    def risk_level(self, score: int | float) -> str:
        risk = self.thresholds["risk"]
        if score <= risk["low_max"]:
            return "low"
        if score <= risk["moderate_max"]:
            return "moderate"
        if score <= risk["high_max"]:
            return "high"
        return "critical"

    def posture_band(self, score: int | float) -> str:
        bands = self.thresholds["posture_bands"]
        if score >= bands["strong"]:
            return "strong"
        if score >= bands["adequate"]:
            return "adequate"
        if score >= bands["weak"]:
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
            "content_sha256": self.content_sha256,
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


# --------------------------------------------------------------------------- validation
def validate_thresholds(pack: Mapping[str, Any]) -> list[str]:
    """Every threshold the scoring engine reads must exist and be ordered sensibly."""
    problems: list[str] = []
    thresholds = pack.get("thresholds")
    if not isinstance(thresholds, Mapping):
        return ["thresholds must be an object"]

    for section, keys in REQUIRED_THRESHOLDS.items():
        block = thresholds.get(section)
        if not isinstance(block, Mapping):
            problems.append(f"thresholds.{section} is required")
            continue
        for key in keys:
            if key not in block:
                problems.append(f"thresholds.{section}.{key} is required")

    def valid_number(value: Any) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    risk = thresholds.get("risk")
    if isinstance(risk, Mapping) and all(k in risk for k in REQUIRED_THRESHOLDS["risk"]):
        values = [risk[k] for k in REQUIRED_THRESHOLDS["risk"]]
        if not all(valid_number(value) for value in values):
            problems.append("thresholds.risk bounds must be numbers")
        elif not values[0] < values[1] < values[2]:
            problems.append("thresholds.risk bounds must be strictly increasing")

    bands = thresholds.get("posture_bands")
    if isinstance(bands, Mapping) and all(k in bands for k in REQUIRED_THRESHOLDS["posture_bands"]):
        values = [bands[k] for k in REQUIRED_THRESHOLDS["posture_bands"]]
        if not all(valid_number(value) for value in values):
            problems.append("thresholds.posture_bands must be numbers")
        elif not values[0] < values[1] < values[2]:
            problems.append("thresholds.posture_bands must be strictly increasing")

    model = thresholds.get("risk_model")
    if isinstance(model, Mapping) and "single_control_likelihood" in model:
        likelihood = model["single_control_likelihood"]
        if isinstance(likelihood, bool) or not isinstance(likelihood, (int, float)) or not 0 < likelihood <= 1:
            problems.append("thresholds.risk_model.single_control_likelihood must be a number in (0, 1]")
    return problems


def _check_op_arguments(label: str, op: str, evaluation: Mapping[str, Any]) -> list[str]:
    """Each op reads specific keys. Check them here so evaluation cannot fail per scan."""
    problems: list[str] = []
    if op == "int_between" and ("min" not in evaluation or "max" not in evaluation):
        problems.append(f"{label}: int_between requires 'min' and 'max'")
    if op in {"int_at_least", "all_int_at_least"} and "min" not in evaluation:
        problems.append(f"{label}: {op} requires 'min'")
    if op == "int_at_most" and "max" not in evaluation:
        problems.append(f"{label}: int_at_most requires 'max'")
    if op in {"bool_is", "int_is"} and "value" not in evaluation:
        problems.append(f"{label}: {op} requires 'value'")
    if op == "enum_in" and not evaluation.get("values"):
        problems.append(f"{label}: enum_in requires a non-empty 'values' list")
    return problems


def validate_pack(pack: Mapping[str, Any]) -> list[str]:
    """Return human-readable problems. An empty list means the pack is usable."""
    problems: list[str] = []
    for key in REQUIRED_PACK_KEYS:
        if key not in pack:
            problems.append(f"missing required key: {key}")

    controls = pack.get("controls")
    if not isinstance(controls, list) or not controls:
        problems.append("controls must be a non-empty list")
        return problems

    problems.extend(validate_thresholds(pack))

    categories = pack.get("categories") if isinstance(pack.get("categories"), Mapping) else {}
    severities = pack.get("severity_impact") if isinstance(pack.get("severity_impact"), Mapping) else {}
    seen: set[str] = set()

    for index, control in enumerate(controls):
        if not isinstance(control, Mapping):
            problems.append(f"controls[{index}]: must be an object")
            continue

        control_id = control.get("control_id")
        label = str(control_id) if control_id else f"controls[{index}]"
        if not control_id:
            problems.append(f"{label}: missing control_id")
        elif str(control_id) in seen:
            problems.append(f"{label}: duplicate control_id")
        else:
            seen.add(str(control_id))

        for key in REQUIRED_CONTROL_KEYS:
            if key not in control:
                problems.append(f"{label}: missing {key}")

        if control.get("category") and control["category"] not in categories:
            problems.append(f"{label}: unknown category {control['category']!r}")
        if control.get("severity") and control["severity"] not in severities:
            problems.append(f"{label}: unknown severity {control['severity']!r}")

        weight = control.get("weight")
        if isinstance(weight, bool):
            problems.append(f"{label}: weight must be an int, not a bool")
        elif not isinstance(weight, int) or not 1 <= weight <= 100:
            problems.append(f"{label}: weight must be an int in 1..100")

        # expected_state is a descriptive security expectation,
        # not a scanner-generated control status.
        expected = control.get("expected_state")
        if not isinstance(expected, str) or not expected.strip():
            problems.append(
                f"{label}: expected_state must be a non-empty string"
            )

        evaluation = control.get("evaluation") if isinstance(control.get("evaluation"), Mapping) else {}
        op = evaluation.get("op")
        if op not in KNOWN_OPS:
            problems.append(f"{label}: unknown evaluation op {op!r}")
        else:
            problems.extend(_check_op_arguments(label, str(op), evaluation))
        if not evaluation.get("paths") and not evaluation.get("path"):
            problems.append(f"{label}: evaluation needs at least one path")

        applicability = control.get("applicability") if isinstance(control.get("applicability"), Mapping) else {}
        app_type = applicability.get("type")
        if app_type not in KNOWN_APPLICABILITY:
            problems.append(f"{label}: unknown applicability type {app_type!r}")
        elif app_type in {"when_supported", "when_present"} and not applicability.get("paths"):
            problems.append(f"{label}: applicability {app_type} needs paths")

        remediation = control.get("remediation") if isinstance(control.get("remediation"), Mapping) else {}
        for key in REQUIRED_REMEDIATION_KEYS:
            if not remediation.get(key):
                problems.append(f"{label}: remediation.{key} is required")

        if not control.get("references"):
            problems.append(f"{label}: at least one standard reference is required")
    return problems


def validate_override_values(
    *,
    weight: int | None = None,
    severity: str | None = None,
    severity_impact: Mapping[str, int],
) -> None:
    """Reject override values the scoring engine cannot interpret.

    Call this when an override is saved, so invalid values fail at write time rather
    than during scoring.
    """
    if weight is not None:
        if isinstance(weight, bool) or not isinstance(weight, int) or not 1 <= weight <= 100:
            raise BaselineError("override weight must be an integer in 1..100")
    if severity is not None and severity not in severity_impact:
        raise BaselineError(f"override severity {severity!r} is not a known severity")


# --------------------------------------------------------------------------- loading
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
        remediation={k: str(v) for k, v in dict(raw["remediation"]).items()},
        references=tuple(dict(r) for r in raw["references"]),
    )


@lru_cache(maxsize=4)
def load_baseline(path: str | None = None) -> Baseline:
    """Load, validate and fingerprint the baseline pack. Raises :class:`BaselineError`."""
    resolved = Path(path) if path else settings.baseline_path
    if not resolved.exists():
        raise BaselineError(f"baseline pack not found: {resolved}")

    try:
        raw_bytes = resolved.read_bytes()
        pack = json.loads(raw_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineError(f"baseline pack could not be read as UTF-8 JSON: {exc}") from exc
    if not isinstance(pack, dict):
        raise BaselineError("baseline pack must be a JSON object")

    problems = validate_pack(pack)
    if problems:
        raise BaselineError("baseline pack failed validation:\n  - " + "\n  - ".join(problems))

    controls = tuple(_parse_control(c) for c in pack["controls"])
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
        controls=controls,
        source_path=str(resolved),
        content_sha256=hashlib.sha256(raw_bytes).hexdigest(),
    )
    logger.info(
        "baseline loaded id=%s version=%s sha256=%s controls=%d weight=%d",
        baseline.baseline_id,
        baseline.version,
        baseline.content_sha256[:12],
        len(baseline.controls),
        baseline.total_weight,
    )
    return baseline


def reload_baseline() -> Baseline:
    load_baseline.cache_clear()
    return load_baseline()


# --------------------------------------------------------------------------- effective
def _aware(value: datetime) -> datetime:
    """Database timestamps can come back naive (SQLite). Treat them as UTC."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


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
    exemption_expires_at: datetime | None = None

    @property
    def control_id(self) -> str:
        return self.spec.control_id

    @property
    def category(self) -> str:
        return self.spec.category

    @property
    def override_applied(self) -> bool:
        return any(
            value != "baseline"
            for key, value in self.sources.items()
            if key in OVERRIDABLE_FIELDS or key in {"weight", "severity", "enabled", "remediation", "title"}
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
            "exemption_expires_at": (
                self.exemption_expires_at.isoformat() if self.exemption_expires_at else None
            ),
        }


@dataclass
class EffectiveSet:
    baseline: Baseline
    controls: tuple[EffectiveControl, ...]
    orphaned_overrides: tuple[str, ...] = ()

    @property
    def by_id(self) -> dict[str, EffectiveControl]:
        return {c.control_id: c for c in self.controls}

    @property
    def total_weight(self) -> int:
        return sum(c.weight for c in self.controls if c.enabled and not c.exempted)

    def version(self) -> str:
        """Return the baseline version (kept callable for existing scan-service callers)."""
        return self.baseline.version


def _apply_override(
    spec: BaselineControl,
    override: Any,
    severity_impact: Mapping[str, int],
    sources: dict[str, str],
) -> tuple[int, str, bool, str, Mapping[str, str]]:
    """Return (weight, severity, enabled, title, remediation) after one override."""
    weight, severity = spec.weight, spec.severity
    enabled = True
    title = spec.title
    remediation: Mapping[str, str] = dict(spec.remediation)

    new_weight = getattr(override, "weight", None)
    if new_weight is not None:
        validate_override_values(weight=new_weight, severity_impact=severity_impact)
        weight = new_weight
        sources["weight"] = "override"

    new_severity = getattr(override, "severity", None)
    if new_severity is not None:
        validate_override_values(severity=str(new_severity), severity_impact=severity_impact)
        severity = str(new_severity)
        sources["severity"] = "override"

    is_enabled = getattr(override, "is_enabled", None)
    if is_enabled is not None:
        enabled = bool(is_enabled)
        sources["enabled"] = "override"

    name = getattr(override, "name", None)
    if name:
        title = str(name)
        sources["title"] = "override"

    template = getattr(override, "recommendation_template", None)
    if template:
        remediation = {**remediation, "what_should_be_done": str(template)}
        sources["remediation"] = "override"

    return weight, severity, enabled, title, remediation


def resolve_effective(
    baseline: Baseline,
    overrides: Iterable[Any] | None = None,
    exemptions: Iterable[Any] | None = None,
    *,
    now: datetime | None = None,
) -> EffectiveSet:
    """Layer global overrides and live device exemptions onto the baseline.

    Expired exemptions are ignored, and the check uses ``now`` so callers can pin time
    in tests. Overrides for controls the baseline no longer contains are returned in
    ``orphaned_overrides`` and logged.
    """
    current = now or datetime.now(UTC)
    known = baseline.by_id

    override_map: dict[str, Any] = {}
    orphaned: set[str] = set()
    for override in overrides or ():
        key = str(getattr(override, "control_id", "") or "")
        if not key:
            continue
        if key in known:
            override_map[key] = override
        else:
            orphaned.add(key)

    exemption_map: dict[str, Any] = {}
    for exemption in exemptions or ():
        key = str(getattr(exemption, "control_id", "") or "")
        expires = getattr(exemption, "expires_at", None)
        if not key:
            continue
        if expires is not None and _aware(expires) <= current:
            continue  # lapsed: the deviation is no longer accepted
        exemption_map[key] = exemption

    resolved: list[EffectiveControl] = []
    for spec in baseline.controls:
        sources = {
            "weight": "baseline",
            "severity": "baseline",
            "enabled": "baseline",
            "title": "baseline",
            "remediation": "baseline",
            "exemption": "none",
        }
        weight, severity, enabled, title, remediation = spec.weight, spec.severity, True, spec.title, dict(spec.remediation)

        override = override_map.get(spec.control_id)
        if override is not None:
            weight, severity, enabled, title, remediation = _apply_override(
                spec, override, baseline.severity_impact, sources
            )

        exemption = exemption_map.get(spec.control_id)
        exempted = exemption is not None
        if exempted:
            sources["exemption"] = "device-exemption"

        expires = getattr(exemption, "expires_at", None) if exempted else None
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
                exemption_reason=getattr(exemption, "reason", None) if exempted else None,
                exemption_expires_at=_aware(expires) if expires is not None else None,
            )
        )

    if orphaned:
        logger.warning(
            "overrides reference controls not in baseline %s: %s",
            baseline.version,
            sorted(orphaned),
        )
    return EffectiveSet(
        baseline=baseline,
        controls=tuple(resolved),
        orphaned_overrides=tuple(sorted(orphaned)),
    )
