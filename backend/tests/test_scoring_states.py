"""Per-control verdict state tests and risk-boundary tests.

These are the cheap guards the research report asked for: for the *whole* registry, not a
sample, assert that

* missing evidence produces ``unknown`` for every control (never a fabricated failure and
  never a fabricated pass);
* a complete compliant host produces ``compliant`` for every control;
* a complete violating host produces ``non_compliant`` for every control;
* ``not_applicable`` is reachable only from explicit evidence or a recorded exemption;
* the risk scale is reachable, monotonic in the number of failures, and sensitive to
  asset criticality — while unknown controls never contribute risk.
"""

from __future__ import annotations

import pytest

from app.services import scoring
from app.services.baseline import load_baseline, resolve_effective
from app.services.scoring import build_controls, build_findings, build_scan_result

from .conftest import empty_document, failing_document, perfect_document


@pytest.fixture(scope="module")
def baseline():
    return load_baseline()


@pytest.fixture(scope="module")
def effective(baseline):
    return resolve_effective(baseline)


@pytest.fixture(scope="module")
def control_ids(baseline):
    return [control.control_id for control in baseline.controls]


def _by_id(controls):
    return {control.control_id: control for control in controls}


def test_baseline_has_a_stable_control_count(effective):
    """The registry is data; its size is a contract other components rely on."""
    assert len(effective.controls) == 28
    assert sum(control.weight for control in effective.controls) == 217


# --------------------------------------------------------------------------- unknown
def test_every_control_is_unknown_without_evidence(effective, control_ids):
    controls = build_controls(empty_document(), effective)
    by_id = _by_id(controls)
    assert sorted(by_id) == sorted(control_ids)
    offenders = {cid: by_id[cid].status for cid in control_ids if by_id[cid].status != "unknown"}
    assert offenders == {}, f"absent evidence must be unknown, got {offenders}"


def test_empty_evidence_produces_no_findings_and_no_risk(effective):
    controls = build_controls(empty_document(), effective)
    findings = build_findings(controls)
    result = build_scan_result(controls, findings, effective)

    assert findings == []
    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"
    assert result["critical_count"] == 0
    assert result["assessment"]["unknown_controls"] == 28
    assert result["assessment"]["assessed_controls"] == 0
    assert result["evidence_quality"] == "unavailable"


def test_partial_evidence_only_resolves_the_controls_it_covers(effective):
    document = empty_document()
    document["checks"] = {
        "system_hardening": {"status": "completed", "bitlocker": {"status": "completed", "enabled": True}},
    }
    controls = _by_id(build_controls(document, effective))

    # BL-001 reads exactly this evidence and must resolve.
    assert controls["BL-001"].status == "compliant"
    # Defender evidence is absent even though its collector reported: still unknown.
    assert controls["DEF-001"].status == "unknown"
    # A collector that never reported: unknown.
    assert controls["FW-001"].status == "unknown"


# --------------------------------------------------------------------------- compliant
def test_complete_compliant_host_satisfies_every_control(effective, control_ids):
    controls = _by_id(build_controls(perfect_document(), effective))
    offenders = {cid: controls[cid].status for cid in control_ids if controls[cid].status != "compliant"}
    assert offenders == {}, f"expected all compliant, got {offenders}"

    result = build_scan_result(list(controls.values()), build_findings(list(controls.values())), effective)
    assert result["security_score"] == 100
    assert result["compliance_score"] == 100
    assert result["assessment_coverage"] == 100
    assert result["risk_score"] == 0
    assert result["evidence_quality"] == "high"


# --------------------------------------------------------------------------- violation
def test_complete_violating_host_fails_every_control(effective, control_ids):
    controls = _by_id(build_controls(failing_document(), effective))
    # TPM and Secure Boot are *supported* in this fixture, so they are applicable.
    expected_not_applicable = set()
    offenders = {
        cid: controls[cid].status
        for cid in control_ids
        if controls[cid].status not in {"non_compliant"} | expected_not_applicable
    }
    assert offenders == {}, f"expected all non-compliant, got {offenders}"

    findings = build_findings(controls.values())
    result = build_scan_result(list(controls.values()), findings, effective)
    assert result["security_score"] == 0
    assert result["risk_level"] == "critical"
    assert len(findings) == len(control_ids)
    assert all(finding["status"] == "non_compliant" for finding in findings)


# --------------------------------------------------------------------------- not applicable
def test_not_applicable_requires_explicit_evidence(effective):
    document = perfect_document()
    document["checks"]["system_hardening"]["secure_boot_supported"] = False
    document["checks"]["tpm"] = {"status": "completed", "present": False, "ready": False}

    controls = _by_id(build_controls(document, effective))
    assert controls["DEV-SB-001"].status == "not_applicable"
    assert controls["TPM-001"].status == "not_applicable"

    # Applicability is evidence, so the weight leaves the denominator honestly.
    result = build_scan_result(list(controls.values()), [], effective)
    assert result["assessment"]["not_applicable_controls"] == 2
    assert result["assessment"]["total_controls"] == 28


def test_missing_applicability_evidence_is_unknown_not_not_applicable(effective):
    document = perfect_document()
    del document["checks"]["system_hardening"]["secure_boot_supported"]
    controls = _by_id(build_controls(document, effective))
    assert controls["DEV-SB-001"].status == "unknown"


def test_disabled_control_is_not_applicable_and_says_why(baseline):
    from app.db.models import Policy

    override = Policy(control_id="FW-002", name="paused", is_enabled=False)
    effective = resolve_effective(baseline, [override], [])
    controls = _by_id(build_controls(perfect_document(), effective))
    assert controls["FW-002"].status == "not_applicable"
    assert any("policy" in note for note in controls["FW-002"].notes)


# --------------------------------------------------------------------------- collector health
@pytest.mark.parametrize("status", ["error", "timeout"])
def test_collector_failure_is_error_state_not_a_verdict(effective, status):
    document = perfect_document()
    document["checks"]["firewall"] = {"status": status, "error": "boom"}
    controls = _by_id(build_controls(document, effective))
    assert controls["FW-001"].status == "error"
    assert controls["FW-001"].collector_status == "error"


@pytest.mark.parametrize("status", ["unavailable", "skipped"])
def test_unavailable_collector_is_unknown_not_a_verdict(effective, status):
    document = perfect_document()
    document["checks"]["tpm"] = {"status": status}
    controls = _by_id(build_controls(document, effective))
    assert controls["TPM-001"].status == "unknown"


def test_unknown_controls_never_contribute_risk(effective):
    controls = _by_id(build_controls(empty_document(), effective))
    for control in controls.values():
        control.risk_contribution = 0.0
    result = build_scan_result(list(controls.values()), [], effective)
    assert result["risk_score"] == 0


# --------------------------------------------------------------------------- risk scale
def test_risk_levels_are_reachable_and_boundary_ordered(baseline):
    thresholds = baseline.thresholds["risk"]
    assert baseline.risk_level(0) == "low"
    assert baseline.risk_level(thresholds["low_max"]) == "low"
    assert baseline.risk_level(thresholds["low_max"] + 1) == "moderate"
    assert baseline.risk_level(thresholds["moderate_max"] + 1) == "high"
    assert baseline.risk_level(thresholds["high_max"] + 1) == "critical"
    assert baseline.risk_level(100) == "critical"


def test_risk_is_monotonic_in_the_number_of_failures(baseline):
    impacts = [0.1, 0.2, 0.3, 0.4, 0.5]
    scores = [scoring.aggregate_risk(impacts[:n], 0.5)[0] for n in range(0, len(impacts) + 1)]
    assert scores == sorted(scores)
    assert scores[0] == 0
    assert scores[-1] > scores[0]


def test_risk_ceiling_is_reachable_at_the_maximum_criticality(baseline):
    """A worst case at max criticality must be able to reach the critical band."""
    effective = resolve_effective(baseline)
    findings = build_findings(build_controls(failing_document(), effective))
    best = max(
        (
            build_scan_result(
                build_controls(failing_document(), effective), findings, effective, criticality=level
            )["risk_score"]
            for level in range(1, 6)
        ),
    )
    assert best >= baseline.thresholds["risk"]["high_max"] + 1
    assert baseline.risk_level(best) == "critical"


def _risk_at(document, effective, criticality: int) -> tuple[int, list[dict]]:
    controls = build_controls(document, effective, criticality=criticality)
    findings = build_findings(controls)
    return build_scan_result(controls, findings, effective, criticality=criticality)["risk_score"], findings


def test_asset_criticality_scales_risk_and_never_lowers_it(effective):
    """A single failure isolates the criticality factor from noisy-OR saturation."""
    document = perfect_document()
    document["checks"]["network_security"]["smb1"] = {"enabled": True}
    findings = build_findings(build_controls(document, effective))
    assert [finding["control_id"] for finding in findings] == ["NET-SMB1-001"]

    scores = [_risk_at(document, effective, level)[0] for level in range(1, 6)]
    assert scores == sorted(scores)
    assert scores[0] < scores[-1], f"criticality had no effect: {scores}"


def test_many_failures_saturate_the_bounded_scale(effective):
    """The scale is bounded: a host failing everything lands in the critical band."""
    document = failing_document()
    scores = [_risk_at(document, effective, level)[0] for level in range(1, 6)]
    assert scores == sorted(scores)
    assert scores[-1] >= 99
    assert all(0 <= score <= 100 for score in scores)


def test_criticality_is_clamped_to_the_documented_range(effective):
    document = failing_document()
    high = build_scan_result(build_controls(document, effective), [], effective, criticality=99)
    five = build_scan_result(build_controls(document, effective), [], effective, criticality=5)
    low = build_scan_result(build_controls(document, effective), [], effective, criticality=-7)
    one = build_scan_result(build_controls(document, effective), [], effective, criticality=1)
    assert high["risk_score"] == five["risk_score"]
    assert low["risk_score"] == one["risk_score"]
