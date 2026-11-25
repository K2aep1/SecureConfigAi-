"""Baseline and decision-engine tests.

These are the tests that guard the correctness rules the previous implementation broke:
absence of evidence must produce ``unknown`` (never a fabricated failure), the risk scale
must be reachable, and asset criticality must actually influence the score.
"""

from __future__ import annotations

import pytest

from app.services import scoring
from app.services.baseline import (
    BaselineError,
    load_baseline,
    resolve_effective,
    validate_pack,
)
from app.services.scoring import (
    aggregate_risk,
    build_controls,
    build_findings,
    build_scan_result,
    evaluate_predicate,
    explain_risk,
    resolve_path,
)

from .conftest import (
    empty_document,
    failing_document,
    perfect_document,
)


@pytest.fixture(scope="module")
def baseline():
    return load_baseline()


@pytest.fixture(scope="module")
def effective(baseline):
    return resolve_effective(baseline)


# --------------------------------------------------------------------------- baseline pack
def test_baseline_pack_is_complete(baseline):
    assert len(baseline.controls) >= 25
    assert baseline.total_weight == sum(c.weight for c in baseline.controls)
    ids = [c.control_id for c in baseline.controls]
    assert len(ids) == len(set(ids))
    for control in baseline.controls:
        assert control.references, f"{control.control_id} has no standard reference"
        assert control.remediation.get("what_should_be_done")
        assert control.remediation.get("verify")
        assert control.rationale
        assert control.category in baseline.categories
        assert control.severity in baseline.severity_impact
        assert 1 <= control.weight <= 100


def test_baseline_references_name_real_standards(baseline):
    standards = {reference["standard"] for control in baseline.controls for reference in control.references}
    assert {"cis-controls-v8.1", "ms-security-baseline", "nist-sp-800-53r5"} <= standards
    for reference in baseline.references:
        assert reference["url"].startswith("https://")


@pytest.mark.parametrize(
    "mutate,expected",
    [
        (lambda pack: pack["controls"][0].pop("control_id"), "control_id"),
        (lambda pack: pack["controls"][0].update({"category": "Nonsense"}), "unknown category"),
        (lambda pack: pack["controls"][0].update({"evaluation": {"op": "magic"}}), "unknown evaluation op"),
        (
            lambda pack: pack["controls"][0].update({"applicability": {"type": "maybe"}}),
            "unknown applicability",
        ),
        (lambda pack: pack["controls"][0].update({"remediation": {}}), "remediation"),
        (lambda pack: pack["controls"][0].update({"references": []}), "reference"),
        (lambda pack: pack["controls"].append(dict(pack["controls"][0])), "duplicate"),
    ],
)
def test_validate_pack_rejects_broken_packs(baseline, mutate, expected):
    import json

    pack = json.loads(json.dumps(baseline.as_dict()))
    mutate(pack)
    problems = validate_pack(pack)
    assert any(expected in problem for problem in problems), problems


# --------------------------------------------------------------------------- path resolver
def test_resolve_path_fans_out_over_lists_and_dicts():
    document = {
        "checks": {
            "firewall": {
                "profiles": [{"enabled": True}, {"enabled": False}],
                "logging": {"Domain": {"LogBlocked": True}, "Public": {"LogBlocked": False}},
            }
        }
    }
    assert resolve_path(document, "checks.firewall.profiles[*].enabled") == [True, False]
    assert resolve_path(document, "checks.firewall.logging[*].LogBlocked") == [True, False]
    assert resolve_path(document, "checks.missing.key") == []
    assert resolve_path(document, "checks.firewall") == [document["checks"]["firewall"]]


# --------------------------------------------------------------------------- predicates
@pytest.mark.parametrize(
    "value,expected",
    [
        (True, "compliant"),
        (False, "non_compliant"),
        (None, "unknown"),
        ("true", "unknown"),
        (1, "unknown"),
        ([], "unknown"),
    ],
)
def test_bool_is_requires_a_real_boolean(value, expected):
    status, _ = evaluate_predicate("bool_is", [value], {"value": True})
    assert status == expected


@pytest.mark.parametrize(
    "values,expected",
    [
        ([True, True], "compliant"),
        ([True, False], "non_compliant"),
        ([True, None], "unknown"),
        ([], "unknown"),
        ([True, 1], "unknown"),
    ],
)
def test_all_bool_true_rejects_non_booleans(values, expected):
    status, _ = evaluate_predicate("all_bool_true", values, {})
    assert status == expected


@pytest.mark.parametrize(
    "op,values,params,expected",
    [
        ("int_between", [10], {"min": 1, "max": 10}, "compliant"),
        ("int_between", [0], {"min": 1, "max": 10}, "non_compliant"),
        ("int_at_least", [14], {"min": 14}, "compliant"),
        ("int_at_least", [13], {"min": 14}, "non_compliant"),
        ("int_at_most", [30], {"max": 30}, "compliant"),
        ("int_at_most", [31], {"max": 30}, "non_compliant"),
        ("int_is", [2], {"value": 2}, "compliant"),
        ("int_is", [True], {"value": 1}, "unknown"),  # bool is not an integer here
        ("int_is", ["2"], {"value": 2}, "unknown"),  # strings are not coerced
        ("int_at_least", [None], {"min": 1}, "unknown"),
        ("all_int_at_least", [1, 1, 1], {"min": 1}, "compliant"),
        ("all_int_at_least", [1, 0, 1], {"min": 1}, "non_compliant"),
        ("all_int_at_least", [1, None, 1], {"min": 1}, "unknown"),
        ("enum_in", ["Block"], {"values": ["block"]}, "compliant"),
        ("enum_in", ["Allow"], {"values": ["block"]}, "non_compliant"),
        ("enum_in", [None], {"values": ["block"]}, "unknown"),
        ("list_empty", [[]], {}, "compliant"),
        ("list_empty", [[{"name": "svc"}]], {}, "non_compliant"),
        ("list_empty", [None], {}, "unknown"),
    ],
)
def test_predicate_operators(op, values, params, expected):
    status, _ = evaluate_predicate(op, values, params)
    assert status == expected


# --------------------------------------------------------------------------- engine
def test_empty_evidence_produces_no_findings_and_no_risk(effective):
    controls = build_controls(empty_document(), effective, criticality=3)
    findings = build_findings(controls)
    result = build_scan_result(controls, findings, effective, criticality=3)

    assert {c.status for c in controls} == {"unknown"}
    assert findings == []
    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"
    assert result["assessment_coverage"] == 0
    assert result["security_score"] == 0
    assert result["evidence_quality"] == "unavailable"


def test_collector_errors_map_to_error_state(effective):
    document = {
        "checks": {c.spec.collector: {"status": "error", "error": "boom"} for c in effective.controls}
    }
    controls = build_controls(document, effective, criticality=3)
    assert {c.status for c in controls} == {"error"}
    assert all("boom" in " ".join(c.notes) for c in controls)
    result = build_scan_result(controls, build_findings(controls), effective, criticality=3)
    assert result["risk_score"] == 0
    assert result["assessment"]["error_controls"] == len(controls)


def test_perfect_host_scores_full_marks(effective):
    controls = build_controls(perfect_document(), effective, criticality=3)
    findings = build_findings(controls)
    result = build_scan_result(controls, findings, effective, criticality=3)

    assert result["security_score"] == 100
    assert result["compliance_score"] == 100
    assert result["assessment_coverage"] == 100
    assert result["risk_score"] == 0
    assert result["evidence_quality"] == "high"
    assert findings == []
    assert all(c.status == "compliant" for c in controls)


def test_failing_host_produces_expected_controls_and_reachable_risk(effective):
    controls = build_controls(failing_document(), effective, criticality=3)
    failing = {c.control_id for c in controls if c.status == "non_compliant"}
    assert {
        "FW-001",
        "FW-002",
        "BL-001",
        "DEF-001",
        "AUTH-001",
        "NET-SMB1-001",
        "NET-SMB-SIGN-001",
        "PATCH-001",
        "ACCT-001",
        "SVC-001",
        "ACL-001",
        "REG-WDIGEST-001",
        "REG-LLMNR-001",
        "REG-AUTORUN-001",
        "REG-NETLOGON-001",
        "REG-LMCOMPAT-001",
        "REG-PSLOGGING-001",
    } <= failing
    result = build_scan_result(controls, build_findings(controls), effective, criticality=3)
    assert result["security_score"] == 0
    assert result["risk_score"] >= 70, "the critical band must be reachable"
    assert result["risk_level"] == "critical"
    assert 0 <= result["risk_score"] <= 100


def test_absent_defender_evidence_is_unknown_not_failure(effective):
    """Regression: the previous engine reported DEF-001 as non-compliant with no data."""
    document = perfect_document()
    document["checks"]["system_hardening"] = {
        "status": "completed",
        "bitlocker": {"status": "completed", "enabled": True},
        "uac_enabled": True,
        "secure_boot": True,
        "secure_boot_supported": True,
    }
    controls = {c.control_id: c for c in build_controls(document, effective, criticality=3)}
    for control_id in ("DEF-001", "DEF-002", "DEF-003"):
        assert controls[control_id].status == "unknown", control_id
    assert build_findings(list(controls.values())) == []


def test_unreadable_values_are_unknown_not_false(effective):
    document = perfect_document()
    document["checks"]["system_hardening"]["bitlocker"] = {
        "status": "unavailable",
        "enabled": None,
        "error": "Access denied",
    }
    document["checks"]["tpm"] = {"status": "unavailable", "present": None, "ready": None}
    controls = {c.control_id: c for c in build_controls(document, effective, criticality=3)}
    assert controls["BL-001"].status == "unknown"
    assert controls["TPM-001"].status == "unknown"


def test_not_applicable_requires_explicit_evidence(effective):
    document = perfect_document()
    document["checks"]["system_hardening"]["secure_boot_supported"] = False
    document["checks"]["system_hardening"]["secure_boot"] = None
    document["checks"]["tpm"] = {"status": "completed", "present": False, "ready": False}
    controls = {c.control_id: c for c in build_controls(document, effective, criticality=3)}
    assert controls["DEV-SB-001"].status == "not_applicable"
    assert controls["TPM-001"].status == "not_applicable"

    result = build_scan_result(
        list(controls.values()), build_findings(list(controls.values())), effective, criticality=3
    )
    assert result["assessment"]["not_applicable_controls"] == 2
    assert result["assessment_coverage"] == 100  # excluded from the denominator


def test_asset_criticality_scales_risk(effective):
    scores = []
    for criticality in (1, 3, 5):
        controls = build_controls(failing_document(), effective, criticality=criticality)
        result = build_scan_result(controls, build_findings(controls), effective, criticality=criticality)
        scores.append(result["risk_score"])
    assert scores[0] < scores[1] <= scores[2]


def test_risk_aggregation_is_bounded_and_monotonic():
    assert aggregate_risk([], 0.5)[0] == 0
    assert 0 < aggregate_risk([0.5], 0.5)[0] < 100
    assert aggregate_risk([1.0], 0.5)[0] == 50
    assert aggregate_risk([1.0, 1.0, 1.0], 0.5)[0] == 88
    assert aggregate_risk([1.0] * 40, 0.5)[0] <= 100


def test_explain_risk_lists_contributions(effective):
    controls = build_controls(failing_document(), effective, criticality=3)
    explanation = explain_risk(controls, effective, 3)
    assert explanation["score"] >= 70
    assert explanation["contributions"]
    assert explanation["contributions"][0]["impact"] >= explanation["contributions"][-1]["impact"]
    assert "noisy" in explanation["formula"] or "product" in explanation["formula"]


def test_evidence_projection_is_bounded(effective):
    document = perfect_document()
    for control in effective.controls:
        document["checks"].setdefault(control.spec.collector, {"status": "completed"})
    document["checks"]["system_hardening"]["huge"] = ["x" * 5000] * 200
    controls = build_controls(document, effective, criticality=3)
    for control in controls:
        evidence = control.evidence
        if isinstance(evidence, str):
            assert len(evidence) <= scoring.MAX_EVIDENCE_CHARS + 20
        if isinstance(evidence, list):
            assert len(evidence) <= scoring.MAX_EVIDENCE_ITEMS


# --------------------------------------------------------------------------- resolution
def test_global_override_changes_weight_severity_and_state(baseline):

    class Override:
        control_id = "FW-001"
        weight = 1
        severity = "low"
        is_enabled = False
        name = "Firewall state (relaxed)"
        recommendation_template = "Custom guidance."

    effective = resolve_effective(baseline, [Override], [])
    control = effective.by_id["FW-001"]
    assert control.weight == 1 and control.sources["weight"] == "override"
    assert control.severity == "low" and control.sources["severity"] == "override"
    assert control.enabled is False
    assert control.remediation["what_should_be_done"] == "Custom guidance."

    result = build_controls(perfect_document(), effective, criticality=3)
    fw = next(c for c in result if c.control_id == "FW-001")
    assert fw.status == "not_applicable"
    assert "disabled by a global policy override" in " ".join(fw.notes)


def test_device_exemption_marks_accepted_risk_with_reason(baseline):

    class Exemption:
        control_id = "NET-RDP-001"
        reason = "RDP is required for the on-call jump host."
        expires_at = None

    effective = resolve_effective(baseline, [], [Exemption])

    controls = {
        c.control_id: c
        for c in build_controls(
            failing_document(),
            effective,
            criticality=3,
        )
    }

    rdp = controls["NET-RDP-001"]

    # Actual security verdict remains unchanged.
    assert rdp.status == "non_compliant"

    # Exemption is explicitly recorded.
    assert rdp.exempted is True
    assert rdp.exemption_reason == (
        "RDP is required for the on-call jump host."
    )

    # Accepted violations are not open failures.
    assert rdp.accepted_risk is True
    assert rdp.open_failure is False

    # Accepted violations do not contribute to open risk.
    assert rdp.risk_contribution == 0.0
def test_findings_carry_remediation_and_references(effective):
    controls = build_controls(failing_document(), effective, criticality=3)
    findings = build_findings(controls)
    assert findings
    for finding in findings:
        assert finding["remediation"]["what_should_be_done"]
        assert finding["remediation"]["verify"]
        assert finding["standard_refs"]
        assert finding["severity"] in effective.baseline.severity_impact


def test_missing_baseline_file_raises(tmp_path):
    from app.services.baseline import load_baseline as loader

    with pytest.raises(BaselineError):
        loader(str(tmp_path / "does-not-exist.json"))


def test_explicit_null_is_distinguished_from_absent(effective):
    """A key present with a null value is evidence; an absent key is not."""
    document = perfect_document()
    document["checks"]["system_hardening"]["bitlocker"] = {"status": "completed", "enabled": None}
    controls = {c.control_id: c for c in build_controls(document, effective, criticality=3)}
    assert controls["BL-001"].status == "unknown"
    assert "explicitly null" in " ".join(controls["BL-001"].notes)
