"""
Day 6 Unit Tests: Verification Report Synthesis & Risk Scoring
Tests VerificationReport models, risk score weighting, security posture categorization,
and structured remediation plan generation.
"""

import json
from backend.models.report import (
    VerificationReport,
    PolicyViolation,
    ViolationType,
    ViolationSeverity,
)


def test_compliant_report_metrics():
    report = VerificationReport(
        policy_id="pol_comp_01",
        policy_name="Compliant Policy",
        valid=True,
        total_states=7,
        total_transitions=8,
        violations_count=0,
        violations=[]
    )

    assert report.calculate_risk_score() == 0
    assert report.determine_posture() == "COMPLIANT"
    assert len(report.get_remediation_plan()) == 0


def test_critical_risk_score_calculation():
    critical_violation = PolicyViolation(
        type=ViolationType.MISSING_AUTHENTICATION,
        severity=ViolationSeverity.CRITICAL,
        message="Unauthenticated access granted.",
        explanation="Trajectory skips authentication check.",
        witness_path=["START", "ACCESS_GRANTED"],
        remediation="Insert AUTHENTICATED state."
    )
    high_violation = PolicyViolation(
        type=ViolationType.MISSING_DEVICE_VERIFICATION,
        severity=ViolationSeverity.HIGH,
        message="Device posture unverified.",
        explanation="Missing endpoint posture inspection.",
        remediation="Insert DEVICE_VERIFIED state."
    )

    report = VerificationReport(
        policy_id="pol_flawed_01",
        policy_name="Flawed Policy",
        valid=False,
        total_states=5,
        total_transitions=4,
        violations_count=2,
        violations=[critical_violation, high_violation]
    )

    # 40 (CRITICAL) + 20 (HIGH) = 60
    assert report.calculate_risk_score() == 60
    assert report.determine_posture() == "CRITICAL_RISK"


def test_remediation_plan_generation():
    v1 = PolicyViolation(
        type=ViolationType.MISSING_AUTHENTICATION,
        severity=ViolationSeverity.CRITICAL,
        message="No auth",
        explanation="Auth missing",
        remediation="Add MFA verification."
    )
    v2 = PolicyViolation(
        type=ViolationType.DEAD_STATE,
        severity=ViolationSeverity.HIGH,
        state="PENDING_STATE",
        message="Trap state",
        explanation="Dead end",
        remediation="Add transition to ACCESS_DENIED."
    )

    report = VerificationReport(
        policy_id="pol_02",
        policy_name="Test Policy",
        valid=False,
        total_states=4,
        total_transitions=3,
        violations_count=2,
        violations=[v1, v2]
    )

    plan = report.get_remediation_plan()
    assert len(plan) == 2
    assert plan[0]["step"] == 1
    assert plan[0]["severity"] == "CRITICAL"
    assert plan[0]["action"] == "Add MFA verification."
    assert plan[1]["step"] == 2
    assert plan[1]["target"] == "PENDING_STATE"
    assert plan[1]["action"] == "Add transition to ACCESS_DENIED."


def test_report_json_serialization_roundtrip():
    v = PolicyViolation(
        type=ViolationType.UNREACHABLE_STATE,
        severity=ViolationSeverity.MEDIUM,
        state="ORPHAN_NODE",
        message="Orphan state detected",
        explanation="No incoming transitions",
        remediation="Connect or prune orphan node."
    )
    report = VerificationReport(
        policy_id="pol_roundtrip",
        policy_name="Roundtrip Test",
        valid=False,
        total_states=6,
        total_transitions=5,
        violations_count=1,
        violations=[v],
        risk_score=10,
        security_posture="LOW_RISK"
    )

    # Serialize to JSON and parse back
    raw_json = json.dumps(report.model_dump())
    loaded = VerificationReport.model_validate(json.loads(raw_json))

    assert loaded.policy_id == report.policy_id
    assert loaded.violations_count == 1
    assert loaded.violations[0].type == ViolationType.UNREACHABLE_STATE
    assert loaded.risk_score == 10
    assert loaded.security_posture == "LOW_RISK"
