"""
Formal Zero Trust Invariant & Verification Engine Tests
Tests all 7 flaw categories, witness trace generation, and valid policy compliance.
"""

from backend.core.verifier import ZeroTrustVerificationEngine
from backend.models.report import ViolationType, ViolationSeverity


def test_valid_employee_policy_passes(verifier, valid_policy_employee):
    report = verifier.verify(valid_policy_employee)
    assert report.valid is True
    assert report.violations_count == 0
    assert len(report.unreachable_states) == 0
    assert len(report.dead_states) == 0
    assert all(report.formal_invariants_checked.values())


def test_valid_admin_policy_passes(verifier, valid_policy_admin):
    report = verifier.verify(valid_policy_admin)
    assert report.valid is True
    assert report.violations_count == 0
    assert all(report.formal_invariants_checked.values())


def test_valid_contractor_policy_passes(verifier, policies_dir):
    import json
    path = policies_dir / "valid" / "03_contractor_restricted_access.json"
    from backend.models.policy import ZeroTrustPolicy
    policy = ZeroTrustPolicy.model_validate(json.loads(path.read_text(encoding="utf-8")))
    report = verifier.verify(policy)
    assert report.valid is True
    assert report.violations_count == 0
    assert all(report.formal_invariants_checked.values())


def test_missing_authentication_detected(verifier, invalid_policy_auth):
    report = verifier.verify(invalid_policy_auth)
    assert report.valid is False
    assert report.violations_count > 0
    types = [v.type for v in report.violations]
    assert ViolationType.MISSING_AUTHENTICATION in types

    auth_violation = next(v for v in report.violations if v.type == ViolationType.MISSING_AUTHENTICATION)
    assert auth_violation.severity == ViolationSeverity.CRITICAL
    assert auth_violation.witness_path is not None
    assert "ACCESS_GRANTED" in auth_violation.witness_path


def test_missing_device_verification_detected(verifier, invalid_policy_device):
    report = verifier.verify(invalid_policy_device)
    assert report.valid is False
    types = [v.type for v in report.violations]
    assert ViolationType.MISSING_DEVICE_VERIFICATION in types

    dev_violation = next(v for v in report.violations if v.type == ViolationType.MISSING_DEVICE_VERIFICATION)
    assert dev_violation.severity == ViolationSeverity.HIGH
    assert dev_violation.witness_path is not None


def test_unreachable_state_detected(verifier, invalid_policy_unreachable):
    report = verifier.verify(invalid_policy_unreachable)
    assert report.valid is False
    assert "ELEVATED_AUDIT_LOG" in report.unreachable_states
    types = [v.type for v in report.violations]
    assert ViolationType.UNREACHABLE_STATE in types


def test_dead_state_detected(verifier, invalid_policy_dead_state):
    report = verifier.verify(invalid_policy_dead_state)
    assert report.valid is False
    assert "PENDING_MANUAL_REVIEW" in report.dead_states
    types = [v.type for v in report.violations]
    assert ViolationType.DEAD_STATE in types


def test_conflicting_rules_detected(verifier, invalid_policy_conflict):
    report = verifier.verify(invalid_policy_conflict)
    assert report.valid is False
    types = [v.type for v in report.violations]
    assert ViolationType.RULE_CONFLICT in types


def test_no_revocation_path_detected(verifier, invalid_policy_no_revocation):
    report = verifier.verify(invalid_policy_no_revocation)
    assert report.valid is False
    types = [v.type for v in report.violations]
    assert ViolationType.NO_REVOCATION_PATH in types


def test_critical_privilege_bypass_detected(verifier, invalid_policy_bypass):
    report = verifier.verify(invalid_policy_bypass)
    assert report.valid is False
    types = [v.type for v in report.violations]
    assert ViolationType.PRIVILEGE_BYPASS in types or ViolationType.MISSING_AUTHENTICATION in types
    criticals = [v for v in report.violations if v.severity == ViolationSeverity.CRITICAL]
    assert len(criticals) >= 1
