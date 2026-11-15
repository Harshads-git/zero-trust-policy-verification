"""
Unit & Integration Tests for Continuous Risk-Adaptive Verification Engine
Validates per-transition dynamic risk calculation, monotonic trajectory risk accumulation,
NIST SP 800-207 step-up authentication invariant enforcement, counterexample extraction,
SMT risk bound solving, and REST API endpoint behavior.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.core.fsm import FiniteStateMachine
from backend.core.risk_engine import (
    ContinuousRiskEngine,
    RiskAdaptiveInvariantRule,
    TrajectoryRiskProfile,
    STEP_UP_STATES,
)
from backend.models.policy import ZeroTrustPolicy, PolicyRule
from backend.models.report import ViolationType, ViolationSeverity

client = TestClient(app)


def test_transition_risk_calculation_weights_and_heuristics():
    """Verifies transition risk calculation with explicit weights and keyword heuristics."""
    engine = ContinuousRiskEngine()

    rule_explicit = PolicyRule(
        source="START",
        target="AUTHENTICATED",
        action="login",
        risk_weight=0.75
    )
    rule_admin = PolicyRule(
        source="AUTHENTICATED",
        target="AUTHORIZED",
        action="admin_privilege_escalation"
    )
    rule_stepup = PolicyRule(
        source="MFA_CHALLENGE",
        target="STEP_UP_AUTH",
        action="mfa_verify"
    )
    rule_standard = PolicyRule(
        source="START",
        target="UNAUTHENTICATED",
        action="connect"
    )

    assert engine.calculate_transition_risk(rule_explicit) == 0.75
    assert engine.calculate_transition_risk(rule_admin) >= 0.40
    assert engine.calculate_transition_risk(rule_stepup) < 0.0  # mitigation
    assert engine.calculate_transition_risk(rule_standard) <= 0.15


def test_trajectory_risk_accumulation_without_stepup():
    """Verifies trajectory accumulating risk >= 0.50 without step-up is flagged non-compliant."""
    engine = ContinuousRiskEngine(stepup_threshold=0.50)

    rules = {
        ("START", "AUTHENTICATED"): PolicyRule(source="START", target="AUTHENTICATED", action="login", risk_weight=0.20),
        ("AUTHENTICATED", "ELEVATED_ROLE"): PolicyRule(source="AUTHENTICATED", target="ELEVATED_ROLE", action="request_admin", risk_weight=0.45),
        ("ELEVATED_ROLE", "ACCESS_GRANTED"): PolicyRule(source="ELEVATED_ROLE", target="ACCESS_GRANTED", action="grant", risk_weight=0.20)
    }

    trajectory = ["START", "AUTHENTICATED", "ELEVATED_ROLE", "ACCESS_GRANTED"]
    profile = engine.calculate_trajectory_risk(trajectory, rules)

    assert profile.cumulative_risk >= 0.65
    assert profile.step_up_triggered is False
    assert profile.requires_step_up is True
    assert profile.is_compliant is False


def test_trajectory_risk_mitigation_with_stepup_state():
    """Verifies that traversing a step-up challenge state mitigates risk and renders path compliant."""
    engine = ContinuousRiskEngine(stepup_threshold=0.50)

    rules = {
        ("START", "AUTHENTICATED"): PolicyRule(source="START", target="AUTHENTICATED", action="login", risk_weight=0.20),
        ("AUTHENTICATED", "MFA_CHALLENGE"): PolicyRule(source="AUTHENTICATED", target="MFA_CHALLENGE", action="elevate_action", risk_weight=0.40),
        ("MFA_CHALLENGE", "AUTHORIZED"): PolicyRule(source="MFA_CHALLENGE", target="AUTHORIZED", action="mfa_verify"),
        ("AUTHORIZED", "ACCESS_GRANTED"): PolicyRule(source="AUTHORIZED", target="ACCESS_GRANTED", action="grant", risk_weight=0.10)
    }

    trajectory = ["START", "AUTHENTICATED", "MFA_CHALLENGE", "AUTHORIZED", "ACCESS_GRANTED"]
    profile = engine.calculate_trajectory_risk(trajectory, rules)

    assert profile.step_up_triggered is True
    assert profile.requires_step_up is True
    assert profile.is_compliant is True


def test_policy_risk_invariant_detects_unmitigated_path():
    """Verifies that an unmitigated high-risk path generates UNMITIGATED_HIGH_RISK_PATH violation."""
    engine = ContinuousRiskEngine(stepup_threshold=0.50)

    policy = ZeroTrustPolicy(
        policy_name="High Risk Admin Bypass Policy",
        rules=[
            PolicyRule(source="START", target="AUTHENTICATED", action="login", risk_weight=0.20),
            PolicyRule(source="AUTHENTICATED", target="ADMIN_ZONE", action="elevate_privilege", risk_weight=0.45),
            PolicyRule(source="ADMIN_ZONE", target="ACCESS_GRANTED", action="grant_admin_access", risk_weight=0.25)
        ]
    )

    fsm = FiniteStateMachine.from_policy(policy)
    violations, profiles = engine.evaluate_policy_risk_invariants(fsm, policy)

    assert len(violations) >= 1
    v = violations[0]
    assert v.type == ViolationType.UNMITIGATED_HIGH_RISK_PATH
    assert v.severity == ViolationSeverity.HIGH
    assert "START" in v.witness_path
    assert "ACCESS_GRANTED" in v.witness_path
    assert "MFA_CHALLENGE" in v.remediation


def test_policy_risk_invariant_passes_with_stepup():
    """Verifies that a policy enforcing step-up authentication passes with zero risk violations."""
    engine = ContinuousRiskEngine(stepup_threshold=0.50)

    policy = ZeroTrustPolicy(
        policy_name="Safe Continuous Step-Up Policy",
        rules=[
            PolicyRule(source="START", target="AUTHENTICATED", action="login", risk_weight=0.20),
            PolicyRule(source="AUTHENTICATED", target="MFA_CHALLENGE", action="request_admin_scope", risk_weight=0.40),
            PolicyRule(source="MFA_CHALLENGE", target="AUTHORIZED", action="mfa_verify"),
            PolicyRule(source="AUTHORIZED", target="ACCESS_GRANTED", action="grant", risk_weight=0.10)
        ]
    )

    fsm = FiniteStateMachine.from_policy(policy)
    violations, profiles = engine.evaluate_policy_risk_invariants(fsm, policy)

    assert len(violations) == 0
    assert all(p.is_compliant for p in profiles)


def test_risk_engine_smt_bounds_verification():
    """Verifies SMT bounds verification accurately identifies unmitigated trajectories."""
    engine = ContinuousRiskEngine(stepup_threshold=0.50)

    safe_policy = ZeroTrustPolicy(
        policy_name="Safe Policy",
        rules=[
            PolicyRule(source="START", target="AUTHENTICATED", action="login", risk_weight=0.10),
            PolicyRule(source="AUTHENTICATED", target="ACCESS_GRANTED", action="grant", risk_weight=0.10)
        ]
    )

    res = engine.verify_risk_bounds_with_smt(safe_policy)
    assert res["is_provably_safe"] is True
    assert res["unmitigated_high_risk_paths_count"] == 0
    assert res["peak_risk_observed"] <= 0.50


def test_verify_risk_rest_api_endpoint():
    """Tests the /api/policies/verify-risk REST endpoint."""
    sample_policy = {
        "policy_name": "API Risk Test Policy",
        "initial_state": "START",
        "terminal_states": ["ACCESS_GRANTED", "SESSION_EXPIRED"],
        "rules": [
            {
                "rule_id": "r1",
                "source": "START",
                "target": "AUTHENTICATED",
                "action": "login",
                "risk_weight": 0.20
            },
            {
                "rule_id": "r2",
                "source": "AUTHENTICATED",
                "target": "SENSITIVE_ZONE",
                "action": "admin_access",
                "risk_weight": 0.55
            },
            {
                "rule_id": "r3",
                "source": "SENSITIVE_ZONE",
                "target": "ACCESS_GRANTED",
                "action": "grant",
                "risk_weight": 0.15
            }
        ]
    }

    response = client.post("/api/policies/verify-risk?stepup_threshold=0.50", json=sample_policy)
    assert response.status_code == 200
    data = response.json()

    assert data["policy_name"] == "API Risk Test Policy"
    assert data["stepup_threshold"] == 0.50
    assert data["is_risk_compliant"] is False
    assert data["violations_count"] >= 1
    assert data["violations"][0]["type"] == "UNMITIGATED_HIGH_RISK_PATH"
    assert len(data["trajectory_risk_profiles"]) >= 1
    assert "smt_risk_bounds" in data
