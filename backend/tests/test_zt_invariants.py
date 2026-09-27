"""
Day 5 Unit Tests: Zero Trust Safety Invariant Rules
Tests each Zero Trust domain invariant rule in isolation:
- Authentication Invariant (Primary user verification)
- Device Trust Invariant (Endpoint compliance and posture)
- Authorization Inspection (Principle of Least Privilege and bypass defense)
- Session Revocability Invariant (Lifecycle termination and zombie session prevention)
"""

import pytest
from backend.core.fsm import FiniteStateMachine
from backend.models.policy import ZeroTrustPolicy, PolicyRule
from backend.core.rules.zt_invariants import (
    AuthenticationInvariantRule,
    DeviceTrustInvariantRule,
    AuthorizationCheckRule,
    SessionRevocationInvariantRule,
)
from backend.models.report import ViolationType, ViolationSeverity


@pytest.fixture
def auth_rule():
    return AuthenticationInvariantRule()


@pytest.fixture
def device_rule():
    return DeviceTrustInvariantRule()


@pytest.fixture
def authz_rule():
    return AuthorizationCheckRule()


@pytest.fixture
def revocation_rule():
    return SessionRevocationInvariantRule()


# 1. Authentication Invariant Tests
def test_auth_invariant_passes_on_legitimate_flow(auth_rule):
    fsm = FiniteStateMachine()
    fsm.add_transition(PolicyRule(source="START", target="AUTHENTICATED", action="login"))
    fsm.add_transition(PolicyRule(source="AUTHENTICATED", target="ACCESS_GRANTED", action="allow"))
    dummy_policy = ZeroTrustPolicy(policy_name="Dummy", rules=[PolicyRule(source="A", target="B")])

    violations = auth_rule.evaluate(fsm, dummy_policy)
    assert len(violations) == 0


def test_auth_invariant_catches_unauthenticated_path(auth_rule):
    fsm = FiniteStateMachine()
    fsm.add_transition(PolicyRule(source="START", target="GUEST_STAGE", action="guest_connect"))
    fsm.add_transition(PolicyRule(source="GUEST_STAGE", target="ACCESS_GRANTED", action="grant"))
    dummy_policy = ZeroTrustPolicy(policy_name="Dummy", rules=[PolicyRule(source="A", target="B")])

    violations = auth_rule.evaluate(fsm, dummy_policy)
    assert len(violations) == 1
    assert violations[0].type == ViolationType.MISSING_AUTHENTICATION
    assert violations[0].severity == ViolationSeverity.CRITICAL
    assert violations[0].witness_path == ["START", "GUEST_STAGE", "ACCESS_GRANTED"]


# 2. Device Trust Invariant Tests
def test_device_trust_passes_with_device_verified_state(device_rule):
    fsm = FiniteStateMachine()
    fsm.add_transition(PolicyRule(source="START", target="AUTHENTICATED", action="login"))
    fsm.add_transition(PolicyRule(source="AUTHENTICATED", target="DEVICE_VERIFIED", action="check_edr"))
    fsm.add_transition(PolicyRule(source="DEVICE_VERIFIED", target="ACCESS_GRANTED", action="grant"))
    dummy_policy = ZeroTrustPolicy(policy_name="Dummy", rules=[PolicyRule(source="A", target="B")])

    violations = device_rule.evaluate(fsm, dummy_policy)
    assert len(violations) == 0


def test_device_trust_passes_with_device_predicate_condition(device_rule):
    fsm = FiniteStateMachine()
    fsm.add_transition(PolicyRule(source="START", target="AUTHENTICATED", action="login"))
    fsm.add_transition(PolicyRule(source="AUTHENTICATED", target="ACCESS_GRANTED", action="grant", condition="device_healthy_posture"))
    dummy_policy = ZeroTrustPolicy(policy_name="Dummy", rules=[PolicyRule(source="A", target="B")])

    violations = device_rule.evaluate(fsm, dummy_policy)
    assert len(violations) == 0


def test_device_trust_catches_missing_endpoint_posture(device_rule):
    fsm = FiniteStateMachine()
    fsm.add_transition(PolicyRule(source="START", target="AUTHENTICATED", action="login"))
    fsm.add_transition(PolicyRule(source="AUTHENTICATED", target="AUTHORIZED", action="check_role"))
    fsm.add_transition(PolicyRule(source="AUTHORIZED", target="ACCESS_GRANTED", action="grant"))
    dummy_policy = ZeroTrustPolicy(policy_name="Dummy", rules=[PolicyRule(source="A", target="B")])

    violations = device_rule.evaluate(fsm, dummy_policy)
    assert len(violations) == 1
    assert violations[0].type == ViolationType.MISSING_DEVICE_VERIFICATION
    assert violations[0].severity == ViolationSeverity.HIGH


# 3. Authorization Check Tests
def test_authz_check_catches_direct_start_to_access_grant(authz_rule):
    fsm = FiniteStateMachine()
    fsm.add_transition(PolicyRule(source="START", target="ACCESS_GRANTED", action="backdoor_jump"))
    dummy_policy = ZeroTrustPolicy(policy_name="Dummy", rules=[PolicyRule(source="A", target="B")])

    violations = authz_rule.evaluate(fsm, dummy_policy)
    assert len(violations) == 1
    assert violations[0].type == ViolationType.PRIVILEGE_BYPASS
    assert violations[0].severity == ViolationSeverity.CRITICAL


def test_authz_check_catches_skipped_permission_evaluation(authz_rule):
    fsm = FiniteStateMachine()
    fsm.add_transition(PolicyRule(source="AUTHENTICATED", target="ACCESS_GRANTED", action="direct_grant", condition=""))
    dummy_policy = ZeroTrustPolicy(policy_name="Dummy", rules=[PolicyRule(source="A", target="B")])

    violations = authz_rule.evaluate(fsm, dummy_policy)
    assert len(violations) == 1
    assert violations[0].type == ViolationType.MISSING_AUTHORIZATION
    assert violations[0].severity == ViolationSeverity.HIGH


# 4. Session Revocability Invariant Tests
def test_session_revocability_catches_zombie_session(revocation_rule):
    fsm = FiniteStateMachine()
    fsm.add_transition(PolicyRule(source="START", target="ACCESS_GRANTED", action="login"))
    # No outgoing transitions from ACCESS_GRANTED
    dummy_policy = ZeroTrustPolicy(policy_name="Dummy", rules=[PolicyRule(source="A", target="B")])

    violations = revocation_rule.evaluate(fsm, dummy_policy)
    assert len(violations) == 1
    assert violations[0].type == ViolationType.NO_REVOCATION_PATH
    assert violations[0].severity == ViolationSeverity.HIGH


def test_session_revocability_passes_with_timeout_and_revoke_paths(revocation_rule):
    fsm = FiniteStateMachine()
    fsm.add_transition(PolicyRule(source="START", target="ACCESS_GRANTED", action="login"))
    fsm.add_transition(PolicyRule(source="ACCESS_GRANTED", target="SESSION_EXPIRED", action="timeout"))
    fsm.add_transition(PolicyRule(source="ACCESS_GRANTED", target="REVOKED", action="admin_kill"))
    dummy_policy = ZeroTrustPolicy(policy_name="Dummy", rules=[PolicyRule(source="A", target="B")])

    violations = revocation_rule.evaluate(fsm, dummy_policy)
    assert len(violations) == 0
