"""
Day 2 Unit Tests: Policy Data Model & Validation
Tests Pydantic v2 schemas for PolicyRule, PolicyMetadata, and ZeroTrustPolicy.
"""

import pytest
from pydantic import ValidationError
from backend.models.policy import ZeroTrustPolicy, PolicyRule, PolicyMetadata


def test_valid_policy_creation():
    rule = PolicyRule(
        source="START",
        target="AUTHENTICATED",
        action="submit_credentials",
        condition="valid_creds",
        description="Initial login"
    )
    policy = ZeroTrustPolicy(
        policy_name="Enterprise Test Policy",
        rules=[rule]
    )

    assert policy.policy_name == "Enterprise Test Policy"
    assert policy.initial_state == "START"
    assert "ACCESS_GRANTED" in policy.terminal_states
    assert len(policy.rules) == 1
    assert policy.rules[0].rule_id.startswith("rule_")
    assert policy.policy_id.startswith("pol_")


def test_rule_requires_source_and_target():
    with pytest.raises(ValidationError):
        PolicyRule(source="START")  # missing target

    with pytest.raises(ValidationError):
        PolicyRule(target="AUTHENTICATED")  # missing source


def test_policy_requires_at_least_one_rule():
    with pytest.raises(ValidationError):
        ZeroTrustPolicy(
            policy_name="Empty Policy",
            rules=[]  # min_length=1
        )


def test_policy_get_all_states_aggregates_uniquely():
    r1 = PolicyRule(source="START", target="AUTH", action="t1")
    r2 = PolicyRule(source="AUTH", target="ACCESS_GRANTED", action="t2")
    r3 = PolicyRule(source="AUTH", target="ACCESS_DENIED", action="t3")

    policy = ZeroTrustPolicy(
        policy_name="Multi-State Policy",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "ACCESS_DENIED", "REVOKED"],
        rules=[r1, r2, r3]
    )

    all_states = policy.get_all_states()
    expected = {"START", "AUTH", "ACCESS_GRANTED", "ACCESS_DENIED", "REVOKED"}
    assert set(all_states) == expected
    assert all_states == sorted(list(expected))


def test_policy_metadata_defaults_and_overrides():
    policy = ZeroTrustPolicy(
        policy_name="Metadata Policy",
        rules=[PolicyRule(source="A", target="B", action="test")],
        metadata=PolicyMetadata(
            author="SecurityArchitect",
            target_resource="finance-db",
            allowed_roles=["admin"],
            max_session_seconds=1200,
            risk_threshold="HIGH"
        )
    )

    assert policy.metadata.author == "SecurityArchitect"
    assert policy.metadata.target_resource == "finance-db"
    assert policy.metadata.allowed_roles == ["admin"]
    assert policy.metadata.max_session_seconds == 1200
    assert policy.metadata.risk_threshold == "HIGH"
