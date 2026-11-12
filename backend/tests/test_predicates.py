"""
Comprehensive Unit Tests for First-Order Guard Predicate Algebra
Validates atomic comparisons, CIDR matching, temporal intervals,
compound boolean algebra (AND/OR/NOT), fail-closed context semantics,
and PolicyRule schema integration.
"""

import pytest
from backend.models.predicate import (
    ComparisonOp,
    LogicalOp,
    AccessContext,
    AtomicPredicate,
    CompoundPredicate,
    parse_predicate
)
from backend.models.policy import PolicyRule


def test_atomic_numeric_comparisons():
    """Validates numeric equality, inequality, and relational bounds."""
    ctx_low = AccessContext(risk_score=0.15)
    ctx_high = AccessContext(risk_score=0.85)

    p_lte = AtomicPredicate(attribute="risk_score", operator=ComparisonOp.LTE, value=0.35)
    p_gt = AtomicPredicate(attribute="risk_score", operator=ComparisonOp.GT, value=0.50)
    p_eq = AtomicPredicate(attribute="risk_score", operator=ComparisonOp.EQ, value=0.15)
    p_neq = AtomicPredicate(attribute="risk_score", operator=ComparisonOp.NEQ, value=0.15)

    assert p_lte.evaluate(ctx_low) is True
    assert p_lte.evaluate(ctx_high) is False

    assert p_gt.evaluate(ctx_low) is False
    assert p_gt.evaluate(ctx_high) is True

    assert p_eq.evaluate(ctx_low) is True
    assert p_neq.evaluate(ctx_low) is False


def test_atomic_cidr_matching():
    """Validates IPv4 and IPv6 subnet containment checks."""
    p_cidr_v4 = AtomicPredicate(attribute="client_ip", operator=ComparisonOp.CIDR_MATCH, value="10.0.0.0/16")
    p_cidr_v6 = AtomicPredicate(attribute="client_ip", operator=ComparisonOp.CIDR_MATCH, value="2001:db8::/32")

    ctx_internal = AccessContext(client_ip="10.0.4.55")
    ctx_external = AccessContext(client_ip="192.168.1.10")
    ctx_ipv6 = AccessContext(client_ip="2001:db8:0000:0000::1")
    ctx_invalid = AccessContext(client_ip="not_an_ip")

    assert p_cidr_v4.evaluate(ctx_internal) is True
    assert p_cidr_v4.evaluate(ctx_external) is False
    assert p_cidr_v4.evaluate(ctx_invalid) is False

    assert p_cidr_v6.evaluate(ctx_ipv6) is True
    assert p_cidr_v6.evaluate(ctx_internal) is False


def test_atomic_temporal_intervals_between():
    """Validates time-of-day interval evaluations including overnight windows."""
    p_business_hours = AtomicPredicate(
        attribute="time_of_day",
        operator=ComparisonOp.BETWEEN,
        value=["09:00", "18:00"]
    )
    p_overnight_maintenance = AtomicPredicate(
        attribute="time_of_day",
        operator=ComparisonOp.BETWEEN,
        value=["22:00", "06:00"]
    )

    ctx_afternoon = AccessContext(time_of_day="14:30")
    ctx_evening = AccessContext(time_of_day="20:45")
    ctx_midnight = AccessContext(time_of_day="03:15")

    assert p_business_hours.evaluate(ctx_afternoon) is True
    assert p_business_hours.evaluate(ctx_evening) is False

    # Overnight evaluation
    assert p_overnight_maintenance.evaluate(ctx_midnight) is True
    assert p_overnight_maintenance.evaluate(ctx_afternoon) is False


def test_atomic_set_membership():
    """Validates IN and NOT_IN set containment operations."""
    p_role_allowed = AtomicPredicate(
        attribute="user_roles",
        operator=ComparisonOp.IN,
        value=["admin", "security_engineer", "auditor"]
    )
    p_role_forbidden = AtomicPredicate(
        attribute="user_roles",
        operator=ComparisonOp.NOT_IN,
        value=["contractor_temp", "guest"]
    )

    ctx_admin = AccessContext(user_roles=["developer", "security_engineer"])
    ctx_intern = AccessContext(user_roles=["intern", "contractor_temp"])

    assert p_role_allowed.evaluate(ctx_admin) is True
    assert p_role_allowed.evaluate(ctx_intern) is False

    assert p_role_forbidden.evaluate(ctx_admin) is True
    assert p_role_forbidden.evaluate(ctx_intern) is False


def test_compound_predicate_boolean_algebra():
    """Validates recursive evaluation of AND, OR, and NOT clauses."""
    p_risk = AtomicPredicate(attribute="risk_score", operator=ComparisonOp.LTE, value=0.30)
    p_ip = AtomicPredicate(attribute="client_ip", operator=ComparisonOp.CIDR_MATCH, value="10.0.0.0/16")
    p_mfa = AtomicPredicate(attribute="mfa_verified", operator=ComparisonOp.EQ, value=True)
    p_admin = AtomicPredicate(attribute="user_roles", operator=ComparisonOp.IN, value=["break_glass_admin"])

    # Standard corporate access: risk <= 0.30 AND ip in 10.0.0.0/16 AND mfa == True
    standard_gate = CompoundPredicate(
        logical_op=LogicalOp.AND,
        predicates=[p_risk, p_ip, p_mfa]
    )

    # Policy with break-glass override: (standard_gate) OR (admin)
    full_policy_guard = CompoundPredicate(
        logical_op=LogicalOp.OR,
        predicates=[standard_gate, p_admin]
    )

    # Compliant internal employee
    ctx_compliant = AccessContext(
        risk_score=0.10,
        client_ip="10.0.2.1",
        mfa_verified=True,
        user_roles=["employee"]
    )
    assert standard_gate.evaluate(ctx_compliant) is True
    assert full_policy_guard.evaluate(ctx_compliant) is True

    # High-risk internal employee (fails standard gate)
    ctx_compromised = AccessContext(
        risk_score=0.75,
        client_ip="10.0.2.1",
        mfa_verified=True,
        user_roles=["employee"]
    )
    assert standard_gate.evaluate(ctx_compromised) is False
    assert full_policy_guard.evaluate(ctx_compromised) is False

    # Break-glass admin from external IP (bypasses standard gate via OR)
    ctx_emergency = AccessContext(
        risk_score=0.90,
        client_ip="203.0.113.5",
        mfa_verified=False,
        user_roles=["break_glass_admin"]
    )
    assert standard_gate.evaluate(ctx_emergency) is False
    assert full_policy_guard.evaluate(ctx_emergency) is True

    # NOT operator check
    not_compromised = CompoundPredicate(
        logical_op=LogicalOp.NOT,
        predicates=[AtomicPredicate(attribute="device_health", operator=ComparisonOp.EQ, value="COMPROMISED")]
    )
    assert not_compromised.evaluate(AccessContext(device_health="HEALTHY")) is True
    assert not_compromised.evaluate(AccessContext(device_health="COMPROMISED")) is False


def test_missing_context_fails_closed():
    """Verifies NIST SP 800-207 fail-closed principle when context is absent."""
    p = AtomicPredicate(attribute="risk_score", operator=ComparisonOp.LTE, value=0.50)
    empty_ctx = AccessContext()
    assert p.evaluate(empty_ctx) is False


def test_parse_predicate_utility():
    """Validates automatic string parsing and dictionary deserialization."""
    # 1. Comparison string
    p1 = parse_predicate("risk_score <= 0.40")
    assert isinstance(p1, AtomicPredicate)
    assert p1.attribute == "risk_score"
    assert p1.operator == ComparisonOp.LTE
    assert p1.value == 0.40

    # 2. CIDR string
    p2 = parse_predicate("client_ip CIDR_MATCH 192.168.0.0/24")
    assert isinstance(p2, AtomicPredicate)
    assert p2.operator == ComparisonOp.CIDR_MATCH
    assert p2.value == "192.168.0.0/24"

    # 3. Legacy boolean condition string
    p3 = parse_predicate("device_verified")
    assert isinstance(p3, AtomicPredicate)
    assert p3.attribute == "device_verified"
    assert p3.value is True

    # 4. Dictionary parsing
    raw_dict = {
        "logical_op": "AND",
        "predicates": [
            {"attribute": "clearance_level", "operator": ">=", "value": 3},
            {"attribute": "device_health", "operator": "==", "value": "COMPLIANT"}
        ]
    }
    p4 = parse_predicate(raw_dict)
    assert isinstance(p4, CompoundPredicate)
    assert p4.logical_op == LogicalOp.AND
    assert len(p4.predicates) == 2


def test_policy_rule_predicate_integration():
    """Verifies that PolicyRule cleanly embeds structured predicates and supports legacy conditions."""
    pred = AtomicPredicate(attribute="risk_score", operator=ComparisonOp.LTE, value=0.25)
    rule_structured = PolicyRule(
        source="IDENTITY_VERIFIED",
        target="DEVICE_VERIFIED",
        predicate=pred
    )
    assert rule_structured.get_guard_predicate() == pred

    # Legacy condition string fallback
    rule_legacy = PolicyRule(
        source="START",
        target="AUTHENTICATED",
        condition="mfa_verified == true"
    )
    guard = rule_legacy.get_guard_predicate()
    assert guard is not None
    assert guard.attribute == "mfa_verified"
    assert guard.value is True
