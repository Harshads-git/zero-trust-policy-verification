"""
Unit & Integration Tests for Microsoft Z3 SMT Constraint Solver
Validates first-order guard satisfiability (SAT), contradiction detection (UNSAT),
satisfying model extraction, multi-hop path condition solving, dead transition discovery,
and REST API endpoint behavior.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.core.smt_solver import Z3ConstraintSolver, SMTResult, SMTPathResult
from backend.models.predicate import (
    ComparisonOp,
    LogicalOp,
    AtomicPredicate,
    CompoundPredicate,
)
from backend.models.policy import ZeroTrustPolicy, PolicyRule

client = TestClient(app)


def test_z3_satisfiable_numeric_constraints():
    """Verifies Z3 finds satisfying model for compatible numeric predicates."""
    solver = Z3ConstraintSolver()
    p1 = AtomicPredicate(attribute="risk_score", operator=ComparisonOp.LTE, value=0.40)
    p2 = AtomicPredicate(attribute="clearance_level", operator=ComparisonOp.GTE, value=3)
    p3 = AtomicPredicate(attribute="device_verified", operator=ComparisonOp.EQ, value=True)

    result = solver.check_satisfiability([p1, p2, p3])
    assert result.is_satisfiable is True
    assert result.status == "SAT"
    assert result.model is not None
    assert "risk_score" in result.model
    assert result.model["risk_score"] <= 0.40
    assert result.model["clearance_level"] >= 3
    assert result.model["device_verified"] is True


def test_z3_unsatisfiable_numeric_contradiction():
    """Verifies Z3 identifies contradictory numeric intervals as UNSAT."""
    solver = Z3ConstraintSolver()
    # Impossible constraint: risk < 0.20 AND risk > 0.70
    p1 = AtomicPredicate(attribute="risk_score", operator=ComparisonOp.LT, value=0.20)
    p2 = AtomicPredicate(attribute="risk_score", operator=ComparisonOp.GT, value=0.70)

    result = solver.check_satisfiability([p1, p2])
    assert result.is_satisfiable is False
    assert result.status == "UNSAT"
    assert result.model is None
    assert result.unsat_core is not None


def test_z3_cidr_subnet_satisfiability():
    """Verifies Z3 generates a valid concrete IP address model within a CIDR subnet."""
    solver = Z3ConstraintSolver()
    p_cidr = AtomicPredicate(attribute="client_ip", operator=ComparisonOp.CIDR_MATCH, value="10.50.0.0/16")

    result = solver.check_satisfiability([p_cidr])
    assert result.is_satisfiable is True
    assert result.status == "SAT"
    assert result.model is not None
    assert "client_ip" in result.model
    # Verify the generated IP string is actually inside 10.50.0.0/16
    import ipaddress
    ip = ipaddress.ip_address(result.model["client_ip"])
    net = ipaddress.ip_network("10.50.0.0/16")
    assert ip in net


def test_z3_cidr_disjoint_subnets_contradiction():
    """Verifies Z3 proves impossible to satisfy two disjoint CIDR constraints simultaneously."""
    solver = Z3ConstraintSolver()
    p1 = AtomicPredicate(attribute="client_ip", operator=ComparisonOp.CIDR_MATCH, value="10.0.0.0/16")
    p2 = AtomicPredicate(attribute="client_ip", operator=ComparisonOp.CIDR_MATCH, value="192.168.1.0/24")

    result = solver.check_satisfiability([p1, p2])
    assert result.is_satisfiable is False
    assert result.status == "UNSAT"


def test_z3_temporal_window_satisfiability():
    """Verifies Z3 solves time-of-day between intervals."""
    solver = Z3ConstraintSolver()
    p_time = AtomicPredicate(attribute="time_of_day", operator=ComparisonOp.BETWEEN, value=["08:30", "17:30"])

    result = solver.check_satisfiability([p_time])
    assert result.is_satisfiable is True
    assert result.status == "SAT"
    assert "time_of_day" in result.model


def test_z3_path_condition_chain():
    """Verifies path-condition satisfiability along a multi-hop execution trajectory."""
    solver = Z3ConstraintSolver()

    r1 = PolicyRule(
        rule_id="r1",
        source="START",
        target="AUTHENTICATED",
        predicate=AtomicPredicate(attribute="mfa_verified", operator=ComparisonOp.EQ, value=True)
    )
    r2 = PolicyRule(
        rule_id="r2",
        source="AUTHENTICATED",
        target="DEVICE_VERIFIED",
        predicate=AtomicPredicate(attribute="risk_score", operator=ComparisonOp.LTE, value=0.30)
    )
    r3 = PolicyRule(
        rule_id="r3",
        source="DEVICE_VERIFIED",
        target="AUTHORIZED",
        predicate=AtomicPredicate(attribute="client_ip", operator=ComparisonOp.CIDR_MATCH, value="10.0.0.0/8")
    )

    trajectory = ["START", "AUTHENTICATED", "DEVICE_VERIFIED", "AUTHORIZED"]
    path_res = solver.check_path_satisfiability(trajectory, [r1, r2, r3])

    assert path_res.is_satisfiable is True
    assert path_res.status == "SAT"
    assert path_res.model is not None
    assert path_res.model["mfa_verified"] is True
    assert path_res.model["risk_score"] <= 0.30


def test_z3_detect_dead_transitions_in_policy():
    """Verifies detection of dead transitions with self-contradictory guard predicates."""
    solver = Z3ConstraintSolver()

    contradictory_guard = CompoundPredicate(
        logical_op=LogicalOp.AND,
        predicates=[
            AtomicPredicate(attribute="risk_score", operator=ComparisonOp.LT, value=0.10),
            AtomicPredicate(attribute="risk_score", operator=ComparisonOp.GT, value=0.90)
        ]
    )

    policy = ZeroTrustPolicy(
        policy_name="Policy with Dead Transition",
        rules=[
            PolicyRule(source="START", target="AUTHENTICATED", action="login"),
            PolicyRule(
                rule_id="dead_rule_01",
                source="AUTHENTICATED",
                target="ACCESS_GRANTED",
                action="impossible_grant",
                predicate=contradictory_guard
            )
        ]
    )

    dead_transitions = solver.detect_dead_transitions(policy)
    assert len(dead_transitions) == 1
    assert dead_transitions[0]["rule_id"] == "dead_rule_01"
    assert "mathematically unsatisfiable" in dead_transitions[0]["reason"]


def test_verify_smt_api_endpoint():
    """Tests the /api/policies/verify-smt REST endpoint."""
    sample_policy = {
        "policy_name": "SMT Verification Test Policy",
        "initial_state": "START",
        "terminal_states": ["ACCESS_GRANTED", "SESSION_EXPIRED"],
        "rules": [
            {
                "rule_id": "r_auth",
                "source": "START",
                "target": "AUTHENTICATED",
                "action": "auth",
                "condition": "mfa_verified == true"
            },
            {
                "rule_id": "r_device",
                "source": "AUTHENTICATED",
                "target": "DEVICE_VERIFIED",
                "action": "device_check",
                "predicate": {
                    "attribute": "risk_score",
                    "operator": "<=",
                    "value": 0.25
                }
            },
            {
                "rule_id": "r_grant",
                "source": "DEVICE_VERIFIED",
                "target": "ACCESS_GRANTED",
                "action": "grant",
                "predicate": {
                    "attribute": "clearance_level",
                    "operator": ">=",
                    "value": 2
                }
            }
        ]
    }

    response = client.post("/api/policies/verify-smt", json=sample_policy)
    assert response.status_code == 200
    data = response.json()

    assert "fsm_report" in data
    assert "smt_analysis" in data
    assert data["smt_analysis"]["solver_engine"] == "Microsoft Z3 Theorem Prover"
    assert data["smt_analysis"]["has_dead_transitions"] is False
    assert len(data["smt_analysis"]["guard_satisfiability_checks"]) >= 1

    grant_check = data["smt_analysis"]["guard_satisfiability_checks"][0]
    assert grant_check["smt_status"] == "SAT"
    assert grant_check["is_satisfiable"] is True
    assert grant_check["witness_model"]["clearance_level"] >= 2
