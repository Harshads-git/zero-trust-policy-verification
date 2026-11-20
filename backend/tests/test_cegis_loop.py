"""
Unit and Integration Test Suite for Counterexample-Guided Inductive Synthesis (CEGIS) Loop
AxiomTrust Formal Verification Platform

Tests:
- CEGIS termination on already-compliant policies (NO_REPAIR_NEEDED)
- Single-round and multi-round iterative convergence (CONVERGED)
- Bounded iteration limits avoiding infinite synthesis loops (MAX_ITERATIONS_REACHED)
- Inductive counterexample witness trace accumulation across rounds
- Cumulative RFC 6902 JSON patch application roundtrip
- REST API endpoints for CEGIS loop execution
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.policy import ZeroTrustPolicy, PolicyRule
from backend.core.cegis_loop import CEGISEngine, CEGISStatus
from backend.core.synthesizer import apply_rfc6902_patch

client = TestClient(app)


def test_cegis_no_repair_needed_on_compliant_policy():
    """Verifies that an already compliant policy short-circuits with NO_REPAIR_NEEDED."""
    policy = ZeroTrustPolicy(
        policy_name="Already Compliant Policy",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "ACCESS_DENIED", "SESSION_EXPIRED", "REVOKED"],
        rules=[
            PolicyRule(source="START", target="AUTHENTICATED", action="authenticate", condition="auth_method == 'mfa'"),
            PolicyRule(source="AUTHENTICATED", target="DEVICE_VERIFIED", action="verify_device", condition="device_health == 'compliant'"),
            PolicyRule(source="DEVICE_VERIFIED", target="ACCESS_GRANTED", action="grant"),
            PolicyRule(source="ACCESS_GRANTED", target="SESSION_EXPIRED", action="timeout"),
            PolicyRule(source="ACCESS_GRANTED", target="REVOKED", action="revoke"),
            PolicyRule(source="AUTHENTICATED", target="ACCESS_DENIED", action="deny"),
        ]
    )
    engine = CEGISEngine(max_iterations=5)
    result = engine.run_cegis_loop(policy)

    assert result.status == CEGISStatus.NO_REPAIR_NEEDED
    assert result.converged is True
    assert result.iterations_count == 0
    assert result.initial_violations_count == 0
    assert result.final_violations_count == 0
    assert len(result.iteration_history) == 0


def test_cegis_single_round_convergence():
    """
    Verifies that a policy with an isolated flaw (missing session revocability)
    converges cleanly in a single CEGIS iteration round.
    """
    flawed_policy = ZeroTrustPolicy(
        policy_name="Missing Revocation Policy",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "SESSION_EXPIRED", "REVOKED"],
        rules=[
            PolicyRule(source="START", target="AUTHENTICATED", action="login", condition="auth_method == 'mfa'"),
            PolicyRule(source="AUTHENTICATED", target="DEVICE_VERIFIED", action="check_dev", condition="device_health == 'compliant'"),
            PolicyRule(source="DEVICE_VERIFIED", target="ACCESS_GRANTED", action="grant")
        ]
    )
    engine = CEGISEngine(max_iterations=5)
    result = engine.run_cegis_loop(flawed_policy)

    assert result.converged is True
    assert result.status == CEGISStatus.CONVERGED
    assert result.iterations_count >= 1
    assert result.initial_violations_count >= 1
    assert result.final_violations_count == 0
    assert result.final_verification_report["valid"] is True


def test_cegis_multi_round_chained_convergence():
    """
    Verifies that a severely flawed policy with multiple interacting vulnerabilities
    iteratively refines and converges over multiple synthesis-verification rounds.
    """
    severely_flawed_policy = ZeroTrustPolicy(
        policy_name="Severely Flawed Chained Policy",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "ACCESS_DENIED", "SESSION_EXPIRED", "REVOKED"],
        rules=[
            # 1. Direct unauthenticated bypass
            PolicyRule(rule_id="r_bypass", source="START", target="ACCESS_GRANTED", action="direct_bypass"),
            # 2. Dead trap state
            PolicyRule(source="START", target="TRAP_STATE", action="enter_trap")
            # 3. Missing revocation paths from ACCESS_GRANTED
        ]
    )
    engine = CEGISEngine(max_iterations=6)
    result = engine.run_cegis_loop(severely_flawed_policy)

    assert result.converged is True
    assert result.status == CEGISStatus.CONVERGED
    assert result.final_violations_count == 0
    assert result.final_verification_report["valid"] is True
    assert len(result.iteration_history) >= 1

    # Check telemetry of each iteration
    for record in result.iteration_history:
        assert record.iteration >= 1
        assert record.iteration_latency_ms >= 0.0


def test_cegis_bounded_iteration_termination():
    """
    Verifies that the CEGIS loop respects the max_iterations bound
    and terminates safely without infinite looping.
    """
    flawed_policy = ZeroTrustPolicy(
        policy_name="Bounded Iteration Policy",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "SESSION_EXPIRED", "REVOKED"],
        rules=[
            PolicyRule(rule_id="r1", source="START", target="ACCESS_GRANTED", action="bypass")
        ]
    )
    # Restrict to strictly 1 iteration
    engine = CEGISEngine(max_iterations=1)
    result = engine.run_cegis_loop(flawed_policy, max_iterations=1)

    assert result.iterations_count <= 1
    assert result.max_iterations == 1
    assert result.status in (CEGISStatus.CONVERGED, CEGISStatus.MAX_ITERATIONS_REACHED)


def test_cegis_counterexample_witness_accumulation():
    """
    Verifies that the CEGIS engine records and accumulates counterexample
    witness traces across all synthesis iterations.
    """
    flawed_policy = ZeroTrustPolicy(
        policy_name="Witness Accumulation Policy",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "SESSION_EXPIRED", "REVOKED"],
        rules=[
            PolicyRule(source="START", target="ACCESS_GRANTED", action="direct_bypass")
        ]
    )
    engine = CEGISEngine(max_iterations=5)
    result = engine.run_cegis_loop(flawed_policy)

    assert result.accumulated_counterexamples_count >= 1
    assert result.unique_counterexamples_count >= 1
    assert len(result.iteration_history) >= 1
    assert len(result.iteration_history[0].counterexample_witnesses) >= 1


def test_cegis_cumulative_rfc6902_applicability():
    """
    Verifies that applying the cumulative RFC 6902 patch document
    to the original flawed policy dictionary yields a structurally compliant policy.
    """
    flawed_policy = ZeroTrustPolicy(
        policy_name="RFC 6902 CEGIS Applicability Policy",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "SESSION_EXPIRED", "REVOKED"],
        rules=[
            PolicyRule(rule_id="r_bypass", source="START", target="ACCESS_GRANTED", action="direct_bypass")
        ]
    )
    engine = CEGISEngine(max_iterations=5)
    result = engine.run_cegis_loop(flawed_policy)

    assert len(result.cumulative_rfc6902_patch_document) > 0
    orig_dict = flawed_policy.model_dump()
    patched_dict = apply_rfc6902_patch(orig_dict, result.cumulative_rfc6902_patch_document)

    patched_rule_ids = [r.get("rule_id") for r in patched_dict.get("rules", [])]
    assert "r_bypass" not in patched_rule_ids


def test_cegis_rest_api_endpoints():
    """
    Verifies HTTP REST API endpoints:
    1. POST /api/policies/cegis-repair (direct payload)
    2. POST /api/policies/{id}/cegis-repair (stored policy)
    """
    sample_policy = {
        "policy_id": "pol_cegis_api_test",
        "policy_name": "API CEGIS Test Policy",
        "initial_state": "START",
        "terminal_states": ["ACCESS_GRANTED", "SESSION_EXPIRED", "REVOKED"],
        "rules": [
            {"rule_id": "r1", "source": "START", "target": "ACCESS_GRANTED", "action": "direct_bypass"}
        ]
    }

    # 1. Direct payload CEGIS endpoint
    res1 = client.post("/api/policies/cegis-repair?max_iterations=5", json=sample_policy)
    assert res1.status_code == 200
    data1 = res1.json()
    assert "status" in data1
    assert "converged" in data1
    assert "iteration_history" in data1
    assert "repaired_policy" in data1

    # 2. Save policy to DB
    save_res = client.post("/api/policies", json=sample_policy)
    assert save_res.status_code == 201

    # 3. Stored policy CEGIS endpoint
    res2 = client.post("/api/policies/pol_cegis_api_test/cegis-repair?max_iterations=5")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["policy_id"] == "pol_cegis_api_test"
    assert data2["converged"] is True

    # Cleanup stored policy
    del_res = client.delete("/api/policies/pol_cegis_api_test")
    assert del_res.status_code == 200
