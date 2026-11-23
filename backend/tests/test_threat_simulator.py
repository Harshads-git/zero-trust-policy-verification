"""
Unit & Integration Test Suite for Red-Team Attack Graph & Lateral Movement Simulation
AxiomTrust Formal Verification Platform
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.policy import ZeroTrustPolicy, PolicyRule
from backend.models.threat import (
    ThreatSimulationRequest,
    ExploitDifficulty
)
from backend.core.threat_simulator import AttackGraphSimulator


@pytest.fixture
def api_client():
    return TestClient(app)


@pytest.fixture
def sample_enterprise_policy():
    return ZeroTrustPolicy(
        policy_name="Enterprise Corporate Zero Trust Perimeter",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "ACCESS_DENIED", "SESSION_EXPIRED", "REVOKED"],
        rules=[
            PolicyRule(source="START", target="AUTHENTICATED", action="mfa_login", condition="auth_method == 'mfa'"),
            PolicyRule(source="AUTHENTICATED", target="DEVICE_VERIFIED", action="check_posture", condition="device_health == 'compliant'"),
            PolicyRule(source="DEVICE_VERIFIED", target="ACCESS_GRANTED", action="grant_access", condition="role == 'analyst'"),
            PolicyRule(source="ACCESS_GRANTED", target="SESSION_EXPIRED", action="timeout"),
            PolicyRule(source="ACCESS_GRANTED", target="REVOKED", action="revoke"),
            PolicyRule(source="START", target="ACCESS_DENIED", action="reject")
        ]
    )


@pytest.fixture
def multi_path_choke_point_policy():
    return ZeroTrustPolicy(
        policy_name="Multi-Path Choke Point Gateway Policy",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "ACCESS_DENIED"],
        rules=[
            # Path 1: via Identity Provider A
            PolicyRule(source="START", target="IDP_A", action="login_idp_a"),
            PolicyRule(source="IDP_A", target="SECURITY_GATEWAY", action="route_gateway_a"),
            # Path 2: via Identity Provider B
            PolicyRule(source="START", target="IDP_B", action="login_idp_b"),
            PolicyRule(source="IDP_B", target="SECURITY_GATEWAY", action="route_gateway_b"),
            # Unified choke point to crown jewel
            PolicyRule(source="SECURITY_GATEWAY", target="ACCESS_GRANTED", action="grant_final", condition="role == 'admin'"),
            PolicyRule(source="START", target="ACCESS_DENIED", action="deny")
        ]
    )


def test_threat_simulation_initial_compromise_reachability(sample_enterprise_policy):
    """Simulates compromise from START and checks lateral reachability to crown jewels."""
    simulator = AttackGraphSimulator()
    req = ThreatSimulationRequest(
        compromised_node="START",
        crown_jewels=["ACCESS_GRANTED"],
        max_exploit_depth=5
    )

    result = simulator.simulate(sample_enterprise_policy, req)

    assert result.compromised_node == "START"
    assert result.total_policy_states == 7
    assert "AUTHENTICATED" in result.attacker_reachable_states
    assert "DEVICE_VERIFIED" in result.attacker_reachable_states
    assert "ACCESS_GRANTED" in result.attacker_reachable_states
    assert "ACCESS_GRANTED" in result.compromised_crown_jewels

    assert result.blast_radius_percentage > 50.0
    assert result.blast_radius_score > 0.5
    assert len(result.exploit_paths) >= 1
    assert result.exploit_paths[0].target_crown_jewel == "ACCESS_GRANTED"
    assert result.exploit_paths[0].hop_count == 3
    assert len(result.containment_recommendations) >= 2


def test_threat_simulation_isolated_node_zero_blast_radius(sample_enterprise_policy):
    """Simulates compromise of terminal state with 0 outbound edges."""
    simulator = AttackGraphSimulator()
    req = ThreatSimulationRequest(
        compromised_node="SESSION_EXPIRED",
        crown_jewels=["ACCESS_GRANTED"]
    )

    result = simulator.simulate(sample_enterprise_policy, req)

    assert result.compromised_node == "SESSION_EXPIRED"
    assert result.attacker_reachable_states == ["SESSION_EXPIRED"]
    assert result.blast_radius_score == round(1.0 / 7.0, 3)
    assert result.compromised_crown_jewels == []
    assert result.exploit_paths == []
    assert result.choke_points == []
    assert result.blast_radius_severity == "LOW"


def test_critical_single_point_of_defense_choke_point(multi_path_choke_point_policy):
    """Verifies that SECURITY_GATEWAY is identified as 100% critical single-point-of-defense."""
    simulator = AttackGraphSimulator()
    req = ThreatSimulationRequest(
        compromised_node="START",
        crown_jewels=["ACCESS_GRANTED"],
        max_exploit_depth=5
    )

    result = simulator.simulate(multi_path_choke_point_policy, req)

    assert len(result.exploit_paths) == 2  # Through IDP_A and IDP_B
    assert len(result.choke_points) >= 1

    primary_cp = result.choke_points[0]
    assert primary_cp.node == "SECURITY_GATEWAY"
    assert primary_cp.interception_ratio == 1.0
    assert primary_cp.paths_intercepted == 2
    assert primary_cp.is_critical_single_point_of_defense is True
    assert "Critical Choke Point" in primary_cp.defense_strategy

    # Assert recommendations highlight the single-point-of-defense
    assert any("Single-Point-of-Defense" in r and "'SECURITY_GATEWAY'" in r for r in result.containment_recommendations)


def test_exploit_path_difficulty_and_bypasses():
    """Validates exploit path difficulty classification and architectural bypass flagging."""
    flawed_policy = ZeroTrustPolicy(
        policy_name="Flawed Bypass Policy",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED"],
        rules=[
            PolicyRule(source="START", target="ACCESS_GRANTED", action="unauthenticated_bypass", condition="")
        ]
    )

    simulator = AttackGraphSimulator()
    req = ThreatSimulationRequest(
        compromised_node="START",
        crown_jewels=["ACCESS_GRANTED"]
    )

    result = simulator.simulate(flawed_policy, req)

    assert len(result.exploit_paths) == 1
    path = result.exploit_paths[0]
    assert path.overall_difficulty == ExploitDifficulty.TRIVIAL
    assert "missing_device_inspection" in path.required_bypasses
    assert "unauthenticated_access_jump" in path.required_bypasses
    assert result.blast_radius_severity == "CRITICAL"


def test_invalid_compromised_node_raises_error(sample_enterprise_policy):
    """Assures ValueError is raised when compromised node is not in policy state space."""
    simulator = AttackGraphSimulator()
    req = ThreatSimulationRequest(
        compromised_node="GHOST_NODE_404",
        crown_jewels=["ACCESS_GRANTED"]
    )

    with pytest.raises(ValueError) as excinfo:
        simulator.simulate(sample_enterprise_policy, req)
    assert "GHOST_NODE_404" in str(excinfo.value)


def test_threat_simulate_rest_api_endpoint(api_client, sample_enterprise_policy):
    """Tests POST /api/threat/simulate with inline policy payload."""
    payload = {
        "policy": sample_enterprise_policy.model_dump(),
        "compromised_node": "START",
        "crown_jewels": ["ACCESS_GRANTED"],
        "max_exploit_depth": 5
    }

    response = api_client.post("/api/threat/simulate", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["compromised_node"] == "START"
    assert "simulation_id" in data
    assert data["blast_radius_score"] > 0
    assert "ACCESS_GRANTED" in data["compromised_crown_jewels"]
    assert len(data["exploit_paths"]) >= 1
    assert len(data["containment_recommendations"]) >= 1


def test_threat_simulate_stored_policy_endpoint(api_client, sample_enterprise_policy):
    """Tests POST /api/threat/{policy_id}/simulate for an existing stored policy."""
    # 1. Create policy in storage
    create_resp = api_client.post("/api/policies/", json=sample_enterprise_policy.model_dump())
    assert create_resp.status_code == 201
    policy_id = create_resp.json()["policy"]["policy_id"]

    # 2. Simulate threat on stored policy
    sim_payload = {
        "compromised_node": "AUTHENTICATED",
        "crown_jewels": ["ACCESS_GRANTED"]
    }
    sim_resp = api_client.post(f"/api/threat/{policy_id}/simulate", json=sim_payload)
    assert sim_resp.status_code == 200

    sim_data = sim_resp.json()
    assert sim_data["compromised_node"] == "AUTHENTICATED"
    assert "ACCESS_GRANTED" in sim_data["compromised_crown_jewels"]

    # 3. Simulate on non-existent policy returns 404
    bad_resp = api_client.post("/api/threat/pol_nonexistent_999/simulate", json=sim_payload)
    assert bad_resp.status_code == 404
