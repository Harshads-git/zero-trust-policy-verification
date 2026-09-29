"""
FastAPI Integration Tests
Verifies HTTP endpoints for policy submission, verification, and template retrieval.
"""

from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["theory_of_computation_core"] == "operational"


def test_frontend_root_served():
    response = client.get("/")
    assert response.status_code == 200
    assert "Zero Trust Policy Verification Engine" in response.text


def test_get_sample_templates():
    response = client.get("/api/policies/samples/templates")
    assert response.status_code == 200
    data = response.json()
    assert "valid" in data
    assert "invalid" in data
    assert len(data["valid"]) >= 1
    assert len(data["invalid"]) >= 1


def test_verify_endpoint_direct():
    sample_policy = {
        "policy_name": "API Test Direct Verify",
        "initial_state": "START",
        "terminal_states": ["ACCESS_GRANTED", "SESSION_EXPIRED"],
        "rules": [
            {"source": "START", "target": "ACCESS_GRANTED", "action": "direct_bypass"}
        ]
    }
    response = client.post("/api/policies/verify", json=sample_policy)
    assert response.status_code == 200
    report = response.json()
    assert report["valid"] is False
    assert report["violations_count"] > 0


def test_experiments_benchmark_endpoint():
    response = client.post("/api/experiments/benchmark", json=[10, 25])
    assert response.status_code == 200
    data = response.json()
    assert "measurements" in data
    assert len(data["measurements"]) == 2
    for m in data["measurements"]:
        assert "verification_time_ms" in m
        assert "throughput_rules_per_sec" in m


def test_create_and_retrieve_policy():
    new_policy = {
        "policy_id": "pol_api_test_01",
        "policy_name": "API Created Policy",
        "initial_state": "START",
        "terminal_states": ["ACCESS_GRANTED", "SESSION_EXPIRED"],
        "rules": [
            {"source": "START", "target": "AUTHENTICATED", "action": "login"},
            {"source": "AUTHENTICATED", "target": "ACCESS_GRANTED", "action": "grant"},
            {"source": "ACCESS_GRANTED", "target": "SESSION_EXPIRED", "action": "timeout"}
        ]
    }
    # Create policy
    create_res = client.post("/api/policies", json=new_policy)
    assert create_res.status_code == 201
    created_data = create_res.json()
    assert created_data["policy"]["policy_id"] == "pol_api_test_01"

    # Retrieve policy by ID
    get_res = client.get("/api/policies/pol_api_test_01")
    assert get_res.status_code == 200
    assert get_res.json()["policy_name"] == "API Created Policy"


def test_verify_stored_policy_endpoint():
    res = client.get("/api/policies/pol_api_test_01/verify")
    assert res.status_code == 200
    report = res.json()
    assert report["policy_id"] == "pol_api_test_01"
    assert "risk_score" in report
    assert "security_posture" in report


def test_get_remediation_plan_endpoint():
    res = client.get("/api/policies/pol_api_test_01/remediation")
    assert res.status_code == 200
    data = res.json()
    assert data["policy_id"] == "pol_api_test_01"
    assert "remediation_plan" in data
    assert "security_posture" in data


def test_get_nonexistent_policy_returns_404():
    res = client.get("/api/policies/non_existent_policy_999")
    assert res.status_code == 404


def test_delete_policy_endpoint():
    del_res = client.delete("/api/policies/pol_api_test_01")
    assert del_res.status_code == 200
    # Confirm deletion
    get_res = client.get("/api/policies/pol_api_test_01")
    assert get_res.status_code == 404

