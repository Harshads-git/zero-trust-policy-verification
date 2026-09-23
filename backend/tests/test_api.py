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
