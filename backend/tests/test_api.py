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



def test_ui_verify_smt_contract():
    """
    Verifies that the /api/policies/verify-smt contract matches the exact JSON
    structure expected by the frontend Visualizer and SMT Inspector.
    """
    sample_policy = {
        "policy_id": "pol_smt_ui_test",
        "policy_name": "SMT UI Contract Verification",
        "initial_state": "START",
        "terminal_states": ["ACCESS_GRANTED", "SESSION_EXPIRED"],
        "rules": [
            {
                "rule_id": "r_auth",
                "source": "START",
                "target": "AUTHENTICATED",
                "action": "authenticate",
                "condition": "auth_method == 'mfa'"
            },
            {
                "rule_id": "r_grant",
                "source": "AUTHENTICATED",
                "target": "ACCESS_GRANTED",
                "action": "grant",
                "predicate": {
                    "attribute": "risk_score",
                    "operator": "<=",
                    "value": 0.40
                }
            },
            {
                "rule_id": "r_dead",
                "source": "AUTHENTICATED",
                "target": "SESSION_EXPIRED",
                "action": "impossible",
                "predicate": {
                    "logical_op": "AND",
                    "predicates": [
                        {"attribute": "risk_score", "operator": ">", "value": 0.90},
                        {"attribute": "risk_score", "operator": "<", "value": 0.10}
                    ]
                }
            }
        ]
    }
    response = client.post("/api/policies/verify-smt", json=sample_policy)
    assert response.status_code == 200
    data = response.json()
    assert "fsm_report" in data
    assert "smt_analysis" in data

    smt = data["smt_analysis"]
    assert smt["solver_engine"] == "Microsoft Z3 Theorem Prover"
    assert smt["has_dead_transitions"] is True
    assert len(smt["dead_transitions_detected"]) == 1
    dead_entry = smt["dead_transitions_detected"][0]
    assert dead_entry["rule_id"] == "r_dead"
    assert "reason" in dead_entry

    # Verify guard satisfiability check for r_grant
    checks = smt["guard_satisfiability_checks"]
    assert len(checks) == 1
    assert checks[0]["rule_id"] == "r_grant"
    assert checks[0]["is_satisfiable"] is True
    assert "witness_model" in checks[0]
    assert checks[0]["witness_model"] is not None


def test_ui_verify_risk_contract():
    """
    Verifies that the /api/policies/verify-risk contract provides trajectory
    profiles, continuous risk calculations, and step-up authentication status for the UI.
    """
    sample_policy = {
        "policy_id": "pol_risk_ui_test",
        "policy_name": "Risk UI Contract Verification",
        "initial_state": "START",
        "terminal_states": ["ACCESS_GRANTED", "SESSION_EXPIRED"],
        "rules": [
            {
                "rule_id": "r1",
                "source": "START",
                "target": "AUTHENTICATED",
                "action": "login",
                "condition": "auth_method == 'mfa'"
            },
            {
                "rule_id": "r2",
                "source": "AUTHENTICATED",
                "target": "STEP_UP_AUTH",
                "action": "challenge_stepup",
                "condition": "risk_score > 0.50"
            },
            {
                "rule_id": "r3",
                "source": "STEP_UP_AUTH",
                "target": "ACCESS_GRANTED",
                "action": "grant_after_challenge"
            },
            {
                "rule_id": "r4",
                "source": "ACCESS_GRANTED",
                "target": "SESSION_EXPIRED",
                "action": "logout"
            }
        ]
    }
    response = client.post("/api/policies/verify-risk?stepup_threshold=0.50", json=sample_policy)
    assert response.status_code == 200
    data = response.json()

    assert data["policy_id"] == "pol_risk_ui_test"
    assert data["stepup_threshold"] == 0.50
    assert "trajectory_risk_profiles" in data
    assert len(data["trajectory_risk_profiles"]) >= 1

    profile = data["trajectory_risk_profiles"][0]
    assert "trajectory" in profile
    assert profile["trajectory"] == ["START", "AUTHENTICATED", "STEP_UP_AUTH", "ACCESS_GRANTED"]
    assert "cumulative_risk" in profile
    assert "step_up_triggered" in profile
    assert profile["step_up_triggered"] is True
    assert profile["is_compliant"] is True
    assert "risk_breakdown" in profile


def test_frontend_smt_ui_assets_served():
    """
    Verifies that frontend static assets are properly wired and contain
    SMT theorem prover UI components, CSS classes, and controller functions.
    """
    # Check index.html contains SMT elements
    res_html = client.get("/")
    assert res_html.status_code == 200
    assert "btn-verify-smt" in res_html.text
    assert "smt-inspector-container" in res_html.text
    assert "First-Order SMT Solver & Risk Dashboard" in res_html.text

    # Check CSS contains SMT styles
    res_css = client.get("/static/css/style.css")
    assert res_css.status_code == 200
    assert ".smt-inspector-box" in res_css.text
    assert ".btn-smt" in res_css.text
    assert ".badge-sat" in res_css.text

    # Check JS contains SMT controller functions
    res_js = client.get("/static/js/app.js")
    assert res_js.status_code == 200
    assert "verifyPolicyWithSMT" in res_js.text
    assert "renderSmtAndRiskDashboard" in res_js.text


def test_frontend_cegis_ui_assets_served():
    """
    Verifies that frontend static assets are properly wired and contain
    CEGIS self-healing UI components, visual graph diff classes, and controller functions.
    """
    # Check index.html contains CEGIS elements
    res_html = client.get("/")
    assert res_html.status_code == 200
    assert "btn-cegis-repair" in res_html.text
    assert "cegis-inspector-container" in res_html.text
    assert "CEGIS Self-Healing Policy Synthesizer" in res_html.text
    assert "btn-view-diff" in res_html.text
    assert "btn-apply-cegis" in res_html.text

    # Check CSS contains CEGIS styles
    res_css = client.get("/static/css/style.css")
    assert res_css.status_code == 200
    assert ".btn-cegis" in res_css.text
    assert ".cegis-inspector-box" in res_css.text
    assert ".cegis-trace-table" in res_css.text

    # Check visualizer JS contains graph diff functions and styles
    res_viz = client.get("/static/js/visualizer.js")
    assert res_viz.status_code == 200
    assert "renderGraphDiff" in res_viz.text
    assert "diff-added" in res_viz.text
    assert "diff-removed" in res_viz.text

    # Check app JS contains CEGIS controller functions
    res_js = client.get("/static/js/app.js")
    assert res_js.status_code == 200
    assert "runCegisAutoRepair" in res_js.text
    assert "applySynthesizedRepairToEditor" in res_js.text
    assert "switchGraphView" in res_js.text


def test_frontend_threat_ui_assets_served():
    """Day 27: Verify frontend serves threat simulation & blast radius radar assets."""
    # Check HTML contains Threat Simulation controls
    res_html = client.get("/")
    assert res_html.status_code == 200
    assert "btn-threat-sim" in res_html.text
    assert "threat-inspector-container" in res_html.text
    assert "threat-node-select" in res_html.text
    assert "threat-exploit-paths-container" in res_html.text
    assert "Simulate Adversary" in res_html.text

    # Check CSS contains Threat Simulation styles
    res_css = client.get("/static/css/style.css")
    assert res_css.status_code == 200
    assert ".btn-threat" in res_css.text
    assert ".threat-inspector-box" in res_css.text
    assert ".badge-choke-point" in res_css.text
    assert ".threat-stats-grid" in res_css.text

    # Check visualizer JS contains threat modeling functions and styles
    res_viz = client.get("/static/js/visualizer.js")
    assert res_viz.status_code == 200
    assert "renderThreatSimulation" in res_viz.text
    assert "clearThreatSimulationView" in res_viz.text
    assert "threat-compromised-node" in res_viz.text
    assert "threat-choke-point" in res_viz.text

    # Check app JS contains Threat Simulation controller functions
    res_js = client.get("/static/js/app.js")
    assert res_js.status_code == 200
    assert "runThreatSimulation" in res_js.text
    assert "populateThreatNodeSelector" in res_js.text
    assert "renderThreatChokePoints" in res_js.text
    assert "closeThreatInspector" in res_js.text

