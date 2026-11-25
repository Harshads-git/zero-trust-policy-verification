"""
Unit & Integration Test Suite for Open Policy Agent (OPA) Rego Compiler
AxiomTrust Formal Verification Platform
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.policy import ZeroTrustPolicy, PolicyRule, PolicyMetadata
from backend.models.transpiler import OPARegoExportRequest
from backend.transpiler.opa_rego import OPARegoGenerator


@pytest.fixture
def api_client():
    return TestClient(app)


@pytest.fixture
def generator():
    return OPARegoGenerator()


@pytest.fixture
def enterprise_fsm_policy():
    return ZeroTrustPolicy(
        policy_id="pol_rego_test_01",
        policy_name="Corporate Banking Zero Trust Perimeter",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "ACCESS_DENIED", "SESSION_EXPIRED", "REVOKED"],
        metadata=PolicyMetadata(
            author="AxiomTrust Security Team",
            target_resource="core_banking_ledger",
            allowed_roles=["teller", "bank_manager", "auditor"],
            max_session_seconds=1800,
            risk_threshold="LOW"
        ),
        rules=[
            PolicyRule(source="START", target="AUTHENTICATED", action="mfa_login", condition="auth_method == 'mfa'"),
            PolicyRule(source="AUTHENTICATED", target="DEVICE_VERIFIED", action="verify_hardware", condition="device_health == 'compliant'"),
            PolicyRule(source="DEVICE_VERIFIED", target="ACCESS_GRANTED", action="grant_ledger_access", condition="role == 'bank_manager'"),
            PolicyRule(source="ACCESS_GRANTED", target="SESSION_EXPIRED", action="timeout", condition="session_duration > 1800"),
            PolicyRule(source="ACCESS_GRANTED", target="REVOKED", action="admin_revoke"),
            PolicyRule(source="START", target="ACCESS_DENIED", action="reject")
        ]
    )


def test_compile_standard_policy_to_rego(generator, enterprise_fsm_policy):
    """Validates complete compilation of Zero Trust FSM into idiomatic OPA Rego."""
    response = generator.compile(enterprise_fsm_policy)

    assert response.policy_id == "pol_rego_test_01"
    assert response.package_name == "axiomtrust.authz"
    assert response.rules_compiled == 6
    assert response.validation_status == "COMPILED"

    rego = response.rego_code
    assert "package axiomtrust.authz" in rego
    assert "default allow := false" in rego
    assert "default allow_action := false" in rego
    assert 'initial_state := "START"' in rego
    assert '"ACCESS_GRANTED"' in rego
    assert '"bank_manager"' in rego
    assert "max_session_seconds := 1800" in rego

    # Verify core decision logic
    assert "allow if {" in rego
    assert "valid_transition" in rego
    assert "not session_expired" in rego
    assert "not is_revoked" in rego

    # Verify individual transition rules
    assert 'input.current_state == "START"' in rego
    assert 'input.action == "mfa_login"' in rego
    assert 'input.target_state == "AUTHENTICATED"' in rego
    assert 'input.auth_method == "mfa"' in rego

    # Verify explainable denial diagnostics
    assert "violations contains \"MISSING_IDENTITY_AUTHENTICATION\"" in rego
    assert "violations contains \"NON_COMPLIANT_DEVICE_POSTURE\"" in rego
    assert "violations contains \"INVALID_FSM_TRANSITION\"" in rego


def test_compile_with_custom_package_and_roles(generator, enterprise_fsm_policy):
    """Verifies custom package namespace and metadata override."""
    req = OPARegoExportRequest(
        package_name="k8s.admission.secops",
        target_framework="general",
        enforce_strict_zero_trust=False
    )
    response = generator.compile(enterprise_fsm_policy, req)

    assert response.package_name == "k8s.admission.secops"
    assert "package k8s.admission.secops" in response.rego_code


def test_condition_translation_to_rego_clauses(generator):
    """Tests the translation of diverse FSM condition strings into Rego syntax."""
    # Equality
    clauses1 = generator._translate_condition_to_rego("role == 'admin'")
    assert clauses1 == ['input.role == "admin"']

    # Inequality
    clauses2 = generator._translate_condition_to_rego("status != 'revoked'")
    assert clauses2 == ['input.status != "revoked"']

    # Numeric comparison with literal
    clauses3 = generator._translate_condition_to_rego("session_duration > 3600")
    assert clauses3 == ['input.session_duration > 3600']

    # Numeric comparison with input variable
    clauses4 = generator._translate_condition_to_rego("age >= max_age")
    assert clauses4 == ['input.age >= input.max_age']

    # Boolean
    clauses5 = generator._translate_condition_to_rego("is_active == true")
    assert clauses5 == ['input.is_active == true']

    # Compound AND
    clauses6 = generator._translate_condition_to_rego("auth == 'mfa' AND risk <= 20")
    assert clauses6 == ['input.auth == "mfa"', 'input.risk <= 20']


def test_gatekeeper_framework_export(generator, enterprise_fsm_policy):
    """Validates generation of Kubernetes Gatekeeper constraint violation blocks."""
    req = OPARegoExportRequest(
        target_framework="kubernetes_gatekeeper"
    )
    response = generator.compile(enterprise_fsm_policy, req)

    rego = response.rego_code
    assert "violation[{\"msg\": msg}] if {" in rego
    assert "AxiomTrust Zero Trust Admission Denied" in rego
    assert "not allow" in rego


def test_envoy_proxy_framework_export(generator, enterprise_fsm_policy):
    """Validates generation of Envoy ext_authz JSON response mappings."""
    req = OPARegoExportRequest(
        target_framework="envoy_proxy"
    )
    response = generator.compile(enterprise_fsm_policy, req)

    rego = response.rego_code
    assert "response := {" in rego
    assert '"allowed": allow' in rego
    assert '"x-axiomtrust-policy"' in rego


def test_opa_rego_rest_api_endpoint(api_client, enterprise_fsm_policy):
    """Tests POST /api/transpile/opa-rego endpoint with inline policy."""
    payload = {
        "policy": enterprise_fsm_policy.model_dump(),
        "package_name": "corp.authz",
        "target_framework": "general"
    }
    response = api_client.post("/api/transpile/opa-rego", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["policy_id"] == "pol_rego_test_01"
    assert data["package_name"] == "corp.authz"
    assert data["rules_compiled"] == 6
    assert "package corp.authz" in data["rego_code"]


def test_export_stored_policy_api_endpoint(api_client, enterprise_fsm_policy):
    """Tests GET /api/transpile/{policy_id}/opa-rego for stored policy."""
    # 1. Create policy in storage
    create_res = api_client.post("/api/policies/", json=enterprise_fsm_policy.model_dump())
    assert create_res.status_code == 201
    stored_id = create_res.json()["policy"]["policy_id"]

    # 2. Export to OPA Rego
    get_res = api_client.get(f"/api/transpile/{stored_id}/opa-rego?package_name=api.test")
    assert get_res.status_code == 200

    data = get_res.json()
    assert data["policy_id"] == stored_id
    assert data["package_name"] == "api.test"

    # 3. 404 for missing policy
    missing_res = api_client.get("/api/transpile/pol_missing_404/opa-rego")
    assert missing_res.status_code == 404


def test_download_stored_policy_rego_file(api_client, enterprise_fsm_policy):
    """Tests GET /api/transpile/{policy_id}/opa-rego/download endpoint."""
    create_res = api_client.post("/api/policies/", json=enterprise_fsm_policy.model_dump())
    assert create_res.status_code == 201
    stored_id = create_res.json()["policy"]["policy_id"]

    download_res = api_client.get(f"/api/transpile/{stored_id}/opa-rego/download")
    assert download_res.status_code == 200
    assert "text/plain" in download_res.headers["content-type"]
    assert f'filename="{stored_id}.rego"' in download_res.headers["content-disposition"]
    assert "package axiomtrust.authz" in download_res.text
    assert "default allow := false" in download_res.text
