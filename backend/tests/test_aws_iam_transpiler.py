"""
Unit & Integration Test Suite for AWS IAM Policy to Zero Trust FSM Transpiler
AxiomTrust Formal Verification Platform
"""

import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.transpiler.aws_iam import AWSIAMTranspiler


@pytest.fixture
def api_client():
    return TestClient(app)


@pytest.fixture
def transpiler():
    return AWSIAMTranspiler()


@pytest.fixture
def standard_s3_mfa_iam_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3WithMFA",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::corp-analytics-data/*",
                "Condition": {
                    "Bool": {
                        "aws:MultiFactorAuthPresent": "true"
                    },
                    "IpAddress": {
                        "aws:SourceIp": "10.0.0.0/8"
                    }
                }
            }
        ]
    }


@pytest.fixture
def wildcard_admin_iam_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "WildcardAdminAccess",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }


def test_transpile_standard_s3_policy_with_mfa(transpiler, standard_s3_mfa_iam_policy):
    """Verifies transpilation of standard S3 policy with MFA and network CIDR constraints."""
    result = transpiler.transpile(standard_s3_mfa_iam_policy, policy_name="S3_Corp_Policy")

    assert result.policy_name == "S3_Corp_Policy"
    assert result.statements_count == 1
    assert result.mfa_enforced is True
    assert result.has_wildcard_actions is False
    assert result.has_wildcard_resources is False
    assert "s3:GetObject" in result.allowed_actions
    assert "s3:PutObject" in result.allowed_actions

    policy = result.transpiled_policy
    assert policy.initial_state == "START"
    all_states = policy.get_all_states()
    assert "START" in all_states
    assert "AUTHENTICATED" in all_states
    assert "DEVICE_VERIFIED" in all_states
    assert "ACCESS_GRANTED" in all_states
    assert "SESSION_EXPIRED" in all_states
    assert "REVOKED" in all_states

    # Verify MFA rule condition
    mfa_rule = next(r for r in policy.rules if r.source == "START" and r.target == "AUTHENTICATED")
    assert mfa_rule.condition == "auth_method == 'mfa'"

    # Verify session timeout rule
    assert any(r.source == "ACCESS_GRANTED" and r.target == "SESSION_EXPIRED" for r in policy.rules)


def test_transpile_wildcard_admin_policy_with_escalation_detection(transpiler, wildcard_admin_iam_policy):
    """Verifies detection of wildcards and critical privilege escalation vectors."""
    result = transpiler.transpile(wildcard_admin_iam_policy)

    assert result.has_wildcard_actions is True
    assert result.has_wildcard_resources is True
    assert result.mfa_enforced is False
    assert len(result.transpilation_notes) >= 2

    # Privilege escalation vectors must be detected for wildcard
    vector_names = [risk.vector for risk in result.privilege_escalation_risks]
    assert "IAM_POLICY_VERSION_UPDATE" in vector_names
    assert "IAM_ATTACH_ADMIN_POLICY" in vector_names
    assert "IAM_INLINE_POLICY_CREATION" in vector_names

    # Check risk severity
    critical_risks = [r for r in result.privilege_escalation_risks if r.severity == "CRITICAL"]
    assert len(critical_risks) >= 3


def test_transpile_passrole_compute_escalation_detection(transpiler):
    """Validates specific combination detection for iam:PassRole + ec2:RunInstances."""
    iam_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:PassRole", "ec2:RunInstances"],
                "Resource": "*"
            }
        ]
    }
    result = transpiler.transpile(iam_doc)

    vector_names = [risk.vector for risk in result.privilege_escalation_risks]
    assert "IAM_PASS_ROLE_COMPUTE_ESCALATION" in vector_names

    passrole_risk = next(r for r in result.privilege_escalation_risks if r.vector == "IAM_PASS_ROLE_COMPUTE_ESCALATION")
    assert passrole_risk.severity == "CRITICAL"
    assert "iam:passrole" in passrole_risk.actions
    assert "ec2:runinstances" in passrole_risk.actions


def test_transpile_explicit_deny_statement(transpiler):
    """Verifies that IAM Effect: Deny statements route directly to ACCESS_DENIED sink."""
    iam_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRead",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            },
            {
                "Sid": "DenyDelete",
                "Effect": "Deny",
                "Action": "s3:DeleteBucket",
                "Resource": "arn:aws:s3:::my-bucket"
            }
        ]
    }
    result = transpiler.transpile(iam_doc)

    assert result.statements_count == 2
    assert "s3:GetObject" in result.allowed_actions
    assert "s3:DeleteBucket" in result.denied_actions

    policy = result.transpiled_policy
    # Deny transitions should target ACCESS_DENIED
    deny_rules = [r for r in policy.rules if r.target == "ACCESS_DENIED"]
    assert len(deny_rules) >= 1
    assert any(r.action == "s3:DeleteBucket" for r in deny_rules)


def test_transpile_assume_role_chain(transpiler):
    """Validates that sts:AssumeRole creates intermediate role assumption states."""
    iam_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::123456789012:role/ProductionDeployer"
            }
        ]
    }
    result = transpiler.transpile(iam_doc)

    policy = result.transpiled_policy
    all_states = policy.get_all_states()
    assert "ROLE_ASSUMED_PRIVILEGED" in all_states

    # Check for AssumeRole privilege escalation risk
    vector_names = [r.vector for r in result.privilege_escalation_risks]
    assert "STS_ASSUME_ROLE_ELEVATION" in vector_names


def test_transpile_and_auto_verify(transpiler, standard_s3_mfa_iam_policy):
    """Verifies auto_verify flag runs the Zero Trust Verification Engine on the transpiled policy."""
    result = transpiler.transpile(standard_s3_mfa_iam_policy, auto_verify=True)

    assert result.verification_report is not None
    assert "valid" in result.verification_report
    assert "security_posture" in result.verification_report
    assert "risk_score" in result.verification_report
    assert "violations_count" in result.verification_report


def test_transpile_api_endpoint(api_client, standard_s3_mfa_iam_policy):
    """Tests POST /api/transpile/aws-iam endpoint with valid IAM JSON."""
    payload = {
        "iam_policy": standard_s3_mfa_iam_policy,
        "policy_name": "API_Transpiled_S3",
        "auto_verify": False
    }
    response = api_client.post("/api/transpile/aws-iam", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["policy_name"] == "API_Transpiled_S3"
    assert data["statements_count"] == 1
    assert data["mfa_enforced"] is True
    assert "transpiled_policy" in data
    assert data["transpiled_policy"]["initial_state"] == "START"


def test_transpile_and_verify_api_endpoint(api_client, standard_s3_mfa_iam_policy):
    """Tests POST /api/transpile/aws-iam/verify endpoint."""
    payload = {
        "iam_policy": json.dumps(standard_s3_mfa_iam_policy),
        "policy_name": "API_Verified_S3"
    }
    response = api_client.post("/api/transpile/aws-iam/verify", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["verification_report"] is not None
    assert "security_posture" in data["verification_report"]


def test_invalid_json_document_raises_400(api_client):
    """Tests that malformed JSON document returns HTTP 400."""
    payload = {
        "iam_policy": "INVALID_JSON_SYNTAX{{{",
        "policy_name": "Broken_Policy"
    }
    response = api_client.post("/api/transpile/aws-iam", json=payload)
    assert response.status_code == 400
    assert "Invalid AWS IAM JSON document" in response.json()["detail"]
