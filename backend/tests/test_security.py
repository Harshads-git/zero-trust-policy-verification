"""
Security Hardening & Threat Mitigation Test Suite
Tests payload sanitization (JSON bomb, XSS, null bytes), rate limiting throttling (HTTP 429),
and NIST SP 800-207 least-privilege IAM policy generation.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.policy import ZeroTrustPolicy, PolicyRule
from backend.security.sanitizer import (
    PolicySanitizer,
    PolicySanitizationError,
    MAX_NESTING_DEPTH
)
from backend.security.iam_generator import IAMLeastPrivilegePolicyGenerator
from backend.security.rate_limiter import SlidingWindowRateLimiter

client = TestClient(app)


def test_sanitizer_allows_valid_policy():
    """Verifies legitimate Zero Trust policy passes sanitization cleanly."""
    valid_policy = ZeroTrustPolicy(
        policy_id="valid-corp-pol",
        policy_name="Corp Production Zero Trust Policy",
        version="1.0.0",
        rules=[
            PolicyRule(rule_id="R1", source="START", target="AUTH", action="MFA_LOGIN")
        ]
    )
    sanitized = PolicySanitizer.sanitize_policy(valid_policy)
    assert sanitized.policy_id == "valid-corp-pol"
    assert sanitized.policy_name == "Corp Production Zero Trust Policy"


def test_sanitizer_rejects_nested_json_bomb():
    """Verifies that deeply nested objects (JSON bombs / DoS payloads) are rejected."""
    # Build nested dictionary deeper than MAX_NESTING_DEPTH
    nested_bomb = {"level": 1}
    curr = nested_bomb
    for i in range(2, MAX_NESTING_DEPTH + 5):
        curr["child"] = {"level": i}
        curr = curr["child"]

    with pytest.raises(PolicySanitizationError) as exc_info:
        PolicySanitizer.check_nesting_depth(nested_bomb)
    assert "exceeds maximum allowed nesting depth" in str(exc_info.value.detail)


def test_sanitizer_rejects_script_injection():
    """Verifies XSS / script injection in policy strings is caught and rejected."""
    xss_policy = ZeroTrustPolicy(
        policy_id="xss-pol",
        policy_name="<script>alert('xss')</script>",
        rules=[
            PolicyRule(rule_id="R1", source="START", target="AUTH", action="LOGIN")
        ]
    )
    with pytest.raises(PolicySanitizationError) as exc_info:
        PolicySanitizer.sanitize_policy(xss_policy)
    assert "Malicious script or execution sequence" in str(exc_info.value.detail)


def test_sanitizer_rejects_null_byte_injection():
    """Verifies null byte poisoning attempts are immediately blocked."""
    with pytest.raises(PolicySanitizationError) as exc_info:
        PolicySanitizer.sanitize_string("malicious\x00user_id", "user_id")
    assert "Null byte detected" in str(exc_info.value.detail)


def test_sanitizer_rejects_oversized_rules():
    """Verifies policy rule count cannot exceed security ceiling."""
    oversized_policy = ZeroTrustPolicy(
        policy_id="huge-pol",
        policy_name="Huge Policy",
        rules=[
            PolicyRule(rule_id=f"R{i}", source="START", target="ACCESS", action="PERMIT")
            for i in range(5005)
        ]
    )
    with pytest.raises(PolicySanitizationError) as exc_info:
        PolicySanitizer.sanitize_policy(oversized_policy)
    assert "exceeds maximum security limit" in str(exc_info.value.detail)


def test_iam_generator_least_privilege_structure():
    """Verifies generated IAM policies follow NIST SP 800-207 least-privilege constraints."""
    generator = IAMLeastPrivilegePolicyGenerator(
        account_id="111222333444",
        region="eu-west-1",
        dynamodb_table="corp_policies",
        reports_table="corp_reports",
        s3_bucket="corp-ztpve-bucket",
        cloudwatch_namespace="Corp/ZeroTrust"
    )

    policy_doc = generator.generate_app_iam_policy()
    assert policy_doc["Version"] == "2012-10-17"
    statements = policy_doc["Statement"]
    assert len(statements) == 6

    # Verify DynamoDB statement is scoped to exact ARN
    dynamo_stmt = statements[0]
    assert "arn:aws:dynamodb:eu-west-1:111222333444:table/corp_policies" in dynamo_stmt["Resource"]
    assert "dynamodb:DeleteTable" not in dynamo_stmt["Action"]

    # Verify S3 statement is scoped to exact bucket ARN
    s3_obj_stmt = statements[3]
    assert s3_obj_stmt["Resource"] == "arn:aws:s3:::corp-ztpve-bucket/*"
    assert "s3:DeleteBucket" not in s3_obj_stmt["Action"]

    # Verify CloudWatch statement uses namespace condition
    cw_stmt = statements[4]
    assert cw_stmt["Condition"]["StringEquals"]["cloudwatch:namespace"] == "Corp/ZeroTrust"

    # Verify AssumeRole trust policy
    trust_doc = generator.generate_assume_role_trust_policy()
    assert "sts:AssumeRole" in trust_doc["Statement"][0]["Action"]


def test_sliding_window_rate_limiter_logic():
    """Tests rate limiter allowance, throttling, and remaining calculations."""
    limiter = SlidingWindowRateLimiter(requests_per_window=3, window_seconds=60)
    client_ip = "192.168.1.100"

    # Request 1, 2, 3 should be permitted
    allowed, remaining, _ = limiter.is_allowed(client_ip)
    assert allowed is True and remaining == 2

    allowed, remaining, _ = limiter.is_allowed(client_ip)
    assert allowed is True and remaining == 1

    allowed, remaining, _ = limiter.is_allowed(client_ip)
    assert allowed is True and remaining == 0

    # Request 4 should be throttled
    allowed, remaining, retry_after = limiter.is_allowed(client_ip)
    assert allowed is False
    assert remaining == 0
    assert retry_after > 0

    # Reset allows requests again
    limiter.reset()
    allowed, remaining, _ = limiter.is_allowed(client_ip)
    assert allowed is True and remaining == 2


def test_iam_policy_rest_endpoint():
    """Verifies GET /api/cloud/iam-policy returns complete valid IAM document."""
    response = client.get("/api/cloud/iam-policy?account_id=555666777888")
    assert response.status_code == 200
    data = response.json()
    assert "iam_policy" in data
    assert "assume_role_trust_policy" in data

    iam_doc = data["iam_policy"]
    resource_strings = json_to_string(iam_doc)
    assert "555666777888" in resource_strings
    assert "zero_trust_policies" in resource_strings


def json_to_string(obj) -> str:
    import json
    return json.dumps(obj)
