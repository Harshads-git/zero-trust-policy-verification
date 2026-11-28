"""
AxiomTrust DevSecOps CLI & OASIS SARIF v2.1.0 Exporter Test Suite
Tests command-line interface execution, exit codes, SARIF schema compliance,
counterexample threadFlows, and REST API SARIF integration.
"""

import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.policy import ZeroTrustPolicy, PolicyRule, PolicyMetadata
from backend.core.verifier import ZeroTrustVerificationEngine
from backend.exporters.sarif import SARIFExporter, SARIF_RULE_METADATA
from backend.cli.axiom_cli import main, load_policy_from_file, collect_policy_files


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sample_valid_policy() -> ZeroTrustPolicy:
    """Fixture providing a known compliant Zero Trust policy."""
    return ZeroTrustPolicy(
        policy_id="pol_test_sarif_valid",
        policy_name="Test Compliant SARIF Policy",
        initial_state="START",
        states=[
            "START",
            "UNAUTHENTICATED",
            "AUTHENTICATED",
            "DEVICE_VERIFIED",
            "AUTHORIZED",
            "ACCESS_GRANTED",
            "ACCESS_DENIED",
            "REVOKED"
        ],
        rules=[
            PolicyRule(rule_id="r1", source="START", target="UNAUTHENTICATED", action="connect"),
            PolicyRule(rule_id="r2", source="UNAUTHENTICATED", target="AUTHENTICATED", action="authenticate", condition="auth_method == 'mfa'"),
            PolicyRule(rule_id="r3", source="AUTHENTICATED", target="DEVICE_VERIFIED", action="verify_device", condition="device_health == 'compliant'"),
            PolicyRule(rule_id="r4", source="DEVICE_VERIFIED", target="AUTHORIZED", action="authorize", condition="role == 'employee'"),
            PolicyRule(rule_id="r5", source="AUTHORIZED", target="ACCESS_GRANTED", action="grant"),
            PolicyRule(rule_id="r6", source="ACCESS_GRANTED", target="REVOKED", action="revoke"),
            PolicyRule(rule_id="r7", source="UNAUTHENTICATED", target="ACCESS_DENIED", action="fail_auth"),
        ],
        terminal_states=["ACCESS_GRANTED", "ACCESS_DENIED", "REVOKED"],
        metadata=PolicyMetadata(version="1.0", author="AxiomTrust Test")
    )


@pytest.fixture
def sample_flawed_policy() -> ZeroTrustPolicy:
    """Fixture providing a policy with authentication bypass and dead state."""
    return ZeroTrustPolicy(
        policy_id="pol_test_sarif_flawed",
        policy_name="Test Flawed SARIF Policy",
        initial_state="START",
        states=[
            "START",
            "UNAUTHENTICATED",
            "DEVICE_VERIFIED",
            "AUTHORIZED",
            "ACCESS_GRANTED",
            "TRAP_STATE"
        ],
        rules=[
            # Bypass authentication: jump directly to DEVICE_VERIFIED
            PolicyRule(rule_id="r1", source="START", target="UNAUTHENTICATED", action="connect"),
            PolicyRule(rule_id="r2", source="UNAUTHENTICATED", target="DEVICE_VERIFIED", action="skip_auth"),
            PolicyRule(rule_id="r3", source="DEVICE_VERIFIED", target="AUTHORIZED", action="authorize"),
            PolicyRule(rule_id="r4", source="AUTHORIZED", target="ACCESS_GRANTED", action="grant"),
            # No revocation from ACCESS_GRANTED
            # Transition to a trap state
            PolicyRule(rule_id="r5", source="START", target="TRAP_STATE", action="trap_action"),
        ],
        terminal_states=["ACCESS_GRANTED"],
        metadata=PolicyMetadata(version="1.0", author="AxiomTrust Test")
    )


# ============================================================================
# 1. SARIF Exporter Schema & Invariant Mapping Tests
# ============================================================================

def test_sarif_exporter_schema_structure(sample_valid_policy):
    """Verifies that generated SARIF document strictly conforms to OASIS SARIF 2.1.0 top-level schema."""
    verifier = ZeroTrustVerificationEngine()
    report = verifier.verify(sample_valid_policy)

    sarif_dict = SARIFExporter.to_sarif_dict([report])

    assert sarif_dict["$schema"] == SARIFExporter.SARIF_SCHEMA
    assert sarif_dict["version"] == "2.1.0"
    assert "runs" in sarif_dict
    assert len(sarif_dict["runs"]) == 1

    run = sarif_dict["runs"][0]
    assert run["tool"]["driver"]["name"] == "AxiomTrust"
    assert run["tool"]["driver"]["semanticVersion"] == "1.0.0"
    assert len(run["tool"]["driver"]["rules"]) > 0
    assert len(run["results"]) == 0  # Valid policy has zero violations


def test_sarif_flaw_violation_mappings(sample_flawed_policy):
    """Verifies that policy violations correctly map to SARIF results, levels, and rules."""
    verifier = ZeroTrustVerificationEngine()
    report = verifier.verify(sample_flawed_policy)

    assert not report.valid
    assert len(report.violations) > 0

    sarif_dict = SARIFExporter.to_sarif_dict(
        [report],
        policy_file_paths={sample_flawed_policy.policy_id: "policies/test/flawed.json"}
    )

    results = sarif_dict["runs"][0]["results"]
    assert len(results) == len(report.violations)

    rule_ids = {r["ruleId"] for r in results}
    # Check that known rule IDs are present
    assert any("AXIOM-ZT" in rid or "AXIOM-TOC" in rid for rid in rule_ids)

    # Check level mapping (CRITICAL/HIGH -> error, MEDIUM/LOW -> warning/note)
    for res in results:
        assert res["level"] in ("error", "warning", "note")
        assert "message" in res
        assert "text" in res["message"]
        assert "markdown" in res["message"]
        assert len(res["locations"]) > 0
        loc = res["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "policies/test/flawed.json"


def test_sarif_codeflows_counterexample_threadflows(sample_flawed_policy):
    """Verifies that BFS witness execution trajectories are serialized as SARIF codeFlows / threadFlows."""
    verifier = ZeroTrustVerificationEngine()
    report = verifier.verify(sample_flawed_policy)

    sarif_dict = SARIFExporter.to_sarif_dict([report])
    results = sarif_dict["runs"][0]["results"]

    # Locate the result with a counterexample witness path
    results_with_codeflows = [r for r in results if "codeFlows" in r]
    assert len(results_with_codeflows) > 0

    codeflow_entry = results_with_codeflows[0]
    thread_flows = codeflow_entry["codeFlows"][0]["threadFlows"]
    assert len(thread_flows) == 1

    steps = thread_flows[0]["locations"]
    assert len(steps) >= 3  # START -> UNAUTHENTICATED -> DEVICE_VERIFIED ...
    assert steps[0]["executionOrder"] == 1
    assert "START" in steps[0]["location"]["message"]["text"]


def test_sarif_file_export(sample_flawed_policy, tmp_path):
    """Verifies that SARIFExporter writes formatted JSON to disk correctly."""
    verifier = ZeroTrustVerificationEngine()
    report = verifier.verify(sample_flawed_policy)

    out_file = tmp_path / "reports" / "security_audit.sarif.json"
    written_path = SARIFExporter.export_sarif_file([report], str(out_file))

    assert Path(written_path).exists()
    with open(written_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) > 0


# ============================================================================
# 2. Shift-Left DevSecOps CLI Command Tests
# ============================================================================

def test_cli_load_policy_from_file(tmp_path, sample_valid_policy):
    """Verifies CLI helper for loading and validating policy files."""
    p_file = tmp_path / "valid_policy.json"
    with open(p_file, "w", encoding="utf-8") as f:
        json.dump(sample_valid_policy.model_dump(), f)

    loaded = load_policy_from_file(p_file)
    assert loaded.policy_id == sample_valid_policy.policy_id

    # Test file collection
    collected = collect_policy_files([str(tmp_path)])
    assert p_file in collected


def test_cli_verify_compliant_policy(tmp_path, sample_valid_policy):
    """Verifies CLI verify command returns exit code 0 on compliant policies."""
    p_file = tmp_path / "valid_policy.json"
    with open(p_file, "w", encoding="utf-8") as f:
        json.dump(sample_valid_policy.model_dump(), f)

    exit_code = main(["verify", str(p_file), "--strict", "-q"])
    assert exit_code == 0


def test_cli_verify_flawed_policy_exit_code(tmp_path, sample_flawed_policy):
    """Verifies CLI verify command returns exit code 1 when policy violations exist."""
    p_file = tmp_path / "flawed_policy.json"
    with open(p_file, "w", encoding="utf-8") as f:
        json.dump(sample_flawed_policy.model_dump(), f)

    exit_code = main(["verify", str(p_file), "--strict", "-q"])
    assert exit_code == 1


def test_cli_verify_with_sarif_export(tmp_path, sample_flawed_policy):
    """Verifies CLI verify command generates SARIF report via --sarif option."""
    p_file = tmp_path / "flawed_policy.json"
    sarif_out = tmp_path / "audit.sarif.json"
    with open(p_file, "w", encoding="utf-8") as f:
        json.dump(sample_flawed_policy.model_dump(), f)

    exit_code = main(["verify", str(p_file), "--sarif", str(sarif_out), "-q"])
    assert exit_code == 1  # Failed due to violations
    assert sarif_out.exists()

    with open(sarif_out, "r", encoding="utf-8") as f:
        sarif_doc = json.load(f)
    assert sarif_doc["version"] == "2.1.0"


def test_cli_sarif_command(tmp_path, sample_valid_policy):
    """Verifies dedicated 'sarif' CLI subcommand."""
    p_file = tmp_path / "valid.json"
    sarif_out = tmp_path / "output.sarif.json"
    with open(p_file, "w", encoding="utf-8") as f:
        json.dump(sample_valid_policy.model_dump(), f)

    exit_code = main(["sarif", str(p_file), "-o", str(sarif_out)])
    assert exit_code == 0
    assert sarif_out.exists()


def test_cli_transpile_iam_command(tmp_path):
    """Verifies CLI transpile-iam command."""
    iam_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3WithMFA",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "arn:aws:s3:::mybucket/*",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
            }
        ]
    }
    iam_file = tmp_path / "iam_mfa.json"
    out_fsm = tmp_path / "fsm_out.json"
    with open(iam_file, "w", encoding="utf-8") as f:
        json.dump(iam_json, f)

    # Transpilation without verification check returns exit code 0
    exit_code = main(["transpile-iam", "-f", str(iam_file), "-o", str(out_fsm)])
    assert exit_code == 0
    assert out_fsm.exists()

    # Transpilation with --verify detects inherent cloud policy gaps (e.g., missing device trust) and returns 1
    verify_exit_code = main(["transpile-iam", "-f", str(iam_file), "--verify"])
    assert verify_exit_code == 1


def test_cli_export_rego_command(tmp_path, sample_valid_policy):
    """Verifies CLI export-rego command."""
    fsm_file = tmp_path / "fsm_policy.json"
    rego_file = tmp_path / "exported.rego"
    with open(fsm_file, "w", encoding="utf-8") as f:
        json.dump(sample_valid_policy.model_dump(), f)

    exit_code = main(["export-rego", "-f", str(fsm_file), "-o", str(rego_file), "--framework", "kubernetes_gatekeeper"])
    assert exit_code == 0
    assert rego_file.exists()
    rego_content = rego_file.read_text(encoding="utf-8")
    assert "package axiomtrust.authz" in rego_content
    assert "Gatekeeper" in rego_content


def test_cli_threat_command(tmp_path, sample_valid_policy):
    """Verifies CLI threat simulation command."""
    fsm_file = tmp_path / "threat_policy.json"
    with open(fsm_file, "w", encoding="utf-8") as f:
        json.dump(sample_valid_policy.model_dump(), f)

    exit_code = main(["threat", "-f", str(fsm_file), "--pivot", "START"])
    assert exit_code == 0


# ============================================================================
# 3. REST API SARIF Endpoints Tests
# ============================================================================

def test_api_verify_policy_sarif(client, sample_flawed_policy):
    """Verifies POST /api/policies/verify/sarif returns valid OASIS SARIF document."""
    resp = client.post("/api/policies/verify/sarif", json=sample_flawed_policy.model_dump())
    assert resp.status_code == 200
    data = resp.json()

    assert data["$schema"] == SARIFExporter.SARIF_SCHEMA
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    assert len(data["runs"][0]["results"]) > 0


def test_api_get_policy_sarif(client, sample_valid_policy):
    """Verifies GET /api/policies/{policy_id}/sarif returns SARIF for stored policy."""
    # First save policy
    create_resp = client.post("/api/policies/", json=sample_valid_policy.model_dump())
    assert create_resp.status_code == 201

    sarif_resp = client.get(f"/api/policies/{sample_valid_policy.policy_id}/sarif")
    assert sarif_resp.status_code == 200
    sarif_data = sarif_resp.json()

    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "AxiomTrust"
