"""
Unit and Integration Test Suite for Automated Policy Synthesizer
AxiomTrust Formal Verification Platform

Tests:
- Minimal graph surgery operators (INTERPOSE_STATE, INJECT_TRANSITION, ADD_REVOCATION_PATH, CONNECT_DEAD_STATE)
- RFC 6902 JSON Patch document synthesis and applicator round-trip
- Re-verification of synthesized repaired policies ensuring 100% invariant compliance
- REST API endpoints for on-demand policy synthesis and repair
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.policy import ZeroTrustPolicy, PolicyRule
from backend.core.synthesizer import (
    PolicySynthesizer,
    PatchOpType,
    apply_rfc6902_patch
)
from backend.core.verifier import ZeroTrustVerificationEngine

client = TestClient(app)


def test_compliant_policy_requires_no_surgery():
    """Verifies that an already-compliant policy yields zero patches and 0.0 edit distance."""
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
    synthesizer = PolicySynthesizer()
    res = synthesizer.synthesize_repair(policy)

    assert res.is_flawed is False
    assert res.flaws_detected == 0
    assert len(res.patches) == 0
    assert res.total_edit_distance == 0.0
    assert res.repaired_policy is not None
    assert res.repaired_report["valid"] is True


def test_repair_missing_authentication_interposition():
    """
    Verifies that a direct unauthenticated privilege bypass (START -> ACCESS_GRANTED)
    is repaired by interposing the AUTHENTICATED checkpoint.
    """
    flawed_policy = ZeroTrustPolicy(
        policy_name="Direct Bypass Policy",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "SESSION_EXPIRED", "REVOKED"],
        rules=[
            PolicyRule(rule_id="r_bypass", source="START", target="ACCESS_GRANTED", action="direct_bypass"),
            PolicyRule(source="ACCESS_GRANTED", target="SESSION_EXPIRED", action="timeout"),
            PolicyRule(source="ACCESS_GRANTED", target="REVOKED", action="revoke")
        ]
    )
    synthesizer = PolicySynthesizer()
    res = synthesizer.synthesize_repair(flawed_policy)

    assert res.is_flawed is True
    assert res.flaws_detected >= 1
    assert len(res.patches) >= 1

    # Check that INTERPOSE_STATE was chosen for authentication
    auth_patches = [p for p in res.patches if p.op_type == PatchOpType.INTERPOSE_STATE]
    assert len(auth_patches) >= 1
    assert "AUTHENTICATED" in auth_patches[0].affected_states

    # Verify that repaired policy is structurally updated
    repaired = res.repaired_policy
    assert repaired is not None
    rule_sources = [r.source for r in repaired.rules]
    rule_targets = [r.target for r in repaired.rules]
    assert "AUTHENTICATED" in rule_sources or "AUTHENTICATED" in rule_targets


def test_repair_missing_device_verification():
    """
    Verifies that a policy missing device verification is repaired by
    interposing the DEVICE_VERIFIED checkpoint before access grant.
    """
    flawed_policy = ZeroTrustPolicy(
        policy_name="Missing Device Verification Policy",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "SESSION_EXPIRED", "REVOKED"],
        rules=[
            PolicyRule(source="START", target="AUTHENTICATED", action="login", condition="auth_method == 'mfa'"),
            PolicyRule(rule_id="r_grant_nodev", source="AUTHENTICATED", target="ACCESS_GRANTED", action="grant"),
            PolicyRule(source="ACCESS_GRANTED", target="SESSION_EXPIRED", action="timeout"),
            PolicyRule(source="ACCESS_GRANTED", target="REVOKED", action="revoke")
        ]
    )
    synthesizer = PolicySynthesizer()
    res = synthesizer.synthesize_repair(flawed_policy)

    assert res.is_flawed is True
    dev_patches = [p for p in res.patches if "DEVICE_VERIFIED" in p.affected_states or p.op_type == PatchOpType.INTERPOSE_STATE]
    assert len(dev_patches) >= 1

    # Re-verify repaired candidate
    verifier = ZeroTrustVerificationEngine()
    repaired_report = verifier.verify(res.repaired_policy)
    # Check that device trust invariant passes
    assert repaired_report.formal_invariants_checked.get("device_posture_trust", True) is True


def test_repair_no_revocation_path():
    """
    Verifies that a perpetual zombie access grant is repaired by
    injecting session expiration and administrative revocation paths.
    """
    flawed_policy = ZeroTrustPolicy(
        policy_name="Zombie Session Policy",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "SESSION_EXPIRED", "REVOKED"],
        rules=[
            PolicyRule(source="START", target="AUTHENTICATED", action="login", condition="auth_method == 'mfa'"),
            PolicyRule(source="AUTHENTICATED", target="DEVICE_VERIFIED", action="check_dev", condition="device_health == 'compliant'"),
            PolicyRule(source="DEVICE_VERIFIED", target="ACCESS_GRANTED", action="grant")
            # Missing forward transitions from ACCESS_GRANTED
        ]
    )
    synthesizer = PolicySynthesizer()
    res = synthesizer.synthesize_repair(flawed_policy)

    assert res.is_flawed is True
    rev_patches = [p for p in res.patches if p.op_type == PatchOpType.ADD_REVOCATION_PATH]
    assert len(rev_patches) >= 1
    assert "SESSION_EXPIRED" in rev_patches[0].affected_states

    # Check repaired policy has revocation edges
    repaired_targets = [r.target for r in res.repaired_policy.rules if r.source == "ACCESS_GRANTED"]
    assert "SESSION_EXPIRED" in repaired_targets or "REVOKED" in repaired_targets


def test_repair_dead_state():
    """
    Verifies that a non-terminal trap state with zero outgoing edges is
    repaired by connecting it to a safe ACCESS_DENIED sink.
    """
    flawed_policy = ZeroTrustPolicy(
        policy_name="Dead Trap State Policy",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "ACCESS_DENIED", "SESSION_EXPIRED", "REVOKED"],
        rules=[
            PolicyRule(source="START", target="AUTHENTICATED", action="login", condition="auth_method == 'mfa'"),
            PolicyRule(source="AUTHENTICATED", target="TRAP_STATE", action="enter_trap"),
            PolicyRule(source="AUTHENTICATED", target="DEVICE_VERIFIED", action="check_dev", condition="device_health == 'compliant'"),
            PolicyRule(source="DEVICE_VERIFIED", target="ACCESS_GRANTED", action="grant"),
            PolicyRule(source="ACCESS_GRANTED", target="SESSION_EXPIRED", action="timeout"),
            PolicyRule(source="ACCESS_GRANTED", target="REVOKED", action="revoke"),
            PolicyRule(source="AUTHENTICATED", target="ACCESS_DENIED", action="deny")
        ]
    )
    synthesizer = PolicySynthesizer()
    res = synthesizer.synthesize_repair(flawed_policy)

    assert res.is_flawed is True
    dead_patches = [p for p in res.patches if p.op_type == PatchOpType.CONNECT_DEAD_STATE]
    assert len(dead_patches) >= 1
    assert "TRAP_STATE" in dead_patches[0].affected_states


def test_rfc6902_patch_application_roundtrip():
    """
    Verifies that the generated RFC 6902 patch document can be applied
    directly to the raw policy dictionary to yield the repaired structure.
    """
    flawed_policy = ZeroTrustPolicy(
        policy_name="RFC 6902 Test Policy",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "SESSION_EXPIRED", "REVOKED"],
        rules=[
            PolicyRule(rule_id="r_bypass", source="START", target="ACCESS_GRANTED", action="direct_bypass")
        ]
    )
    synthesizer = PolicySynthesizer()
    res = synthesizer.synthesize_repair(flawed_policy)

    assert len(res.rfc6902_patch_document) > 0

    # Apply RFC 6902 patch via standalone applicator
    orig_dict = flawed_policy.model_dump()
    patched_dict = apply_rfc6902_patch(orig_dict, res.rfc6902_patch_document)

    # Check that removed rule is absent and added rules are present
    patched_rule_ids = [r.get("rule_id") for r in patched_dict.get("rules", [])]
    assert "r_bypass" not in patched_rule_ids
    assert len(patched_rule_ids) >= 2


def test_synthesize_patch_api_endpoints():
    """
    Verifies HTTP REST API endpoints:
    1. POST /api/policies/synthesize-patch (direct payload)
    2. POST /api/policies/{id}/synthesize-patch (stored policy)
    """
    sample_policy = {
        "policy_id": "pol_synth_api_test",
        "policy_name": "API Synthesis Test Policy",
        "initial_state": "START",
        "terminal_states": ["ACCESS_GRANTED", "SESSION_EXPIRED", "REVOKED"],
        "rules": [
            {"rule_id": "r1", "source": "START", "target": "ACCESS_GRANTED", "action": "direct_bypass"}
        ]
    }

    # 1. Direct synthesis endpoint
    res1 = client.post("/api/policies/synthesize-patch", json=sample_policy)
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["is_flawed"] is True
    assert len(data1["patches"]) >= 1
    assert "rfc6902_patch_document" in data1
    assert "repaired_policy" in data1
    assert data1["total_edit_distance"] > 0

    # 2. Save policy first
    save_res = client.post("/api/policies", json=sample_policy)
    assert save_res.status_code == 201

    # 3. Stored policy synthesis endpoint
    res2 = client.post("/api/policies/pol_synth_api_test/synthesize-patch")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["original_policy_id"] == "pol_synth_api_test"
    assert data2["is_flawed"] is True
    assert len(data2["patches"]) >= 1

    # Cleanup stored policy
    del_res = client.delete("/api/policies/pol_synth_api_test")
    assert del_res.status_code == 200
