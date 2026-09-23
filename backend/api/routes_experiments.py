"""
Experimental Evaluation API
Allows running synthetic policy verification benchmarks on demand
to evaluate scalability, throughput, latency, and detection rates.
"""

from fastapi import APIRouter
from typing import Dict, Any, List
import time
import random
from backend.models.policy import ZeroTrustPolicy, PolicyRule
from backend.core.verifier import ZeroTrustVerificationEngine

router = APIRouter(prefix="/experiments", tags=["Empirical Evaluation"])
verifier = ZeroTrustVerificationEngine()


def generate_synthetic_fsm(num_rules: int, inject_flaws: bool = False) -> ZeroTrustPolicy:
    """Generates a synthetic access control workflow of scale N."""
    intermediate_states = [f"STAGE_{i}" for i in range(1, max(3, num_rules // 3))]
    rules: List[PolicyRule] = []

    # Valid skeleton baseline
    rules.append(PolicyRule(source="START", target="AUTHENTICATED", action="submit_credentials", condition="valid_password"))
    rules.append(PolicyRule(source="AUTHENTICATED", target="IDENTITY_VERIFIED", action="verify_mfa", condition="totp_valid"))
    rules.append(PolicyRule(source="IDENTITY_VERIFIED", target="DEVICE_VERIFIED", action="check_device", condition="device_healthy"))
    rules.append(PolicyRule(source="DEVICE_VERIFIED", target="AUTHORIZED", action="evaluate_rbac", condition="role_matches"))
    rules.append(PolicyRule(source="AUTHORIZED", target="ACCESS_GRANTED", action="issue_token", condition="token_signed"))
    rules.append(PolicyRule(source="ACCESS_GRANTED", target="SESSION_EXPIRED", action="timeout", condition="ttl_exceeded"))
    rules.append(PolicyRule(source="ACCESS_GRANTED", target="REVOKED", action="revoke", condition="anomaly_detected"))

    curr = "AUTHORIZED"
    for st in intermediate_states:
        rules.append(PolicyRule(source=curr, target=st, action="step_eval", condition="context_ok"))
        rules.append(PolicyRule(source=st, target="ACCESS_GRANTED", action="allow", condition="granted"))
        curr = st

    # Inject random cross-edges to meet target rule count
    all_states = ["START", "AUTHENTICATED", "IDENTITY_VERIFIED", "DEVICE_VERIFIED", "AUTHORIZED", "ACCESS_GRANTED", "REVOKED"] + intermediate_states
    while len(rules) < num_rules:
        src = random.choice(all_states)
        tgt = random.choice(all_states)
        if src != "REVOKED" and src != "SESSION_EXPIRED":
            rules.append(PolicyRule(source=src, target=tgt, action=f"op_{len(rules)}", condition="sub_check"))

    if inject_flaws:
        # Inject critical bypass flaw
        rules.append(PolicyRule(source="START", target="ACCESS_GRANTED", action="bypass", condition=""))

    return ZeroTrustPolicy(
        policy_name=f"Synthetic Policy (N={num_rules})",
        description=f"Generated policy with {num_rules} transitions for performance benchmarking.",
        rules=rules
    )


@router.post("/benchmark", summary="Run verification performance benchmark")
def run_benchmark(scale_steps: List[int] = [10, 50, 100, 250, 500]) -> Dict[str, Any]:
    """
    Evaluates verification engine performance across multiple policy scales.
    Measures latency (ms), rule throughput (rules/sec), and detection reliability.
    """
    results = []
    for count in scale_steps:
        policy = generate_synthetic_fsm(count, inject_flaws=(count % 2 == 0))
        
        start = time.perf_counter()
        report = verifier.verify(policy)
        duration_ms = (time.perf_counter() - start) * 1000.0

        results.append({
            "num_rules": count,
            "actual_states": report.total_states,
            "actual_transitions": report.total_transitions,
            "verification_time_ms": round(duration_ms, 3),
            "throughput_rules_per_sec": round((report.total_transitions / (duration_ms / 1000.0)), 1) if duration_ms > 0 else 0,
            "violations_detected": report.violations_count,
            "is_valid": report.valid
        })

    return {
        "benchmark_summary": "Formal Verification Engine Scalability & Invariant Check Test",
        "timestamp": time.time(),
        "measurements": results
    }
