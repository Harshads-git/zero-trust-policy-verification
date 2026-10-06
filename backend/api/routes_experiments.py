"""
Experimental Evaluation API
Allows running synthetic policy verification benchmarks on demand
to evaluate scalability, throughput, latency percentiles, and detection rates.
Generates publication-ready LaTeX tables for academic viva and conference defense.
"""

from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import time
import math
import random
from backend.models.policy import ZeroTrustPolicy, PolicyRule
from backend.core.verifier import ZeroTrustVerificationEngine

router = APIRouter(prefix="/experiments", tags=["Empirical Evaluation"])
verifier = ZeroTrustVerificationEngine()


class AdvancedBenchmarkRequest(BaseModel):
    scales: List[int] = Field(default=[10, 25, 50, 100, 250, 500, 1000], description="Target scale sizes")
    iterations: int = Field(default=5, ge=1, le=50, description="Repeated benchmark runs per scale")


def calculate_percentiles(times: List[float]) -> Dict[str, float]:
    """Computes exact statistical percentiles (p50, p90, p95, p99), mean, and stdev."""
    if not times:
        return {"p50": 0.0, "p90": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0, "std_dev": 0.0, "min": 0.0, "max": 0.0}

    sorted_times = sorted(times)
    n = len(sorted_times)

    def percentile(p: float) -> float:
        k = (n - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_times[int(k)]
        d0 = sorted_times[int(f)] * (c - k)
        d1 = sorted_times[int(c)] * (k - f)
        return d0 + d1

    mean = sum(sorted_times) / n
    variance = sum((x - mean) ** 2 for x in sorted_times) / n if n > 1 else 0.0
    std_dev = math.sqrt(variance)

    return {
        "p50": round(percentile(50), 3),
        "p90": round(percentile(90), 3),
        "p95": round(percentile(95), 3),
        "p99": round(percentile(99), 3),
        "mean": round(mean, 3),
        "std_dev": round(std_dev, 3),
        "min": round(sorted_times[0], 3),
        "max": round(sorted_times[-1], 3)
    }


def format_latex_table(measurements: List[Dict[str, Any]]) -> str:
    """Formats benchmark results as publication-grade LaTeX tabular environment."""
    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{Empirical Scalability and Latency Percentiles of ZTPVE FSM Invariant Verification}",
        r"\label{tab:ztpve_scalability}",
        r"\begin{tabular}{rrrrrrrr}",
        r"\hline",
        r"\textbf{Scale $N$} & \textbf{$|Q|$} & \textbf{$|\delta|$} & \textbf{Mean (ms)} & \textbf{$p_{50}$ (ms)} & \textbf{$p_{95}$ (ms)} & \textbf{$p_{99}$ (ms)} & \textbf{Throughput (t/s)} \\",
        r"\hline"
    ]
    for m in measurements:
        p = m.get("percentiles", {})
        mean_val = p.get("mean", m.get("verification_time_ms", 0))
        p50_val = p.get("p50", m.get("verification_time_ms", 0))
        p95_val = p.get("p95", m.get("verification_time_ms", 0))
        p99_val = p.get("p99", m.get("verification_time_ms", 0))
        thr = m.get("throughput_rules_per_sec", 0)
        lines.append(
            f"{m['num_rules']:d} & {m['actual_states']:d} & {m['actual_transitions']:d} & "
            f"{mean_val:.2f} & {p50_val:.2f} & {p95_val:.2f} & {p99_val:.2f} & {thr:,.0f} \\\\"
        )
    lines.extend([
        r"\hline",
        r"\end{tabular}",
        r"\end{table}"
    ])
    return "\n".join(lines)


def format_markdown_table(measurements: List[Dict[str, Any]]) -> str:
    """Formats benchmark results into standard GitHub Flavored Markdown table."""
    lines = [
        "| Scale (N) | States |Q| | Transitions |δ| | Mean Latency | Median (p50) | 95th %ile (p95) | 99th %ile (p99) | Throughput (t/s) | Violations |",
        "|---|---|---|---|---|---|---|---|---|"
    ]
    for m in measurements:
        p = m.get("percentiles", {})
        lines.append(
            f"| N = {m['num_rules']} | {m['actual_states']} | {m['actual_transitions']} | "
            f"{p.get('mean', m.get('verification_time_ms', 0)):.2f} ms | "
            f"{p.get('p50', m.get('verification_time_ms', 0)):.2f} ms | "
            f"{p.get('p95', m.get('verification_time_ms', 0)):.2f} ms | "
            f"{p.get('p99', m.get('verification_time_ms', 0)):.2f} ms | "
            f"{m.get('throughput_rules_per_sec', 0):,.0f} | {m.get('violations_detected', 0)} |"
        )
    return "\n".join(lines)


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

    # Inject cross-edges to meet target rule count
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
        
        # Single timed run for basic benchmark
        start = time.perf_counter()
        report = verifier.verify(policy)
        duration_ms = (time.perf_counter() - start) * 1000.0

        throughput = round((report.total_transitions / (duration_ms / 1000.0)), 1) if duration_ms > 0 else 0

        results.append({
            "num_rules": count,
            "actual_states": report.total_states,
            "actual_transitions": report.total_transitions,
            "verification_time_ms": round(duration_ms, 3),
            "throughput_rules_per_sec": throughput,
            "violations_detected": report.violations_count,
            "is_valid": report.valid
        })

    return {
        "benchmark_summary": "Formal Verification Engine Scalability & Invariant Check Test",
        "timestamp": time.time(),
        "measurements": results
    }


@router.post("/benchmark/advanced", summary="Run multi-iteration benchmark with statistical percentiles and LaTeX export")
def run_advanced_benchmark(request: Optional[AdvancedBenchmarkRequest] = None) -> Dict[str, Any]:
    """
    Executes repeated benchmark trials per scale size.
    Calculates statistical latency percentiles (p50, p90, p95, p99, mean, stdev)
    and returns exportable LaTeX and Markdown tables.
    """
    req = request or AdvancedBenchmarkRequest()
    results = []

    for count in req.scales:
        policy = generate_synthetic_fsm(count, inject_flaws=(count % 2 == 0))
        
        # Warmup
        verifier.verify(policy)

        times = []
        last_report = None
        for _ in range(req.iterations):
            t0 = time.perf_counter()
            last_report = verifier.verify(policy)
            times.append((time.perf_counter() - t0) * 1000.0)

        percentiles = calculate_percentiles(times)
        mean_sec = percentiles["mean"] / 1000.0
        throughput = round((last_report.total_transitions / mean_sec), 1) if mean_sec > 0 else 0.0

        results.append({
            "num_rules": count,
            "actual_states": last_report.total_states,
            "actual_transitions": last_report.total_transitions,
            "verification_time_ms": percentiles["mean"],
            "percentiles": percentiles,
            "throughput_rules_per_sec": throughput,
            "violations_detected": last_report.violations_count,
            "is_valid": last_report.valid
        })

    return {
        "benchmark_summary": "Advanced Multi-Trial Latency Percentile Evaluation",
        "iterations_per_scale": req.iterations,
        "measurements": results,
        "latex_table": format_latex_table(results),
        "markdown_table": format_markdown_table(results)
    }
