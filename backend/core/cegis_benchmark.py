"""
CEGIS Synthesis Scalability & Optimality Benchmark Engine
AxiomTrust Formal Verification Platform

Provides empirical benchmarking tools for Counterexample-Guided Inductive Synthesis (CEGIS):
- Generates parameterized synthetic flawed policies with controlled vulnerability distributions
- Measures synthesis latency percentiles (p50, p90, p95, p99), convergence rate, and throughput
- Evaluates Graph Edit Distance (GED) optimality ratio relative to theoretical lower bounds
- Generates publication-ready LaTeX and Markdown benchmark reports
"""

import time
import math
import random
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from backend.models.policy import ZeroTrustPolicy, PolicyRule
from backend.core.cegis_loop import CEGISEngine, CEGISStatus, CEGISResult


class SynthesisBenchmarkRequest(BaseModel):
    batch_sizes: List[int] = Field(default=[5, 10, 25, 50], description="Policy batch sizes to evaluate")
    max_iterations: int = Field(default=5, ge=1, le=10, description="Max CEGIS iterations per repair")


def generate_synthetic_flawed_policy(
    scale: int = 10,
    flaw_types: Optional[List[str]] = None,
    seed: Optional[int] = None
) -> ZeroTrustPolicy:
    """
    Generates a synthetic access control policy with controlled zero-trust flaw injections.
    Flaw types: 'auth_bypass', 'no_revocation', 'dead_trap', 'missing_device', 'rule_conflict'.
    """
    if seed is not None:
        random.seed(seed)

    if flaw_types is None:
        flaw_types = ["auth_bypass", "no_revocation", "dead_trap"]

    rules: List[PolicyRule] = []
    intermediate_states = [f"WORKFLOW_STATE_{i}" for i in range(1, max(3, scale // 2))]

    # Baseline valid scaffolding
    rules.append(PolicyRule(source="START", target="AUTHENTICATED", action="login", condition="auth_method == 'mfa'"))
    rules.append(PolicyRule(source="AUTHENTICATED", target="DEVICE_VERIFIED", action="verify_dev", condition="device_health == 'compliant'"))
    rules.append(PolicyRule(source="DEVICE_VERIFIED", target="ACCESS_GRANTED", action="grant", condition="role == 'user'"))
    rules.append(PolicyRule(source="ACCESS_GRANTED", target="SESSION_EXPIRED", action="timeout"))
    rules.append(PolicyRule(source="ACCESS_GRANTED", target="REVOKED", action="revoke"))
    rules.append(PolicyRule(source="AUTHENTICATED", target="ACCESS_DENIED", action="deny"))

    # Chain intermediate states
    curr = "DEVICE_VERIFIED"
    for st in intermediate_states:
        rules.append(PolicyRule(source=curr, target=st, action=f"step_{st.lower()}", condition="active == true"))
        rules.append(PolicyRule(source=st, target="ACCESS_GRANTED", action="sub_grant", condition="role == 'user'"))
        curr = st

    # Inject specific controlled flaws
    if "auth_bypass" in flaw_types:
        rules.append(PolicyRule(
            rule_id=f"flaw_bypass_{random.randint(100, 999)}",
            source="START",
            target="ACCESS_GRANTED",
            action="direct_bypass",
            description="Injected flaw: direct authentication bypass"
        ))

    if "no_revocation" in flaw_types:
        # Strip all revocation transitions from ACCESS_GRANTED
        rules = [r for r in rules if not (r.source == "ACCESS_GRANTED" and r.target in ("SESSION_EXPIRED", "REVOKED"))]

    if "dead_trap" in flaw_types:
        trap_state = f"TRAP_{random.randint(10, 99)}"
        rules.append(PolicyRule(
            rule_id=f"flaw_trap_{random.randint(100, 999)}",
            source="START",
            target=trap_state,
            action="enter_trap",
            description="Injected flaw: dead trap state with zero outgoing transitions"
        ))

    if "missing_device" in flaw_types:
        # Direct from AUTHENTICATED to ACCESS_GRANTED skipping device check
        rules.append(PolicyRule(
            rule_id=f"flaw_nodev_{random.randint(100, 999)}",
            source="AUTHENTICATED",
            target="ACCESS_GRANTED",
            action="skip_device_grant",
            condition="role == 'guest'"
        ))

    if "rule_conflict" in flaw_types:
        rules.append(PolicyRule(
            rule_id=f"flaw_conf1_{random.randint(100, 999)}",
            source="AUTHENTICATED",
            target="ACCESS_DENIED",
            action="ambiguous_action",
            condition=""
        ))
        rules.append(PolicyRule(
            rule_id=f"flaw_conf2_{random.randint(100, 999)}",
            source="AUTHENTICATED",
            target="STEP_UP_REQUIRED",
            action="ambiguous_action",
            condition=""
        ))

    return ZeroTrustPolicy(
        policy_name=f"Synthetic Flawed Policy (Scale={scale}, Flaws={len(flaw_types)})",
        initial_state="START",
        terminal_states=["ACCESS_GRANTED", "ACCESS_DENIED", "SESSION_EXPIRED", "REVOKED"],
        rules=rules
    )


def calculate_synthesis_percentiles(times: List[float]) -> Dict[str, float]:
    """Computes exact statistical percentiles (p50, p90, p95, p99), mean, and std_dev."""
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


def format_synthesis_latex_table(measurements: List[Dict[str, Any]]) -> str:
    """Formats CEGIS synthesis benchmark results as publication-grade LaTeX tabular environment."""
    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{Empirical Scalability, Latency Percentiles, and Optimality Ratio of CEGIS Automated Policy Synthesis}",
        r"\label{tab:cegis_synthesis_benchmarks}",
        r"\begin{tabular}{rrrrrrrrr}",
        r"\hline",
        r"\textbf{Batch $N$} & \textbf{Rules $|\delta|$} & \textbf{Mean (ms)} & \textbf{$p_{50}$ (ms)} & \textbf{$p_{95}$ (ms)} & \textbf{$p_{99}$ (ms)} & \textbf{Convergence} & \textbf{Avg Rounds} & \textbf{Optimality} \\",
        r"\hline"
    ]
    for m in measurements:
        p = m.get("percentiles", {})
        mean_val = p.get("mean", 0.0)
        p50_val = p.get("p50", 0.0)
        p95_val = p.get("p95", 0.0)
        p99_val = p.get("p99", 0.0)
        conv_rate = m.get("convergence_rate", 100.0)
        avg_rounds = m.get("avg_convergence_rounds", 1.0)
        opt_ratio = m.get("mean_optimality_ratio", 1.0)
        lines.append(
            f"{m['batch_size']:d} & {m['mean_rules']:d} & "
            f"{mean_val:.2f} & {p50_val:.2f} & {p95_val:.2f} & {p99_val:.2f} & "
            f"{conv_rate:.1f}\\% & {avg_rounds:.2f} & {opt_ratio:.2f} \\\\"
        )
    lines.extend([
        r"\hline",
        r"\end{tabular}",
        r"\end{table}"
    ])
    return "\n".join(lines)


def format_synthesis_markdown_table(measurements: List[Dict[str, Any]]) -> str:
    """Formats CEGIS synthesis benchmark results into standard GitHub Flavored Markdown table."""
    lines = [
        "| Batch Size | Mean Rules | Mean Latency | Median (p50) | 95th %ile (p95) | 99th %ile (p99) | Convergence Rate | Avg CEGIS Rounds | Optimality Ratio | Throughput |",
        "|---|---|---|---|---|---|---|---|---|---|"
    ]
    for m in measurements:
        p = m.get("percentiles", {})
        lines.append(
            f"| N = {m['batch_size']} | {m['mean_rules']} | "
            f"{p.get('mean', 0.0):.2f} ms | {p.get('p50', 0.0):.2f} ms | "
            f"{p.get('p95', 0.0):.2f} ms | {p.get('p99', 0.0):.2f} ms | "
            f"{m.get('convergence_rate', 100.0):.1f}% | {m.get('avg_convergence_rounds', 1.0):.2f} | "
            f"{m.get('mean_optimality_ratio', 1.0):.2f}x | {m.get('synthesis_throughput_policies_per_sec', 0.0):.1f} pol/s |"
        )
    return "\n".join(lines)


def run_synthesis_benchmark_suite(
    batch_sizes: Optional[List[int]] = None,
    max_iterations: int = 5
) -> Dict[str, Any]:
    """
    Executes empirical CEGIS synthesis benchmarks across scaling batches of flawed policies.
    """
    if batch_sizes is None:
        batch_sizes = [5, 10, 25, 50]

    engine = CEGISEngine(max_iterations=max_iterations)
    measurements = []

    for batch_size in batch_sizes:
        policies = [
            generate_synthetic_flawed_policy(
                scale=max(10, batch_size),
                flaw_types=random.sample(
                    ["auth_bypass", "no_revocation", "dead_trap", "missing_device", "rule_conflict"],
                    k=random.randint(2, 4)
                ),
                seed=42 + idx
            )
            for idx in range(batch_size)
        ]

        latencies = []
        converged_count = 0
        total_rounds = 0
        optimality_ratios = []
        total_rules = sum(len(p.rules) for p in policies)

        t_batch_start = time.perf_counter()
        for p in policies:
            t0 = time.perf_counter()
            res = engine.run_cegis_loop(p, max_iterations=max_iterations)
            duration_ms = (time.perf_counter() - t0) * 1000.0
            latencies.append(duration_ms)

            if res.converged:
                converged_count += 1
            total_rounds += max(1, res.iterations_count)

            # Optimality ratio: synthesized GED cost vs minimal theoretical lower bound (flaws_detected)
            min_bound = max(1.0, float(res.initial_violations_count))
            ratio = max(1.0, res.cumulative_edit_distance / min_bound)
            optimality_ratios.append(ratio)

        batch_duration_sec = time.perf_counter() - t_batch_start
        throughput = round(batch_size / batch_duration_sec, 1) if batch_duration_sec > 0 else 0.0

        percentiles = calculate_synthesis_percentiles(latencies)
        measurements.append({
            "batch_size": batch_size,
            "mean_rules": round(total_rules / batch_size),
            "percentiles": percentiles,
            "convergence_rate": round((converged_count / batch_size) * 100.0, 1),
            "avg_convergence_rounds": round(total_rounds / batch_size, 2),
            "mean_optimality_ratio": round(sum(optimality_ratios) / len(optimality_ratios), 2),
            "synthesis_throughput_policies_per_sec": throughput
        })

    return {
        "benchmark_summary": "CEGIS Automated Synthesis Scalability & Optimality Evaluation",
        "timestamp": time.time(),
        "batch_sizes": batch_sizes,
        "max_iterations": max_iterations,
        "measurements": measurements,
        "latex_table": format_synthesis_latex_table(measurements),
        "markdown_table": format_synthesis_markdown_table(measurements)
    }
