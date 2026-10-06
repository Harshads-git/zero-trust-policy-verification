"""
Empirical Benchmark Scalability & Statistical Percentile Tests
Validates synthetic policy generation at scale (N=10 to 1000 rules),
percentile calculation algorithms (p50, p90, p95, p99), and LaTeX/Markdown table synthesis.
"""

import pytest
import math
from fastapi.testclient import TestClient

from backend.main import app
from backend.api.routes_experiments import (
    generate_synthetic_fsm,
    calculate_percentiles,
    format_latex_table,
    format_markdown_table
)
from backend.core.verifier import ZeroTrustVerificationEngine

client = TestClient(app)
verifier = ZeroTrustVerificationEngine()


def test_synthetic_fsm_scaling_up_to_1000():
    """Verifies synthetic policy generator scales cleanly from N=10 to N=1000 rules."""
    for n in [10, 50, 100, 500, 1000]:
        policy = generate_synthetic_fsm(num_rules=n, inject_flaws=False)
        assert len(policy.rules) >= n
        assert len(policy.get_all_states()) >= 5
        
        # Verify verifier can evaluate it without exceptions
        report = verifier.verify(policy)
        assert report.total_states > 0
        assert report.total_transitions >= n
        assert report.verification_time_ms >= 0.0


def test_percentile_calculation_distribution():
    """Tests exact statistical percentile computations against known sample array."""
    # 100 uniform sample measurements from 1.0ms to 100.0ms
    times = [float(i) for i in range(1, 101)]
    stats = calculate_percentiles(times)

    assert stats["min"] == 1.0
    assert stats["max"] == 100.0
    assert stats["mean"] == 50.5
    # For 1..100, median p50 is 50.5
    assert abs(stats["p50"] - 50.5) < 0.1
    assert abs(stats["p90"] - 90.1) < 0.5
    assert abs(stats["p95"] - 95.05) < 0.5
    assert abs(stats["p99"] - 99.01) < 0.5
    assert stats["std_dev"] > 28.0


def test_percentile_calculation_empty_and_single():
    """Tests edge cases for percentile calculation."""
    empty_stats = calculate_percentiles([])
    assert empty_stats["mean"] == 0.0
    assert empty_stats["p50"] == 0.0

    single_stats = calculate_percentiles([42.5])
    assert single_stats["mean"] == 42.5
    assert single_stats["p50"] == 42.5
    assert single_stats["p99"] == 42.5
    assert single_stats["std_dev"] == 0.0


def test_latex_table_generation():
    """Verifies output contains well-formed LaTeX table syntax."""
    measurements = [
        {
            "num_rules": 100,
            "actual_states": 35,
            "actual_transitions": 102,
            "verification_time_ms": 1.45,
            "percentiles": {"mean": 1.45, "p50": 1.40, "p95": 1.62, "p99": 1.70},
            "throughput_rules_per_sec": 70344
        }
    ]
    latex_code = format_latex_table(measurements)
    assert r"\begin{table}" in latex_code
    assert r"\begin{tabular}" in latex_code
    assert r"\caption{" in latex_code
    assert "100 & 35 & 102 & 1.45 & 1.40 & 1.62 & 1.70" in latex_code
    assert r"\end{table}" in latex_code


def test_markdown_table_generation():
    """Verifies output contains well-formed Markdown table headers and data rows."""
    measurements = [
        {
            "num_rules": 50,
            "actual_states": 20,
            "actual_transitions": 52,
            "verification_time_ms": 0.85,
            "percentiles": {"mean": 0.85, "p50": 0.82, "p95": 0.95, "p99": 0.99},
            "throughput_rules_per_sec": 61176,
            "violations_detected": 0
        }
    ]
    md_code = format_markdown_table(measurements)
    assert "| Scale (N) | States |Q|" in md_code
    assert "| N = 50 | 20 | 52 |" in md_code


def test_advanced_benchmark_endpoint():
    """Verifies POST /api/experiments/benchmark/advanced returns percentiles and LaTeX."""
    payload = {
        "scales": [10, 50],
        "iterations": 3
    }
    response = client.post("/api/experiments/benchmark/advanced", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["iterations_per_scale"] == 3
    assert len(data["measurements"]) == 2
    first_m = data["measurements"][0]
    assert "percentiles" in first_m
    assert "p50" in first_m["percentiles"]
    assert "p95" in first_m["percentiles"]
    assert "latex_table" in data
    assert r"\begin{table}" in data["latex_table"]
    assert "markdown_table" in data
