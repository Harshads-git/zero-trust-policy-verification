"""
Unit & Integration Tests for CEGIS Policy Synthesis Benchmarks
AxiomTrust Formal Verification Platform
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.core.verifier import ZeroTrustVerificationEngine
from backend.core.cegis_benchmark import (
    generate_synthetic_flawed_policy,
    calculate_synthesis_percentiles,
    format_synthesis_latex_table,
    format_synthesis_markdown_table,
    run_synthesis_benchmark_suite
)


@pytest.fixture
def api_client():
    return TestClient(app)


def test_generate_synthetic_flawed_policy_injected_flaws():
    """Validates that synthetic flawed policy generator produces targeted vulnerabilities."""
    verifier = ZeroTrustVerificationEngine()

    flaws = ["auth_bypass", "no_revocation", "dead_trap", "missing_device", "rule_conflict"]
    flawed_policy = generate_synthetic_flawed_policy(
        scale=8,
        flaw_types=flaws,
        seed=123
    )

    assert flawed_policy.policy_name.startswith("Synthetic Flawed Policy")
    assert flawed_policy.initial_state == "START"
    assert len(flawed_policy.rules) >= 6

    # When verified, flawed policy should produce multiple formal violations
    report = verifier.verify(flawed_policy)
    assert not report.valid
    assert report.violations_count >= 2


def test_calculate_synthesis_percentiles_accuracy():
    """Tests exact statistical percentile computations and empty list edge cases."""
    empty_result = calculate_synthesis_percentiles([])
    assert empty_result["p50"] == 0.0
    assert empty_result["mean"] == 0.0

    sample_times = [10.0, 20.0, 30.0, 40.0, 50.0]
    p = calculate_synthesis_percentiles(sample_times)

    assert p["min"] == 10.0
    assert p["max"] == 50.0
    assert p["mean"] == 30.0
    assert p["p50"] == 30.0
    assert p["p90"] == 46.0
    assert p["p95"] == 48.0
    assert p["p99"] == 49.6
    assert p["std_dev"] > 0.0


def test_format_synthesis_latex_and_markdown_tables():
    """Validates that LaTeX and Markdown table exporters generate valid tabular schemas."""
    mock_measurements = [
        {
            "batch_size": 10,
            "mean_rules": 25,
            "percentiles": {
                "mean": 12.5,
                "p50": 11.2,
                "p95": 18.4,
                "p99": 21.0
            },
            "convergence_rate": 100.0,
            "avg_convergence_rounds": 1.4,
            "mean_optimality_ratio": 1.15,
            "synthesis_throughput_policies_per_sec": 80.0
        }
    ]

    latex_str = format_synthesis_latex_table(mock_measurements)
    assert r"\begin{table}" in latex_str
    assert r"\begin{tabular}" in latex_str
    assert "tab:cegis_synthesis_benchmarks" in latex_str
    assert r"\end{table}" in latex_str
    assert "100.0\\%" in latex_str

    md_str = format_synthesis_markdown_table(mock_measurements)
    assert "| Batch Size | Mean Rules | Mean Latency |" in md_str
    assert "| N = 10 | 25 | 12.50 ms | 11.20 ms |" in md_str
    assert "100.0%" in md_str


def test_run_synthesis_benchmark_suite_convergence():
    """Runs a compact benchmark suite to assert CEGIS convergence and output structure."""
    results = run_synthesis_benchmark_suite(batch_sizes=[2, 4], max_iterations=4)

    assert "benchmark_summary" in results
    assert len(results["measurements"]) == 2
    for m in results["measurements"]:
        assert m["convergence_rate"] == 100.0
        assert m["avg_convergence_rounds"] >= 1.0
        assert m["mean_optimality_ratio"] >= 1.0
        assert m["percentiles"]["p50"] > 0.0
        assert m["synthesis_throughput_policies_per_sec"] > 0.0

    assert r"\begin{table}" in results["latex_table"]
    assert "| Batch Size |" in results["markdown_table"]


def test_synthesis_benchmark_rest_api_endpoint(api_client):
    """Asserts POST /api/experiments/synthesis-benchmark executes and responds with HTTP 200."""
    payload = {
        "batch_sizes": [2],
        "max_iterations": 3
    }
    response = api_client.post("/api/experiments/synthesis-benchmark", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert "measurements" in data
    assert len(data["measurements"]) == 1
    assert data["measurements"][0]["batch_size"] == 2
    assert data["measurements"][0]["convergence_rate"] == 100.0
    assert "latex_table" in data
    assert "markdown_table" in data
