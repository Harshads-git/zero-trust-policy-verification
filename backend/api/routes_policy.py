"""
FastAPI Policy Routes
Endpoints for submitting, verifying, listing, and retrieving policies and audit reports.
"""

from fastapi import APIRouter, HTTPException, Depends, status
from typing import List, Dict, Any
import os
import json
from pathlib import Path

from backend.models.policy import ZeroTrustPolicy
from backend.models.report import VerificationReport
from backend.core.verifier import ZeroTrustVerificationEngine
from backend.core.smt_solver import Z3ConstraintSolver
from backend.core.risk_engine import ContinuousRiskEngine
from backend.core.fsm import FiniteStateMachine
from backend.core.synthesizer import PolicySynthesizer, SynthesisResult
from backend.core.cegis_loop import CEGISEngine, CEGISResult
from backend.exporters.sarif import SARIFExporter
from backend.storage import get_repository, PolicyRepository
from backend.cloud import get_cloudwatch_publisher
from backend.security import PolicySanitizer

router = APIRouter(prefix="/policies", tags=["Zero Trust Policies"])
verifier = ZeroTrustVerificationEngine()
synthesizer = PolicySynthesizer()
cegis_engine = CEGISEngine()


@router.post("/verify", response_model=VerificationReport, summary="Verify policy against Zero Trust & TOC invariants")
def verify_policy(
    policy: ZeroTrustPolicy,
    save_audit: bool = True,
    repo: PolicyRepository = Depends(get_repository)
) -> VerificationReport:
    """
    Formally evaluates a Zero Trust policy using Finite State Machine invariants.
    Returns structured verification report with violations, counterexamples, and graph data.
    """
    policy = PolicySanitizer.sanitize_policy(policy)
    report = verifier.verify(policy)
    if save_audit:
        try:
            repo.save_report(report)
        except Exception:
            pass  # Non-blocking for audit logging
    try:
        get_cloudwatch_publisher().publish_verification_metrics(report)
    except Exception:
        pass  # Non-blocking telemetry
    return report


@router.post("/verify-smt", summary="Verify policy with FSM invariants and Z3 SMT solver")
def verify_policy_with_smt(
    policy: ZeroTrustPolicy,
    repo: PolicyRepository = Depends(get_repository)
) -> Dict[str, Any]:
    """
    Combines formal FSM graph reachability verification with First-Order Logic
    SMT theorem proving using Microsoft Z3. Proves guard satisfiability,
    detects contradictory dead transitions, and extracts concrete witness models.
    """
    policy = PolicySanitizer.sanitize_policy(policy)
    fsm_report = verifier.verify(policy)

    smt_solver = Z3ConstraintSolver()
    dead_transitions = smt_solver.detect_dead_transitions(policy)

    grant_rules = [r for r in policy.rules if r.target in ("ACCESS_GRANTED",)]
    grant_evaluations = []
    for gr in grant_rules:
        guard = gr.get_guard_predicate()
        if guard:
            res = smt_solver.check_satisfiability([guard])
            grant_evaluations.append({
                "rule_id": gr.rule_id,
                "source": gr.source,
                "target": gr.target,
                "guard": guard.to_expression(),
                "smt_status": res.status,
                "is_satisfiable": res.is_satisfiable,
                "witness_model": res.model
            })

    risk_engine = ContinuousRiskEngine()
    risk_smt_bounds = risk_engine.verify_risk_bounds_with_smt(policy)

    return {
        "fsm_report": fsm_report,
        "smt_analysis": {
            "solver_engine": "Microsoft Z3 Theorem Prover",
            "dead_transitions_detected": dead_transitions,
            "has_dead_transitions": len(dead_transitions) > 0,
            "guard_satisfiability_checks": grant_evaluations,
            "continuous_risk_smt_bounds": risk_smt_bounds
        }
    }


@router.post("/verify-risk", summary="Verify dynamic continuous risk and step-up authentication invariants")
def verify_policy_risk(
    policy: ZeroTrustPolicy,
    stepup_threshold: float = 0.50
) -> Dict[str, Any]:
    """
    Evaluates dynamic continuous risk accumulation along access trajectories (NIST SP 800-207 Tenet 6).
    Checks whether high-risk execution paths trigger mandatory step-up authentication challenges.
    """
    policy = PolicySanitizer.sanitize_policy(policy)
    fsm = FiniteStateMachine.from_policy(policy)
    risk_engine = ContinuousRiskEngine(stepup_threshold=stepup_threshold)
    violations, profiles = risk_engine.evaluate_policy_risk_invariants(fsm, policy)
    smt_bounds = risk_engine.verify_risk_bounds_with_smt(policy)

    return {
        "policy_id": policy.policy_id,
        "policy_name": policy.policy_name,
        "stepup_threshold": stepup_threshold,
        "is_risk_compliant": len(violations) == 0,
        "violations_count": len(violations),
        "violations": violations,
        "trajectory_risk_profiles": profiles,
        "smt_risk_bounds": smt_bounds
    }


@router.post("", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED, summary="Create and store policy")
def create_policy(
    policy: ZeroTrustPolicy,
    repo: PolicyRepository = Depends(get_repository)
) -> Dict[str, Any]:
    """Saves policy to storage and runs formal verification."""
    policy = PolicySanitizer.sanitize_policy(policy)
    saved = repo.save_policy(policy)
    report = verifier.verify(saved)
    repo.save_report(report)
    return {
        "message": "Policy stored successfully",
        "policy": saved,
        "verification": report
    }


@router.get("", response_model=List[ZeroTrustPolicy], summary="List all stored policies")
def list_policies(repo: PolicyRepository = Depends(get_repository)) -> List[ZeroTrustPolicy]:
    return repo.list_policies()


@router.get("/{policy_id}", response_model=ZeroTrustPolicy, summary="Retrieve a policy by ID")
def get_policy(policy_id: str, repo: PolicyRepository = Depends(get_repository)) -> ZeroTrustPolicy:
    policy = repo.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy with ID '{policy_id}' not found.")
    return policy


@router.get("/{policy_id}/verify", response_model=VerificationReport, summary="Verify a stored policy on-demand")
def verify_stored_policy(
    policy_id: str,
    save_audit: bool = True,
    repo: PolicyRepository = Depends(get_repository)
) -> VerificationReport:
    """Retrieves an existing policy from storage and executes formal verification."""
    policy = repo.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy with ID '{policy_id}' not found.")
    report = verifier.verify(policy)
    if save_audit:
        try:
            repo.save_report(report)
        except Exception:
            pass
    return report


@router.get("/{policy_id}/remediation", summary="Retrieve remediation plan for a stored policy")
def get_policy_remediation_plan(
    policy_id: str,
    repo: PolicyRepository = Depends(get_repository)
) -> Dict[str, Any]:
    """Retrieves policy, verifies it, and returns an actionable remediation plan."""
    policy = repo.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy with ID '{policy_id}' not found.")
    report = verifier.verify(policy)
    return {
        "policy_id": policy.policy_id,
        "policy_name": policy.policy_name,
        "valid": report.valid,
        "risk_score": report.risk_score,
        "security_posture": report.security_posture,
        "violations_count": report.violations_count,
        "remediation_plan": report.get_remediation_plan()
    }


@router.delete("/{policy_id}", summary="Delete a policy")
def delete_policy(policy_id: str, repo: PolicyRepository = Depends(get_repository)) -> Dict[str, str]:
    success = repo.delete_policy(policy_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Policy with ID '{policy_id}' not found.")
    return {"message": f"Policy '{policy_id}' deleted successfully."}



@router.post("/synthesize-patch", response_model=SynthesisResult, summary="Synthesize minimal graph surgery patch & RFC 6902 delta")
def synthesize_policy_patch(
    policy: ZeroTrustPolicy
) -> SynthesisResult:
    """
    Counterexample-Guided Inductive Synthesis (CEGIS).
    Analyzes formal violation counterexamples, computes minimal graph surgery operations,
    and returns compliant policy candidate alongside an RFC 6902 JSON Patch document.
    """
    policy = PolicySanitizer.sanitize_policy(policy)
    result = synthesizer.synthesize_repair(policy)
    return result


@router.post("/{policy_id}/synthesize-patch", response_model=SynthesisResult, summary="Synthesize minimal patch for stored policy")
def synthesize_stored_policy_patch(
    policy_id: str,
    repo: PolicyRepository = Depends(get_repository)
) -> SynthesisResult:
    """
    Retrieves stored policy by ID, analyzes formal counterexamples, and synthesizes
    minimal graph surgery patches with RFC 6902 JSON Patch document.
    """
    policy = repo.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy with ID '{policy_id}' not found.")
    result = synthesizer.synthesize_repair(policy)
    return result


@router.post("/cegis-repair", response_model=CEGISResult, summary="Execute multi-iteration CEGIS loop for automated policy repair")
def run_cegis_repair(
    policy: ZeroTrustPolicy,
    max_iterations: int = 5
) -> CEGISResult:
    """
    Executes the full Counterexample-Guided Inductive Synthesis (CEGIS) loop:
    Iteratively proposes candidate graph surgery patches, queries the verification oracle,
    accumulates counterexample witness traces, and refines candidates until provable compliance.
    """
    policy = PolicySanitizer.sanitize_policy(policy)
    return cegis_engine.run_cegis_loop(policy, max_iterations=max_iterations)


@router.post("/{policy_id}/cegis-repair", response_model=CEGISResult, summary="Execute CEGIS repair loop for a stored policy")
def run_stored_policy_cegis_repair(
    policy_id: str,
    max_iterations: int = 5,
    repo: PolicyRepository = Depends(get_repository)
) -> CEGISResult:
    """
    Retrieves stored policy by ID and runs iterative CEGIS loop until all invariant violations
    are eliminated or max_iterations bound is reached.
    """
    policy = repo.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy with ID '{policy_id}' not found.")
    return cegis_engine.run_cegis_loop(policy, max_iterations=max_iterations)


@router.get("/reports/history", response_model=List[VerificationReport], summary="Retrieve verification audit history")
def list_reports(limit: int = 50, repo: PolicyRepository = Depends(get_repository)) -> List[VerificationReport]:
    return repo.list_reports(limit=limit)


@router.get("/samples/templates", summary="Retrieve bundled sample policies")
def get_sample_templates() -> Dict[str, Any]:
    """Loads bundled valid and invalid Zero Trust policies from the policies directory."""
    samples = {"valid": [], "invalid": []}
    base_dir = Path(__file__).resolve().parent.parent.parent / "policies"

    valid_dir = base_dir / "valid"
    if valid_dir.exists():
        for f in sorted(valid_dir.glob("*.json")):
            try:
                samples["valid"].append(json.loads(f.read_text(encoding="utf-8")))
            except Exception:
                pass

    invalid_dir = base_dir / "invalid"
    if invalid_dir.exists():
        for f in sorted(invalid_dir.glob("*.json")):
            try:
                samples["invalid"].append(json.loads(f.read_text(encoding="utf-8")))
            except Exception:
                pass

    return samples


@router.post("/verify/sarif", summary="Verify policy and export report in OASIS SARIF v2.1.0 format")
def verify_policy_sarif(
    policy: ZeroTrustPolicy,
    repo: PolicyRepository = Depends(get_repository)
) -> Dict[str, Any]:
    """
    Evaluates policy invariants and exports full OASIS SARIF v2.1.0 document
    for GitHub Code Scanning, GitLab SAST, and DevSecOps pipelines.
    """
    policy = PolicySanitizer.sanitize_policy(policy)
    report = verifier.verify(policy)
    return SARIFExporter.to_sarif_dict([report])


@router.get("/{policy_id}/sarif", summary="Retrieve policy verification report in OASIS SARIF v2.1.0 format")
def get_policy_sarif(
    policy_id: str,
    repo: PolicyRepository = Depends(get_repository)
) -> Dict[str, Any]:
    """
    Retrieves stored policy and generates an OASIS SARIF v2.1.0 JSON security report.
    """
    policy = repo.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy with ID '{policy_id}' not found.")
    report = verifier.verify(policy)
    return SARIFExporter.to_sarif_dict([report])

