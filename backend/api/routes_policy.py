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
from backend.storage import get_repository, PolicyRepository

router = APIRouter(prefix="/policies", tags=["Zero Trust Policies"])
verifier = ZeroTrustVerificationEngine()


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
    report = verifier.verify(policy)
    if save_audit:
        try:
            repo.save_report(report)
        except Exception:
            pass  # Non-blocking for audit logging
    return report


@router.post("", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED, summary="Create and store policy")
def create_policy(
    policy: ZeroTrustPolicy,
    repo: PolicyRepository = Depends(get_repository)
) -> Dict[str, Any]:
    """Saves policy to storage and runs formal verification."""
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


@router.delete("/{policy_id}", summary="Delete a policy")
def delete_policy(policy_id: str, repo: PolicyRepository = Depends(get_repository)) -> Dict[str, str]:
    success = repo.delete_policy(policy_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Policy with ID '{policy_id}' not found.")
    return {"message": f"Policy '{policy_id}' deleted successfully."}


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
