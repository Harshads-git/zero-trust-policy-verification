"""
Red-Team Threat Simulation & Lateral Movement REST API Routes
AxiomTrust Formal Verification Platform
"""

from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Depends

from backend.models.threat import (
    ThreatSimulationRequest,
    ThreatSimulationResult
)
from backend.core.threat_simulator import AttackGraphSimulator
from backend.storage import PolicyRepository, get_repository
from backend.security import PolicySanitizer

router = APIRouter(prefix="/threat", tags=["Red-Team Threat Simulation"])
simulator = AttackGraphSimulator()


@router.post("/simulate", response_model=ThreatSimulationResult, summary="Simulate adversarial lateral movement and blast radius")
def simulate_threat_impact(
    request: ThreatSimulationRequest
) -> ThreatSimulationResult:
    """
    Simulates adversarial lateral movement through an access control policy from an initial compromised node.
    Computes reachable state closure, blast radius percentage, crown jewel reachability,
    exploit trajectories with difficulty ratings, critical choke points, and Zero Trust containment advisories.
    """
    if not request.policy:
        raise HTTPException(
            status_code=400,
            detail="Policy definition must be provided in request body when calling /api/threat/simulate."
        )

    sanitized_policy = PolicySanitizer.sanitize_policy(request.policy)
    try:
        result = simulator.simulate(sanitized_policy, request)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat simulation error: {str(e)}")


@router.post("/{policy_id}/simulate", response_model=ThreatSimulationResult, summary="Simulate threat on a stored policy")
def simulate_stored_policy_threat(
    policy_id: str,
    request: ThreatSimulationRequest,
    repo: PolicyRepository = Depends(get_repository)
) -> ThreatSimulationResult:
    """
    Retrieves stored policy by ID and runs red-team adversarial lateral movement simulation
    from the specified compromised node.
    """
    policy = repo.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy with ID '{policy_id}' not found.")

    try:
        result = simulator.simulate(policy, request)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat simulation error: {str(e)}")
