"""
Cloud Policy Transpiler REST API Endpoints
AxiomTrust Formal Verification Platform
"""

from fastapi import APIRouter, HTTPException

from backend.models.transpiler import (
    AWSIAMTranspileRequest,
    AWSIAMTranspileResponse
)
from backend.transpiler.aws_iam import AWSIAMTranspiler

router = APIRouter(prefix="/transpile", tags=["Cloud Policy Transpiler"])
iam_transpiler = AWSIAMTranspiler()


@router.post("/aws-iam", response_model=AWSIAMTranspileResponse, summary="Transpile AWS IAM JSON policy into Zero Trust FSM")
def transpile_aws_iam_policy(
    request: AWSIAMTranspileRequest
) -> AWSIAMTranspileResponse:
    """
    Ingests native AWS IAM JSON policy documents (Statements with Effect, Action, Resource, Condition),
    translates IAM conditions into formal predicate guards, identifies privilege escalation attack vectors,
    and transpiles the policy into a verifiable Zero Trust Finite State Machine.
    """
    try:
        response = iam_transpiler.transpile(
            iam_policy_doc=request.iam_policy,
            policy_name=request.policy_name,
            auto_verify=request.auto_verify
        )
        return response
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Transpilation error: {str(e)}")


@router.post("/aws-iam/verify", response_model=AWSIAMTranspileResponse, summary="Transpile AWS IAM policy and immediately run formal verification")
def transpile_and_verify_aws_iam_policy(
    request: AWSIAMTranspileRequest
) -> AWSIAMTranspileResponse:
    """
    Transpiles an AWS IAM JSON document into an FSM and immediately executes formal model checking
    against NIST SP 800-207 safety invariants, returning the transpiled model and full verification report.
    """
    try:
        response = iam_transpiler.transpile(
            iam_policy_doc=request.iam_policy,
            policy_name=request.policy_name,
            auto_verify=True
        )
        return response
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Transpilation & verification error: {str(e)}")
