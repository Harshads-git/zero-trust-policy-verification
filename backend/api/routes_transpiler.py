"""
Cloud Policy Transpiler & OPA Rego Exporter REST API Endpoints
AxiomTrust Formal Verification Platform
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Response

from backend.models.transpiler import (
    AWSIAMTranspileRequest,
    AWSIAMTranspileResponse,
    OPARegoExportRequest,
    OPARegoExportResponse
)
from backend.transpiler.aws_iam import AWSIAMTranspiler
from backend.transpiler.opa_rego import OPARegoGenerator
from backend.storage import PolicyRepository, get_repository
from backend.security import PolicySanitizer

router = APIRouter(prefix="/transpile", tags=["Cloud Policy Transpiler"])
iam_transpiler = AWSIAMTranspiler()
rego_generator = OPARegoGenerator()


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


@router.post("/opa-rego", response_model=OPARegoExportResponse, summary="Compile Zero Trust policy into OPA Rego code")
def compile_opa_rego_policy(
    request: OPARegoExportRequest
) -> OPARegoExportResponse:
    """
    Compiles an inline Zero Trust policy FSM into production-ready Open Policy Agent (OPA) Rego code.
    Translates state transitions, NIST SP 800-207 guard invariants, and contextual conditions into Rego rules.
    """
    if not request.policy:
        raise HTTPException(
            status_code=400,
            detail="Policy definition must be provided in request body when calling /api/transpile/opa-rego."
        )

    sanitized_policy = PolicySanitizer.sanitize_policy(request.policy)
    try:
        return rego_generator.compile(sanitized_policy, request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OPA Rego compilation error: {str(e)}")


@router.get("/{policy_id}/opa-rego", response_model=OPARegoExportResponse, summary="Export stored policy as OPA Rego code")
def export_stored_policy_to_opa_rego(
    policy_id: str,
    package_name: str = "axiomtrust.authz",
    framework: str = "general",
    strict_zero_trust: bool = True,
    include_audit: bool = True,
    repo: PolicyRepository = Depends(get_repository)
) -> OPARegoExportResponse:
    """
    Retrieves stored policy by ID and compiles it into an OPA Rego document.
    """
    policy = repo.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy with ID '{policy_id}' not found.")

    req = OPARegoExportRequest(
        policy=policy,
        package_name=package_name,
        target_framework=framework,
        enforce_strict_zero_trust=strict_zero_trust,
        include_audit_violations=include_audit
    )
    return rego_generator.compile(policy, req)


@router.get("/{policy_id}/opa-rego/download", summary="Download raw OPA Rego (.rego) policy file")
def download_stored_policy_rego_file(
    policy_id: str,
    package_name: str = "axiomtrust.authz",
    framework: str = "general",
    repo: PolicyRepository = Depends(get_repository)
) -> Response:
    """
    Exports and downloads a raw .rego file for direct deployment to OPA Gatekeeper or Envoy.
    """
    policy = repo.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy with ID '{policy_id}' not found.")

    req = OPARegoExportRequest(
        policy=policy,
        package_name=package_name,
        target_framework=framework
    )
    result = rego_generator.compile(policy, req)

    filename = f"{policy_id}.rego"
    return Response(
        content=result.rego_code,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )
