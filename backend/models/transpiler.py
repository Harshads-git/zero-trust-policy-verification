"""
AWS IAM & Cloud Policy Transpiler Data Models
AxiomTrust Formal Verification Platform

Defines schemas for transpiling enterprise cloud policies (AWS IAM, K8s RBAC)
into verifiable Zero Trust Finite State Machines (DFAs).
"""

from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field

from backend.models.policy import ZeroTrustPolicy


class PrivilegeEscalationRisk(BaseModel):
    """Represents a dangerous IAM privilege escalation vector detected during transpilation."""
    vector: str = Field(..., description="Name of the privilege escalation vector (e.g., iam:PassRole-RunInstances)")
    actions: List[str] = Field(..., description="IAM actions contributing to this escalation")
    severity: str = Field(..., description="CRITICAL, HIGH, or MEDIUM")
    description: str = Field(..., description="Technical explanation of how the attack vector allows unauthorized elevation")
    mitigation: str = Field(..., description="Prescriptive AWS IAM least-privilege remediation advice")


class AWSIAMTranspileRequest(BaseModel):
    """Payload for transpiling an AWS IAM JSON policy into an AxiomTrust FSM."""
    iam_policy: Union[Dict[str, Any], str] = Field(..., description="Raw AWS IAM JSON policy document or dictionary")
    policy_name: Optional[str] = Field(default=None, description="Custom name for the transpiled policy")
    auto_verify: bool = Field(default=False, description="Whether to immediately run formal verification on the transpiled policy")


class AWSIAMTranspileResponse(BaseModel):
    """Output containing the transpiled Zero Trust FSM and IAM security analysis."""
    policy_name: str
    transpiled_policy: ZeroTrustPolicy
    statements_count: int
    allowed_actions: List[str]
    denied_actions: List[str]
    privilege_escalation_risks: List[PrivilegeEscalationRisk]
    has_wildcard_actions: bool
    has_wildcard_resources: bool
    mfa_enforced: bool
    transpilation_notes: List[str]
    verification_report: Optional[Dict[str, Any]] = None


class OPARegoExportRequest(BaseModel):
    """Request payload for exporting a verified FSM policy to Open Policy Agent (OPA) Rego."""
    policy: Optional[ZeroTrustPolicy] = Field(default=None, description="Inline Zero Trust policy to compile")
    package_name: str = Field(default="axiomtrust.authz", description="OPA package namespace")
    enforce_strict_zero_trust: bool = Field(default=True, description="Enforce NIST SP 800-207 MFA and device posture in Rego rules")
    include_audit_violations: bool = Field(default=True, description="Generate violation reason sets for explainable denial audit logs")
    target_framework: str = Field(default="general", description="Target framework: 'general', 'kubernetes_gatekeeper', or 'envoy_proxy'")


class OPARegoExportResponse(BaseModel):
    """Result of compiling a Zero Trust policy into production OPA Rego code."""
    policy_id: str
    policy_name: str
    package_name: str
    rego_code: str
    rules_compiled: int
    states_modeled: List[str]
    terminal_states: List[str]
    target_framework: str
    generated_at: float
    validation_status: str = "COMPILED"
