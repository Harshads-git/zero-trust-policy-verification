"""
Open Policy Agent (OPA) Rego Compiler & Exporter
AxiomTrust Formal Verification Platform

Compiles formally verified Zero Trust Finite State Machines into idiomatic,
production-ready OPA Rego code for:
- Cloud-Native Policy Enforcement Points (PEP)
- Kubernetes Admission Controllers (Gatekeeper / OPA)
- Envoy Proxy Service Mesh External Authorization (ext_authz)
"""

import time
import re
from typing import List, Dict, Any, Optional, Set

from backend.models.policy import ZeroTrustPolicy, PolicyRule
from backend.models.transpiler import (
    OPARegoExportRequest,
    OPARegoExportResponse
)


class OPARegoGenerator:
    """
    Compiles Zero Trust FSM policies into standard Open Policy Agent (OPA) Rego documents.
    """

    def compile(
        self,
        policy: ZeroTrustPolicy,
        request: Optional[OPARegoExportRequest] = None
    ) -> OPARegoExportResponse:
        """
        Translates a ZeroTrustPolicy object into an OPA Rego document.
        """
        req = request or OPARegoExportRequest()
        package_name = req.package_name or "axiomtrust.authz"
        framework = req.target_framework or "general"
        strict_zt = req.enforce_strict_zero_trust
        include_audit = req.include_audit_violations

        all_states = sorted(list(policy.get_all_states()))
        terminal_states = sorted(list(policy.terminal_states))

        allowed_roles = policy.metadata.allowed_roles if (policy.metadata and policy.metadata.allowed_roles) else ["user", "admin"]
        max_session = policy.metadata.max_session_seconds if policy.metadata else 3600

        lines: List[str] = []

        # 1. Package & Metadata Header
        lines.append(f"package {package_name}")
        lines.append("")
        lines.append("# " + "=" * 76)
        lines.append(f"# AxiomTrust Formal Zero Trust Policy Compilation (OPA Rego)")
        lines.append(f"# Policy ID:   {policy.policy_id}")
        lines.append(f"# Policy Name: {policy.policy_name}")
        lines.append(f"# Framework:   {framework.upper()}")
        lines.append(f"# Timestamp:   {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
        lines.append("# " + "=" * 76)
        lines.append("")
        lines.append("import future.keywords.in")
        lines.append("import future.keywords.if")
        lines.append("import future.keywords.contains")
        lines.append("")

        # 2. Default Deny Semantics (NIST SP 800-207 Core Tenet)
        lines.append("# --- Default Deny Posture ---")
        lines.append("# In Zero Trust Architecture, access is denied unless affirmatively proven compliant.")
        lines.append("default allow := false")
        lines.append("default allow_action := false")
        lines.append("default is_compliant := false")
        lines.append("")

        # 3. Model Constants
        lines.append("# --- Policy Constants & Boundaries ---")
        lines.append(f'initial_state := "{policy.initial_state}"')
        
        term_states_str = ", ".join(f'"{s}"' for s in terminal_states)
        lines.append(f"terminal_states := {{{term_states_str}}}")

        roles_str = ", ".join(f'"{r}"' for r in allowed_roles)
        lines.append(f"allowed_roles := {{{roles_str}}}")
        lines.append(f"max_session_seconds := {max_session}")
        lines.append("")

        # 4. Primary Decision Rule: allow
        lines.append("# --- Primary Access Authorization Decision ---")
        lines.append("allow if {")
        lines.append("    valid_transition")
        lines.append("    not session_expired")
        lines.append("    not is_revoked")
        if strict_zt:
            lines.append("    identity_authenticated")
            lines.append("    device_compliant")
            lines.append("    role_authorized")
        lines.append("}")
        lines.append("")

        # 5. Core Security Invariant Checkpoints
        lines.append("# --- Zero Trust Invariant Checkpoints ---")
        
        # Identity Authentication Checkpoint
        lines.append("identity_authenticated if {")
        lines.append("    input.identity_verified == true")
        lines.append("}")
        lines.append("identity_authenticated if {")
        lines.append('    input.auth_method in {"mfa", "hardware_token", "biometric", "fido2"}')
        lines.append("}")
        lines.append("")

        # Device Posture Checkpoint
        lines.append("device_compliant if {")
        lines.append("    input.device_verified == true")
        lines.append("}")
        lines.append("device_compliant if {")
        lines.append('    input.device_health in {"compliant", "managed", "healthy"}')
        lines.append("}")
        lines.append("")

        # Role Authorization Checkpoint
        lines.append("role_authorized if {")
        lines.append("    input.role in allowed_roles")
        lines.append("}")
        lines.append("")

        # Session Lifetime & Revocation Checks
        lines.append("session_expired if {")
        lines.append("    input.session_duration > max_session_seconds")
        lines.append("}")
        lines.append("")
        lines.append("is_revoked if {")
        lines.append("    input.revocation_status == true")
        lines.append("}")
        lines.append("is_revoked if {")
        lines.append('    input.current_state == "REVOKED"')
        lines.append("}")
        lines.append("")

        # 6. FSM State Transition Rules
        lines.append("# --- Directed Automaton State Transitions ---")
        lines.append("# Verifies that (current_state, action) -> target_state satisfies transition guards.")
        
        rules_compiled = 0
        for r in policy.rules:
            # Build Rego rule body for this transition
            cond_clauses = self._translate_condition_to_rego(r.condition)
            lines.append(f"# Rule {r.rule_id}: {r.source} -> {r.target} ({r.action})")
            lines.append("valid_transition if {")
            lines.append(f'    input.current_state == "{r.source}"')
            lines.append(f'    input.action == "{r.action}"')
            lines.append(f'    input.target_state == "{r.target}"')
            for clause in cond_clauses:
                lines.append(f"    {clause}")
            lines.append("}")
            lines.append("")
            rules_compiled += 1

        # Action-level permission lookup
        lines.append("# --- Fine-Grained Action Permission ---")
        lines.append("allow_action if {")
        lines.append("    allow")
        lines.append("}")
        lines.append("")

        # 7. Diagnostic Denial Reasons / Violation Audit Set
        if include_audit:
            lines.append("# --- Explainable Denial Diagnostics (Audit Trail) ---")
            lines.append("violations contains \"MISSING_IDENTITY_AUTHENTICATION\" if {")
            lines.append("    not identity_authenticated")
            lines.append("}")
            lines.append("")
            lines.append("violations contains \"NON_COMPLIANT_DEVICE_POSTURE\" if {")
            lines.append("    not device_compliant")
            lines.append("}")
            lines.append("")
            lines.append("violations contains \"UNAUTHORIZED_ROLE_PRIVILEGE\" if {")
            lines.append("    not role_authorized")
            lines.append("}")
            lines.append("")
            lines.append("violations contains \"SESSION_MAX_DURATION_EXCEEDED\" if {")
            lines.append("    session_expired")
            lines.append("}")
            lines.append("")
            lines.append("violations contains \"CREDENTIAL_OR_TOKEN_REVOKED\" if {")
            lines.append("    is_revoked")
            lines.append("}")
            lines.append("")
            lines.append("violations contains \"INVALID_FSM_TRANSITION\" if {")
            lines.append("    not valid_transition")
            lines.append("}")
            lines.append("")

        # 8. Framework-Specific Bindings (Gatekeeper / Envoy)
        if framework == "kubernetes_gatekeeper":
            lines.append("# --- Kubernetes Gatekeeper Constraint Binding ---")
            lines.append("violation[{\"msg\": msg}] if {")
            lines.append("    not allow")
            lines.append("    reasons := concat(\", \", [v | v := violations[_]])")
            lines.append("    msg := sprintf(\"AxiomTrust Zero Trust Admission Denied: %v\", [reasons])")
            lines.append("}")
            lines.append("")
        elif framework == "envoy_proxy":
            lines.append("# --- Envoy External Authorization (ext_authz) Binding ---")
            lines.append("response := {")
            lines.append('    "allowed": allow,')
            lines.append('    "headers": {"x-axiomtrust-policy": policy_name},')
            lines.append('    "body": sprintf("{\\"status\\": \\"%v\\", \\"violations\\": %v}", [')
            lines.append('        "GRANTED" if allow else "DENIED",')
            lines.append('        [v | v := violations[_]]')
            lines.append("    ])")
            lines.append("}")
            lines.append("")

        rego_code = "\n".join(lines)

        return OPARegoExportResponse(
            policy_id=policy.policy_id,
            policy_name=policy.policy_name,
            package_name=package_name,
            rego_code=rego_code,
            rules_compiled=rules_compiled,
            states_modeled=all_states,
            terminal_states=terminal_states,
            target_framework=framework,
            generated_at=time.time(),
            validation_status="COMPILED"
        )

    def _translate_condition_to_rego(self, condition: Optional[str]) -> List[str]:
        """Translates a Python/FSM condition expression into OPA Rego boolean clauses."""
        if not condition or condition.strip() == "":
            return []

        clauses: List[str] = []
        # Split on AND
        parts = [p.strip() for p in condition.split("AND") if p.strip()]

        for part in parts:
            # Match key == 'val' or key == "val"
            eq_match = re.match(r"^([a-zA-Z0-9_]+)\s*==\s*['\"]([^'\"]+)['\"]$", part)
            if eq_match:
                key, val = eq_match.group(1), eq_match.group(2)
                clauses.append(f'input.{key} == "{val}"')
                continue

            # Match key != 'val' or key != "val"
            neq_match = re.match(r"^([a-zA-Z0-9_]+)\s*!=\s*['\"]([^'\"]+)['\"]$", part)
            if neq_match:
                key, val = neq_match.group(1), neq_match.group(2)
                clauses.append(f'input.{key} != "{val}"')
                continue

            # Match numeric comparison (e.g. session_age > max_duration or risk_score <= 50)
            num_match = re.match(r"^([a-zA-Z0-9_]+)\s*(<=|>=|<|>)\s*([0-9a-zA-Z_]+)$", part)
            if num_match:
                key, op, val = num_match.group(1), num_match.group(2), num_match.group(3)
                if val.isdigit():
                    clauses.append(f"input.{key} {op} {val}")
                else:
                    clauses.append(f"input.{key} {op} input.{val}")
                continue

            # Boolean true/false
            bool_match = re.match(r"^([a-zA-Z0-9_]+)\s*==\s*(true|false)$", part, re.IGNORECASE)
            if bool_match:
                key, val = bool_match.group(1), bool_match.group(2).lower()
                clauses.append(f"input.{key} == {val}")
                continue

            # Fallback raw input prefix
            safe_part = part.replace("'", '"')
            clauses.append(f"input.{safe_part}")

        return clauses
