"""
AWS IAM Policy JSON to Zero Trust Finite State Machine (FSM) Transpiler
AxiomTrust Formal Verification Platform

Parses real-world AWS IAM policy JSON documents (Statement blocks with Effect,
Action, Resource, Condition) and compiles them into formally verifiable
Deterministic Finite Automata (DFAs).

Features:
- Normalizes single/array Actions and Resources
- Translates IAM Condition blocks (Bool, IpAddress, StringEquals) into formal predicate guards
- Analyzes 7 critical AWS IAM privilege escalation vectors (iam:PassRole, iam:AttachPolicy, etc.)
- Maps IAM authorization life-cycles into Zero Trust checkpoints (MFA, Device, Roles, Terminal sinks)
"""

import json
import uuid
import re
from typing import List, Dict, Any, Optional, Set, Union

from backend.models.policy import ZeroTrustPolicy, PolicyRule, PolicyMetadata
from backend.models.transpiler import (
    PrivilegeEscalationRisk,
    AWSIAMTranspileResponse
)
from backend.core.verifier import ZeroTrustVerificationEngine


KNOWN_PRIVILEGE_ESCALATION_VECTORS = [
    {
        "vector": "IAM_POLICY_VERSION_UPDATE",
        "required_actions": {"iam:createpolicyversion", "iam:setdefaultpolicyversion"},
        "match_mode": "any",
        "severity": "CRITICAL",
        "description": "Allows creating or setting a new IAM policy version, enabling direct elevation to AdministratorAccess (*:*).",
        "mitigation": "Restrict iam:CreatePolicyVersion and iam:SetDefaultPolicyVersion to cloud security administrators."
    },
    {
        "vector": "IAM_ATTACH_ADMIN_POLICY",
        "required_actions": {"iam:attachuserpolicy", "iam:attachgrouppolicy", "iam:attachrolepolicy"},
        "match_mode": "any",
        "severity": "CRITICAL",
        "description": "Allows attaching arbitrary managed policies (such as AdministratorAccess) to the actor's own IAM entity.",
        "mitigation": "Enforce strict IAM Permission Boundaries to prevent self-attachment of elevated policies."
    },
    {
        "vector": "IAM_INLINE_POLICY_CREATION",
        "required_actions": {"iam:putuserpolicy", "iam:putgrouppolicy", "iam:putrolepolicy"},
        "match_mode": "any",
        "severity": "CRITICAL",
        "description": "Allows embedding unrestricted inline administrator policies directly into IAM identities.",
        "mitigation": "Deny iam:Put*Policy across non-admin roles and monitor inline policy creations with AWS Config."
    },
    {
        "vector": "IAM_PASS_ROLE_COMPUTE_ESCALATION",
        "required_actions": {"iam:passrole"},
        "co_actions": {"ec2:runinstances", "lambda:createfunction", "glue:createdevendpoint", "ecs:runtask"},
        "match_mode": "passrole_combo",
        "severity": "CRITICAL",
        "description": "Allows passing a privileged IAM role to a compute resource (EC2, Lambda) and executing code with that role's permissions.",
        "mitigation": "Constrain iam:PassRole with strict iam:PassedToService conditions and explicit role ARN whitelists."
    },
    {
        "vector": "STS_ASSUME_ROLE_ELEVATION",
        "required_actions": {"sts:assumerole"},
        "match_mode": "any",
        "severity": "HIGH",
        "description": "Allows assuming privileged roles across accounts or within the same account to inherit elevated permissions.",
        "mitigation": "Enforce aws:MultiFactorAuthPresent and sts:ExternalId conditions in IAM role trust relationships."
    },
    {
        "vector": "IAM_ADD_USER_TO_GROUP",
        "required_actions": {"iam:addusertogroup"},
        "match_mode": "any",
        "severity": "HIGH",
        "description": "Allows adding unauthorized IAM users directly into high-privilege administrative groups.",
        "mitigation": "Restrict iam:AddUserToGroup via Service Control Policies (SCPs) and require multi-party approval."
    },
    {
        "vector": "IAM_UPDATE_ASSUME_ROLE_POLICY",
        "required_actions": {"iam:updateassumerolepolicy"},
        "match_mode": "any",
        "severity": "HIGH",
        "description": "Allows modifying the trust policy of existing roles to permit unauthorized external assumption.",
        "mitigation": "Enforce organizational SCPs and monitor IAM role trust relationship modifications."
    }
]


class AWSIAMTranspiler:
    """
    Transpiles native AWS IAM policy documents into formal Zero Trust Finite State Machines.
    """

    def __init__(self):
        self.verifier = ZeroTrustVerificationEngine()

    def transpile(
        self,
        iam_policy_doc: Union[Dict[str, Any], str],
        policy_name: Optional[str] = None,
        auto_verify: bool = False
    ) -> AWSIAMTranspileResponse:
        """
        Parses and compiles an AWS IAM policy into a ZeroTrustPolicy model.
        """
        doc = self._parse_json_policy(iam_policy_doc)

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        name = policy_name or doc.get("Id") or f"AWS_IAM_Transpiled_{uuid.uuid4().hex[:6]}"

        allowed_actions: Set[str] = set()
        denied_actions: Set[str] = set()
        all_actions: Set[str] = set()
        all_resources: Set[str] = set()
        transpilation_notes: List[str] = []

        has_wildcard_actions = False
        has_wildcard_resources = False
        mfa_enforced_overall = False

        rules: List[PolicyRule] = []

        # Analyze each Statement
        for idx, stmt in enumerate(statements):
            effect = stmt.get("Effect", "Allow")
            sid = stmt.get("Sid", f"Stmt_{idx + 1}")

            raw_actions = stmt.get("Action", [])
            if isinstance(raw_actions, str):
                raw_actions = [raw_actions]

            raw_resources = stmt.get("Resource", [])
            if isinstance(raw_resources, str):
                raw_resources = [raw_resources]

            conditions = stmt.get("Condition", {})

            for act in raw_actions:
                all_actions.add(act.lower())
                if act == "*" or act.endswith(":*"):
                    has_wildcard_actions = True
                if effect == "Allow":
                    allowed_actions.add(act)
                elif effect == "Deny":
                    denied_actions.add(act)

            for res in raw_resources:
                all_resources.add(res)
                if res == "*":
                    has_wildcard_resources = True

            # Parse conditions into formal predicate string & detect security posture
            guard_expr, is_mfa, is_device, is_ip = self._parse_iam_conditions(conditions)
            if is_mfa:
                mfa_enforced_overall = True

            # Generate FSM transitions for this statement
            stmt_rules = self._synthesize_rules_for_statement(
                sid=sid,
                effect=effect,
                actions=raw_actions,
                resources=raw_resources,
                guard_expr=guard_expr,
                is_mfa=is_mfa,
                is_device=is_device,
                is_ip=is_ip
            )
            rules.extend(stmt_rules)

        # Ensure session termination & revocation invariants are structurally satisfied if allowed
        if allowed_actions:
            rules.append(PolicyRule(
                rule_id=f"rule_iam_timeout_{uuid.uuid4().hex[:4]}",
                source="ACCESS_GRANTED",
                target="SESSION_EXPIRED",
                action="session_timeout",
                condition="session_duration > max_duration",
                description="Synthesized: session timeout after lease expiry (NIST SP 800-207)"
            ))
            rules.append(PolicyRule(
                rule_id=f"rule_iam_revoke_{uuid.uuid4().hex[:4]}",
                source="ACCESS_GRANTED",
                target="REVOKED",
                action="admin_revoke",
                description="Synthesized: emergency administrative credential revocation"
            ))

        # Check for Privilege Escalation vectors
        privilege_escalation_risks = self._detect_privilege_escalations(all_actions)

        if has_wildcard_actions:
            transpilation_notes.append("Wildcard action ('*') detected: over-permissive administrator privileges mapped.")
        if has_wildcard_resources:
            transpilation_notes.append("Wildcard resource ('*') detected: permissions apply across all cloud assets.")
        if not mfa_enforced_overall:
            transpilation_notes.append("MFA Condition absent: policy allows access without multi-factor verification.")

        # Construct final ZeroTrustPolicy
        transpiled_policy = ZeroTrustPolicy(
            policy_id=f"pol_{uuid.uuid4().hex[:8]}",
            policy_name=name,
            description=f"Transpiled from AWS IAM Policy. Statements: {len(statements)}, Actions: {len(allowed_actions)}",
            initial_state="START",
            terminal_states=["ACCESS_GRANTED", "ACCESS_DENIED", "SESSION_EXPIRED", "REVOKED"],
            metadata=PolicyMetadata(
                author="AxiomTrust AWS IAM Transpiler",
                target_resource=", ".join(list(all_resources)[:3]) or "AWS_DEFAULT_RESOURCE",
                allowed_roles=["aws_iam_identity"],
                max_session_seconds=3600,
                risk_threshold="MEDIUM" if has_wildcard_actions else "LOW"
            ),
            rules=rules
        )

        verification_report = None
        if auto_verify:
            report_obj = self.verifier.verify(transpiled_policy)
            verification_report = {
                "valid": report_obj.valid,
                "violations_count": report_obj.violations_count,
                "security_posture": report_obj.security_posture,
                "risk_score": report_obj.risk_score,
                "violations": [v.model_dump() for v in report_obj.violations]
            }

        return AWSIAMTranspileResponse(
            policy_name=name,
            transpiled_policy=transpiled_policy,
            statements_count=len(statements),
            allowed_actions=sorted(list(allowed_actions)),
            denied_actions=sorted(list(denied_actions)),
            privilege_escalation_risks=privilege_escalation_risks,
            has_wildcard_actions=has_wildcard_actions,
            has_wildcard_resources=has_wildcard_resources,
            mfa_enforced=mfa_enforced_overall,
            transpilation_notes=transpilation_notes,
            verification_report=verification_report
        )

    def _parse_json_policy(self, iam_policy_doc: Union[Dict[str, Any], str]) -> Dict[str, Any]:
        """Validates and loads raw JSON string or dictionary."""
        if isinstance(iam_policy_doc, str):
            try:
                return json.loads(iam_policy_doc)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid AWS IAM JSON document: {str(e)}")
        elif isinstance(iam_policy_doc, dict):
            return iam_policy_doc
        else:
            raise ValueError(f"Expected dict or JSON string for AWS IAM policy, got {type(iam_policy_doc)}")

    def _parse_iam_conditions(self, conditions: Dict[str, Any]) -> tuple[str, bool, bool, bool]:
        """
        Translates AWS IAM condition blocks into formal guard predicates.
        Returns: (guard_expression, is_mfa, is_device, is_ip)
        """
        if not conditions:
            return "", False, False, False

        guard_parts = []
        is_mfa = False
        is_device = False
        is_ip = False

        for operator, op_dict in conditions.items():
            if not isinstance(op_dict, dict):
                continue

            for key, val in op_dict.items():
                k_lower = key.lower()

                # 1. MultiFactorAuthPresent
                if "multifactorauthpresent" in k_lower:
                    is_true = str(val).lower() == "true"
                    if is_true:
                        is_mfa = True
                        guard_parts.append("auth_method == 'mfa'")

                # 2. SourceIp CIDR matching
                elif "sourceip" in k_lower:
                    is_ip = True
                    ip_val = val[0] if isinstance(val, list) and val else val
                    guard_parts.append(f"client_ip == '{ip_val}'")

                # 3. Device health or posture condition
                elif "device" in k_lower or "posture" in k_lower or "compliant" in k_lower:
                    is_device = True
                    guard_parts.append("device_health == 'compliant'")

                # 4. Role or Tag matching
                elif "role" in k_lower or "principaltag" in k_lower:
                    guard_parts.append(f"role == '{val}'")

                # 5. Generic StringEquals / NumericEquals
                else:
                    safe_key = re.sub(r"[^a-zA-Z0-9_]", "_", key)
                    guard_parts.append(f"{safe_key} == '{val}'")

        guard_expr = " AND ".join(guard_parts)
        return guard_expr, is_mfa, is_device, is_ip

    def _synthesize_rules_for_statement(
        self,
        sid: str,
        effect: str,
        actions: List[str],
        resources: List[str],
        guard_expr: str,
        is_mfa: bool,
        is_device: bool,
        is_ip: bool
    ) -> List[PolicyRule]:
        """
        Synthesizes directed FSM rules for an individual IAM statement block.
        """
        rules: List[PolicyRule] = []

        if effect == "Allow":
            curr_state = "START"

            # Step 1: Authentication Checkpoint
            if is_mfa:
                rule_auth = PolicyRule(
                    rule_id=f"rule_mfa_{uuid.uuid4().hex[:4]}",
                    source="START",
                    target="AUTHENTICATED",
                    action="mfa_authenticate",
                    condition="auth_method == 'mfa'",
                    description=f"[{sid}] Enforce AWS MultiFactorAuthPresent check"
                )
                rules.append(rule_auth)
                curr_state = "AUTHENTICATED"
            else:
                # If neither MFA nor IP is required, check if actions are over-permissive
                # Allow direct flow through standard authentication
                rule_auth = PolicyRule(
                    rule_id=f"rule_auth_{uuid.uuid4().hex[:4]}",
                    source="START",
                    target="AUTHENTICATED",
                    action="authenticate",
                    description=f"[{sid}] Standard identity authentication"
                )
                rules.append(rule_auth)
                curr_state = "AUTHENTICATED"

            # Step 2: Device / Network Posture Checkpoint
            if is_device or is_ip:
                cond = "device_health == 'compliant'" if is_device else (guard_expr or "ip_verified == true")
                rule_dev = PolicyRule(
                    rule_id=f"rule_dev_{uuid.uuid4().hex[:4]}",
                    source=curr_state,
                    target="DEVICE_VERIFIED",
                    action="verify_device_posture",
                    condition=cond,
                    description=f"[{sid}] Enforce device posture and network boundary inspection"
                )
                rules.append(rule_dev)
                curr_state = "DEVICE_VERIFIED"

            # Step 3: Action Execution / Role Assumption
            for act in actions:
                act_slug = act.replace(":", "_").replace("*", "all")

                if act.lower() == "sts:assumerole":
                    # Model Role Assumption intermediate state
                    role_target = "ROLE_ASSUMED_PRIVILEGED"
                    rules.append(PolicyRule(
                        rule_id=f"rule_assume_{uuid.uuid4().hex[:4]}",
                        source=curr_state,
                        target=role_target,
                        action="assume_role",
                        condition=guard_expr or "role == 'user'",
                        description=f"[{sid}] sts:AssumeRole credential exchange"
                    ))
                    rules.append(PolicyRule(
                        rule_id=f"rule_grant_{uuid.uuid4().hex[:4]}",
                        source=role_target,
                        target="ACCESS_GRANTED",
                        action="execute_assumed_action",
                        condition="role == 'admin'",
                        description=f"[{sid}] Access granted under assumed role"
                    ))
                else:
                    rules.append(PolicyRule(
                        rule_id=f"rule_act_{act_slug}_{uuid.uuid4().hex[:4]}",
                        source=curr_state,
                        target="ACCESS_GRANTED",
                        action=act,
                        condition=guard_expr or "role == 'user'",
                        description=f"[{sid}] Allow {act} on {', '.join(resources[:2])}"
                    ))

        elif effect == "Deny":
            # Explicit Deny statements map directly to ACCESS_DENIED sink
            for act in actions:
                act_slug = act.replace(":", "_").replace("*", "all")
                rules.append(PolicyRule(
                    rule_id=f"rule_deny_{act_slug}_{uuid.uuid4().hex[:4]}",
                    source="START",
                    target="ACCESS_DENIED",
                    action=act,
                    condition=guard_expr or "deny_explicit == true",
                    description=f"[{sid}] Explicit IAM Deny on {act}"
                ))
                rules.append(PolicyRule(
                    rule_id=f"rule_deny_auth_{act_slug}_{uuid.uuid4().hex[:4]}",
                    source="AUTHENTICATED",
                    target="ACCESS_DENIED",
                    action=act,
                    condition=guard_expr or "deny_explicit == true",
                    description=f"[{sid}] Explicit IAM Deny from authenticated state on {act}"
                ))

        return rules

    def _detect_privilege_escalations(self, actions_lower: Set[str]) -> List[PrivilegeEscalationRisk]:
        """
        Analyzes policy actions against known AWS IAM privilege escalation vectors.
        """
        risks: List[PrivilegeEscalationRisk] = []
        is_wildcard = "*" in actions_lower or "iam:*" in actions_lower

        for entry in KNOWN_PRIVILEGE_ESCALATION_VECTORS:
            req = entry["required_actions"]
            mode = entry["match_mode"]

            matched = False
            matching_actions = []

            if is_wildcard:
                matched = True
                matching_actions = list(req)
            elif mode == "any":
                for a in req:
                    if a in actions_lower:
                        matched = True
                        matching_actions.append(a)
            elif mode == "passrole_combo":
                co_actions = entry.get("co_actions", set())
                has_passrole = "iam:passrole" in actions_lower
                has_co = any(co in actions_lower for co in co_actions)
                if has_passrole and has_co:
                    matched = True
                    matching_actions = ["iam:passrole"] + [co for co in co_actions if co in actions_lower]

            if matched:
                risks.append(PrivilegeEscalationRisk(
                    vector=entry["vector"],
                    actions=sorted(matching_actions),
                    severity=entry["severity"],
                    description=entry["description"],
                    mitigation=entry["mitigation"]
                ))

        return risks
