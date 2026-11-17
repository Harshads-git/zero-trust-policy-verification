"""
Automated Policy Synthesis & Minimal Graph Surgery Engine (CEGIS Component)
AxiomTrust Formal Verification Platform

Implements Counterexample-Guided Policy Synthesis and Minimal Graph Surgery:
- Translates formal counterexample witness paths into minimal graph surgery operations
- Computes weighted Graph Edit Distance (GED): Δ(G, G')
- Synthesizes compliant ZeroTrustPolicy candidates that satisfy all invariants
- Emits RFC 6902 JSON Patch documents (RFC 6902 standard) for interoperable automated repair
"""

from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
from pydantic import BaseModel, Field
import copy
import time
import uuid

from backend.models.policy import ZeroTrustPolicy, PolicyRule
from backend.models.report import PolicyViolation, ViolationType, VerificationReport
from backend.core.verifier import ZeroTrustVerificationEngine


class PatchOpType(str, Enum):
    INTERPOSE_STATE = "INTERPOSE_STATE"
    INJECT_TRANSITION = "INJECT_TRANSITION"
    REMOVE_TRANSITION = "REMOVE_TRANSITION"
    ADD_REVOCATION_PATH = "ADD_REVOCATION_PATH"
    CONNECT_DEAD_STATE = "CONNECT_DEAD_STATE"
    TIGHTEN_GUARD = "TIGHTEN_GUARD"
    RESOLVE_CONFLICT = "RESOLVE_CONFLICT"


class RFC6902Op(BaseModel):
    """RFC 6902 JSON Patch operation object."""
    op: str = Field(..., description="Patch operation: 'add', 'remove', 'replace'")
    path: str = Field(..., description="JSON Pointer string path, e.g. '/rules/-' or '/rules/0'")
    value: Optional[Any] = Field(default=None, description="Payload value for add/replace")


class GraphSurgeryPatch(BaseModel):
    """A discrete graph surgery modification addressing a specific formal invariant violation."""
    patch_id: str = Field(default_factory=lambda: f"patch_{uuid.uuid4().hex[:6]}")
    op_type: PatchOpType
    target_rule_id: Optional[str] = None
    affected_states: List[str] = Field(default_factory=list)
    description: str
    violation_addressed: Optional[str] = None
    rules_to_add: List[PolicyRule] = Field(default_factory=list)
    rules_to_remove: List[str] = Field(default_factory=list, description="IDs of rules to remove")
    rules_to_modify: List[PolicyRule] = Field(default_factory=list)
    rfc6902_ops: List[RFC6902Op] = Field(default_factory=list)
    edit_distance_cost: float = Field(default=1.0, description="Weighted Graph Edit Distance penalty")


class SynthesisResult(BaseModel):
    """Outcome of automated policy synthesis and minimal graph surgery."""
    original_policy_id: str
    original_policy_name: str
    is_flawed: bool
    flaws_detected: int
    patches: List[GraphSurgeryPatch] = Field(default_factory=list)
    total_edit_distance: float = 0.0
    repaired_policy: Optional[ZeroTrustPolicy] = None
    rfc6902_patch_document: List[Dict[str, Any]] = Field(default_factory=list)
    repaired_report: Optional[Dict[str, Any]] = None
    synthesis_time_ms: float = 0.0


def apply_rfc6902_patch(doc: Dict[str, Any], patch: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Applies an RFC 6902 JSON Patch document to a target dictionary.
    Supports 'add', 'remove', and 'replace' operations with standard JSON Pointer paths.
    """
    result = copy.deepcopy(doc)
    for op_item in patch:
        op = op_item.get("op")
        path = op_item.get("path", "")
        value = op_item.get("value")

        tokens = [t.replace("~1", "/").replace("~0", "~") for t in path.split("/") if t != ""]
        if not tokens:
            continue

        parent = result
        for t in tokens[:-1]:
            if isinstance(parent, dict):
                parent = parent.setdefault(t, {})
            elif isinstance(parent, list):
                idx = int(t)
                parent = parent[idx]

        last_token = tokens[-1]
        if isinstance(parent, list):
            if last_token == "-":
                if op == "add":
                    parent.append(value)
            else:
                idx = int(last_token)
                if op == "add":
                    parent.insert(idx, value)
                elif op == "remove":
                    if 0 <= idx < len(parent):
                        parent.pop(idx)
                elif op == "replace":
                    if 0 <= idx < len(parent):
                        parent[idx] = value
        elif isinstance(parent, dict):
            if op in ("add", "replace"):
                parent[last_token] = value
            elif op == "remove":
                parent.pop(last_token, None)

    return result


class PolicySynthesizer:
    """
    Counterexample-Guided Inductive Policy Synthesizer.
    Analyzes formal violation counterexamples, computes minimal graph surgery operations,
    and synthesizes RFC 6902-compliant compliant policies.
    """

    def __init__(self):
        self.verifier = ZeroTrustVerificationEngine()

    def synthesize_repair(self, policy: ZeroTrustPolicy) -> SynthesisResult:
        """
        Executes formal verification, analyzes counterexamples, and synthesizes
        minimal graph surgery patches to repair all discovered invariant violations.
        """
        start_time = time.perf_counter()
        report = self.verifier.verify(policy)

        if report.valid:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return SynthesisResult(
                original_policy_id=policy.policy_id,
                original_policy_name=policy.policy_name,
                is_flawed=False,
                flaws_detected=0,
                patches=[],
                total_edit_distance=0.0,
                repaired_policy=policy,
                rfc6902_patch_document=[],
                repaired_report={
                    "valid": True,
                    "violations_count": 0,
                    "security_posture": "COMPLIANT",
                    "risk_score": 0
                },
                synthesis_time_ms=round(elapsed, 3)
            )

        # Policy is flawed; compute minimal graph surgery patches
        patches: List[GraphSurgeryPatch] = []
        handled_scenarios: Set[str] = set()

        # Step 1: Synthesize patches per violation
        for violation in report.violations:
            scenario_key = f"{violation.type.value}:{violation.rule_id}:{violation.state}"
            if scenario_key in handled_scenarios:
                continue
            handled_scenarios.add(scenario_key)

            patch = self._synthesize_patch_for_violation(policy, violation)
            if patch:
                patches.append(patch)

        # Step 2: Apply patches to clone of policy to produce repaired candidate
        repaired_policy, rfc_doc = self._apply_patches_to_policy(policy, patches)

        # Step 3: Re-verify repaired candidate to validate soundness
        repaired_report_obj = self.verifier.verify(repaired_policy)
        repaired_report_summary = {
            "valid": repaired_report_obj.valid,
            "violations_count": repaired_report_obj.violations_count,
            "security_posture": repaired_report_obj.security_posture,
            "risk_score": repaired_report_obj.risk_score,
            "violations": [v.model_dump() for v in repaired_report_obj.violations]
        }

        total_cost = sum(p.edit_distance_cost for p in patches)
        elapsed = (time.perf_counter() - start_time) * 1000.0

        return SynthesisResult(
            original_policy_id=policy.policy_id,
            original_policy_name=policy.policy_name,
            is_flawed=True,
            flaws_detected=len(report.violations),
            patches=patches,
            total_edit_distance=round(total_cost, 2),
            repaired_policy=repaired_policy,
            rfc6902_patch_document=rfc_doc,
            repaired_report=repaired_report_summary,
            synthesis_time_ms=round(elapsed, 3)
        )

    def _synthesize_patch_for_violation(
        self,
        policy: ZeroTrustPolicy,
        violation: PolicyViolation
    ) -> Optional[GraphSurgeryPatch]:
        """Maps a specific formal violation into a minimal graph surgery patch."""
        v_type = violation.type

        # 1. MISSING_AUTHENTICATION or PRIVILEGE_BYPASS
        if v_type in (ViolationType.MISSING_AUTHENTICATION, ViolationType.PRIVILEGE_BYPASS):
            return self._repair_missing_authentication(policy, violation)

        # 2. MISSING_DEVICE_VERIFICATION
        elif v_type == ViolationType.MISSING_DEVICE_VERIFICATION:
            return self._repair_missing_device_verification(policy, violation)

        # 3. NO_REVOCATION_PATH
        elif v_type == ViolationType.NO_REVOCATION_PATH:
            return self._repair_missing_revocation(policy, violation)

        # 4. DEAD_STATE
        elif v_type == ViolationType.DEAD_STATE:
            return self._repair_dead_state(policy, violation)

        # 5. RULE_CONFLICT
        elif v_type == ViolationType.RULE_CONFLICT:
            return self._repair_rule_conflict(policy, violation)

        # 6. UNMITIGATED_HIGH_RISK_PATH
        elif v_type == ViolationType.UNMITIGATED_HIGH_RISK_PATH:
            return self._repair_high_risk_path(policy, violation)

        # 7. UNREACHABLE_STATE
        elif v_type == ViolationType.UNREACHABLE_STATE:
            return self._repair_unreachable_state(policy, violation)

        return None

    def _repair_missing_authentication(
        self,
        policy: ZeroTrustPolicy,
        violation: PolicyViolation
    ) -> GraphSurgeryPatch:
        """
        Interposes AUTHENTICATED checkpoint state into unauthenticated bypass edge.
        Splits (START -> TARGET) into (START -> AUTHENTICATED) and (AUTHENTICATED -> TARGET).
        """
        # Find bypass rule
        target_rule = None
        if violation.rule_id:
            for r in policy.rules:
                if r.rule_id == violation.rule_id:
                    target_rule = r
                    break

        if not target_rule and violation.witness_path and len(violation.witness_path) >= 2:
            src, tgt = violation.witness_path[0], violation.witness_path[1]
            for r in policy.rules:
                if r.source == src and r.target == tgt:
                    target_rule = r
                    break

        # Fallback to direct START -> ACCESS_GRANTED if not isolated
        if not target_rule:
            for r in policy.rules:
                if r.source == "START" and r.target in ("ACCESS_GRANTED", "AUTHORIZED"):
                    target_rule = r
                    break

        if target_rule:
            rule_in = PolicyRule(
                rule_id=f"rule_synth_auth_in_{uuid.uuid4().hex[:4]}",
                source=target_rule.source,
                target="AUTHENTICATED",
                action="authenticate",
                condition="auth_method == 'mfa'",
                description="Synthesized: enforce MFA identity authentication checkpoint"
            )
            rule_out = PolicyRule(
                rule_id=f"rule_synth_auth_out_{uuid.uuid4().hex[:4]}",
                source="AUTHENTICATED",
                target=target_rule.target,
                action=target_rule.action or "grant",
                condition=target_rule.condition,
                description=f"Synthesized: proceed to {target_rule.target} after valid authentication"
            )
            return GraphSurgeryPatch(
                op_type=PatchOpType.INTERPOSE_STATE,
                target_rule_id=target_rule.rule_id,
                affected_states=[target_rule.source, "AUTHENTICATED", target_rule.target],
                description=f"Interpose AUTHENTICATED checkpoint splitting bypass edge ({target_rule.source} -> {target_rule.target})",
                violation_addressed=violation.type.value,
                rules_to_remove=[target_rule.rule_id],
                rules_to_add=[rule_in, rule_out],
                edit_distance_cost=2.0  # 1 removal + 2 additions
            )

        # Default fallback: add START -> AUTHENTICATED
        rule_add = PolicyRule(
            rule_id=f"rule_synth_auth_{uuid.uuid4().hex[:4]}",
            source="START",
            target="AUTHENTICATED",
            action="authenticate",
            condition="auth_method == 'mfa'",
            description="Synthesized: add required identity authentication transition"
        )
        return GraphSurgeryPatch(
            op_type=PatchOpType.INJECT_TRANSITION,
            affected_states=["START", "AUTHENTICATED"],
            description="Inject missing START -> AUTHENTICATED transition",
            violation_addressed=violation.type.value,
            rules_to_add=[rule_add],
            edit_distance_cost=1.0
        )

    def _repair_missing_device_verification(
        self,
        policy: ZeroTrustPolicy,
        violation: PolicyViolation
    ) -> GraphSurgeryPatch:
        """
        Interposes DEVICE_VERIFIED checkpoint between AUTHENTICATED and ACCESS_GRANTED.
        """
        # Find transition leading to ACCESS_GRANTED
        target_rule = None
        if violation.rule_id:
            for r in policy.rules:
                if r.rule_id == violation.rule_id:
                    target_rule = r
                    break

        if not target_rule:
            for r in policy.rules:
                if r.target == "ACCESS_GRANTED":
                    target_rule = r
                    break

        if target_rule and target_rule.source != "DEVICE_VERIFIED":
            rule_dev_in = PolicyRule(
                rule_id=f"rule_synth_dev_in_{uuid.uuid4().hex[:4]}",
                source=target_rule.source,
                target="DEVICE_VERIFIED",
                action="verify_device_posture",
                condition="device_health == 'compliant'",
                description="Synthesized: validate endpoint posture and hardware integrity"
            )
            rule_dev_out = PolicyRule(
                rule_id=f"rule_synth_dev_out_{uuid.uuid4().hex[:4]}",
                source="DEVICE_VERIFIED",
                target=target_rule.target,
                action=target_rule.action or "grant",
                condition=target_rule.condition,
                description=f"Synthesized: grant access from verified compliant device"
            )
            return GraphSurgeryPatch(
                op_type=PatchOpType.INTERPOSE_STATE,
                target_rule_id=target_rule.rule_id,
                affected_states=[target_rule.source, "DEVICE_VERIFIED", target_rule.target],
                description=f"Interpose DEVICE_VERIFIED checkpoint between {target_rule.source} and {target_rule.target}",
                violation_addressed=violation.type.value,
                rules_to_remove=[target_rule.rule_id],
                rules_to_add=[rule_dev_in, rule_dev_out],
                edit_distance_cost=2.0
            )

        # Fallback: add DEVICE_VERIFIED condition or state
        rule_add = PolicyRule(
            rule_id=f"rule_synth_dev_{uuid.uuid4().hex[:4]}",
            source="AUTHENTICATED",
            target="DEVICE_VERIFIED",
            action="verify_device",
            condition="device_health == 'compliant'",
            description="Synthesized: explicit device posture check"
        )
        return GraphSurgeryPatch(
            op_type=PatchOpType.INJECT_TRANSITION,
            affected_states=["AUTHENTICATED", "DEVICE_VERIFIED"],
            description="Inject DEVICE_VERIFIED validation transition",
            violation_addressed=violation.type.value,
            rules_to_add=[rule_add],
            edit_distance_cost=1.0
        )

    def _repair_missing_revocation(
        self,
        policy: ZeroTrustPolicy,
        violation: PolicyViolation
    ) -> GraphSurgeryPatch:
        """
        Injects lifecycle termination transitions from ACCESS_GRANTED to SESSION_EXPIRED and REVOKED.
        """
        grant_state = violation.state or "ACCESS_GRANTED"
        r1 = PolicyRule(
            rule_id=f"rule_synth_timeout_{uuid.uuid4().hex[:4]}",
            source=grant_state,
            target="SESSION_EXPIRED",
            action="session_timeout",
            condition="session_age > max_duration",
            description="Synthesized: bounded session revocation on inactivity or lease expiry"
        )
        r2 = PolicyRule(
            rule_id=f"rule_synth_revoke_{uuid.uuid4().hex[:4]}",
            source=grant_state,
            target="REVOKED",
            action="admin_revoke",
            description="Synthesized: administrative immediate access revocation path"
        )
        return GraphSurgeryPatch(
            op_type=PatchOpType.ADD_REVOCATION_PATH,
            affected_states=[grant_state, "SESSION_EXPIRED", "REVOKED"],
            description=f"Inject forward revocation and expiration transitions from {grant_state}",
            violation_addressed=violation.type.value,
            rules_to_add=[r1, r2],
            edit_distance_cost=1.5
        )

    def _repair_dead_state(
        self,
        policy: ZeroTrustPolicy,
        violation: PolicyViolation
    ) -> GraphSurgeryPatch:
        """
        Connects an intermediate dead state to terminal ACCESS_DENIED sink state.
        """
        dead_state = violation.state
        if not dead_state and violation.witness_path:
            dead_state = violation.witness_path[-1]
        dead_state = dead_state or "UNKNOWN_DEAD_STATE"

        r_exit = PolicyRule(
            rule_id=f"rule_synth_exit_{uuid.uuid4().hex[:4]}",
            source=dead_state,
            target="ACCESS_DENIED",
            action="deny_unresolved",
            description=f"Synthesized: eliminate trap state {dead_state} with forward denial sink"
        )
        return GraphSurgeryPatch(
            op_type=PatchOpType.CONNECT_DEAD_STATE,
            affected_states=[dead_state, "ACCESS_DENIED"],
            description=f"Connect dead trap state {dead_state} to ACCESS_DENIED sink",
            violation_addressed=violation.type.value,
            rules_to_add=[r_exit],
            edit_distance_cost=1.0
        )

    def _repair_rule_conflict(
        self,
        policy: ZeroTrustPolicy,
        violation: PolicyViolation
    ) -> GraphSurgeryPatch:
        """
        Differentiates non-deterministic or conflicting rules with disambiguated guard predicates.
        """
        target_rule_id = violation.rule_id
        target_rule = None
        for r in policy.rules:
            if r.rule_id == target_rule_id:
                target_rule = r
                break

        if target_rule:
            modified_rule = copy.deepcopy(target_rule)
            cond = modified_rule.condition or ""
            if "role == 'admin'" not in cond and "role != 'admin'" not in cond:
                modified_rule.condition = f"{cond} AND role == 'admin'".strip(" AND ")
            modified_rule.description = "Synthesized: disambiguate rule conflict with specialized claim guard"

            return GraphSurgeryPatch(
                op_type=PatchOpType.TIGHTEN_GUARD,
                target_rule_id=target_rule.rule_id,
                affected_states=[target_rule.source, target_rule.target],
                description=f"Tighten guard condition on rule {target_rule.rule_id} to eliminate nondeterministic conflict",
                violation_addressed=violation.type.value,
                rules_to_modify=[modified_rule],
                edit_distance_cost=0.5
            )

        return GraphSurgeryPatch(
            op_type=PatchOpType.RESOLVE_CONFLICT,
            description="Disambiguate conflicting transition rules",
            violation_addressed=violation.type.value,
            edit_distance_cost=0.5
        )

    def _repair_high_risk_path(
        self,
        policy: ZeroTrustPolicy,
        violation: PolicyViolation
    ) -> GraphSurgeryPatch:
        """
        Interposes STEP_UP_AUTH checkpoint into high-risk access trajectory (NIST SP 800-207 Tenet 6).
        """
        target_rule = None
        if violation.witness_path and len(violation.witness_path) >= 2:
            src, tgt = violation.witness_path[-2], violation.witness_path[-1]
            for r in policy.rules:
                if r.source == src and r.target == tgt:
                    target_rule = r
                    break

        if not target_rule:
            for r in policy.rules:
                if r.target == "ACCESS_GRANTED":
                    target_rule = r
                    break

        if target_rule:
            r_step_in = PolicyRule(
                rule_id=f"rule_synth_stepup_in_{uuid.uuid4().hex[:4]}",
                source=target_rule.source,
                target="STEP_UP_AUTH",
                action="challenge_stepup",
                condition="risk_score > 0.50",
                risk_weight=-0.50,
                description="Synthesized: trigger step-up MFA challenge for elevated risk session"
            )
            r_step_out = PolicyRule(
                rule_id=f"rule_synth_stepup_out_{uuid.uuid4().hex[:4]}",
                source="STEP_UP_AUTH",
                target=target_rule.target,
                action="grant_after_challenge",
                description="Synthesized: complete grant following verified step-up authentication"
            )
            return GraphSurgeryPatch(
                op_type=PatchOpType.INTERPOSE_STATE,
                target_rule_id=target_rule.rule_id,
                affected_states=[target_rule.source, "STEP_UP_AUTH", target_rule.target],
                description=f"Interpose STEP_UP_AUTH checkpoint mitigating high-risk trajectory before {target_rule.target}",
                violation_addressed=violation.type.value,
                rules_to_remove=[target_rule.rule_id],
                rules_to_add=[r_step_in, r_step_out],
                edit_distance_cost=2.0
            )

        return GraphSurgeryPatch(
            op_type=PatchOpType.INJECT_TRANSITION,
            affected_states=["AUTHENTICATED", "STEP_UP_AUTH"],
            description="Inject STEP_UP_AUTH challenge transition",
            violation_addressed=violation.type.value,
            rules_to_add=[
                PolicyRule(
                    source="AUTHENTICATED",
                    target="STEP_UP_AUTH",
                    action="mfa_challenge",
                    risk_weight=-0.50
                )
            ],
            edit_distance_cost=1.0
        )

    def _repair_unreachable_state(
        self,
        policy: ZeroTrustPolicy,
        violation: PolicyViolation
    ) -> GraphSurgeryPatch:
        """
        Connects an orphaned state from START or removes dangling rules.
        """
        unreachable = violation.state or "ORPHANED_STATE"
        r_connect = PolicyRule(
            rule_id=f"rule_synth_reach_{uuid.uuid4().hex[:4]}",
            source="AUTHENTICATED",
            target=unreachable,
            action="enter_substate",
            description=f"Synthesized: link orphaned state {unreachable} from primary workflow"
        )
        return GraphSurgeryPatch(
            op_type=PatchOpType.INJECT_TRANSITION,
            affected_states=["AUTHENTICATED", unreachable],
            description=f"Connect unreachable state {unreachable} from AUTHENTICATED",
            violation_addressed=violation.type.value,
            rules_to_add=[r_connect],
            edit_distance_cost=1.0
        )

    def _apply_patches_to_policy(
        self,
        original_policy: ZeroTrustPolicy,
        patches: List[GraphSurgeryPatch]
    ) -> Tuple[ZeroTrustPolicy, List[Dict[str, Any]]]:
        """
        Applies a list of GraphSurgeryPatch objects to a copy of original policy.
        Computes RFC 6902-compliant patch document.
        """
        repaired_dict = copy.deepcopy(original_policy.model_dump())
        rfc6902_ops: List[Dict[str, Any]] = []

        all_rules_to_remove: Set[str] = set()
        all_rules_to_add: List[PolicyRule] = []
        all_rules_to_modify: Dict[str, PolicyRule] = {}

        for p in patches:
            for r_id in p.rules_to_remove:
                all_rules_to_remove.add(r_id)
            for r in p.rules_to_add:
                all_rules_to_add.append(r)
            for r in p.rules_to_modify:
                all_rules_to_modify[r.rule_id] = r

        # 1. Process Rule Removals
        if all_rules_to_remove:
            original_rules = repaired_dict.get("rules", [])
            # Iterate in reverse index order so index shifts do not corrupt subsequent removals
            indices_to_remove = [
                idx for idx, r in enumerate(original_rules)
                if r.get("rule_id") in all_rules_to_remove
            ]
            indices_to_remove.sort(reverse=True)
            for idx in indices_to_remove:
                rfc6902_ops.append({
                    "op": "remove",
                    "path": f"/rules/{idx}"
                })
                original_rules.pop(idx)

        # 2. Process Rule Modifications
        if all_rules_to_modify:
            for idx, r in enumerate(repaired_dict.get("rules", [])):
                r_id = r.get("rule_id")
                if r_id in all_rules_to_modify:
                    mod_rule = all_rules_to_modify[r_id]
                    repaired_dict["rules"][idx] = mod_rule.model_dump()
                    rfc6902_ops.append({
                        "op": "replace",
                        "path": f"/rules/{idx}",
                        "value": mod_rule.model_dump()
                    })

        # 3. Process Rule Additions
        for new_rule in all_rules_to_add:
            rule_dump = new_rule.model_dump()
            repaired_dict.setdefault("rules", []).append(rule_dump)
            rfc6902_ops.append({
                "op": "add",
                "path": "/rules/-",
                "value": rule_dump
            })

        # Update policy metadata
        repaired_dict["policy_id"] = f"{original_policy.policy_id}_repaired"
        repaired_dict["policy_name"] = f"{original_policy.policy_name} (Synthesized Repair)"
        repaired_dict["description"] = (
            f"Formally synthesized Zero Trust policy repair. "
            f"Applied {len(patches)} minimal graph surgery patches."
        )

        repaired_policy = ZeroTrustPolicy(**repaired_dict)
        return repaired_policy, rfc6902_ops
