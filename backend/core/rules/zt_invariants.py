"""
Zero Trust Domain Invariants (NIST SP 800-207 Principles)
Formal verification of Zero Trust security properties:
- Invariant 1: Continuous Authentication (Never Trust, Always Verify Identity)
- Invariant 2: Explicit Device Trust (Health & Posture Verification)
- Invariant 3: Least Privilege & Strict Authorization
- Invariant 4: Session Revocability & Expiration Lifecycle
- Invariant 5: Direct Privilege Escalation / Bypass Prevention
"""

from typing import List, Set
from backend.core.fsm import FiniteStateMachine
from backend.core.graph_algorithms import find_all_simple_paths, compute_reachable_states
from backend.core.rules.base_rule import BaseVerificationRule
from backend.models.policy import ZeroTrustPolicy
from backend.models.report import PolicyViolation, ViolationType, ViolationSeverity


class AuthenticationInvariantRule(BaseVerificationRule):
    @property
    def rule_name(self) -> str:
        return "ZT_AUTHENTICATION_INVARIANT"

    @property
    def description(self) -> str:
        return "Ensures that EVERY path from START to ACCESS_GRANTED verifies user identity."

    def evaluate(self, fsm: FiniteStateMachine, policy: ZeroTrustPolicy) -> List[PolicyViolation]:
        violations = []
        target = "ACCESS_GRANTED"
        if target not in fsm.Q:
            return violations

        paths = find_all_simple_paths(fsm, fsm.q0, target, max_depth=12)
        valid_auth_states = {"AUTHENTICATED", "IDENTITY_VERIFIED", "MFA_VERIFIED"}

        for path in paths:
            # Check if this path intersects with any recognized authentication state
            if not any(state in valid_auth_states for state in path):
                violations.append(
                    PolicyViolation(
                        type=ViolationType.MISSING_AUTHENTICATION,
                        severity=ViolationSeverity.CRITICAL,
                        source_state=path[0],
                        target_state=target,
                        message="Access can be granted without mandatory user authentication.",
                        explanation=(
                            f"Discovered an access trajectory {path} that terminates at '{target}' "
                            f"without traversing any identity authentication state ({valid_auth_states}). "
                            f"This directly violates the foundational Zero Trust principle of 'Never Trust, Always Verify'."
                        ),
                        witness_path=path,
                        remediation=(
                            "Insert an intermediate AUTHENTICATED or IDENTITY_VERIFIED state check "
                            "prior to granting resource access."
                        )
                    )
                )
                # One counterexample is sufficient to falsify the safety property
                break

        return violations


class DeviceTrustInvariantRule(BaseVerificationRule):
    @property
    def rule_name(self) -> str:
        return "ZT_DEVICE_TRUST_INVARIANT"

    @property
    def description(self) -> str:
        return "Ensures that device health/posture is formally validated before access is granted."

    def evaluate(self, fsm: FiniteStateMachine, policy: ZeroTrustPolicy) -> List[PolicyViolation]:
        violations = []
        target = "ACCESS_GRANTED"
        if target not in fsm.Q:
            return violations

        paths = find_all_simple_paths(fsm, fsm.q0, target, max_depth=12)
        valid_device_markers = {"DEVICE_VERIFIED", "DEVICE_HEALTHY", "COMPLIANT_DEVICE"}

        for path in paths:
            # Check if state path contains device state or if rule conditions include device check
            has_device_state = any(state in valid_device_markers for state in path)
            has_device_condition = False

            # Check transitions along the path for device validation conditions
            for i in range(len(path) - 1):
                s, t = path[i], path[i + 1]
                for trans in fsm.get_outgoing(s):
                    if trans.target == t and trans.condition:
                        cond_lower = trans.condition.lower()
                        if "device" in cond_lower or "posture" in cond_lower or "endpoint" in cond_lower:
                            has_device_condition = True
                            break

            if not (has_device_state or has_device_condition):
                violations.append(
                    PolicyViolation(
                        type=ViolationType.MISSING_DEVICE_VERIFICATION,
                        severity=ViolationSeverity.HIGH,
                        target_state=target,
                        message="Access can reach ACCESS_GRANTED without validating device trust posture.",
                        explanation=(
                            f"The trajectory {path} allows an identity to receive '{target}' without inspecting "
                            f"endpoint compliance or device health. In modern cloud zero-trust perimeters, "
                            f"unmanaged or compromised devices represent an attack vector."
                        ),
                        witness_path=path,
                        remediation=(
                            "Introduce a DEVICE_VERIFIED state requirement or add a 'device_verified' "
                            "predicate before transitioning to AUTHORIZED or ACCESS_GRANTED."
                        )
                    )
                )
                break

        return violations


class AuthorizationCheckRule(BaseVerificationRule):
    @property
    def rule_name(self) -> str:
        return "ZT_AUTHORIZATION_INSPECTION"

    @property
    def description(self) -> str:
        return "Ensures that resource permission evaluation occurs before access grant."

    def evaluate(self, fsm: FiniteStateMachine, policy: ZeroTrustPolicy) -> List[PolicyViolation]:
        violations = []
        target = "ACCESS_GRANTED"
        if target not in fsm.Q:
            return violations

        incoming = fsm.get_incoming(target)
        for trans in incoming:
            # Entering ACCESS_GRANTED from START or UNAUTHENTICATED without authorization check
            if trans.source in {"START", "UNAUTHENTICATED"}:
                violations.append(
                    PolicyViolation(
                        type=ViolationType.PRIVILEGE_BYPASS,
                        severity=ViolationSeverity.CRITICAL,
                        rule_id=trans.rule_id,
                        source_state=trans.source,
                        target_state=target,
                        message=f"Direct transition from '{trans.source}' to '{target}' detected.",
                        explanation=(
                            f"Rule '{trans.rule_id}' directly transitions an unverified subject "
                            f"from '{trans.source}' into '{target}'. This constitutes a critical authorization bypass."
                        ),
                        witness_path=[trans.source, target],
                        remediation=(
                            "Remove this direct transition. Access must flow through identity verification, "
                            "device posture check, and authorization evaluation."
                        )
                    )
                )
            elif trans.source in {"AUTHENTICATED", "IDENTITY_VERIFIED"}:
                # Skipped AUTHORIZED state check and has no authorization condition
                has_authz_condition = trans.condition and any(
                    k in trans.condition.lower() for k in ["role", "perm", "auth", "allow", "scope"]
                )
                if not has_authz_condition:
                    violations.append(
                        PolicyViolation(
                            type=ViolationType.MISSING_AUTHORIZATION,
                            severity=ViolationSeverity.HIGH,
                            rule_id=trans.rule_id,
                            source_state=trans.source,
                            target_state=target,
                            message=f"Transition from '{trans.source}' to '{target}' skips explicit authorization.",
                            explanation=(
                                f"Authentication proves identity, not permissions. Moving directly from "
                                f"'{trans.source}' to '{target}' without an AUTHORIZED intermediate state "
                                f"or permission guard allows any authenticated user to access protected resources."
                            ),
                            witness_path=[trans.source, target],
                            remediation=(
                                "Route transitions through an 'AUTHORIZED' state or enforce resource permission checks."
                            )
                        )
                    )

        return violations


class SessionRevocationInvariantRule(BaseVerificationRule):
    @property
    def rule_name(self) -> str:
        return "ZT_SESSION_REVOCABILITY"

    @property
    def description(self) -> str:
        return "Ensures granted access sessions can always be revoked or expired (no perpetual sessions)."

    def evaluate(self, fsm: FiniteStateMachine, policy: ZeroTrustPolicy) -> List[PolicyViolation]:
        violations = []
        granted = "ACCESS_GRANTED"
        if granted not in fsm.Q:
            return violations

        # Check reachability from ACCESS_GRANTED
        reachable_from_grant = compute_reachable_states(fsm, start_state=granted)
        valid_exit_states = {"SESSION_EXPIRED", "REVOKED", "ACCESS_DENIED", "UNAUTHENTICATED"}
        has_revocation_path = any(state in reachable_from_grant for state in valid_exit_states)

        if not has_revocation_path:
            violations.append(
                PolicyViolation(
                    type=ViolationType.NO_REVOCATION_PATH,
                    severity=ViolationSeverity.HIGH,
                    state=granted,
                    message="State 'ACCESS_GRANTED' lacks any transition to session expiry or revocation.",
                    explanation=(
                        f"Zero Trust requires continuous evaluation and session termination capabilities. "
                        f"Once granted, no path exists to {sorted(list(valid_exit_states))}, creating a permanent "
                        f"zombie session that cannot be revoked upon policy change or token expiry."
                    ),
                    witness_path=[granted],
                    remediation=(
                        "Add outgoing transitions from 'ACCESS_GRANTED' to 'SESSION_EXPIRED' (on timeout) "
                        "and 'REVOKED' (on administrative revocation or anomaly detection)."
                    )
                )
            )

        return violations
