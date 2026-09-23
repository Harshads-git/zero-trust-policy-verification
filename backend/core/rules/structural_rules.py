r"""
Structural & Automata Theory Verification Rules
Validates fundamental FSM properties:
- Unreachable State Detection: Q \ Reachable(q0)
- Dead/Sink State Trap Detection
- Determinism & Rule Ambiguity/Conflict
"""

from typing import List
from backend.core.fsm import FiniteStateMachine
from backend.core.graph_algorithms import (
    compute_unreachable_states,
    detect_dead_states,
    detect_conflicts_and_nondeterminism,
)
from backend.core.rules.base_rule import BaseVerificationRule
from backend.models.policy import ZeroTrustPolicy
from backend.models.report import PolicyViolation, ViolationType, ViolationSeverity


class UnreachableStateRule(BaseVerificationRule):
    @property
    def rule_name(self) -> str:
        return "TOC_UNREACHABLE_STATES"

    @property
    def description(self) -> str:
        return "Ensures all defined states are reachable from initial state q0 via valid transitions."

    def evaluate(self, fsm: FiniteStateMachine, policy: ZeroTrustPolicy) -> List[PolicyViolation]:
        violations = []
        unreachable = compute_unreachable_states(fsm)

        for state in sorted(list(unreachable)):
            violations.append(
                PolicyViolation(
                    type=ViolationType.UNREACHABLE_STATE,
                    severity=ViolationSeverity.MEDIUM,
                    state=state,
                    message=f"State '{state}' cannot be reached from initial state '{fsm.q0}'.",
                    explanation=(
                        f"Formal reachability analysis found no valid path from q0 ('{fsm.q0}') "
                        f"to state '{state}'. This indicates dead policy logic or orphan security rules."
                    ),
                    remediation=(
                        f"Add an inbound transition leading into '{state}', or remove the orphan state "
                        f"and its associated rules if no longer required."
                    )
                )
            )
        return violations


class DeadStateRule(BaseVerificationRule):
    @property
    def rule_name(self) -> str:
        return "TOC_DEAD_STATES"

    @property
    def description(self) -> str:
        return "Ensures that all non-terminal states can eventually reach a designated terminal state F."

    def evaluate(self, fsm: FiniteStateMachine, policy: ZeroTrustPolicy) -> List[PolicyViolation]:
        violations = []
        dead_states = detect_dead_states(fsm)

        for state in sorted(list(dead_states)):
            violations.append(
                PolicyViolation(
                    type=ViolationType.DEAD_STATE,
                    severity=ViolationSeverity.HIGH,
                    state=state,
                    message=f"State '{state}' is a dead-end state with no path to terminal completion.",
                    explanation=(
                        f"State '{state}' is reachable from START but has no reachable path to any "
                        f"terminal state {sorted(list(fsm.F))}. An access workflow reaching this state "
                        f"will become permanently stuck without granting, denying, or revoking access."
                    ),
                    remediation=(
                        f"Add a failure/fallback transition from '{state}' to 'ACCESS_DENIED' or 'REVOKED' "
                        f"to ensure the workflow always reaches an explicit termination."
                    )
                )
            )
        return violations


class RuleConflictRule(BaseVerificationRule):
    @property
    def rule_name(self) -> str:
        return "TOC_RULE_DETERMINISM"

    @property
    def description(self) -> str:
        return "Detects conflicting or non-deterministic transitions from the same source state."

    def evaluate(self, fsm: FiniteStateMachine, policy: ZeroTrustPolicy) -> List[PolicyViolation]:
        violations = []
        conflicts = detect_conflicts_and_nondeterminism(fsm)

        for conflict in conflicts:
            violations.append(
                PolicyViolation(
                    type=ViolationType.RULE_CONFLICT,
                    severity=ViolationSeverity.HIGH,
                    source_state=conflict["source"],
                    message=(
                        f"Conflicting rules found for state '{conflict['source']}' on action "
                        f"'{conflict['action']}' condition '{conflict['condition']}'."
                    ),
                    explanation=(
                        f"From state '{conflict['source']}', the identical trigger leads to divergent targets "
                        f"{conflict['targets']}. In a Zero Trust environment, non-deterministic transitions "
                        f"introduce unpredictable security posture and policy race conditions."
                    ),
                    witness_path=[conflict["source"]],
                    remediation=(
                        f"Disambiguate rules {conflict['rules']} by specifying mutually exclusive conditions "
                        f"or consolidating redundant rules."
                    )
                )
            )
        return violations
