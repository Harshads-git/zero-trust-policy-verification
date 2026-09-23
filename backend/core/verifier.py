"""
Core Policy Verification Engine
Coordinates automata model construction, formal invariant evaluations,
and structured report synthesis.
"""

import time
from typing import List, Dict
from backend.core.fsm import FiniteStateMachine
from backend.core.graph_algorithms import (
    compute_reachable_states,
    compute_unreachable_states,
    detect_dead_states,
)
from backend.core.rules import (
    BaseVerificationRule,
    UnreachableStateRule,
    DeadStateRule,
    RuleConflictRule,
    AuthenticationInvariantRule,
    DeviceTrustInvariantRule,
    AuthorizationCheckRule,
    SessionRevocationInvariantRule,
)
from backend.models.policy import ZeroTrustPolicy
from backend.models.report import VerificationReport, PolicyViolation, ViolationSeverity


class ZeroTrustVerificationEngine:
    """
    Formal Policy Verification Engine.
    Executes structural graph checks and Zero Trust security invariant validations.
    """

    def __init__(self, rules: List[BaseVerificationRule] = None):
        self.rules: List[BaseVerificationRule] = rules or [
            # Structural Automata Checks
            UnreachableStateRule(),
            DeadStateRule(),
            RuleConflictRule(),
            # Zero Trust Architectural Invariants
            AuthenticationInvariantRule(),
            DeviceTrustInvariantRule(),
            AuthorizationCheckRule(),
            SessionRevocationInvariantRule(),
        ]

    def verify(self, policy: ZeroTrustPolicy) -> VerificationReport:
        start_time = time.perf_counter()

        # Step 1: Construct the formal Finite State Machine Automaton
        fsm = FiniteStateMachine.from_policy(policy)

        # Step 2: Compute fundamental graph properties
        reachable = compute_reachable_states(fsm, fsm.q0)
        unreachable = compute_unreachable_states(fsm)
        dead = detect_dead_states(fsm)

        # Step 3: Run formal verification rules
        violations: List[PolicyViolation] = []
        rule_results: Dict[str, bool] = {}

        for rule in self.rules:
            rule_violations = rule.evaluate(fsm, policy)
            rule_results[rule.rule_name] = len(rule_violations) == 0
            violations.extend(rule_violations)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Step 4: Calculate severity distribution
        severity_breakdown: Dict[str, int] = {
            s.value: 0 for s in ViolationSeverity
        }
        for v in violations:
            severity_breakdown[v.severity.value] += 1

        # Step 5: Mark elements in graph summary for frontend highlighting
        graph_elements = fsm.to_cytoscape_elements()
        violation_states = {v.state for v in violations if v.state}
        for v in violations:
            if v.witness_path:
                violation_states.update(v.witness_path)

        for el in graph_elements:
            node_id = el.get("data", {}).get("id")
            if node_id in violation_states:
                el["classes"] = (el.get("classes", "") + " violation-node").strip()

        is_valid = len(violations) == 0

        return VerificationReport(
            policy_id=policy.policy_id,
            policy_name=policy.policy_name,
            valid=is_valid,
            total_states=len(fsm.Q),
            total_transitions=len(fsm.transitions),
            violations_count=len(violations),
            severity_breakdown=severity_breakdown,
            violations=violations,
            reachable_states=sorted(list(reachable)),
            unreachable_states=sorted(list(unreachable)),
            dead_states=sorted(list(dead)),
            verification_time_ms=round(elapsed_ms, 3),
            formal_invariants_checked=rule_results,
            fsm_graph_summary={
                "elements": graph_elements,
                "initial_state": fsm.q0,
                "terminal_states": sorted(list(fsm.F)),
            }
        )
