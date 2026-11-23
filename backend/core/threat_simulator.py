"""
Red-Team Attack Graph & Lateral Movement Simulation Engine
AxiomTrust Formal Verification Platform

Models adversarial threat actor capabilities across enterprise Zero Trust finite state machines:
- Attacker Lateral Movement Graph Traversal
- Reachable Closure & Blast Radius Scoring (0.0 - 1.0)
- Exploit Difficulty & Step-by-Step Attack Trajectories
- Graph Choke Point & Articulation Bottleneck Identification
- Actionable Zero Trust Containment & Microsegmentation Advisories
"""

import time
import uuid
from typing import List, Dict, Any, Optional, Set

from backend.models.policy import ZeroTrustPolicy
from backend.models.threat import (
    ThreatSimulationRequest,
    ThreatSimulationResult,
    AttackExploitPath,
    AttackExploitStep,
    ExploitDifficulty,
    ChokePointAnalysis
)
from backend.core.fsm import FiniteStateMachine
from backend.core.graph_algorithms import find_all_simple_paths


class AttackGraphSimulator:
    """
    Simulates adversarial lateral movement through an access policy FSM.
    Identifies reachable attack surfaces, evaluates crown jewel vulnerabilities,
    and isolates critical single-points-of-defense (choke points).
    """

    def simulate(
        self,
        policy: ZeroTrustPolicy,
        request: ThreatSimulationRequest
    ) -> ThreatSimulationResult:
        """
        Executes red-team adversarial simulation from the initial compromised node.
        """
        start_time = time.perf_counter()

        # Build FSM representation
        fsm = FiniteStateMachine(
            states=policy.get_all_states(),
            initial_state=policy.initial_state,
            terminal_states=policy.terminal_states
        )
        for r in policy.rules:
            fsm.add_transition(r.source, r.target, r.action, r.condition)

        compromised = request.compromised_node
        if compromised not in fsm.Q:
            raise ValueError(
                f"Compromised node '{compromised}' does not exist in policy state space: {sorted(list(fsm.Q))}"
            )

        # 1. Attacker Reachability Closure via BFS
        reachable_states = self._compute_attacker_reachability(fsm, compromised)
        total_states = len(fsm.Q)

        blast_pct = round((len(reachable_states) / max(1, total_states)) * 100.0, 1)
        blast_score = round(len(reachable_states) / max(1, total_states), 3)

        # 2. Crown Jewels Evaluation
        crown_jewels = request.crown_jewels or ["ACCESS_GRANTED"]
        compromised_jewels = [cj for cj in crown_jewels if cj in reachable_states and cj != compromised]

        # 3. Exploit Path Enumeration
        exploit_paths: List[AttackExploitPath] = []
        for cj in compromised_jewels:
            paths = find_all_simple_paths(fsm, compromised, cj, max_depth=request.max_exploit_depth)
            for path in paths:
                exploit_path = self._construct_exploit_path(policy, path, cj)
                exploit_paths.append(exploit_path)

        # Sort exploit paths by shortest hop count, then highest cumulative risk
        exploit_paths.sort(key=lambda p: (p.hop_count, -p.cumulative_risk))

        # 4. Severity Assessment
        severity = self._evaluate_severity(compromised_jewels, blast_pct, exploit_paths)

        # 5. Graph Choke Point Analysis
        choke_points = self._compute_choke_points(exploit_paths, compromised, compromised_jewels)

        # 6. Zero Trust Containment Recommendations
        recommendations = self._generate_containment_recommendations(
            compromised,
            blast_pct,
            compromised_jewels,
            exploit_paths,
            choke_points
        )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return ThreatSimulationResult(
            simulation_id=f"sim_{uuid.uuid4().hex[:8]}",
            policy_name=policy.policy_name,
            compromised_node=compromised,
            total_policy_states=total_states,
            attacker_reachable_states=sorted(list(reachable_states)),
            blast_radius_percentage=blast_pct,
            blast_radius_score=blast_score,
            blast_radius_severity=severity,
            compromised_crown_jewels=compromised_jewels,
            exploit_paths=exploit_paths,
            choke_points=choke_points,
            containment_recommendations=recommendations,
            simulation_time_ms=round(elapsed_ms, 3)
        )

    def _compute_attacker_reachability(self, fsm: FiniteStateMachine, start_node: str) -> Set[str]:
        """Calculates the complete forward reachability closure from start_node."""
        visited: Set[str] = {start_node}
        queue = [start_node]

        while queue:
            curr = queue.pop(0)
            for trans in fsm.get_outgoing(curr):
                nxt = trans.target
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append(nxt)

        return visited

    def _construct_exploit_path(
        self,
        policy: ZeroTrustPolicy,
        path: List[str],
        target_cj: str
    ) -> AttackExploitPath:
        """Constructs an annotated exploit trajectory with step difficulties and risk weights."""
        steps: List[AttackExploitStep] = []
        cumulative_risk = 0.0
        max_difficulty = ExploitDifficulty.TRIVIAL
        required_bypasses: List[str] = []

        difficulty_ranks = {
            ExploitDifficulty.TRIVIAL: 1,
            ExploitDifficulty.LOW: 2,
            ExploitDifficulty.MEDIUM: 3,
            ExploitDifficulty.HIGH: 4,
            ExploitDifficulty.CRITICAL_BARRIER: 5
        }

        # Check for architectural Zero Trust bypasses
        if "DEVICE_VERIFIED" not in path and target_cj == "ACCESS_GRANTED":
            required_bypasses.append("missing_device_inspection")
        if "AUTHENTICATED" not in path and target_cj == "ACCESS_GRANTED":
            required_bypasses.append("unauthenticated_access_jump")

        for i in range(len(path) - 1):
            src, tgt = path[i], path[i + 1]

            # Find matching rule
            matched_rule = None
            for r in policy.rules:
                if r.source == src and r.target == tgt:
                    matched_rule = r
                    break

            action = matched_rule.action if matched_rule else "traverse"
            condition = matched_rule.condition if matched_rule else None

            step_diff, step_risk = self._evaluate_step_difficulty(action, condition)
            cumulative_risk += step_risk

            if difficulty_ranks[step_diff] > difficulty_ranks[max_difficulty]:
                max_difficulty = step_diff

            steps.append(AttackExploitStep(
                source=src,
                target=tgt,
                action=action,
                condition=condition,
                step_difficulty=step_diff,
                description=f"Adversary traverses ({src} -> {tgt}) via action '{action}'"
            ))

        return AttackExploitPath(
            target_crown_jewel=target_cj,
            path=path,
            steps=steps,
            hop_count=len(path) - 1,
            overall_difficulty=max_difficulty,
            cumulative_risk=round(cumulative_risk, 2),
            required_bypasses=required_bypasses
        )

    def _evaluate_step_difficulty(
        self,
        action: str,
        condition: Optional[str]
    ) -> tuple[ExploitDifficulty, float]:
        """Classifies edge traversal difficulty and incremental adversary risk."""
        if not condition or condition.strip() == "":
            return ExploitDifficulty.TRIVIAL, 10.0

        cond_lower = condition.lower()
        if "mfa" in cond_lower or "biometric" in cond_lower:
            return ExploitDifficulty.CRITICAL_BARRIER, 35.0
        elif "device" in cond_lower or "compliant" in cond_lower or "health" in cond_lower:
            return ExploitDifficulty.HIGH, 25.0
        elif "role" in cond_lower or "group" in cond_lower:
            return ExploitDifficulty.MEDIUM, 15.0
        else:
            return ExploitDifficulty.LOW, 12.0

    def _evaluate_severity(
        self,
        compromised_jewels: List[str],
        blast_pct: float,
        exploit_paths: List[AttackExploitPath]
    ) -> str:
        """Determines overall threat severity based on reachability and path barrier height."""
        if compromised_jewels:
            # If any path to a crown jewel is TRIVIAL or LOW difficulty, it's CRITICAL
            has_easy_path = any(
                p.overall_difficulty in (ExploitDifficulty.TRIVIAL, ExploitDifficulty.LOW)
                for p in exploit_paths
            )
            return "CRITICAL" if has_easy_path else "HIGH"

        if blast_pct >= 50.0:
            return "HIGH"
        elif blast_pct >= 20.0:
            return "MEDIUM"
        else:
            return "LOW"

    def _compute_choke_points(
        self,
        exploit_paths: List[AttackExploitPath],
        compromised_node: str,
        crown_jewels: List[str]
    ) -> List[ChokePointAnalysis]:
        """
        Computes graph betweenness / articulation cut-sets on exploit trajectories.
        Identifies intermediate nodes whose defense or severance isolates crown jewels.
        """
        if not exploit_paths:
            return []

        total_paths = len(exploit_paths)
        cj_set = set(crown_jewels)

        # Count occurrences of intermediate nodes
        node_counts: Dict[str, int] = {}
        for ep in exploit_paths:
            # Only consider intermediate nodes (exclude origin compromise and terminal crown jewel)
            intermediate_nodes = set(ep.path[1:-1])
            for node in intermediate_nodes:
                if node != compromised_node and node not in cj_set:
                    node_counts[node] = node_counts.get(node, 0) + 1

        choke_points: List[ChokePointAnalysis] = []
        for node, count in node_counts.items():
            ratio = round(count / total_paths, 3)
            is_single_point = (count == total_paths)

            if is_single_point:
                strategy = f"Critical Choke Point: Enforce mandatory step-up authentication or isolate '{node}' to sever 100% of exploit trajectories."
            else:
                strategy = f"Secondary Choke Point: Hardening '{node}' intercepts {count}/{total_paths} ({ratio * 100:.1f}%) of adversarial exploit paths."

            choke_points.append(ChokePointAnalysis(
                node=node,
                interception_ratio=ratio,
                paths_intercepted=count,
                total_exploit_paths=total_paths,
                is_critical_single_point_of_defense=is_single_point,
                defense_strategy=strategy
            ))

        # Sort descending by interception ratio, then alphabetical
        choke_points.sort(key=lambda cp: (-cp.interception_ratio, cp.node))
        return choke_points

    def _generate_containment_recommendations(
        self,
        compromised_node: str,
        blast_pct: float,
        compromised_jewels: List[str],
        exploit_paths: List[AttackExploitPath],
        choke_points: List[ChokePointAnalysis]
    ) -> List[str]:
        """Generates actionable, prescriptive Zero Trust security advisories."""
        recs = []

        # 1. Primary Compromise Containment
        recs.append(
            f"Immediate Containment: Invalidate active tokens, terminate sessions, and quarantine credentials mapped to state '{compromised_node}'."
        )

        # 2. Critical Choke Point Defense
        critical_cps = [cp for cp in choke_points if cp.is_critical_single_point_of_defense]
        if critical_cps:
            cp_names = ", ".join(f"'{cp.node}'" for cp in critical_cps)
            recs.append(
                f"Single-Point-of-Defense: Enforce zero-trust policy enforcement checkpoints (PEP) at {cp_names}. "
                f"Severing these nodes eliminates 100% of adversarial trajectories to crown jewels."
            )
        elif choke_points:
            best_cp = choke_points[0]
            recs.append(
                f"Defense-in-Depth: Prioritize hardening node '{best_cp.node}', which disrupts {best_cp.interception_ratio * 100:.1f}% of exploit paths."
            )

        # 3. Crown Jewel Protection
        if compromised_jewels:
            jewels_str = ", ".join(f"'{cj}'" for cj in compromised_jewels)
            min_hops = min(ep.hop_count for ep in exploit_paths)
            recs.append(
                f"Crown Jewel Alert: High-value assets ({jewels_str}) are reachable within {min_hops} hop(s). "
                f"Apply microsegmentation to decouple target assets from the compromised perimeter."
            )

        # 4. Blast Radius Reduction
        if blast_pct >= 50.0:
            recs.append(
                f"Lateral Movement Warning: Adversary can access {blast_pct}% of the policy state space. "
                f"Introduce compartmentalized authorization zones to reduce the perimeter blast radius."
            )

        return recs
