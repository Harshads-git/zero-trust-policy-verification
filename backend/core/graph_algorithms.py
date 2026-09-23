r"""
Theory of Computation Core: Graph Algorithms for Formal Verification
Implements:
- Breadth-First Search (BFS) Reachability Analysis
- Depth-First Search (DFS) Path Finding & Cycle Detection
- Unreachable State Identification: Q \ Reachable(q0)
- Dead State / Non-Terminating Trap Detection
- Shortest Witness Counterexample Extraction
- Rule Conflict & Non-Determinism Detection
"""

from collections import deque
from typing import Set, Dict, List, Optional, Tuple
from backend.core.fsm import FiniteStateMachine, Transition


def compute_reachable_states(fsm: FiniteStateMachine, start_state: Optional[str] = None) -> Set[str]:
    """
    Computes all states reachable from start_state (defaults to q0) using BFS.
    Time Complexity: O(|V| + |E|)
    """
    root = start_state or fsm.q0
    if root not in fsm.Q:
        return set()

    visited: Set[str] = {root}
    queue: deque[str] = deque([root])

    while queue:
        curr = queue.popleft()
        for trans in fsm.get_outgoing(curr):
            if trans.target not in visited:
                visited.add(trans.target)
                queue.append(trans.target)

    return visited


def compute_unreachable_states(fsm: FiniteStateMachine) -> Set[str]:
    r"""
    Identifies unreachable states in the FSM: Q \ Reachable(q0).
    Any state that cannot be reached from q0 represents dead policy logic or orphan rules.
    """
    reachable = compute_reachable_states(fsm, fsm.q0)
    return fsm.Q - reachable


def find_shortest_path(fsm: FiniteStateMachine, source: str, target: str) -> Optional[List[str]]:
    """
    Finds the shortest sequence of states from source to target using BFS.
    Used for extracting minimal counterexample witness paths.
    """
    if source not in fsm.Q or target not in fsm.Q:
        return None
    if source == target:
        return [source]

    queue: deque[Tuple[str, List[str]]] = deque([(source, [source])])
    visited: Set[str] = {source}

    while queue:
        curr, path = queue.popleft()
        for trans in fsm.get_outgoing(curr):
            nxt = trans.target
            if nxt == target:
                return path + [nxt]
            if nxt not in visited:
                visited.add(nxt)
                queue.append((nxt, path + [nxt]))

    return None


def find_all_simple_paths(
    fsm: FiniteStateMachine, source: str, target: str, max_depth: int = 15
) -> List[List[str]]:
    """
    Finds all cycle-free paths from source to target up to max_depth.
    Essential for exhaustive invariant checking (e.g. verifying that EVERY path to
    ACCESS_GRANTED contains DEVICE_VERIFIED).
    """
    results: List[List[str]] = []

    def dfs(current: str, current_path: List[str]):
        if len(current_path) > max_depth:
            return
        if current == target:
            results.append(list(current_path))
            return

        for trans in fsm.get_outgoing(current):
            nxt = trans.target
            if nxt not in current_path:  # Avoid cycle in path
                current_path.append(nxt)
                dfs(nxt, current_path)
                current_path.pop()

    if source in fsm.Q and target in fsm.Q:
        dfs(source, [source])

    return results


def detect_dead_states(fsm: FiniteStateMachine) -> Set[str]:
    r"""
    Identifies dead/trap states:
    Non-terminal states (q in Q \ F) from which NO terminal state in F can ever be reached.
    If a user reaches such a state, the session hangs in an un-evaluable limbo.
    """
    # Reverse reachability: Find all states that can reach ANY state in F
    can_reach_terminal: Set[str] = set()
    queue: deque[str] = deque([t for t in fsm.F if t in fsm.Q])
    visited: Set[str] = set(queue)

    while queue:
        curr = queue.popleft()
        can_reach_terminal.add(curr)
        for trans in fsm.get_incoming(curr):
            if trans.source not in visited:
                visited.add(trans.source)
                queue.append(trans.source)

    # Dead states are reachable states that cannot reach any terminal state, excluding terminal states themselves
    reachable_from_start = compute_reachable_states(fsm, fsm.q0)
    dead_states = {
        state for state in reachable_from_start
        if state not in fsm.F and state not in can_reach_terminal
    }
    return dead_states


def detect_conflicts_and_nondeterminism(fsm: FiniteStateMachine) -> List[Dict]:
    """
    Detects non-deterministic or conflicting rules:
    Multiple transitions from the same source state with identical actions and conditions
    leading to different target states.
    """
    conflicts = []
    for state in fsm.Q:
        outgoing = fsm.get_outgoing(state)
        seen: Dict[Tuple[str, Optional[str]], List[Transition]] = {}
        for t in outgoing:
            key = (t.action.strip().lower(), (t.condition or "").strip().lower())
            seen.setdefault(key, []).append(t)

        for (action, condition), transitions in seen.items():
            if len(transitions) > 1:
                targets = {t.target for t in transitions}
                if len(targets) > 1:
                    conflicts.append({
                        "source": state,
                        "action": action,
                        "condition": condition,
                        "targets": list(targets),
                        "rules": [t.rule_id for t in transitions]
                    })

    return conflicts
