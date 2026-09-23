"""
Theory of Computation Core: Finite State Machine (FSM) Automaton Model
Represents the formal 5-tuple: M = (Q, Sigma, delta, q0, F)
where:
  Q: Set of all access workflow states
  Sigma: Input alphabet of authentication and authorization events/actions
  delta: Transition function mapping (source, action, condition) -> target
  q0: Initial start state (e.g., START)
  F: Set of terminal / accepting states (e.g., ACCESS_GRANTED, ACCESS_DENIED, REVOKED)
"""

from typing import Set, Dict, List, Optional, Tuple, NamedTuple
from backend.models.policy import ZeroTrustPolicy, PolicyRule


class Transition(NamedTuple):
    rule_id: str
    source: str
    target: str
    action: str
    condition: Optional[str] = None
    description: Optional[str] = None


class FiniteStateMachine:
    """
    Formal Automaton representation M = (Q, Sigma, delta, q0, F)
    """

    def __init__(self, initial_state: str = "START", terminal_states: Optional[List[str]] = None):
        self.q0: str = initial_state
        self.F: Set[str] = set(terminal_states) if terminal_states else {
            "ACCESS_GRANTED", "ACCESS_DENIED", "REVOKED", "SESSION_EXPIRED"
        }
        self.Q: Set[str] = {self.q0} | self.F
        self.Sigma: Set[str] = set()
        
        # delta: adjacency mapping from state to list of outgoing transitions
        self.transitions: List[Transition] = []
        self._adj: Dict[str, List[Transition]] = {}
        self._rev_adj: Dict[str, List[Transition]] = {}

    def add_state(self, state: str, is_terminal: bool = False) -> None:
        """Adds a state q in Q."""
        self.Q.add(state)
        if is_terminal:
            self.F.add(state)
        if state not in self._adj:
            self._adj[state] = []
        if state not in self._rev_adj:
            self._rev_adj[state] = []

    def add_transition(self, rule: PolicyRule) -> Transition:
        """Adds transition delta(source, action, condition) -> target."""
        self.add_state(rule.source)
        self.add_state(rule.target)
        self.Sigma.add(rule.action)

        trans = Transition(
            rule_id=rule.rule_id,
            source=rule.source,
            target=rule.target,
            action=rule.action,
            condition=rule.condition,
            description=rule.description
        )
        self.transitions.append(trans)
        self._adj.setdefault(rule.source, []).append(trans)
        self._rev_adj.setdefault(rule.target, []).append(trans)
        return trans

    @classmethod
    def from_policy(cls, policy: ZeroTrustPolicy) -> "FiniteStateMachine":
        """Instantiates an FSM from a user-defined ZeroTrustPolicy specification."""
        fsm = cls(initial_state=policy.initial_state, terminal_states=policy.terminal_states)
        for state in policy.get_all_states():
            fsm.add_state(state, is_terminal=(state in fsm.F))
        for rule in policy.rules:
            fsm.add_transition(rule)
        return fsm

    def get_outgoing(self, state: str) -> List[Transition]:
        """Returns all transitions delta(state, *)."""
        return self._adj.get(state, [])

    def get_incoming(self, state: str) -> List[Transition]:
        """Returns all transitions leading to state."""
        return self._rev_adj.get(state, [])

    def get_neighbors(self, state: str) -> List[str]:
        """Returns target states directly reachable in one step from state."""
        return [t.target for t in self.get_outgoing(state)]

    def to_cytoscape_elements(self) -> List[Dict]:
        """Exports graph structure formatted for Cytoscape.js visualizer."""
        elements = []
        for state in sorted(self.Q):
            classes = []
            if state == self.q0:
                classes.append("start-state")
            if state in self.F:
                classes.append("terminal-state")
            if "DENIED" in state or "REVOKED" in state:
                classes.append("denied-state")
            elif "GRANTED" in state:
                classes.append("granted-state")

            elements.append({
                "data": {
                    "id": state,
                    "label": state,
                    "is_start": state == self.q0,
                    "is_terminal": state in self.F
                },
                "classes": " ".join(classes)
            })

        for t in self.transitions:
            label = t.action
            if t.condition:
                label += f" [{t.condition}]"
            elements.append({
                "data": {
                    "id": f"{t.rule_id}",
                    "source": t.source,
                    "target": t.target,
                    "label": label,
                    "action": t.action,
                    "condition": t.condition or "",
                    "rule_id": t.rule_id
                }
            })
        return elements
