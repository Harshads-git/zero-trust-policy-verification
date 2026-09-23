"""
Automata & Graph Traversal Unit Tests
Tests Theory of Computation FSM construction, reachability, shortest paths, and dead states.
"""

from backend.core.fsm import FiniteStateMachine
from backend.models.policy import PolicyRule
from backend.core.graph_algorithms import (
    compute_reachable_states,
    compute_unreachable_states,
    find_shortest_path,
    find_all_simple_paths,
    detect_dead_states,
    detect_conflicts_and_nondeterminism,
)


def test_fsm_initialization():
    fsm = FiniteStateMachine(initial_state="START", terminal_states=["ACCESS_GRANTED", "REVOKED"])
    assert fsm.q0 == "START"
    assert "ACCESS_GRANTED" in fsm.F
    assert "REVOKED" in fsm.F
    assert "START" in fsm.Q


def test_fsm_add_transitions():
    fsm = FiniteStateMachine()
    r1 = PolicyRule(source="START", target="AUTH", action="login", condition="creds")
    r2 = PolicyRule(source="AUTH", target="ACCESS_GRANTED", action="allow")

    t1 = fsm.add_transition(r1)
    t2 = fsm.add_transition(r2)

    assert len(fsm.transitions) == 2
    assert "AUTH" in fsm.Q
    assert len(fsm.get_outgoing("START")) == 1
    assert fsm.get_outgoing("START")[0].target == "AUTH"
    assert fsm.get_incoming("ACCESS_GRANTED")[0].source == "AUTH"


def test_reachability_bfs():
    fsm = FiniteStateMachine()
    fsm.add_transition(PolicyRule(source="START", target="A", action="step1"))
    fsm.add_transition(PolicyRule(source="A", target="B", action="step2"))
    fsm.add_state("ORPHAN_C")

    reachable = compute_reachable_states(fsm, "START")
    assert reachable == {"START", "A", "B"}

    unreachable = compute_unreachable_states(fsm)
    assert "ORPHAN_C" in unreachable


def test_shortest_witness_path():
    fsm = FiniteStateMachine()
    fsm.add_transition(PolicyRule(source="START", target="A", action="t1"))
    fsm.add_transition(PolicyRule(source="A", target="B", action="t2"))
    fsm.add_transition(PolicyRule(source="B", target="GRANTED", action="t3"))
    fsm.add_transition(PolicyRule(source="START", target="GRANTED", action="backdoor"))

    path = find_shortest_path(fsm, "START", "GRANTED")
    assert path == ["START", "GRANTED"]


def test_dead_state_detection():
    fsm = FiniteStateMachine(terminal_states=["TERMINAL_END"])
    fsm.add_transition(PolicyRule(source="START", target="HEALTHY_PATH", action="ok"))
    fsm.add_transition(PolicyRule(source="HEALTHY_PATH", target="TERMINAL_END", action="finish"))
    fsm.add_transition(PolicyRule(source="START", target="TRAP_STATE", action="divert"))

    dead = detect_dead_states(fsm)
    assert "TRAP_STATE" in dead
    assert "HEALTHY_PATH" not in dead


def test_rule_conflict_detection():
    fsm = FiniteStateMachine()
    fsm.add_transition(PolicyRule(source="AUTH", target="TARGET_A", action="eval", condition="cond_1"))
    fsm.add_transition(PolicyRule(source="AUTH", target="TARGET_B", action="eval", condition="cond_1"))

    conflicts = detect_conflicts_and_nondeterminism(fsm)
    assert len(conflicts) == 1
    assert conflicts[0]["source"] == "AUTH"
    assert set(conflicts[0]["targets"]) == {"TARGET_A", "TARGET_B"}
