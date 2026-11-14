"""
Microsoft Z3 SMT Constraint Solver Integration
AxiomTrust Formal Verification Platform

Translates first-order guard predicates into First-Order Logic (SMT-LIB2) assertions
and solves for path satisfiability, conflicting constraints, and dead transition detection
using the Microsoft Z3 Theorem Prover.
"""

import time
import re
import ipaddress
from typing import Dict, Any, List, Optional, Union, Tuple
from pydantic import BaseModel, Field

import z3

from backend.models.predicate import (
    ComparisonOp,
    LogicalOp,
    AtomicPredicate,
    CompoundPredicate,
    parse_predicate,
)
from backend.models.policy import ZeroTrustPolicy, PolicyRule


class SMTResult(BaseModel):
    """Result of an SMT satisfiability check on a set of guard predicates."""
    is_satisfiable: bool = Field(..., description="True if a satisfying context valuation exists (SAT)")
    status: str = Field(..., description="'SAT', 'UNSAT', or 'UNKNOWN'")
    model: Optional[Dict[str, Any]] = Field(default=None, description="Concrete witness model satisfying all guards")
    unsat_core: Optional[List[str]] = Field(default=None, description="List of contradictory predicate expressions")
    solve_time_ms: float = Field(default=0.0, description="Solver execution time in milliseconds")


class SMTPathResult(BaseModel):
    """Result of path-condition satisfiability along a multi-hop execution trajectory."""
    trajectory: List[str] = Field(..., description="Sequence of states in path, e.g. [START, AUTHENTICATED, ...]")
    rule_ids: List[str] = Field(..., description="Identifiers of transitions along trajectory")
    is_satisfiable: bool = Field(..., description="True if combined path condition /\\ guards is SAT")
    status: str = Field(..., description="'SAT' or 'UNSAT'")
    model: Optional[Dict[str, Any]] = Field(default=None, description="Witness input context triggering path")
    conflicting_guards: Optional[List[str]] = Field(default=None, description="Expressions of conflicting guards")
    solve_time_ms: float = Field(default=0.0)


class Z3ConstraintSolver:
    """
    Translates and solves AxiomTrust First-Order Predicates using the Microsoft Z3 Theorem Prover.
    Supports:
    - Real arithmetic (continuous risk metrics, latency)
    - Integer arithmetic & bitwise ranges (clearance levels, IPv4 subnets, time minutes)
    - String theory (user roles, identity claims, resource names)
    - Boolean propositional logic (MFA verification, device compliance flags)
    """

    def __init__(self):
        self._symbols: Dict[str, Any] = {}

    def _get_or_create_symbol(self, attribute: str, val_hint: Any) -> Any:
        """Retrieves or creates the appropriate Z3 typed variable based on value hint."""
        if attribute in self._symbols:
            return self._symbols[attribute]

        # Type inference based on attribute name and value hint
        if isinstance(val_hint, bool) or attribute.endswith("_verified") or attribute.endswith("_checked"):
            sym = z3.Bool(attribute)
        elif isinstance(val_hint, float) or attribute in ("risk_score", "anomaly_score", "confidence"):
            sym = z3.Real(attribute)
        elif isinstance(val_hint, int) or attribute in ("clearance_level", "port", "attempts", "session_seconds"):
            sym = z3.Int(attribute)
        elif attribute == "client_ip":
            # Model IP address as a 32-bit integer for exact CIDR range checks
            sym = z3.Int(attribute)
        elif attribute == "time_of_day":
            # Model time of day as minutes from midnight [0..1439]
            sym = z3.Int(attribute)
        elif isinstance(val_hint, str):
            sym = z3.String(attribute)
        else:
            sym = z3.Real(attribute)

        self._symbols[attribute] = sym
        return sym

    def translate_atomic(self, pred: AtomicPredicate) -> Optional[z3.BoolRef]:
        """Translates an AtomicPredicate into a Z3 BoolRef expression."""
        attr = pred.attribute
        op = pred.operator
        val = pred.value
        sym = self._get_or_create_symbol(attr, val)

        # 1. CIDR Matching: [net_start, net_end] integer bounds
        if op == ComparisonOp.CIDR_MATCH:
            try:
                net = ipaddress.ip_network(str(val), strict=False)
                start = int(net.network_address)
                end = int(net.broadcast_address)
                return z3.And(sym >= start, sym <= end)
            except (ValueError, TypeError):
                return z3.BoolVal(False)

        # 2. Time-of-day BETWEEN
        if attr == "time_of_day" and op == ComparisonOp.BETWEEN and isinstance(val, (list, tuple)) and len(val) == 2:
            try:
                def to_minutes(t_str: str) -> int:
                    h, m = map(int, str(t_str).split(":"))
                    return h * 60 + m

                low_min = to_minutes(val[0])
                upp_min = to_minutes(val[1])
                if low_min <= upp_min:
                    return z3.And(sym >= low_min, sym <= upp_min)
                else:
                    # Overnight interval: e.g. 22:00 to 06:00
                    return z3.Or(sym >= low_min, sym <= upp_min)
            except Exception:
                return z3.BoolVal(False)

        # 3. Numeric BETWEEN
        if op == ComparisonOp.BETWEEN and isinstance(val, (list, tuple)) and len(val) == 2:
            try:
                low = float(val[0])
                upp = float(val[1])
                return z3.And(sym >= low, sym <= upp)
            except Exception:
                return z3.BoolVal(False)

        # 4. Set Membership (IN / NOT_IN)
        if op == ComparisonOp.IN and isinstance(val, (list, tuple, set)):
            clauses = []
            for item in val:
                if isinstance(sym, z3.SeqRef):  # Z3 String
                    clauses.append(sym == z3.StringVal(str(item)))
                else:
                    clauses.append(sym == item)
            return z3.Or(*clauses) if clauses else z3.BoolVal(False)

        if op == ComparisonOp.NOT_IN and isinstance(val, (list, tuple, set)):
            clauses = []
            for item in val:
                if isinstance(sym, z3.SeqRef):
                    clauses.append(sym != z3.StringVal(str(item)))
                else:
                    clauses.append(sym != item)
            return z3.And(*clauses) if clauses else z3.BoolVal(True)

        # 5. String Comparisons
        if isinstance(sym, z3.SeqRef):
            target = z3.StringVal(str(val))
            if op == ComparisonOp.EQ:
                return sym == target
            if op == ComparisonOp.NEQ:
                return sym != target
            return z3.BoolVal(False)

        # 6. Boolean / Numeric Comparisons
        try:
            target = val
            if isinstance(sym, z3.ArithRef):
                target = float(val) if isinstance(sym, z3.RatNumRef) or "." in str(val) else int(val)

            if op == ComparisonOp.EQ:
                return sym == target
            if op == ComparisonOp.NEQ:
                return sym != target
            if op == ComparisonOp.LT:
                return sym < target
            if op == ComparisonOp.LTE:
                return sym <= target
            if op == ComparisonOp.GT:
                return sym > target
            if op == ComparisonOp.GTE:
                return sym >= target
        except Exception:
            return z3.BoolVal(False)

        return z3.BoolVal(False)

    def translate_compound(self, pred: CompoundPredicate) -> Optional[z3.BoolRef]:
        """Recursively translates a CompoundPredicate into a Z3 BoolRef."""
        child_refs = []
        for child in pred.predicates:
            translated = self.translate(child)
            if translated is not None:
                child_refs.append(translated)

        if not child_refs:
            return z3.BoolVal(True)

        if pred.logical_op == LogicalOp.NOT:
            return z3.Not(child_refs[0])
        if pred.logical_op == LogicalOp.AND:
            return z3.And(*child_refs)
        if pred.logical_op == LogicalOp.OR:
            return z3.Or(*child_refs)

        return z3.BoolVal(True)

    def translate(self, obj: Union[AtomicPredicate, CompoundPredicate, str, None]) -> Optional[z3.BoolRef]:
        """Translates any supported predicate type or string representation into a Z3 expression."""
        if obj is None:
            return None

        if isinstance(obj, str):
            parsed = parse_predicate(obj)
            if parsed is None:
                return None
            return self.translate(parsed)

        if isinstance(obj, AtomicPredicate):
            return self.translate_atomic(obj)

        if isinstance(obj, CompoundPredicate):
            return self.translate_compound(obj)

        return None

    def check_satisfiability(
        self,
        predicates: List[Union[AtomicPredicate, CompoundPredicate, str]],
        timeout_ms: int = 2000
    ) -> SMTResult:
        """
        Tests whether a collection of guard predicates is simultaneously satisfiable (SAT).
        If SAT, extracts a concrete witness model.
        If UNSAT, identifies contradictory constraints.
        """
        start = time.perf_counter()
        solver = z3.Solver()
        solver.set("timeout", timeout_ms)

        # Domain boundary axioms for standard security attributes
        if "risk_score" in self._symbols:
            r = self._symbols["risk_score"]
            solver.add(r >= 0.0, r <= 1.0)
        if "clearance_level" in self._symbols:
            c = self._symbols["clearance_level"]
            solver.add(c >= 1, c <= 5)
        if "time_of_day" in self._symbols:
            t = self._symbols["time_of_day"]
            solver.add(t >= 0, t < 1440)
        if "client_ip" in self._symbols:
            ip_sym = self._symbols["client_ip"]
            solver.add(ip_sym >= 0, ip_sym <= 0xFFFFFFFF)

        # Add translated predicates
        expr_strs: List[str] = []
        for p in predicates:
            z3_expr = self.translate(p)
            if z3_expr is not None:
                solver.add(z3_expr)
                expr_strs.append(p.to_expression() if hasattr(p, "to_expression") else str(p))

        status = solver.check()
        elapsed = (time.perf_counter() - start) * 1000.0

        if status == z3.sat:
            m = solver.model()
            extracted_model = self._extract_readable_model(m)
            return SMTResult(
                is_satisfiable=True,
                status="SAT",
                model=extracted_model,
                solve_time_ms=round(elapsed, 3)
            )
        elif status == z3.unsat:
            return SMTResult(
                is_satisfiable=False,
                status="UNSAT",
                unsat_core=expr_strs,
                solve_time_ms=round(elapsed, 3)
            )
        else:
            return SMTResult(
                is_satisfiable=False,
                status="UNKNOWN",
                solve_time_ms=round(elapsed, 3)
            )

    def check_path_satisfiability(self, trajectory: List[str], path_rules: List[PolicyRule]) -> SMTPathResult:
        """
        Evaluates the path condition along a multi-hop execution trajectory:
        Phi(trajectory) = /\\_{i=1}^k guard(e_i)
        Proves whether an access grant path can actually be traversed.
        """
        t0 = time.perf_counter()
        guards = []
        rule_ids = []
        guard_descriptions = []

        for r in path_rules:
            g = r.get_guard_predicate()
            if g is not None:
                guards.append(g)
                guard_descriptions.append(g.to_expression())
            rule_ids.append(r.rule_id)

        smt_res = self.check_satisfiability(guards)
        dur = (time.perf_counter() - t0) * 1000.0

        return SMTPathResult(
            trajectory=trajectory,
            rule_ids=rule_ids,
            is_satisfiable=smt_res.is_satisfiable,
            status=smt_res.status,
            model=smt_res.model,
            conflicting_guards=guard_descriptions if not smt_res.is_satisfiable else None,
            solve_time_ms=round(dur, 3)
        )

    def detect_dead_transitions(self, policy: ZeroTrustPolicy) -> List[Dict[str, Any]]:
        """
        Scans all rules in the policy to detect individual transitions whose guards
        are mathematically impossible / contradictory (e.g. risk < 0.2 AND risk > 0.5).
        """
        dead_transitions = []
        for rule in policy.rules:
            guard = rule.get_guard_predicate()
            if guard is not None:
                res = self.check_satisfiability([guard])
                if not res.is_satisfiable:
                    dead_transitions.append({
                        "rule_id": rule.rule_id,
                        "source": rule.source,
                        "target": rule.target,
                        "action": rule.action,
                        "guard": guard.to_expression(),
                        "reason": "Guard is mathematically unsatisfiable (self-contradictory)"
                    })
        return dead_transitions

    def _extract_readable_model(self, model: z3.ModelRef) -> Dict[str, Any]:
        """Translates Z3 low-level model values into human/JSON readable valuations."""
        result: Dict[str, Any] = {}
        for d in model.decls():
            name = d.name()
            val = model[d]
            if z3.is_bool(val):
                result[name] = bool(val)
            elif z3.is_int(val):
                int_val = val.as_long()
                if name == "client_ip":
                    try:
                        result[name] = str(ipaddress.ip_address(int_val))
                    except Exception:
                        result[name] = int_val
                elif name == "time_of_day":
                    h = int_val // 60
                    m = int_val % 60
                    result[name] = f"{h:02d}:{m:02d}"
                else:
                    result[name] = int_val
            elif z3.is_real(val):
                # Convert rational / real fraction to float
                num = val.numerator_as_long()
                den = val.denominator_as_long()
                result[name] = round(float(num) / float(den), 4)
            elif z3.is_string(val):
                result[name] = val.as_string()
            else:
                result[name] = str(val)
        return result
