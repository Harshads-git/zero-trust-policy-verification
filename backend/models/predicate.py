"""
First-Order Guard Predicate Algebra & Context Attributes
AxiomTrust Formal Verification Platform

Defines first-order guard predicates (Atomic and Compound Boolean combinations),
runtime access context attributes (IP CIDRs, continuous risk scores, temporal windows, device health),
and evaluation semantics for Zero Trust access control workflows.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Union
import ipaddress
import re
from datetime import datetime, time as dt_time
from pydantic import BaseModel, Field


class ComparisonOp(str, Enum):
    EQ = "=="
    NEQ = "!="
    LT = "<"
    LTE = "<="
    GT = ">"
    GTE = ">="
    IN = "IN"
    NOT_IN = "NOT_IN"
    CIDR_MATCH = "CIDR_MATCH"
    BETWEEN = "BETWEEN"


class LogicalOp(str, Enum):
    AND = "AND"
    OR = "OR"
    NOT = "NOT"


class AccessContext(BaseModel):
    """
    Runtime context for an access request evaluated against Zero Trust guard predicates.
    Captures NIST SP 800-207 dynamic contextual attributes:
    - Subject context (roles, clearance, authentication claims)
    - Device context (posture, health, verification state)
    - Environmental context (client IP, geolocation, time of access, continuous risk score)
    """
    client_ip: Optional[str] = Field(default=None, description="Client IPv4 or IPv6 address")
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Continuous risk metric [0.0, 1.0]")
    time_of_day: Optional[str] = Field(default=None, description="Time of request formatted as HH:MM")
    device_health: Optional[str] = Field(default=None, description="Endpoint posture (e.g., COMPLIANT, QUARANTINED)")
    device_verified: Optional[bool] = Field(default=None, description="Cryptographic endpoint trust verified")
    mfa_verified: Optional[bool] = Field(default=None, description="Multi-factor authentication validated")
    user_roles: List[str] = Field(default_factory=list, description="Assigned enterprise RBAC/ABAC roles")
    clearance_level: Optional[int] = Field(default=None, description="Numerical security clearance tier [1..5]")
    custom_attributes: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary ABAC claims and tags")

    def get_attribute(self, name: str) -> Any:
        """Retrieves an attribute from standard fields or custom attributes dictionary."""
        if hasattr(self, name) and getattr(self, name) is not None:
            return getattr(self, name)
        return self.custom_attributes.get(name)


class AtomicPredicate(BaseModel):
    """
    First-order atomic comparison: (attribute <operator> value).
    Examples:
    - risk_score <= 0.35
    - client_ip CIDR_MATCH 10.0.0.0/16
    - time_of_day BETWEEN ["09:00", "18:00"]
    - user_roles IN ["admin", "security_auditor"]
    """
    attribute: str = Field(..., description="Context attribute name to inspect")
    operator: ComparisonOp = Field(..., description="Comparison operator")
    value: Any = Field(..., description="Target threshold, set, or subnet value")

    def evaluate(self, context: AccessContext) -> bool:
        """Evaluates this atomic predicate against the provided AccessContext."""
        actual_val = context.get_attribute(self.attribute)
        if actual_val is None:
            # If the context is missing the required attribute, evaluation fails closed
            return False

        op = self.operator
        target_val = self.value

        # 1. CIDR Subnet Matching (IPv4 / IPv6)
        if op == ComparisonOp.CIDR_MATCH:
            try:
                ip_obj = ipaddress.ip_address(str(actual_val))
                net_obj = ipaddress.ip_network(str(target_val), strict=False)
                return ip_obj in net_obj
            except (ValueError, TypeError):
                return False

        # 2. Time-of-day Range (BETWEEN ["HH:MM", "HH:MM"])
        if op == ComparisonOp.BETWEEN:
            if isinstance(target_val, (list, tuple)) and len(target_val) == 2:
                lower, upper = target_val
                return self._evaluate_between(actual_val, lower, upper)
            return False

        # 3. Set Membership (IN, NOT_IN)
        if op == ComparisonOp.IN:
            if isinstance(actual_val, list):
                # Any intersection
                return any(v in target_val for v in actual_val)
            return actual_val in target_val

        if op == ComparisonOp.NOT_IN:
            if isinstance(actual_val, list):
                return not any(v in target_val for v in actual_val)
            return actual_val not in target_val

        # 4. Numeric and Boolean comparisons
        try:
            if op == ComparisonOp.EQ:
                return actual_val == target_val
            if op == ComparisonOp.NEQ:
                return actual_val != target_val
            if op == ComparisonOp.LT:
                return float(actual_val) < float(target_val)
            if op == ComparisonOp.LTE:
                return float(actual_val) <= float(target_val)
            if op == ComparisonOp.GT:
                return float(actual_val) > float(target_val)
            if op == ComparisonOp.GTE:
                return float(actual_val) >= float(target_val)
        except (ValueError, TypeError):
            return False

        return False

    def _evaluate_between(self, actual: Any, lower: Any, upper: Any) -> bool:
        """Handles numeric and time string interval comparisons."""
        # Check time format HH:MM
        if isinstance(actual, str) and re.match(r"^\d{2}:\d{2}$", actual):
            try:
                t_act = datetime.strptime(actual, "%H:%M").time()
                t_low = datetime.strptime(str(lower), "%H:%M").time()
                t_upp = datetime.strptime(str(upper), "%H:%M").time()
                if t_low <= t_upp:
                    return t_low <= t_act <= t_upp
                else:
                    # Overnight interval (e.g., 22:00 to 06:00)
                    return t_act >= t_low or t_act <= t_upp
            except ValueError:
                return False

        try:
            return float(lower) <= float(actual) <= float(upper)
        except (ValueError, TypeError):
            return False

    def to_expression(self) -> str:
        """Renders canonical human/mathematical notation."""
        if self.operator == ComparisonOp.CIDR_MATCH:
            return f"{self.attribute} \u2208 {self.value}"
        if self.operator == ComparisonOp.IN:
            return f"{self.attribute} \u2208 {self.value}"
        if self.operator == ComparisonOp.BETWEEN:
            return f"{self.attribute} \u2208 [{self.value[0]}, {self.value[1]}]"
        return f"{self.attribute} {self.operator.value} {self.value}"


class CompoundPredicate(BaseModel):
    """
    Boolean algebra composition (AND, OR, NOT) over child predicates.
    Supports arbitrarily nested tree structures for complex zero trust policies.
    """
    logical_op: LogicalOp = Field(..., description="Boolean operator (AND, OR, NOT)")
    predicates: List[Union['CompoundPredicate', AtomicPredicate]] = Field(
        ..., min_length=1, description="List of child predicates"
    )

    def evaluate(self, context: AccessContext) -> bool:
        """Recursively evaluates the compound boolean formula."""
        if self.logical_op == LogicalOp.NOT:
            # NOT operates on first child predicate
            if not self.predicates:
                return True
            return not self.predicates[0].evaluate(context)

        if self.logical_op == LogicalOp.AND:
            return all(p.evaluate(context) for p in self.predicates)

        if self.logical_op == LogicalOp.OR:
            return any(p.evaluate(context) for p in self.predicates)

        return False

    def to_expression(self) -> str:
        """Renders parenthesized mathematical logic expression."""
        if self.logical_op == LogicalOp.NOT:
            inner = self.predicates[0].to_expression() if self.predicates else "true"
            return f"\u00AC({inner})"
        op_str = f" {self.logical_op.value} "
        inner = op_str.join(p.to_expression() for p in self.predicates)
        return f"({inner})"


# Enable self-referencing recursive model
CompoundPredicate.model_rebuild()


def parse_predicate(obj: Union[str, Dict[str, Any], AtomicPredicate, CompoundPredicate, None]) -> Optional[Union[AtomicPredicate, CompoundPredicate]]:
    """
    Utility parser that accepts raw strings, serialized JSON dictionaries,
    or existing Predicate instances and returns a validated Atomic or Compound Predicate.
    Supports backward compatibility for simple condition flags like 'device_verified'.
    """
    if obj is None:
        return None

    if isinstance(obj, (AtomicPredicate, CompoundPredicate)):
        return obj

    if isinstance(obj, dict):
        if "logical_op" in obj:
            return CompoundPredicate.model_validate(obj)
        if "attribute" in obj:
            return AtomicPredicate.model_validate(obj)
        return None

    if isinstance(obj, str):
        trimmed = obj.strip()
        if not trimmed:
            return None

        # Check for standard comparison patterns: <attr> <op> <val>
        pattern = r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*(==|!=|<=|>=|<|>|CIDR_MATCH|IN)\s*(.+)$"
        match = re.match(pattern, trimmed)
        if match:
            attr, op, raw_val = match.groups()
            raw_val = raw_val.strip()

            # Parse primitive value
            val: Any = raw_val
            if raw_val.lower() == "true":
                val = True
            elif raw_val.lower() == "false":
                val = False
            elif re.match(r"^-?\d+$", raw_val):
                val = int(raw_val)
            elif re.match(r"^-?\d+\.\d+$", raw_val):
                val = float(raw_val)
            elif (raw_val.startswith('"') and raw_val.endswith('"')) or (raw_val.startswith("'") and raw_val.endswith("'")):
                val = raw_val[1:-1]
            elif raw_val.startswith("[") and raw_val.endswith("]"):
                import json
                try:
                    val = json.loads(raw_val)
                except Exception:
                    val = [x.strip().strip("'\"") for x in raw_val[1:-1].split(",") if x.strip()]

            return AtomicPredicate(
                attribute=attr,
                operator=ComparisonOp(op),
                value=val
            )

        # Fallback for simple boolean flag names (e.g. "device_verified", "mfa_verified")
        return AtomicPredicate(
            attribute=trimmed,
            operator=ComparisonOp.EQ,
            value=True
        )

    return None
