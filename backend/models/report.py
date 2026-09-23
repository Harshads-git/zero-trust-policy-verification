"""
Verification Report Models
Defines violation categories, severities, and the structured verification output.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class ViolationSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ViolationType(str, Enum):
    # Zero Trust Architectural Invariants
    MISSING_AUTHENTICATION = "MISSING_AUTHENTICATION"
    MISSING_DEVICE_VERIFICATION = "MISSING_DEVICE_VERIFICATION"
    MISSING_AUTHORIZATION = "MISSING_AUTHORIZATION"
    UNAUTHORIZED_TRANSITION = "UNAUTHORIZED_TRANSITION"
    NO_REVOCATION_PATH = "NO_REVOCATION_PATH"
    UNSAFE_TERMINAL_STATE = "UNSAFE_TERMINAL_STATE"
    PRIVILEGE_BYPASS = "PRIVILEGE_BYPASS"

    # Automata & Theory of Computation Structural Invariants
    UNREACHABLE_STATE = "UNREACHABLE_STATE"
    DEAD_STATE = "DEAD_STATE"
    RULE_CONFLICT = "RULE_CONFLICT"
    NON_DETERMINISTIC_TRANSITION = "NON_DETERMINISTIC_TRANSITION"
    MALFORMED_POLICY = "MALFORMED_POLICY"


class PolicyViolation(BaseModel):
    type: ViolationType
    severity: ViolationSeverity
    rule_id: Optional[str] = None
    state: Optional[str] = None
    source_state: Optional[str] = None
    target_state: Optional[str] = None
    message: str
    explanation: str
    witness_path: Optional[List[str]] = Field(
        default=None,
        description="Counterexample state path demonstrating the violation"
    )
    remediation: Optional[str] = Field(
        default=None,
        description="Actionable guidance to remediate the vulnerability"
    )


class VerificationReport(BaseModel):
    policy_id: str
    policy_name: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    valid: bool
    total_states: int
    total_transitions: int
    violations_count: int
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    violations: List[PolicyViolation] = Field(default_factory=list)
    reachable_states: List[str] = Field(default_factory=list)
    unreachable_states: List[str] = Field(default_factory=list)
    dead_states: List[str] = Field(default_factory=list)
    verification_time_ms: float = 0.0
    formal_invariants_checked: Dict[str, bool] = Field(default_factory=dict)
    fsm_graph_summary: Dict[str, Any] = Field(default_factory=dict)
