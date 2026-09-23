"""
Zero Trust Policy Data Models
Defines Pydantic models for Policies, Rules, Transitions, and Contexts.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import uuid


class PolicyRule(BaseModel):
    rule_id: str = Field(default_factory=lambda: f"rule_{uuid.uuid4().hex[:6]}")
    source: str = Field(..., description="Source state name, e.g. START, AUTHENTICATED")
    target: str = Field(..., description="Target state name, e.g. IDENTITY_VERIFIED")
    action: str = Field(default="transition", description="Action or event triggering transition")
    condition: Optional[str] = Field(default=None, description="Guard predicate or required claim")
    description: Optional[str] = Field(default=None, description="Human explanation of rule intent")


class PolicyMetadata(BaseModel):
    author: Optional[str] = "admin"
    target_resource: Optional[str] = "default_resource"
    allowed_roles: List[str] = Field(default_factory=lambda: ["user", "admin"])
    max_session_seconds: int = 3600
    risk_threshold: str = "LOW"
    extra: Dict[str, Any] = Field(default_factory=dict)


class ZeroTrustPolicy(BaseModel):
    policy_id: str = Field(default_factory=lambda: f"pol_{uuid.uuid4().hex[:8]}")
    policy_name: str = Field(..., min_length=2, description="Human-readable policy name")
    description: Optional[str] = Field(default="Zero Trust access control policy specification")
    version: str = Field(default="1.0.0")
    initial_state: str = Field(default="START", description="Formal start state q0")
    terminal_states: List[str] = Field(
        default_factory=lambda: ["ACCESS_GRANTED", "ACCESS_DENIED", "REVOKED", "SESSION_EXPIRED"],
        description="Designated terminal / sink states F"
    )
    rules: List[PolicyRule] = Field(..., min_length=1, description="List of transition rules delta")
    metadata: Optional[PolicyMetadata] = Field(default_factory=PolicyMetadata)

    def get_all_states(self) -> List[str]:
        """Collects distinct states mentioned across all rules, start state, and terminal states."""
        states = set()
        states.add(self.initial_state)
        for t in self.terminal_states:
            states.add(t)
        for r in self.rules:
            states.add(r.source)
            states.add(r.target)
        return sorted(list(states))
