"""
Red-Team Threat Simulation & Lateral Movement Data Models
AxiomTrust Formal Verification Platform

Defines schemas for adversarial lateral movement modeling:
- Initial Compromised Nodes
- Attacker Capabilities & Exploit Trajectories
- Blast Radius Metrics & Severity Ratings
- Critical Choke Points & Containment Recommendations
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from backend.models.policy import ZeroTrustPolicy


class AttackerCapability(str, Enum):
    STOLEN_CREDENTIALS = "STOLEN_CREDENTIALS"
    UNPATCHED_CVE = "UNPATCHED_CVE"
    COMPROMISED_ENDPOINT = "COMPROMISED_ENDPOINT"
    SESSION_HIJACK = "SESSION_HIJACK"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"


class ExploitDifficulty(str, Enum):
    TRIVIAL = "TRIVIAL"        # No guard / open role
    LOW = "LOW"                # Basic claim condition
    MEDIUM = "MEDIUM"          # Multi-attribute or role constraint
    HIGH = "HIGH"              # Device posture / compliance required
    CRITICAL_BARRIER = "CRITICAL_BARRIER"  # MFA / biometric step-up required


class ThreatSimulationRequest(BaseModel):
    """Request payload for red-team lateral movement simulation."""
    policy: Optional[ZeroTrustPolicy] = Field(default=None, description="Optional inline policy object")
    compromised_node: str = Field(..., description="Initial node/state compromised by the adversary")
    crown_jewels: List[str] = Field(
        default=["ACCESS_GRANTED"],
        description="High-value target assets / states to evaluate reachability for"
    )
    attacker_capabilities: List[str] = Field(
        default=["STOLEN_CREDENTIALS", "LATERAL_MOVEMENT"],
        description="Assumed threat actor capabilities"
    )
    max_exploit_depth: int = Field(default=10, ge=1, le=25, description="Maximum hops to explore")


class AttackExploitStep(BaseModel):
    """Single hop along an adversarial exploit trajectory."""
    source: str
    target: str
    action: str
    condition: Optional[str] = None
    step_difficulty: ExploitDifficulty = ExploitDifficulty.LOW
    description: Optional[str] = None


class AttackExploitPath(BaseModel):
    """Complete lateral movement trajectory from compromised node to a crown jewel."""
    target_crown_jewel: str
    path: List[str]
    steps: List[AttackExploitStep]
    hop_count: int
    overall_difficulty: ExploitDifficulty
    cumulative_risk: float
    required_bypasses: List[str] = Field(default_factory=list)


class ChokePointAnalysis(BaseModel):
    """Identifies bottleneck nodes whose isolation or defense severs exploit trajectories."""
    node: str
    interception_ratio: float = Field(..., description="Fraction of exploit paths passing through this node (0.0 - 1.0)")
    paths_intercepted: int
    total_exploit_paths: int
    is_critical_single_point_of_defense: bool = Field(
        ...,
        description="True if ALL exploit paths to crown jewels traverse this node (100% cut)"
    )
    defense_strategy: str


class ThreatSimulationResult(BaseModel):
    """Full empirical analysis of adversarial blast radius and lateral movement."""
    simulation_id: str
    policy_name: str
    compromised_node: str
    total_policy_states: int
    attacker_reachable_states: List[str]
    blast_radius_percentage: float = Field(..., description="Percentage of policy states accessible to adversary")
    blast_radius_score: float = Field(..., description="Normalized score 0.0 - 1.0")
    blast_radius_severity: str = Field(..., description="LOW, MEDIUM, HIGH, or CRITICAL")
    compromised_crown_jewels: List[str]
    exploit_paths: List[AttackExploitPath]
    choke_points: List[ChokePointAnalysis]
    containment_recommendations: List[str]
    simulation_time_ms: float
