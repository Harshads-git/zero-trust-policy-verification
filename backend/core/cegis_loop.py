"""
Counterexample-Guided Inductive Synthesis (CEGIS) Loop Engine
AxiomTrust Formal Verification Platform

Implements the iterative CEGIS loop:
    Candidate Policy P_k  --->  Verifier Oracle (FSM Model Checker)
           ^                                |
           |                                v
    Synthesizer (Graph Surgery) <--- Counterexample Traces W_k

Iterates until the candidate policy is provably compliant (W_k = ∅)
or the bounded iteration limit K_max is reached.
"""

from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
from pydantic import BaseModel, Field
import copy
import time

from backend.models.policy import ZeroTrustPolicy, PolicyRule
from backend.models.report import PolicyViolation, ViolationType, VerificationReport
from backend.core.verifier import ZeroTrustVerificationEngine
from backend.core.synthesizer import (
    PolicySynthesizer,
    GraphSurgeryPatch,
    SynthesisResult,
    PatchOpType,
    apply_rfc6902_patch
)


class CEGISStatus(str, Enum):
    CONVERGED = "CONVERGED"
    MAX_ITERATIONS_REACHED = "MAX_ITERATIONS_REACHED"
    NO_REPAIR_NEEDED = "NO_REPAIR_NEEDED"
    STAGNATED = "STAGNATED"


class CEGISIterationRecord(BaseModel):
    """Detailed telemetry and audit record for a single CEGIS iteration round."""
    iteration: int = Field(..., description="1-indexed iteration number")
    violations_before: int = Field(..., description="Number of invariant violations at start of round")
    violation_types: List[str] = Field(default_factory=list, description="Types of violations encountered")
    patches_applied: List[GraphSurgeryPatch] = Field(default_factory=list, description="Surgeries applied in this round")
    edit_distance_delta: float = Field(default=0.0, description="Graph Edit Distance incurred in this round")
    violations_after: int = Field(..., description="Violations remaining after round")
    converged_this_round: bool = Field(default=False)
    counterexample_witnesses: List[List[str]] = Field(default_factory=list, description="Witness paths discovered this round")
    iteration_latency_ms: float = Field(default=0.0, description="Round execution duration in milliseconds")


class CEGISResult(BaseModel):
    """Overall outcome of the Counterexample-Guided Inductive Synthesis loop."""
    policy_id: str
    policy_name: str
    status: CEGISStatus
    converged: bool
    initial_violations_count: int
    final_violations_count: int
    iterations_count: int
    max_iterations: int
    cumulative_edit_distance: float
    accumulated_counterexamples_count: int
    unique_counterexamples_count: int
    iteration_history: List[CEGISIterationRecord] = Field(default_factory=list)
    total_latency_ms: float = 0.0
    repaired_policy: Optional[ZeroTrustPolicy] = None
    cumulative_rfc6902_patch_document: List[Dict[str, Any]] = Field(default_factory=list)
    final_verification_report: Dict[str, Any] = Field(default_factory=dict)


class CEGISEngine:
    """
    Automated CEGIS Orchestrator.
    Executes iterative synthesis-verification cycles:
    Propose Candidate -> Verify -> Extract Counterexamples -> Accumulate -> Refine.
    """

    def __init__(
        self,
        max_iterations: int = 5,
        verifier: Optional[ZeroTrustVerificationEngine] = None,
        synthesizer: Optional[PolicySynthesizer] = None
    ):
        self.max_iterations: int = max(1, max_iterations)
        self.verifier: ZeroTrustVerificationEngine = verifier or ZeroTrustVerificationEngine()
        self.synthesizer: PolicySynthesizer = synthesizer or PolicySynthesizer()

    def run_cegis_loop(
        self,
        policy: ZeroTrustPolicy,
        max_iterations: Optional[int] = None
    ) -> CEGISResult:
        """
        Executes the iterative CEGIS loop until policy is fully verified
        or the iteration bound is exhausted.
        """
        start_time = time.perf_counter()
        k_max = max_iterations if max_iterations is not None else self.max_iterations

        # Initial Oracle Verification Check
        initial_report = self.verifier.verify(policy)
        initial_violation_count = len(initial_report.violations)

        if initial_report.valid:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return CEGISResult(
                policy_id=policy.policy_id,
                policy_name=policy.policy_name,
                status=CEGISStatus.NO_REPAIR_NEEDED,
                converged=True,
                initial_violations_count=0,
                final_violations_count=0,
                iterations_count=0,
                max_iterations=k_max,
                cumulative_edit_distance=0.0,
                accumulated_counterexamples_count=0,
                unique_counterexamples_count=0,
                iteration_history=[],
                total_latency_ms=round(elapsed, 3),
                repaired_policy=policy,
                cumulative_rfc6902_patch_document=[],
                final_verification_report={
                    "valid": True,
                    "violations_count": 0,
                    "security_posture": "COMPLIANT",
                    "risk_score": 0
                }
            )

        current_policy = copy.deepcopy(policy)
        current_report = initial_report
        cumulative_patches: List[GraphSurgeryPatch] = []
        cumulative_rfc_ops: List[Dict[str, Any]] = []
        all_witness_paths: List[List[str]] = []
        unique_witness_tuples: Set[Tuple[str, ...]] = set()
        history: List[CEGISIterationRecord] = []
        status = CEGISStatus.MAX_ITERATIONS_REACHED

        for iteration_idx in range(1, k_max + 1):
            round_start = time.perf_counter()
            violations_before = len(current_report.violations)
            violation_types = [v.type.value for v in current_report.violations]

            # Extract and accumulate counterexample witness traces
            round_witnesses: List[List[str]] = []
            for v in current_report.violations:
                if v.witness_path and len(v.witness_path) > 0:
                    round_witnesses.append(v.witness_path)
                    all_witness_paths.append(v.witness_path)
                    unique_witness_tuples.add(tuple(v.witness_path))

            # Synthesizer Phase: compute minimal graph surgery patches
            synth_result = self.synthesizer.synthesize_repair(current_policy)

            if not synth_result.patches or synth_result.total_edit_distance == 0.0:
                # No progress could be made
                round_elapsed = (time.perf_counter() - round_start) * 1000.0
                history.append(CEGISIterationRecord(
                    iteration=iteration_idx,
                    violations_before=violations_before,
                    violation_types=violation_types,
                    patches_applied=[],
                    edit_distance_delta=0.0,
                    violations_after=violations_before,
                    converged_this_round=False,
                    counterexample_witnesses=round_witnesses,
                    iteration_latency_ms=round(round_elapsed, 3)
                ))
                status = CEGISStatus.STAGNATED
                break

            # Update candidate policy and accumulate patches
            current_policy = synth_result.repaired_policy
            cumulative_patches.extend(synth_result.patches)
            cumulative_rfc_ops.extend(synth_result.rfc6902_patch_document)

            # Verifier Oracle Phase: re-verify newly synthesized candidate
            next_report = self.verifier.verify(current_policy)
            violations_after = len(next_report.violations)
            is_converged = next_report.valid

            round_elapsed = (time.perf_counter() - round_start) * 1000.0
            history.append(CEGISIterationRecord(
                iteration=iteration_idx,
                violations_before=violations_before,
                violation_types=violation_types,
                patches_applied=synth_result.patches,
                edit_distance_delta=synth_result.total_edit_distance,
                violations_after=violations_after,
                converged_this_round=is_converged,
                counterexample_witnesses=round_witnesses,
                iteration_latency_ms=round(round_elapsed, 3)
            ))

            current_report = next_report

            if is_converged:
                status = CEGISStatus.CONVERGED
                break

        total_cost = sum(r.edit_distance_delta for r in history)
        total_elapsed = (time.perf_counter() - start_time) * 1000.0

        final_summary = {
            "valid": current_report.valid,
            "violations_count": current_report.violations_count,
            "security_posture": current_report.security_posture,
            "risk_score": current_report.risk_score,
            "violations": [v.model_dump() for v in current_report.violations]
        }

        return CEGISResult(
            policy_id=policy.policy_id,
            policy_name=policy.policy_name,
            status=status,
            converged=(status == CEGISStatus.CONVERGED),
            initial_violations_count=initial_violation_count,
            final_violations_count=len(current_report.violations),
            iterations_count=len(history),
            max_iterations=k_max,
            cumulative_edit_distance=round(total_cost, 2),
            accumulated_counterexamples_count=len(all_witness_paths),
            unique_counterexamples_count=len(unique_witness_tuples),
            iteration_history=history,
            total_latency_ms=round(total_elapsed, 3),
            repaired_policy=current_policy,
            cumulative_rfc6902_patch_document=cumulative_rfc_ops,
            final_verification_report=final_summary
        )
