"""
Base Verification Rule Interface
All formal security and automata rules implement this interface.
"""

from abc import ABC, abstractmethod
from typing import List
from backend.core.fsm import FiniteStateMachine
from backend.models.policy import ZeroTrustPolicy
from backend.models.report import PolicyViolation


class BaseVerificationRule(ABC):
    """
    Abstract interface for formal policy verification checks.
    """

    @property
    @abstractmethod
    def rule_name(self) -> str:
        """Name of the verification check."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Brief theoretical description of the property being verified."""
        pass

    @abstractmethod
    def evaluate(self, fsm: FiniteStateMachine, policy: ZeroTrustPolicy) -> List[PolicyViolation]:
        """
        Executes formal check against FSM and policy specification.
        Returns empty list if property holds; returns list of PolicyViolation objects with witness traces if violated.
        """
        pass
