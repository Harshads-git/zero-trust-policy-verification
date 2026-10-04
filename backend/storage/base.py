"""
Storage Repository Interface
Abstracts persistence layer between local SQLite (development) and AWS DynamoDB (Free Tier cloud).
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from backend.models.policy import ZeroTrustPolicy
from backend.models.report import VerificationReport


class PolicyRepository(ABC):
    @abstractmethod
    def save_policy(self, policy: ZeroTrustPolicy) -> ZeroTrustPolicy:
        """Stores or updates a policy."""
        pass

    @abstractmethod
    def get_policy(self, policy_id: str) -> Optional[ZeroTrustPolicy]:
        """Retrieves a policy by ID."""
        pass

    @abstractmethod
    def list_policies(self) -> List[ZeroTrustPolicy]:
        """Lists all stored policies."""
        pass

    @abstractmethod
    def delete_policy(self, policy_id: str) -> bool:
        """Deletes a policy by ID."""
        pass

    @abstractmethod
    def save_report(self, report: VerificationReport) -> VerificationReport:
        """Saves a verification run result."""
        pass

    @abstractmethod
    def list_reports(self, limit: int = 50) -> List[VerificationReport]:
        """Retrieves past verification reports."""
        pass

    def get_reports_for_policy(self, policy_id: str, limit: int = 20) -> List[VerificationReport]:
        """Retrieves past verification reports specifically for a given policy ID."""
        return [r for r in self.list_reports(limit=100) if r.policy_id == policy_id][:limit]

    def count_policies(self) -> int:
        """Returns total count of stored policies."""
        return len(self.list_policies())

    def count_reports(self) -> int:
        """Returns total count of recorded audit reports."""
        return len(self.list_reports(limit=1000))

