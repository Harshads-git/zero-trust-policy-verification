"""
Security Hardening & Governance Package
Defends against payload attacks, implements rate limiting, and generates least-privilege IAM policies.
"""

from backend.security.sanitizer import (
    PolicySanitizer,
    PolicySanitizationError,
    MAX_NESTING_DEPTH,
    MAX_RULES_COUNT
)
from backend.security.iam_generator import IAMLeastPrivilegePolicyGenerator

__all__ = [
    "PolicySanitizer",
    "PolicySanitizationError",
    "MAX_NESTING_DEPTH",
    "MAX_RULES_COUNT",
    "IAMLeastPrivilegePolicyGenerator"
]
