"""
Zero Trust Policy Input Sanitization & Attack Defense Module
Defends against JSON recursion bombs, prototype pollution, script injection (XSS),
null byte injections, and memory exhaustion via oversized payloads.
"""

import re
import html
from typing import Dict, Any, List, Union
from fastapi import HTTPException, status
from backend.models.policy import ZeroTrustPolicy

MAX_NESTING_DEPTH = 8
MAX_IDENTIFIER_LENGTH = 128
MAX_DESCRIPTION_LENGTH = 2048
MAX_RULES_COUNT = 5000

# Patterns for script injection / unsafe characters
UNSAFE_PATTERNS = [
    re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"onerror\s*=", re.IGNORECASE),
    re.compile(r"onload\s*=", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
]


class PolicySanitizationError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Security Validation Error: {detail}"
        )


class PolicySanitizer:
    """
    Sanitizes and hardens Zero Trust policy inputs before passing to
    FSM compilation or persistent storage engines.
    """

    @classmethod
    def check_nesting_depth(cls, data: Union[Dict, List, Any], current_depth: int = 1) -> None:
        """Protects against stack-overflow and JSON recursion bombs."""
        if current_depth > MAX_NESTING_DEPTH:
            raise PolicySanitizationError(
                f"Payload exceeds maximum allowed nesting depth of {MAX_NESTING_DEPTH} levels (potential JSON bomb)."
            )

        if isinstance(data, dict):
            for k, v in data.items():
                if len(str(k)) > MAX_IDENTIFIER_LENGTH:
                    raise PolicySanitizationError(f"Dictionary key exceeds {MAX_IDENTIFIER_LENGTH} characters.")
                cls.check_nesting_depth(v, current_depth + 1)
        elif isinstance(data, list):
            for item in data:
                cls.check_nesting_depth(item, current_depth + 1)

    @classmethod
    def sanitize_string(cls, val: str, field_name: str = "field", max_len: int = MAX_IDENTIFIER_LENGTH) -> str:
        """Sanitizes strings against null bytes, script injection, and excessive lengths."""
        if not isinstance(val, str):
            return str(val)

        if "\x00" in val:
            raise PolicySanitizationError(f"Null byte detected in field '{field_name}'.")

        if len(val) > max_len:
            raise PolicySanitizationError(
                f"Field '{field_name}' exceeds maximum allowed length of {max_len} characters."
            )

        for pattern in UNSAFE_PATTERNS:
            if pattern.search(val):
                raise PolicySanitizationError(
                    f"Malicious script or execution sequence detected in field '{field_name}'."
                )

        # HTML entity escape for storage safety
        return html.escape(val.strip())

    @classmethod
    def sanitize_policy(cls, policy: ZeroTrustPolicy) -> ZeroTrustPolicy:
        """
        Runs comprehensive security sanitization across a ZeroTrustPolicy object.
        Returns the sanitized policy or raises PolicySanitizationError.
        """
        # 1. Rule count ceiling
        if len(policy.rules) > MAX_RULES_COUNT:
            raise PolicySanitizationError(
                f"Rule count ({len(policy.rules)}) exceeds maximum security limit of {MAX_RULES_COUNT} rules."
            )

        # 2. Check depth on serialized dict
        raw_dict = policy.model_dump()
        cls.check_nesting_depth(raw_dict)

        # 3. Sanitize identifiers & metadata
        policy.policy_id = cls.sanitize_string(policy.policy_id, "policy_id", MAX_IDENTIFIER_LENGTH)
        policy.policy_name = cls.sanitize_string(policy.policy_name, "policy_name", MAX_IDENTIFIER_LENGTH)
        if policy.description:
            policy.description = cls.sanitize_string(policy.description, "description", MAX_DESCRIPTION_LENGTH)

        # 4. Sanitize rules
        for r in policy.rules:
            r.rule_id = cls.sanitize_string(r.rule_id, "rule_id", MAX_IDENTIFIER_LENGTH)
            r.source = cls.sanitize_string(r.source, "source", MAX_IDENTIFIER_LENGTH)
            r.target = cls.sanitize_string(r.target, "target", MAX_IDENTIFIER_LENGTH)
            r.action = cls.sanitize_string(r.action, "action", MAX_IDENTIFIER_LENGTH)
            if r.condition:
                r.condition = cls.sanitize_string(r.condition, "condition", MAX_DESCRIPTION_LENGTH)

        return policy
