"""
Pytest Test Configuration & Shared Fixtures
"""

import pytest
import json
from pathlib import Path
from backend.models.policy import ZeroTrustPolicy
from backend.core.verifier import ZeroTrustVerificationEngine
from backend.storage.sqlite_store import SQLitePolicyRepository


@pytest.fixture
def policies_dir() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "policies"


@pytest.fixture
def valid_policy_employee(policies_dir) -> ZeroTrustPolicy:
    path = policies_dir / "valid" / "01_standard_employee_zt.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return ZeroTrustPolicy.model_validate(data)


@pytest.fixture
def valid_policy_admin(policies_dir) -> ZeroTrustPolicy:
    path = policies_dir / "valid" / "02_admin_privileged_access.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return ZeroTrustPolicy.model_validate(data)


@pytest.fixture
def invalid_policy_auth(policies_dir) -> ZeroTrustPolicy:
    path = policies_dir / "invalid" / "01_missing_authentication.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return ZeroTrustPolicy.model_validate(data)


@pytest.fixture
def invalid_policy_device(policies_dir) -> ZeroTrustPolicy:
    path = policies_dir / "invalid" / "02_missing_device_check.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return ZeroTrustPolicy.model_validate(data)


@pytest.fixture
def invalid_policy_unreachable(policies_dir) -> ZeroTrustPolicy:
    path = policies_dir / "invalid" / "03_unreachable_isolated_state.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return ZeroTrustPolicy.model_validate(data)


@pytest.fixture
def invalid_policy_dead_state(policies_dir) -> ZeroTrustPolicy:
    path = policies_dir / "invalid" / "04_dead_end_state.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return ZeroTrustPolicy.model_validate(data)


@pytest.fixture
def invalid_policy_conflict(policies_dir) -> ZeroTrustPolicy:
    path = policies_dir / "invalid" / "05_conflicting_ambiguous_rules.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return ZeroTrustPolicy.model_validate(data)


@pytest.fixture
def invalid_policy_no_revocation(policies_dir) -> ZeroTrustPolicy:
    path = policies_dir / "invalid" / "06_no_session_revocation.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return ZeroTrustPolicy.model_validate(data)


@pytest.fixture
def invalid_policy_bypass(policies_dir) -> ZeroTrustPolicy:
    path = policies_dir / "invalid" / "07_privilege_escalation_bypass.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return ZeroTrustPolicy.model_validate(data)


@pytest.fixture
def verifier() -> ZeroTrustVerificationEngine:
    return ZeroTrustVerificationEngine()


@pytest.fixture
def temp_repo(tmp_path) -> SQLitePolicyRepository:
    db_file = tmp_path / "test_policies.db"
    return SQLitePolicyRepository(str(db_file))
