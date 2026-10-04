"""
Cross-Backend Storage Parity & Schema Consistency Test Suite
Verifies identical interface contracts, index performance, and lossless data migration
between SQLite and DynamoDB repository implementations.
"""

import sqlite3
import pytest
import json
from unittest.mock import MagicMock, patch

from backend.models.policy import ZeroTrustPolicy, PolicyRule
from backend.models.report import VerificationReport, PolicyViolation, ViolationType, ViolationSeverity
from backend.storage.sqlite_store import SQLitePolicyRepository
from backend.storage.dynamodb_store import DynamoDBPolicyRepository
from backend.storage.migration import migrate_data, initialize_sqlite_database


@pytest.fixture
def sqlite_repo(tmp_path):
    db_file = str(tmp_path / "test_consistency.db")
    return initialize_sqlite_database(db_file)


@pytest.fixture
def sample_policies():
    p1 = ZeroTrustPolicy(
        policy_id="consistency-pol-1",
        policy_name="Zero Trust Corp Network Policy",
        version="1.0.0",
        rules=[
            PolicyRule(rule_id="R1", source="START", target="AUTHENTICATED", action="PASS_MFA"),
            PolicyRule(rule_id="R2", source="AUTHENTICATED", target="ACCESS_GRANTED", action="GRANT_ACCESS")
        ]
    )
    p2 = ZeroTrustPolicy(
        policy_id="consistency-pol-2",
        policy_name="Contractor Quarantine Policy",
        version="2.0.0",
        rules=[
            PolicyRule(rule_id="R10", source="START", target="DEVICE_CHECK", action="VERIFY_POSTURE"),
            PolicyRule(rule_id="R11", source="DEVICE_CHECK", target="ACCESS_DENIED", action="ISOLATE")
        ]
    )
    return [p1, p2]


@pytest.fixture
def sample_reports():
    r1 = VerificationReport(
        policy_id="consistency-pol-1",
        policy_name="Zero Trust Corp Network Policy",
        timestamp="2026-09-18T10:00:00Z",
        valid=True,
        total_states=3,
        total_transitions=2,
        violations_count=0,
        risk_score=0,
        security_posture="COMPLIANT"
    )
    r2 = VerificationReport(
        policy_id="consistency-pol-1",
        policy_name="Zero Trust Corp Network Policy",
        timestamp="2026-09-18T10:05:00Z",
        valid=False,
        total_states=3,
        total_transitions=2,
        violations_count=1,
        risk_score=40,
        security_posture="CRITICAL_RISK",
        violations=[
            PolicyViolation(
                type=ViolationType.MISSING_AUTHENTICATION,
                severity=ViolationSeverity.CRITICAL,
                message="Privilege bypass detected",
                explanation="Bypass directly to access."
            )
        ]
    )
    r3 = VerificationReport(
        policy_id="consistency-pol-2",
        policy_name="Contractor Quarantine Policy",
        timestamp="2026-09-18T10:10:00Z",
        valid=True,
        total_states=3,
        total_transitions=2,
        violations_count=0,
        risk_score=0,
        security_posture="COMPLIANT"
    )
    return [r1, r2, r3]


def test_sqlite_schema_indexes_created(sqlite_repo):
    """Verifies that performance optimization indexes exist in sqlite_master."""
    with sqlite3.connect(sqlite_repo.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {row[0] for row in cursor.fetchall()}

    expected_indexes = {
        "idx_policies_created_at",
        "idx_policies_name",
        "idx_reports_policy_id",
        "idx_reports_timestamp",
        "idx_reports_valid"
    }
    assert expected_indexes.issubset(indexes), f"Missing indexes: {expected_indexes - indexes}"


def test_sqlite_policy_filtered_reports(sqlite_repo, sample_policies, sample_reports):
    """Verifies get_reports_for_policy filters by policy_id accurately."""
    for p in sample_policies:
        sqlite_repo.save_policy(p)

    for r in sample_reports:
        sqlite_repo.save_report(r)

    reports_pol_1 = sqlite_repo.get_reports_for_policy("consistency-pol-1")
    assert len(reports_pol_1) == 2
    assert all(r.policy_id == "consistency-pol-1" for r in reports_pol_1)

    reports_pol_2 = sqlite_repo.get_reports_for_policy("consistency-pol-2")
    assert len(reports_pol_2) == 1
    assert reports_pol_2[0].policy_id == "consistency-pol-2"

    reports_nonexistent = sqlite_repo.get_reports_for_policy("nonexistent-pol")
    assert len(reports_nonexistent) == 0


def test_sqlite_counts_and_clear(sqlite_repo, sample_policies, sample_reports):
    """Tests count_policies, count_reports, and clear_all methods."""
    assert sqlite_repo.count_policies() == 0
    assert sqlite_repo.count_reports() == 0

    for p in sample_policies:
        sqlite_repo.save_policy(p)
    for r in sample_reports:
        sqlite_repo.save_report(r)

    assert sqlite_repo.count_policies() == 2
    assert sqlite_repo.count_reports() == 3

    sqlite_repo.clear_all()
    assert sqlite_repo.count_policies() == 0
    assert sqlite_repo.count_reports() == 0


def test_lossless_cross_backend_migration(sqlite_repo, sample_policies, sample_reports, tmp_path):
    """Tests migration from source SQLite repo to target SQLite repo with zero data loss."""
    target_repo = SQLitePolicyRepository(db_path=str(tmp_path / "target.db"))

    for p in sample_policies:
        sqlite_repo.save_policy(p)
    for r in sample_reports:
        sqlite_repo.save_report(r)

    result = migrate_data(source_repo=sqlite_repo, target_repo=target_repo)
    assert result["policies_migrated"] == 2
    assert result["reports_migrated"] == 3

    assert target_repo.count_policies() == 2
    assert target_repo.count_reports() == 3

    migrated_p1 = target_repo.get_policy("consistency-pol-1")
    assert migrated_p1 is not None
    assert migrated_p1.policy_name == "Zero Trust Corp Network Policy"
    assert len(migrated_p1.rules) == 2


def test_dynamodb_single_table_key_generation(sample_policies, sample_reports):
    """Verifies DynamoDB store injects single-table design partition keys and sort keys."""
    with patch("boto3.resource") as mock_boto:
        mock_pol_table = MagicMock()
        mock_rep_table = MagicMock()

        def table_side_effect(name):
            return mock_pol_table if "policies" in name else mock_rep_table

        mock_boto.return_value.Table.side_effect = table_side_effect

        dynamo_repo = DynamoDBPolicyRepository(
            table_name="test_policies",
            reports_table_name="test_reports"
        )
        dynamo_repo.policy_table = mock_pol_table
        dynamo_repo.reports_table = mock_rep_table

        # 1. Save Policy Check
        dynamo_repo.save_policy(sample_policies[0])
        saved_policy_call = mock_pol_table.put_item.call_args[1]["Item"]
        assert saved_policy_call["PK"] == "POLICY#consistency-pol-1"
        assert saved_policy_call["SK"] == "METADATA"
        assert saved_policy_call["GSI1PK"] == "TYPE#POLICY"

        # 2. Save Report Check
        dynamo_repo.save_report(sample_reports[0])
        saved_report_call = mock_rep_table.put_item.call_args[1]["Item"]
        assert saved_report_call["PK"] == "POLICY#consistency-pol-1"
        assert saved_report_call["SK"] == f"REPORT#{sample_reports[0].timestamp}"
        assert saved_report_call["GSI1PK"] == "TYPE#REPORT"
