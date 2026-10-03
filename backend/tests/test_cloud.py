"""
Unit & Integration Tests for AWS Cloud Free Tier Integration
Tests CloudWatch metrics publisher, S3 policy backup archiver, DynamoDB store,
and Cloud API endpoints using mocking to ensure offline execution.
"""

import pytest
from unittest.mock import MagicMock, patch
import json
from pathlib import Path
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.policy import ZeroTrustPolicy, PolicyRule
from backend.models.report import VerificationReport, PolicyViolation, ViolationType, ViolationSeverity
from backend.cloud.cloudwatch import CloudWatchMetricsPublisher
from backend.cloud.s3 import S3BackupArchiver
from backend.storage.dynamodb_store import DynamoDBPolicyRepository

client = TestClient(app)


@pytest.fixture
def sample_report():
    return VerificationReport(
        policy_id="test-cloud-policy",
        policy_name="Cloud Test Policy",
        valid=False,
        total_states=4,
        total_transitions=3,
        violations_count=1,
        risk_score=40,
        security_posture="CRITICAL_RISK",
        verification_time_ms=1.23,
        violations=[
            PolicyViolation(
                type=ViolationType.MISSING_AUTHENTICATION,
                severity=ViolationSeverity.CRITICAL,
                message="Missing authentication on path",
                explanation="No auth step present."
            )
        ]
    )


@pytest.fixture
def sample_policy():
    return ZeroTrustPolicy(
        policy_id="cloud-backup-pol-1",
        policy_name="Employee Cloud Access Policy",
        version="1.0.0",
        rules=[
            PolicyRule(
                rule_id="R1",
                source="START",
                target="AUTHENTICATED",
                action="MFA_LOGIN"
            ),
            PolicyRule(
                rule_id="R2",
                source="AUTHENTICATED",
                target="ACCESS_GRANTED",
                action="GRANT_RESOURCE"
            )
        ]
    )


def test_cloudwatch_publisher_offline_buffering(sample_report):
    """Verifies CloudWatch publisher buffers metrics locally when offline."""
    publisher = CloudWatchMetricsPublisher(enabled=False)
    success = publisher.publish_verification_metrics(sample_report)
    assert success is True
    
    recent = publisher.get_recent_metrics(limit=5)
    assert len(recent) >= 1
    assert recent[0]["policy_id"] == "test-cloud-policy"
    assert recent[0]["valid"] is False


def test_cloudwatch_publisher_with_mock_client(sample_report):
    """Verifies CloudWatch publisher calls put_metric_data when client is active."""
    publisher = CloudWatchMetricsPublisher(enabled=True)
    publisher.client = MagicMock()
    
    success = publisher.publish_verification_metrics(sample_report)
    assert success is True
    assert publisher.client.put_metric_data.called
    
    call_args = publisher.client.put_metric_data.call_args[1]
    assert call_args["Namespace"] == publisher.namespace
    assert len(call_args["MetricData"]) == 4


def test_s3_archiver_local_fallback(sample_policy, tmp_path):
    """Verifies S3 archiver falls back to local backup directory when S3 is unavailable."""
    archiver = S3BackupArchiver(local_backup_dir=str(tmp_path / "backups"))
    archiver.s3_client = None  # Force local fallback
    
    record = archiver.archive_policy(sample_policy)
    assert record["storage_destination"] == "local"
    assert Path(record["local_path"]).exists()
    
    with open(record["local_path"], "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["policy_id"] == "cloud-backup-pol-1"


def test_s3_archiver_archive_all(sample_policy, sample_report, tmp_path):
    """Verifies full manifest backup of policies and audit reports."""
    archiver = S3BackupArchiver(local_backup_dir=str(tmp_path / "manifests"))
    archiver.s3_client = None
    
    manifest_record = archiver.archive_all([sample_policy], [sample_report])
    assert manifest_record["policies_archived"] == 1
    assert manifest_record["reports_archived"] == 1
    assert Path(manifest_record["local_path"]).exists()


def test_dynamodb_repository_mocked(sample_policy):
    """Verifies DynamoDB repository CRUD operations with mocked boto3 table."""
    with patch("boto3.resource") as mock_boto:
        mock_table = MagicMock()
        mock_boto.return_value.Table.return_value = mock_table
        
        repo = DynamoDBPolicyRepository(table_name="test_pol", reports_table_name="test_rep")
        repo.policy_table = mock_table
        
        # Test save_policy
        saved = repo.save_policy(sample_policy)
        assert saved.policy_id == sample_policy.policy_id
        assert mock_table.put_item.called
        
        # Test get_policy
        mock_table.get_item.return_value = {
            "Item": {
                "policy_id": sample_policy.policy_id,
                "data": json.dumps(sample_policy.model_dump())
            }
        }
        fetched = repo.get_policy("cloud-backup-pol-1")
        assert fetched is not None
        assert fetched.policy_name == sample_policy.policy_name
        
        # Test delete_policy
        deleted = repo.delete_policy("cloud-backup-pol-1")
        assert deleted is True
        assert mock_table.delete_item.called


def test_cloud_status_endpoint():
    """Verifies GET /api/cloud/status returns operational AWS Free Tier parameters."""
    response = client.get("/api/cloud/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert "storage" in data
    assert "cloudwatch" in data
    assert "s3" in data
    assert "$0.00 / month" in data["cost_projection"]


def test_cloud_s3_backup_endpoint():
    """Verifies POST /api/cloud/s3/backup triggers manifest generation."""
    response = client.post("/api/cloud/s3/backup")
    assert response.status_code == 200
    data = response.json()
    assert "backup" in data
    assert data["backup"]["policies_archived"] >= 0


def test_cloud_publish_test_metric_endpoint():
    """Verifies POST /api/cloud/cloudwatch/publish-test records heartbeat metric."""
    response = client.post("/api/cloud/cloudwatch/publish-test")
    assert response.status_code == 200
    data = response.json()
    assert "published_to_aws" in data
    assert data["recent_metrics_count"] >= 1
