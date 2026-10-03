"""
FastAPI Cloud Infrastructure Routes
Endpoints for monitoring AWS Free Tier services (DynamoDB, CloudWatch, S3) and triggering backups.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import Dict, Any, List
import os

from backend.cloud import get_cloudwatch_publisher, get_s3_archiver
from backend.storage import get_repository, PolicyRepository

router = APIRouter(prefix="/cloud", tags=["AWS Cloud Infrastructure"])


@router.get("/status", summary="Get AWS Free Tier status and service connectivity")
def get_cloud_status(repo: PolicyRepository = Depends(get_repository)) -> Dict[str, Any]:
    """
    Returns live connectivity and configuration for AWS Free Tier resources.
    Covers DynamoDB, CloudWatch Metrics, and S3 Backup Archiver.
    """
    cw = get_cloudwatch_publisher()
    s3 = get_s3_archiver()
    storage_backend = os.getenv("STORAGE_BACKEND", "sqlite")

    policies = repo.list_policies()
    reports = repo.list_reports(limit=10)

    return {
        "status": "operational",
        "region": os.getenv("AWS_REGION", "us-east-1"),
        "storage": {
            "configured_backend": storage_backend,
            "policies_stored_count": len(policies),
            "dynamodb_table_name": os.getenv("DYNAMODB_TABLE_NAME", "zero_trust_policies"),
            "free_tier_allowance": "25 RCU / 25 WCU (25 GB perpetual storage)"
        },
        "cloudwatch": {
            **cw.get_status(),
            "free_tier_allowance": "10 custom metrics, 5 GB log ingestion / month"
        },
        "s3": {
            **s3.get_status(),
            "free_tier_allowance": "5 GB standard storage, 20,000 GET / 2,000 PUT requests"
        },
        "cost_projection": "$0.00 / month (Fully within AWS Free Tier limits)"
    }


@router.post("/s3/backup", summary="Trigger instant policy and audit log backup to S3")
def trigger_s3_backup(repo: PolicyRepository = Depends(get_repository)) -> Dict[str, Any]:
    """
    Generates a versioned backup manifest of all stored policies and audit reports
    and uploads it to Amazon S3 (with local fallback if offline).
    """
    s3 = get_s3_archiver()
    policies = repo.list_policies()
    reports = repo.list_reports(limit=100)

    backup_record = s3.archive_all(policies, reports)
    return {
        "message": "Backup completed successfully",
        "backup": backup_record
    }


@router.get("/s3/archives", summary="List policy backup archives")
def list_s3_archives() -> List[Dict[str, Any]]:
    """Returns catalog of recent policy backup archives."""
    s3 = get_s3_archiver()
    return s3.list_archives()


@router.post("/cloudwatch/publish-test", summary="Send test operational metric to CloudWatch")
def publish_test_metric() -> Dict[str, Any]:
    """Sends a sample heartbeat verification metric to CloudWatch to test credentials."""
    cw = get_cloudwatch_publisher()
    success = cw.publish_custom_metric(
        metric_name="HeartbeatTestMetric",
        value=1.0,
        unit="Count",
        dimensions=[{"Name": "Environment", "Value": "Production-FreeTier"}]
    )
    return {
        "message": "Heartbeat metric processed",
        "published_to_aws": success,
        "recent_metrics_count": len(cw.in_memory_metrics)
    }
