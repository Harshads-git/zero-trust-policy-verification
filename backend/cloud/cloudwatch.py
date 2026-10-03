"""
AWS CloudWatch Metrics & Telemetry Integration (AWS Free Tier Compatible)
Publishes custom verification metrics and security posture telemetry to Amazon CloudWatch.
Operates within the AWS Free Tier allowance (10 custom metrics, 5GB log data ingestion).
Provides seamless local in-memory fallback when offline or running without AWS credentials.
"""

import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from backend.models.report import VerificationReport

logger = logging.getLogger("ztpve.cloudwatch")


class CloudWatchMetricsPublisher:
    """
    Publishes formal verification metrics and alarm telemetry to AWS CloudWatch.
    Gracefully falls back to local in-memory buffering if AWS credentials are unavailable.
    """

    def __init__(
        self,
        namespace: Optional[str] = None,
        region_name: Optional[str] = None,
        enabled: Optional[bool] = None
    ):
        self.namespace = namespace or os.getenv("CLOUDWATCH_NAMESPACE", "ZTPVE/VerificationEngine")
        self.region_name = region_name or os.getenv("AWS_REGION", "us-east-1")
        
        env_enabled = os.getenv("ENABLE_CLOUDWATCH", "false").lower() in ("true", "1", "yes")
        self.enabled = enabled if enabled is not None else env_enabled
        
        self.client = None
        self.in_memory_metrics: List[Dict[str, Any]] = []

        if self.enabled:
            try:
                self.client = boto3.client("cloudwatch", region_name=self.region_name)
                logger.info(f"Initialized CloudWatch client in region '{self.region_name}'")
            except Exception as e:
                logger.warning(f"Could not initialize CloudWatch client ({e}); falling back to in-memory mode.")
                self.client = None

    def publish_verification_metrics(self, report: VerificationReport) -> bool:
        """
        Publishes verification latency, violation counts, and risk score to CloudWatch.
        """
        metric_data = [
            {
                "MetricName": "VerificationLatencyMs",
                "Value": float(report.verification_time_ms),
                "Unit": "Milliseconds",
                "Dimensions": [
                    {"Name": "PolicyId", "Value": report.policy_id},
                    {"Name": "SecurityPosture", "Value": report.security_posture}
                ]
            },
            {
                "MetricName": "ViolationsDetected",
                "Value": float(report.violations_count),
                "Unit": "Count",
                "Dimensions": [
                    {"Name": "PolicyId", "Value": report.policy_id},
                    {"Name": "SecurityPosture", "Value": report.security_posture}
                ]
            },
            {
                "MetricName": "SecurityRiskScore",
                "Value": float(report.risk_score),
                "Unit": "None",
                "Dimensions": [
                    {"Name": "PolicyId", "Value": report.policy_id},
                    {"Name": "SecurityPosture", "Value": report.security_posture}
                ]
            },
            {
                "MetricName": "CompliancePassed",
                "Value": 1.0 if report.valid else 0.0,
                "Unit": "Count",
                "Dimensions": [
                    {"Name": "PolicyId", "Value": report.policy_id}
                ]
            }
        ]

        timestamp = datetime.now(timezone.utc).isoformat()
        buffered_record = {
            "timestamp": timestamp,
            "policy_id": report.policy_id,
            "policy_name": report.policy_name,
            "valid": report.valid,
            "metrics": metric_data
        }
        self.in_memory_metrics.append(buffered_record)
        if len(self.in_memory_metrics) > 100:
            self.in_memory_metrics.pop(0)

        if not self.enabled or not self.client:
            logger.debug("CloudWatch disabled or client unavailable; stored in local buffer.")
            return True

        try:
            self.client.put_metric_data(
                Namespace=self.namespace,
                MetricData=metric_data
            )
            logger.info(f"Published 4 CloudWatch metrics for policy '{report.policy_id}' to namespace '{self.namespace}'")
            return True
        except (ClientError, NoCredentialsError) as e:
            logger.warning(f"Failed to publish metrics to CloudWatch: {e}. Metrics kept in local buffer.")
            return False

    def publish_custom_metric(self, metric_name: str, value: float, unit: str = "Count", dimensions: Optional[List[Dict[str, str]]] = None) -> bool:
        """Publishes an arbitrary operational metric."""
        metric_item = {
            "MetricName": metric_name,
            "Value": float(value),
            "Unit": unit,
            "Dimensions": dimensions or []
        }
        timestamp = datetime.now(timezone.utc).isoformat()
        self.in_memory_metrics.append({
            "timestamp": timestamp,
            "metric_name": metric_name,
            "value": value,
            "unit": unit
        })

        if not self.enabled or not self.client:
            return True

        try:
            self.client.put_metric_data(
                Namespace=self.namespace,
                MetricData=[metric_item]
            )
            return True
        except (ClientError, NoCredentialsError) as e:
            logger.warning(f"Failed to publish custom metric '{metric_name}': {e}")
            return False

    def get_recent_metrics(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Returns in-memory audit log of published verification metrics."""
        return list(reversed(self.in_memory_metrics[-limit:]))

    def get_status(self) -> Dict[str, Any]:
        """Returns current operational status of the CloudWatch publisher."""
        return {
            "enabled": self.enabled,
            "client_connected": self.client is not None,
            "namespace": self.namespace,
            "region": self.region_name,
            "buffered_events_count": len(self.in_memory_metrics)
        }
