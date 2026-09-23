"""
AWS DynamoDB Storage Implementation (AWS Free Tier Compatible)
Integrates with AWS DynamoDB using Boto3 with error handling and fallback capabilities.
Uses 25 Read/Write Capacity Units (RCU/WCU within the perpetual Free Tier) or on-demand mode.
"""

import json
import logging
from typing import List, Optional
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from backend.storage.base import PolicyRepository
from backend.models.policy import ZeroTrustPolicy
from backend.models.report import VerificationReport

logger = logging.getLogger("ztpve.dynamodb")


class DynamoDBPolicyRepository(PolicyRepository):
    def __init__(
        self,
        table_name: str = "zero_trust_policies",
        reports_table_name: str = "zero_trust_audit_reports",
        region_name: str = "us-east-1"
    ):
        self.table_name = table_name
        self.reports_table_name = reports_table_name
        self.region_name = region_name

        try:
            self.dynamodb = boto3.resource("dynamodb", region_name=region_name)
            self.policy_table = self.dynamodb.Table(self.table_name)
            self.reports_table = self.dynamodb.Table(self.reports_table_name)
        except Exception as e:
            logger.warning(f"DynamoDB initialization warning: {e}. Ensure AWS credentials or IAM role are configured.")

    def save_policy(self, policy: ZeroTrustPolicy) -> ZeroTrustPolicy:
        try:
            item = {
                "policy_id": policy.policy_id,
                "policy_name": policy.policy_name,
                "description": policy.description or "",
                "version": policy.version,
                "data": json.dumps(policy.model_dump())
            }
            self.policy_table.put_item(Item=item)
            return policy
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to put item in DynamoDB: {e}")
            raise RuntimeError(f"DynamoDB Error: {e}")

    def get_policy(self, policy_id: str) -> Optional[ZeroTrustPolicy]:
        try:
            response = self.policy_table.get_item(Key={"policy_id": policy_id})
            item = response.get("Item")
            if item:
                return ZeroTrustPolicy.model_validate(json.loads(item["data"]))
            return None
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to get policy from DynamoDB: {e}")
            return None

    def list_policies(self) -> List[ZeroTrustPolicy]:
        try:
            response = self.policy_table.scan(Limit=100)
            items = response.get("Items", [])
            policies = []
            for item in items:
                policies.append(ZeroTrustPolicy.model_validate(json.loads(item["data"])))
            return policies
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to scan DynamoDB policies: {e}")
            return []

    def delete_policy(self, policy_id: str) -> bool:
        try:
            self.policy_table.delete_item(Key={"policy_id": policy_id})
            return True
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to delete policy from DynamoDB: {e}")
            return False

    def save_report(self, report: VerificationReport) -> VerificationReport:
        try:
            item = {
                "report_id": f"{report.policy_id}#{report.timestamp}",
                "policy_id": report.policy_id,
                "policy_name": report.policy_name,
                "timestamp": report.timestamp,
                "valid": 1 if report.valid else 0,
                "violations_count": report.violations_count,
                "report_data": json.dumps(report.model_dump())
            }
            self.reports_table.put_item(Item=item)
            return report
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to save report to DynamoDB: {e}")
            return report

    def list_reports(self, limit: int = 50) -> List[VerificationReport]:
        try:
            response = self.reports_table.scan(Limit=limit)
            items = response.get("Items", [])
            reports = []
            for item in items:
                reports.append(VerificationReport.model_validate(json.loads(item["report_data"])))
            return reports
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to scan DynamoDB reports: {e}")
            return []
