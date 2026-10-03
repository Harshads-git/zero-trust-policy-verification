"""
AWS S3 Policy Backup & Audit Archiving Integration (AWS Free Tier Compatible)
Provides snapshot backup and cold-storage archiving of Zero Trust policies and verification logs.
Operates within the AWS Free Tier allowance (5GB standard storage, 20,000 GET requests).
Includes automatic local filesystem fallback for offline development and testing.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pathlib import Path
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from backend.models.policy import ZeroTrustPolicy
from backend.models.report import VerificationReport

logger = logging.getLogger("ztpve.s3")


class S3BackupArchiver:
    """
    Manages automated S3 backups of policies and audit verification logs.
    Falls back gracefully to local disk storage (`./backups`) if AWS credentials are not configured.
    """

    def __init__(
        self,
        bucket_name: Optional[str] = None,
        region_name: Optional[str] = None,
        local_backup_dir: Optional[str] = None
    ):
        self.bucket_name = bucket_name or os.getenv("S3_BACKUP_BUCKET", "ztpve-policy-archives")
        self.region_name = region_name or os.getenv("AWS_REGION", "us-east-1")
        self.local_backup_dir = Path(local_backup_dir or os.getenv("LOCAL_BACKUP_DIR", "./backups"))
        self.local_backup_dir.mkdir(parents=True, exist_ok=True)

        self.s3_client = None
        try:
            self.s3_client = boto3.client("s3", region_name=self.region_name)
        except Exception as e:
            logger.warning(f"Could not initialize S3 client ({e}); will use local backup directory.")
            self.s3_client = None

        self._in_memory_catalog: List[Dict[str, Any]] = []

    def archive_policy(self, policy: ZeroTrustPolicy) -> Dict[str, Any]:
        """Archives a single policy specification into S3 (or local disk fallback)."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        key = f"policies/{policy.policy_id}_{timestamp}.json"
        payload = json.dumps(policy.model_dump(), indent=2)

        record = {
            "key": key,
            "policy_id": policy.policy_id,
            "policy_name": policy.policy_name,
            "timestamp": timestamp,
            "size_bytes": len(payload.encode("utf-8")),
            "storage_destination": "s3"
        }

        uploaded_to_s3 = False
        if self.s3_client:
            try:
                self.s3_client.put_object(
                    Bucket=self.bucket_name,
                    Key=key,
                    Body=payload,
                    ContentType="application/json",
                    Metadata={"policy_id": policy.policy_id, "policy_name": policy.policy_name}
                )
                record["s3_uri"] = f"s3://{self.bucket_name}/{key}"
                uploaded_to_s3 = True
                logger.info(f"Successfully archived policy '{policy.policy_id}' to s3://{self.bucket_name}/{key}")
            except (ClientError, NoCredentialsError) as e:
                logger.warning(f"S3 upload failed ({e}); falling back to local storage.")

        if not uploaded_to_s3:
            local_path = self.local_backup_dir / key.replace("/", "_")
            with open(local_path, "w", encoding="utf-8") as f:
                f.write(payload)
            record["storage_destination"] = "local"
            record["local_path"] = str(local_path)
            logger.info(f"Archived policy '{policy.policy_id}' locally to {local_path}")

        self._in_memory_catalog.append(record)
        return record

    def archive_all(
        self,
        policies: List[ZeroTrustPolicy],
        reports: List[VerificationReport]
    ) -> Dict[str, Any]:
        """Creates a consolidated manifest archive of all policies and audit reports."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        manifest_key = f"manifests/ztpve_backup_{timestamp}.json"

        manifest_data = {
            "backup_timestamp": datetime.now(timezone.utc).isoformat(),
            "policies_count": len(policies),
            "reports_count": len(reports),
            "policies": [p.model_dump() for p in policies],
            "reports": [r.model_dump() for r in reports]
        }
        payload = json.dumps(manifest_data, indent=2)

        record = {
            "key": manifest_key,
            "timestamp": timestamp,
            "policies_archived": len(policies),
            "reports_archived": len(reports),
            "size_bytes": len(payload.encode("utf-8")),
            "storage_destination": "s3"
        }

        uploaded_to_s3 = False
        if self.s3_client:
            try:
                self.s3_client.put_object(
                    Bucket=self.bucket_name,
                    Key=manifest_key,
                    Body=payload,
                    ContentType="application/json"
                )
                record["s3_uri"] = f"s3://{self.bucket_name}/{manifest_key}"
                uploaded_to_s3 = True
            except (ClientError, NoCredentialsError) as e:
                logger.warning(f"S3 manifest upload failed ({e}); using local storage.")

        if not uploaded_to_s3:
            local_path = self.local_backup_dir / manifest_key.replace("/", "_")
            with open(local_path, "w", encoding="utf-8") as f:
                f.write(payload)
            record["storage_destination"] = "local"
            record["local_path"] = str(local_path)

        self._in_memory_catalog.append(record)
        return record

    def list_archives(self) -> List[Dict[str, Any]]:
        """Returns catalog of all generated backups across S3 and local storage."""
        if self.s3_client:
            try:
                resp = self.s3_client.list_objects_v2(Bucket=self.bucket_name, MaxKeys=50)
                if "Contents" in resp:
                    return [
                        {
                            "key": item["Key"],
                            "size_bytes": item["Size"],
                            "last_modified": item["LastModified"].isoformat(),
                            "storage_destination": "s3",
                            "s3_uri": f"s3://{self.bucket_name}/{item['Key']}"
                        }
                        for item in resp["Contents"]
                    ]
            except (ClientError, NoCredentialsError):
                pass

        # Return catalog of local files or in-memory tracking
        local_files = []
        if self.local_backup_dir.exists():
            for f in self.local_backup_dir.glob("*.json"):
                local_files.append({
                    "key": f.name,
                    "size_bytes": f.stat().st_size,
                    "storage_destination": "local",
                    "local_path": str(f)
                })
        return local_files or self._in_memory_catalog

    def get_status(self) -> Dict[str, Any]:
        """Returns operational status of the S3 archiver."""
        return {
            "bucket_name": self.bucket_name,
            "region": self.region_name,
            "s3_connected": self.s3_client is not None,
            "local_backup_dir": str(self.local_backup_dir),
            "total_archives_recorded": len(self.list_archives())
        }
