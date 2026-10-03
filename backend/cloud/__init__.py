"""
AWS Cloud Free Tier Integration Package
Provides DynamoDB, CloudWatch, and S3 operational components.
"""

from backend.cloud.cloudwatch import CloudWatchMetricsPublisher
from backend.cloud.s3 import S3BackupArchiver

# Global singleton accessors
_cloudwatch_publisher = None
_s3_archiver = None


def get_cloudwatch_publisher() -> CloudWatchMetricsPublisher:
    global _cloudwatch_publisher
    if _cloudwatch_publisher is None:
        _cloudwatch_publisher = CloudWatchMetricsPublisher()
    return _cloudwatch_publisher


def get_s3_archiver() -> S3BackupArchiver:
    global _s3_archiver
    if _s3_archiver is None:
        _s3_archiver = S3BackupArchiver()
    return _s3_archiver


__all__ = [
    "CloudWatchMetricsPublisher",
    "S3BackupArchiver",
    "get_cloudwatch_publisher",
    "get_s3_archiver"
]
