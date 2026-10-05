"""
AWS IAM Least-Privilege Policy Generator (NIST SP 800-207 Zero Trust Compliant)
Automates generation of cryptographically and architecturally scoped AWS IAM JSON policies.
Guarantees the principle of least privilege (PoLP) by strictly constraining resource ARNs
and eliminating wildcard ('*') administrative entitlements.
"""

import json
from typing import Dict, Any, Optional


class IAMLeastPrivilegePolicyGenerator:
    """
    Generates tailored AWS IAM policies adhering strictly to NIST SP 800-207
    Zero Trust Architecture for DynamoDB, S3, CloudWatch, and Lambda.
    """

    def __init__(
        self,
        account_id: str = "123456789012",
        region: str = "us-east-1",
        dynamodb_table: str = "zero_trust_policies",
        reports_table: str = "zero_trust_audit_reports",
        s3_bucket: str = "ztpve-policy-archives",
        cloudwatch_namespace: str = "ZTPVE/VerificationEngine"
    ):
        self.account_id = account_id
        self.region = region
        self.dynamodb_table = dynamodb_table
        self.reports_table = reports_table
        self.s3_bucket = s3_bucket
        self.cloudwatch_namespace = cloudwatch_namespace

    def generate_app_iam_policy(self) -> Dict[str, Any]:
        """
        Generates production-ready IAM policy restricting the verification engine
        exclusively to designated DynamoDB tables, S3 bucket prefixes, and CloudWatch namespace.
        """
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DynamoDBPolicyStoreLeastPrivilege",
                    "Effect": "Allow",
                    "Action": [
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:DeleteItem",
                        "dynamodb:Scan",
                        "dynamodb:Query"
                    ],
                    "Resource": [
                        f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.dynamodb_table}",
                        f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.dynamodb_table}/index/*"
                    ]
                },
                {
                    "Sid": "DynamoDBAuditReportsLeastPrivilege",
                    "Effect": "Allow",
                    "Action": [
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:Scan",
                        "dynamodb:Query"
                    ],
                    "Resource": [
                        f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.reports_table}",
                        f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.reports_table}/index/*"
                    ]
                },
                {
                    "Sid": "S3PolicyArchiveBucketLeastPrivilege",
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListBucket",
                        "s3:GetBucketLocation"
                    ],
                    "Resource": f"arn:aws:s3:::{self.s3_bucket}"
                },
                {
                    "Sid": "S3PolicyArchiveObjectsLeastPrivilege",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject"
                    ],
                    "Resource": f"arn:aws:s3:::{self.s3_bucket}/*"
                },
                {
                    "Sid": "CloudWatchVerificationMetricsScoped",
                    "Effect": "Allow",
                    "Action": [
                        "cloudwatch:PutMetricData"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "cloudwatch:namespace": self.cloudwatch_namespace
                        }
                    }
                },
                {
                    "Sid": "CloudWatchLogsAuditTrail",
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                    "Resource": f"arn:aws:logs:{self.region}:{self.account_id}:log-group:/aws/ztpve/*"
                }
            ]
        }

    def generate_assume_role_trust_policy(self) -> Dict[str, Any]:
        """Generates IAM Trust Relationship allowing AWS Lambda or EC2 execution."""
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": [
                            "lambda.amazonaws.com",
                            "ec2.amazonaws.com"
                        ]
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }

    def to_json(self, indent: int = 2) -> str:
        """Returns JSON string of the complete application least-privilege IAM policy."""
        return json.dumps(self.generate_app_iam_policy(), indent=indent)
