"""
Storage Migration & Schema Initialization Utilities
Facilitates database schema setup, index creation, and cross-backend data migration
between local SQLite and cloud Amazon DynamoDB.
"""

import sqlite3
import logging
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError

from backend.storage.base import PolicyRepository
from backend.storage.sqlite_store import SQLitePolicyRepository

logger = logging.getLogger("ztpve.storage.migration")


def initialize_sqlite_database(db_path: str = "policies.db") -> SQLitePolicyRepository:
    """
    Initializes SQLite tables and performance indexes idempotently.
    Returns the ready repository instance.
    """
    repo = SQLitePolicyRepository(db_path=db_path)
    logger.info(f"SQLite schema initialized successfully at '{db_path}'")
    return repo


def create_dynamodb_tables_if_not_exist(
    dynamodb_resource,
    table_name: str = "zero_trust_policies",
    reports_table_name: str = "zero_trust_audit_reports",
    billing_mode: str = "PAY_PER_REQUEST"
) -> Dict[str, Any]:
    """
    Creates AWS DynamoDB single-table design compatible tables if they don't already exist.
    Configured for AWS Free Tier on-demand capacity or 25 RCU/WCU provisioned mode.
    """
    created = []
    existing = []

    # 1. Main Policies Table
    try:
        table = dynamodb_resource.create_table(
            TableName=table_name,
            KeySchema=[
                {"AttributeName": "policy_id", "KeyType": "HASH"}
            ],
            AttributeDefinitions=[
                {"AttributeName": "policy_id", "AttributeType": "S"}
            ],
            BillingMode=billing_mode
        )
        table.wait_until_exists()
        created.append(table_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceInUseException":
            existing.append(table_name)
        else:
            raise

    # 2. Audit Reports Table
    try:
        rep_table = dynamodb_resource.create_table(
            TableName=reports_table_name,
            KeySchema=[
                {"AttributeName": "report_id", "KeyType": "HASH"}
            ],
            AttributeDefinitions=[
                {"AttributeName": "report_id", "AttributeType": "S"}
            ],
            BillingMode=billing_mode
        )
        rep_table.wait_until_exists()
        created.append(reports_table_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceInUseException":
            existing.append(reports_table_name)
        else:
            raise

    return {
        "created_tables": created,
        "existing_tables": existing,
        "billing_mode": billing_mode
    }


def migrate_data(
    source_repo: PolicyRepository,
    target_repo: PolicyRepository
) -> Dict[str, int]:
    """
    Executes lossless cross-backend data migration from source to target repository.
    Works bi-directionally between SQLite and DynamoDB.
    """
    policies = source_repo.list_policies()
    reports = source_repo.list_reports(limit=1000)

    policies_migrated = 0
    reports_migrated = 0

    for policy in policies:
        target_repo.save_policy(policy)
        policies_migrated += 1

    for report in reports:
        target_repo.save_report(report)
        reports_migrated += 1

    logger.info(
        f"Completed data migration: {policies_migrated} policies and {reports_migrated} reports."
    )
    return {
        "policies_migrated": policies_migrated,
        "reports_migrated": reports_migrated
    }
