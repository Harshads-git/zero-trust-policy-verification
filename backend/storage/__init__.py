import os
from backend.storage.base import PolicyRepository
from backend.storage.sqlite_store import SQLitePolicyRepository
from backend.storage.dynamodb_store import DynamoDBPolicyRepository


def get_repository() -> PolicyRepository:
    """Factory creating configured storage backend from environment variables."""
    backend_type = os.getenv("STORAGE_BACKEND", "sqlite").lower()
    if backend_type == "dynamodb":
        table_name = os.getenv("DYNAMODB_TABLE_NAME", "zero_trust_policies")
        reports_table = os.getenv("DYNAMODB_AUDIT_TABLE", "zero_trust_audit_reports")
        region = os.getenv("AWS_REGION", "us-east-1")
        return DynamoDBPolicyRepository(table_name=table_name, reports_table_name=reports_table, region_name=region)
    
    db_path = os.getenv("SQLITE_DB_PATH", "policies.db")
    return SQLitePolicyRepository(db_path=db_path)


__all__ = ["PolicyRepository", "SQLitePolicyRepository", "DynamoDBPolicyRepository", "get_repository"]
