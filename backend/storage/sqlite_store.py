"""
SQLite Storage Implementation
Zero-configuration, lightweight local database suitable for developer testing and classroom viva demos.
"""

import sqlite3
import json
from typing import List, Optional
from backend.storage.base import PolicyRepository
from backend.models.policy import ZeroTrustPolicy
from backend.models.report import VerificationReport


class SQLitePolicyRepository(PolicyRepository):
    def __init__(self, db_path: str = "policies.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS policies (
                    policy_id TEXT PRIMARY KEY,
                    policy_name TEXT NOT NULL,
                    description TEXT,
                    version TEXT,
                    data JSON NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS verification_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_id TEXT NOT NULL,
                    policy_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    valid INTEGER NOT NULL,
                    violations_count INTEGER NOT NULL,
                    report_data JSON NOT NULL
                );
            """)
            conn.commit()

    def save_policy(self, policy: ZeroTrustPolicy) -> ZeroTrustPolicy:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO policies (policy_id, policy_name, description, version, data)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(policy_id) DO UPDATE SET
                    policy_name=excluded.policy_name,
                    description=excluded.description,
                    version=excluded.version,
                    data=excluded.data;
            """, (
                policy.policy_id,
                policy.policy_name,
                policy.description,
                policy.version,
                json.dumps(policy.model_dump())
            ))
            conn.commit()
        return policy

    def get_policy(self, policy_id: str) -> Optional[ZeroTrustPolicy]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM policies WHERE policy_id = ?", (policy_id,))
            row = cursor.fetchone()
            if row:
                return ZeroTrustPolicy.model_validate(json.loads(row["data"]))
        return None

    def list_policies(self) -> List[ZeroTrustPolicy]:
        policies = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM policies ORDER BY created_at DESC")
            for row in cursor.fetchall():
                policies.append(ZeroTrustPolicy.model_validate(json.loads(row["data"])))
        return policies

    def delete_policy(self, policy_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM policies WHERE policy_id = ?", (policy_id,))
            deleted = cursor.rowcount > 0
            conn.commit()
            return deleted

    def save_report(self, report: VerificationReport) -> VerificationReport:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO verification_reports (policy_id, policy_name, timestamp, valid, violations_count, report_data)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                report.policy_id,
                report.policy_name,
                report.timestamp,
                1 if report.valid else 0,
                report.violations_count,
                json.dumps(report.model_dump())
            ))
            conn.commit()
        return report

    def list_reports(self, limit: int = 50) -> List[VerificationReport]:
        reports = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT report_data FROM verification_reports ORDER BY id DESC LIMIT ?",
                (limit,)
            )
            for row in cursor.fetchall():
                reports.append(VerificationReport.model_validate(json.loads(row["report_data"])))
        return reports
