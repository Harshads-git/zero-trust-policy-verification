"""
Database Seeding Script
Loads bundled valid and invalid policies into local SQLite/DynamoDB storage
and executes initial verification to pre-populate audit history.
"""

import sys
import json
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from backend.models.policy import ZeroTrustPolicy
from backend.core.verifier import ZeroTrustVerificationEngine
from backend.storage import get_repository


def seed():
    print("=" * 60)
    print("SEEDING ZTPVE DATABASE WITH SAMPLE ZERO TRUST POLICIES")
    print("=" * 60)

    repo = get_repository()
    verifier = ZeroTrustVerificationEngine()
    policies_dir = root_dir / "policies"

    count = 0
    # Seed valid policies
    for f in (policies_dir / "valid").glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            policy = ZeroTrustPolicy.model_validate(data)
            repo.save_policy(policy)
            report = verifier.verify(policy)
            repo.save_report(report)
            print(f"[+] Loaded [VALID]   : {policy.policy_name}")
            count += 1
        except Exception as e:
            print(f"[-] Error loading {f.name}: {e}")

    # Seed invalid policies
    for f in (policies_dir / "invalid").glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            policy = ZeroTrustPolicy.model_validate(data)
            repo.save_policy(policy)
            report = verifier.verify(policy)
            repo.save_report(report)
            print(f"[+] Loaded [INVALID] : {policy.policy_name} ({report.violations_count} violations)")
            count += 1
        except Exception as e:
            print(f"[-] Error loading {f.name}: {e}")

    print("=" * 60)
    print(f"Successfully seeded {count} policies and audit reports into storage.")
    print("=" * 60)


if __name__ == "__main__":
    seed()
