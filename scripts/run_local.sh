#!/usr/bin/env bash
set -e

echo "=========================================================="
echo "Starting Zero Trust Policy Verification Engine (ZTPVE)"
echo "=========================================================="

python3 -c "import fastapi, uvicorn" 2>/dev/null || {
    echo "[!] Installing dependencies..."
    pip install -r requirements.txt
}

echo "[*] Seeding database with initial policies..."
python3 scripts/seed_policies.py

echo "[*] Starting FastAPI server on http://localhost:8000"
echo "=========================================================="
python3 -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
