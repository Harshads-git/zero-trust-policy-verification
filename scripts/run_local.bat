@echo off
echo ==========================================================
echo Starting Zero Trust Policy Verification Engine (ZTPVE)
echo ==========================================================

REM Check if dependencies are present
python -c "import fastapi, uvicorn" 2>nul
if %errorlevel% neq 0 (
    echo [!] Installing required dependencies...
    pip install -r requirements.txt
)

echo [*] Seeding database with initial policies...
python scripts/seed_policies.py

echo [*] Starting FastAPI server on http://localhost:8000
echo [*] Interactive Visualizer Dashboard: http://localhost:8000
echo [*] Interactive OpenAPI Documentation: http://localhost:8000/docs
echo ==========================================================
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
