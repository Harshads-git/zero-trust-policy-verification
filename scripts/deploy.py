#!/usr/bin/env python3
"""
Zero Trust Policy Verification Engine (ZTPVE)
Automated Production & Demonstration Deployment Orchestrator

Performs end-to-end setup:
1. Environment & Python Runtime Validation (>= 3.10)
2. Dependency Verification (requirements.txt)
3. Database Initialization & Policy Seeding
4. Automated Pytest Verification Suite Execution (71 Tests)
5. Service Bootstrapping (FastAPI on Port 8000)
"""

import sys
import os
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ANSI Colors
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def log_step(msg: str):
    print(f"\n{BOLD}{CYAN}==> [DEPLOY] {msg}{RESET}")


def check_python_version():
    log_step("Validating Python Runtime...")
    major, minor = sys.version_info.major, sys.version_info.minor
    print(f"    Detected Python version: {major}.{minor}.{sys.version_info.micro}")
    if major < 3 or (major == 3 and minor < 10):
        print(f"{RED}Error: Python 3.10 or higher is required. Found {major}.{minor}{RESET}")
        sys.exit(1)
    print(f"    {GREEN}Python version compatible.{RESET}")


def install_dependencies():
    log_step("Checking and Installing Dependencies...")
    req_file = PROJECT_ROOT / "requirements.txt"
    if not req_file.exists():
        print(f"{RED}Error: requirements.txt not found at {req_file}{RESET}")
        sys.exit(1)
    
    cmd = [sys.executable, "-m", "pip", "install", "-r", str(req_file)]
    res = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True)
    if res.returncode != 0:
        print(f"{YELLOW}Warning: pip install returned non-zero. Output:\n{res.stderr}{RESET}")
    else:
        print(f"    {GREEN}Dependencies verified successfully.{RESET}")


def seed_database():
    log_step("Initializing Database & Seeding Standard Policies...")
    seeder = PROJECT_ROOT / "scripts" / "seed_policies.py"
    cmd = [sys.executable, str(seeder)]
    res = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True)
    if res.returncode != 0:
        print(f"{RED}Error seeding database:\n{res.stderr}{RESET}")
        sys.exit(1)
    print(f"    {GREEN}Database schema initialized and sample policies seeded.{RESET}")


def run_tests():
    log_step("Executing Full Pytest Verification Suite (71 Tests)...")
    cmd = [sys.executable, "-m", "pytest", "backend/tests", "-q"]
    res = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True)
    print(res.stdout)
    if res.returncode != 0:
        print(f"{RED}Test suite failed. Deployment aborted.{RESET}")
        print(res.stderr)
        sys.exit(1)
    print(f"    {GREEN}All 71 automated tests PASSED (100% pass rate).{RESET}")


def start_server(host: str = "127.0.0.1", port: int = 8000):
    log_step(f"Launching FastAPI Server on http://{host}:{port} ...")
    print(f"\n{BOLD}{GREEN}==============================================================={RESET}")
    print(f"{BOLD}{GREEN}  Zero Trust Policy Verification Engine is LIVE!{RESET}")
    print(f"  - Web Interface:        http://{host}:{port}")
    print(f"  - Swagger API Docs:     http://{host}:{port}/docs")
    print(f"  - Redoc API Docs:       http://{host}:{port}/redoc")
    print(f"{BOLD}{GREEN}==============================================================={RESET}\n")
    print("Press Ctrl+C to stop the server.\n")

    cmd = [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", host, "--port", str(port)]
    try:
        subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Server stopped by user.{RESET}")


def main():
    print(f"""{BOLD}{CYAN}
===========================================================================
  ZTPVE AUTOMATED DEPLOYMENT & VERIFICATION ORCHESTRATOR
  NIST SP 800-207 Zero Trust Policy Verification Engine (Capstone Final)
===========================================================================
{RESET}""")

    check_python_version()
    install_dependencies()
    seed_database()
    run_tests()

    if "--no-serve" in sys.argv:
        print(f"\n{GREEN}{BOLD}Deployment validation complete (--no-serve flag detected). Ready for production.{RESET}")
    elif "--demo" in sys.argv:
        print(f"\n{CYAN}{BOLD}Launching interactive demonstration showcase...{RESET}")
        demo_script = PROJECT_ROOT / "run_demo.py"
        subprocess.run([sys.executable, str(demo_script)], cwd=str(PROJECT_ROOT))
    else:
        start_server()


if __name__ == "__main__":
    main()
