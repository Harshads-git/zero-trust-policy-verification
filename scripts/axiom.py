#!/usr/bin/env python3
"""
AxiomTrust Shift-Left CLI Runner
Quick executable entrypoint for CI/CD pipelines, pre-commit hooks, and terminal audits.
"""

import sys
from pathlib import Path

# Ensure root directory is on PYTHONPATH
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.cli.axiom_cli import main

if __name__ == "__main__":
    sys.exit(main())
