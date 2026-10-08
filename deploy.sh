#!/usr/bin/env bash
# Zero Trust Policy Verification Engine (ZTPVE)
# One-Click Production Deployment Shell Script

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "==========================================================================="
echo "  Deploying Zero Trust Policy Verification Engine (ZTPVE)"
echo "==========================================================================="

python3 scripts/deploy.py "$@"
