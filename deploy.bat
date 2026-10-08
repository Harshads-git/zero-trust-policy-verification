@echo off
REM Zero Trust Policy Verification Engine (ZTPVE)
REM One-Click Windows Deployment Script

cd /d "%~dp0"
echo ===========================================================================
echo   Deploying Zero Trust Policy Verification Engine (ZTPVE)
echo ===========================================================================

python scripts\deploy.py %*
