#!/usr/bin/env bash
# AWS Free Tier Deployment Automation for ZTPVE
set -e

echo "=========================================================="
echo "ZTPVE: AWS Free Tier Cloud Deployment"
echo "=========================================================="

REGION="${AWS_REGION:-us-east-1}"
STACK_NAME="ztpve-free-tier-stack"

echo "[1/3] Validating AWS CLI identity..."
aws sts get-caller-identity > /dev/null || { echo "Error: AWS credentials not found. Run 'aws configure'."; exit 1; }

echo "[2/3] Deploying CloudFormation Stack ($STACK_NAME in $REGION)..."
aws cloudformation deploy \
  --template-file infrastructure/cloudformation/template.yaml \
  --stack-name "$STACK_NAME" \
  --capabilities CAPABILITY_NAMED_IAM \
  --region "$REGION"

echo "[3/3] Deployment complete. Querying stack outputs..."
aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query "Stacks[0].Outputs" \
  --output table

echo "=========================================================="
echo "Deployment Successful! Configure STORAGE_BACKEND=dynamodb in .env"
echo "=========================================================="
