terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "ZeroTrustPolicyVerification"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# 1. DynamoDB: Policy Storage Table (AWS Free Tier: 25 RCU / 25 WCU)
resource "aws_dynamodb_table" "policies_table" {
  name         = "zero_trust_policies"
  billing_mode = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
  hash_key     = "policy_id"

  attribute {
    name = "policy_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false # Disabled to stay 100% Free Tier
  }
}

# 2. DynamoDB: Verification Reports Table
resource "aws_dynamodb_table" "reports_table" {
  name         = "zero_trust_audit_reports"
  billing_mode = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
  hash_key     = "report_id"

  attribute {
    name = "report_id"
    type = "S"
  }
}

# 3. S3 Bucket for Static Frontend Web Dashboard
resource "aws_s3_bucket" "frontend_bucket" {
  bucket_prefix = "ztpve-frontend-"
  force_destroy = true
}

resource "aws_s3_bucket_website_configuration" "frontend_website" {
  bucket = aws_s3_bucket.frontend_bucket.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "index.html"
  }
}

resource "aws_s3_bucket_public_access_block" "public_access" {
  bucket = aws_s3_bucket.frontend_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "frontend_public_read" {
  depends_on = [aws_s3_bucket_public_access_block.public_access]
  bucket     = aws_s3_bucket.frontend_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.frontend_bucket.arn}/*"
      }
    ]
  })
}

# 4. CloudWatch Log Group for Audit Monitoring (Free Tier: 5GB retention)
resource "aws_cloudwatch_log_group" "ztpve_logs" {
  name              = "/aws/ztpve/api-audit"
  retention_in_days = 14
}

# 5. IAM Role with Least Privilege
resource "aws_iam_role" "backend_execution_role" {
  name = "ztpve_backend_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = ["lambda.amazonaws.com", "ec2.amazonaws.com"]
        }
      }
    ]
  })
}

resource "aws_iam_policy" "backend_least_privilege" {
  name        = "ztpve_least_privilege_policy"
  description = "Allows access only to ZTPVE DynamoDB tables and CloudWatch Logs"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Scan",
          "dynamodb:DeleteItem"
        ]
        Resource = [
          aws_dynamodb_table.policies_table.arn,
          aws_dynamodb_table.reports_table.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.ztpve_logs.arn}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_least_privilege" {
  role       = aws_iam_role.backend_execution_role.name
  policy_arn = aws_iam_policy.backend_least_privilege.arn
}
