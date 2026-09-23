output "dynamodb_policies_table" {
  description = "Name of the DynamoDB policy table"
  value       = aws_dynamodb_table.policies_table.name
}

output "dynamodb_reports_table" {
  description = "Name of the DynamoDB reports table"
  value       = aws_dynamodb_table.reports_table.name
}

output "s3_website_endpoint" {
  description = "HTTP endpoint for the static frontend"
  value       = aws_s3_bucket_website_configuration.frontend_website.website_endpoint
}

output "backend_iam_role_arn" {
  description = "Least privilege IAM execution role ARN"
  value       = aws_iam_role.backend_execution_role.arn
}
