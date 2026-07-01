terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {
  cloud = "us-2"
}

# Example: ingest AWS CloudTrail logs (delivered to an S3 bucket and announced
# via an SQS queue) into CrowdStrike Falcon Next-Gen SIEM.
#
# The exact keys inside `config.auth` and `config.params` are specific to the
# connector identified by `connector_id`; the values below are illustrative.
resource "crowdstrike_ngsiem_data_connection" "aws_cloudtrail" {
  name         = "aws-cloudtrail-prod"
  connector_id = "aws-s3-sqs"
  log_sources  = ["cloudtrail"]
  description  = "AWS CloudTrail logs ingested from S3 via SQS notifications"

  vendor_name         = "aws"
  vendor_product_name = "cloudtrail"

  enable_host_enrichment = true
  enable_user_enrichment = true

  config = {
    name = "aws-cloudtrail-prod"

    # Authentication for the connector to assume into the source account.
    auth = jsonencode({
      role_arn    = "arn:aws:iam::123456789012:role/crowdstrike-ngsiem"
      external_id = "00000000-0000-0000-0000-000000000000"
    })

    # Connector parameters (bucket / queue / region for the AWS connector).
    params = jsonencode({
      region    = "us-east-1"
      s3_bucket = "my-org-cloudtrail-logs"
      sqs_url   = "https://sqs.us-east-1.amazonaws.com/123456789012/crowdstrike-siem-cloudtrail"
    })
  }
}

output "ngsiem_data_connection_id" {
  value = crowdstrike_ngsiem_data_connection.aws_cloudtrail.id
}
