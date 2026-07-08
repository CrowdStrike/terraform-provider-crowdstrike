terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {}

resource "crowdstrike_ngsiem_data_connector_config" "s3_access_logs" {
  # AWS S3 Access Log Data Connector from the connector catalog.
  connector_id = "07d3b89a204f41d988e198bd2d6536d8"
  name         = "prod-s3-access-logs"

  # Per-connector parameters, encoded as JSON. The exact shape is validated
  # server-side per connector. For AWS S3 the fields are account_id, sqs_name,
  # region, bucket, and prefix, plus an authentication_method that gates further
  # required fields.
  params = jsonencode({
    account_id            = "123456789012"
    bucket                = "my-access-log-bucket"
    prefix                = "logs/"
    region                = "us-east-1"
    sqs_name              = "my-s3-notification-queue"
    authentication_method = "iam_assume_role"
    iam_assume_role       = "arn:aws:iam::123456789012:role/crowdstrike-s3-ingest"
  })
}
