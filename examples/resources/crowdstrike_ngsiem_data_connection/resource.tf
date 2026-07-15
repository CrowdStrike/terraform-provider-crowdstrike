terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {}

# Reusable connector config (see crowdstrike_ngsiem_data_connector_config).
resource "crowdstrike_ngsiem_data_connector_config" "s3" {
  connector_id = "07d3b89a204f41d988e198bd2d6536d8"
  name         = "prod-s3-access-logs"
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

# Look up the connector to get its id and default parser.
data "crowdstrike_ngsiem_data_connector" "s3" {
  name = "Amazon S3 Access Log Data Connector"
}

# PULL connection referencing the config by id.
resource "crowdstrike_ngsiem_data_connection" "s3_access_logs" {
  name         = "prod-s3-access-logs"
  connector_id = data.crowdstrike_ngsiem_data_connector.s3.id
  config_id    = crowdstrike_ngsiem_data_connector_config.s3.id

  # parser is REQUIRED; use the connector's first supported parser from the data source.
  parser = data.crowdstrike_ngsiem_data_connector.s3.parsers[0]

  # Both enrichment flags are REQUIRED with no default. The console defaults
  # these to true, but this resource forces an explicit choice.
  enable_host_enrichment = true
  enable_user_enrichment = true

  description = "Production S3 server-access logs"
}

# PUSH connection (HEC / HTTP Event Connector): no config, exposes an ingest URL.
resource "crowdstrike_ngsiem_data_connection" "hec" {
  name         = "app-hec-ingest"
  connector_id = "a1bfd0c4380f436790cb41afc2b95f38"
  parser       = "aws-elb" # required: supply a valid parser name from the catalog

  enable_host_enrichment = false
  enable_user_enrichment = false
}
