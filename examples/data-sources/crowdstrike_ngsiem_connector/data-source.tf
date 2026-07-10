terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {}

data "crowdstrike_ngsiem_connector" "s3_access_logs" {
  name = "Amazon S3 Access Log Data Connector"
}

output "connector_id" {
  value = data.crowdstrike_ngsiem_connector.s3_access_logs.id
}

output "parsers" {
  value = data.crowdstrike_ngsiem_connector.s3_access_logs.parsers
}
