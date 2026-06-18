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

# Resolve the HEC connector's ID by name.
data "crowdstrike_ngsiem_data_connectors" "hec" {
  by_name = "HEC / HTTP Event Connector"
}

resource "crowdstrike_ngsiem_data_connection" "example" {
  name         = "example-hec-collector"
  connector_id = data.crowdstrike_ngsiem_data_connectors.hec.id
  parser       = "aws-cloudtrail"
  description  = "Example HEC data connection managed by Terraform"
}

output "ingest_url" {
  value = crowdstrike_ngsiem_data_connection.example.ingest_url
}

# The ingest token is sensitive and generated once at creation.
output "ingest_token" {
  value     = crowdstrike_ngsiem_data_connection.example.ingest_token
  sensitive = true
}
