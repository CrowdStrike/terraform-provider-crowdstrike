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

# List every available Next-Gen SIEM data connector.
data "crowdstrike_ngsiem_data_connectors" "all" {}

# Resolve a specific connector's ID by its exact name (use as connector_id on a data connection).
data "crowdstrike_ngsiem_data_connectors" "hec" {
  by_name = "HEC / HTTP Event Connector"
}

output "all_connectors" {
  value = data.crowdstrike_ngsiem_data_connectors.all.connectors
}

output "hec_connector_id" {
  value = data.crowdstrike_ngsiem_data_connectors.hec.id
}
