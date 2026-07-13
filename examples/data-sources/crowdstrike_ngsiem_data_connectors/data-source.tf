terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {}

# All connectors.
data "crowdstrike_ngsiem_data_connectors" "all" {}

# Only pull connectors.
data "crowdstrike_ngsiem_data_connectors" "pull" {
  filter = "type:'PULL'"
}

# Compose filters with FQL: AWS pull connectors only.
data "crowdstrike_ngsiem_data_connectors" "aws_pull" {
  filter = "type:'PULL'+vendor_name:'AmazonWebServices'"
}

# Build a name -> connector lookup to drive connections.
locals {
  connectors_by_name = {
    for c in data.crowdstrike_ngsiem_data_connectors.all.connectors : c.name => c
  }
}

output "connector_names" {
  value = [for c in data.crowdstrike_ngsiem_data_connectors.all.connectors : c.name]
}
