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

resource "crowdstrike_cloud_azure_tenant" "org" {
  tenant_id                      = "00000000-0000-0000-0000-000000000000"
  microsoft_graph_permission_ids = ["9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"]
}

output "tenant_registration" {
  value = crowdstrike_cloud_azure_tenant.org
}
