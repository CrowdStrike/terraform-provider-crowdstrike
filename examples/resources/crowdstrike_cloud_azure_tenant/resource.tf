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
  tenant_id                      = "00000000-0000-0000-0000-000000000003"
  microsoft_graph_permission_ids = ["9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"]
  realtime_visibility = {
    enabled = true
  }
  resource_name_prefix = "1234567"
  environment          = "123"
  management_group_ids = []
  subscription_ids     = ["00000000-0000-0000-0000-000000000002"]
  tags = {
    "tag1" = "value1-one"
    "tag2" = "value2"
    "tag3" = "value2"
  }
}

output "tenant_registration" {
  value = crowdstrike_cloud_azure_tenant.org.cs_azure_client_id
}
