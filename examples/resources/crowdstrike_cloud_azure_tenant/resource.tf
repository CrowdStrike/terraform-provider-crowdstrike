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
  tenant_id                      = "00000000-0000-0000-0000-000000000002"
  microsoft_graph_permission_ids = ["9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"]
  realtime_visibility = {
    enabled = true
  }
  resource_name_prefix = "1"
  # resource_name_suffix = "1"
  environment          = "test123456"
  management_group_ids = ["0000000", "2"]
  subscription_ids     = ["00000000-0000-0000-0000-000000000009", "00000000-0000-0000-0000-000000000001"]
  # tags = {
  #   "tag1" = "value1-one"
  #   "tag2" = "value2"
  #   "tag3" = "value2"
  # }
}

output "tenant_registration" {
  value = crowdstrike_cloud_azure_tenant.org
}
