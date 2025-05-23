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

resource "crowdstrike_cloud_azure_tenant" "tenant" {
  tenant_id                      = "00000000-0000-0000-0000-000000000003"
  microsoft_graph_permission_ids = ["9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"]
  realtime_visibility = {
    enabled = true
  }
}


resource "crowdstrike_cloud_azure_tenant_eventhub_settings" "eventhub" {
  tenant_id = crowdstrike_cloud_azure_tenant.tenant.tenant_id
  settings = [
    {
      type           = "activity_logs",
      id             = "1234",
      consumer_group = "idk"
    },
    {
      type           = "entra_logs",
      id             = "1234",
      consumer_group = "idk"
    },
  ]
  depends_on = [crowdstrike_cloud_azure_tenant.tenant]
}

output "eventhub_settings" {
  value = crowdstrike_cloud_azure_tenant_eventhub_settings.eventhub
}
