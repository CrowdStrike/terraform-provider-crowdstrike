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

# Look up a tenant by its Azure tenant ID (directory ID).
data "crowdstrike_cloud_azure_tenant" "by_tenant_id" {
  tenant_id = "00000000-0000-0000-0000-000000000000"
}

# Look up a tenant by its Falcon Cloud Security registration ID.
data "crowdstrike_cloud_azure_tenant" "by_registration_id" {
  registration_id = "abcd1234-0000-0000-0000-000000000000"
}

output "azure_tenant" {
  value = {
    registration_id = data.crowdstrike_cloud_azure_tenant.by_tenant_id.registration_id

    cs_infra_subscription_id = data.crowdstrike_cloud_azure_tenant.by_tenant_id.cs_infra_subscription_id
    cs_infra_location        = data.crowdstrike_cloud_azure_tenant.by_tenant_id.cs_infra_location

    realtime_visibility_enabled = data.crowdstrike_cloud_azure_tenant.by_tenant_id.realtime_visibility.enabled
  }
}

# Event Hub settings come back with the tenant, and are empty when none are
# attached.
output "activity_log_consumer_groups" {
  value = [
    for setting in data.crowdstrike_cloud_azure_tenant.by_tenant_id.eventhub_settings :
    setting.consumer_group if setting.type == "activity_logs"
  ]
}
