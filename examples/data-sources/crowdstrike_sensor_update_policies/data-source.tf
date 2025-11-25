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

# Get all sensor update policies
data "crowdstrike_sensor_update_policies" "all" {}

# Output policies with null descriptions
output "policies_with_null_description" {
  value = [
    for policy in data.crowdstrike_sensor_update_policies.all.policies :
    policy if policy.description == null
  ]
}

# Get only enabled policies
data "crowdstrike_sensor_update_policies" "enabled" {
  enabled = true
}

# Get policies for a specific platform
data "crowdstrike_sensor_update_policies" "windows_policies" {
  platform_name = "Windows"
}

# Get policies using FQL filter
data "crowdstrike_sensor_update_policies" "filtered" {
  filter = "enabled:true+platform_name:'Linux'"
}

# Get policies sorted by name
data "crowdstrike_sensor_update_policies" "sorted" {
  sort = "name.asc"
}

# Get specific policies by ID
data "crowdstrike_sensor_update_policies" "specific" {
  ids = [
    "policy-id-1",
    "policy-id-2"
  ]
}

# Filter by name pattern
data "crowdstrike_sensor_update_policies" "by_name" {
  name = "production"
}

# Filter by description
data "crowdstrike_sensor_update_policies" "by_description" {
  description = "critical"
}
