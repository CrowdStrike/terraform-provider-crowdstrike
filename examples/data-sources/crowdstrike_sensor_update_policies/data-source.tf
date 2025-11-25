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

# Output IDs of policies with build turned off (null)
output "policy_ids_with_build_off" {
  value = [
    for policy in data.crowdstrike_sensor_update_policies.all.policies :
    policy.id if policy.build == null
  ]
}

# Output IDs of Linux policies with ARM64 builds turned off (null)
output "linux_policy_ids_with_arm64_off" {
  value = [
    for policy in data.crowdstrike_sensor_update_policies.all.policies :
    policy.id if policy.platform_name == "Linux" && policy.build_arm64 == null
  ]
}

# Output IDs of all policies with any build turned off (standard or ARM64)
output "all_policy_ids_with_builds_off" {
  value = setunion(
    [
      for policy in data.crowdstrike_sensor_update_policies.all.policies :
      policy.id if policy.build == null
    ],
    [
      for policy in data.crowdstrike_sensor_update_policies.all.policies :
      policy.id if policy.platform_name == "Linux" && policy.build_arm64 == null
    ]
  )
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
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"
  ]
}

