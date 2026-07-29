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

# Look up the live membership of a host group by name
data "crowdstrike_host_group_members" "prod" {
  name = "Production"
}

# Look up the live membership of a host group by ID
data "crowdstrike_host_group_members" "by_id" {
  id = "dbe9c1fabd024fafaf44adf4df5f0f0f"
}

# Only count the Windows hosts in the group
data "crowdstrike_host_group_members" "prod_windows" {
  name   = "Production"
  filter = "platform_name:'Windows'"
}

output "prod_member_count" {
  value = data.crowdstrike_host_group_members.prod.member_count
}

output "prod_host_ids" {
  value = data.crowdstrike_host_group_members.prod.host_ids
}

# Fail the run when a host group that policies target is empty
check "prod_has_members" {
  assert {
    condition     = data.crowdstrike_host_group_members.prod.member_count > 0
    error_message = "Host group 'Production' has no attached hosts."
  }
}
