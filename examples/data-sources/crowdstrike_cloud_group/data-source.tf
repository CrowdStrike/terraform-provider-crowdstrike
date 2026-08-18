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

# Look up a cloud group by its UUID.
data "crowdstrike_cloud_group" "by_id" {
  id = "d3adb33f-dead-beef-dead-beefdeadbeef"
}

# Look up a cloud group with an FQL filter. Group names are unique within a CID,
# so an equality filter on name resolves at most one group.
data "crowdstrike_cloud_group" "by_name" {
  filter = "name:'Production Accounts'"
}

output "prod_accounts_owners" {
  value = data.crowdstrike_cloud_group.by_name.owners
}
