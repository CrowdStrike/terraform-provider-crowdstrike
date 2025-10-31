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

# return all container registries
data "crowdstrike_container_registries" "all" {}

# return specific container registries by ID
data "crowdstrike_container_registries" "filtered" {
  ids = [
    "12345678-1234-1234-1234-123456789abc",
    "87654321-4321-4321-4321-cba987654321"
  ]
}

output "all_registries" {
  value = data.crowdstrike_container_registries.all.registries
}

output "filtered_registries" {
  value = data.crowdstrike_container_registries.filtered.registries
}
