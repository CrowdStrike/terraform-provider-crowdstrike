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

# Look up a container registry by its UUID.
data "crowdstrike_container_registry" "by_id" {
  id = "f0bb103e-f9ae-4d88-8fb3-c61caf1f3b89"
}

# Or look it up by its user-defined alias (must match exactly one registry).
data "crowdstrike_container_registry" "by_alias" {
  user_defined_alias = "My Docker Hub"
}

output "container_registry" {
  value = data.crowdstrike_container_registry.by_id
}
