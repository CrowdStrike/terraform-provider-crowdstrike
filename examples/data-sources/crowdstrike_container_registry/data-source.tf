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

data "crowdstrike_container_registry" "example" {
  id = "7fb858a949034a0cbca175f660f1e769"
}

output "container_registry" {
  value = data.crowdstrike_container_registry.example
}
