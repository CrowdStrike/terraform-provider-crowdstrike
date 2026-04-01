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

# List all lookup files in the "all" repository
data "crowdstrike_ngsiem_lookup_files" "all_files" {
  repository = "all"
}

# List lookup files matching a name filter
data "crowdstrike_ngsiem_lookup_files" "network_files" {
  repository = "all"
  filter     = "name:~'network'"
}

output "all_lookup_files" {
  value = data.crowdstrike_ngsiem_lookup_files.all_files.lookup_files
}
