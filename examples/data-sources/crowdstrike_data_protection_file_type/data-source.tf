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

# Look up a file type by name.
data "crowdstrike_data_protection_file_type" "by_name" {
  name = "PDF"
}

# Look up a file type by ID.
data "crowdstrike_data_protection_file_type" "by_id" {
  id = "00000000-0000-0000-0000-000000000000"
}

output "file_type" {
  value = data.crowdstrike_data_protection_file_type.by_name
}
