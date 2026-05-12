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

# Look up an RTR put file by name
data "crowdstrike_rtr_put_file" "by_name" {
  name = "my-put-file"
}

# Look up an RTR put file by ID
data "crowdstrike_rtr_put_file" "by_id" {
  id = "abc123def456"
}

output "put_file_sha256" {
  value = data.crowdstrike_rtr_put_file.by_name.sha256
}
