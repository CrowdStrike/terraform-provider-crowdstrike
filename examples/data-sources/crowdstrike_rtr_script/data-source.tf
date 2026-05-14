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

# Look up an RTR script by name
data "crowdstrike_rtr_script" "by_name" {
  name = "my-rtr-script"
}

# Look up an RTR script by ID
data "crowdstrike_rtr_script" "by_id" {
  id = "dbe9c1fabd024fafaf44adf4df5f0f0f"
}

output "rtr_script_content" {
  value = data.crowdstrike_rtr_script.by_name.content
}
