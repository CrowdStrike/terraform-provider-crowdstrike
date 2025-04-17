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


resource "crowdstrike_sensor_update_policy_host_group_attachment" "example" {
  id          = "34ef8e65eb1b4642861e389da3f7e82f"
  host_groups = ["ff1ca3nfr7899j1abf61c0448db28be5"]
}

output "sensor_update_policy_host_group_attachment" {
  value = crowdstrike_sensor_update_policy_host_group_attachment.example
}
