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

resource "crowdstrike_content_update_policy_attachment" "example" {
  id          = "16c0eecfeebb47ce95185fda2e5b3112"
  host_groups = ["df868c936cd443e5a95b2603e2483602"]
  exclusive   = false
}

output "content_update_policy_attachment" {
  value = crowdstrike_content_update_policy_attachment.example
}
