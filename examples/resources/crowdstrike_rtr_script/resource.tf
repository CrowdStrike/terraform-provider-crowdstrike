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

resource "crowdstrike_rtr_script" "cleanup" {
  name            = "cleanup-temp-files"
  description     = "Removes temporary files from common locations"
  content         = file("${path.module}/scripts/cleanup.ps1")
  platform_name   = "Windows"
  permission_type = "group"

  comments_for_audit_log = "Initial upload via Terraform"
}

output "rtr_script" {
  value = crowdstrike_rtr_script.cleanup
}
