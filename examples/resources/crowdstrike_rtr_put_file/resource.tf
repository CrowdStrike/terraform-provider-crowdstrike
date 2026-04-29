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

resource "crowdstrike_rtr_put_file" "remediation_script" {
  name           = "remediation.ps1"
  source         = "${path.module}/files/remediation.ps1"
  description    = "PowerShell remediation script for incident response"
  content_sha256 = filesha256("${path.module}/files/remediation.ps1")

  comments_for_audit_log = "Managed by Terraform"
}

output "rtr_put_file_id" {
  value = crowdstrike_rtr_put_file.remediation_script.id
}
