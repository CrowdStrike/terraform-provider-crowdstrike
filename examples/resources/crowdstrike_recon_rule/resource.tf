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

resource "crowdstrike_recon_rule" "example" {
  name        = "example-recon-rule"
  topic       = "SA_CVE"
  filter      = "(phrase:'CVE-2024-1234')"
  priority    = "high"
  permissions = "private"

  notification {
    content_format = "enhanced"
    frequency      = "asap"
    recipients     = ["security-team@example.com"]
  }

  notification {
    content_format = "standard"
    frequency      = "weekly"
    recipients     = ["management@example.com", "compliance@example.com"]
  }
}

output "recon_rule" {
  value = crowdstrike_recon_rule.example
}
