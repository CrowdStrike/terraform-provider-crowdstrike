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

resource "crowdstrike_certificate_based_exclusion" "example" {
  name             = "example-certificate-exclusion"
  applied_globally = true

  certificate {
    issuer     = "CN=Example Issuer,O=Example Corp,C=US"
    serial     = "1234567890"
    subject    = "CN=Example Subject,O=Example Corp,C=US"
    thumbprint = "example-thumbprint"
    valid_from = "2024-01-01T00:00:00Z"
    valid_to   = "2026-01-01T00:00:00Z"
  }
}
