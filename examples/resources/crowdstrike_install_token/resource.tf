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

# Create an installation token that never expires
resource "crowdstrike_install_token" "example" {
  name = "Production Deployment Token"
}

# Create an installation token with expiration
resource "crowdstrike_install_token" "temporary" {
  name              = "Temporary QA Token"
  expires_timestamp = "2026-12-31T23:59:59Z"
}

# Revoke an installation token
resource "crowdstrike_install_token" "revoked" {
  name    = "Old Token"
  revoked = true
}
