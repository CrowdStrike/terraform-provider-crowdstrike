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

variable "user_password" {
  description = "Initial password for the Falcon user."
  type        = string
  sensitive   = true
}

# Create a user with an initial password.
#
# password_wo is write-only and is never stored in state. Because the Falcon
# API has no in-place password-change endpoint, changing the password requires
# replacing the user: increment password_wo_version to apply a new password
# (this deletes and recreates the user with a new UUID).
resource "crowdstrike_user" "with_password" {
  email               = "jane.doe@example.com"
  first_name          = "Jane"
  last_name           = "Doe"
  password_wo         = var.user_password
  password_wo_version = 1
}

# Create a user without a password. When SSO is not enabled, CrowdStrike sends
# the user an automated email prompting them to create a password and configure
# MFA.
resource "crowdstrike_user" "invite" {
  email      = "john.smith@example.com"
  first_name = "John"
  last_name  = "Smith"
}
