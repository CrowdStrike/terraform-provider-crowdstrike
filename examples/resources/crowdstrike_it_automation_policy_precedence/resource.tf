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

resource "crowdstrike_it_automation_policy_precedence" "strict_example" {
  platform_name = "Windows"
  enforcement   = "strict"

  # Strict requires ALL policy IDs to be specified.
  ids = [
    "717cc96f8c5240bd8126f58153a8b13f",
    "acc1c69c65ac4a238406f75d6adee02e",
    "ce5779ce62aa4e6fbb647abd45193d11",
    "9d2f8e1a3b5c4e6f7890123456789abc",
    "4a7b2c8d9e0f1234567890abcdef5678",
    "f8e9d0c1b2a3456789012345678901de",
  ]
}

resource "crowdstrike_it_automation_policy_precedence" "dynamic_example" {
  platform_name = "Linux"
  enforcement   = "dynamic"

  ids = [
    "859448168fe947d781798b090402479c",
    "2b5ecfeb8dc24a73bb3a51c76cfbd02e",
  ]
}

output "strict_policy_precedence" {
  value = crowdstrike_it_automation_policy_precedence.strict_example
}

output "dynamic_policy_precedence" {
  value = crowdstrike_it_automation_policy_precedence.dynamic_example
}
