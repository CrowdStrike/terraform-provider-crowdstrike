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


resource "crowdstrike_prevention_policy_precedence" "example" {
  ids           = ["622205fedad649b5846c85abc45783c7"]
  platform_name = "linux"
  enforcement   = "strict"
}

output "prevention_policy_precedence" {
  value = crowdstrike_prevention_policy_precedence.example
}
