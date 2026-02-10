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

resource "crowdstrike_prevention_policy_attachment" "example" {
  id              = "16c0eecfeebb47ce95185fda2e5b3112"
  host_groups     = ["df868c936cd443e5a95b2603e2483602"]
  ioa_rule_groups = ["507117bc669d41bb93d0a009f557bb23"]
  exclusive       = false
}

output "prevention_policy_attachment" {
  value = crowdstrike_prevention_policy_attachment.example
}
