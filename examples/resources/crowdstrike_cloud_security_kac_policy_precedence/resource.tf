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


resource "crowdstrike_cloud_security_kac_policy_precedence" "example" {
  ids = [
    "a1j09y3yq0wnrpb5o6jlij9e4f40k6lq",
    "2asia54xti93bg0jbr5hfpqqbhxbyeoa",
    "xuzq8hs1uyc2s7zdar3fli0shiyl22vc",
  ]
}

output "cloud_security_kac_policy_precedence" {
  value = crowdstrike_cloud_security_kac_policy_precedence.example
}
