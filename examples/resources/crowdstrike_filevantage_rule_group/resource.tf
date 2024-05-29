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


resource "crowdstrike_filevantage_rule_group" "example" {
  name        = "example_filevantage_policy"
  description = "made with terraform"
  type        = "WindowsRegistry"
  rules = [
    {
      description                 = "first rule"
      path                        = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\"
      severity                    = "High"
      depth                       = "ANY"
      registry_values             = ["first", "rule"]
      watch_key_value_set_changes = true
    },
    {
      description                 = "second rule"
      path                        = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\"
      severity                    = "High"
      depth                       = "ANY"
      registry_values             = ["Value1", "Value2"]
      watch_key_value_set_changes = true
    },
  ]
}

output "filevantage_rule_group" {
  value = crowdstrike_filevantage_rule_group.example
}
