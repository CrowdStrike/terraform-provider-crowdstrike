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


resource "crowdstrike_cloud_security_kac_policy" "example" {
  name        = "example-kac-policy"
  description = "An example KAC policy created with Terraform"
  is_enabled  = true
  host_groups = [
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    "f47ac10b58cc4372a5670e4cn521b862",
  ]
  rule_groups = [
    {
      name          = "example-rule-group"
      description   = "An example rule group"
      deny_on_error = false
      image_assessment = {
        enabled             = true
        unassessed_handling = "Alert"
      }
      labels = [
        {
          key      = "pd*",
          value    = "abc*",
          operator = "neq"
        }
      ]
      namespaces = ["abc*"]
      default_rules = {
        privileged_container = {
          action = "Prevent"
        }
        sensitive_data_in_environment = {
          action = "Disabled"
        }
      }
    }
  ]
  default_rule_group = {
    deny_on_error = false
    image_assessment = {
      enabled = false
    }
    default_rule_overrides = {
      container_run_as_root = {
        action = "Prevent"
      }
    }
  }
}

output "cloud_security_kac_policy" {
  value = crowdstrike_cloud_security_kac_policy.example
}
