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

# Custom rule derived from a parent rule with specific modifications
resource "crowdstrike_cloud_posture_custom_rule" "copy_rule" {
  resource_type  = "AWS::EC2::Instance"
  name           = "Test Terraform"
  description    = "Test Terraform"
  cloud_provider = "AWS"
  severity       = "informational"
  remediation_info = [
    "Remediation step 1",
    "Remediation step 2",
    "Remediation step 3",
  ]
  alert_info = [
    "First item in alert info",
    "Second item in alert info"
  ]
  controls = [
    {
      authority = "CIS",
      code      = "89"
    },
    {
      authority = "CIS",
      code      = "791"
    }
  ]
  parent_rule_id = "190c2d3d-8b0e-4838-bf11-4c6e044b9cb1"
}

resource "crowdstrike_cloud_posture_custom_rule" "custom_rule" {
  resource_type  = "AWS::EC2::Instance"
  name           = "Test Terraform"
  description    = "Test Terraform"
  cloud_provider = "AWS"
  attack_types = [
    "Attack Type 1",
    "Attack Type 2"
  ]
  remediation_info = [
    "Remediation step 1",
    "Remediation step 2",
    "Remediation step 3",
  ]
  severity = "medium"
  logic    = <<EOF
package crowdstrike
default result = "pass"
result = "fail" if {
  input.tags[_] == "catch-me"
}
EOF
  alert_info = [
    "First item in alert info",
    "Second item in alert info"
  ]
  controls = [
    {
      authority = "CIS",
      code      = "89"
    },
    {
      authority = "CIS",
      code      = "791"
    },
  ]
}
