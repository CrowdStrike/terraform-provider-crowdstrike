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

# Custom IOM rule derived from a parent rule with specific modifications
resource "crowdstrike_cloud_security_iom_custom_rule" "copy_rule" {
  resource_type  = "AWS::EC2::Instance"
  name           = "copy_rule"
  description    = "Test Terraform IOM Rule"
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

resource "crowdstrike_cloud_security_iom_custom_rule" "minimal_copy_rule" {
  resource_type  = "AWS::EC2::Instance"
  name           = "minimal_copy_rule"
  description    = "Test Terraform IOM Rule"
  cloud_provider = "AWS"
  severity       = "informational"
  parent_rule_id = "190c2d3d-8b0e-4838-bf11-4c6e044b9cb1"
}

resource "crowdstrike_cloud_security_iom_custom_rule" "custom_rule" {
  resource_type  = "AWS::EC2::Instance"
  name           = "custom_rule"
  description    = "Test Terraform IOM Rule"
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

# Custom IOM rule with Rego logic loaded from external file
resource "crowdstrike_cloud_security_iom_custom_rule" "custom_rule_from_file" {
  resource_type  = "AWS::S3::Bucket"
  name           = "custom_rule_from_file"
  description    = "Test Terraform IOM Rule with Rego logic from file"
  cloud_provider = "AWS"
  attack_types = [
    "Data Exposure",
    "Insecure Configuration"
  ]
  remediation_info = [
    "Review bucket encryption settings",
    "Enable server-side encryption",
    "Verify encryption configuration",
  ]
  severity = "high"
  logic    = file("${path.module}/policy.rego")
  alert_info = [
    "S3 bucket encryption is not enabled",
    "Bucket data may be exposed to unauthorized access"
  ]
  controls = [
    {
      authority = "CIS",
      code      = "2.1.1"
    },
  ]
}
