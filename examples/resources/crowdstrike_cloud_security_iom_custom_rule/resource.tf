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

# Only controls from a custom compliance framework (authority "Custom") can be
# assigned to custom rules. Look up the control codes by control name.
data "crowdstrike_cloud_compliance_framework_controls" "custom" {
  fql = "compliance_control_authority:'Custom'+compliance_control_benchmark_name:'Example Custom Framework'"
}

locals {
  custom_control_codes = {
    for control in data.crowdstrike_cloud_compliance_framework_controls.custom.controls : control.name => control.code
  }
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
      authority = "Custom",
      code      = local.custom_control_codes["Restrict instance network access"]
    },
    {
      authority = "Custom",
      code      = local.custom_control_codes["Require approved instance images"]
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
      authority = "Custom",
      code      = local.custom_control_codes["Restrict instance network access"]
    },
    {
      authority = "Custom",
      code      = local.custom_control_codes["Require approved instance images"]
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
      authority = "Custom",
      code      = local.custom_control_codes["Encrypt storage at rest"]
    },
  ]
}
