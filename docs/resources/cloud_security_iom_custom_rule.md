---
page_title: "crowdstrike_cloud_security_iom_custom_rule Resource - crowdstrike"
subcategory: "Falcon Cloud Security"
description: |-
  This resource manages custom cloud security IOM rules. These rules can be created either by inheriting properties from a parent rule with minimal customization, or by fully customizing all attributes for maximum flexibility. To create a rule based on a parent rule, utilize the crowdstrike_cloud_security_rules data source to gather parent rule information to use in the new custom rule. The crowdstrike_cloud_compliance_framework_controls data source can be used to query Falcon for custom compliance framework controls to associate with custom rules created with this resource.
  API Scopes
  The following API scopes are required:
  Cloud Security Policies | Read & Write
---

# crowdstrike_cloud_security_iom_custom_rule (Resource)

This resource manages custom cloud security IOM rules. These rules can be created either by inheriting properties from a parent rule with minimal customization, or by fully customizing all attributes for maximum flexibility. To create a rule based on a parent rule, utilize the `crowdstrike_cloud_security_rules` data source to gather parent rule information to use in the new custom rule. The `crowdstrike_cloud_compliance_framework_controls` data source can be used to query Falcon for custom compliance framework controls to associate with custom rules created with this resource. 

## API Scopes

The following API scopes are required:

- Cloud Security Policies | Read & Write


## Example Usage

```terraform
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
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `cloud_provider` (String) Cloud provider for the policy rule.
- `description` (String) Description of the policy rule.
- `name` (String) Name of the policy rule.
- `resource_type` (String) The full resource type. Examples: `AWS::IAM::CredentialReport`, `Microsoft.Compute/virtualMachines`, `container.googleapis.com/Cluster`

### Optional

- `alert_info` (List of String) A list of the alert logic and detection criteria for rule violations. Do not include numbering within this list. The Falcon console will automatically add numbering. When `alert_info` is not defined and `parent_rule_id` is defined, this field will inherit the parent rule's `alert_info`.
- `attack_types` (Set of String) Specific attack types associated with the rule. If `parent_rule_id` is defined, `attack_types` will be inherited from the parent rule and cannot be specified using this field.
- `controls` (Attributes Set) Custom compliance controls to associate with this rule. Only custom controls (authority `Custom`) are supported. Utilize the `crowdstrike_cloud_compliance_framework_controls` data source to obtain control codes from a custom framework. Controls are not inherited from `parent_rule_id`. (see [below for nested schema](#nestedatt--controls))
- `logic` (String) Rego logic for the rule. Either `logic` or `parent_rule_id` must be defined. When `parent_rule_id` is set, the rule inherits the Rego logic from the parent rule. Note: The API does not return Rego logic for rules created from a parent rule, so this field will not appear in state when using `parent_rule_id`.
- `parent_rule_id` (String) Id of the parent rule to copy. The rule uses the parent rule's Rego logic and `attack_types`, and inherits `alert_info` and `remediation_info` when they are not defined. `severity` and `controls` are not inherited. The `crowdstrike_cloud_security_rules` data source can be used to query Falcon for parent rule information to use in this field. Required if `logic` is not specified.
- `remediation_info` (List of String) Information about how to remediate issues detected by this rule. Do not include numbering within this list. The Falcon console will automatically add numbering. When `remediation_info` is not defined and `parent_rule_id` is defined, this field will inherit the parent rule's `remediation_info`.
- `severity` (String) Severity of the rule. Valid values are `critical`, `high`, `medium`, `informational`. Defaults to `critical`, including for rules created from `parent_rule_id`.

### Read-Only

- `cloud_platform` (String) Cloud platform for the policy rule.
- `id` (String) Unique identifier of the policy rule.

<a id="nestedatt--controls"></a>
### Nested Schema for `controls`

Required:

- `authority` (String) The compliance framework authority. Must be 'Custom'.
- `code` (String) The control code from the custom compliance framework.

## Import

Import is supported using the following syntax:

```shell
# Cloud Security IOM Custom Rule resources can be imported using their UUID, e.g.
terraform import crowdstrike_cloud_security_iom_custom_rule.example 123e4567-e89b-12d3-a456-426614174000
```
