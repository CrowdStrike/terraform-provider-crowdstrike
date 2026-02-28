resource "crowdstrike_data_protection_policy" "example" {
  name          = "example-data-protection-policy"
  description   = "Example Falcon Data Protection policy managed by Terraform."
  platform_name = "win"
  enabled       = false
  precedence    = 1

  policy_properties {
    classifications               = ["classification-id"]
    enable_content_inspection     = true
    min_confidence_level          = "medium"
    max_file_size_to_inspect      = 10
    max_file_size_to_inspect_unit = "MB"
  }
}
