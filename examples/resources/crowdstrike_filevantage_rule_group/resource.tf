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


# resource "crowdstrike_filevantage_rule_group" "example" {
#   name        = "example_filevantage_policy"
#   description = "made with terraform"
#   type        = "WindowsFiles"
# }
resource "crowdstrike_filevantage_rule_group" "w" {
  name        = "example_filevantage_policy"
  description = "made with terraform"
  type        = "WindowsRegistry"
  # rules = [
  # {
  #   description                 = "example rule"
  #   path                        = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\"
  #   severity                    = "High"
  #   depth                       = "ANY"
  #   registry_values             = ["Value1", "Value2"]
  #   watch_key_value_set_changes = true
  # },
  # ]
}
# resource "crowdstrike_filevantage_rule_group" "l" {
#   name        = "example_filevantage_policy"
#   description = "made with terraform"
#   type        = "LinuxFiles"
#   rules = [
#     {
#       description              = "example rule"
#       path                     = "/etc/dev"
#       severity                 = "high"
#       file_content             = "123"
#       watch_file_write_changes = true
#     },
#   ]
# }
# resource "crowdstrike_filevantage_rule_group" "m" {
#   name        = "example_filevantage_policy"
#   description = "made with terraform"
#   type        = "MacFiles"
# }

# output "filevantage_rule_group" {
#   value = crowdstrike_filevantage_rule_group.example
# }
