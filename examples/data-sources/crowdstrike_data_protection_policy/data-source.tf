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

# Look up a policy by its identifier. platform_name is not used here.
data "crowdstrike_data_protection_policy" "by_id" {
  id = "00112233445566778899aabbccddeeff"
}

# Look up a policy with an FQL filter. platform_name scopes the search, and the
# text match operator matches the whole policy name.
data "crowdstrike_data_protection_policy" "by_name" {
  filter        = "name:~'Payroll Data Policy'"
  platform_name = "Windows"
}

# Filters are not limited to name.
data "crowdstrike_data_protection_policy" "default_windows" {
  filter        = "is_default:true"
  platform_name = "Windows"
}

output "payroll_policy_classifications" {
  value = data.crowdstrike_data_protection_policy.by_name.classifications
}
