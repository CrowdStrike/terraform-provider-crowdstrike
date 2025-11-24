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

# Example 1: Get all Windows file vantage policies
data "crowdstrike_filevantage_policies" "windows_policies" {
  type = "Windows"
}

# Example 2: Get all Linux file vantage policies with sorting
data "crowdstrike_filevantage_policies" "linux_policies_sorted" {
  type = "Linux"
  sort = "name.asc"
}

# Example 3: Get all Mac file vantage policies sorted by precedence
data "crowdstrike_filevantage_policies" "mac_policies_by_precedence" {
  type = "Mac"
  sort = "precedence.desc"
}

# Example 4: Get specific file vantage policies by IDs
data "crowdstrike_filevantage_policies" "specific_policies" {
  ids = [
    "policy-12345678901234567890123456789012",
    "policy-98765432109876543210987654321098"
  ]
}
