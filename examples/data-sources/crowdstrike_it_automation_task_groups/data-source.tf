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

# Get all task groups
data "crowdstrike_it_automation_task_groups" "all" {}

# Look up task groups by name (translated to FQL)
data "crowdstrike_it_automation_task_groups" "security_scans" {
  name = "Security Scans"
}

# Look up task groups by access type
data "crowdstrike_it_automation_task_groups" "public_groups" {
  access_type = "Public"
}

# Look up specific task groups by IDs
data "crowdstrike_it_automation_task_groups" "specific" {
  ids = ["a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"]
}

# Use FQL filter for advanced queries
data "crowdstrike_it_automation_task_groups" "recent" {
  filter = "created_time:>='2025-01-01T00:00:00Z'"
  sort   = "name|asc"
}
