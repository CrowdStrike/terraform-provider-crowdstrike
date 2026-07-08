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

# Get all IT Automation tasks
data "crowdstrike_it_automation_tasks" "all" {
  sort = "name|asc"
}

# Get tasks by ID
data "crowdstrike_it_automation_tasks" "specific" {
  ids = [
    "task-id-one",
    "task-id-two",
  ]
}

# Get tasks by name using the convenience attribute
data "crowdstrike_it_automation_tasks" "by_name" {
  name = "Collect System Info"
}

# Get all query tasks
data "crowdstrike_it_automation_tasks" "queries" {
  type = "query"
  sort = "modified_time|desc"
}

# Get all shared action tasks
data "crowdstrike_it_automation_tasks" "shared_actions" {
  type        = "action"
  access_type = "Shared"
}

# Get tasks using an FQL filter
data "crowdstrike_it_automation_tasks" "recent" {
  filter = "modified_time:>'2025-01-01'"
  sort   = "modified_time|desc"
}

# Filter tasks created by a specific user
data "crowdstrike_it_automation_tasks" "admin_tasks" {
  filter = "created_by:'admin@example.com'"
}
