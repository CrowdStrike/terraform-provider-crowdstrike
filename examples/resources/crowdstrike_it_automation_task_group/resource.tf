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

resource "crowdstrike_it_automation_task_group" "example" {
  name        = "Example Task Group"
  description = "Example IT automation task group"
  access_type = "Shared"

  assigned_user_ids = [
    "21dff902-85e0-48b5-b909-b9a7099b1829",
    "fbf23972-9999-4bc4-9f9f-c2ec07fadeed"
  ]

  task_ids = [
    "005e5b946b1e9920bffb7c71427c0a00",
    "bdb7d0283ff8428f9332c5dfeb99a3aa",
  ]
}

output "task_group" {
  value = crowdstrike_it_automation_task_group.example
}
