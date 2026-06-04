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

# Daily scheduled task targeting Linux production hosts.
resource "crowdstrike_it_automation_scheduled_task" "daily_example" {
  task_id       = "005e5b946b1e4320bffb7c71427c0a00"
  schedule_name = "Daily Inventory Run"
  enabled       = true
  target        = "platform_name:'Linux'+tags:'production'"

  discover_new_hosts     = true
  queue_offline_hosts    = false
  distribute_execution   = true
  expiration_period      = "1d"
  run_time_limit_minutes = 30

  schedule = {
    frequency  = "Daily"
    start_time = "2026-06-01T09:00:00-05:00"
    end_time   = "2026-12-31T09:00:00-05:00"
  }
}

# Weekly scheduled task gated by a trigger condition on a query task result.
resource "crowdstrike_it_automation_scheduled_task" "weekly_example" {
  task_id       = "005e5b946b1e4320bffb7c71427c0a00"
  schedule_name = "Weekly Compliance Check"
  enabled       = true
  target        = "platform_name:'Windows'"

  schedule = {
    frequency   = "Weekly"
    start_time  = "2026-06-01T08:00:00Z"
    day_of_week = "Monday"
  }

  trigger_condition = [{
    operator = "AND"
    statements = [{
      task_id         = "bdb7d0283ff8428f9332c5dfeb00a3aa"
      key             = "compliance_status"
      data_type       = "StringType"
      data_comparator = "Equals"
      value           = "non_compliant"
    }]
  }]
}
