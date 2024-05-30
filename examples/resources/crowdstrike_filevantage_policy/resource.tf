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

resource "crowdstrike_filevantage_rule_group" "example" {
  name        = "example_filevantage_rule_group"
  description = "made with terraform"
  type        = "MacFiles"
  rules = [
    {
      description = "first rule"
      path        = "/path/to/example/"
      severity    = "High"
      depth       = "ANY"
    },
  ]
}

resource "crowdstrike_filevantage_rule_group" "example2" {
  name        = "example_filevantage_rule_group"
  description = "made with terraform"
  type        = "MacFiles"
  rules = [
    {
      description              = "first rule"
      path                     = "/path/to/example/"
      severity                 = "High"
      depth                    = "ANY"
      enable_content_capture   = true
      watch_file_write_changes = true
      file_names               = ["example.exe"]
    },
  ]
}

resource "crowdstrike_filevantage_policy" "example" {
  name          = "example_filevantage_policy"
  enabled       = true
  description   = "made with terraform"
  platform_name = "Mac"
  # host_groups   = ["1232313"]
  rule_groups = [crowdstrike_filevantage_rule_group.example.id, crowdstrike_filevantage_rule_group.example2.id]
  scheduled_exclusions = [
    {
      name        = "policy1"
      description = "Run the first 3 days of the month. All day."
      start_date  = "2024-05-21"
      start_time  = "11:09"
      timezone    = "US/Central"
      processes   = "**/example.exe,/path/to/example2.exe"
      repeated = {
        all_day            = true
        frequency          = "monthly"
        monthly_occurrence = "Days"
        days_of_month      = [1, 2, 3]
      }
    },
    {
      name        = "policy2"
      description = "Run monday, tuesday, wednesday. 11:09 - 12:10."
      start_date  = "2024-05-21"
      start_time  = "11:09"
      users       = "admin*,example"
      timezone    = "US/Central"
      repeated = {
        all_day      = false
        start_time   = "11:09"
        end_time     = "12:10"
        frequency    = "weekly"
        days_of_week = ["Monday", "Tuesday", "Wednesday"]
      }
    },
  ]
}

output "filevantage_policy" {
  value = crowdstrike_filevantage_policy.example
}
