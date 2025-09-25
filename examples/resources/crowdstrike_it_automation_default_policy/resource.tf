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

resource "crowdstrike_it_automation_default_policy" "windows_example" {
  platform    = "Windows"
  description = "Example Windows Default Policy configuration"

  concurrent_host_file_transfer_limit = 500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = false
  enable_python_execution = false
  enable_script_execution = false
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_throttle           = 20
  memory_allocation      = 1024
  memory_allocation_unit = "MB"
}

resource "crowdstrike_it_automation_default_policy" "linux_example" {
  platform    = "Linux"
  description = "Example Linux Default Policy configuration"

  concurrent_host_file_transfer_limit = 500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = false
  enable_python_execution = false
  enable_script_execution = false
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_throttle           = 20
  memory_allocation      = 1024
  memory_allocation_unit = "MB"
}

resource "crowdstrike_it_automation_default_policy" "mac_example" {
  platform    = "Mac"
  description = "Example Mac Default Policy configuration"

  concurrent_host_file_transfer_limit = 500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = false
  enable_python_execution = false
  enable_script_execution = false
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_scheduling_priority = "Medium"
  memory_pressure_level   = "Medium"
}

output "windows_default_policy" {
  value = crowdstrike_it_automation_default_policy.windows_example
}

output "linux_default_policy" {
  value = crowdstrike_it_automation_default_policy.linux_example
}

output "mac_default_policy" {
  value = crowdstrike_it_automation_default_policy.mac_example
}
