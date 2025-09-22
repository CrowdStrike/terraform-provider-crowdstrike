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

resource "crowdstrike_it_automation_policy" "windows_example" {
  name        = "Example Windows Policy"
  description = "Example Windows policy configuration"

  platform   = "Windows"
  is_enabled = true

  host_groups = [
    "cd2168944fd648bc9545df05ace3705a"
  ]

  concurrency {
    concurrent_host_file_transfer_limit = 500
    concurrent_host_limit               = 5000
    concurrent_task_limit               = 3
  }

  execution {
    enable_os_query         = false
    enable_python_execution = false
    enable_script_execution = false
    execution_timeout       = 30
    execution_timeout_unit  = "Minutes"
  }

  resources {
    cpu_throttle           = 20
    memory_allocation      = 1024
    memory_allocation_unit = "MB"
  }
}

resource "crowdstrike_it_automation_policy" "linux_example" {
  name        = "Example Linux Policy"
  description = "Example Linux policy configuration"

  platform   = "Linux"
  is_enabled = true

  host_groups = [
    "e44e040561424ca8980c46abacfaa204"
  ]

  concurrency {
    concurrent_host_file_transfer_limit = 500
    concurrent_host_limit               = 5000
    concurrent_task_limit               = 3
  }

  execution {
    enable_os_query         = false
    enable_python_execution = false
    enable_script_execution = false
    execution_timeout       = 30
    execution_timeout_unit  = "Minutes"
  }

  resources {
    cpu_throttle           = 20
    memory_allocation      = 1024
    memory_allocation_unit = "MB"
  }
}

resource "crowdstrike_it_automation_policy" "mac_example" {
  name        = "Example Mac Policy"
  description = "Example Mac policy configuration"

  platform   = "Mac"
  is_enabled = true

  host_groups = [
    "f4562561640f4cdf9ea8340d8990d758"
  ]

  concurrency {
    concurrent_host_file_transfer_limit = 500
    concurrent_host_limit               = 5000
    concurrent_task_limit               = 3
  }

  execution {
    enable_os_query         = false
    enable_python_execution = false
    enable_script_execution = false
    execution_timeout       = 30
    execution_timeout_unit  = "Minutes"
  }

  resources {
    cpu_scheduling_priority = "Medium"
    memory_pressure_level   = "Medium"
  }
}

output "windows_policy" {
  value = crowdstrike_it_automation_policy.windows_example
}

output "linux_policy" {
  value = crowdstrike_it_automation_policy.linux_example
}

output "mac_policy" {
  value = crowdstrike_it_automation_policy.mac_example
}
