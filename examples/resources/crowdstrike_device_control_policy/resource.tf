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

resource "crowdstrike_device_control_policy" "example" {
  name                  = "example_device_control"
  description           = "Example device control policy managed by Terraform"
  platform_name         = "Windows"
  enabled               = true
  enforcement_mode      = "MONITOR_ENFORCE"
  end_user_notification = "NOTIFY_USER"

  classes = [
    {
      id     = "MASS_STORAGE"
      action = "BLOCK_EXECUTE"
      exceptions = [
        {
          vendor_id   = "0781"
          description = "Allow SanDisk devices"
          action      = "FULL_ACCESS"
        },
      ]
    },
    {
      id     = "WIRELESS"
      action = "FULL_ACCESS"
    },
  ]

  host_groups = ["abc123"]
}

output "device_control_policy" {
  value = crowdstrike_device_control_policy.example
}
