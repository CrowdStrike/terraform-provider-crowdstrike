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

resource "crowdstrike_it_automation_task" "script_content_example" {
  name        = "Script Content Query Example"
  access_type = "Shared"
  description = "Example task using inline script content"
  type        = "query"

  linux_script_language = "bash"
  linux_script_content  = <<-END
    #!/bin/bash
    echo "System info|$(uname -a)"
    echo "Uptime|$(uptime)"
  END

  assigned_user_ids = [
    "21dff902-85e0-48b5-b909-b9a7099b1829",
    "fbf23972-9999-4bc4-9f9f-c2ec07fadeed"
  ]

  script_columns = {
    delimiter     = "|"
    group_results = false

    columns = [
      {
        name = "info_type"
      },
      {
        name = "value"
      }
    ]
  }
}

resource "crowdstrike_it_automation_task" "script_file_example" {
  name        = "Script File Action Example"
  access_type = "Public"
  description = "Example task using script files, file attachments, and a verification condition."
  type        = "action"

  linux_script_file_id  = "378e984aee3511efb8a2bef47e6c96ec_a4eb840ff5424cbd89ba28497b6fcb6b"
  linux_script_language = "bash"

  file_ids = [
    "1b08868dee3511efa739d6ef9e24a20c_a4eb840ff5424cbd89ba28497b6fcb6b"
  ]

  verification_condition = [{
    operator = "AND"
    statements = [{
      data_comparator = "Equals"
      data_type       = "StringType"
      key             = "script_output"
      task_id         = "bdb7d0283ff8428f9332c5dfeb00a3aa"
      value           = "Success"
    }]
  }]
}

resource "crowdstrike_it_automation_task" "mac_script_example" {
  name        = "Mac Script Content Example"
  access_type = "Public"
  description = "Example task for Mac using inline script content"
  type        = "query"

  mac_script_language = "zsh"
  mac_script_content  = <<-END
    #!/bin/zsh
    echo "System|$(uname -s)"
    echo "Version|$(sw_vers -productVersion)"
  END

  script_columns = {
    delimiter     = "|"
    group_results = false

    columns = [
      {
        name = "info"
      },
      {
        name = "value"
      }
    ]
  }
}

resource "crowdstrike_it_automation_task" "windows_script_example" {
  name        = "Windows Script Content Example"
  access_type = "Public"
  description = "Example task for Windows using inline script content"
  type        = "query"

  windows_script_language = "powershell"
  windows_script_content  = <<-END
    Write-Output "Computer|$env:COMPUTERNAME"
    Write-Output "OS|$((Get-WmiObject Win32_OperatingSystem).Caption)"
  END

  script_columns = {
    delimiter     = "|"
    group_results = false

    columns = [
      {
        name = "type"
      },
      {
        name = "data"
      }
    ]
  }
}

resource "crowdstrike_it_automation_task" "osquery_example" {
  name        = "OSQuery Example"
  access_type = "Shared"
  description = "Example task using OSQuery"
  type        = "query"

  os_query = "SELECT name, version FROM programs WHERE name LIKE '%chrome%';"

  assigned_user_ids = [
    "21dff902-85e0-48b5-b909-b9a7099b1829",
    "fbf23972-9999-4bc4-9f9f-c2ec07fadeed"
  ]
}

output "script_content_task" {
  value = crowdstrike_it_automation_task.script_content_example
}

output "script_file_task" {
  value = crowdstrike_it_automation_task.script_file_example
}

output "mac_script_task" {
  value = crowdstrike_it_automation_task.mac_script_example
}

output "windows_script_task" {
  value = crowdstrike_it_automation_task.windows_script_example
}

output "osquery_task" {
  value = crowdstrike_it_automation_task.osquery_example
}
