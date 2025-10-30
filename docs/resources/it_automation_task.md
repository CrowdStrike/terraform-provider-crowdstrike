---
page_title: "crowdstrike_it_automation_task Resource - crowdstrike"
subcategory: "IT Automation"
description: |-
  IT Automation --- IT Automation Tasks --- This resource allows management of IT Automation tasks in the CrowdStrike Falcon platform. Tasks allow you to run queries or actions across your hosts.
  API Scopes
  The following API scopes are required:
  IT Automation - Policies | Read & WriteIT Automation - Task Executions | Read & WriteIT Automation - Tasks | Read & WriteIT Automation - User Groups | Read & Write
---

# crowdstrike_it_automation_task (Resource)

IT Automation --- IT Automation Tasks --- This resource allows management of IT Automation tasks in the CrowdStrike Falcon platform. Tasks allow you to run queries or actions across your hosts.

## API Scopes

The following API scopes are required:

- IT Automation - Policies | Read & Write
- IT Automation - Task Executions | Read & Write
- IT Automation - Tasks | Read & Write
- IT Automation - User Groups | Read & Write

~> **Warning** When a task is part of a task group (via `crowdstrike_it_automation_task_group`), the `access_type` and `assigned_user_ids` are inherited from the task group and cannot be configured on the task itself. Attempting to configure these fields will result in an error. Use the `effective_access_type` and `effective_assigned_user_ids` computed attributes to view the actual values when a task is in a group.

## Example Usage

```terraform
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

  additional_file_ids = [
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
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) Name of the task.
- `type` (String) Type of task (action, query).

### Optional

- `access_type` (String) Access control configuration for the task (Public, Shared). Cannot be configured when the task belongs to a task group; inherited from the group instead.
- `additional_file_ids` (Set of String) Additional RTR Response file IDs (65 characters) to be available for the task.
- `assigned_user_ids` (Set of String) Assigned user IDs of the task, when access_type is Shared. Required when access_type is 'Shared' and the task is not part of a task group.
- `description` (String) Description of the task.
- `linux_script_content` (String) Linux script content.
- `linux_script_file_id` (String) Linux RTR Response script ID (65 characters) to be used by the task. This option disables linux_script_content.
- `linux_script_language` (String) Linux script language (bash, python).
- `mac_script_content` (String) Mac script content.
- `mac_script_file_id` (String) Mac RTR Response script ID (65 characters) to be used by the task. This option disables mac_script_content.
- `mac_script_language` (String) Mac script language (zsh, python).
- `os_query` (String) OSQuery string. This option will disable the task script options. See https://osquery.readthedocs.io/en/stable for syntax.
- `script_columns` (Attributes) Column configuration for the script output. (see [below for nested schema](#nestedatt--script_columns))
- `target` (String) Target of the task in FQL string syntax. See https://falconpy.io/Usage/Falcon-Query-Language.html.
- `verification_condition` (Attributes List) Verification conditions for action tasks to determine success (only valid for action tasks). (see [below for nested schema](#nestedatt--verification_condition))
- `windows_script_content` (String) Windows script content.
- `windows_script_file_id` (String) Windows RTR Response script ID (65 characters) to be used by the task. This option disables windows_script_content.
- `windows_script_language` (String) Windows script language (powershell, python).

### Read-Only

- `effective_access_type` (String) Effective access type for the task. May differ from configured access_type if the task is part of a group.
- `effective_assigned_user_ids` (Set of String) Effective assigned user IDs for the task. May differ from configured assigned_user_ids if the task is part of a group.
- `id` (String) Identifier for the task.
- `last_updated` (String) Timestamp of the last Terraform update of the resource.
- `task_group_id` (String) The ID of the task group this task belongs to, if any.

<a id="nestedatt--script_columns"></a>
### Nested Schema for `script_columns`

Required:

- `columns` (Attributes List) List of column definitions (see [below for nested schema](#nestedatt--script_columns--columns))
- `delimiter` (String) Delimiter character for script columns.

Optional:

- `group_results` (Boolean) Whether to group results by column values.

<a id="nestedatt--script_columns--columns"></a>
### Nested Schema for `script_columns.columns`

Required:

- `name` (String) Name of the column.



<a id="nestedatt--verification_condition"></a>
### Nested Schema for `verification_condition`

Required:

- `operator` (String) Logical operator for the statements (AND, OR).
- `statements` (Attributes List) List of verification statements (see [below for nested schema](#nestedatt--verification_condition--statements))

<a id="nestedatt--verification_condition--statements"></a>
### Nested Schema for `verification_condition.statements`

Required:

- `data_comparator` (String) Comparison operator for verification.
- `data_type` (String) Type of data being compared.
- `key` (String) Key to compare (e.g., script_output).
- `task_id` (String) ID of the task to query for results.
- `value` (String) Value to compare against.

## Import

Import is supported using the following syntax:

```shell
# it automation task can be imported by specifying the task id.
terraform import crowdstrike_it_automation_task.example 005e5b946b1e4320bffb7c71427c0a00

# using import block (requires terraform 1.5+)
import {
  to = crowdstrike_it_automation_task.example
  id = "005e5b946b1e4320bffb7c71427c0a00"
}
```
