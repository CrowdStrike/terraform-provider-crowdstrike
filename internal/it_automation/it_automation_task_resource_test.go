package itautomation_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/go-version"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

const taskResourceName = "crowdstrike_it_automation_task.test"

type taskConfig struct {
	Name                  string
	AccessType            string
	Description           string
	Type                  string
	AssignedUserIds       []string
	LinuxScriptLanguage   *string
	LinuxScriptContent    *string
	LinuxScriptFileId     *string
	MacScriptLanguage     *string
	MacScriptContent      *string
	MacScriptFileId       *string
	WindowsScriptLanguage *string
	WindowsScriptContent  *string
	WindowsScriptFileId   *string
	OsQuery               *string
	FileIds               []string
	ScriptColumns         *scriptColumnsConfig
	VerificationCondition *verificationConditionConfig
}

type scriptColumnsConfig struct {
	Delimiter    string
	GroupResults bool
	Columns      []scriptColumnConfig
}

type scriptColumnConfig struct {
	Name string
}

type verificationConditionConfig struct {
	Operator   string
	Statements []verificationStatementConfig
}

type verificationStatementConfig struct {
	DataComparator string
	DataType       string
	Key            string
	TaskID         string
	Value          string
}

func ptrString(s string) *string {
	return &s
}

func (config *taskConfig) String() string {
	result := fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name        = %q
  access_type = %q
  description = %q
  type        = %q
`, config.Name, config.AccessType, config.Description, config.Type)

	if len(config.AssignedUserIds) > 0 {
		result += "\n  assigned_user_ids = [\n"
		for _, uid := range config.AssignedUserIds {
			result += fmt.Sprintf("    %q,\n", uid)
		}
		result += "  ]\n"
	}

	if config.LinuxScriptLanguage != nil {
		result += fmt.Sprintf("\n  linux_script_language = %q\n", *config.LinuxScriptLanguage)
	}
	if config.LinuxScriptContent != nil {
		result += fmt.Sprintf("\n  linux_script_content = <<-END\n%s\nEND\n", *config.LinuxScriptContent)
	}
	if config.LinuxScriptFileId != nil {
		result += fmt.Sprintf("\n  linux_script_file_id = %q\n", *config.LinuxScriptFileId)
	}

	if config.MacScriptLanguage != nil {
		result += fmt.Sprintf("\n  mac_script_language = %q\n", *config.MacScriptLanguage)
	}
	if config.MacScriptContent != nil {
		result += fmt.Sprintf("\n  mac_script_content = <<-END\n%s\nEND\n", *config.MacScriptContent)
	}
	if config.MacScriptFileId != nil {
		result += fmt.Sprintf("\n  mac_script_file_id = %q\n", *config.MacScriptFileId)
	}

	if config.WindowsScriptLanguage != nil {
		result += fmt.Sprintf("\n  windows_script_language = %q\n", *config.WindowsScriptLanguage)
	}
	if config.WindowsScriptContent != nil {
		result += fmt.Sprintf("\n  windows_script_content = <<-END\n%s\nEND\n", *config.WindowsScriptContent)
	}
	if config.WindowsScriptFileId != nil {
		result += fmt.Sprintf("\n  windows_script_file_id = %q\n", *config.WindowsScriptFileId)
	}

	if config.OsQuery != nil {
		result += fmt.Sprintf("\n  os_query = %q\n", *config.OsQuery)
	}

	if len(config.FileIds) > 0 {
		result += "\n  file_ids = [\n"
		for _, fid := range config.FileIds {
			result += fmt.Sprintf("    %q,\n", fid)
		}
		result += "  ]\n"
	}

	if config.ScriptColumns != nil {
		result += fmt.Sprintf(`
  script_columns = {
    delimiter     = %q
    group_results = %t

    columns = [`, config.ScriptColumns.Delimiter, config.ScriptColumns.GroupResults)

		for _, col := range config.ScriptColumns.Columns {
			result += fmt.Sprintf(`
      {
        name = %q
      },`, col.Name)
		}
		result += `
    ]
  }
`
	}

	if config.VerificationCondition != nil {
		result += fmt.Sprintf(`
  verification_condition = [{
    operator = %q
    statements = [`, config.VerificationCondition.Operator)

		for _, stmt := range config.VerificationCondition.Statements {
			taskID := stmt.TaskID
			if taskID == "placeholder" {
				platform := ""
				if config.LinuxScriptFileId != nil || config.LinuxScriptContent != nil {
					platform = "linux"
				} else if config.MacScriptFileId != nil || config.MacScriptContent != nil {
					platform = "mac"
				} else if config.WindowsScriptFileId != nil || config.WindowsScriptContent != nil {
					platform = "windows"
				}
				if platform != "" {
					taskID = fmt.Sprintf("crowdstrike_it_automation_task.verify_%s.id", platform)
				}
			}

			result += fmt.Sprintf(`{
      data_comparator = %q
      data_type       = %q
      key             = %q
      task_id         = %s
      value           = %q
    },`, stmt.DataComparator, stmt.DataType, stmt.Key, taskID, stmt.Value)
		}
		result += `]
  }]
`
	}

	result += "}\n"
	return result
}

func (config *taskConfig) TestChecks() resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks,
		resource.TestCheckResourceAttrSet(taskResourceName, "id"),
		resource.TestCheckResourceAttrSet(taskResourceName, "last_updated"),
		resource.TestCheckResourceAttr(taskResourceName, "name", config.Name),
		resource.TestCheckResourceAttr(taskResourceName, "access_type", config.AccessType),
		resource.TestCheckResourceAttr(taskResourceName, "description", config.Description),
		resource.TestCheckResourceAttr(taskResourceName, "type", config.Type),
	)

	if len(config.AssignedUserIds) > 0 {
		checks = append(checks,
			resource.TestCheckResourceAttr(taskResourceName, "assigned_user_ids.#", fmt.Sprintf("%d", len(config.AssignedUserIds))),
		)
	}

	if config.OsQuery != nil {
		checks = append(checks,
			resource.TestCheckResourceAttr(taskResourceName, "os_query", *config.OsQuery),
		)
	}

	if config.LinuxScriptContent != nil {
		checks = append(checks,
			resource.TestCheckResourceAttrSet(taskResourceName, "linux_script_content"),
		)
	}

	if config.MacScriptContent != nil {
		checks = append(checks,
			resource.TestCheckResourceAttrSet(taskResourceName, "mac_script_content"),
		)
	}

	if config.WindowsScriptContent != nil {
		checks = append(checks,
			resource.TestCheckResourceAttrSet(taskResourceName, "windows_script_content"),
		)
	}

	if config.LinuxScriptFileId != nil {
		checks = append(checks,
			resource.TestCheckResourceAttr(taskResourceName, "linux_script_file_id", *config.LinuxScriptFileId),
		)
	}

	if config.MacScriptFileId != nil {
		checks = append(checks,
			resource.TestCheckResourceAttr(taskResourceName, "mac_script_file_id", *config.MacScriptFileId),
		)
	}

	if config.WindowsScriptFileId != nil {
		checks = append(checks,
			resource.TestCheckResourceAttr(taskResourceName, "windows_script_file_id", *config.WindowsScriptFileId),
		)
	}

	if len(config.FileIds) > 0 {
		checks = append(checks,
			resource.TestCheckResourceAttr(taskResourceName, "file_ids.#", fmt.Sprintf("%d", len(config.FileIds))),
		)
	}

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

func TestAccITAutomationTaskResource_ScriptContent(t *testing.T) {
	sdk := createSDKFixtures(t)
	t.Cleanup(func() { sdk.Cleanup(t) })

	rName := sdkacctest.RandomWithPrefix("tf-acctest")

	testCases := []struct {
		name   string
		config taskConfig
	}{
		{
			name: "script_content_initial",
			config: taskConfig{
				Name:                rName,
				AccessType:          "Shared",
				Description:         "Example task using inline script content",
				Type:                "query",
				LinuxScriptLanguage: ptrString("bash"),
				LinuxScriptContent: ptrString(`#!/bin/bash
echo "System info|$(uname -a)"
echo "Uptime|$(uptime)"`),
				AssignedUserIds: sdk.UserIDs,
				ScriptColumns: &scriptColumnsConfig{
					Delimiter:    "|",
					GroupResults: false,
					Columns: []scriptColumnConfig{
						{Name: "info_type"},
						{Name: "value"},
					},
				},
			},
		},
		{
			name: "script_content_updated",
			config: taskConfig{
				Name:                rName + "-updated",
				AccessType:          "Public",
				Description:         "Updated script content task",
				Type:                "query",
				LinuxScriptLanguage: ptrString("bash"),
				LinuxScriptContent: ptrString(`#!/bin/bash
echo "Hostname|$(hostname)"
echo "Date|$(date)"`),
				ScriptColumns: &scriptColumnsConfig{
					Delimiter:    "|",
					GroupResults: true,
					Columns: []scriptColumnConfig{
						{Name: "field"},
						{Name: "result"},
					},
				},
			},
		},
		{
			name: "script_content_mac",
			config: taskConfig{
				Name:              rName + "-mac",
				AccessType:        "Public",
				Description:       "Mac script content task",
				Type:              "query",
				MacScriptLanguage: ptrString("zsh"),
				MacScriptContent: ptrString(`#!/bin/zsh
echo "System|$(uname -s)"
echo "Version|$(sw_vers -productVersion)"`),
				ScriptColumns: &scriptColumnsConfig{
					Delimiter:    "|",
					GroupResults: false,
					Columns: []scriptColumnConfig{
						{Name: "info"},
						{Name: "value"},
					},
				},
			},
		},
		{
			name: "script_content_windows",
			config: taskConfig{
				Name:                  rName + "-windows",
				AccessType:            "Public",
				Description:           "Windows script content task",
				Type:                  "query",
				WindowsScriptLanguage: ptrString("powershell"),
				WindowsScriptContent: ptrString(`Write-Output "Computer|$env:COMPUTERNAME"
Write-Output "OS|$((Get-WmiObject Win32_OperatingSystem).Caption)"`),
				ScriptColumns: &scriptColumnsConfig{
					Delimiter:    "|",
					GroupResults: false,
					Columns: []scriptColumnConfig{
						{Name: "type"},
						{Name: "data"},
					},
				},
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			fixtures := getTestFixtures()
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + fixtures.VerificationTasksOnly() + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			steps = append(steps, resource.TestStep{
				ResourceName:      taskResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			})
			return steps
		}(),
	})
}

func TestAccITAutomationTaskResource_ScriptFile(t *testing.T) {
	sdk := createSDKFixtures(t)
	t.Cleanup(func() { sdk.Cleanup(t) })

	rName := sdkacctest.RandomWithPrefix("tf-acctest")

	testCases := []struct {
		name   string
		config taskConfig
	}{
		{
			name: "script_file_initial",
			config: taskConfig{
				Name:                rName,
				AccessType:          "Public",
				Description:         "Example task using script files, file attachments, and verification condition",
				Type:                "action",
				LinuxScriptFileId:   ptrString(sdk.ScriptFileIDs["linux"]),
				LinuxScriptLanguage: ptrString("bash"),
				FileIds:             []string{sdk.FileIDs["linux"]},
				VerificationCondition: &verificationConditionConfig{
					Operator: "AND",
					Statements: []verificationStatementConfig{
						{
							DataComparator: "Equals",
							DataType:       "StringType",
							Key:            "script_output",
							TaskID:         "placeholder",
							Value:          "Success",
						},
					},
				},
			},
		},
		{
			name: "script_file_updated",
			config: taskConfig{
				Name:                rName + "-updated",
				AccessType:          "Shared",
				Description:         "Updated script file task",
				Type:                "action",
				LinuxScriptFileId:   ptrString(sdk.ScriptFileIDs["linux"]),
				LinuxScriptLanguage: ptrString("bash"),
				FileIds:             []string{sdk.FileIDs["linux"]},
				AssignedUserIds:     sdk.UserIDs,
				VerificationCondition: &verificationConditionConfig{
					Operator: "OR",
					Statements: []verificationStatementConfig{
						{
							DataComparator: "Contains",
							DataType:       "StringType",
							Key:            "script_output",
							TaskID:         "placeholder",
							Value:          "Complete",
						},
					},
				},
			},
		},
		{
			name: "script_file_mac",
			config: taskConfig{
				Name:              rName + "-mac",
				AccessType:        "Public",
				Description:       "Mac script file task",
				Type:              "action",
				MacScriptFileId:   ptrString(sdk.ScriptFileIDs["mac"]),
				MacScriptLanguage: ptrString("zsh"),
				VerificationCondition: &verificationConditionConfig{
					Operator: "AND",
					Statements: []verificationStatementConfig{
						{
							DataComparator: "Equals",
							DataType:       "StringType",
							Key:            "script_output",
							TaskID:         "placeholder",
							Value:          "Success",
						},
					},
				},
			},
		},
		{
			name: "script_file_windows",
			config: taskConfig{
				Name:                  rName + "-windows",
				AccessType:            "Public",
				Description:           "Windows script file task",
				Type:                  "action",
				WindowsScriptFileId:   ptrString(sdk.ScriptFileIDs["windows"]),
				WindowsScriptLanguage: ptrString("powershell"),
				VerificationCondition: &verificationConditionConfig{
					Operator: "AND",
					Statements: []verificationStatementConfig{
						{
							DataComparator: "Equals",
							DataType:       "StringType",
							Key:            "script_output",
							TaskID:         "placeholder",
							Value:          "Success",
						},
					},
				},
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			fixtures := getTestFixtures()
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + fixtures.VerificationTasksOnly() + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			steps = append(steps, resource.TestStep{
				ResourceName:      taskResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			})
			return steps
		}(),
	})
}

func TestAccITAutomationTaskResource_OSQuery(t *testing.T) {
	sdk := createSDKFixtures(t)
	t.Cleanup(func() { sdk.Cleanup(t) })

	rName := sdkacctest.RandomWithPrefix("tf-acctest")

	testCases := []struct {
		name   string
		config taskConfig
	}{
		{
			name: "osquery_initial",
			config: taskConfig{
				Name:            rName,
				AccessType:      "Shared",
				Description:     "Example task using OSQuery",
				Type:            "query",
				OsQuery:         ptrString("SELECT name, version FROM programs WHERE name LIKE '%chrome%';"),
				AssignedUserIds: sdk.UserIDs,
			},
		},
		{
			name: "osquery_updated",
			config: taskConfig{
				Name:        rName + "-updated",
				AccessType:  "Public",
				Description: "Updated OSQuery task",
				Type:        "query",
				OsQuery:     ptrString("SELECT name, path FROM processes WHERE name LIKE '%python%';"),
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			fixtures := getTestFixtures()
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + fixtures.VerificationTasksOnly() + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			steps = append(steps, resource.TestStep{
				ResourceName:      taskResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			})
			return steps
		}(),
	})
}

func TestAccITAutomationTaskResource_InTaskGroup(t *testing.T) {
	sdk := createSDKFixtures(t)
	t.Cleanup(func() { sdk.Cleanup(t) })

	rName := sdkacctest.RandomWithPrefix("tf-acctest")
	taskName := rName + "-task"
	groupName := rName + "-group"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name                  = %[1]q
  description           = "Task for group testing"
  type                  = "query"
  linux_script_language = "bash"
  linux_script_content  = "echo 'test'"
}

resource "crowdstrike_it_automation_task_group" "test" {
  name        = %[2]q
  description = "Test task group"
  access_type = "Shared"
  assigned_user_ids = [
    %[3]q,
  ]
  task_ids = [crowdstrike_it_automation_task.test.id]
}
`, taskName, groupName, sdk.UserIDs[0]),
			},
			{
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(taskResourceName, "name", taskName),
					resource.TestCheckResourceAttr(taskResourceName, "in_task_group", "true"),
					resource.TestCheckResourceAttr(taskResourceName, "effective_access_type", "Shared"),
					resource.TestCheckResourceAttr(taskResourceName, "effective_assigned_user_ids.#", "1"),
				),
			},
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name                  = %[1]q
  access_type           = "Public"
  description           = "Task for group testing"
  type                  = "query"
  linux_script_language = "bash"
  linux_script_content  = "echo 'test'"
}

resource "crowdstrike_it_automation_task_group" "test" {
  name        = %[2]q
  description = "Test task group"
  access_type = "Shared"
  assigned_user_ids = [
    %[3]q,
  ]
  task_ids = [crowdstrike_it_automation_task.test.id]
}
`, taskName, groupName, sdk.UserIDs[0]),
				ExpectError: regexp.MustCompile("Cannot configure access_type when task is part of a task group"),
			},
		},
	})
}

func TestAccITAutomationTaskResource_RemovedFromGroup(t *testing.T) {
	sdk := createSDKFixtures(t)
	t.Cleanup(func() { sdk.Cleanup(t) })

	rName := sdkacctest.RandomWithPrefix("tf-acctest")
	taskName := rName + "-task"
	groupName := rName + "-group"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name                  = %[1]q
  description           = "Task to test group removal"
  type                  = "query"
  linux_script_language = "bash"
  linux_script_content  = "echo 'test'"
}

resource "crowdstrike_it_automation_task_group" "test" {
  name        = %[2]q
  description = "Test task group"
  access_type = "Shared"
  assigned_user_ids = [
    %[3]q,
  ]
  task_ids = [crowdstrike_it_automation_task.test.id]
}
`, taskName, groupName, sdk.UserIDs[0]),
			},
			{
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(taskResourceName, "in_task_group", "true"),
					resource.TestCheckResourceAttr(taskResourceName, "effective_access_type", "Shared"),
					resource.TestCheckResourceAttr(taskResourceName, "effective_assigned_user_ids.#", "1"),
				),
			},
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name                  = %[1]q
  description           = "Task to test group removal"
  type                  = "query"
  linux_script_language = "bash"
  linux_script_content  = "echo 'test'"
}
`, taskName),
			},
			{
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(taskResourceName, "in_task_group", "false"),
					resource.TestCheckResourceAttr(taskResourceName, "access_type", "Shared"),
					resource.TestCheckResourceAttr(taskResourceName, "effective_access_type", "Shared"),
					resource.TestCheckResourceAttr(taskResourceName, "effective_assigned_user_ids.#", "1"),
				),
			},
		},
	})
}

func TestAccITAutomationTaskResource_ConfigureWhileInGroup(t *testing.T) {
	sdk := createSDKFixtures(t)
	t.Cleanup(func() { sdk.Cleanup(t) })

	rName := sdkacctest.RandomWithPrefix("tf-acctest")
	taskName := rName + "-task"
	groupName := rName + "-group"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name                  = %[1]q
  description           = "Task for testing configuration restrictions"
  type                  = "query"
  linux_script_language = "bash"
  linux_script_content  = "echo 'test'"
}

resource "crowdstrike_it_automation_task_group" "test" {
  name        = %[2]q
  description = "Test task group"
  access_type = "Shared"
  assigned_user_ids = [
    %[3]q,
  ]
  task_ids = [crowdstrike_it_automation_task.test.id]
}
`, taskName, groupName, sdk.UserIDs[0]),
			},
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name                  = %[1]q
  description           = "Task for testing configuration restrictions"
  type                  = "query"
  access_type           = "Public"
  linux_script_language = "bash"
  linux_script_content  = "echo 'test'"
}

resource "crowdstrike_it_automation_task_group" "test" {
  name        = %[2]q
  description = "Test task group"
  access_type = "Shared"
  assigned_user_ids = [
    %[3]q,
  ]
  task_ids = [crowdstrike_it_automation_task.test.id]
}
`, taskName, groupName, sdk.UserIDs[0]),
				ExpectError: regexp.MustCompile("Cannot configure access_type when task is part of a task group"),
			},
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name                  = %[1]q
  description           = "Task for testing configuration restrictions"
  type                  = "query"
  access_type           = "Shared"
  assigned_user_ids     = [%[3]q]
  linux_script_language = "bash"
  linux_script_content  = "echo 'test'"
}

resource "crowdstrike_it_automation_task_group" "test" {
  name        = %[2]q
  description = "Test task group"
  access_type = "Shared"
  assigned_user_ids = [
    %[3]q,
  ]
  task_ids = [crowdstrike_it_automation_task.test.id]
}
`, taskName, groupName, sdk.UserIDs[0]),
				ExpectError: regexp.MustCompile("Cannot configure (access_type|assigned_user_ids) when task is part of a task group"),
			},
		},
	})
}

func TestAccITAutomationTaskResource_ExplicitAccessTypeOverride(t *testing.T) {
	sdk := createSDKFixtures(t)
	t.Cleanup(func() { sdk.Cleanup(t) })

	rName := sdkacctest.RandomWithPrefix("tf-acctest")
	taskName := rName + "-task"
	groupName := rName + "-group"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name                  = %[1]q
  description           = "Task with explicit access_type"
  type                  = "query"
  access_type           = "Public"
  linux_script_language = "bash"
  linux_script_content  = "echo 'test'"
}
`, taskName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(taskResourceName, "name", taskName),
					resource.TestCheckResourceAttr(taskResourceName, "access_type", "Public"),
					resource.TestCheckResourceAttr(taskResourceName, "in_task_group", "false"),
				),
			},
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name                  = %[1]q
  description           = "Task with explicit access_type"
  type                  = "query"
  access_type           = "Public"
  linux_script_language = "bash"
  linux_script_content  = "echo 'test'"
}

resource "crowdstrike_it_automation_task_group" "test" {
  name        = %[2]q
  description = "Test task group"
  access_type = "Shared"
  assigned_user_ids = [
    %[3]q,
  ]
  task_ids = [crowdstrike_it_automation_task.test.id]
}
`, taskName, groupName, sdk.UserIDs[0]),
				ExpectError: regexp.MustCompile("Cannot configure access_type when task is part of a task group"),
			},
		},
	})
}

func TestAccITAutomationTaskResource_PublicAccessInheritance(t *testing.T) {
	sdk := createSDKFixtures(t)
	t.Cleanup(func() { sdk.Cleanup(t) })

	rName := sdkacctest.RandomWithPrefix("tf-acctest")
	taskName := rName + "-task"
	groupName := rName + "-group"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name                  = %[1]q
  description           = "Task in public group"
  type                  = "query"
  linux_script_language = "bash"
  linux_script_content  = "echo 'test'"
}

resource "crowdstrike_it_automation_task_group" "test" {
  name        = %[2]q
  description = "Public task group"
  access_type = "Public"
  task_ids    = [crowdstrike_it_automation_task.test.id]
}
`, taskName, groupName),
			},
			{
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(taskResourceName, "name", taskName),
					resource.TestCheckResourceAttr(taskResourceName, "in_task_group", "true"),
					resource.TestCheckResourceAttr(taskResourceName, "effective_access_type", "Public"),
					resource.TestCheckResourceAttrPair(taskResourceName, "task_group_id", "crowdstrike_it_automation_task_group.test", "id"),
				),
			},
		},
	})
}

func TestAccITAutomationTaskResource_GroupAccessTypeChange(t *testing.T) {
	sdk := createSDKFixtures(t)
	t.Cleanup(func() { sdk.Cleanup(t) })

	rName := sdkacctest.RandomWithPrefix("tf-acctest")
	taskName := rName + "-task"
	groupName := rName + "-group"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name                  = %[1]q
  description           = "Task for testing access_type change"
  type                  = "query"
  linux_script_language = "bash"
  linux_script_content  = "echo 'test'"
}

resource "crowdstrike_it_automation_task_group" "test" {
  name        = %[2]q
  description = "Test task group"
  access_type = "Shared"
  assigned_user_ids = [
    %[3]q,
  ]
  task_ids = [crowdstrike_it_automation_task.test.id]
}
`, taskName, groupName, sdk.UserIDs[0]),
			},
			{
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(taskResourceName, "in_task_group", "true"),
					resource.TestCheckResourceAttr(taskResourceName, "effective_access_type", "Shared"),
					resource.TestCheckResourceAttr(taskResourceName, "effective_assigned_user_ids.#", "1"),
				),
			},
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name                  = %[1]q
  description           = "Task for testing access_type change"
  type                  = "query"
  linux_script_language = "bash"
  linux_script_content  = "echo 'test'"
}

resource "crowdstrike_it_automation_task_group" "test" {
  name        = %[2]q
  description = "Test task group"
  access_type = "Public"
  task_ids    = [crowdstrike_it_automation_task.test.id]
}
`, taskName, groupName),
			},
			{
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(taskResourceName, "in_task_group", "true"),
					resource.TestCheckResourceAttr(taskResourceName, "effective_access_type", "Public"),
					resource.TestCheckResourceAttr(taskResourceName, "effective_assigned_user_ids.#", "0"),
				),
			},
		},
	})
}

func TestAccITAutomationTaskResource_OmittedOptionalFields(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acctest")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name                  = %q
  type                  = "query"
  linux_script_language = "bash"
  linux_script_content  = "echo 'test'"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(taskResourceName, "id"),
					resource.TestCheckResourceAttr(taskResourceName, "name", rName),
					resource.TestCheckResourceAttr(taskResourceName, "type", "query"),
					resource.TestCheckNoResourceAttr(taskResourceName, "description"),
					resource.TestCheckNoResourceAttr(taskResourceName, "target"),
					resource.TestCheckNoResourceAttr(taskResourceName, "os_query"),
				),
			},
		},
	})
}
