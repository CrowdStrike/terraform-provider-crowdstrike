package sensorupdatepolicy_test

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"text/template"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"

	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// sensorUpdatePolicyConfig represents a complete policy configuration for testing.
type sensorUpdatePolicyConfig struct {
	Name                string
	Description         string
	Enabled             *bool
	PlatformName        string
	Build               string
	BuildArm64          string
	UninstallProtection *bool
	Schedule            scheduleConfig
	HostGroupCount      int
}

// scheduleConfig represents schedule configuration.
type scheduleConfig struct {
	Enabled    bool
	Timezone   *string
	TimeBlocks []timeBlockConfig
}

// timeBlockConfig represents a time block within a schedule.
type timeBlockConfig struct {
	Days      []string
	StartTime string
	EndTime   string
}

const sensorUpdatePolicyTemplate = `{{.HostGroupResources}}
data "crowdstrike_sensor_update_policy_builds" "all" {}

resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "{{.Name}}"
  description          = "{{.Description}}"
  enabled              = {{if .Enabled}}{{.Enabled}}{{else}}true{{end}}
  platform_name        = "{{.PlatformName}}"
  build                = {{.BuildValue}}
  {{if eq .PlatformName "Linux"}}build_arm64          = {{.BuildArm64Value}}{{end}}
  uninstall_protection = {{if .UninstallProtection}}{{.UninstallProtection}}{{else}}false{{end}}
  host_groups          = [{{range $i, $ref := .HostGroupRefs}}{{if $i}}, {{end}}{{$ref}}{{end}}]
  {{.ScheduleBlock}}
}
`

const hostGroupTemplate = `
resource "crowdstrike_host_group" "hg_{{.Index}}" {
  name        = "{{.Name}}"
  description = "Test host group {{.Index}} for sensor update policy"
  type        = "static"
  hostnames   = ["test-host{{.Index}}-1", "test-host{{.Index}}-2"]
}
`

// String generates Terraform configuration from sensorUpdatePolicyConfig.
func (config *sensorUpdatePolicyConfig) String() string {
	randomSuffix := sdkacctest.RandString(8)
	config.Name = fmt.Sprintf("%s-%s", config.Name, randomSuffix)

	// Generate host group resources and references
	hostGroupResources := ""
	hostGroupRefs := []string{}

	for i := 0; i < config.HostGroupCount; i++ {
		hostGroupName := fmt.Sprintf("hg-%s-%d", randomSuffix, i)

		tmplData := struct {
			Index int
			Name  string
		}{
			Index: i,
			Name:  hostGroupName,
		}

		tmpl := template.Must(template.New("hostgroup").Parse(hostGroupTemplate))
		var buf bytes.Buffer
		tmpl.Execute(&buf, tmplData)
		hostGroupResources += buf.String()

		hostGroupRefs = append(hostGroupRefs, fmt.Sprintf("crowdstrike_host_group.hg_%d.id", i))
	}

	// Prepare template data with simplified structure
	templateData := struct {
		*sensorUpdatePolicyConfig
		HostGroupResources string
		HostGroupRefs      []string
	}{
		sensorUpdatePolicyConfig: config,
		HostGroupResources:       hostGroupResources,
		HostGroupRefs:            hostGroupRefs,
	}

	tmpl := template.Must(template.New("policy").Parse(sensorUpdatePolicyTemplate))
	var buf bytes.Buffer
	tmpl.Execute(&buf, templateData)

	return acctest.ProviderConfig + buf.String()
}

// BuildValue returns the build value for the template
func (config sensorUpdatePolicyConfig) BuildValue() string {
	if config.Build == "" {
		return `""`
	}
	return fmt.Sprintf("data.crowdstrike_sensor_update_policy_builds.all.%s.%s.build", strings.ToLower(config.PlatformName), config.Build)
}

// BuildArm64Value returns the ARM64 build value for Linux
func (config sensorUpdatePolicyConfig) BuildArm64Value() string {
	if config.BuildArm64 == "" {
		return `""`
	}
	return fmt.Sprintf("data.crowdstrike_sensor_update_policy_builds.all.linux_arm64.%s.build", config.BuildArm64)
}

// ScheduleBlock returns the formatted schedule block
func (config sensorUpdatePolicyConfig) ScheduleBlock() string {
	if !config.Schedule.Enabled && len(config.Schedule.TimeBlocks) == 0 {
		return "schedule = {\n    enabled = false\n  }"
	}

	scheduleStr := "schedule = {\n    enabled = true"

	if config.Schedule.Timezone != nil {
		scheduleStr += fmt.Sprintf("\n    timezone = %q", *config.Schedule.Timezone)
	}

	if len(config.Schedule.TimeBlocks) > 0 {
		scheduleStr += "\n    time_blocks = ["
		for i, block := range config.Schedule.TimeBlocks {
			if i > 0 {
				scheduleStr += ","
			}
			scheduleStr += fmt.Sprintf("\n     {\n       days       = [%s]\n       start_time = %q\n       end_time   = %q\n     }",
				strings.Join(func() []string {
					quoted := make([]string, len(block.Days))
					for i, day := range block.Days {
						quoted[i] = fmt.Sprintf("%q", day)
					}
					return quoted
				}(), ", "), block.StartTime, block.EndTime)
		}
		scheduleStr += "\n   ]"
	}

	scheduleStr += "\n  }"
	return scheduleStr
}

func (config sensorUpdatePolicyConfig) resourceName() string {
	return "crowdstrike_sensor_update_policy.test"
}

func (config sensorUpdatePolicyConfig) TestChecks() resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks,
		resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", "name", config.Name),
		resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", "description", config.Description),
		resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", "platform_name", config.PlatformName),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_update_policy.test", "id"),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_update_policy.test", "last_updated"),
	)

	if config.Enabled != nil {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", "enabled", fmt.Sprintf("%t", *config.Enabled)))
	} else {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", "enabled", "true"))
	}

	if config.Build == "" {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", "build", ""))
	} else {
		checks = append(checks, resource.TestCheckResourceAttrSet("crowdstrike_sensor_update_policy.test", "build"))
	}

	if config.PlatformName == "Linux" {
		if config.BuildArm64 == "" {
			checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", "build_arm64", ""))
		} else {
			checks = append(checks, resource.TestCheckResourceAttrSet("crowdstrike_sensor_update_policy.test", "build_arm64"))
		}
	}

	if config.UninstallProtection != nil {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", "uninstall_protection", fmt.Sprintf("%t", *config.UninstallProtection)))
	} else {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", "uninstall_protection", "false"))
	}

	checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", "host_groups.#", fmt.Sprintf("%d", config.HostGroupCount)))

	checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", "schedule.enabled", fmt.Sprintf("%t", config.Schedule.Enabled)))

	if config.Schedule.Enabled {
		if config.Schedule.Timezone != nil {
			checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", "schedule.timezone", *config.Schedule.Timezone))
		}

		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", "schedule.time_blocks.#", fmt.Sprintf("%d", len(config.Schedule.TimeBlocks))))

		for i, block := range config.Schedule.TimeBlocks {
			checks = append(checks,
				resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", fmt.Sprintf("schedule.time_blocks.%d.days.#", i), fmt.Sprintf("%d", len(block.Days))),
				resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", fmt.Sprintf("schedule.time_blocks.%d.start_time", i), block.StartTime),
				resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", fmt.Sprintf("schedule.time_blocks.%d.end_time", i), block.EndTime),
			)

			for j, day := range block.Days {
				checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test", fmt.Sprintf("schedule.time_blocks.%d.days.%d", i, j), day))
			}
		}
	}

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

func TestAccSensorUpdatePolicyResourceBadBuildUpdate(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_sensor_update_policy_builds" "all" {}
resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "%s"
  enabled              = true
  description          = "made with terraform"
  host_groups          = []
  platform_name        = "Windows"
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection = false 
  schedule = {
    enabled = false
  }
}
`, rName),
			},
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "%s"
  enabled              = true
  description          = "made with terraform"
  host_groups          = []
  platform_name        = "Windows"
  build                = "invalid"
  uninstall_protection = false 
  schedule = {
    enabled = false
  }
}
`, rName),
				ExpectError: regexp.MustCompile(
					"(?i)(?s).*invalid(?s).*build invalid.*",
				),
			},
		},
	})
}

func TestAccSensorUpdatePolicyResource_EmptyStringBuilds(t *testing.T) {
	testCases := []struct {
		name   string
		config sensorUpdatePolicyConfig
	}{
		{
			name: "windows_empty_build",
			config: sensorUpdatePolicyConfig{
				Name:                "test-policy-windows-empty",
				Description:         "Test Windows policy with empty build",
				Enabled:             utils.Addr(true),
				PlatformName:        "Windows",
				Build:               "",
				UninstallProtection: utils.Addr(false),
				Schedule: scheduleConfig{
					Enabled: false,
				},
			},
		},
		{
			name: "mac_empty_build",
			config: sensorUpdatePolicyConfig{
				Name:                "test-policy-mac-empty",
				Description:         "Test Mac policy with empty build",
				Enabled:             utils.Addr(true),
				PlatformName:        "Mac",
				Build:               "",
				UninstallProtection: utils.Addr(false),
				Schedule: scheduleConfig{
					Enabled: false,
				},
			},
		},
		{
			name: "linux_empty_builds",
			config: sensorUpdatePolicyConfig{
				Name:                "test-policy-linux-empty",
				Description:         "Test Linux policy with empty builds",
				Enabled:             utils.Addr(true),
				PlatformName:        "Linux",
				Build:               "",
				BuildArm64:          "",
				UninstallProtection: utils.Addr(false),
				Schedule: scheduleConfig{
					Enabled: false,
				},
			},
		},
		{
			name: "linux_valid_build_empty_arm64",
			config: sensorUpdatePolicyConfig{
				Name:                "test-policy-linux-mixed",
				Description:         "Test Linux policy with valid build and empty ARM64",
				Enabled:             utils.Addr(true),
				PlatformName:        "Linux",
				Build:               "n1",
				BuildArm64:          "",
				UninstallProtection: utils.Addr(false),
				Schedule: scheduleConfig{
					Enabled: false,
				},
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})

				ignoreFields := []string{"last_updated"}
				if tc.config.PlatformName == "Linux" && tc.config.BuildArm64 == "" {
					ignoreFields = append(ignoreFields, "build_arm64")
				}

				steps = append(steps, resource.TestStep{
					ResourceName:            tc.config.resourceName(),
					ImportState:             true,
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: ignoreFields,
				})
			}
			return steps
		}(),
	})
}

func TestAccSensorUpdatePolicyResource_PlatformReplace(t *testing.T) {
	testCases := []struct {
		name   string
		config sensorUpdatePolicyConfig
	}{
		{
			name: "windows_empty_build",
			config: sensorUpdatePolicyConfig{
				Name:                "test-policy-platform-replace",
				Description:         "Test platform replacement with empty builds",
				Enabled:             utils.Addr(true),
				PlatformName:        "Windows",
				Build:               "",
				UninstallProtection: utils.Addr(false),
				Schedule: scheduleConfig{
					Enabled: false,
				},
			},
		},
		{
			name: "linux_empty_builds",
			config: sensorUpdatePolicyConfig{
				Name:                "test-policy-platform-replace",
				Description:         "Test platform replacement with empty builds",
				Enabled:             utils.Addr(true),
				PlatformName:        "Linux",
				Build:               "",
				BuildArm64:          "",
				UninstallProtection: utils.Addr(false),
				Schedule: scheduleConfig{
					Enabled: false,
				},
			},
		},
		{
			name: "mac_empty_build",
			config: sensorUpdatePolicyConfig{
				Name:                "test-policy-platform-replace",
				Description:         "Test platform replacement with empty builds",
				Enabled:             utils.Addr(true),
				PlatformName:        "Mac",
				Build:               "",
				UninstallProtection: utils.Addr(false),
				Schedule: scheduleConfig{
					Enabled: false,
				},
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}

func TestAccSensorUpdatePolicyResource_LinuxPlatform(t *testing.T) {
	testCases := []struct {
		name   string
		config sensorUpdatePolicyConfig
	}{
		{
			name: "linux_valid_builds",
			config: sensorUpdatePolicyConfig{
				Name:                "test-policy-linux-valid",
				Description:         "Test Linux policy with valid builds",
				Enabled:             utils.Addr(true),
				PlatformName:        "Linux",
				Build:               "n1",
				BuildArm64:          "n1",
				UninstallProtection: utils.Addr(false),
				Schedule: scheduleConfig{
					Enabled: false,
				},
			},
		},
		{
			name: "linux_empty_builds",
			config: sensorUpdatePolicyConfig{
				Name:                "test-policy-linux-empty",
				Description:         "Test Linux policy with empty builds",
				Enabled:             utils.Addr(true),
				PlatformName:        "Linux",
				Build:               "",
				BuildArm64:          "",
				UninstallProtection: utils.Addr(false),
				Schedule: scheduleConfig{
					Enabled: false,
				},
			},
		},
		{
			name: "linux_mixed_builds",
			config: sensorUpdatePolicyConfig{
				Name:                "test-policy-linux-mixed",
				Description:         "Test Linux policy with mixed build states",
				Enabled:             utils.Addr(true),
				PlatformName:        "Linux",
				Build:               "n1",
				BuildArm64:          "",
				UninstallProtection: utils.Addr(false),
				Schedule: scheduleConfig{
					Enabled: false,
				},
			},
		},
		{
			name: "linux_with_host_groups",
			config: sensorUpdatePolicyConfig{
				Name:                "test-policy-linux-hg",
				Description:         "Test Linux policy with host groups",
				Enabled:             utils.Addr(true),
				PlatformName:        "Linux",
				Build:               "",
				BuildArm64:          "",
				HostGroupCount:      2,
				UninstallProtection: utils.Addr(false),
				Schedule: scheduleConfig{
					Enabled: false,
				},
			},
		},
		{
			name: "linux_with_schedule",
			config: sensorUpdatePolicyConfig{
				Name:                "test-policy-linux-schedule",
				Description:         "Test Linux policy with schedule",
				Enabled:             utils.Addr(true),
				PlatformName:        "Linux",
				Build:               "",
				BuildArm64:          "",
				UninstallProtection: utils.Addr(false),
				Schedule: scheduleConfig{
					Enabled:  true,
					Timezone: utils.Addr("Etc/UTC"),
					TimeBlocks: []timeBlockConfig{
						{
							Days:      []string{"friday", "monday"},
							StartTime: "02:00",
							EndTime:   "06:00",
						},
					},
				},
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})

				ignoreFields := []string{"last_updated"}
				if tc.config.PlatformName == "Linux" && tc.config.BuildArm64 == "" {
					ignoreFields = append(ignoreFields, "build_arm64")
				}

				steps = append(steps, resource.TestStep{
					ResourceName:            tc.config.resourceName(),
					ImportState:             true,
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: ignoreFields,
				})
			}
			return steps
		}(),
	})
}

func TestAccSensorUpdatePolicyResource_BuildTransitions(t *testing.T) {
	testCases := []struct {
		name   string
		config sensorUpdatePolicyConfig
	}{
		{
			name: "initial_empty_build",
			config: sensorUpdatePolicyConfig{
				Name:                "test-policy-build-transitions",
				Description:         "Test build transitions from empty to valid",
				Enabled:             utils.Addr(true),
				PlatformName:        "Windows",
				Build:               "",
				UninstallProtection: utils.Addr(false),
				Schedule: scheduleConfig{
					Enabled: false,
				},
			},
		},
		{
			name: "update_to_valid_build",
			config: sensorUpdatePolicyConfig{
				Name:                "test-policy-build-transitions",
				Description:         "Test build transitions from empty to valid",
				Enabled:             utils.Addr(true),
				PlatformName:        "Windows",
				Build:               "n1",
				UninstallProtection: utils.Addr(false),
				Schedule: scheduleConfig{
					Enabled: false,
				},
			},
		},
		{
			name: "back_to_empty_build",
			config: sensorUpdatePolicyConfig{
				Name:                "test-policy-build-transitions",
				Description:         "Test build transitions back to empty",
				Enabled:             utils.Addr(true),
				PlatformName:        "Windows",
				Build:               "",
				UninstallProtection: utils.Addr(false),
				Schedule: scheduleConfig{
					Enabled: false,
				},
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}

func TestAccSensorUpdatePolicyResourceBadHostGroup(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_sensor_update_policy_builds" "all" {}
resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "%s"
  enabled              = true
  description          = "made with terraform"
  host_groups          = ["invalid"]
  platform_name        = "Windows"
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection = false 
  schedule = {
    enabled = false
  }
}
`, rName),
				ExpectError: regexp.MustCompile("Error: Host group mismatch"),
			},
		},
	})
}

func TestAccSensorUpdatePolicyResource(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_sensor_update_policy_builds" "all" {}
resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "%s"
  enabled              = true
  description          = "made with terraform"
  host_groups          = []
  platform_name        = "Windows"
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection = false 
  schedule = {
    enabled = false
  }
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"description",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"enabled",
						"true",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"platform_name",
						"Windows",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"uninstall_protection",
						"false",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"schedule.enabled",
						"false",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_sensor_update_policy.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_sensor_update_policy_builds" "all" {}
resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "%s-updated"
  enabled              = false
  description          = "made with terraform updated"
  platform_name        = "Windows"
  host_groups          = []
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection = true 
  schedule = {
    enabled = false
  }
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"description",
						"made with terraform updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"enabled",
						"false",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"platform_name",
						"Windows",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"uninstall_protection",
						"true",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"schedule.enabled",
						"false",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"last_updated",
					),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccSensorUpdatePolicyResourceWithHostGroup(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	hostGroupID, _ := os.LookupEnv("HOST_GROUP_ID")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireHostGroupID) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_sensor_update_policy_builds" "all" {}
resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "%s"
  enabled              = true
  host_groups          = ["%s"]
  description          = "made with terraform"
  platform_name        = "Windows"
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection = false 
  schedule = {
    enabled = false
  }
}
`, rName, hostGroupID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"description",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"enabled",
						"true",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"platform_name",
						"Windows",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"uninstall_protection",
						"false",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"schedule.enabled",
						"false",
					),
					resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test",
						"host_groups.#",
						"1",
					),
					resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test",
						"host_groups.0",
						hostGroupID,
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_sensor_update_policy.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_sensor_update_policy_builds" "all" {}
resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "%s-updated"
  enabled              = false
  description          = "made with terraform updated"
  platform_name        = "Windows"
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection = true 
  host_groups          = []
  schedule = {
    enabled = false
  }
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"description",
						"made with terraform updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"enabled",
						"false",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"platform_name",
						"Windows",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"uninstall_protection",
						"true",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"schedule.enabled",
						"false",
					),

					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"host_groups.#",
						"0",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"last_updated",
					),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccSensorUpdatePolicyResourceWithSchedule(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_sensor_update_policy_builds" "all" {}
resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "%s"
  enabled              = true
  description          = "made with terraform"
  platform_name        = "Windows"
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection = false 
  schedule = {
    enabled = false
  }
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"description",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"enabled",
						"true",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"platform_name",
						"Windows",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"uninstall_protection",
						"false",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"schedule.enabled",
						"false",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"last_updated",
					),
				),
			},
			// Update and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_sensor_update_policy_builds" "all" {}
resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "%s-updated"
  enabled              = false
  description          = "made with terraform updated"
  platform_name        = "Windows"
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection = true 
  schedule = {
    enabled = true 
    timezone = "Etc/UTC"
    time_blocks = [
     {
       days       = ["sunday", "wednesday"]
       start_time = "12:40"
       end_time   = "16:40"
     }
   ]
  }
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"description",
						"made with terraform updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"enabled",
						"false",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"platform_name",
						"Windows",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"uninstall_protection",
						"true",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"schedule.enabled",
						"true",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"schedule.timezone",
						"Etc/UTC",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"schedule.time_blocks.#",
						"1",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"schedule.time_blocks.0.days.#",
						"2",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"schedule.time_blocks.0.days.0",
						"sunday",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"schedule.time_blocks.0.days.1",
						"wednesday",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"schedule.time_blocks.0.start_time",
						"12:40",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"schedule.time_blocks.0.end_time",
						"16:40",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_sensor_update_policy.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}
