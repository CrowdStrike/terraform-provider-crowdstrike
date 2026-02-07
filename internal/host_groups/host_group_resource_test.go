package hostgroups_test

import (
	"fmt"
	"regexp"
	"slices"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-framework/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
)

func TestGenerateAssignmentRule(t *testing.T) {
	tests := []struct {
		name                      string
		expectedAPIAssignmentRule string
		groupType                 string
		assignmentRule            string
		hostnames                 []string
		hostIDs                   []string
	}{
		{
			name:                      "dynamic",
			expectedAPIAssignmentRule: "tags:'SensorGroupingTags/cloud-lab'+os_version:'Amazon Linux 2'",
			groupType:                 hostgroups.HgDynamic,
			assignmentRule:            "tags:'SensorGroupingTags/cloud-lab'+os_version:'Amazon Linux 2'",
		},
		{
			name:                      "static",
			expectedAPIAssignmentRule: "device_id:[''],hostname:['MY-HOST-1','MY-HOST-2','MY-HOST-3']",
			groupType:                 hostgroups.HgStatic,
			hostnames:                 []string{"MY-HOST-1", "MY-HOST-2", "MY-HOST-3"},
		},
		{
			name:                      "staticByID",
			expectedAPIAssignmentRule: "device_id:['DEVICE','DEVICE2'],hostname:['']",
			groupType:                 hostgroups.HgStaticByID,
			hostIDs:                   []string{"DEVICE", "DEVICE2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := hostgroups.HostGroupResourceModel{
				GroupType: types.StringValue(tt.groupType),
			}

			switch tt.groupType {
			case hostgroups.HgDynamic:
				config.AssignmentRule = types.StringValue(tt.assignmentRule)
				apiAssignmentRule, diags := hostgroups.GenerateAssignmentRule(t.Context(), config)
				if diags.HasError() {
					t.Errorf("unexpected error: %v", diags)
				}

				if apiAssignmentRule != tt.expectedAPIAssignmentRule {
					t.Errorf(
						"generated assignmentRule = %v, want %v",
						apiAssignmentRule,
						tt.expectedAPIAssignmentRule,
					)
				}
			case hostgroups.HgStatic:
				hostnames, diags := types.SetValueFrom(t.Context(), types.StringType, tt.hostnames)
				if diags.HasError() {
					t.Errorf("unexpected error: %v", diags)
				}
				config.Hostnames = hostnames
				apiAssignmentRule, diags := hostgroups.GenerateAssignmentRule(t.Context(), config)
				if diags.HasError() {
					t.Errorf("unexpected error: %v", diags)
				}

				if apiAssignmentRule != tt.expectedAPIAssignmentRule {
					t.Errorf(
						"generated assignmentRule = %v, want %v",
						apiAssignmentRule,
						tt.expectedAPIAssignmentRule,
					)
				}
			case hostgroups.HgStaticByID:
				hostIDs, diags := types.SetValueFrom(t.Context(), types.StringType, tt.hostIDs)
				if diags.HasError() {
					t.Errorf("unexpected error: %v", diags)
				}
				config.HostIDs = hostIDs
				apiAssignmentRule, diags := hostgroups.GenerateAssignmentRule(t.Context(), config)
				if diags.HasError() {
					t.Errorf("unexpected error: %v", diags)
				}

				if apiAssignmentRule != tt.expectedAPIAssignmentRule {
					t.Errorf(
						"generated assignmentRule = %v, want %v",
						apiAssignmentRule,
						tt.expectedAPIAssignmentRule,
					)
				}
			}
		})
	}
}

func TestAssignAssignmentRule(t *testing.T) {
	tests := []struct {
		name                   string
		apiAssignmentRule      string
		groupType              string
		expectedAssignmentRule string
		expectedHostnames      []string
		expectedHostIDs        []string
	}{
		{
			name:                   "dynamic",
			apiAssignmentRule:      "tags:'SensorGroupingTags/cloud-lab'+os_version:'Amazon Linux 2'",
			groupType:              hostgroups.HgDynamic,
			expectedAssignmentRule: "tags:'SensorGroupingTags/cloud-lab'+os_version:'Amazon Linux 2'",
		},
		{
			name:              "static",
			apiAssignmentRule: "device_id:['DEVICE','DEVICE2'],hostname:['MY HOST-1', 'MY-HOST-2','MY-HOST-3','']",
			groupType:         hostgroups.HgStatic,
			expectedHostnames: []string{"MY HOST-1", "MY-HOST-2", "MY-HOST-3"},
		},
		{
			name:              "staticEmpty",
			apiAssignmentRule: "device_id:['DEVICE','DEVICE2'],hostname:['']",
			groupType:         hostgroups.HgStatic,
			expectedHostnames: []string{},
		},

		{
			name:              "staticByID",
			apiAssignmentRule: "device_id:['DEVICE HOST','DEVICE2',  'DEVICE-3', ''],hostname:['MY HOST-1', 'MY-HOST-2','MY-HOST-3']",
			groupType:         hostgroups.HgStaticByID,
			expectedHostIDs:   []string{"DEVICE HOST", "DEVICE2", "DEVICE-3"},
		},
		{
			name:              "staticByIDEmpty",
			apiAssignmentRule: "device_id:[''],hostname:['MY-HOST-1', 'MY-HOST-2', 'MY-HOST-3']",
			groupType:         hostgroups.HgStaticByID,
			expectedHostIDs:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := hostgroups.HostGroupResourceModel{
				GroupType: types.StringValue(tt.groupType),
			}
			diags := hostgroups.AssignAssignmentRule(t.Context(), tt.apiAssignmentRule, &config)
			if diags.HasError() {
				t.Errorf("unexpected error: %v", diags)
			}

			switch tt.groupType {
			case hostgroups.HgDynamic:
				if config.AssignmentRule.ValueString() != tt.expectedAssignmentRule {
					t.Errorf(
						"config.AssignmentRule = %v, want %v",
						config.AssignmentRule,
						tt.expectedAssignmentRule,
					)
				}
			case hostgroups.HgStatic:
				var hostnames []string
				diags := config.Hostnames.ElementsAs(t.Context(), &hostnames, false)
				if diags.HasError() {
					t.Errorf("unexpected error: %v", diags)
				}

				if !slices.Equal(hostnames, tt.expectedHostnames) {
					t.Errorf(
						"config.hostnames= %v, want %v",
						hostnames,
						tt.expectedHostnames,
					)
				}
			case hostgroups.HgStaticByID:
				var hostIDs []string
				diags := config.HostIDs.ElementsAs(t.Context(), &hostIDs, false)
				if diags.HasError() {
					t.Errorf("unexpected error: %v", diags)
				}

				if !slices.Equal(hostIDs, tt.expectedHostIDs) {
					t.Errorf(
						"config.hostIDs= %v, want %v",
						config.HostIDs,
						tt.expectedHostIDs,
					)
				}
			}
		})
	}
}

func TestAccHostGroupResource(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = "%s"
  description     = "made with terraform"
  type            = "dynamic"
  assignment_rule = ""
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"description",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"type",
						"dynamic",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"assignment_rule",
						"",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_host_group.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = "%s-updated"
  description     = "made with terraform updated"
  type            = "dynamic"
  assignment_rule = "tags:'SensorGroupingTags/cloud-lab'+os_version:'Amazon Linux 2'"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"description",
						"made with terraform updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"type",
						"dynamic",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"assignment_rule",
						"tags:'SensorGroupingTags/cloud-lab'+os_version:'Amazon Linux 2'",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"last_updated",
					),
				),
			},
			// if no assignment_rule is passed we don't manage the value
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = "%s-updated"
  description     = "made with terraform updated"
  type            = "dynamic"
  assignment_rule = "tags:'SensorGroupingTags/cloud-lab'"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"description",
						"made with terraform updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"type",
						"dynamic",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"assignment_rule",
						"tags:'SensorGroupingTags/cloud-lab'",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"last_updated",
					),
				),
			},
			// remove assignment_rule
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = "%s-updated"
  description     = "made with terraform updated"
  type            = "dynamic"
  assignment_rule = ""
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"description",
						"made with terraform updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"type",
						"dynamic",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"assignment_rule",
						"",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"last_updated",
					),
				),
			},
		},
	})
}

func TestAccHostGroupResourceValidation(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	hostGroup := func(name, typ, attrs string) string {
		return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = "%s"
  description = "made with terraform"
  type        = "%s"
  %s
}
`, name, typ, attrs)
	}

	tests := []struct {
		name        string
		config      string
		expectError *regexp.Regexp
	}{
		{
			name:        "name_empty",
			config:      hostGroup("", "dynamic", `assignment_rule = "tags:'test'"`),
			expectError: regexp.MustCompile(`must not be empty or contain only whitespace`),
		},
		{
			name:        "name_whitespace_only",
			config:      hostGroup("   ", "dynamic", `assignment_rule = "tags:'test'"`),
			expectError: regexp.MustCompile(`must not be empty or contain only whitespace`),
		},
		{
			name:        "hostname_empty",
			config:      hostGroup(rName, "static", `hostnames = [""]`),
			expectError: regexp.MustCompile(`must not be empty or contain only whitespace`),
		},
		{
			name:        "hostname_whitespace_only",
			config:      hostGroup(rName, "static", `hostnames = ["  "]`),
			expectError: regexp.MustCompile(`must not be empty or contain only\s+whitespace`),
		},
		{
			name:        "host_id_empty",
			config:      hostGroup(rName, "staticByID", `host_ids = [""]`),
			expectError: regexp.MustCompile(`must not be empty or contain only whitespace`),
		},
		{
			name:        "host_id_whitespace_only",
			config:      hostGroup(rName, "staticByID", `host_ids = ["   "]`),
			expectError: regexp.MustCompile(`must not be empty or contain only\s+whitespace`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t) },
				Steps: []resource.TestStep{
					{
						Config:      tt.config,
						ExpectError: tt.expectError,
						PlanOnly:    true,
					},
				},
			})
		})
	}
}
