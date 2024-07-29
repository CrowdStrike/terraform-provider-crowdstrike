package provider

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
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
			groupType:                 hgDynamic,
			assignmentRule:            "tags:'SensorGroupingTags/cloud-lab'+os_version:'Amazon Linux 2'",
		},
		{
			name:                      "static",
			expectedAPIAssignmentRule: "device_id:[''],hostname:['MY-HOST-1','MY-HOST-2','MY-HOST-3']",
			groupType:                 hgStatic,
			hostnames:                 []string{"MY-HOST-1", "MY-HOST-2", "MY-HOST-3"},
		},
		{
			name:                      "staticByID",
			expectedAPIAssignmentRule: "device_id:['DEVICE','DEVICE2'],hostname:['']",
			groupType:                 hgStaticByID,
			hostIDs:                   []string{"DEVICE", "DEVICE2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			config := hostGroupResourceModel{
				GroupType: types.StringValue(tt.groupType),
			}

			switch tt.groupType {
			case hgDynamic:
				config.AssignmentRule = types.StringValue(tt.assignmentRule)
				apiAssignmentRule, diags := generateAssignmentRule(ctx, config)
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
			case hgStatic:
				hostnames, diags := types.SetValueFrom(ctx, types.StringType, tt.hostnames)
				if diags.HasError() {
					t.Errorf("unexpected error: %v", diags)
				}
				config.Hostnames = hostnames
				apiAssignmentRule, diags := generateAssignmentRule(ctx, config)
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
			case hgStaticByID:
				hostIDs, diags := types.SetValueFrom(ctx, types.StringType, tt.hostIDs)
				if diags.HasError() {
					t.Errorf("unexpected error: %v", diags)
				}
				config.HostIDs = hostIDs
				apiAssignmentRule, diags := generateAssignmentRule(ctx, config)
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
			groupType:              hgDynamic,
			expectedAssignmentRule: "tags:'SensorGroupingTags/cloud-lab'+os_version:'Amazon Linux 2'",
		},
		{
			name:              "static",
			apiAssignmentRule: "device_id:['DEVICE','DEVICE2'],hostname:['MY HOST-1', 'MY-HOST-2','MY-HOST-3','']",
			groupType:         hgStatic,
			expectedHostnames: []string{"MY HOST-1", "MY-HOST-2", "MY-HOST-3"},
		},
		{
			name:              "staticEmpty",
			apiAssignmentRule: "device_id:['DEVICE','DEVICE2'],hostname:['']",
			groupType:         hgStatic,
			expectedHostnames: []string{},
		},

		{
			name:              "staticByID",
			apiAssignmentRule: "device_id:['DEVICE HOST','DEVICE2',  'DEVICE-3', ''],hostname:['MY HOST-1', 'MY-HOST-2','MY-HOST-3']",
			groupType:         hgStaticByID,
			expectedHostIDs:   []string{"DEVICE HOST", "DEVICE2", "DEVICE-3"},
		},
		{
			name:              "staticByIDEmpty",
			apiAssignmentRule: "device_id:[''],hostname:['MY-HOST-1', 'MY-HOST-2', 'MY-HOST-3']",
			groupType:         hgStaticByID,
			expectedHostIDs:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			config := hostGroupResourceModel{
				GroupType: types.StringValue(tt.groupType),
			}
			diags := assignAssignmentRule(ctx, tt.apiAssignmentRule, &config)
			if diags.HasError() {
				t.Errorf("unexpected error: %v", diags)
			}

			switch tt.groupType {
			case hgDynamic:
				if config.AssignmentRule.ValueString() != tt.expectedAssignmentRule {
					t.Errorf(
						"config.AssignmentRule = %v, want %v",
						config.AssignmentRule,
						tt.expectedAssignmentRule,
					)
				}
			case hgStatic:
				var hostnames []string
				diags := config.Hostnames.ElementsAs(ctx, &hostnames, false)
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
			case hgStaticByID:
				var hostIDs []string
				diags := config.HostIDs.ElementsAs(ctx, &hostIDs, false)
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
	rName := acctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		PreCheck:                 func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: providerConfig + fmt.Sprintf(`
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
				Config: providerConfig + fmt.Sprintf(`
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
				Config: providerConfig + fmt.Sprintf(`
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
				Config: providerConfig + fmt.Sprintf(`
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
