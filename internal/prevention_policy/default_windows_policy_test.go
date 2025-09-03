package preventionpolicy_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

func testAccDefaultPreventionPolicyWindowsConfig_basic() string {
	return acctest.ProviderConfig + `
resource "crowdstrike_default_prevention_policy_windows" "test" {
  ioa_rule_groups           = []
  description               = "made with terraform"
  additional_user_mode_data = true
  cloud_anti_malware_microsoft_office_files = {
    detection  = "MODERATE"
    prevention = "MODERATE"
  }
}`
}

func testAccDefaultPreventionPolicyWindowsConfig_groups(
	ruleGroupID string,
) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_default_prevention_policy_windows" "test" {
  ioa_rule_groups           = ["%s"]
  description               = "made with terraform"
  additional_user_mode_data = true
  cloud_anti_malware_microsoft_office_files = {
    detection  = "MODERATE"
    prevention = "MODERATE"
  }
}
`, ruleGroupID)
}

// regression test to handle unknown states https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues/136
func testAccDefaultPreventionPolicyWindowsConfig_unknown() string {
	return acctest.ProviderConfig + `
variable "extended_user_mode_data" {
  type = object({
    detection = string
  })
  description = "Extended user mode data settings."
  default = {
    detection = "MODERATE"
  }
}

variable "cloud_anti_malware_microsoft_office_files" {
  type = object({
    detection = string
    prevention = string
  })
  description = "Cloud anti-malware settings for Microsoft Office files."
  default = {
    detection = "MODERATE"
    prevention = "MODERATE"
  }
}

locals {
  anti_malware_settings = {
    extended_user_mode_data = var.extended_user_mode_data
    cloud_anti_malware_microsoft_office_files = var.cloud_anti_malware_microsoft_office_files
  }
}

resource "crowdstrike_default_prevention_policy_windows" "default" {
  description     = "Default Windows Prevention Policy"
  ioa_rule_groups = []
  extended_user_mode_data = local.anti_malware_settings.extended_user_mode_data
  cloud_anti_malware_microsoft_office_files = local.anti_malware_settings.cloud_anti_malware_microsoft_office_files
}
	`
}

func TestAccDefaultPreventionPolicyWindowsResource_unknown(t *testing.T) {
	resourceName := "crowdstrike_default_prevention_policy_windows.default"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccDefaultPreventionPolicyWindowsConfig_unknown(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						resourceName,
						"extended_user_mode_data.detection",
						"MODERATE",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"cloud_anti_malware_microsoft_office_files.detection",
						"MODERATE",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"cloud_anti_malware_microsoft_office_files.prevention",
						"MODERATE",
					),
				),
			},
		},
	})
}

func TestAccDefaultPreventionPolicyWindowsResource(t *testing.T) {
	resourceName := "crowdstrike_default_prevention_policy_windows.test"
	ruleGroupID, _ := os.LookupEnv("IOA_RULE_GROUP_ID")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireIOARuleGroupID) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccDefaultPreventionPolicyWindowsConfig_basic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						resourceName,
						"description",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"additional_user_mode_data",
						"true",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"cloud_anti_malware_microsoft_office_files.detection",
						"MODERATE",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"cloud_anti_malware_microsoft_office_files.prevention",
						"MODERATE",
					),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			{
				Config: testAccDefaultPreventionPolicyWindowsConfig_groups(
					ruleGroupID,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "ioa_rule_groups.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "ioa_rule_groups.0", ruleGroupID),
				),
			},
		},
	})
}
