package preventionpolicy_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccPreventionPolicyWindowsConfig_basic(rName string, enabled bool) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_prevention_policy_windows" "test" {
  name                                   = "%s"
  enabled                                = %t
  host_groups                            = []
  ioa_rule_groups                        = []
  description                            = "made with terraform"
  additional_user_mode_data              = true
  suspicious_registry_operations         = true
  boot_configuration_database_protection = true
  wsl2_visibility                        = true
  cloud_anti_malware_microsoft_office_files = {
    detection  = "MODERATE"
    prevention = "MODERATE"
  }
}
`, rName, enabled)
}

func testAccPreventionPolicyWindowsConfig_groups(
	rName string,
	hostGroupID string,
	ruleGroupID string,
	enabled bool,
) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_prevention_policy_windows" "test" {
  name                                   = "%s"
  host_groups                            = ["%s"]
  ioa_rule_groups                        = ["%s"]
  enabled                                = %t
  description                            = "updated with terraform"
  additional_user_mode_data              = false
  suspicious_registry_operations         = false
  boot_configuration_database_protection = false
  wsl2_visibility                        = false
  cloud_anti_malware_microsoft_office_files = {
    detection  = "MODERATE"
    prevention = "DISABLED"
  }
}
`, rName, hostGroupID, ruleGroupID, enabled)
}

func testAccPreventionPolicyWindowsConfig_validationError(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_prevention_policy_windows" "test" {
  name                                   = "%s"
  host_groups                            = []
  ioa_rule_groups                        = []
  enabled                                = true
  description                            = "validation error test"
  suspicious_registry_operations         = false
  boot_configuration_database_protection = true
}
`, rName)
}

// regression test to handle unknown states https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues/136
func testAccPreventionPolicyWindowsConfig_unknown(rName string, enabled bool) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
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

resource "crowdstrike_prevention_policy_windows" "test" {
  name 			  = "%s"
  enabled 	      = %t
  description     = "Made with terraform"
  ioa_rule_groups = []
  host_groups     = []
  extended_user_mode_data = local.anti_malware_settings.extended_user_mode_data
  cloud_anti_malware_microsoft_office_files = local.anti_malware_settings.cloud_anti_malware_microsoft_office_files
}`, rName, enabled)
}

func TestAccPreventionPolicyWindowsResource_unknown(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resourceName := "crowdstrike_prevention_policy_windows.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPolicyWindowsConfig_unknown(rName, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
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

func TestAccPreventionPolicyWindowsResource_validationError(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccPreventionPolicyWindowsConfig_validationError(rName),
				ExpectError: regexp.MustCompile("Error: requirements not met to enable boot_configuration_database_protection"),
			},
		},
	})
}

func TestAccPreventionPolicyWindowsResource(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resourceName := "crowdstrike_prevention_policy_windows.test"
	hostGroupID, _ := os.LookupEnv("HOST_GROUP_ID")
	ruleGroupID, _ := os.LookupEnv("IOA_RULE_GROUP_ID")

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireHostGroupID, acctest.RequireIOARuleGroupID) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccPreventionPolicyWindowsConfig_basic(rName, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(
						resourceName,
						"description",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(
						resourceName,
						"additional_user_mode_data",
						"true",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"suspicious_registry_operations",
						"true",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"boot_configuration_database_protection",
						"true",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"wsl2_visibility",
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
					// Verify dynamic values have any value set in the state.
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
				Config: testAccPreventionPolicyWindowsConfig_groups(
					fmt.Sprintf("%s-updated", rName),
					hostGroupID,
					ruleGroupID,
					false,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						resourceName,
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"description",
						"updated with terraform",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"enabled",
						"false",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"additional_user_mode_data",
						"false",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"suspicious_registry_operations",
						"false",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"boot_configuration_database_protection",
						"false",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"wsl2_visibility",
						"false",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"cloud_anti_malware_microsoft_office_files.detection",
						"MODERATE",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"cloud_anti_malware_microsoft_office_files.prevention",
						"DISABLED",
					),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.0", hostGroupID),
					resource.TestCheckResourceAttr(resourceName, "ioa_rule_groups.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "ioa_rule_groups.0", ruleGroupID),
				),
			},
		},
	})
}
