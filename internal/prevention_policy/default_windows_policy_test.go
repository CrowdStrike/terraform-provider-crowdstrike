package preventionpolicy_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

func testAccDefaultPreventionPolicyWindowsConfig_validationError() string {
	return acctest.ProviderConfig + `
resource "crowdstrike_default_prevention_policy_windows" "test" {
  ioa_rule_groups                        = []
  description                            = "validation error test"
  suspicious_registry_operations         = false
  boot_configuration_database_protection = true
}`
}

func testAccDefaultPreventionPolicyWindowsConfig_basic() string {
	return acctest.ProviderConfig + `
resource "crowdstrike_default_prevention_policy_windows" "test" {
  ioa_rule_groups                        = []
  description                            = "made with terraform"
  additional_user_mode_data              = true
  suspicious_registry_operations         = true
  boot_configuration_database_protection = true
  wsl2_visibility                        = true
  suspicious_file_analysis               = true

  cloud_anti_malware_microsoft_office_files = {
    detection  = "MODERATE"
    prevention = "MODERATE"
  }

  cloud_adware_pup_user_initiated = {
    detection  = "CAUTIOUS"
    prevention = "CAUTIOUS"
  }

  cloud_based_anomalous_process_execution = {
    detection = "MODERATE"
  }
}`
}

func testAccDefaultPreventionPolicyWindowsConfig_update(
	ruleGroupID string,
) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_default_prevention_policy_windows" "test" {
  ioa_rule_groups                        = ["%s"]
  description                            = "updated with terraform"
  additional_user_mode_data              = false
  suspicious_registry_operations         = false
  boot_configuration_database_protection = false
  wsl2_visibility                        = false
  suspicious_file_analysis               = false

  cloud_anti_malware_microsoft_office_files = {
    detection  = "MODERATE"
    prevention = "DISABLED"
  }

  cloud_adware_pup_user_initiated = {
    detection  = "DISABLED"
    prevention = "DISABLED"
  }

  cloud_based_anomalous_process_execution = {
    detection = "DISABLED"
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

func TestAccDefaultPreventionPolicyWindowsResource_validationError(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccDefaultPreventionPolicyWindowsConfig_validationError(),
				ExpectError: regexp.MustCompile("When boot_configuration_database_protection is enabled"),
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
						"suspicious_registry_operations",
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
						"suspicious_file_analysis",
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
					resource.TestCheckResourceAttr(
						resourceName,
						"cloud_adware_pup_user_initiated.detection",
						"CAUTIOUS",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"cloud_adware_pup_user_initiated.prevention",
						"CAUTIOUS",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"cloud_based_anomalous_process_execution.detection",
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
				Config: testAccDefaultPreventionPolicyWindowsConfig_update(
					ruleGroupID,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						resourceName,
						"description",
						"updated with terraform",
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
						"suspicious_file_analysis",
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
					resource.TestCheckResourceAttr(
						resourceName,
						"cloud_adware_pup_user_initiated.detection",
						"DISABLED",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"cloud_adware_pup_user_initiated.prevention",
						"DISABLED",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"cloud_based_anomalous_process_execution.detection",
						"DISABLED",
					),
					resource.TestCheckResourceAttr(resourceName, "ioa_rule_groups.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "ioa_rule_groups.0", ruleGroupID),
				),
			},
		},
	})
}
