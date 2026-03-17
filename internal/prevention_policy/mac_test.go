package preventionpolicy_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccPreventionPolicyMac_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_prevention_policy_mac.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPolicyMacConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ioa_rule_groups"), knownvalue.SetExact([]knownvalue.Check{})),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccPreventionPolicyMac_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_prevention_policy_mac.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPolicyMacConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ioa_rule_groups"), knownvalue.SetExact([]knownvalue.Check{})),
					// toggle defaults (false)
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notify_end_users"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("upload_unknown_detection_related_executables"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("upload_unknown_executables"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_tampering_protection"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("script_based_execution_monitoring"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("detect_on_write"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("quarantine_on_write"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("quarantine"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("custom_blocking"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("intelligence_sourced_threats"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("prevent_suspicious_processes"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("xpcom_shell"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("empyre_backdoor"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("chopper_webshell"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("kc_password_decoded"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("hash_collector"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enhanced_network_visibility"), knownvalue.Bool(false)),
					// ml slider defaults (DISABLED)
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_anti_malware").AtMapKey("detection"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_anti_malware").AtMapKey("prevention"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_adware_and_pup").AtMapKey("detection"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_adware_and_pup").AtMapKey("prevention"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_anti_malware").AtMapKey("detection"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_anti_malware").AtMapKey("prevention"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_adware_and_pup").AtMapKey("detection"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_adware_and_pup").AtMapKey("prevention"), knownvalue.StringExact("DISABLED")),
				},
			},
			{
				Config: testAccPreventionPolicyMacConfig_updated(fmt.Sprintf("%s-updated", rName)),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(fmt.Sprintf("%s-updated", rName))),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("updated description")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					// toggles changed to true
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notify_end_users"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enhanced_network_visibility"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_tampering_protection"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("quarantine"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("custom_blocking"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("detect_on_write"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("quarantine_on_write"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("script_based_execution_monitoring"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("upload_unknown_detection_related_executables"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("upload_unknown_executables"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("intelligence_sourced_threats"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("prevent_suspicious_processes"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("xpcom_shell"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("empyre_backdoor"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("chopper_webshell"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("kc_password_decoded"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("hash_collector"), knownvalue.Bool(true)),
					// ml sliders changed
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_anti_malware").AtMapKey("detection"), knownvalue.StringExact("MODERATE")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_anti_malware").AtMapKey("prevention"), knownvalue.StringExact("CAUTIOUS")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_adware_and_pup").AtMapKey("detection"), knownvalue.StringExact("AGGRESSIVE")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_adware_and_pup").AtMapKey("prevention"), knownvalue.StringExact("MODERATE")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_anti_malware").AtMapKey("detection"), knownvalue.StringExact("MODERATE")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_anti_malware").AtMapKey("prevention"), knownvalue.StringExact("CAUTIOUS")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_adware_and_pup").AtMapKey("detection"), knownvalue.StringExact("EXTRA_AGGRESSIVE")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_adware_and_pup").AtMapKey("prevention"), knownvalue.StringExact("AGGRESSIVE")),
				},
			},
			{
				Config: testAccPreventionPolicyMacConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					// toggles back to defaults
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notify_end_users"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("upload_unknown_detection_related_executables"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("upload_unknown_executables"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_tampering_protection"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("script_based_execution_monitoring"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("detect_on_write"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("quarantine_on_write"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("quarantine"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("custom_blocking"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("intelligence_sourced_threats"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("prevent_suspicious_processes"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("xpcom_shell"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("empyre_backdoor"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("chopper_webshell"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("kc_password_decoded"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("hash_collector"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enhanced_network_visibility"), knownvalue.Bool(false)),
					// ml sliders back to defaults
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_anti_malware").AtMapKey("detection"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_anti_malware").AtMapKey("prevention"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_adware_and_pup").AtMapKey("detection"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_adware_and_pup").AtMapKey("prevention"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_anti_malware").AtMapKey("detection"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_anti_malware").AtMapKey("prevention"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_adware_and_pup").AtMapKey("detection"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_adware_and_pup").AtMapKey("prevention"), knownvalue.StringExact("DISABLED")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func testAccPreventionPolicyMacConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_prevention_policy_mac" "test" {
  name           = %[1]q
  host_groups    = []
  ioa_rule_groups = []
}`, name)
}

func testAccPreventionPolicyMacConfig_updated(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_prevention_policy_mac" "test" {
  name        = %[1]q
  description = "updated description"
  enabled     = false
  host_groups    = []
  ioa_rule_groups = []

  notify_end_users                           = true
  enhanced_network_visibility                = true
  sensor_tampering_protection                = true
  quarantine                                 = true
  custom_blocking                            = true
  detect_on_write                            = true
  quarantine_on_write                        = true
  script_based_execution_monitoring          = true
  upload_unknown_detection_related_executables = true
  upload_unknown_executables                 = true
  intelligence_sourced_threats               = true
  prevent_suspicious_processes               = true
  xpcom_shell                                = true
  empyre_backdoor                            = true
  chopper_webshell                           = true
  kc_password_decoded                        = true
  hash_collector                             = true

  cloud_anti_malware = {
    detection  = "MODERATE"
    prevention = "CAUTIOUS"
  }

  cloud_adware_and_pup = {
    detection  = "AGGRESSIVE"
    prevention = "MODERATE"
  }

  sensor_anti_malware = {
    detection  = "MODERATE"
    prevention = "CAUTIOUS"
  }

  sensor_adware_and_pup = {
    detection  = "EXTRA_AGGRESSIVE"
    prevention = "AGGRESSIVE"
  }
}`, name)
}
