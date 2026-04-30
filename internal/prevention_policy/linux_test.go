package preventionpolicy_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccPreventionPolicyLinux_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_prevention_policy_linux.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPolicyLinuxConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
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

func TestAccPreventionPolicyLinux_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_prevention_policy_linux.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPolicyLinuxConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ioa_rule_groups"), knownvalue.SetExact([]knownvalue.Check{})),
					// toggle defaults (false)
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("upload_unknown_detection_related_executables"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("upload_unknown_executables"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("script_based_execution_monitoring"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("quarantine"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("custom_blocking"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("prevent_suspicious_processes"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("drift_prevention"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filesystem_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("network_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("http_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ftp_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tls_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("email_protocol_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_tampering_protection"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("memory_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("on_write_script_file_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("extended_command_line_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("dbus_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enhance_php_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enhance_environment_variable_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("suspicious_file_analysis"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ssh_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enhance_systemd_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("php_script_optimization"), knownvalue.Bool(false)),
					// ml slider defaults (DISABLED)
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_anti_malware").AtMapKey("detection"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_anti_malware").AtMapKey("prevention"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_anti_malware").AtMapKey("detection"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_anti_malware").AtMapKey("prevention"), knownvalue.StringExact("DISABLED")),
				},
			},
			{
				Config: testAccPreventionPolicyLinuxConfig_updated(fmt.Sprintf("%s-updated", rName)),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(fmt.Sprintf("%s-updated", rName))),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("updated description")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ioa_rule_groups"), knownvalue.SetExact([]knownvalue.Check{})),
					// toggles changed to true
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("upload_unknown_detection_related_executables"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("upload_unknown_executables"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("script_based_execution_monitoring"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("quarantine"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("custom_blocking"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("prevent_suspicious_processes"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("drift_prevention"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filesystem_visibility"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("network_visibility"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("http_visibility"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ftp_visibility"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tls_visibility"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("email_protocol_visibility"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_tampering_protection"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("memory_visibility"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("on_write_script_file_visibility"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("extended_command_line_visibility"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("dbus_visibility"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enhance_php_visibility"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enhance_environment_variable_visibility"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("suspicious_file_analysis"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ssh_visibility"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enhance_systemd_visibility"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("php_script_optimization"), knownvalue.Bool(true)),
					// ml sliders changed
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_anti_malware").AtMapKey("detection"), knownvalue.StringExact("MODERATE")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_anti_malware").AtMapKey("prevention"), knownvalue.StringExact("CAUTIOUS")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_anti_malware").AtMapKey("detection"), knownvalue.StringExact("MODERATE")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_anti_malware").AtMapKey("prevention"), knownvalue.StringExact("CAUTIOUS")),
				},
			},
			{
				Config: testAccPreventionPolicyLinuxConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ioa_rule_groups"), knownvalue.SetExact([]knownvalue.Check{})),
					// toggles back to defaults
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("upload_unknown_detection_related_executables"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("upload_unknown_executables"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("script_based_execution_monitoring"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("quarantine"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("custom_blocking"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("prevent_suspicious_processes"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("drift_prevention"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filesystem_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("network_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("http_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ftp_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tls_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("email_protocol_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_tampering_protection"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("memory_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("on_write_script_file_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("extended_command_line_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("dbus_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enhance_php_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enhance_environment_variable_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("suspicious_file_analysis"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ssh_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enhance_systemd_visibility"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("php_script_optimization"), knownvalue.Bool(false)),
					// ml sliders back to defaults
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_anti_malware").AtMapKey("detection"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_anti_malware").AtMapKey("prevention"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_anti_malware").AtMapKey("detection"), knownvalue.StringExact("DISABLED")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sensor_anti_malware").AtMapKey("prevention"), knownvalue.StringExact("DISABLED")),
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

func TestAccPreventionPolicyLinux_validationError(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccPreventionPolicyLinuxConfig_validationError(rName),
				ExpectError: regexp.MustCompile("Invalid ml slider setting"),
			},
		},
	})
}

func testAccPreventionPolicyLinuxConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_prevention_policy_linux" "test" {
  name           = %[1]q
  host_groups    = []
  ioa_rule_groups = []
}`, name)
}

func testAccPreventionPolicyLinuxConfig_updated(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_prevention_policy_linux" "test" {
  name        = %[1]q
  description = "updated description"
  enabled     = false
  host_groups    = []
  ioa_rule_groups = []

  upload_unknown_detection_related_executables = true
  upload_unknown_executables                   = true
  script_based_execution_monitoring            = true
  quarantine                                   = true
  custom_blocking                              = true
  prevent_suspicious_processes                 = true
  drift_prevention                             = true
  filesystem_visibility                        = true
  network_visibility                           = true
  http_visibility                              = true
  ftp_visibility                               = true
  tls_visibility                               = true
  email_protocol_visibility                    = true
  sensor_tampering_protection                  = true
  memory_visibility                            = true
  on_write_script_file_visibility              = true
  extended_command_line_visibility             = true
  dbus_visibility                              = true
  enhance_php_visibility                       = true
  enhance_environment_variable_visibility      = true
  suspicious_file_analysis                     = true
  ssh_visibility                               = true
  enhance_systemd_visibility                   = true
  php_script_optimization                      = true

  cloud_anti_malware = {
    detection  = "MODERATE"
    prevention = "CAUTIOUS"
  }

  sensor_anti_malware = {
    detection  = "MODERATE"
    prevention = "CAUTIOUS"
  }
}`, name)
}

func testAccPreventionPolicyLinuxConfig_validationError(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_prevention_policy_linux" "test" {
  name           = %[1]q
  host_groups    = []
  ioa_rule_groups = []

  cloud_anti_malware = {
    detection  = "CAUTIOUS"
    prevention = "MODERATE"
  }
}`, name)
}
