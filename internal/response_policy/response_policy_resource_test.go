package responsepolicy_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccResponsePolicyResourceWindows(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_response_policy.test"
	hgResourcename := "crowdstrike_host_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResponsePolicyWindowsConfig(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test RTR Policy"),
					resource.TestCheckResourceAttr(resourceName, "platform_name", "Windows"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "real_time_response", "false"),
					resource.TestCheckResourceAttr(resourceName, "custom_scripts", "false"),
					resource.TestCheckResourceAttr(resourceName, "get_command", "false"),
					resource.TestCheckResourceAttr(resourceName, "put_command", "false"),
					resource.TestCheckResourceAttr(resourceName, "exec_command", "false"),
					resource.TestCheckResourceAttr(resourceName, "falcon_scripts", "false"),
					resource.TestCheckResourceAttr(resourceName, "memdump_command", "false"),
					resource.TestCheckResourceAttr(resourceName, "xmemdump_command", "false"),
					resource.TestCheckResourceAttr(resourceName, "put_and_run_command", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", hgResourcename, "id"),
				),
			},
			{
				Config: testAccResponsePolicyWindowsConfigUpdate(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName+"-updated"),
					resource.TestCheckNoResourceAttr(resourceName, "description"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "real_time_response", "true"),
					resource.TestCheckResourceAttr(resourceName, "custom_scripts", "true"),
					resource.TestCheckResourceAttr(resourceName, "get_command", "true"),
					resource.TestCheckResourceAttr(resourceName, "put_command", "true"),
					resource.TestCheckResourceAttr(resourceName, "exec_command", "true"),
					resource.TestCheckResourceAttr(resourceName, "falcon_scripts", "true"),
					resource.TestCheckResourceAttr(resourceName, "memdump_command", "true"),
					resource.TestCheckResourceAttr(resourceName, "xmemdump_command", "true"),
					resource.TestCheckResourceAttr(resourceName, "put_and_run_command", "true"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "0"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			},
		},
	})
}

func TestAccResponsePolicyResourceMac(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_response_policy.test"
	hgResourcename := "crowdstrike_host_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResponsePolicyMacConfig(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test RTR Mac Policy"),
					resource.TestCheckResourceAttr(resourceName, "platform_name", "Mac"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "real_time_response", "false"),
					resource.TestCheckResourceAttr(resourceName, "custom_scripts", "false"),
					resource.TestCheckResourceAttr(resourceName, "get_command", "false"),
					resource.TestCheckResourceAttr(resourceName, "put_command", "false"),
					resource.TestCheckResourceAttr(resourceName, "exec_command", "false"),
					resource.TestCheckResourceAttr(resourceName, "put_and_run_command", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", hgResourcename, "id"),
				),
			},
			{
				Config: testAccResponsePolicyMacConfigUpdate(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName+"-updated"),
					resource.TestCheckNoResourceAttr(resourceName, "description"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "real_time_response", "true"),
					resource.TestCheckResourceAttr(resourceName, "custom_scripts", "true"),
					resource.TestCheckResourceAttr(resourceName, "get_command", "true"),
					resource.TestCheckResourceAttr(resourceName, "put_command", "true"),
					resource.TestCheckResourceAttr(resourceName, "exec_command", "true"),
					resource.TestCheckResourceAttr(resourceName, "put_and_run_command", "true"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "0"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			},
		},
	})
}

func TestAccResponsePolicyResourceLinux(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_response_policy.test"
	hgResourceName := "crowdstrike_host_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResponsePolicyLinuxConfig(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test RTR Linux Policy"),
					resource.TestCheckResourceAttr(resourceName, "platform_name", "Linux"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "real_time_response", "false"),
					resource.TestCheckResourceAttr(resourceName, "custom_scripts", "false"),
					resource.TestCheckResourceAttr(resourceName, "get_command", "false"),
					resource.TestCheckResourceAttr(resourceName, "put_command", "false"),
					resource.TestCheckResourceAttr(resourceName, "exec_command", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", hgResourceName, "id"),
				),
			},
			{
				Config: testAccResponsePolicyLinuxConfigUpdate(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName+"-updated"),
					resource.TestCheckNoResourceAttr(resourceName, "description"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "real_time_response", "true"),
					resource.TestCheckResourceAttr(resourceName, "custom_scripts", "true"),
					resource.TestCheckResourceAttr(resourceName, "get_command", "true"),
					resource.TestCheckResourceAttr(resourceName, "put_command", "true"),
					resource.TestCheckResourceAttr(resourceName, "exec_command", "true"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "0"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			},
		},
	})
}

func TestAccResponsePolicyResource_validationErrors_Mac(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccResponsePolicyValidationConfig_Mac(),
				ExpectError: regexp.MustCompile("(?s).*Real Time Response required.*falcon_scripts requires custom_scripts.*Invalid platform for falcon_scripts.*Invalid platform for memdump_command.*Invalid platform for xmemdump_command.*"),
			},
		},
	})
}

func TestAccResponsePolicyResource_validationErrors_Linux(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccResponsePolicyValidationConfig_Linux(),
				ExpectError: regexp.MustCompile("(?s).*Real Time Response required.*falcon_scripts requires custom_scripts.*Invalid platform for falcon_scripts.*Invalid platform for memdump_command.*Invalid platform for xmemdump_command.*Invalid platform for put_and_run_command.*"),
			},
		},
	})
}

func testAccResponsePolicyWindowsConfig(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = "%[1]s"
  description     = "Test host group 1"
  type            = "dynamic"
  assignment_rule = "tags:'SensorGroupingTags/test'"
}

resource "crowdstrike_response_policy" "test" {
  name          = "%[1]s"
  description   = "Test RTR Policy"
  platform_name = "Windows"
  enabled       = false
  host_groups   = [crowdstrike_host_group.test.id]

  real_time_response  = false
  custom_scripts      = false
  get_command         = false
  put_command         = false
  exec_command        = false
  falcon_scripts      = false
  memdump_command     = false
  xmemdump_command    = false
  put_and_run_command = false
}
`, rName)
}

func testAccResponsePolicyMacConfig(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = "%[1]s"
  description     = "Test host group 1"
  type            = "dynamic"
  assignment_rule = "tags:'SensorGroupingTags/test'"
}

resource "crowdstrike_response_policy" "test" {
  name          = "%[1]s"
  description   = "Test RTR Mac Policy"
  platform_name = "Mac"
  enabled       = false
  host_groups   = [crowdstrike_host_group.test.id]

  real_time_response  = false
  custom_scripts      = false
  get_command         = false
  put_command         = false
  exec_command        = false
  put_and_run_command = false
}
`, rName)
}

func testAccResponsePolicyLinuxConfig(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = "%[1]s"
  description     = "Test host group 1"
  type            = "dynamic"
  assignment_rule = "tags:'SensorGroupingTags/test'"
}

resource "crowdstrike_response_policy" "test" {
  name          = "%[1]s"
  description   = "Test RTR Linux Policy"
  platform_name = "Linux"
  enabled       = false
  host_groups   = [crowdstrike_host_group.test.id]

  real_time_response = false
  custom_scripts     = false
  get_command        = false
  put_command        = false
  exec_command       = false
}
`, rName)
}

func testAccResponsePolicyValidationConfig_Mac() string {
	return `
resource "crowdstrike_response_policy" "test" {
  name               = "test-rtr-policy-validation-mac"
  description        = "Test RTR Policy for validation"
  platform_name      = "Mac"
  enabled            = true
  real_time_response = false
  custom_scripts     = false
  get_command        = true
  falcon_scripts     = true
  memdump_command    = true
  xmemdump_command   = true
  put_and_run_command = true
}
`
}

func testAccResponsePolicyValidationConfig_Linux() string {
	return `
resource "crowdstrike_response_policy" "test" {
  name                = "test-rtr-policy-validation-linux"
  description         = "Test RTR Policy for validation"
  platform_name       = "Linux"
  enabled             = true
  real_time_response  = false
  custom_scripts      = false
  get_command         = true
  falcon_scripts      = true
  memdump_command     = true
  xmemdump_command    = true
  put_and_run_command = true
}
`
}

func testAccResponsePolicyWindowsConfigUpdate(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_response_policy" "test" {
  name          = "%[1]s-updated"
  platform_name = "Windows"
  enabled       = true

  real_time_response  = true
  custom_scripts      = true
  get_command         = true
  put_command         = true
  exec_command        = true
  falcon_scripts      = true
  memdump_command     = true
  xmemdump_command    = true
  put_and_run_command = true
}
`, rName)
}

func testAccResponsePolicyMacConfigUpdate(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_response_policy" "test" {
  name          = "%[1]s-updated"
  platform_name = "Mac"
  enabled       = true

  real_time_response  = true
  custom_scripts      = true
  get_command         = true
  put_command         = true
  exec_command        = true
  put_and_run_command = true
}
`, rName)
}

func testAccResponsePolicyLinuxConfigUpdate(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_response_policy" "test" {
  name          = "%[1]s-updated"
  platform_name = "Linux"
  enabled       = true

  real_time_response = true
  custom_scripts     = true
  get_command        = true
  put_command        = true
  exec_command       = true
}
`, rName)
}
