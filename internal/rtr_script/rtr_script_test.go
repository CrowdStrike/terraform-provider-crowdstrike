package rtrscript_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccRTRScriptResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_rtr_script.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccRTRScriptConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("content"), knownvalue.StringExact("echo 'hello world'")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Linux")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("permission_type"), knownvalue.StringExact("private")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sha256"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("size"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_timestamp"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_timestamp"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccRTRScriptResource_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_rtr_script.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccRTRScriptConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("content"), knownvalue.StringExact("echo 'hello world'")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Linux")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("permission_type"), knownvalue.StringExact("private")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comments_for_audit_log"), knownvalue.Null()),
				},
			},
			{
				Config: testAccRTRScriptConfig_updated(fmt.Sprintf("%s-updated", rName)),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(fmt.Sprintf("%s-updated", rName))),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("content"), knownvalue.StringExact("echo 'updated script'")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Linux")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("permission_type"), knownvalue.StringExact("group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Updated description")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comments_for_audit_log"), knownvalue.StringExact("Updated during acceptance testing")),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccRTRScriptResource_platforms(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_rtr_script.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccRTRScriptConfig_withPlatform(rName, "Windows"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Windows")),
				},
			},
			{
				Config: testAccRTRScriptConfig_withPlatform(rName, "Mac"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Mac")),
				},
			},
			{
				Config: testAccRTRScriptConfig_withPlatform(rName, "Linux"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Linux")),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccRTRScriptResource_description(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_rtr_script.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccRTRScriptConfig_withDescription(rName, "Initial description"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Initial description")),
				},
			},
			{
				Config: testAccRTRScriptConfig_withDescription(rName, "Changed description"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Changed description")),
				},
			},
			{
				Config: testAccRTRScriptConfig_basic(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccRTRScriptResource_commentsForAuditLog(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_rtr_script.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccRTRScriptConfig_withComments(rName, "Initial comment"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comments_for_audit_log"), knownvalue.StringExact("Initial comment")),
				},
			},
			{
				Config: testAccRTRScriptConfig_withComments(rName, "Changed comment"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comments_for_audit_log"), knownvalue.StringExact("Changed comment")),
				},
			},
			{
				Config: testAccRTRScriptConfig_basic(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comments_for_audit_log"), knownvalue.Null()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccRTRScriptConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_rtr_script" "test" {
  name            = %[1]q
  content         = "echo 'hello world'"
  platform_name   = "Linux"
  permission_type = "private"
}`, name)
}

func testAccRTRScriptConfig_updated(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_rtr_script" "test" {
  name                   = %[1]q
  content                = "echo 'updated script'"
  platform_name          = "Linux"
  permission_type        = "group"
  description            = "Updated description"
  comments_for_audit_log = "Updated during acceptance testing"
}`, name)
}

func testAccRTRScriptConfig_withPlatform(name, platform string) string {
	return fmt.Sprintf(`
resource "crowdstrike_rtr_script" "test" {
  name            = %[1]q
  content         = "echo 'hello world'"
  platform_name   = %[2]q
  permission_type = "private"
}`, name, platform)
}

func testAccRTRScriptConfig_withDescription(name, description string) string {
	return fmt.Sprintf(`
resource "crowdstrike_rtr_script" "test" {
  name            = %[1]q
  description     = %[2]q
  content         = "echo 'hello world'"
  platform_name   = "Linux"
  permission_type = "private"
}`, name, description)
}

func testAccRTRScriptConfig_withComments(name, comments string) string {
	return fmt.Sprintf(`
resource "crowdstrike_rtr_script" "test" {
  name                   = %[1]q
  content                = "echo 'hello world'"
  platform_name          = "Linux"
  permission_type        = "private"
  comments_for_audit_log = %[2]q
}`, name, comments)
}
