package iocindicator_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccIOCIndicatorResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ioc_indicator.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIOCIndicatorConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("domain")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value"), knownvalue.StringExact(rName+".example.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("detect")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("high")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platforms"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_on"), knownvalue.NotNull()),
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

func TestAccIOCIndicatorResource_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ioc_indicator.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with initial values.
			{
				Config: testAccIOCIndicatorConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("detect")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("high")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags"), knownvalue.Null()),
				},
			},
			// Update action, severity, description, and add tags.
			{
				Config: testAccIOCIndicatorConfig_updated(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("critical")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(rName+"-updated")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platforms"), knownvalue.SetSizeExact(2)),
				},
			},
			// Remove optional fields (tags, severity back to simpler values).
			{
				Config: testAccIOCIndicatorConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("detect")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("high")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags"), knownvalue.Null()),
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

func TestAccIOCIndicatorResource_allPlatforms(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ioc_indicator.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIOCIndicatorConfig_allPlatforms(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("ipv4")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platforms"), knownvalue.SetSizeExact(3)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(true)),
				},
			},
		},
	})
}

func testAccIOCIndicatorConfig_basic(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioc_indicator" "test" {
  type             = "domain"
  value            = "%[1]s.example.com"
  action           = "detect"
  severity         = "high"
  description      = %[1]q
  platforms        = ["windows"]
  applied_globally = true
}
`, rName)
}

func testAccIOCIndicatorConfig_updated(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioc_indicator" "test" {
  type             = "domain"
  value            = "%[1]s.example.com"
  action           = "prevent"
  severity         = "critical"
  description      = "%[1]s-updated"
  platforms        = ["windows", "linux"]
  applied_globally = true
  tags             = ["tf-acc-test"]
}
`, rName)
}

func testAccIOCIndicatorConfig_allPlatforms(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioc_indicator" "test" {
  type             = "ipv4"
  value            = "198.51.100.1"
  action           = "detect"
  severity         = "medium"
  description      = %[1]q
  platforms        = ["windows", "mac", "linux"]
  applied_globally = true
}
`, rName)
}
