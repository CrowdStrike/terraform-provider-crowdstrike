package dataprotection_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

const (
	testAccSensitivityLabelProviderEnvName       = "TF_ACC_DATA_PROTECTION_LABEL_PROVIDER"
	testAccSensitivityLabelPluginConfigIDEnvName = "TF_ACC_DATA_PROTECTION_PLUGIN_CONFIGURATION_ID"
)

func TestAccDataProtectionSensitivityLabelResource_Basic(t *testing.T) {
	labelProvider := os.Getenv(testAccSensitivityLabelProviderEnvName)
	if labelProvider == "" {
		t.Skip("Skipping test that requires a data protection label provider. Set TF_ACC_DATA_PROTECTION_LABEL_PROVIDER to run this test.")
	}

	pluginConfigID := os.Getenv(testAccSensitivityLabelPluginConfigIDEnvName)
	if pluginConfigID == "" {
		t.Skip("Skipping test that requires a data protection plugin configuration ID. Set TF_ACC_DATA_PROTECTION_PLUGIN_CONFIGURATION_ID to run this test.")
	}

	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_data_protection_sensitivity_label.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataProtectionSensitivityLabelConfig(
					rName,
					rName,
					rName+"-external",
					labelProvider,
					pluginConfigID,
					false,
					true,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "cid"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "display_name", rName),
					resource.TestCheckResourceAttr(resourceName, "external_id", rName+"-external"),
					resource.TestCheckResourceAttr(resourceName, "label_provider", labelProvider),
					resource.TestCheckResourceAttr(resourceName, "plugins_configuration_id", pluginConfigID),
					resource.TestCheckResourceAttr(resourceName, "co_authoring", "false"),
					resource.TestCheckResourceAttr(resourceName, "synced", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				Config: testAccDataProtectionSensitivityLabelConfig(
					rName+"-updated",
					rName+" Updated",
					rName+"-external-updated",
					labelProvider,
					pluginConfigID,
					true,
					true,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName+"-updated"),
					resource.TestCheckResourceAttr(resourceName, "display_name", rName+" Updated"),
					resource.TestCheckResourceAttr(resourceName, "external_id", rName+"-external-updated"),
					resource.TestCheckResourceAttr(resourceName, "co_authoring", "true"),
					resource.TestCheckResourceAttr(resourceName, "synced", "true"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
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

func TestAccDataProtectionSensitivityLabelResource_Standard(t *testing.T) {
	labelProvider := os.Getenv(testAccSensitivityLabelProviderEnvName)
	if labelProvider == "" {
		t.Skip("Skipping test that requires a data protection label provider. Set TF_ACC_DATA_PROTECTION_LABEL_PROVIDER to run this test.")
	}

	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_data_protection_sensitivity_label.standard"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataProtectionSensitivityLabelStandardConfig(rName, labelProvider),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "cid"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "display_name", rName),
					resource.TestCheckResourceAttr(resourceName, "label_provider", labelProvider),
					resource.TestCheckResourceAttr(resourceName, "synced", "false"),
					resource.TestCheckNoResourceAttr(resourceName, "external_id"),
					resource.TestCheckNoResourceAttr(resourceName, "plugins_configuration_id"),
					resource.TestCheckNoResourceAttr(resourceName, "co_authoring"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccDataProtectionSensitivityLabelConfig(
	name string,
	displayName string,
	externalID string,
	labelProvider string,
	pluginConfigID string,
	coAuthoring bool,
	synced bool,
) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_data_protection_sensitivity_label" "test" {
  name                     = %[1]q
  display_name             = %[2]q
  external_id              = %[3]q
  label_provider           = %[4]q
  plugins_configuration_id = %[5]q
  co_authoring             = %[6]t
  synced                   = %[7]t
}
`, name, displayName, externalID, labelProvider, pluginConfigID, coAuthoring, synced)
}

func testAccDataProtectionSensitivityLabelStandardConfig(
	name string,
	labelProvider string,
) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_data_protection_sensitivity_label" "standard" {
  name           = %[1]q
  label_provider = %[2]q
  synced         = false
}
`, name, labelProvider)
}
