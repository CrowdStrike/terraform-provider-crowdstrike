package dataprotection_test

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const (
	testAccDataProtectionPolicyClassificationIDsEnvName = "TF_ACC_DATA_PROTECTION_POLICY_CLASSIFICATION_IDS"
	testAccDataProtectionPolicyPlatformNameEnvName      = "TF_ACC_DATA_PROTECTION_POLICY_PLATFORM_NAME"
)

func TestAccDataProtectionPolicyResource_Basic(t *testing.T) {
	classificationIDs := testAccDataProtectionPolicyClassificationIDs(t)
	platformName := os.Getenv(testAccDataProtectionPolicyPlatformNameEnvName)
	if platformName == "" {
		platformName = "win"
	}

	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_data_protection_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataProtectionPolicyConfig(
					rName,
					"Terraform acceptance test policy",
					platformName,
					classificationIDs,
					"medium",
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "cid"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Terraform acceptance test policy"),
					resource.TestCheckResourceAttr(resourceName, "platform_name", platformName),
					resource.TestCheckResourceAttr(resourceName, "enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "precedence", "1"),
					resource.TestCheckResourceAttr(resourceName, "policy_properties.enable_content_inspection", "true"),
					resource.TestCheckResourceAttr(resourceName, "policy_properties.min_confidence_level", "medium"),
					resource.TestCheckResourceAttr(resourceName, "policy_properties.classifications.#", strconv.Itoa(len(classificationIDs))),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "modified_at"),
				),
			},
			{
				Config: testAccDataProtectionPolicyConfig(
					rName+"-updated",
					"Terraform acceptance test policy updated",
					platformName,
					classificationIDs,
					"high",
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName+"-updated"),
					resource.TestCheckResourceAttr(resourceName, "description", "Terraform acceptance test policy updated"),
					resource.TestCheckResourceAttr(resourceName, "policy_properties.min_confidence_level", "high"),
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

func testAccDataProtectionPolicyClassificationIDs(t *testing.T) []string {
	t.Helper()

	rawValue := os.Getenv(testAccDataProtectionPolicyClassificationIDsEnvName)
	if rawValue == "" {
		t.Skip("Skipping test that requires data protection classifications. Set TF_ACC_DATA_PROTECTION_POLICY_CLASSIFICATION_IDS to run this test.")
	}

	parts := strings.Split(rawValue, ",")
	classificationIDs := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			classificationIDs = append(classificationIDs, trimmed)
		}
	}

	if len(classificationIDs) == 0 {
		t.Skip("Skipping test because TF_ACC_DATA_PROTECTION_POLICY_CLASSIFICATION_IDS did not contain any usable classification IDs.")
	}

	return classificationIDs
}

func testAccDataProtectionPolicyConfig(
	name string,
	description string,
	platformName string,
	classificationIDs []string,
	minConfidenceLevel string,
) string {
	quotedClassificationIDs := make([]string, 0, len(classificationIDs))
	for _, classificationID := range classificationIDs {
		quotedClassificationIDs = append(quotedClassificationIDs, strconv.Quote(classificationID))
	}

	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_data_protection_policy" "test" {
  name         = %[1]q
  description  = %[2]q
  platform_name = %[3]q
  enabled      = false
  precedence   = 1

  policy_properties {
    classifications           = [%[4]s]
    enable_content_inspection = true
    min_confidence_level      = %[5]q
  }
}
`, name, description, platformName, strings.Join(quotedClassificationIDs, ", "), minConfidenceLevel)
}
