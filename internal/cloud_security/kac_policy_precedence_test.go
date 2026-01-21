package cloudsecurity_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

type kacPolicyPrecedenceConfig struct {
	policyIds []string
}

func (c kacPolicyPrecedenceConfig) String() string {
	config := `
resource "crowdstrike_cloud_security_kac_policy_precedence" "test" {
  policy_ids = [`

	for i, id := range c.policyIds {
		if i > 0 {
			config += ", "
		}
		config += id
	}

	config += `]
}`
	return config
}

func TestCloudSecurityKacPolicyPrecedenceResource_Comprehensive(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy_precedence.test"

	// Create 4 minimal KAC policies for testing various precedence scenarios
	policy1Name := fmt.Sprintf("tfacc-kac-policy-precedence-1-%s", randomSuffix)
	policy2Name := fmt.Sprintf("tfacc-kac-policy-precedence-2-%s", randomSuffix)
	policy3Name := fmt.Sprintf("tfacc-kac-policy-precedence-3-%s", randomSuffix)
	policy4Name := fmt.Sprintf("tfacc-kac-policy-precedence-4-%s", randomSuffix)
	policy1ResourceName := "crowdstrike_cloud_security_kac_policy.test_policy_1"
	policy2ResourceName := "crowdstrike_cloud_security_kac_policy.test_policy_2"
	policy3ResourceName := "crowdstrike_cloud_security_kac_policy.test_policy_3"
	policy4ResourceName := "crowdstrike_cloud_security_kac_policy.test_policy_4"

	testPoliciesConfig := fmt.Sprintf(`
resource "crowdstrike_cloud_security_kac_policy" "test_policy_1" {
  name = %q
}

resource "crowdstrike_cloud_security_kac_policy" "test_policy_2" {
  name = %q
}

resource "crowdstrike_cloud_security_kac_policy" "test_policy_3" {
  name = %q
}

resource "crowdstrike_cloud_security_kac_policy" "test_policy_4" {
  name = %q
}
`, policy1Name, policy2Name, policy3Name, policy4Name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				// Initial order: policy_1, policy_2, policy_3, policy_4
				Config: acctest.ConfigCompose(
					testPoliciesConfig,
					kacPolicyPrecedenceConfig{
						policyIds: []string{
							"crowdstrike_cloud_security_kac_policy.test_policy_1.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_2.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_3.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_4.id",
						},
					}.String(),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policy_ids.#", "4"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_ids.0", policy1ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_ids.1", policy2ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_ids.2", policy3ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_ids.3", policy4ResourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				// Completely reverse the order: policy_4, policy_3, policy_2, policy_1
				Config: acctest.ConfigCompose(
					testPoliciesConfig,
					kacPolicyPrecedenceConfig{
						policyIds: []string{
							"crowdstrike_cloud_security_kac_policy.test_policy_4.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_3.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_2.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_1.id",
						},
					}.String(),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policy_ids.#", "4"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_ids.0", policy4ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_ids.1", policy3ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_ids.2", policy2ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_ids.3", policy1ResourceName, "id"),
				),
			},
			{
				// Mixed up the order: policy_1, policy_3, policy_2, policy_4
				Config: acctest.ConfigCompose(
					testPoliciesConfig,
					kacPolicyPrecedenceConfig{
						policyIds: []string{
							"crowdstrike_cloud_security_kac_policy.test_policy_1.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_3.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_2.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_4.id",
						},
					}.String(),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policy_ids.#", "4"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_ids.0", policy1ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_ids.1", policy3ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_ids.2", policy2ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_ids.3", policy4ResourceName, "id"),
				),
			},
		},
	})
}
