package cloudsecurity_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

type kacPolicyConfig struct {
	name        string
	description *string
	isEnabled   *bool
	precedence  *int32
}

func (c kacPolicyConfig) String() string {
	config := fmt.Sprintf(`
resource "crowdstrike_cloud_security_kac_policy" "test" {
  name = %q`, c.name)

	if c.description != nil {
		config += fmt.Sprintf(`
  description = %q`, *c.description)
	}

	if c.isEnabled != nil {
		config += fmt.Sprintf(`
  is_enabled = %t`, *c.isEnabled)
	}

	if c.precedence != nil {
		config += fmt.Sprintf(`
  precedence = %d`, *c.precedence)
	}

	config += `
}
`
	return config
}

func boolPtr(b bool) *bool       { return &b }
func stringPtr(s string) *string { return &s }
func int32Ptr(i int32) *int32    { return &i }

// TestCloudSecurityKacPolicyResource_Minimal tests creating a KAC policy with minimal configuration.
func TestCloudSecurityKacPolicyResource_Minimal(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-minimal-%s", randomSuffix)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{name: policyName}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckNoResourceAttr(resourceName, "description"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"), // should default to false
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

// TestCloudSecurityKacPolicyResource_Basic tests basic CRUD operations for KAC policy resource.
func TestCloudSecurityKacPolicyResource_Basic(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-%s", randomSuffix)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy created by Terraform"),
					isEnabled:   boolPtr(false),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy created by Terraform"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return "", fmt.Errorf("Resource not found: %s", resourceName)
					}
					return rs.Primary.Attributes["id"], nil
				},
			},
		},
	})
}

// TestCloudSecurityKacPolicyResource_Update tests updating KAC policy attributes.
func TestCloudSecurityKacPolicyResource_Update(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-%s", randomSuffix)
	updatedPolicyName := fmt.Sprintf("tfacc-kac-policy-updated-%s", randomSuffix)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy created by Terraform"),
					isEnabled:   boolPtr(false),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy created by Terraform"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: kacPolicyConfig{
					name:        updatedPolicyName,
					description: stringPtr("Updated KAC policy description"),
					isEnabled:   boolPtr(false),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", updatedPolicyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated KAC policy description"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

// TestCloudSecurityKacPolicyResource_EnabledToggle tests toggling the is_enabled flag.
func TestCloudSecurityKacPolicyResource_EnabledToggle(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-enabled-%s", randomSuffix)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:      policyName,
					isEnabled: boolPtr(false),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: kacPolicyConfig{
					name:      policyName,
					isEnabled: boolPtr(true),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: kacPolicyConfig{
					name:      policyName,
					isEnabled: boolPtr(false),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

// TestCloudSecurityKacPolicyResource_Precedence tests creating and updating KAC policy precedence.
func TestCloudSecurityKacPolicyResource_Precedence(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-precedence-%s", randomSuffix)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with precedence"),
					isEnabled:   boolPtr(false),
					precedence:  int32Ptr(5),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with precedence"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "precedence", "5"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with updated precedence"),
					isEnabled:   boolPtr(false),
					precedence:  int32Ptr(10),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with updated precedence"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "precedence", "10"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

// TestCloudSecurityKacPolicyResource_NameValidation tests name validation.
func TestCloudSecurityKacPolicyResource_NameValidation(t *testing.T) {
	configWithoutName := `resource "crowdstrike_cloud_security_kac_policy" "test" {}`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      configWithoutName,
				ExpectError: regexp.MustCompile("The argument \"name\" is required"),
			},
			{
				Config:      kacPolicyConfig{name: ""}.String(),
				ExpectError: regexp.MustCompile("Attribute name must not be empty"),
			},
		},
	})
}
