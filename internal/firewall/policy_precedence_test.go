package firewall_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// NOTE: crowdstrike_firewall_policy_precedence does not implement ImportState,
// so an ImportState verification step cannot be added to these tests.

func TestAccFirewallPolicyPrecedence_updateOrder(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_policy_precedence.test"
	policy1 := "crowdstrike_firewall_policy.test1"
	policy2 := "crowdstrike_firewall_policy.test2"

	// Use sequential test to avoid race conditions with other tests creating/deleting policies
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyPrecedenceConfig(rName, 2,
					"crowdstrike_firewall_policy.test1.id",
					"crowdstrike_firewall_policy.test2.id"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Windows")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enforcement"), knownvalue.StringExact("dynamic")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ids"), knownvalue.ListSizeExact(2)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("ids").AtSliceIndex(0),
						policy1, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("ids").AtSliceIndex(1),
						policy2, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
				},
			},
			{
				Config: testAccFirewallPolicyPrecedenceConfig(rName, 2,
					"crowdstrike_firewall_policy.test2.id",
					"crowdstrike_firewall_policy.test1.id"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ids"), knownvalue.ListSizeExact(2)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("ids").AtSliceIndex(0),
						policy2, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("ids").AtSliceIndex(1),
						policy1, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccFirewallPolicyPrecedence_dynamicSubset(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_policy_precedence.test"
	policy1 := "crowdstrike_firewall_policy.test1"
	policy3 := "crowdstrike_firewall_policy.test3"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyPrecedenceConfig(rName, 3,
					"crowdstrike_firewall_policy.test1.id",
					"crowdstrike_firewall_policy.test3.id"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ids"), knownvalue.ListSizeExact(2)),
					statecheck.CompareValuePairs(resourceName, tfjsonpath.New("ids").AtSliceIndex(0), policy1, tfjsonpath.New("id"), compare.ValuesSame()),
					statecheck.CompareValuePairs(resourceName, tfjsonpath.New("ids").AtSliceIndex(1), policy3, tfjsonpath.New("id"), compare.ValuesSame()),
				},
			},
		},
	})
}

func TestAccFirewallPolicyPrecedence_invalidID(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccFirewallPolicyPrecedenceConfig_invalidID(rName),
				ExpectError: regexp.MustCompile("Invalid policy IDs provided"),
			},
		},
	})
}

func testAccFirewallPolicyPrecedenceConfig(rName string, policyCount int, orderedIDRefs ...string) string {
	var b strings.Builder
	for i := 1; i <= policyCount; i++ {
		fmt.Fprintf(&b, `
resource "crowdstrike_firewall_policy" "test%[2]d" {
  name          = "%[1]s-%[2]d"
  description   = "Test policy %[2]d for precedence"
  platform_name = "Windows"
  enabled       = false
}
`, rName, i)
	}
	fmt.Fprintf(&b, `
resource "crowdstrike_firewall_policy_precedence" "test" {
  platform_name = "Windows"
  enforcement   = "dynamic"
  ids = [
    %s,
  ]
}
`, strings.Join(orderedIDRefs, ",\n    "))
	return b.String()
}

func testAccFirewallPolicyPrecedenceConfig_invalidID(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_policy" "test1" {
  name          = "%[1]s-1"
  description   = "Test policy 1 for precedence"
  platform_name = "Windows"
  enabled       = false
}

resource "crowdstrike_firewall_policy_precedence" "test" {
  platform_name = "Windows"
  enforcement   = "dynamic"
  ids = [
    crowdstrike_firewall_policy.test1.id,
    "00000000000000000000000000000000",
  ]
}
`, rName)
}
