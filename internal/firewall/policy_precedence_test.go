package firewall_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccFirewallPolicyPrecedenceResource_Dynamic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resourceName := "crowdstrike_firewall_policy_precedence.test"

	// Use sequential test to avoid race conditions with other tests creating/deleting policies
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyPrecedenceConfig_dynamic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "platform_name", "Windows"),
					resource.TestCheckResourceAttr(resourceName, "enforcement", "dynamic"),
					resource.TestCheckResourceAttr(resourceName, "ids.#", "2"),
				),
			},
		},
	})
}

func TestAccFirewallPolicyPrecedenceResource_UpdateOrder(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resourceName := "crowdstrike_firewall_policy_precedence.test"

	// Use sequential test to avoid race conditions with other tests creating/deleting policies
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyPrecedenceConfig_dynamic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "ids.#", "2"),
				),
			},
			{
				Config: testAccFirewallPolicyPrecedenceConfig_reordered(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "ids.#", "2"),
				),
			},
		},
	})
}

func testAccFirewallPolicyPrecedenceConfig_dynamic(rName string) string {
	return `
resource "crowdstrike_firewall_policy" "test1" {
  name          = "` + rName + `-1"
  description   = "Test policy 1 for precedence"
  platform_name = "Windows"
  enabled       = false
}

resource "crowdstrike_firewall_policy" "test2" {
  name          = "` + rName + `-2"
  description   = "Test policy 2 for precedence"
  platform_name = "Windows"
  enabled       = false
}

resource "crowdstrike_firewall_policy_precedence" "test" {
  platform_name = "Windows"
  enforcement   = "dynamic"
  ids = [
    crowdstrike_firewall_policy.test1.id,
    crowdstrike_firewall_policy.test2.id,
  ]
}
`
}

func testAccFirewallPolicyPrecedenceConfig_reordered(rName string) string {
	return `
resource "crowdstrike_firewall_policy" "test1" {
  name          = "` + rName + `-1"
  description   = "Test policy 1 for precedence"
  platform_name = "Windows"
  enabled       = false
}

resource "crowdstrike_firewall_policy" "test2" {
  name          = "` + rName + `-2"
  description   = "Test policy 2 for precedence"
  platform_name = "Windows"
  enabled       = false
}

resource "crowdstrike_firewall_policy_precedence" "test" {
  platform_name = "Windows"
  enforcement   = "dynamic"
  ids = [
    crowdstrike_firewall_policy.test2.id,
    crowdstrike_firewall_policy.test1.id,
  ]
}
`
}
