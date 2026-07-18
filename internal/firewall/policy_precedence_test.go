package firewall_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/firewall"
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

func TestFilterPoliciesByCID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policies []firewall.PolicyRef
		cid      string
		want     []string
	}{
		{
			name: "keeps only matching cid preserving order",
			policies: []firewall.PolicyRef{
				firewall.NewPolicyRef("a", "010abf4b", ""),
				firewall.NewPolicyRef("b", "2436580c", ""),
				firewall.NewPolicyRef("c", "010abf4b", ""),
			},
			cid:  "010abf4b",
			want: []string{"a", "c"},
		},
		{
			name: "case insensitive cid match",
			policies: []firewall.PolicyRef{
				firewall.NewPolicyRef("a", "010ABF4B", ""),
			},
			cid:  "010abf4b",
			want: []string{"a"},
		},
		{
			name: "no matches returns empty",
			policies: []firewall.PolicyRef{
				firewall.NewPolicyRef("a", "2436580c", ""),
			},
			cid:  "010abf4b",
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := firewall.FilterPoliciesByCID(tt.policies, tt.cid)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestDistinctCIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policies []firewall.PolicyRef
		want     []string
	}{
		{
			name: "single cid",
			policies: []firewall.PolicyRef{
				firewall.NewPolicyRef("a", "010abf4b", ""),
				firewall.NewPolicyRef("b", "010abf4b", ""),
			},
			want: []string{"010abf4b"},
		},
		{
			name: "multiple distinct cids first-seen order",
			policies: []firewall.PolicyRef{
				firewall.NewPolicyRef("a", "2436580c", ""),
				firewall.NewPolicyRef("b", "010abf4b", ""),
				firewall.NewPolicyRef("c", "2436580c", ""),
			},
			want: []string{"2436580c", "010abf4b"},
		},
		{
			name: "empty cids skipped",
			policies: []firewall.PolicyRef{
				firewall.NewPolicyRef("a", "", ""),
				firewall.NewPolicyRef("b", "010abf4b", ""),
			},
			want: []string{"010abf4b"},
		},
		{
			name:     "no policies",
			policies: []firewall.PolicyRef{},
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := firewall.DistinctCIDs(tt.policies)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestStripChecksum(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "uppercase ccid with checksum",
			in:   "010ABF4B1BA04B7DA3F240A4C56657AC-C1",
			want: "010abf4b1ba04b7da3f240a4c56657ac",
		},
		{
			name: "no checksum suffix",
			in:   "010ABF4B1BA04B7DA3F240A4C56657AC",
			want: "010abf4b1ba04b7da3f240a4c56657ac",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := firewall.StripChecksum(tt.in); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
