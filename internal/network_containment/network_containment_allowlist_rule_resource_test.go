package networkcontainment_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/containment_allowlist_rules"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	networkcontainment "github.com/crowdstrike/terraform-provider-crowdstrike/internal/network_containment"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	tfjson "github.com/hashicorp/terraform-json"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const allowlistRuleResourceType = "crowdstrike_network_containment_allowlist_rule"

func TestAccNetworkContainmentAllowlistRule_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	updatedName := rName + "-updated"
	resourceName := allowlistRuleResourceType + ".test"
	ipv4 := randomTestIPv4(t)
	ipv6CIDR := randomTestIPv6CIDR()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckAllowlistRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAllowlistRuleConfig_basic(rName, "ip_range", ipv4),
				ConfigStateChecks: []statecheck.StateCheck{
					testAccCheckAllowlistRuleExists(resourceName),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.StringExact("containment|"+ipv4)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("ip_range")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule"), knownvalue.StringExact(ipv4)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("allow_subdomains"), knownvalue.Bool(false)),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// The name is the only attribute that updates in place.
				Config: testAccAllowlistRuleConfig_basic(updatedName, "ip_range", ipv4),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.StringExact("containment|"+ipv4)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(updatedName)),
				},
			},
			{
				Config: testAccAllowlistRuleConfig_basic(updatedName, "ip_range", ipv6CIDR),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					testAccCheckAllowlistRuleExists(resourceName),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.StringExact("containment|"+ipv6CIDR)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule"), knownvalue.StringExact(ipv6CIDR)),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:  resourceName,
				ImportState:   true,
				ImportStateId: ipv6CIDR,
				ExpectError:   regexp.MustCompile(`Invalid import ID`),
			},
		},
	})
}

// TestAccNetworkContainmentAllowlistRule_fqdn covers the fqdn and ip_dns rule
// types together, since an fqdn rule cannot exist without an ip_dns rule.
func TestAccNetworkContainmentAllowlistRule_fqdn(t *testing.T) {
	rName := acctest.RandomResourceName()
	dnsName := allowlistRuleResourceType + ".dns"
	fqdnName := allowlistRuleResourceType + ".test"
	dnsServer := randomTestIPv4(t)
	// Mixed case proves the API stores the domain exactly as given.
	domain := rName + ".Example.COM"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckAllowlistRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAllowlistRuleConfig_fqdn(rName, dnsServer, domain, true),
				ConfigStateChecks: []statecheck.StateCheck{
					testAccCheckAllowlistRuleExists(dnsName),
					statecheck.ExpectKnownValue(dnsName, tfjsonpath.New("id"), knownvalue.StringExact("containment|dns|"+dnsServer)),
					statecheck.ExpectKnownValue(dnsName, tfjsonpath.New("type"), knownvalue.StringExact("ip_dns")),
					statecheck.ExpectKnownValue(dnsName, tfjsonpath.New("allow_subdomains"), knownvalue.Bool(false)),
					testAccCheckAllowlistRuleExists(fqdnName),
					statecheck.ExpectKnownValue(fqdnName, tfjsonpath.New("id"), knownvalue.StringExact("containment|"+domain)),
					statecheck.ExpectKnownValue(fqdnName, tfjsonpath.New("type"), knownvalue.StringExact("fqdn")),
					statecheck.ExpectKnownValue(fqdnName, tfjsonpath.New("rule"), knownvalue.StringExact(domain)),
					statecheck.ExpectKnownValue(fqdnName, tfjsonpath.New("allow_subdomains"), knownvalue.Bool(true)),
				},
			},
			{
				ResourceName:      dnsName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      fqdnName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// allow_subdomains cannot change after creation.
				Config: testAccAllowlistRuleConfig_fqdn(rName, dnsServer, domain, false),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(fqdnName, plancheck.ResourceActionDestroyBeforeCreate),
						plancheck.ExpectResourceAction(dnsName, plancheck.ResourceActionNoop),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					testAccCheckAllowlistRuleExists(fqdnName),
					statecheck.ExpectKnownValue(fqdnName, tfjsonpath.New("allow_subdomains"), knownvalue.Bool(false)),
				},
			},
		},
	})
}

func TestAccNetworkContainmentAllowlistRule_disappears(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := allowlistRuleResourceType + ".test"
	ipv4 := randomTestIPv4(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckAllowlistRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAllowlistRuleConfig_basic(rName, "ip_range", ipv4),
				ConfigStateChecks: []statecheck.StateCheck{
					testAccCheckAllowlistRuleDisappears(resourceName),
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccNetworkContainmentAllowlistRule_validation(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccAllowlistRuleConfig_basic(rName, "dns", "192.0.2.1"),
				ExpectError: regexp.MustCompile(`Attribute type value must be one of`),
			},
			{
				Config:      testAccAllowlistRuleConfig_basic(rName, "ip_range", "192.0.2.0/33"),
				ExpectError: regexp.MustCompile(`not a valid IP address or CIDR block`),
			},
			{
				Config:      testAccAllowlistRuleConfig_basic(rName, "ip_dns", "192.0.2.0/24"),
				ExpectError: regexp.MustCompile(`not a valid IP address, which "ip_dns"`),
			},
			{
				Config:      testAccAllowlistRuleConfig_basic(rName, "fqdn", "*.example.com"),
				ExpectError: regexp.MustCompile(`not a valid FQDN`),
			},
			{
				Config:      testAccAllowlistRuleConfig_basic(" ", "ip_range", "192.0.2.1"),
				ExpectError: regexp.MustCompile(`must not be empty or contain only whitespace`),
			},
			{
				Config: fmt.Sprintf(`
resource "crowdstrike_network_containment_allowlist_rule" "test" {
  type             = "ip_range"
  rule             = "192.0.2.1"
  name             = %[1]q
  allow_subdomains = true
}
`, rName),
				ExpectError: regexp.MustCompile(`allow_subdomains can only be true for "fqdn" rules`),
			},
		},
	})
}

func TestValidateRule(t *testing.T) {
	tests := []struct {
		name     string
		ruleType string
		rule     string
		wantErr  bool
	}{
		{"ip_range ipv4 address", "ip_range", "203.0.113.5", false},
		{"ip_range ipv4 cidr", "ip_range", "203.0.113.0/24", false},
		{"ip_range cidr with host bits", "ip_range", "203.0.113.5/24", false},
		{"ip_range ipv6 address", "ip_range", "2001:db8::1", false},
		{"ip_range ipv6 cidr", "ip_range", "2001:db8::/32", false},
		{"ip_range prefix too long", "ip_range", "203.0.113.0/33", true},
		{"ip_range range syntax", "ip_range", "203.0.113.1-203.0.113.9", true},
		{"ip_range hostname", "ip_range", "example.com", true},
		{"ip_dns ipv4 address", "ip_dns", "192.0.2.53", false},
		{"ip_dns ipv6 address", "ip_dns", "2001:db8::53", false},
		{"ip_dns cidr", "ip_dns", "192.0.2.0/24", true},
		{"ip_dns hostname", "ip_dns", "dns.example.com", true},
		{"fqdn domain", "fqdn", "updates.example.com", false},
		{"fqdn two labels", "fqdn", "example.com", false},
		{"fqdn mixed case", "fqdn", "Vendor.Example.COM", false},
		{"fqdn hyphenated label", "fqdn", "my-vendor.example.com", false},
		{"fqdn single label", "fqdn", "localhost", true},
		{"fqdn wildcard", "fqdn", "*.example.com", true},
		{"fqdn scheme", "fqdn", "https://example.com", true},
		{"fqdn port", "fqdn", "example.com:443", true},
		{"fqdn path", "fqdn", "example.com/path", true},
		{"fqdn leading hyphen", "fqdn", "-bad.example.com", true},
		{"fqdn trailing dot", "fqdn", "example.com.", true},
		{"fqdn label too long", "fqdn", strings.Repeat("a", 64) + ".example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := networkcontainment.ValidateRule(tt.ruleType, tt.rule)
			if tt.wantErr && got == "" {
				t.Errorf("ValidateRule(%q, %q) accepted an invalid rule", tt.ruleType, tt.rule)
			}
			if !tt.wantErr && got != "" {
				t.Errorf("ValidateRule(%q, %q) rejected a valid rule: %s", tt.ruleType, tt.rule, got)
			}
		})
	}
}

// randomTestIPv4 returns an address from the 198.18.0.0/15 benchmarking range.
// Rule IDs are derived from the rule value, so a fixed address would collide
// across concurrent runs and with leaked rules.
func randomTestIPv4(t *testing.T) string {
	t.Helper()

	ip, err := sdkacctest.RandIpAddress("198.18.0.0/15")
	if err != nil {
		t.Fatalf("generating random IP address: %s", err)
	}
	return ip
}

// randomTestIPv6CIDR returns a /64 from the 2001:db8::/32 documentation range.
func randomTestIPv6CIDR() string {
	return fmt.Sprintf("2001:db8:%x:%x::/64", sdkacctest.RandIntRange(1, 0xffff), sdkacctest.RandIntRange(1, 0xffff))
}

func stateResourceAtAddress(state *tfjson.State, address string) (*tfjson.StateResource, error) {
	if state == nil || state.Values == nil || state.Values.RootModule == nil {
		return nil, fmt.Errorf("no state available")
	}
	for _, r := range state.Values.RootModule.Resources {
		if r.Address == address {
			return r, nil
		}
	}
	return nil, fmt.Errorf("not found in state: %s", address)
}

func stateResourceID(state *tfjson.State, address string) (string, error) {
	rs, err := stateResourceAtAddress(state, address)
	if err != nil {
		return "", err
	}
	id, ok := rs.AttributeValues["id"].(string)
	if !ok || id == "" {
		return "", fmt.Errorf("%s: no id in state", address)
	}
	return id, nil
}

// allowlistRuleExists reports whether the API still holds the rule. The API
// answers a missing ID with 200 and no resources rather than a 404.
func allowlistRuleExists(ctx context.Context, id string) (bool, error) {
	params := containment_allowlist_rules.NewGetContainmentAllowlistRulesParamsWithContext(ctx).
		WithIds([]string{id})

	res, err := testconfig.GetTestClient().ContainmentAllowlistRules.GetContainmentAllowlistRules(params)
	if err != nil {
		return false, err
	}
	return res != nil && res.Payload != nil && len(res.Payload.Resources) > 0, nil
}

type allowlistRuleExistsCheck struct {
	resourceAddress string
}

func (c allowlistRuleExistsCheck) CheckState(ctx context.Context, req statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	id, err := stateResourceID(req.State, c.resourceAddress)
	if err != nil {
		resp.Error = err
		return
	}

	exists, err := allowlistRuleExists(ctx, id)
	if err != nil {
		resp.Error = fmt.Errorf("reading allowlist rule %s: %w", id, err)
		return
	}
	if !exists {
		resp.Error = fmt.Errorf("allowlist rule %s not found via API", id)
	}
}

func testAccCheckAllowlistRuleExists(resourceAddress string) statecheck.StateCheck {
	return allowlistRuleExistsCheck{resourceAddress: resourceAddress}
}

type allowlistRuleDisappearsCheck struct {
	resourceAddress string
}

func (c allowlistRuleDisappearsCheck) CheckState(ctx context.Context, req statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	id, err := stateResourceID(req.State, c.resourceAddress)
	if err != nil {
		resp.Error = err
		return
	}

	params := containment_allowlist_rules.NewDeleteContainmentAllowlistRulesParamsWithContext(ctx).
		WithIds([]string{id})

	if _, err := testconfig.GetTestClient().ContainmentAllowlistRules.DeleteContainmentAllowlistRules(params); err != nil {
		resp.Error = fmt.Errorf("deleting allowlist rule %s out of band: %w", id, err)
	}
}

func testAccCheckAllowlistRuleDisappears(resourceAddress string) statecheck.StateCheck {
	return allowlistRuleDisappearsCheck{resourceAddress: resourceAddress}
}

func testAccCheckAllowlistRuleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != allowlistRuleResourceType {
			continue
		}

		exists, err := allowlistRuleExists(context.Background(), rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("checking allowlist rule %s: %w", rs.Primary.ID, err)
		}
		if exists {
			return fmt.Errorf("allowlist rule %s still exists", rs.Primary.ID)
		}
	}

	return nil
}

func testAccAllowlistRuleConfig_basic(name, ruleType, rule string) string {
	return fmt.Sprintf(`
resource "crowdstrike_network_containment_allowlist_rule" "test" {
  type = %[2]q
  rule = %[3]q
  name = %[1]q
}
`, name, ruleType, rule)
}

func testAccAllowlistRuleConfig_fqdn(name, dnsServer, domain string, allowSubdomains bool) string {
	return fmt.Sprintf(`
resource "crowdstrike_network_containment_allowlist_rule" "dns" {
  type = "ip_dns"
  rule = %[2]q
  name = "%[1]s-dns"
}

resource "crowdstrike_network_containment_allowlist_rule" "test" {
  type             = "fqdn"
  rule             = %[3]q
  name             = %[1]q
  allow_subdomains = %[4]t

  depends_on = [crowdstrike_network_containment_allowlist_rule.dns]
}
`, name, dnsServer, domain, allowSubdomains)
}
