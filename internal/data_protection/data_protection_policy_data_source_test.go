package dataprotection_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const policyDataSourceName = "data.crowdstrike_data_protection_policy.test"

// TestAccDataProtectionPolicyDataSource_byID creates a policy fixture and looks
// it up by id. platform_name is deliberately absent: the API resolves an ID
// without a platform, and platform_name conflicts with id.
func TestAccDataProtectionPolicyDataSource_byID(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyDataSourceConfig_byID(rName, "Windows"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(policyDataSourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(policyDataSourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					// platform_name is unset in config and filled from the API.
					statecheck.ExpectKnownValue(policyDataSourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Windows")),
					statecheck.ExpectKnownValue(policyDataSourceName, tfjsonpath.New("filter"), knownvalue.Null()),
					statecheck.ExpectKnownValue(policyDataSourceName, tfjsonpath.New("is_default"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(policyDataSourceName, tfjsonpath.New("precedence"), knownvalue.NotNull()),
				},
			},
		},
	})
}

// TestAccDataProtectionPolicyDataSource_byFilter creates a policy fixture and
// looks it up with an FQL filter scoped to a platform.
func TestAccDataProtectionPolicyDataSource_byFilter(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyDataSourceConfig_byFilter(rName, "Windows"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(policyDataSourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(policyDataSourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(policyDataSourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Windows")),
				},
			},
		},
	})
}

// TestAccDataProtectionPolicyDataSource_validation covers the lookup argument
// rules: exactly one of id/filter, filter requires platform_name, and
// platform_name conflicts with id.
func TestAccDataProtectionPolicyDataSource_validation(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccPolicyDataSourceConfig_neither(),
				ExpectError: regexp.MustCompile(`(?i)one \(and only one\) of`),
			},
			{
				Config:      testAccPolicyDataSourceConfig_both("00000000000000000000000000000000", "name:'test'"),
				ExpectError: regexp.MustCompile(`(?i)one \(and only one\) of`),
			},
			{
				Config:      testAccPolicyDataSourceConfig_filterWithoutPlatform("name:'test'"),
				ExpectError: regexp.MustCompile(`(?i)platform_name`),
			},
			{
				Config:      testAccPolicyDataSourceConfig_idWithPlatform("00000000000000000000000000000000", "Windows"),
				ExpectError: regexp.MustCompile(`(?i)cannot be specified when`),
			},
		},
	})
}

// TestAccDataProtectionPolicyDataSource_notFound asserts a lookup for an ID that
// does not exist, and a filter that matches nothing, both surface not-found.
func TestAccDataProtectionPolicyDataSource_notFound(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccPolicyDataSourceConfig_notFoundByID(),
				ExpectError: regexp.MustCompile(`(?i)not found`),
			},
			{
				Config:      testAccPolicyDataSourceConfig_notFoundByFilter("Windows"),
				ExpectError: regexp.MustCompile(`(?i)not found`),
			},
		},
	})
}

// TestAccDataProtectionPolicyDataSource_multipleMatches asserts a filter
// matching more than one policy is rejected rather than silently picking one.
func TestAccDataProtectionPolicyDataSource_multipleMatches(t *testing.T) {
	rName := acctest.RandomResourceName()
	rNameOther := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccPolicyDataSourceConfig_multiple(rName, rNameOther, "Windows"),
				ExpectError: regexp.MustCompile(`(?i)multiple data protection policies found`),
			},
		},
	})
}

func testAccPolicyDataSourceConfig_byID(name, platform string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_data_protection_policy" "test" {
  platform_name = %[2]q
  name          = %[1]q
}

data "crowdstrike_data_protection_policy" "test" {
  id = crowdstrike_data_protection_policy.test.id
}
`, name, platform)
}

// testAccPolicyDataSourceConfig_byFilter looks the fixture up by its full name
// using the text-match operator, which ignores the punctuation in the generated
// name. Equality would only match a single token.
func testAccPolicyDataSourceConfig_byFilter(name, platform string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_data_protection_policy" "test" {
  platform_name = %[2]q
  name          = %[1]q
}

data "crowdstrike_data_protection_policy" "test" {
  filter        = "name:~'%[1]s'"
  platform_name = %[2]q

  depends_on = [crowdstrike_data_protection_policy.test]
}
`, name, platform)
}

func testAccPolicyDataSourceConfig_neither() string {
	return acctest.ProviderConfig + `
data "crowdstrike_data_protection_policy" "test" {}
`
}

func testAccPolicyDataSourceConfig_both(id, filter string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_data_protection_policy" "test" {
  id     = %[1]q
  filter = %[2]q
}
`, id, filter)
}

func testAccPolicyDataSourceConfig_filterWithoutPlatform(filter string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_data_protection_policy" "test" {
  filter = %[1]q
}
`, filter)
}

func testAccPolicyDataSourceConfig_idWithPlatform(id, platform string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_data_protection_policy" "test" {
  id            = %[1]q
  platform_name = %[2]q
}
`, id, platform)
}

func testAccPolicyDataSourceConfig_notFoundByID() string {
	return acctest.ProviderConfig + `
data "crowdstrike_data_protection_policy" "test" {
  id = "00000000000000000000000000000000"
}
`
}

func testAccPolicyDataSourceConfig_notFoundByFilter(platform string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_data_protection_policy" "test" {
  filter        = "name:~'nosuchpolicyexists0000'"
  platform_name = %[1]q
}
`, platform)
}

// testAccPolicyDataSourceConfig_multiple creates two policies whose names share
// a token, so a filter on that token matches both.
func testAccPolicyDataSourceConfig_multiple(name, nameOther, platform string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_data_protection_policy" "test" {
  platform_name = %[3]q
  name          = "%[1]s-shared"
}

resource "crowdstrike_data_protection_policy" "other" {
  platform_name = %[3]q
  name          = "%[2]s-shared"
}

data "crowdstrike_data_protection_policy" "test" {
  filter        = "name:~'shared'"
  platform_name = %[3]q

  depends_on = [
    crowdstrike_data_protection_policy.test,
    crowdstrike_data_protection_policy.other,
  ]
}
`, name, nameOther, platform)
}
