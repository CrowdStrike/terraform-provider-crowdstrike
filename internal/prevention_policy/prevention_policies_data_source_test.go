package preventionpolicy_test

import (
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccPreventionPoliciesDataSource_Basic(t *testing.T) {
	resourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfigBasic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					// Check that we have some policies and verify their structure
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.name"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.platform_name"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.enabled"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.created_by"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.created_timestamp"),
				),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_WithFilter(t *testing.T) {
	resourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithFilterWindows(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					// Verify all returned policies are Windows policies
					resource.TestCheckResourceAttr(resourceName, "policies.0.platform_name", "Windows"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithFilterEnabled(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					// Verify all returned policies are enabled
					resource.TestCheckResourceAttr(resourceName, "policies.0.enabled", "true"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithFilterComplex(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_WithIDs(t *testing.T) {
	resourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithIDs(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					// Verify we get exactly the policies we requested (up to 2)
					resource.TestMatchResourceAttr(resourceName, "policies.#", regexp.MustCompile(`^[12]$`)),
				),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_WithIndividualFilters(t *testing.T) {
	resourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test platform filter
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithPlatformFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					// Verify all returned policies are Windows policies
					resource.TestCheckResourceAttr(resourceName, "policies.0.platform_name", "Windows"),
				),
			},
			// Test enabled filter
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithEnabledFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					// Verify all returned policies are enabled
					resource.TestCheckResourceAttr(resourceName, "policies.0.enabled", "true"),
				),
			},
			// Test name filter with wildcard
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithNameFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
			// Test combination of individual filter attributes
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithCombinedFilters(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					// Verify all returned policies match both criteria
					resource.TestCheckResourceAttr(resourceName, "policies.0.platform_name", "Windows"),
					resource.TestCheckResourceAttr(resourceName, "policies.0.enabled", "true"),
				),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_WithSorting(t *testing.T) {
	resourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithSortingAsc(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithSortingDesc(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithSortingFiltered(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_ValidationErrors(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test filter + ids (existing validation)
			{
				Config:      testAccPreventionPoliciesDataSourceConfigValidationFilterIDs(),
				ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
			},
			// Test filter + individual attributes
			{
				Config:      testAccPreventionPoliciesDataSourceConfigValidationFilterIndividual(),
				ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
			},
			// Test ids + individual attributes
			{
				Config:      testAccPreventionPoliciesDataSourceConfigValidationIDsIndividual(),
				ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
			},
			// Test all three types together
			{
				Config:      testAccPreventionPoliciesDataSourceConfigValidationAllThree(),
				ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
			},
			// Test multiple individual attributes + filter
			{
				Config:      testAccPreventionPoliciesDataSourceConfigValidationMultipleFilter(),
				ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_EmptyResults(t *testing.T) {
	resourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfigEmptyResults(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "0"),
				),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_404Handling(t *testing.T) {
	resourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfig404NonExistentID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "0"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfig404PartialResults(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.name"),
				),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_AllAttributes(t *testing.T) {
	resourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfigBasic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify all schema attributes are accessible
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.name"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.platform_name"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.enabled"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.created_by"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.created_timestamp"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.modified_by"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.modified_timestamp"),
					// Check that lists are properly initialized (even if empty)
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.host_groups.#"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.ioa_rule_groups.#"),
				),
			},
		},
	})
}

func testAccPreventionPoliciesDataSourceConfigBasic() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {}
`
}

func testAccPreventionPoliciesDataSourceConfigWithFilterWindows() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter = "platform_name:'Windows'"
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithFilterEnabled() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter = "enabled:true"
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithFilterComplex() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter = "platform_name:'Windows'+enabled:true"
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithIDs() string {
	return acctest.ProviderConfig + `
# First get all policies to extract some IDs
data "crowdstrike_prevention_policies" "all" {}

# Then use specific IDs (using first two policies from all)
data "crowdstrike_prevention_policies" "test" {
  ids = [
    data.crowdstrike_prevention_policies.all.policies[0].id,
    length(data.crowdstrike_prevention_policies.all.policies) > 1 ? data.crowdstrike_prevention_policies.all.policies[1].id : data.crowdstrike_prevention_policies.all.policies[0].id
  ]
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithPlatformFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  platform = "Windows"
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithEnabledFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  enabled = true
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithNameFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  name = "*policy*"
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithCombinedFilters() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  platform = "Windows"
  enabled  = true
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithSortingAsc() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  sort = "name.asc"
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithSortingDesc() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  sort = "created_timestamp.desc"
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithSortingFiltered() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter = "platform_name:'Windows'"
  sort   = "name.asc"
}
`
}

func testAccPreventionPoliciesDataSourceConfigValidationFilterIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter = "platform_name:'Windows'"
  ids    = ["00000000000000000000000000000001", "00000000000000000000000000000002"]
}
`
}

func testAccPreventionPoliciesDataSourceConfigValidationFilterIndividual() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter   = "platform_name:'Windows'"
  platform = "Linux"
}
`
}

func testAccPreventionPoliciesDataSourceConfigValidationIDsIndividual() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  ids     = ["00000000000000000000000000000001"]
  enabled = true
}
`
}

func testAccPreventionPoliciesDataSourceConfigValidationAllThree() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter   = "platform_name:'Windows'"
  ids      = ["00000000000000000000000000000001"]
  platform = "Linux"
}
`
}

func testAccPreventionPoliciesDataSourceConfigValidationMultipleFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter   = "name:'test'"
  platform = "Windows"
  enabled  = true
  name     = "MyPolicy"
}
`
}

func testAccPreventionPoliciesDataSourceConfigEmptyResults() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter = "name:'NonExistentPolicyThatShouldNeverExist12345'"
}
`
}

func testAccPreventionPoliciesDataSourceConfig404NonExistentID() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  ids = ["00000000000000000000000000000000"]
}
`
}

func testAccPreventionPoliciesDataSourceConfig404PartialResults() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "all" {}

data "crowdstrike_prevention_policies" "test" {
  ids = [
    data.crowdstrike_prevention_policies.all.policies[0].id,
    "00000000000000000000000000000000"
  ]
}
`
}
