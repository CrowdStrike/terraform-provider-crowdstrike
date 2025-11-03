package preventionpolicy_test

import (
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccPreventionPoliciesDataSource(t *testing.T) {
	var steps []resource.TestStep

	// Add basic functionality tests
	steps = append(steps, testPreventionPoliciesBasic()...)
	// Add filter-based tests
	steps = append(steps, testPreventionPoliciesWithFilter()...)
	// Add ID-based tests
	steps = append(steps, testPreventionPoliciesWithIDs()...)
	// Add individual filter attributes tests
	steps = append(steps, testPreventionPoliciesWithIndividualFilters()...)
	// Add sorting tests
	steps = append(steps, testPreventionPoliciesWithSorting()...)
	// Add validation error tests
	steps = append(steps, testPreventionPoliciesValidationErrors()...)
	// Add empty result tests
	steps = append(steps, testPreventionPoliciesEmptyResults()...)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    steps,
	})
}

func testPreventionPoliciesBasic() []resource.TestStep {
	return []resource.TestStep{
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.test", "id", "all"),
				// Check that we have some policies and verify their structure
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.id"),
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.name"),
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.platform_name"),
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.enabled"),
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.created_by"),
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.created_timestamp"),
			),
		},
	}
}

func testPreventionPoliciesWithFilter() []resource.TestStep {
	return []resource.TestStep{
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "windows" {
  filter = "platform_name:'Windows'"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.windows", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.windows", "id", "filtered"),
				// Verify all returned policies are Windows policies
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.windows", "policies.0.platform_name", "Windows"),
			),
		},
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "enabled" {
  filter = "enabled:true"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.enabled", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.enabled", "id", "filtered"),
				// Verify all returned policies are enabled
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.enabled", "policies.0.enabled", "true"),
			),
		},
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "complex_filter" {
  filter = "platform_name:'Windows'+enabled:true"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.complex_filter", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.complex_filter", "id", "filtered"),
			),
		},
	}
}

func testPreventionPoliciesWithIDs() []resource.TestStep {
	return []resource.TestStep{
		{
			Config: acctest.ProviderConfig + `
# First get all policies to extract some IDs
data "crowdstrike_prevention_policies" "all" {}

# Then use specific IDs (using first two policies from all)
data "crowdstrike_prevention_policies" "specific" {
  ids = [
    data.crowdstrike_prevention_policies.all.policies[0].id,
    length(data.crowdstrike_prevention_policies.all.policies) > 1 ? data.crowdstrike_prevention_policies.all.policies[1].id : data.crowdstrike_prevention_policies.all.policies[0].id
  ]
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.specific", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.specific", "id", "ids"),
				// Verify we get exactly the policies we requested (up to 2)
				resource.TestMatchResourceAttr("data.crowdstrike_prevention_policies.specific", "policies.#", regexp.MustCompile(`^[12]$`)),
			),
		},
	}
}

func testPreventionPoliciesWithIndividualFilters() []resource.TestStep {
	return []resource.TestStep{
		// Test platform filter
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "platform_windows" {
  platform = "Windows"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.platform_windows", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.platform_windows", "id", "filtered"),
				// Verify all returned policies are Windows policies
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.platform_windows", "policies.0.platform_name", "Windows"),
			),
		},
		// Test enabled filter
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "enabled_true" {
  enabled = true
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.enabled_true", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.enabled_true", "id", "filtered"),
				// Verify all returned policies are enabled
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.enabled_true", "policies.0.enabled", "true"),
			),
		},
		// Test name filter with wildcard
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "name_policy" {
  name = "*policy*"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.name_policy", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.name_policy", "id", "filtered"),
			),
		},
		// Test group_count filter
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "no_groups" {
  group_count = 0
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.no_groups", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.no_groups", "id", "filtered"),
			),
		},
		// Test combination of individual filter attributes
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "combined_filters" {
  platform = "Windows"
  enabled  = true
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.combined_filters", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.combined_filters", "id", "filtered"),
				// Verify all returned policies match both criteria
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.combined_filters", "policies.0.platform_name", "Windows"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.combined_filters", "policies.0.enabled", "true"),
			),
		},
		// Test created_by filter using dynamic reference
		{
			Config: acctest.ProviderConfig + `
# Get all policies to find a real created_by value
data "crowdstrike_prevention_policies" "all_for_created_by" {}

# Filter by the created_by of the first policy
data "crowdstrike_prevention_policies" "by_created_by" {
  created_by = data.crowdstrike_prevention_policies.all_for_created_by.policies[0].created_by
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.by_created_by", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.by_created_by", "id", "filtered"),
			),
		},
	}
}

func testPreventionPoliciesWithSorting() []resource.TestStep {
	return []resource.TestStep{
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "sorted_asc" {
  sort = "name.asc"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.sorted_asc", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.sorted_asc", "id", "all"),
			),
		},
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "sorted_desc" {
  sort = "created_timestamp.desc"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.sorted_desc", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.sorted_desc", "id", "all"),
			),
		},
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "filtered_and_sorted" {
  filter = "platform_name:'Windows'"
  sort   = "name.asc"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.filtered_and_sorted", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.filtered_and_sorted", "id", "filtered"),
			),
		},
	}
}

func testPreventionPoliciesValidationErrors() []resource.TestStep {
	return []resource.TestStep{
		// Test filter + ids (existing validation)
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "invalid_filter_ids" {
  filter = "platform_name:'Windows'"
  ids    = ["policy-id-1", "policy-id-2"]
}
`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		// Test filter + individual attributes
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "invalid_filter_individual" {
  filter   = "platform_name:'Windows'"
  platform = "Linux"
}
`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		// Test ids + individual attributes
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "invalid_ids_individual" {
  ids     = ["policy-id-1"]
  enabled = true
}
`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		// Test all three types together
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "invalid_all_three" {
  filter   = "platform_name:'Windows'"
  ids      = ["policy-id-1"]
  platform = "Linux"
}
`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		// Test multiple individual attributes + filter
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "invalid_multiple_individual_filter" {
  filter   = "name:'test'"
  platform = "Windows"
  enabled  = true
  name     = "MyPolicy"
}
`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
	}
}

func testPreventionPoliciesEmptyResults() []resource.TestStep {
	return []resource.TestStep{
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "empty" {
  filter = "name:'NonExistentPolicyThatShouldNeverExist12345'"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.empty", "policies.#", "0"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.empty", "id", "filtered"),
			),
		},
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "empty_ids" {
  ids = ["non-existent-policy-id-12345"]
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.empty_ids", "policies.#", "0"),
				resource.TestCheckResourceAttr("data.crowdstrike_prevention_policies.empty_ids", "id", "ids"),
			),
		},
	}
}

func TestAccPreventionPoliciesDataSource_AllAttributes(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify all schema attributes are accessible
					resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.id"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.name"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.platform_name"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.enabled"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.created_by"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.created_timestamp"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.modified_by"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.modified_timestamp"),
					// Check that lists are properly initialized (even if empty)
					resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.groups.#"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_prevention_policies.test", "policies.0.ioa_rule_groups.#"),
				),
			},
		},
	})
}
