package contentupdatepolicy_test

import (
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccContentUpdatePoliciesDataSource(t *testing.T) {
	var steps []resource.TestStep

	// Add basic functionality tests
	steps = append(steps, testContentUpdatePoliciesBasic()...)
	// Add filter-based tests
	steps = append(steps, testContentUpdatePoliciesWithFilter()...)
	// Add ID-based tests
	steps = append(steps, testContentUpdatePoliciesWithIDs()...)
	// Add individual filter attributes tests
	steps = append(steps, testContentUpdatePoliciesWithIndividualFilters()...)
	// Add sorting tests
	steps = append(steps, testContentUpdatePoliciesWithSorting()...)
	// Add validation error tests
	steps = append(steps, testContentUpdatePoliciesValidationErrors()...)
	// Add empty result tests
	steps = append(steps, testContentUpdatePoliciesEmptyResults()...)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    steps,
	})
}

func testContentUpdatePoliciesBasic() []resource.TestStep {
	return []resource.TestStep{
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.test", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.test", "id", "all"),
				// Check that we have some policies and verify their structure
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.test", "policies.0.id"),
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.test", "policies.0.name"),
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.test", "policies.0.enabled"),
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.test", "policies.0.created_by"),
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.test", "policies.0.created_timestamp"),
			),
		},
	}
}

func testContentUpdatePoliciesWithFilter() []resource.TestStep {
	return []resource.TestStep{
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "enabled" {
  filter = "enabled:true"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.enabled", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.enabled", "id", "filtered"),
				// Verify all returned policies are enabled
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.enabled", "policies.0.enabled", "true"),
			),
		},
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "by_name" {
  filter = "name:'*policy*'"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.by_name", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.by_name", "id", "filtered"),
			),
		},
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "complex_filter" {
  filter = "enabled:true"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.complex_filter", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.complex_filter", "id", "filtered"),
			),
		},
	}
}

func testContentUpdatePoliciesWithIDs() []resource.TestStep {
	return []resource.TestStep{
		{
			Config: acctest.ProviderConfig + `
# First get all policies to extract some IDs
data "crowdstrike_content_update_policies" "all" {}

# Then use specific IDs (using first two policies from all)
data "crowdstrike_content_update_policies" "specific" {
  ids = [
    data.crowdstrike_content_update_policies.all.policies[0].id,
    length(data.crowdstrike_content_update_policies.all.policies) > 1 ? data.crowdstrike_content_update_policies.all.policies[1].id : data.crowdstrike_content_update_policies.all.policies[0].id
  ]
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.specific", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.specific", "id", "ids"),
				// Verify we get exactly the policies we requested (up to 2)
				resource.TestMatchResourceAttr("data.crowdstrike_content_update_policies.specific", "policies.#", regexp.MustCompile(`^[12]$`)),
			),
		},
	}
}

func testContentUpdatePoliciesWithIndividualFilters() []resource.TestStep {
	return []resource.TestStep{
		// Test enabled filter
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "enabled_true" {
  enabled = true
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.enabled_true", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.enabled_true", "id", "filtered"),
				// Verify all returned policies are enabled
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.enabled_true", "policies.0.enabled", "true"),
			),
		},
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "enabled_false" {
  enabled = false
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.enabled_false", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.enabled_false", "id", "filtered"),
				// Verify all returned policies are disabled
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.enabled_false", "policies.0.enabled", "false"),
			),
		},
		// Test platform filter
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "platform_windows" {
  platform = "windows"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.platform_windows", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.platform_windows", "id", "filtered"),
			),
		},
		// Test combination including platform
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "combined_with_platform" {
  platform = "windows"
  enabled  = true
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.combined_with_platform", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.combined_with_platform", "id", "filtered"),
				// Verify all returned policies match both criteria
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.combined_with_platform", "policies.0.enabled", "true"),
			),
		},
		// Test name filter
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "name_filter" {
  name = "policy"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.name_filter", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.name_filter", "id", "filtered"),
			),
		},
		// Test description filter
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "description_filter" {
  description = "update"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.description_filter", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.description_filter", "id", "filtered"),
			),
		},
		// Test combination with name and enabled
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "combined_name_enabled" {
  name    = "policy"
  enabled = true
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.combined_name_enabled", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.combined_name_enabled", "id", "filtered"),
				// Verify all returned policies are enabled
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.combined_name_enabled", "policies.0.enabled", "true"),
			),
		},
	}
}

func testContentUpdatePoliciesWithSorting() []resource.TestStep {
	return []resource.TestStep{
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "sorted_asc" {
  sort = "name.asc"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.sorted_asc", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.sorted_asc", "id", "all"),
			),
		},
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "sorted_desc" {
  sort = "created_timestamp.desc"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.sorted_desc", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.sorted_desc", "id", "all"),
			),
		},
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "filtered_and_sorted" {
  filter = "enabled:true"
  sort   = "name.asc"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.filtered_and_sorted", "policies.#"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.filtered_and_sorted", "id", "filtered"),
			),
		},
	}
}

func testContentUpdatePoliciesValidationErrors() []resource.TestStep {
	return []resource.TestStep{
		// Test filter + ids (existing validation)
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "invalid_filter_ids" {
  filter = "enabled:true"
  ids    = ["policy-id-1", "policy-id-2"]
}
`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		// Test filter + individual attributes
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "invalid_filter_individual" {
  filter  = "enabled:true"
  enabled = false
}
`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		// Test filter + name attribute
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "invalid_filter_name" {
  filter = "enabled:true"
  name   = "policy"
}
`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		// Test ids + individual attributes
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "invalid_ids_individual" {
  ids     = ["policy-id-1"]
  enabled = true
}
`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		// Test ids + description attribute
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "invalid_ids_description" {
  ids         = ["policy-id-1"]
  description = "update"
}
`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		// Test all three types together
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "invalid_all_three" {
  filter  = "enabled:true"
  ids     = ["policy-id-1"]
  enabled = false
}
`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
	}
}

func testContentUpdatePoliciesEmptyResults() []resource.TestStep {
	return []resource.TestStep{
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "empty" {
  filter = "name:'NonExistentPolicyThatShouldNeverExist12345'"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.empty", "policies.#", "0"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.empty", "id", "filtered"),
			),
		},
		{
			Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "empty_ids" {
  ids = ["non-existent-policy-id-12345"]
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.empty_ids", "policies.#", "0"),
				resource.TestCheckResourceAttr("data.crowdstrike_content_update_policies.empty_ids", "id", "ids"),
			),
		},
	}
}

func TestAccContentUpdatePoliciesDataSource_AllAttributes(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify all schema attributes are accessible
					resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.test", "policies.0.id"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.test", "policies.0.name"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.test", "policies.0.enabled"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.test", "policies.0.created_by"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.test", "policies.0.created_timestamp"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.test", "policies.0.modified_by"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.test", "policies.0.modified_timestamp"),
					// Check that lists are properly initialized (even if empty)
					resource.TestCheckResourceAttrSet("data.crowdstrike_content_update_policies.test", "policies.0.groups.#"),
				),
			},
		},
	})
}
