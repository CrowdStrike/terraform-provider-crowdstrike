package correlationrules_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccCorrelationRulesDataSource_noFilter(t *testing.T) {
	rName := acctest.RandomResourceName()
	dataSourceName := "data.crowdstrike_correlation_rules.all"
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRulesDataSourceSetup(rName) + `
data "crowdstrike_correlation_rules" "all" {
  depends_on = [crowdstrike_correlation_rule.test]
}
`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("id"),
						knownvalue.NotNull(),
					),
				},
			},
		},
	})
}

func TestAccCorrelationRulesDataSource_status(t *testing.T) {
	rName := acctest.RandomResourceName()
	dataSourceName := "data.crowdstrike_correlation_rules.inactive"
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRulesDataSourceSetup(rName) + `
data "crowdstrike_correlation_rules" "inactive" {
  status     = "inactive"
  depends_on = [crowdstrike_correlation_rule.test]
}
`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("id"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("status"),
						knownvalue.StringExact("inactive"),
					),
				},
			},
		},
	})
}

func TestAccCorrelationRulesDataSource_fql(t *testing.T) {
	rName := acctest.RandomResourceName()
	dataSourceName := "data.crowdstrike_correlation_rules.by_fql"
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRulesDataSourceSetup(rName) + fmt.Sprintf(`
data "crowdstrike_correlation_rules" "by_fql" {
  filter     = "name:'%[1]s'"
  depends_on = [crowdstrike_correlation_rule.test]
}
`, rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("rules"),
						knownvalue.ListSizeExact(1),
					),
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"),
						knownvalue.StringExact(rName),
					),
				},
			},
		},
	})
}

func TestAccCorrelationRulesDataSource_filter(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_correlation_rule.test"
	dataSourceName := "data.crowdstrike_correlation_rules.by_name"
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRulesDataSourceSetup(rName) + fmt.Sprintf(`
data "crowdstrike_correlation_rules" "by_name" {
  name       = %[1]q
  depends_on = [crowdstrike_correlation_rule.test]
}
`, rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("rules"),
						knownvalue.ListSizeExact(1),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("id"),
						dataSourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("name"),
						dataSourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("cid"),
						dataSourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("cid"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("severity"),
						dataSourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("severity"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("status"),
						dataSourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("status"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("description"),
						dataSourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("description"),
						compare.ValuesSame(),
					),
					// rule_id is the stable identifier and aliases id.
					statecheck.CompareValuePairs(
						dataSourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("id"),
						dataSourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("rule_id"),
						compare.ValuesSame(),
					),
					// The data source always restricts results to correlation rules.
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("type"),
						knownvalue.StringExact("correlation"),
					),
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("created_on"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("updated_on"),
						knownvalue.NotNull(),
					),
				},
			},
		},
	})
}

func TestAccCorrelationRulesDataSource_filterConflict(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
data "crowdstrike_correlation_rules" "bad" {
  filter = "status:'active'"
  status = "active"
}
`,
				ExpectError: regexp.MustCompile(`Invalid Attribute Combination`),
			},
		},
	})
}

func testAccCorrelationRulesDataSourceSetup(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_cid" "test" {}

resource "crowdstrike_correlation_rule" "test" {
  name        = %[1]q
  cid         = data.crowdstrike_cid.test.cid
  severity    = "medium"
  status      = "inactive"
  description = "Acceptance test correlation rule"

  search = {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    create_case  = false
    trigger_mode = "verbose"
  }

  schedule = {
    interval = "1h0m"
    start_on = "2030-01-01T00:00:00Z"
  }

  notifications = [
    {
      type         = "email"
      is_guardrail = true
      recipients   = ["acc-tests@crowdstrike.com"]
    }
  ]
}
`, rName)
}
