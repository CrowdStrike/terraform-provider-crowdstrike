package correlationrules_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccCorrelationRulesDataSource_NoFilter returns all rules.
func TestAccCorrelationRulesDataSource_NoFilter(t *testing.T) {
	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireCustomerID) },
		Steps: []resource.TestStep{
			// Create a rule so we know at least one exists
			{
				Config: testAccCorrelationRulesDataSourceSetup(rName) + `
data "crowdstrike_correlation_rules" "all" {
  depends_on = [crowdstrike_correlation_rule.test]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// At least one rule should be returned
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_correlation_rules.all",
						"rules.0.id",
					),
				),
			},
		},
	})
}

// TestAccCorrelationRulesDataSource_FilterByStatus uses the status attribute.
func TestAccCorrelationRulesDataSource_FilterByStatus(t *testing.T) {
	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireCustomerID) },
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRulesDataSourceSetup(rName) + `
data "crowdstrike_correlation_rules" "inactive" {
  status     = "inactive"
  depends_on = [crowdstrike_correlation_rule.test]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_correlation_rules.inactive",
						"rules.0.id",
					),
					// All returned rules must be inactive
					resource.TestCheckResourceAttr(
						"data.crowdstrike_correlation_rules.inactive",
						"rules.0.status",
						"inactive",
					),
				),
			},
		},
	})
}

// TestAccCorrelationRulesDataSource_FilterByName uses the name attribute.
func TestAccCorrelationRulesDataSource_FilterByName(t *testing.T) {
	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireCustomerID) },
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRulesDataSourceSetup(rName) + fmt.Sprintf(`
data "crowdstrike_correlation_rules" "by_name" {
  name       = %[1]q
  depends_on = [crowdstrike_correlation_rule.test]
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"data.crowdstrike_correlation_rules.by_name",
						"rules.#",
						"1",
					),
					resource.TestCheckResourceAttr(
						"data.crowdstrike_correlation_rules.by_name",
						"rules.0.name",
						rName,
					),
				),
			},
		},
	})
}

// TestAccCorrelationRulesDataSource_FQLFilter uses the raw filter attribute.
func TestAccCorrelationRulesDataSource_FQLFilter(t *testing.T) {
	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireCustomerID) },
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRulesDataSourceSetup(rName) + fmt.Sprintf(`
data "crowdstrike_correlation_rules" "by_fql" {
  filter     = "name:'%[1]s'"
  depends_on = [crowdstrike_correlation_rule.test]
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"data.crowdstrike_correlation_rules.by_fql",
						"rules.#",
						"1",
					),
					resource.TestCheckResourceAttr(
						"data.crowdstrike_correlation_rules.by_fql",
						"rules.0.name",
						rName,
					),
				),
			},
		},
	})
}

// TestAccCorrelationRulesDataSource_FilterConflict verifies that filter and
// individual attributes cannot be used together.
func TestAccCorrelationRulesDataSource_FilterConflict(t *testing.T) {
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

// testAccCorrelationRulesDataSourceSetup creates a single rule to query against.
func testAccCorrelationRulesDataSourceSetup(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_correlation_rule" "test" {
  name        = %[1]q
  customer_id = %[2]q
  severity    = 50
  status      = "inactive"

  search {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    outcome      = "detection"
    trigger_mode = "verbose"
  }

  operation {
    schedule {
      definition = "@every 1h0m"
    }
  }
}
`, rName, acctest.CustomerID())
}
