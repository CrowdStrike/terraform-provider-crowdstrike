package ngsiem_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
)

const dataConnectorsDataSourceAddr = "data.crowdstrike_ngsiem_data_connectors.test"

func TestAccNGSIEMConnectorsDataSource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(acctest.ProviderConfig, `
data "crowdstrike_ngsiem_data_connectors" "test" {}
`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						dataConnectorsDataSourceAddr,
						tfjsonpath.New("connectors").AtSliceIndex(0).AtMapKey("id"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						dataConnectorsDataSourceAddr,
						tfjsonpath.New("connectors").AtSliceIndex(0).AtMapKey("name"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						dataConnectorsDataSourceAddr,
						tfjsonpath.New("connectors").AtSliceIndex(0).AtMapKey("type"),
						knownvalue.NotNull(),
					),
				},
			},
		},
	})
}

func TestAccNGSIEMConnectorsDataSource_filter(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(acctest.ProviderConfig, `
data "crowdstrike_ngsiem_data_connectors" "test" {
  filter = "type:'PULL'"
}
`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						dataConnectorsDataSourceAddr,
						tfjsonpath.New("connectors").AtSliceIndex(0).AtMapKey("type"),
						knownvalue.StringExact("PULL"),
					),
				},
			},
		},
	})
}

func TestAccNGSIEMConnectorsDataSource_invalidFilter(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(acctest.ProviderConfig, `
data "crowdstrike_ngsiem_data_connectors" "test" {
  filter = " "
}
`),
				ExpectError: regexp.MustCompile("must not be empty or contain only whitespace"),
			},
		},
	})
}
