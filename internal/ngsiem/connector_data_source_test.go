package ngsiem_test

import (
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccNgsiemConnectorDataSource_pull(t *testing.T) {
	dataSourceName := "data.crowdstrike_ngsiem_connector.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: `
data "crowdstrike_ngsiem_connector" "test" {
  name = "Amazon S3 Access Log Data Connector"
}`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("id"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("type"),
						knownvalue.StringExact("PULL"),
					),
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("vendor_name"),
						knownvalue.StringExact("AmazonWebServices"),
					),
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("parsers"),
						knownvalue.ListPartial(map[int]knownvalue.Check{
							0: knownvalue.StringExact("aws-s3serveraccess"),
						}),
					),
				},
			},
		},
	})
}

func TestAccNgsiemConnectorDataSource_push(t *testing.T) {
	dataSourceName := "data.crowdstrike_ngsiem_connector.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: `
data "crowdstrike_ngsiem_connector" "test" {
  name = "HEC / HTTP Event Connector"
}`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("type"),
						knownvalue.StringExact("PUSH"),
					),
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("parsers"),
						knownvalue.Null(),
					),
				},
			},
		},
	})
}

func TestAccNgsiemConnectorDataSource_notFound(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: `
data "crowdstrike_ngsiem_connector" "test" {
  name = "this-connector-does-not-exist-xyz"
}`,
				ExpectError: regexp.MustCompile("No connector found"),
			},
		},
	})
}
