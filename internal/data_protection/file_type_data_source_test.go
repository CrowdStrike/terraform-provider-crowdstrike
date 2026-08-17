package dataprotection_test

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccFileTypeDataSource_byID(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless env 'TF_ACC' set")
	}
	acctest.PreCheck(t)

	fileType := getFirstFileType(t)
	dataSourceName := "data.crowdstrike_data_protection_file_type.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
data "crowdstrike_data_protection_file_type" "test" {
  id = %q
}`, *fileType.ID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("id"), knownvalue.StringExact(*fileType.ID)),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("name"), knownvalue.StringExact(fileType.Name)),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("category_id"), knownvalue.StringExact(*fileType.CategoryID)),
				},
			},
		},
	})
}

func TestAccFileTypeDataSource_byName(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless env 'TF_ACC' set")
	}
	acctest.PreCheck(t)

	fileType := getFirstFileType(t)
	dataSourceName := "data.crowdstrike_data_protection_file_type.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
data "crowdstrike_data_protection_file_type" "test" {
  name = %q
}`, fileType.Name),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("id"), knownvalue.StringExact(*fileType.ID)),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("name"), knownvalue.StringExact(fileType.Name)),
				},
			},
		},
	})
}

func TestAccFileTypeDataSource_notFound(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless env 'TF_ACC' set")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: `
data "crowdstrike_data_protection_file_type" "test" {
  name = "definitely-not-a-real-file-type-name-abc123"
}`,
				ExpectError: regexp.MustCompile(`(?i)not found`),
			},
		},
	})
}

// getFirstFileType queries the file type catalog and returns full details for
// the first entry so the data source can be asserted against live data without
// hardcoding a specific file type name or ID.
func getFirstFileType(t *testing.T) *models.APIFileTypeV1 {
	t.Helper()

	c := testconfig.GetTestClient()
	if c == nil {
		t.Fatal("test client not initialized; PreCheck must run first")
	}

	ctx := context.Background()
	queryRes, err := c.DataProtectionConfiguration.QueriesFileTypeGetV2(
		data_protection_configuration.NewQueriesFileTypeGetV2ParamsWithContext(ctx),
	)
	if err != nil {
		t.Fatalf("failed to query file types: %s", err)
	}
	if queryRes == nil || queryRes.Payload == nil || len(queryRes.Payload.Resources) == 0 {
		t.Skip("no file types available in tenant; nothing to test")
	}

	id := queryRes.Payload.Resources[0]

	entityParams := data_protection_configuration.NewEntitiesFileTypeGetParamsWithContext(ctx)
	entityParams.Ids = []string{id}

	entityRes, err := c.DataProtectionConfiguration.EntitiesFileTypeGet(entityParams)
	if err != nil {
		t.Fatalf("failed to retrieve file type %q: %s", id, err)
	}
	if entityRes == nil || entityRes.Payload == nil || len(entityRes.Payload.Resources) == 0 || entityRes.Payload.Resources[0] == nil {
		t.Fatalf("retrieve returned no data for file type %q", id)
	}

	return entityRes.Payload.Resources[0]
}
