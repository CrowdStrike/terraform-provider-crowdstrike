package user_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccUserDataSource_byUUID(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless env 'TF_ACC' set")
	}
	acctest.PreCheck(t)

	user := getFirstUser(t)
	dataSourceName := "data.crowdstrike_user.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
data "crowdstrike_user" "test" {
  user_uuid = %q
}`, user.UUID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("user_uuid"), knownvalue.StringExact(user.UUID)),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("email"), knownvalue.StringExact(user.UID)),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("first_name"), knownvalue.StringExact(user.FirstName)),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("last_name"), knownvalue.StringExact(user.LastName)),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("cid"), knownvalue.StringExact(user.Cid)),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("status"), knownvalue.StringExact(user.Status)),
				},
			},
		},
	})
}

func TestAccUserDataSource_byEmail(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless env 'TF_ACC' set")
	}
	acctest.PreCheck(t)

	user := getFirstUser(t)
	dataSourceName := "data.crowdstrike_user.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
data "crowdstrike_user" "test" {
  email = %q
}`, user.UID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("user_uuid"), knownvalue.StringExact(user.UUID)),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("email"), knownvalue.StringExact(user.UID)),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("first_name"), knownvalue.StringExact(user.FirstName)),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("last_name"), knownvalue.StringExact(user.LastName)),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("cid"), knownvalue.StringExact(user.Cid)),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("status"), knownvalue.StringExact(user.Status)),
				},
			},
		},
	})
}

// getFirstUser queries the authenticated tenant for an existing user and returns
// its full details so the data source can be asserted against live data without
// hardcoding a user.
func getFirstUser(t *testing.T) *models.DomainUser {
	t.Helper()

	c := testconfig.GetTestClient()
	if c == nil {
		t.Fatal("test client not initialized; PreCheck must run first")
	}

	ctx := context.Background()
	queryRes, err := c.UserManagement.QueryUserV1(&user_management.QueryUserV1Params{Context: ctx})
	if err != nil {
		t.Fatalf("failed to query users: %s", err)
	}
	if queryRes == nil || queryRes.Payload == nil || len(queryRes.Payload.Resources) == 0 {
		t.Skip("no users in tenant; nothing to test")
	}

	uuid := queryRes.Payload.Resources[0]
	retrieveRes, err := c.UserManagement.RetrieveUsersGETV1(&user_management.RetrieveUsersGETV1Params{
		Context: ctx,
		Body:    &models.MsaspecIdsRequest{Ids: []string{uuid}},
	})
	if err != nil {
		t.Fatalf("failed to retrieve user %q: %s", uuid, err)
	}
	if retrieveRes == nil || retrieveRes.Payload == nil || len(retrieveRes.Payload.Resources) == 0 || retrieveRes.Payload.Resources[0] == nil {
		t.Fatalf("retrieve returned no data for user %q", uuid)
	}

	return retrieveRes.Payload.Resources[0]
}
