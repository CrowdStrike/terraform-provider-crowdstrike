package preventionpolicy_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccPreventionPolicyPrecedenceResource_strict(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless env 'TF_ACC' set")
	}
	acctest.PreCheck(t)

	platformName := "Linux"
	ids := getNonDefaultPreventionPolicyIDs(t, platformName)
	if len(ids) == 0 {
		t.Skipf("no non-default %s prevention policies in tenant; nothing to test", platformName)
	}

	resourceName := "crowdstrike_prevention_policy_precedence.test"

	idChecks := make([]knownvalue.Check, len(ids))
	for i, id := range ids {
		idChecks[i] = knownvalue.StringExact(id)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPolicyPrecedenceStrictConfig(platformName, ids),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("ids"),
						knownvalue.ListExact(idChecks),
					),
				},
			},
		},
	})
}

// getNonDefaultPreventionPolicyIDs returns every non-default prevention policy id
// for a platform that belongs to the authenticated CID, ordered by precedence.asc.
// It mirrors what the resource reads back so the strict test can assert against the
// live tenant without hardcoding ids. In a Flight Control environment the combined
// endpoint also returns other CIDs' policies and one platform_default per CID; those
// are excluded here just as the resource does.
func getNonDefaultPreventionPolicyIDs(t *testing.T, platformName string) []string {
	t.Helper()

	c := testconfig.GetTestClient()
	if c == nil {
		t.Fatal("test client not initialized; PreCheck must run first")
	}

	ccidRes, err := c.SensorDownload.GetSensorInstallersCCIDByQuery(
		sensor_download.NewGetSensorInstallersCCIDByQueryParamsWithContext(context.Background()),
	)
	if err != nil {
		t.Fatalf("failed to query ccid: %s", err)
	}
	if ccidRes == nil || ccidRes.Payload == nil || len(ccidRes.Payload.Resources) == 0 {
		t.Fatal("ccid query returned no data")
	}
	ownCID := ccidRes.Payload.Resources[0]
	if idx := strings.LastIndex(ownCID, "-"); idx >= 0 {
		ownCID = ownCID[:idx]
	}
	ownCID = strings.ToLower(ownCID)

	filter := fmt.Sprintf("platform_name:'%s'", platformName)
	sort := "precedence.asc"
	limit := int64(5000)
	offset := int64(0)

	var ids []string
	for {
		res, err := c.PreventionPolicies.QueryCombinedPreventionPolicies(
			&prevention_policies.QueryCombinedPreventionPoliciesParams{
				Context: context.Background(),
				Filter:  &filter,
				Sort:    &sort,
				Limit:   &limit,
				Offset:  &offset,
			},
		)
		if err != nil {
			t.Fatalf("failed to query prevention policies: %s", err)
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			break
		}

		for _, policy := range res.Payload.Resources {
			if policy == nil || policy.ID == nil {
				continue
			}
			if policy.Name != nil && *policy.Name == "platform_default" {
				continue
			}
			if policy.Cid == nil || !strings.EqualFold(*policy.Cid, ownCID) {
				continue
			}
			ids = append(ids, *policy.ID)
		}

		if res.Payload.Meta == nil || res.Payload.Meta.Pagination == nil ||
			res.Payload.Meta.Pagination.Offset == nil || res.Payload.Meta.Pagination.Total == nil {
			offset += limit
			continue
		}

		offset = int64(*res.Payload.Meta.Pagination.Offset)
		if offset >= *res.Payload.Meta.Pagination.Total {
			break
		}
	}

	return ids
}

func testAccPreventionPolicyPrecedenceStrictConfig(platformName string, ids []string) string {
	quoted := ""
	for _, id := range ids {
		quoted += fmt.Sprintf("    %q,\n", id)
	}

	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_prevention_policy_precedence" "test" {
  platform_name = %q
  enforcement   = "strict"
  ids = [
%s  ]
}
`, platformName, quoted)
}
