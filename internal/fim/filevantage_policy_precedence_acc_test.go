package fim_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/filevantage"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccFilevantagePolicyPrecedenceResource_strict(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless env 'TF_ACC' set")
	}
	acctest.PreCheck(t)

	var platformName string
	var ids []string
	for _, p := range []string{"Windows", "Linux", "Mac"} {
		if candidate := getNonDefaultFilevantagePolicyIDs(t, p); len(candidate) > 0 {
			platformName = p
			ids = candidate
			break
		}
	}
	if len(ids) == 0 {
		t.Skip("no non-default filevantage policies in tenant for any platform; nothing to test")
	}

	resourceName := "crowdstrike_filevantage_policy_precedence.test"

	idChecks := make([]knownvalue.Check, len(ids))
	for i, id := range ids {
		idChecks[i] = knownvalue.StringExact(id)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFilevantagePolicyPrecedenceStrictConfig(platformName, ids),
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

// getNonDefaultFilevantagePolicyIDs returns every non-default filevantage policy id
// for a platform that belongs to the authenticated CID, ordered by precedence|asc.
// It mirrors what the resource reads back so the strict test can assert against the
// live tenant without hardcoding ids. In a Flight Control environment the query
// endpoint also returns other CIDs' policies and one "Default Policy (<platform>)"
// per CID; those are excluded here just as the resource does.
func getNonDefaultFilevantagePolicyIDs(t *testing.T, platformName string) []string {
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

	sort := "precedence|asc"
	limit := int64(500)
	offset := int64(0)

	var orderedIDs []string
	for {
		res, err := c.Filevantage.QueryPolicies(
			&filevantage.QueryPoliciesParams{
				Context: context.Background(),
				Type:    platformName,
				Sort:    &sort,
				Limit:   &limit,
				Offset:  &offset,
			},
		)
		if err != nil {
			t.Fatalf("failed to query filevantage policies: %s", err)
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			break
		}

		orderedIDs = append(orderedIDs, res.Payload.Resources...)

		if res.Payload.Meta == nil || res.Payload.Meta.Pagination == nil ||
			res.Payload.Meta.Pagination.Offset == nil || res.Payload.Meta.Pagination.Total == nil {
			offset += limit
			continue
		}

		offset = int64(*res.Payload.Meta.Pagination.Offset) + int64(*res.Payload.Meta.Pagination.Limit)
		if offset >= *res.Payload.Meta.Pagination.Total {
			break
		}
	}

	if len(orderedIDs) == 0 {
		return nil
	}

	detailsRes, err := c.Filevantage.GetPolicies(
		&filevantage.GetPoliciesParams{
			Context: context.Background(),
			Ids:     orderedIDs,
		},
	)
	if err != nil {
		t.Fatalf("failed to get filevantage policies: %s", err)
	}

	byID := make(map[string]struct {
		cid  string
		name string
	}, len(orderedIDs))
	if detailsRes != nil && detailsRes.Payload != nil {
		for _, policy := range detailsRes.Payload.Resources {
			if policy == nil || policy.ID == nil {
				continue
			}
			cid := ""
			if policy.Cid != nil {
				cid = *policy.Cid
			}
			byID[*policy.ID] = struct {
				cid  string
				name string
			}{cid: cid, name: policy.Name}
		}
	}

	defaultName := fmt.Sprintf("Default Policy (%s)", platformName)
	var ids []string
	for _, id := range orderedIDs {
		p, ok := byID[id]
		if !ok {
			continue
		}
		if p.name == defaultName {
			continue
		}
		if !strings.EqualFold(p.cid, ownCID) {
			continue
		}
		ids = append(ids, id)
	}

	return ids
}

func testAccFilevantagePolicyPrecedenceStrictConfig(platformName string, ids []string) string {
	quoted := ""
	for _, id := range ids {
		quoted += fmt.Sprintf("    %q,\n", id)
	}

	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_filevantage_policy_precedence" "test" {
  platform_name = %q
  enforcement   = "strict"
  ids = [
%s  ]
}
`, platformName, quoted)
}
