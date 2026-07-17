package contentupdatepolicy_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	contentupdatepolicy "github.com/crowdstrike/terraform-provider-crowdstrike/internal/content_update_policy"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccContentUpdatePolicyPrecedenceResource_strict(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless env 'TF_ACC' set")
	}
	acctest.PreCheck(t)

	ids := getNonDefaultContentUpdatePolicyIDs(t)
	if len(ids) == 0 {
		t.Skip("no non-default content update policies in tenant; nothing to test")
	}

	resourceName := "crowdstrike_content_update_policy_precedence.test"

	idChecks := make([]knownvalue.Check, len(ids))
	for i, id := range ids {
		idChecks[i] = knownvalue.StringExact(id)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccContentUpdatePolicyPrecedenceStrictConfig(ids),
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

// getNonDefaultContentUpdatePolicyIDs returns every non-default content update policy id
// that belongs to the authenticated CID, ordered by precedence.asc. It mirrors what the
// resource reads back so the strict test can assert against the live tenant without
// hardcoding ids. In a Flight Control environment the combined endpoint also returns other
// CIDs' policies and one platform_default per CID; those are excluded here just as the
// resource does.
func getNonDefaultContentUpdatePolicyIDs(t *testing.T) []string {
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

	sort := "precedence.asc"
	limit := int64(5000)
	offset := int64(0)

	var ids []string
	for {
		res, err := c.ContentUpdatePolicies.QueryCombinedContentUpdatePolicies(
			&content_update_policies.QueryCombinedContentUpdatePoliciesParams{
				Context: context.Background(),
				Sort:    &sort,
				Limit:   &limit,
				Offset:  &offset,
			},
		)
		if err != nil {
			t.Fatalf("failed to query content update policies: %s", err)
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

func testAccContentUpdatePolicyPrecedenceStrictConfig(ids []string) string {
	quoted := ""
	for _, id := range ids {
		quoted += fmt.Sprintf("    %q,\n", id)
	}

	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_content_update_policy_precedence" "test" {
  enforcement = "strict"
  ids = [
%s  ]
}
`, quoted)
}

func TestFilterPoliciesByCID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policies []contentupdatepolicy.PolicyRef
		cid      string
		want     []string
	}{
		{
			name: "keeps only matching cid preserving order",
			policies: []contentupdatepolicy.PolicyRef{
				contentupdatepolicy.NewPolicyRef("a", "010abf4b", ""),
				contentupdatepolicy.NewPolicyRef("b", "2436580c", ""),
				contentupdatepolicy.NewPolicyRef("c", "010abf4b", ""),
			},
			cid:  "010abf4b",
			want: []string{"a", "c"},
		},
		{
			name: "case insensitive cid match",
			policies: []contentupdatepolicy.PolicyRef{
				contentupdatepolicy.NewPolicyRef("a", "010ABF4B", ""),
			},
			cid:  "010abf4b",
			want: []string{"a"},
		},
		{
			name: "no matches returns empty",
			policies: []contentupdatepolicy.PolicyRef{
				contentupdatepolicy.NewPolicyRef("a", "2436580c", ""),
			},
			cid:  "010abf4b",
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := contentupdatepolicy.FilterPoliciesByCID(tt.policies, tt.cid)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestDistinctCIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policies []contentupdatepolicy.PolicyRef
		want     []string
	}{
		{
			name: "single cid",
			policies: []contentupdatepolicy.PolicyRef{
				contentupdatepolicy.NewPolicyRef("a", "010abf4b", ""),
				contentupdatepolicy.NewPolicyRef("b", "010abf4b", ""),
			},
			want: []string{"010abf4b"},
		},
		{
			name: "multiple distinct cids first-seen order",
			policies: []contentupdatepolicy.PolicyRef{
				contentupdatepolicy.NewPolicyRef("a", "2436580c", ""),
				contentupdatepolicy.NewPolicyRef("b", "010abf4b", ""),
				contentupdatepolicy.NewPolicyRef("c", "2436580c", ""),
			},
			want: []string{"2436580c", "010abf4b"},
		},
		{
			name: "empty cids skipped",
			policies: []contentupdatepolicy.PolicyRef{
				contentupdatepolicy.NewPolicyRef("a", "", ""),
				contentupdatepolicy.NewPolicyRef("b", "010abf4b", ""),
			},
			want: []string{"010abf4b"},
		},
		{
			name:     "no policies",
			policies: []contentupdatepolicy.PolicyRef{},
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := contentupdatepolicy.DistinctCIDs(tt.policies)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestStripChecksum(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "uppercase ccid with checksum",
			in:   "010ABF4B1BA04B7DA3F240A4C56657AC-C1",
			want: "010abf4b1ba04b7da3f240a4c56657ac",
		},
		{
			name: "no checksum suffix",
			in:   "010ABF4B1BA04B7DA3F240A4C56657AC",
			want: "010abf4b1ba04b7da3f240a4c56657ac",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := contentupdatepolicy.StripChecksum(tt.in); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
