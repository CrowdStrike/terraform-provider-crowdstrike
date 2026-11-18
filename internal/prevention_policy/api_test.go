package preventionpolicy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubTransport returns a fixed result and error for every operation, so the
// generated gofalcon client can be exercised without sending any request.
type stubTransport struct {
	result any
	err    error
}

func (s *stubTransport) Submit(_ *runtime.ClientOperation) (any, error) {
	return s.result, s.err
}

func newStubClient(result any, err error) *client.CrowdStrikeAPISpecification {
	return client.New(&stubTransport{result: result, err: err}, strfmt.Default)
}

func ruleGroupActionOK(ruleGroupIDs []string, apiErrors ...*models.MsaAPIError) *prevention_policies.PerformPreventionPoliciesActionOK {
	groups := make([]*models.IoaRuleGroupsRuleGroupV1, 0, len(ruleGroupIDs))
	for _, id := range ruleGroupIDs {
		groups = append(groups, &models.IoaRuleGroupsRuleGroupV1{ID: utils.Addr(id)})
	}

	return &prevention_policies.PerformPreventionPoliciesActionOK{
		Payload: &models.PreventionRespV1{
			Errors: apiErrors,
			Resources: []*models.PreventionPolicyV1{
				{ID: utils.Addr("policy-id"), IoaRuleGroups: groups},
			},
		},
	}
}

func errorDetails(diags diag.Diagnostics) string {
	var details []string
	for _, d := range diags.Errors() {
		details = append(details, d.Detail())
	}
	return strings.Join(details, "\n")
}

func TestUpdateRuleGroups(t *testing.T) {
	t.Parallel()

	apiErr := errors.New("[403] Forbidden")

	tests := []struct {
		name         string
		action       ruleGroupAction
		result       any
		err          error
		wantErrors   int
		wantInDetail []string
	}{
		{
			name:         "add returns api error",
			action:       addRuleGroup,
			err:          apiErr,
			wantErrors:   1,
			wantInDetail: []string{"Error adding rule groups (rg-id)", "[403] Forbidden"},
		},
		{
			name:         "remove returns api error",
			action:       removeRuleGroup,
			err:          apiErr,
			wantErrors:   1,
			wantInDetail: []string{"Error removing rule groups (rg-id)", "[403] Forbidden"},
		},
		{
			name:       "add succeeds",
			action:     addRuleGroup,
			result:     ruleGroupActionOK([]string{"rg-id"}),
			wantErrors: 0,
		},
		{
			name:       "remove succeeds",
			action:     removeRuleGroup,
			result:     ruleGroupActionOK(nil),
			wantErrors: 0,
		},
		{
			name:   "payload errors on success are reported",
			action: addRuleGroup,
			result: ruleGroupActionOK(
				[]string{"rg-id"},
				&models.MsaAPIError{ID: "rg-id", Code: utils.Addr(int32(400)), Message: utils.Addr("bad rule group")},
			),
			wantErrors:   1,
			wantInDetail: []string{"bad rule group"},
		},
		{
			name:         "rule group missing after add",
			action:       addRuleGroup,
			result:       ruleGroupActionOK(nil),
			wantErrors:   1,
			wantInDetail: []string{"Adding failed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := newStubClient(tt.result, tt.err)

			var diags diag.Diagnostics
			require.NotPanics(t, func() {
				diags = updateRuleGroups(context.Background(), c, tt.action, []string{"rg-id"}, "policy-id")
			})

			assert.Equal(t, tt.wantErrors, diags.ErrorsCount(), errorDetails(diags))
			for _, want := range tt.wantInDetail {
				assert.Contains(t, errorDetails(diags), want)
			}
		})
	}
}

func TestUpdatePreventionPolicyEmptyResources(t *testing.T) {
	t.Parallel()

	c := newStubClient(&prevention_policies.UpdatePreventionPoliciesOK{
		Payload: &models.PreventionRespV1{Resources: []*models.PreventionPolicyV1{}},
	}, nil)

	var (
		policy *models.PreventionPolicyV1
		diags  diag.Diagnostics
	)
	require.NotPanics(t, func() {
		policy, diags = updatePreventionPolicy(
			context.Background(),
			c,
			nil,
			"policy-id",
			updatePreventionPolicyOptions{},
		)
	})

	assert.Nil(t, policy)
	assert.True(t, diags.HasError())
	assert.Contains(t, errorDetails(diags), "No policy found with id: policy-id")
}
