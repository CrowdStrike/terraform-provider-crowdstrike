package correlationrules

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/correlation_rules"
	"github.com/crowdstrike/gofalcon/falcon/models"
	fwtypes "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/types"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateSplitsStatusAndScheduleChanges checks the PATCH requests Update
// sends. The API rejects a PATCH that changes a rule's status and also carries
// an operation (schedule, start_on or stop_on), so Update has to send those
// changes one at a time and let the rule settle in between.
func TestUpdateSplitsStatusAndScheduleChanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		state     ruleAttrs
		plan      ruleAttrs
		wantCalls []string
	}{
		{
			name:  "reactivate and change interval",
			state: ruleAttrs{name: "rule", status: "inactive", interval: "1h0m"},
			plan:  ruleAttrs{name: "rule-updated", status: "active", interval: "2h0m"},
			wantCalls: []string{
				`PATCH {"id":"rule-1","name":"rule-updated","operation":{"schedule":{"definition":"@every 2h0m"}}}`,
				"GET",
				`PATCH {"id":"rule-1","status":"active"}`,
				"GET",
			},
		},
		{
			name:  "deactivate and change interval",
			state: ruleAttrs{name: "rule", status: "active", interval: "2h0m"},
			plan:  ruleAttrs{name: "rule-updated", status: "inactive", interval: "1h0m"},
			wantCalls: []string{
				`PATCH {"id":"rule-1","name":"rule-updated","status":"inactive"}`,
				"GET",
				`PATCH {"id":"rule-1","operation":{"schedule":{"definition":"@every 1h0m"}}}`,
				"GET",
			},
		},
		{
			name:  "reactivate only",
			state: ruleAttrs{name: "rule", status: "inactive", interval: "1h0m"},
			plan:  ruleAttrs{name: "rule", status: "active", interval: "1h0m"},
			wantCalls: []string{
				`PATCH {"id":"rule-1","status":"active"}`,
				"GET",
			},
		},
		{
			name:  "change interval only",
			state: ruleAttrs{name: "rule", status: "inactive", interval: "1h0m"},
			plan:  ruleAttrs{name: "rule", status: "inactive", interval: "2h0m"},
			wantCalls: []string{
				`PATCH {"id":"rule-1","operation":{"schedule":{"definition":"@every 2h0m"}}}`,
				"GET",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			api := &fakeRulesAPI{status: tt.state.status}
			r := &correlationRuleResource{
				client: &client.CrowdStrikeAPISpecification{
					CorrelationRules: correlation_rules.New(api, strfmt.Default),
				},
			}

			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			require.False(t, schemaResp.Diagnostics.HasError(), schemaResp.Diagnostics)

			req := resource.UpdateRequest{
				Plan:  tfsdk.Plan{Schema: schemaResp.Schema},
				State: tfsdk.State{Schema: schemaResp.Schema},
			}
			diags := req.Plan.Set(ctx, testRuleModel(t, tt.plan))
			require.False(t, diags.HasError(), diags)
			diags = req.State.Set(ctx, testRuleModel(t, tt.state))
			require.False(t, diags.HasError(), diags)

			resp := resource.UpdateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
			r.Update(ctx, req, &resp)

			require.False(t, resp.Diagnostics.HasError(), resp.Diagnostics)
			assert.Equal(t, tt.wantCalls, api.calls)
		})
	}
}

// ruleAttrs holds the rule attributes the Update tests change.
type ruleAttrs struct {
	name     string
	status   string
	interval string
}

// testRuleModel builds a rule model from attrs. Attributes the tests do not
// change are null, so Update leaves them out of every PATCH.
func testRuleModel(t *testing.T, attrs ruleAttrs) CorrelationRuleResourceModel {
	t.Helper()

	schedule, diags := types.ObjectValueFrom(t.Context(), ScheduleModel{}.AttributeTypes(), ScheduleModel{
		Interval: timetypes.NewGoDurationValueFromStringMust(attrs.interval),
		StartOn:  fwtypes.NewRFC3339Null(),
		StopOn:   fwtypes.NewRFC3339Null(),
	})
	require.False(t, diags.HasError(), diags)

	return CorrelationRuleResourceModel{
		ID:            types.StringValue("rule-1"),
		CustomerID:    types.StringNull(),
		Name:          types.StringValue(attrs.name),
		Description:   types.StringNull(),
		Severity:      types.StringNull(),
		Status:        types.StringValue(attrs.status),
		Comment:       types.StringNull(),
		Search:        types.ObjectNull(SearchModel{}.AttributeTypes()),
		Schedule:      schedule,
		MitreAttack:   types.ListNull(types.ObjectType{AttrTypes: MitreAttackModel{}.AttributeTypes()}),
		Notifications: types.SetNull(types.ObjectType{AttrTypes: NotificationModel{}.AttributeTypes()}),
	}
}

// fakeRulesAPI stands in for the correlation rules API. It records every call,
// with the non-null fields of each PATCH body, and like the real API it rejects
// a PATCH that changes the rule's status and also carries an operation.
type fakeRulesAPI struct {
	status string
	calls  []string
}

func (f *fakeRulesAPI) Submit(op *runtime.ClientOperation) (any, error) {
	switch op.ID {
	case "entities.rules.get.v1":
		f.calls = append(f.calls, "GET")
		return &correlation_rules.EntitiesRulesGetV1OK{Payload: f.rules()}, nil

	case "entities.rules.patch.v1":
		patch, err := patchBody(op)
		if err != nil {
			return nil, err
		}
		sent, err := json.Marshal(patch)
		if err != nil {
			return nil, err
		}
		f.calls = append(f.calls, "PATCH "+string(sent))

		status, hasStatus := patch["status"].(string)
		if _, hasOperation := patch["operation"]; hasStatus && hasOperation {
			return nil, &correlation_rules.EntitiesRulesPatchV1BadRequest{
				Payload: &models.CorrelationrulesapiGetEntitiesRulesResponseV1{
					Errors: []*models.MsaAPIError{{
						Code:    utils.Addr(int32(400)),
						Message: utils.Addr("status and operation changes should be performed one at a time"),
					}},
				},
			}
		}
		if hasStatus {
			f.status = status
		}
		return &correlation_rules.EntitiesRulesPatchV1OK{Payload: f.rules()}, nil
	}

	return nil, fmt.Errorf("unexpected operation %q", op.ID)
}

func (f *fakeRulesAPI) rules() *models.CorrelationrulesapiGetEntitiesRulesResponseV1 {
	return &models.CorrelationrulesapiGetEntitiesRulesResponseV1{
		Resources: []*models.CorrelationrulesapiRuleV1{
			{ID: utils.Addr("rule-1"), Status: utils.Addr(f.status)},
		},
	}
}

// patchBody returns the single rule in a PATCH body as it goes on the wire,
// without the fields that are null.
func patchBody(op *runtime.ClientOperation) (map[string]any, error) {
	var req runtime.TestClientRequest
	if err := op.Params.WriteToRequest(&req, strfmt.Default); err != nil {
		return nil, err
	}
	body, err := json.Marshal(req.GetBodyParam())
	if err != nil {
		return nil, err
	}

	var rules []map[string]any
	if err := json.Unmarshal(body, &rules); err != nil {
		return nil, err
	}
	if len(rules) != 1 {
		return nil, fmt.Errorf("expected one rule in the PATCH body, got %d", len(rules))
	}

	for key, value := range rules[0] {
		if value == nil {
			delete(rules[0], key)
		}
	}
	return rules[0], nil
}
