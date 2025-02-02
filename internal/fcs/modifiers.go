package fcs

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type dspmRoleArnModifier struct {
	planmodifier.String
}

func (m dspmRoleArnModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Do nothing if there is no state value.
	if req.StateValue.IsNull() {
		return
	}

	// Do nothing if there is a known planned value.
	if !req.PlanValue.IsUnknown() {
		return
	}

	// Do nothing if there is an unknown configuration value, otherwise interpolation gets messed up.
	if req.ConfigValue.IsUnknown() {
		return
	}

	// Get the plan to check DSPM configuration
	var plan cloudAWSAccountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the state to compare
	var state cloudAWSAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If DSPM role_name has changed, mark role_arn as unknown
	if plan.DSPM != nil && state.DSPM != nil {
		if !plan.DSPM.RoleName.Equal(state.DSPM.RoleName) {
			resp.PlanValue = types.StringUnknown()
			return
		}
	}
	resp.PlanValue = req.StateValue
}
func (m dspmRoleArnModifier) Description(ctx context.Context) string {
	return "Marks the DSPM role ARN as unknown when the DSPM role name changes"
}

func (m dspmRoleArnModifier) MarkdownDescription(ctx context.Context) string {
	return "Marks the DSPM role ARN as unknown when the DSPM role name changes"
}
