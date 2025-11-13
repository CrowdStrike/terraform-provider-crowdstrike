package fcs

import (
	"context"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/path"
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

func DSPMArnStateModifier() dspmRoleArnModifier {
	return dspmRoleArnModifier{}
}

// cloudtrailRegionDefault is a plan modifier that sets the default cloudtrail_region based on account_type.
type cloudtrailRegionDefault struct{}

func (m cloudtrailRegionDefault) Description(_ context.Context) string {
	return "Sets default cloudtrail_region based on account_type: us-gov-west-1 for gov accounts, us-east-1 for commercial accounts"
}

func (m cloudtrailRegionDefault) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m cloudtrailRegionDefault) PlanModifyObject(ctx context.Context, req planmodifier.ObjectRequest, resp *planmodifier.ObjectResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}

	if req.ConfigValue.IsUnknown() {
		return
	}

	attrs := req.PlanValue.Attributes()
	cloudtrailRegion, ok := attrs["cloudtrail_region"].(types.String)
	if !ok {
		resp.Diagnostics.AddError(
			"Invalid realtime_visibility object structure",
			"The cloudtrail_region attribute is missing or has an unexpected type. This is a provider bug, please report it to the provider developers.",
		)
		return
	}

	if !utils.IsNull(cloudtrailRegion) {
		return
	}

	var accountType types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("account_type"), &accountType)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if accountType.IsUnknown() {
		return
	}

	region := "us-east-1"
	if accountType.ValueString() == "gov" {
		region = "us-gov-west-1"
	}

	attrs["cloudtrail_region"] = types.StringValue(region)

	updatedObject, diags := types.ObjectValue(req.PlanValue.AttributeTypes(ctx), attrs)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.PlanValue = updatedObject
}

func CloudtrailRegionDefault() planmodifier.Object {
	return cloudtrailRegionDefault{}
}
