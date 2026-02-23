package fcs

import (
	"context"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	roleTypeDSPM                  = "dspm"
	roleTypeVulnerabilityScanning = "vulnerability_scanning"
)

type roleArnStateModifier struct {
	planmodifier.String
	roleType string
}

func (m roleArnStateModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Do nothing if there is no state value.
	if req.StateValue.IsNull() {
		return
	}

	// Do nothing if there is an unknown configuration value, otherwise interpolation gets messed up.
	if req.ConfigValue.IsUnknown() {
		return
	}

	// Get the plan to check role configuration
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

	// Check if role_name has changed based on roleType
	switch m.roleType {
	case roleTypeDSPM:
		if shouldInvalidateDSPMRoleField(plan, state) {
			resp.PlanValue = types.StringUnknown()
			return
		}

	case roleTypeVulnerabilityScanning:
		if shouldInvalidateVulnerabilityScanningRoleField(plan, state) {
			resp.PlanValue = types.StringUnknown()
			return
		}

	}
	resp.PlanValue = req.StateValue
}

func (m roleArnStateModifier) Description(ctx context.Context) string {
	return "Marks the role ARN as unknown when the role name changes"
}

func (m roleArnStateModifier) MarkdownDescription(ctx context.Context) string {
	return "Marks the role ARN as unknown when the role name changes"
}

func dspmARNStateModifier() roleArnStateModifier {
	return roleArnStateModifier{roleType: roleTypeDSPM}
}

func vulnScanningArnStateModifier() roleArnStateModifier {
	return roleArnStateModifier{roleType: roleTypeVulnerabilityScanning}
}

type agentlessScanningRoleNameModifier struct {
	planmodifier.String
}

func (m agentlessScanningRoleNameModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Do nothing if there is no state value.
	if req.StateValue.IsNull() {
		return
	}

	// Do nothing if there is an unknown configuration value, otherwise interpolation gets messed up.
	if req.ConfigValue.IsUnknown() {
		return
	}

	// Get the plan to check role configuration
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

	if shouldInvalidateAgentlessScanningRoleField(plan, state) {
		resp.PlanValue = types.StringUnknown()
		return
	}

	resp.PlanValue = req.StateValue
}

func (m agentlessScanningRoleNameModifier) Description(ctx context.Context) string {
	return "Marks the role Name as unknown when either DSPM/Vulnerability scanning role name changes"
}

func (m agentlessScanningRoleNameModifier) MarkdownDescription(ctx context.Context) string {
	return "Marks the role Name as unknown when either DSPM/Vulnerability scanning role name changes"
}

func agentlessScanningRoleNameStateModifier() agentlessScanningRoleNameModifier {
	return agentlessScanningRoleNameModifier{}
}

func shouldInvalidateDSPMRoleField(plan, state cloudAWSAccountModel) bool {
	shouldInvalidate := plan.DSPM != nil && state.DSPM != nil && !plan.DSPM.RoleName.Equal(state.DSPM.RoleName)
	return shouldInvalidate
}

func shouldInvalidateVulnerabilityScanningRoleField(plan, state cloudAWSAccountModel) bool {
	shouldInvalidate := plan.VulnerabilityScanning != nil && state.VulnerabilityScanning != nil &&
		!plan.VulnerabilityScanning.RoleName.Equal(state.VulnerabilityScanning.RoleName)
	return shouldInvalidate
}

func shouldInvalidateAgentlessScanningRoleField(plan, state cloudAWSAccountModel) bool {
	shouldInvalidate := shouldInvalidateDSPMRoleField(plan, state) || shouldInvalidateVulnerabilityScanningRoleField(plan, state)
	return shouldInvalidate
}

// cloudtrailBucketNameModifier preserves the prior state value for cloudtrail_bucket_name
// unless the cloudtrail_region has changed, in which case it marks the value as unknown
// so Terraform re-reads it from the backend.
type cloudtrailBucketNameModifier struct {
	planmodifier.String
}

func (m cloudtrailBucketNameModifier) Description(_ context.Context) string {
	return "Uses prior state value unless cloudtrail_region changes, then marks as unknown for re-read"
}

func (m cloudtrailBucketNameModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m cloudtrailBucketNameModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Do nothing on create (no state value yet).
	if req.StateValue.IsNull() {
		return
	}

	// Compare cloudtrail_region between config and state to detect changes.
	// We use config (not plan) because plan modifiers like CloudtrailRegionDefault
	// may not have run yet, and the plan value could still be null.
	var configRegion, stateRegion types.String

	// Get the config's cloudtrail_region. If realtime_visibility is not in the
	// config, this will error — in which case we check whether the state had a
	// non-default region that would change when defaults are applied.
	configDiag := req.Config.GetAttribute(ctx, path.Root("realtime_visibility").AtName("cloudtrail_region"), &configRegion)
	stateDiag := req.State.GetAttribute(ctx, path.Root("realtime_visibility").AtName("cloudtrail_region"), &stateRegion)

	if configDiag.HasError() || stateDiag.HasError() {
		// Can't resolve one side — preserve state value.
		resp.PlanValue = req.StateValue
		return
	}

	// If both are null/unknown, no change.
	if (configRegion.IsNull() || configRegion.IsUnknown()) && (stateRegion.IsNull() || stateRegion.IsUnknown()) {
		resp.PlanValue = req.StateValue
		return
	}

	// If config region is null/unknown (omitted), the CloudtrailRegionDefault
	// modifier will set a default (us-east-1 for commercial). Check if the
	// state region differs from the default.
	if configRegion.IsNull() || configRegion.IsUnknown() {
		// When config omits the region, the default is us-east-1 (or us-gov-west-1
		// for gov). If state has a different region, the bucket name will change.
		var accountType types.String
		_ = req.State.GetAttribute(ctx, path.Root("account_type"), &accountType)
		defaultRegion := "us-east-1"
		if accountType.ValueString() == "gov" {
			defaultRegion = "us-gov-west-1"
		}
		if !stateRegion.IsNull() && !stateRegion.IsUnknown() && stateRegion.ValueString() != defaultRegion {
			resp.PlanValue = types.StringUnknown()
			return
		}
		resp.PlanValue = req.StateValue
		return
	}

	// If state region is null/unknown but config has a value, preserve state.
	if stateRegion.IsNull() || stateRegion.IsUnknown() {
		resp.PlanValue = req.StateValue
		return
	}

	// Both are known — compare directly.
	if configRegion.ValueString() != stateRegion.ValueString() {
		resp.PlanValue = types.StringUnknown()
		return
	}

	// No change — preserve the state value.
	resp.PlanValue = req.StateValue
}

func cloudtrailBucketNameStateModifier() cloudtrailBucketNameModifier {
	return cloudtrailBucketNameModifier{}
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
