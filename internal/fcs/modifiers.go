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

	// Check if the associated feature is disabled - if so, these fields should be null and stable
	switch m.roleType {
	case roleTypeDSPM:
		// DSPM role fields should be null only if BOTH DSPM and vulnerability scanning are disabled
		// This is because vulnerability scanning roles can be shared with DSPM
		dspmEnabled := plan.DSPM != nil && plan.DSPM.Enabled.ValueBool()
		vulnEnabled := plan.VulnerabilityScanning != nil && plan.VulnerabilityScanning.Enabled.ValueBool()
		if !dspmEnabled && !vulnEnabled {
			// Both features disabled, role fields should be null and not unknown
			resp.PlanValue = types.StringNull()
			return
		}
	case roleTypeVulnerabilityScanning:
		// Vulnerability scanning role fields should be null only if BOTH DSPM and vulnerability scanning are disabled
		// This is because DSPM roles can be shared with vulnerability scanning
		dspmEnabled := plan.DSPM != nil && plan.DSPM.Enabled.ValueBool()
		vulnEnabled := plan.VulnerabilityScanning != nil && plan.VulnerabilityScanning.Enabled.ValueBool()
		if !dspmEnabled && !vulnEnabled {
			// Both features disabled, role fields should be null and not unknown
			resp.PlanValue = types.StringNull()
			return
		}
	}

	// If there is no state value, let the resource compute it
	if req.StateValue.IsNull() {
		return
	}

	// Get the state to compare for changes
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

	// Use state value if no changes
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

	// Check if both DSPM and vulnerability scanning are disabled - if so, this field should be null
	dspmEnabled := plan.DSPM != nil && plan.DSPM.Enabled.ValueBool()
	vulnEnabled := plan.VulnerabilityScanning != nil && plan.VulnerabilityScanning.Enabled.ValueBool()

	if !dspmEnabled && !vulnEnabled {
		// Neither feature is enabled, agentless scanning role should be null
		resp.PlanValue = types.StringNull()
		return
	}

	// If there is no state value, let the resource compute it
	if req.StateValue.IsNull() {
		return
	}

	// Get the state to compare for changes
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
