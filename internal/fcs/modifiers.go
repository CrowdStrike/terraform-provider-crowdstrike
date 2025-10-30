package fcs

import (
	"context"

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

	// Do nothing if there is a known planned value.
	if !req.PlanValue.IsUnknown() {
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

func shouldInvalidateDSPMRoleField(plan cloudAWSAccountModel, state cloudAWSAccountModel) bool {
	shouldInvalidate := plan.DSPM != nil && state.DSPM != nil && !plan.DSPM.RoleName.Equal(state.DSPM.RoleName)
	return shouldInvalidate
}

func shouldInvalidateVulnerabilityScanningRoleField(plan cloudAWSAccountModel, state cloudAWSAccountModel) bool {
	shouldInvalidate := plan.VulnerabilityScanning != nil && state.VulnerabilityScanning != nil &&
		!plan.VulnerabilityScanning.RoleName.Equal(state.VulnerabilityScanning.RoleName)
	return shouldInvalidate
}

func shouldInvalidateAgentlessScanningRoleField(plan cloudAWSAccountModel, state cloudAWSAccountModel) bool {
	shouldInvalidate := shouldInvalidateDSPMRoleField(plan, state) || shouldInvalidateVulnerabilityScanningRoleField(plan, state)
	return shouldInvalidate
}
