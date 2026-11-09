package fcs

import (
	"context"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type agentlessRoleField int

const (
	dspmRoleField agentlessRoleField = iota
	vulnerabilityScanningRoleField
	agentlessScanningField
)

var (
	_ planmodifier.String = roleStateModifier{}
	_ planmodifier.Bool   = roleStateModifier{}
)

// roleStateModifier keeps the state value of an agentless scanning (DSPM/Vulnerability scanning) role attribute,
// and marks it unknown when the apply can change it. A configured value is left as planned.
type roleStateModifier struct {
	field agentlessRoleField
}

func (m roleStateModifier) mayChange(ctx context.Context, config tfsdk.Config, plan tfsdk.Plan, state tfsdk.State) (bool, diag.Diagnostics) {
	changes, diags := getAgentlessRoleChanges(ctx, config, plan, state)
	switch m.field {
	case dspmRoleField:
		return changes.DSPM, diags
	case vulnerabilityScanningRoleField:
		return changes.VulnerabilityScanning, diags
	default:
		return changes.AgentlessScanning, diags
	}
}

func (m roleStateModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Do nothing if there is no state value, or if the value is configured.
	if req.StateValue.IsNull() || !req.ConfigValue.IsNull() {
		return
	}

	mayChange, diags := m.mayChange(ctx, req.Config, req.Plan, req.State)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if mayChange {
		resp.PlanValue = types.StringUnknown()
		return
	}
	resp.PlanValue = req.StateValue
}

func (m roleStateModifier) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	// Do nothing if there is no state value, or if the value is configured.
	if req.StateValue.IsNull() || !req.ConfigValue.IsNull() {
		return
	}

	mayChange, diags := m.mayChange(ctx, req.Config, req.Plan, req.State)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if mayChange {
		resp.PlanValue = types.BoolUnknown()
		return
	}
	resp.PlanValue = req.StateValue
}

func (m roleStateModifier) Description(ctx context.Context) string {
	return "Uses the state value, or marks it as unknown when the DSPM/Vulnerability scanning roles can change"
}

func (m roleStateModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func dspmRoleStateModifier() roleStateModifier {
	return roleStateModifier{field: dspmRoleField}
}

func vulnScanningRoleStateModifier() roleStateModifier {
	return roleStateModifier{field: vulnerabilityScanningRoleField}
}

func agentlessScanningRoleStateModifier() roleStateModifier {
	return roleStateModifier{field: agentlessScanningField}
}

// agentlessRoleChanges tells which agentless scanning role values can change on apply.
type agentlessRoleChanges struct {
	DSPM                  bool
	VulnerabilityScanning bool
	// AgentlessScanning covers the values picked from both features: the agentless scanning role and scanner role
	// names, and the resource affixes marker.
	AgentlessScanning bool
}

func getAgentlessRoleChanges(ctx context.Context, config tfsdk.Config, plan tfsdk.Plan, state tfsdk.State) (agentlessRoleChanges, diag.Diagnostics) {
	var diags diag.Diagnostics

	var planModel, stateModel cloudAWSAccountModel
	diags.Append(plan.Get(ctx, &planModel)...)
	diags.Append(state.Get(ctx, &stateModel)...)

	// The role names are read by path: the plan holds unknown for the ones left unset.
	var dspmConfigRole, vulnConfigRole types.String
	diags.Append(config.GetAttribute(ctx, path.Root("dspm").AtName("role_name"), &dspmConfigRole)...)
	diags.Append(config.GetAttribute(ctx, path.Root("vulnerability_scanning").AtName("role_name"), &vulnConfigRole)...)
	if diags.HasError() {
		return agentlessRoleChanges{}, diags
	}

	return newAgentlessRoleChanges(planModel, stateModel, dspmConfigRole, vulnConfigRole), diags
}

// newAgentlessRoleChanges compares the plan to the state. CrowdStrike assigns the roles that aren't configured:
// it generates new names when DSPM and/or Vulnerability scanning is enabled on an account that had neither, and
// rebuilds them when the resource name prefix/suffix of a registration with generated names changes.
func newAgentlessRoleChanges(plan, state cloudAWSAccountModel, dspmConfigRole, vulnConfigRole types.String) agentlessRoleChanges {
	var planDSPM, stateDSPM dspmOptions
	if plan.DSPM != nil {
		planDSPM = *plan.DSPM
	}
	if state.DSPM != nil {
		stateDSPM = *state.DSPM
	}
	var planVuln, stateVuln vulnerabilityScanningOptions
	if plan.VulnerabilityScanning != nil {
		planVuln = *plan.VulnerabilityScanning
	}
	if state.VulnerabilityScanning != nil {
		stateVuln = *state.VulnerabilityScanning
	}

	enabledChanged := !planDSPM.Enabled.Equal(stateDSPM.Enabled) || !planVuln.Enabled.Equal(stateVuln.Enabled)
	// A null marker (state written before the attribute existed, not yet refreshed) may still be true.
	mayUseAffixes := state.AgentlessUseResourceAffixes.IsNull() || state.AgentlessUseResourceAffixes.ValueBool()
	affixesChanged := mayUseAffixes &&
		(!plan.ResourceNamePrefix.Equal(state.ResourceNamePrefix) || !plan.ResourceNameSuffix.Equal(state.ResourceNameSuffix))
	assignedRolesChanged := enabledChanged || affixesChanged

	changes := agentlessRoleChanges{
		DSPM:                  roleNameMayChange(dspmConfigRole, stateDSPM.RoleName, assignedRolesChanged),
		VulnerabilityScanning: roleNameMayChange(vulnConfigRole, stateVuln.RoleName, assignedRolesChanged),
	}
	changes.AgentlessScanning = changes.DSPM || changes.VulnerabilityScanning || assignedRolesChanged
	return changes
}

// roleNameMayChange reports whether a role name can differ from its state value after apply.
func roleNameMayChange(configRole, stateRole types.String, assignedRolesChanged bool) bool {
	if configRole.IsUnknown() {
		return true
	}
	if configRole.IsNull() {
		return assignedRolesChanged
	}
	return configRole.ValueString() != stateRole.ValueString()
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
