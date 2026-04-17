package firewall

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_management"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/swag"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &firewallPolicyResource{}
	_ resource.ResourceWithConfigure   = &firewallPolicyResource{}
	_ resource.ResourceWithImportState = &firewallPolicyResource{}
)

// NewFirewallPolicyResource is a helper function to simplify the provider implementation.
func NewFirewallPolicyResource() resource.Resource {
	return &firewallPolicyResource{}
}

// firewallPolicyResource is the resource implementation.
type firewallPolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

// firewallPolicyResourceModel maps the resource schema data.
type firewallPolicyResourceModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Description     types.String `tfsdk:"description"`
	PlatformName    types.String `tfsdk:"platform_name"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	DefaultInbound  types.String `tfsdk:"default_inbound"`
	DefaultOutbound types.String `tfsdk:"default_outbound"`
	Enforce         types.Bool   `tfsdk:"enforce"`
	TestMode        types.Bool   `tfsdk:"test_mode"`
	LocalLogging    types.Bool   `tfsdk:"local_logging"`
	HostGroups      types.Set    `tfsdk:"host_groups"`
	RuleGroupIDs    types.List   `tfsdk:"rule_group_ids"`
	LastUpdated     types.String `tfsdk:"last_updated"`
}

// platformNameToID converts platform name to platform ID for the API.
var platformNameToID = map[string]string{
	"Windows": "0",
	"Mac":     "1",
	"Linux":   "2",
}

// Configure adds the provider configured client to the resource.
func (r *firewallPolicyResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	r.client = providerConfig.Client
}

// Metadata returns the resource type name.
func (r *firewallPolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_firewall_policy"
}

// Schema defines the schema for the firewall policy resource.
func (r *firewallPolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Firewall Management",
			"This resource allows management of CrowdStrike Firewall policies. A firewall policy defines the firewall settings and rule groups that apply to hosts in assigned host groups.",
			apiScopesReadWrite,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Identifier for the firewall policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp of the last Terraform update of the resource.",
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the firewall policy.",
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Description of the firewall policy.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"platform_name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Platform for the firewall policy. One of: `Windows`, `Mac`, `Linux`. Changing this value will require replacing the resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Mac", "Linux"),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Enable the firewall policy.",
				Default:             booldefault.StaticBool(false),
			},
			"default_inbound": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Default action for inbound traffic. One of: `ALLOW`, `DENY`.",
				Default:             stringdefault.StaticString("DENY"),
				Validators: []validator.String{
					stringvalidator.OneOf("ALLOW", "DENY"),
				},
			},
			"default_outbound": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Default action for outbound traffic. One of: `ALLOW`, `DENY`.",
				Default:             stringdefault.StaticString("ALLOW"),
				Validators: []validator.String{
					stringvalidator.OneOf("ALLOW", "DENY"),
				},
			},
			"enforce": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether to enforce the firewall policy. When false, the policy is in monitoring mode.",
				Default:             booldefault.StaticBool(false),
			},
			"test_mode": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether the policy is in test mode.",
				Default:             booldefault.StaticBool(false),
			},
			"local_logging": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Enable local logging for the policy.",
				Default:             booldefault.StaticBool(false),
			},
			"host_groups": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Host group IDs to attach to the policy.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
				},
			},
			"rule_group_ids": schema.ListAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Firewall rule group IDs to attach to the policy. Order determines precedence (first has highest priority).",
			},
		},
	}
}

// wrapPolicy transforms API response values to their terraform model values.
func (m *firewallPolicyResourceModel) wrapPolicy(
	ctx context.Context,
	policy *models.FirewallPolicyV1,
) diag.Diagnostics {
	var diags diag.Diagnostics
	m.ID = flex.StringPointerToFramework(policy.ID)
	m.Name = flex.StringPointerToFramework(policy.Name)
	m.Description = flex.StringPointerToFramework(policy.Description)
	m.PlatformName = flex.StringPointerToFramework(policy.PlatformName)
	m.Enabled = types.BoolPointerValue(policy.Enabled)

	hostGroupSet, d := flex.FlattenHostGroupsToSet(ctx, policy.Groups)
	if d.HasError() {
		diags.Append(d...)
		return diags
	}
	m.HostGroups = hostGroupSet
	return diags
}

// wrapPolicyContainer transforms policy container API response values to terraform model values.
func (m *firewallPolicyResourceModel) wrapPolicyContainer(
	_ context.Context,
	container *models.FwmgrFirewallPolicyContainerV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.DefaultInbound = flex.StringPointerToFramework(container.DefaultInbound)
	m.DefaultOutbound = flex.StringPointerToFramework(container.DefaultOutbound)
	m.Enforce = types.BoolPointerValue(container.Enforce)
	m.TestMode = types.BoolPointerValue(container.TestMode)
	m.LocalLogging = types.BoolPointerValue(container.LocalLogging)

	// Convert rule group IDs to List - only set if there are rule groups
	// If empty, keep as null to avoid drift when user doesn't specify rule_group_ids
	if len(container.RuleGroupIds) > 0 {
		ruleGroupIDs := make([]attr.Value, 0, len(container.RuleGroupIds))
		for _, id := range container.RuleGroupIds {
			ruleGroupIDs = append(ruleGroupIDs, types.StringValue(id))
		}
		ruleGroupList, d := types.ListValue(types.StringType, ruleGroupIDs)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		m.RuleGroupIDs = ruleGroupList
	}

	return diags
}

// Create creates the resource and sets the initial Terraform state.
func (r *firewallPolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan firewallPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createParams := firewall_policies.CreateFirewallPoliciesParams{
		Context: ctx,
		Body: &models.FirewallCreateFirewallPoliciesReqV1{
			Resources: []*models.FirewallCreateFirewallPolicyReqV1{
				{
					Name:         plan.Name.ValueStringPointer(),
					Description:  plan.Description.ValueString(),
					PlatformName: plan.PlatformName.ValueStringPointer(),
				},
			},
		},
	}

	createRes, createErr := r.client.FirewallPolicies.CreateFirewallPolicies(&createParams)
	if createErr != nil {
		resp.Diagnostics.AddError(
			"Failed to create firewall policy",
			fmt.Sprintf("Failed to create firewall policy: %s", extractPolicyAPIError(createErr)),
		)
		return
	}

	if createRes == nil || createRes.Payload == nil || len(createRes.Payload.Resources) == 0 || createRes.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	policy := createRes.Payload.Resources[0]
	tflog.Info(ctx, "Successfully created firewall policy", map[string]interface{}{
		"policy_id": *policy.ID,
	})

	plan.ID = types.StringPointerValue(policy.ID)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Enabled.ValueBool() {
		updatedPolicy, enableDiag := r.setFirewallPolicyEnabled(ctx, plan.ID.ValueString(), "enable")
		if enableDiag != nil {
			resp.Diagnostics.Append(enableDiag)
			return
		}
		if updatedPolicy != nil {
			policy = updatedPolicy
		}
	}

	if len(plan.HostGroups.Elements()) > 0 {
		var hostGroupIDs []string
		resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &hostGroupIDs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		updatedPolicy, hostGroupDiag := r.syncHostGroups(ctx, plan.ID.ValueString(), hostGroupIDs, nil)
		if hostGroupDiag != nil {
			resp.Diagnostics.Append(hostGroupDiag)
			return
		}
		if updatedPolicy != nil {
			policy = updatedPolicy
		}
	}

	// Update policy container settings (rule groups, enforce, defaults, etc.)
	var ruleGroupIDs []string
	resp.Diagnostics.Append(plan.RuleGroupIDs.ElementsAs(ctx, &ruleGroupIDs, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	containerDiag := r.updatePolicyContainer(ctx, plan.ID.ValueString(), plan.PlatformName.ValueString(), ruleGroupIDs, &plan)
	if containerDiag != nil {
		resp.Diagnostics.Append(containerDiag)
		return
	}

	resp.Diagnostics.Append(plan.wrapPolicy(ctx, policy)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read reads the firewall policy from the API.
func (r *firewallPolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	tflog.Trace(ctx, "Starting firewall policy read")

	var state firewallPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, readDiag := r.getFirewallPolicy(ctx, state.ID.ValueString())
	if readDiag != nil {
		resp.Diagnostics.Append(readDiag)
		return
	}

	if policy == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(state.wrapPolicy(ctx, policy)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read container settings (rule groups, enforce, test_mode, etc.)
	container, containerDiag := r.getPolicyContainer(ctx, state.ID.ValueString())
	if containerDiag != nil {
		resp.Diagnostics.Append(containerDiag)
		return
	}

	if container != nil {
		resp.Diagnostics.Append(state.wrapPolicyContainer(ctx, container)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the firewall policy.
func (r *firewallPolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	tflog.Trace(ctx, "Starting firewall policy update")

	var plan firewallPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state firewallPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateParams := firewall_policies.UpdateFirewallPoliciesParams{
		Context: ctx,
		Body: &models.FirewallUpdateFirewallPoliciesReqV1{
			Resources: []*models.FirewallUpdateFirewallPolicyReqV1{
				{
					ID:          plan.ID.ValueStringPointer(),
					Name:        plan.Name.ValueString(),
					Description: plan.Description.ValueString(),
				},
			},
		},
	}

	tflog.Debug(ctx, "Calling CrowdStrike API to update firewall policy")
	updateRes, updateErr := r.client.FirewallPolicies.UpdateFirewallPolicies(&updateParams)
	if updateErr != nil {
		resp.Diagnostics.AddError(
			"Failed to update firewall policy",
			fmt.Sprintf("Failed to update firewall policy: %s", extractPolicyAPIError(updateErr)),
		)
		return
	}

	if updateRes == nil || updateRes.Payload == nil || len(updateRes.Payload.Resources) == 0 || updateRes.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	policy := updateRes.Payload.Resources[0]

	if plan.Enabled.ValueBool() != state.Enabled.ValueBool() {
		action := "disable"
		if plan.Enabled.ValueBool() {
			action = "enable"
		}
		updatedPolicy, enableDiag := r.setFirewallPolicyEnabled(ctx, plan.ID.ValueString(), action)
		if enableDiag != nil {
			resp.Diagnostics.Append(enableDiag)
			return
		}
		if updatedPolicy != nil {
			policy = updatedPolicy
		}
	}

	var planHostGroups, stateHostGroups []string
	resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &planHostGroups, false)...)
	resp.Diagnostics.Append(state.HostGroups.ElementsAs(ctx, &stateHostGroups, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.HostGroups.Equal(state.HostGroups) {
		updatedPolicy, hostGroupDiag := r.syncHostGroups(ctx, plan.ID.ValueString(), planHostGroups, stateHostGroups)
		if hostGroupDiag != nil {
			resp.Diagnostics.Append(hostGroupDiag)
			return
		}
		if updatedPolicy != nil {
			policy = updatedPolicy
		}
	}

	// Update policy container settings (rule groups, enforce, defaults, etc.)
	var planRuleGroups []string
	resp.Diagnostics.Append(plan.RuleGroupIDs.ElementsAs(ctx, &planRuleGroups, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	containerDiag := r.updatePolicyContainer(ctx, plan.ID.ValueString(), plan.PlatformName.ValueString(), planRuleGroups, &plan)
	if containerDiag != nil {
		resp.Diagnostics.Append(containerDiag)
		return
	}

	resp.Diagnostics.Append(plan.wrapPolicy(ctx, policy)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the firewall policy.
func (r *firewallPolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	tflog.Trace(ctx, "Starting firewall policy delete")

	var state firewallPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.Enabled.ValueBool() {
		_, disableDiag := r.setFirewallPolicyEnabled(ctx, state.ID.ValueString(), "disable")
		if disableDiag != nil {
			resp.Diagnostics.Append(disableDiag)
			return
		}
	}

	deleteParams := firewall_policies.DeleteFirewallPoliciesParams{
		Context: ctx,
		Ids:     []string{state.ID.ValueString()},
	}

	tflog.Debug(ctx, "Calling CrowdStrike API to delete firewall policy")
	_, deleteErr := r.client.FirewallPolicies.DeleteFirewallPolicies(&deleteParams)
	if deleteErr != nil {
		resp.Diagnostics.AddError(
			"Failed to delete firewall policy",
			fmt.Sprintf("Failed to delete firewall policy: %s", extractPolicyAPIError(deleteErr)),
		)
		return
	}

	tflog.Info(ctx, "Successfully deleted firewall policy", map[string]interface{}{
		"policy_id": state.ID.ValueString(),
	})
}

// ImportState imports an existing firewall policy.
func (r *firewallPolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// getFirewallPolicy retrieves a firewall policy by ID.
func (r *firewallPolicyResource) getFirewallPolicy(
	ctx context.Context,
	policyID string,
) (*models.FirewallPolicyV1, diag.Diagnostic) {
	getParams := firewall_policies.GetFirewallPoliciesParams{
		Context: ctx,
		Ids:     []string{policyID},
	}

	getRes, getErr := r.client.FirewallPolicies.GetFirewallPolicies(&getParams)
	if getErr != nil {
		return nil, diag.NewErrorDiagnostic(
			"Failed to get firewall policy",
			fmt.Sprintf("Failed to get firewall policy %s: %s", policyID, extractPolicyAPIError(getErr)),
		)
	}

	if getRes == nil || getRes.Payload == nil || len(getRes.Payload.Resources) == 0 {
		return nil, nil
	}

	return getRes.Payload.Resources[0], nil
}

// getPolicyContainer retrieves the policy container settings (rule groups, enforce, test_mode, etc.).
func (r *firewallPolicyResource) getPolicyContainer(
	ctx context.Context,
	policyID string,
) (*models.FwmgrFirewallPolicyContainerV1, diag.Diagnostic) {
	params := firewall_management.NewGetPolicyContainersParams().
		WithContext(ctx).
		WithIds([]string{policyID})

	res, err := r.client.FirewallManagement.GetPolicyContainers(params)
	if err != nil {
		return nil, diag.NewErrorDiagnostic(
			"Failed to get policy container",
			fmt.Sprintf("Failed to get policy container for %s: %s", policyID, err.Error()),
		)
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		return nil, nil
	}

	return res.Payload.Resources[0], nil
}

// setFirewallPolicyEnabled enables or disables a firewall policy.
func (r *firewallPolicyResource) setFirewallPolicyEnabled(
	ctx context.Context,
	policyID string,
	action string,
) (*models.FirewallPolicyV1, diag.Diagnostic) {
	actionParams := firewall_policies.PerformFirewallPoliciesActionParams{
		Context:    ctx,
		ActionName: action,
		Body: &models.MsaEntityActionRequestV2{
			Ids: []string{policyID},
		},
	}

	actionRes, actionErr := r.client.FirewallPolicies.PerformFirewallPoliciesAction(&actionParams)
	if actionErr != nil {
		return nil, diag.NewErrorDiagnostic(
			"Failed to set firewall policy enabled state",
			fmt.Sprintf("Failed to %s firewall policy %s: %s", action, policyID, extractPolicyAPIError(actionErr)),
		)
	}

	if actionRes == nil || actionRes.Payload == nil || len(actionRes.Payload.Resources) == 0 {
		return nil, nil
	}

	return actionRes.Payload.Resources[0], nil
}

// syncHostGroups synchronizes host group assignments for a policy.
func (r *firewallPolicyResource) syncHostGroups(
	ctx context.Context,
	policyID string,
	planHostGroups []string,
	stateHostGroups []string,
) (*models.FirewallPolicyV1, diag.Diagnostic) {
	toAdd := stringSliceDiff(planHostGroups, stateHostGroups)
	toRemove := stringSliceDiff(stateHostGroups, planHostGroups)

	var policy *models.FirewallPolicyV1

	for _, groupID := range toAdd {
		addParams := firewall_policies.PerformFirewallPoliciesActionParams{
			Context:    ctx,
			ActionName: "add-host-group",
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{policyID},
				ActionParameters: []*models.MsaspecActionParameter{
					{
						Name:  swag.String("group_id"),
						Value: swag.String(groupID),
					},
				},
			},
		}

		addRes, addErr := r.client.FirewallPolicies.PerformFirewallPoliciesAction(&addParams)
		if addErr != nil {
			return nil, diag.NewErrorDiagnostic(
				"Failed to add host group to firewall policy",
				fmt.Sprintf("Failed to add host group %s to policy %s: %s", groupID, policyID, extractPolicyAPIError(addErr)),
			)
		}
		if addRes != nil && addRes.Payload != nil && len(addRes.Payload.Resources) > 0 {
			policy = addRes.Payload.Resources[0]
		}
	}

	for _, groupID := range toRemove {
		removeParams := firewall_policies.PerformFirewallPoliciesActionParams{
			Context:    ctx,
			ActionName: "remove-host-group",
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{policyID},
				ActionParameters: []*models.MsaspecActionParameter{
					{
						Name:  swag.String("group_id"),
						Value: swag.String(groupID),
					},
				},
			},
		}

		removeRes, removeErr := r.client.FirewallPolicies.PerformFirewallPoliciesAction(&removeParams)
		if removeErr != nil {
			return nil, diag.NewErrorDiagnostic(
				"Failed to remove host group from firewall policy",
				fmt.Sprintf("Failed to remove host group %s from policy %s: %s", groupID, policyID, extractPolicyAPIError(removeErr)),
			)
		}
		if removeRes != nil && removeRes.Payload != nil && len(removeRes.Payload.Resources) > 0 {
			policy = removeRes.Payload.Resources[0]
		}
	}

	return policy, nil
}

// stringSliceDiff returns elements in a that are not in b.
func stringSliceDiff(a, b []string) []string {
	bMap := make(map[string]struct{}, len(b))
	for _, x := range b {
		bMap[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := bMap[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

// updatePolicyContainer updates the policy container settings via FirewallManagement API.
// This handles rule group IDs (with ordering), enforce, test_mode, local_logging, and default actions.
func (r *firewallPolicyResource) updatePolicyContainer(
	ctx context.Context,
	policyID string,
	platformName string,
	ruleGroupIDs []string,
	plan *firewallPolicyResourceModel,
) diag.Diagnostic {
	platformID := platformNameToID[platformName]

	containerParams := firewall_management.UpdatePolicyContainerParams{
		Context: ctx,
		Body: &models.FwmgrAPIPolicyContainerUpsertRequestV1{
			PolicyID:        swag.String(policyID),
			PlatformID:      swag.String(platformID),
			RuleGroupIds:    ruleGroupIDs,
			DefaultInbound:  swag.String(plan.DefaultInbound.ValueString()),
			DefaultOutbound: swag.String(plan.DefaultOutbound.ValueString()),
			Enforce:         swag.Bool(plan.Enforce.ValueBool()),
			TestMode:        swag.Bool(plan.TestMode.ValueBool()),
			LocalLogging:    swag.Bool(plan.LocalLogging.ValueBool()),
		},
	}

	tflog.Debug(ctx, "Calling CrowdStrike API to update policy container settings")
	_, _, containerErr := r.client.FirewallManagement.UpdatePolicyContainer(&containerParams)
	if containerErr != nil {
		return diag.NewErrorDiagnostic(
			"Failed to update policy container settings",
			fmt.Sprintf("Failed to update policy container for %s: %s", policyID, extractContainerAPIError(containerErr)),
		)
	}

	return nil
}
