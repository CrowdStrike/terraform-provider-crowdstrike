package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &sensorUpdatePolicyResource{}
	_ resource.ResourceWithConfigure   = &sensorUpdatePolicyResource{}
	_ resource.ResourceWithImportState = &sensorUpdatePolicyResource{}
)

type hostGroupAction int

const (
	removeHostGroup hostGroupAction = iota
	addHostGroup
)

func (h hostGroupAction) String() string {
	return [...]string{"remove-host-group", "add-host-group"}[h]
}

// NewSensorUpdatePolicyResource is a helper function to simplify the provider implementation.
func NewSensorUpdatePolicyResource() resource.Resource {
	return &sensorUpdatePolicyResource{}
}

// sensorUpdatePolicyResource is the resource implementation.
type sensorUpdatePolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

// sensorUpdatePolicyResourceModel maps the resource schema data.
type sensorUpdatePolicyResourceModel struct {
	ID                  types.String `tfsdk:"id"`
	Enabled             types.Bool   `tfsdk:"enabled"`
	Name                types.String `tfsdk:"name"`
	Build               types.String `tfsdk:"build"`
	Description         types.String `tfsdk:"description"`
	PlatformName        types.String `tfsdk:"platform_name"`
	UninstallProtection types.Bool   `tfsdk:"uninstall_protection"`
	LastUpdated         types.String `tfsdk:"last_updated"`
	HostGroups          types.List   `tfsdk:"host_groups"`
}

// Configure adds the provider configured client to the resource.
func (r *sensorUpdatePolicyResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.CrowdStrikeAPISpecification)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf(
				"Expected *client.CrowdStrikeAPISpecification, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)

		return
	}

	r.client = client
}

// Metadata returns the resource type name.
func (r *sensorUpdatePolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_sensor_update_policy"
}

// Schema defines the schema for the resource.
func (r *sensorUpdatePolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed: true,
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Sensor Update Policy name",
			},
			"build": schema.StringAttribute{
				Required:    true,
				Description: "The Sensor build to target",
			},
			// todo: make this case insensitive
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "Sensor Update Policy platform. (Windows, Mac, Linux)",
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Linux", "Mac"),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Enable the Sensor Update Policy",
				Default:     booldefault.StaticBool(true),
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Sensor Update Policy description",
			},
			"uninstall_protection": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Enable uninstall protection",
				Default:     booldefault.StaticBool(false),
			},
			"host_groups": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host Group ids to attach to the policy",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *sensorUpdatePolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {

	var plan sensorUpdatePolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyParams := sensor_update_policies.CreateSensorUpdatePoliciesV2Params{
		Context: ctx,
		Body: &models.SensorUpdateCreatePoliciesReqV2{
			Resources: []*models.SensorUpdateCreatePolicyReqV2{
				{
					Name:         plan.Name.ValueStringPointer(),
					PlatformName: plan.PlatformName.ValueStringPointer(),
					Description:  plan.Description.ValueString(),
					Settings: &models.SensorUpdateSettingsReqV2{
						Build: plan.Build.ValueString(),
					},
				},
			},
		},
	}

	var uninstallProtection string
	if plan.UninstallProtection.ValueBool() {
		uninstallProtection = "ENABLED"
	} else {
		uninstallProtection = "DISABLED"
	}
	policyParams.Body.Resources[0].Settings.UninstallProtection = uninstallProtection

	policy, err := r.client.SensorUpdatePolicies.CreateSensorUpdatePoliciesV2(&policyParams)

	// todo: if we should handle scope and timeout errors instead of giving a vague error
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating sensor update policy",
			"Could not create sensor update policy, unexpected error: "+err.Error(),
		)
		return
	}

	policyResource := policy.Payload.Resources[0]

	plan.ID = types.StringValue(*policyResource.ID)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// by default a policy is disabled, so there is no reason to call this unless enabled is true
	if plan.Enabled.ValueBool() {
		actionResp, err := r.updatePolicyEnabledState(ctx, plan.ID.ValueString(), true)

		// todo: if we should handle scope and timeout errors instead of giving a vague error
		if err != nil {
			resp.Diagnostics.AddError(
				"Error enabling sensor update policy",
				"Could not enable sensor update policy, unexpected error: "+err.Error(),
			)
			return
		}

		plan.Enabled = types.BoolValue(*actionResp.Payload.Resources[0].Enabled)
	}

	if len(plan.HostGroups.Elements()) != 0 {
		var hostGroupIDs []string
		resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &hostGroupIDs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		err = r.updateHostGroups(ctx, addHostGroup, hostGroupIDs, plan.ID.ValueString())

		if err != nil {
			resp.Diagnostics.AddError(
				"Error assinging host group to policy",
				"Could not assign host group to policy, unexpected error: "+err.Error(),
			)
			return
		}
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *sensorUpdatePolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state sensorUpdatePolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.client.SensorUpdatePolicies.GetSensorUpdatePoliciesV2(
		&sensor_update_policies.GetSensorUpdatePoliciesV2Params{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading CrowdStrike sensor update policy",
			"Could not read CrowdStrike sensor update policy: "+state.ID.ValueString()+": "+err.Error(),
		)
		return
	}

	policyResource := policy.Payload.Resources[0]

	state.ID = types.StringValue(*policyResource.ID)
	state.Name = types.StringValue(*policyResource.Name)
	state.Description = types.StringValue(*policyResource.Description)
	state.Build = types.StringValue(*policyResource.Settings.Build)
	state.PlatformName = types.StringValue(*policyResource.PlatformName)
	state.Enabled = types.BoolValue(*policyResource.Enabled)

	if *policyResource.Settings.UninstallProtection == "ENABLED" {
		state.UninstallProtection = types.BoolValue(true)
	} else {
		state.UninstallProtection = types.BoolValue(false)
	}

	var hostGroups []string
	for _, hostGroup := range policyResource.Groups {
		hostGroups = append(hostGroups, *hostGroup.ID)
	}

	hostGroupIDs, diags := types.ListValueFrom(ctx, types.StringType, hostGroups)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.HostGroups = hostGroupIDs

	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *sensorUpdatePolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	// Retrieve values from plan
	var plan sensorUpdatePolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Retrieve values from state
	var state sensorUpdatePolicyResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	hostGroupsToAdd, hostGroupsToRemove, diags := r.getHostGroupsToModify(ctx, plan, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(hostGroupsToAdd) != 0 {
		err := r.updateHostGroups(ctx, addHostGroup, hostGroupsToAdd, plan.ID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating CrowdStrike sensor update policy",
				fmt.Sprintf(
					"Could not add host groups: (%s) to policy with id: %s \n\n %s",
					strings.Join(hostGroupsToAdd, ", "),
					plan.ID.ValueString(),
					err.Error(),
				),
			)
			return
		}
	}

	if len(hostGroupsToRemove) != 0 {
		err := r.updateHostGroups(ctx, removeHostGroup, hostGroupsToRemove, plan.ID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating CrowdStrike sensor update policy",
				fmt.Sprintf(
					"Could not remove host groups: (%s) to policy with id: %s \n\n %s",
					strings.Join(hostGroupsToAdd, ", "),
					plan.ID.ValueString(),
					err.Error(),
				),
			)
			return
		}
	}

	policyParams := sensor_update_policies.UpdateSensorUpdatePoliciesV2Params{
		Context: ctx,
		Body: &models.SensorUpdateUpdatePoliciesReqV2{
			Resources: []*models.SensorUpdateUpdatePolicyReqV2{
				{
					Name:        plan.Name.ValueString(),
					ID:          plan.ID.ValueStringPointer(),
					Description: plan.Description.ValueString(),
					Settings: &models.SensorUpdateSettingsReqV2{
						Build: plan.Build.ValueString(),
					},
				},
			},
		},
	}

	if plan.UninstallProtection.ValueBool() {
		policyParams.Body.Resources[0].Settings.UninstallProtection = "ENABLED"
	} else {
		policyParams.Body.Resources[0].Settings.UninstallProtection = "DISABLED"
	}

	policy, err := r.client.SensorUpdatePolicies.UpdateSensorUpdatePoliciesV2(&policyParams)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating CrowdStrike sensor update policy",
			"Could not update sensor update policy with ID: "+plan.ID.ValueString()+": "+err.Error(),
		)
		return
	}

	policyResource := policy.Payload.Resources[0]

	plan.ID = types.StringValue(*policyResource.ID)
	plan.Name = types.StringValue(*policyResource.Name)
	plan.Description = types.StringValue(*policyResource.Description)
	plan.PlatformName = types.StringValue(*policyResource.PlatformName)
	plan.Build = types.StringValue(*policyResource.Settings.Build)
	if *policyResource.Settings.UninstallProtection == "ENABLED" {
		plan.UninstallProtection = types.BoolValue(true)
	} else {
		plan.UninstallProtection = types.BoolValue(false)
	}
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	actionResp, err := r.updatePolicyEnabledState(
		ctx,
		plan.ID.ValueString(),
		plan.Enabled.ValueBool(),
	)

	// todo: if we should handle scope and timeout errors instead of giving a vague error
	if err != nil {
		resp.Diagnostics.AddError(
			"Error enabling sensor update policy",
			"Could not enable sensor update policy, unexpected error: "+err.Error(),
		)
		return
	}

	plan.Enabled = types.BoolValue(*actionResp.Payload.Resources[0].Enabled)

	var hostGroups []string
	for _, hostGroup := range policyResource.Groups {
		hostGroups = append(hostGroups, *hostGroup.ID)
	}

	hostGroupIDs, diags := types.ListValueFrom(ctx, types.StringType, hostGroups)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.HostGroups = hostGroupIDs

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *sensorUpdatePolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state sensorUpdatePolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// need to make sure the policy is disabled before delete
	_, err := r.updatePolicyEnabledState(
		ctx,
		state.ID.ValueString(),
		false,
	)

	// todo: if we should handle scope and timeout errors instead of giving a vague error
	if err != nil {
		resp.Diagnostics.AddError(
			"Error disabling sensor update policy for delete",
			"Could not disable sensor update policy, unexpected error: "+err.Error(),
		)
		return
	}

	_, err = r.client.SensorUpdatePolicies.DeleteSensorUpdatePolicies(
		&sensor_update_policies.DeleteSensorUpdatePoliciesParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting CrowdStrike sensor update policy",
			"Could not delete sensor update policy, unexpected error: "+err.Error(),
		)
		return
	}
}

// ImportState implements the logic to support resource imports.
func (r *sensorUpdatePolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// updatePolicyEnabledState enables or disables a policy.
func (r *sensorUpdatePolicyResource) updatePolicyEnabledState(
	ctx context.Context,
	policyID string,
	enabled bool,
) (sensor_update_policies.PerformSensorUpdatePoliciesActionOK, error) {
	state := "disable"
	if enabled {
		state = "enable"
	}

	res, err := r.client.SensorUpdatePolicies.PerformSensorUpdatePoliciesAction(
		&sensor_update_policies.PerformSensorUpdatePoliciesActionParams{
			ActionName: state,
			Context:    ctx,
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{policyID},
			},
		},
	)

	return *res, err
}

// updateHostGroups will remove or add a slice of host groups
// to a slice of sensor update policies.
func (r *sensorUpdatePolicyResource) updateHostGroups(
	ctx context.Context,
	action hostGroupAction,
	hostGroupIDs []string,
	policyID string,
) error {
	var actionParams []*models.MsaspecActionParameter
	name := "group_id"

	for _, hostGroup := range hostGroupIDs {
		actionParam := &models.MsaspecActionParameter{
			Name:  &name,
			Value: &hostGroup,
		}

		actionParams = append(actionParams, actionParam)
	}

	_, err := r.client.SensorUpdatePolicies.PerformSensorUpdatePoliciesAction(
		&sensor_update_policies.PerformSensorUpdatePoliciesActionParams{
			Context:    ctx,
			ActionName: action.String(),
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: actionParams,
				Ids:              []string{policyID},
			},
		},
	)

	return err
}

// getHostGroupsToModify takes in the planned state and current state and returns
// a list of host group ids to remove and add.
func (r *sensorUpdatePolicyResource) getHostGroupsToModify(
	ctx context.Context,
	plan, state sensorUpdatePolicyResourceModel,
) (hostGroupsToAdd []string, hostGroupsToRemove []string, diags diag.Diagnostics) {
	var planHostGroupIDs, stateHostGroupIds []string
	planMap := make(map[string]bool)
	stateMap := make(map[string]bool)

	d := plan.HostGroups.ElementsAs(ctx, &planHostGroupIDs, false)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	d = state.HostGroups.ElementsAs(ctx, &stateHostGroupIds, false)
	diags.Append(d...)
	if diags.HasError() {
		return
	}

	for _, id := range planHostGroupIDs {
		planMap[id] = true
	}

	for _, id := range stateHostGroupIds {
		stateMap[id] = true
	}

	for _, id := range planHostGroupIDs {
		if !stateMap[id] {
			hostGroupsToAdd = append(hostGroupsToAdd, id)
		}
	}

	for _, id := range stateHostGroupIds {
		if !planMap[id] {
			hostGroupsToRemove = append(hostGroupsToRemove, id)
		}
	}

	return
}
