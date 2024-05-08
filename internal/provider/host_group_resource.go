package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/device_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/host_group"
	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/response_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &hostGroupResource{}
	_ resource.ResourceWithConfigure   = &hostGroupResource{}
	_ resource.ResourceWithImportState = &hostGroupResource{}
)

// NewHostGroupResource is a helper function to simplify the provider implementation.
func NewHostGroupResource() resource.Resource {
	return &hostGroupResource{}
}

// hostGroupResource is the resource implementation.
type hostGroupResource struct {
	client *client.CrowdStrikeAPISpecification
}

// hostGroupResourceModel maps the resource schema data.
type hostGroupResourceModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	AssignmentRule types.String `tfsdk:"assignment_rule"`
	Description    types.String `tfsdk:"description"`
	GroupType      types.String `tfsdk:"type"`
	LastUpdated    types.String `tfsdk:"last_updated"`
}

// Configure adds the provider configured client to the resource.
func (r *hostGroupResource) Configure(
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
			"Unexpected Resource Configure Type",
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
func (r *hostGroupResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_host_group"
}

// Schema defines the schema for the resource.
func (r *hostGroupResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the host group.",

				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the host group.",
			},
			"assignment_rule": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The assignment rule for dynamic host groups.",
				Default:     nil,
			},
			"type": schema.StringAttribute{
				Required: true,
				// todo: make this case insensitive
				Description: "The host group type, case sensitive. (dynamic, static, staticByID)",
				Validators: []validator.String{
					stringvalidator.OneOf("dynamic", "static", "staticByID"),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the host group.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *hostGroupResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {

	var plan hostGroupResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	hostGroupParams := host_group.CreateHostGroupsParams{
		Context: ctx,
		Body: &models.HostGroupsCreateGroupsReqV1{
			Resources: []*models.HostGroupsCreateGroupReqV1{
				{
					Name:        plan.Name.ValueStringPointer(),
					GroupType:   plan.GroupType.ValueStringPointer(),
					Description: plan.Description.ValueString(),
				},
			},
		},
	}

	// todo: there may be a way to check this in the schema
	if plan.GroupType.ValueString() != "dynamic" && plan.AssignmentRule.ValueString() != "" {
		resp.Diagnostics.AddError(
			"Error creating host group",
			"Group type much be dynamic in order to use assignment_rule",
		)
		return
	}

	hostGroupParams.Body.Resources[0].AssignmentRule = plan.AssignmentRule.ValueString()

	hostGroup, err := r.client.HostGroup.CreateHostGroups(&hostGroupParams)

	// todo: if we should handle scope and timeout errors instead of giving a vague error
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating host group",
			"Could not create host group, unexpected error: "+err.Error(),
		)
		return
	}

	hostGroupResource := hostGroup.Payload.Resources[0]

	plan.ID = types.StringValue(*hostGroupResource.ID)
	plan.Name = types.StringValue(*hostGroupResource.Name)
	plan.AssignmentRule = types.StringValue(hostGroupResource.AssignmentRule)
	plan.Description = types.StringValue(*hostGroupResource.Description)
	plan.GroupType = types.StringValue(hostGroupResource.GroupType)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *hostGroupResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state hostGroupResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	hostGroup, err := r.client.HostGroup.GetHostGroups(
		&host_group.GetHostGroupsParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading CrowdStrike host group",
			"Could not read CrowdStrike host group: "+state.ID.ValueString()+": "+err.Error(),
		)
		return
	}

	hostGroupResource := hostGroup.Payload.Resources[0]

	state.ID = types.StringValue(*hostGroupResource.ID)
	state.Name = types.StringValue(*hostGroupResource.Name)
	state.Description = types.StringValue(*hostGroupResource.Description)
	state.AssignmentRule = types.StringValue(hostGroupResource.AssignmentRule)
	state.GroupType = types.StringValue(hostGroupResource.GroupType)

	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *hostGroupResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	// Retrieve values from plan
	var plan hostGroupResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	hostGroupParams := host_group.UpdateHostGroupsParams{
		Context: ctx,
		Body: &models.HostGroupsUpdateGroupsReqV1{
			Resources: []*models.HostGroupsUpdateGroupReqV1{
				{
					Name:        plan.Name.ValueString(),
					ID:          plan.ID.ValueStringPointer(),
					Description: plan.Description.ValueString(),
				},
			},
		},
	}

	// todo: there may be a way to check this in the schema
	if plan.GroupType.ValueString() != "dynamic" && plan.AssignmentRule.ValueString() != "" {
		resp.Diagnostics.AddError(
			"Error updating host group",
			"Group type much be dynamic in order to use assignment_rule",
		)
		return
	}

	hostGroupParams.Body.Resources[0].AssignmentRule = plan.AssignmentRule.ValueStringPointer()

	hostGroup, err := r.client.HostGroup.UpdateHostGroups(&hostGroupParams)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating CrowdStrike host group",
			"Could not update host group with ID: "+plan.ID.ValueString()+": "+err.Error(),
		)
		return
	}

	hostGroupResource := hostGroup.Payload.Resources[0]

	plan.ID = types.StringValue(*hostGroupResource.ID)
	plan.Name = types.StringValue(*hostGroupResource.Name)
	plan.Description = types.StringValue(*hostGroupResource.Description)
	plan.AssignmentRule = types.StringValue(hostGroupResource.AssignmentRule)
	plan.GroupType = types.StringValue(hostGroupResource.GroupType)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *hostGroupResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state hostGroupResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// all assinged policies must be removed before we are able to delete the host group
	resp.Diagnostics.Append(r.purgeSensorUpdatePolicies(ctx, state.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.purgeUSBDeviceControlPolicies(ctx, state.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.purgeFirewallPolicies(ctx, state.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.purgePreventionPolicies(ctx, state.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.purgeResponsePolicies(ctx, state.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	// removal of assigned policies return before the host group is ready to be deleted
	// adding a simple sleep.
	time.Sleep(10 * time.Second)

	_, err := r.client.HostGroup.DeleteHostGroups(
		&host_group.DeleteHostGroupsParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)

	if err != nil {
		if strings.Contains(err.Error(), "409") {
			resp.Diagnostics.AddError(
				"Error deleting CrowdStrike host group",
				"Please remove all assigned policies (firewall policies, prevention policies, etc) and try again. "+err.Error(),
			)
		} else {
			resp.Diagnostics.AddError(
				"Error deleting CrowdStrike host group",
				"Could not delete host group, unexpected error: "+err.Error(),
			)
		}
		return
	}
}

// ImportState implements the logic to support resource imports.
func (r *hostGroupResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// purgeSensorUpdatePolicies removes all sensor update policies from a host group.
func (r *hostGroupResource) purgeSensorUpdatePolicies(
	ctx context.Context,
	hostGroupID string,
) diag.Diagnostics {
	var diag diag.Diagnostics

	filter := fmt.Sprintf("groups:'%s'", hostGroupID)
	res, err := r.client.SensorUpdatePolicies.QuerySensorUpdatePolicies(
		&sensor_update_policies.QuerySensorUpdatePoliciesParams{
			Context: ctx,
			Filter:  &filter,
		},
	)

	if err != nil {
		diag.AddError(
			"Error deleting CrowdStrike host group",
			"Unable to read assigned sensor update policies "+err.Error(),
		)
		return diag
	}

	policies := res.Payload.Resources

	if len(policies) == 0 {
		return diag
	}

	name := "group_id"
	_, err = r.client.SensorUpdatePolicies.PerformSensorUpdatePoliciesAction(
		&sensor_update_policies.PerformSensorUpdatePoliciesActionParams{
			Context:    ctx,
			ActionName: "remove-host-group",
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: []*models.MsaspecActionParameter{
					{
						Name:  &name,
						Value: &hostGroupID,
					},
				},
				Ids: policies,
			},
		},
	)

	if err != nil {
		diag.AddError(
			"Error deleting CrowdStrike host group",
			"Unable to remove assigned sensor update policies "+err.Error(),
		)
		return diag
	}

	return diag
}

// purgeUSBDeviceControlPolicies removes all usb device control policies from a host group.
func (r *hostGroupResource) purgeUSBDeviceControlPolicies(
	ctx context.Context,
	hostGroupID string,
) diag.Diagnostics {
	var diag diag.Diagnostics

	filter := fmt.Sprintf("groups:'%s'", hostGroupID)
	res, err := r.client.DeviceControlPolicies.QueryDeviceControlPolicies(
		&device_control_policies.QueryDeviceControlPoliciesParams{
			Context: ctx,
			Filter:  &filter,
		},
	)

	if err != nil {
		diag.AddError(
			"Error deleting CrowdStrike host group",
			"Unable to read assigned usb device control policies "+err.Error(),
		)
		return diag
	}

	policies := res.Payload.Resources

	if len(policies) == 0 {
		return diag
	}

	name := "group_id"
	_, err = r.client.DeviceControlPolicies.PerformDeviceControlPoliciesAction(
		&device_control_policies.PerformDeviceControlPoliciesActionParams{
			Context:    ctx,
			ActionName: "remove-host-group",
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: []*models.MsaspecActionParameter{
					{
						Name:  &name,
						Value: &hostGroupID,
					},
				},
				Ids: policies,
			},
		},
	)

	if err != nil {
		diag.AddError(
			"Error deleting CrowdStrike host group",
			"Unable to remove assigned usb device control policies "+err.Error(),
		)
		return diag
	}

	return diag
}

// purgePreventionPolicies removes all prevention policies from a host group.
func (r *hostGroupResource) purgePreventionPolicies(
	ctx context.Context,
	hostGroupID string,
) diag.Diagnostics {
	var diag diag.Diagnostics

	filter := fmt.Sprintf("groups:'%s'", hostGroupID)
	res, err := r.client.PreventionPolicies.QueryPreventionPolicies(
		&prevention_policies.QueryPreventionPoliciesParams{
			Context: ctx,
			Filter:  &filter,
		},
	)

	if err != nil {
		diag.AddError(
			"Error deleting CrowdStrike host group",
			"Unable to read assigned prevention policies "+err.Error(),
		)
		return diag
	}

	policies := res.Payload.Resources

	if len(policies) == 0 {
		return diag
	}

	name := "group_id"
	_, err = r.client.PreventionPolicies.PerformPreventionPoliciesAction(
		&prevention_policies.PerformPreventionPoliciesActionParams{
			Context:    ctx,
			ActionName: "remove-host-group",
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: []*models.MsaspecActionParameter{
					{
						Name:  &name,
						Value: &hostGroupID,
					},
				},
				Ids: policies,
			},
		},
	)

	if err != nil {
		diag.AddError(
			"Error deleting CrowdStrike host group",
			"Unable to remove assigned prevention policies "+err.Error(),
		)
		return diag
	}

	return diag
}

// purgeFirewallPolicies removes all firewall policies from a host group.
func (r *hostGroupResource) purgeFirewallPolicies(
	ctx context.Context,
	hostGroupID string,
) diag.Diagnostics {
	var diag diag.Diagnostics

	filter := fmt.Sprintf("groups:'%s'", hostGroupID)
	res, err := r.client.FirewallPolicies.QueryFirewallPolicies(
		&firewall_policies.QueryFirewallPoliciesParams{
			Context: ctx,
			Filter:  &filter,
		},
	)

	if err != nil {
		diag.AddError(
			"Error deleting CrowdStrike host group",
			"Unable to read assigned firewall prevention policies "+err.Error(),
		)
		return diag
	}

	policies := res.Payload.Resources

	if len(policies) == 0 {
		return diag
	}

	name := "group_id"
	_, err = r.client.FirewallPolicies.PerformFirewallPoliciesAction(
		&firewall_policies.PerformFirewallPoliciesActionParams{
			Context:    ctx,
			ActionName: "remove-host-group",
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: []*models.MsaspecActionParameter{
					{
						Name:  &name,
						Value: &hostGroupID,
					},
				},
				Ids: policies,
			},
		},
	)

	if err != nil {
		diag.AddError(
			"Error deleting CrowdStrike host group",
			"Unable to remove assigned firewall prevention policies "+err.Error(),
		)
		return diag
	}

	return diag
}

// purgeResponsePolicies removes all response policies from a host group.
func (r *hostGroupResource) purgeResponsePolicies(
	ctx context.Context,
	hostGroupID string,
) diag.Diagnostics {
	var diag diag.Diagnostics

	filter := fmt.Sprintf("groups:'%s'", hostGroupID)
	res, err := r.client.ResponsePolicies.QueryRTResponsePolicies(
		&response_policies.QueryRTResponsePoliciesParams{
			Context: ctx,
			Filter:  &filter,
		},
	)

	if err != nil {
		diag.AddError(
			"Error deleting CrowdStrike host group",
			"Unable to read assigned response policies "+err.Error(),
		)
		return diag
	}

	policies := res.Payload.Resources

	if len(policies) == 0 {
		return diag
	}

	name := "group_id"
	_, err = r.client.ResponsePolicies.PerformRTResponsePoliciesAction(
		&response_policies.PerformRTResponsePoliciesActionParams{
			Context:    ctx,
			ActionName: "remove-host-group",
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: []*models.MsaspecActionParameter{
					{
						Name:  &name,
						Value: &hostGroupID,
					},
				},
				Ids: policies,
			},
		},
	)

	if err != nil {
		diag.AddError(
			"Error deleting CrowdStrike host group",
			"Unable to remove assigned response policies "+err.Error(),
		)
		return diag
	}

	return diag
}
