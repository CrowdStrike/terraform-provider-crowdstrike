package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/host_group"
	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/response_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
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
	_ resource.Resource                   = &hostGroupResource{}
	_ resource.ResourceWithConfigure      = &hostGroupResource{}
	_ resource.ResourceWithImportState    = &hostGroupResource{}
	_ resource.ResourceWithValidateConfig = &hostGroupResource{}
)

var (
	hgDynamic    = "dynamic"
	hgStatic     = "static"
	hgStaticByID = "staticByID"
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
	Hostnames      types.Set    `tfsdk:"hostnames"`
	HostIDs        types.Set    `tfsdk:"host_ids"`
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

var apiScopes = []scopes.Scope{
	{
		Name:  "Host groups",
		Read:  true,
		Write: true,
	},
	{
		Name:  "Firewall management",
		Read:  true,
		Write: true,
	},
	{
		Name:  "Prevention policies",
		Read:  true,
		Write: true,
	},
	{
		Name:  "Response policies",
		Read:  true,
		Write: true,
	},
	{
		Name:  "Sensor update policies",
		Read:  true,
		Write: true,
	},
}

// Schema defines the schema for the resource.
func (r *hostGroupResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Host Group --- This resource allows you to manage host groups in the CrowdStrike Falcon Platform.\n\n%s",
			scopes.GenerateScopeDescription(apiScopes),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The unique identifier for the host group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The RFC850 timestamp of the last update to this resource by Terraform.",
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The display name for the host group.",
			},
			"assignment_rule": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The assignment rule used for dynamic host groups. Required if `type` is `dynamic`.",
			},
			"hostnames": schema.SetAttribute{
				Optional:            true,
				MarkdownDescription: "A set of hostnames to include in a static host group. Required if `type` is `static`.",
				ElementType:         types.StringType,
			},
			"host_ids": schema.SetAttribute{
				Optional:            true,
				MarkdownDescription: "A set of host IDs to include in a staticByID host group. Required if `type` is `staticByID`.",
				ElementType:         types.StringType,
			},
			"type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The type of host group. Valid values: `dynamic`, `static`, `staticByID`. This value is case sensitive.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf(hgDynamic, hgStatic, hgStaticByID),
				},
			},
			"description": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "A description for the host group.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
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

	assignmentRule, diags := generateAssignmentRule(ctx, plan)
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

	if plan.GroupType.ValueString() == hgDynamic {
		hostGroupParams.Body.Resources[0].AssignmentRule = assignmentRule
	}

	hostGroup, err := r.client.HostGroup.CreateHostGroups(&hostGroupParams)

	if err != nil {
		errMsg := fmt.Sprintf(
			"Could not create host group (%s): %s",
			plan.Name.ValueString(),
			err.Error(),
		)
		if strings.Contains(err.Error(), "409") {
			errMsg = fmt.Sprintf(
				"Could not create host group (%s): A host group already exists with that name.\n\n%s",
				plan.Name.ValueString(),
				err.Error(),
			)
		}

		if strings.Contains(err.Error(), "500") && plan.GroupType.ValueString() == hgDynamic {
			errMsg = fmt.Sprintf(
				"Could not create host group (%s): Returned error code 500, this could be caused by invalid assignment_rule.\n\n%s",
				plan.Name.ValueString(),
				err.Error(),
			)
		}

		resp.Diagnostics.AddError("Error creating host group", errMsg)
		return
	}

	hostGroupResource := hostGroup.Payload.Resources[0]
	plan.ID = types.StringValue(*hostGroupResource.ID)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.Name = types.StringValue(*hostGroupResource.Name)
	plan.Description = types.StringValue(*hostGroupResource.Description)
	plan.GroupType = types.StringValue(hostGroupResource.GroupType)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	if plan.GroupType.ValueString() != hgDynamic {
		hgUpdate, err := r.updateHostGroup(ctx, plan, assignmentRule)

		if err != nil {
			resp.Diagnostics.AddError(
				"Error assigning hosts to host group",
				fmt.Sprintf("Could not assign hosts to host group with ID: %s: %s", plan.ID.ValueString(), err.Error()),
			)
			return
		}

		hostGroupResource = hgUpdate.Payload.Resources[0]
	}

	diags.Append(assignAssignmentRule(ctx, hostGroupResource.AssignmentRule, &plan)...)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
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
	state.GroupType = types.StringValue(hostGroupResource.GroupType)
	resp.Diagnostics.Append(assignAssignmentRule(ctx, hostGroupResource.AssignmentRule, &state)...)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
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

	assignmentRule, diags := generateAssignmentRule(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	hostGroup, err := r.updateHostGroup(ctx, plan, assignmentRule)

	if err != nil {
		errMsg := fmt.Sprintf(
			"Could not update host group (%s): %s",
			plan.ID.ValueString(),
			err.Error(),
		)
		if strings.Contains(err.Error(), "409") {
			errMsg = fmt.Sprintf(
				"Could not update host group (%s): A host group already exists with that name. \n\n %s",
				plan.ID.ValueString(),
				err.Error(),
			)
		}

		if strings.Contains(err.Error(), "500") && plan.GroupType.ValueString() == hgDynamic {
			errMsg = fmt.Sprintf(
				"Could not update host group (%s): Returned error code 500, this could be caused by invalid assignment_rule. \n\n %s",
				plan.Name.ValueString(),
				err.Error(),
			)
		}

		resp.Diagnostics.AddError("Error updating host group", errMsg)

		return
	}

	hostGroupResource := hostGroup.Payload.Resources[0]

	plan.ID = types.StringValue(*hostGroupResource.ID)
	plan.Name = types.StringValue(*hostGroupResource.Name)
	plan.Description = types.StringValue(*hostGroupResource.Description)
	resp.Diagnostics.Append(assignAssignmentRule(ctx, hostGroupResource.AssignmentRule, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.GroupType = types.StringValue(hostGroupResource.GroupType)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *hostGroupResource) updateHostGroup(
	ctx context.Context,
	plan hostGroupResourceModel,
	assignmentRule string,
) (*host_group.UpdateHostGroupsOK, error) {
	hostGroupParams := host_group.UpdateHostGroupsParams{
		Context: ctx,
		Body: &models.HostGroupsUpdateGroupsReqV1{
			Resources: []*models.HostGroupsUpdateGroupReqV1{
				{
					Name:           plan.Name.ValueString(),
					ID:             plan.ID.ValueStringPointer(),
					Description:    plan.Description.ValueString(),
					AssignmentRule: &assignmentRule,
				},
			},
		},
	}

	hostGroup, err := r.client.HostGroup.UpdateHostGroups(&hostGroupParams)

	return hostGroup, err
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

	// some cxs may not have all modules so they will get a 403
	// storing errors in tempDiags and only throw them after a failed 409 delete
	var tempDiags diag.Diagnostics

	// all assinged policies must be removed before we are able to delete the host group
	tempDiags.Append(r.purgeSensorUpdatePolicies(ctx, state.ID.ValueString())...)
	tempDiags.Append(r.purgeFirewallPolicies(ctx, state.ID.ValueString())...)
	tempDiags.Append(r.purgePreventionPolicies(ctx, state.ID.ValueString())...)
	tempDiags.Append(r.purgeResponsePolicies(ctx, state.ID.ValueString())...)

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
			resp.Diagnostics.Append(tempDiags...)
			resp.Diagnostics.AddError(
				"Error deleting CrowdStrike host group",
				"Please ensure you have the correct api scopes or remove all assigned policies manually (firewall policies, prevention policies, etc) and try again. "+err.Error(),
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
	var diags diag.Diagnostics

	filter := fmt.Sprintf("groups:'%s'", hostGroupID)
	res, err := r.client.SensorUpdatePolicies.QuerySensorUpdatePolicies(
		&sensor_update_policies.QuerySensorUpdatePoliciesParams{
			Context: ctx,
			Filter:  &filter,
		},
	)

	if err != nil {
		diags.AddError(
			"Error deleting CrowdStrike host group",
			"Unable to read assigned sensor update policies "+err.Error(),
		)
		return diags
	}

	policies := res.Payload.Resources
	name := "group_id"

	for _, policy := range policies {
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
					Ids: []string{policy},
				},
			},
		)

		if err != nil {
			diags.AddError(
				"Error deleting CrowdStrike host group",
				"Unable to remove assigned sensor update policies "+err.Error(),
			)
			return diags
		}
	}

	return diags
}

// purgePreventionPolicies removes all prevention policies from a host group.
func (r *hostGroupResource) purgePreventionPolicies(
	ctx context.Context,
	hostGroupID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	filter := fmt.Sprintf("groups:'%s'", hostGroupID)
	res, err := r.client.PreventionPolicies.QueryPreventionPolicies(
		&prevention_policies.QueryPreventionPoliciesParams{
			Context: ctx,
			Filter:  &filter,
		},
	)

	if err != nil {
		diags.AddError(
			"Error deleting CrowdStrike host group",
			"Unable to read assigned prevention policies "+err.Error(),
		)
		return diags
	}

	policies := res.Payload.Resources
	name := "group_id"

	for _, policy := range policies {
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
					Ids: []string{policy},
				},
			},
		)

		if err != nil {
			diags.AddError(
				"Error deleting CrowdStrike host group",
				"Unable to remove assigned prevention policies "+err.Error(),
			)
			return diags
		}
	}

	return diags
}

// purgeFirewallPolicies removes all firewall policies from a host group.
func (r *hostGroupResource) purgeFirewallPolicies(
	ctx context.Context,
	hostGroupID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	filter := fmt.Sprintf("groups:'%s'", hostGroupID)
	res, err := r.client.FirewallPolicies.QueryFirewallPolicies(
		&firewall_policies.QueryFirewallPoliciesParams{
			Context: ctx,
			Filter:  &filter,
		},
	)

	if err != nil {
		diags.AddError(
			"Error deleting CrowdStrike host group",
			"Unable to read assigned firewall prevention policies "+err.Error(),
		)
		return diags
	}

	policies := res.Payload.Resources
	name := "group_id"

	for _, policy := range policies {
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
					Ids: []string{policy},
				},
			},
		)

		if err != nil {
			diags.AddError(
				"Error deleting CrowdStrike host group",
				"Unable to remove assigned firewall prevention policies "+err.Error(),
			)
			return diags
		}
	}

	return diags
}

// purgeResponsePolicies removes all response policies from a host group.
func (r *hostGroupResource) purgeResponsePolicies(
	ctx context.Context,
	hostGroupID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	filter := fmt.Sprintf("groups:'%s'", hostGroupID)
	res, err := r.client.ResponsePolicies.QueryRTResponsePolicies(
		&response_policies.QueryRTResponsePoliciesParams{
			Context: ctx,
			Filter:  &filter,
		},
	)

	if err != nil {
		diags.AddError(
			"Error deleting CrowdStrike host group",
			"Unable to read assigned response policies "+err.Error(),
		)
		return diags
	}

	policies := res.Payload.Resources
	name := "group_id"

	for _, policy := range policies {
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
					Ids: []string{policy},
				},
			},
		)

		if err != nil {
			diags.AddError(
				"Error deleting CrowdStrike host group",
				"Unable to remove assigned response policies "+err.Error(),
			)
			return diags
		}
	}

	return diags
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *hostGroupResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config hostGroupResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	switch config.GroupType.ValueString() {
	case hgDynamic:
		if config.AssignmentRule.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("assignment_rule"),
				"Error validating host group",
				"The assignment_rule attribute is required for dynamic host groups.",
			)
		}

		if !config.Hostnames.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("hostnames"),
				"Error validating host group",
				"The hostnames attribute can only be used with a static host group.",
			)
		}

		if !config.HostIDs.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("host_ids"),
				"Error validating host group",
				"The host_ids attribute can only be used with a staticByID host group.",
			)
		}
	case hgStatic:
		if config.Hostnames.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("hostnames"),
				"Error validating host group",
				"The hostnames attribute is required for static host groups.",
			)
		}

		if config.AssignmentRule.ValueString() != "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("assignment_rule"),
				"Error validating host group",
				"The assignment_rule attribute can only be used by a dynamic host group.",
			)
		}

		if !config.HostIDs.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("host_ids"),
				"Error validating host group",
				"The host_ids attribute can only be used with a staticByID host group.",
			)
		}

	case hgStaticByID:
		if config.HostIDs.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("host_ids"),
				"Error validating host group",
				"The host_ids attribute is required for staticByID host groups.",
			)
		}

		if config.AssignmentRule.ValueString() != "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("assignment_rule"),
				"Error validating host group",
				"The assignment_rule attribute can only be used by a dynamic host group.",
			)
		}

		if !config.Hostnames.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("hostnames"),
				"Error validating host group",
				"The hostnames attribute can only be used with a static host group.",
			)
		}
	}
}

// assignAssignmentRule takes an assignment_rule from the API and assigns it to the correct attribute.
func assignAssignmentRule(
	ctx context.Context,
	assignmentRule string,
	config *hostGroupResourceModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	deviceIDs := []string{}
	hostnames := []string{}

	emptySet, diag := types.SetValueFrom(ctx, types.StringType, []string{})
	diags.Append(diag...)
	if diags.HasError() {
		return diags
	}

	groupType := config.GroupType.ValueString()

	if groupType == hgDynamic {
		config.AssignmentRule = types.StringValue(assignmentRule)
		return diags
	}

	re := regexp.MustCompile(`(?mi)device_id:\[(.*?)],hostname:\[(.*?)]`)
	matches := make([]string, 3)
	for i, m := range re.FindStringSubmatch(assignmentRule) {
		matches[i] = m
	}

	if len(matches[1]) != 0 {
		deviceIDs = cleanMatches(matches[1])
	}
	if len(matches[2]) != 0 {
		hostnames = cleanMatches(matches[2])
	}

	if groupType == hgStatic {
		hostnameSet, err := types.SetValueFrom(ctx, types.StringType, hostnames)
		diags.Append(err...)
		if diags.HasError() {
			return diags
		}
		config.Hostnames = hostnameSet
		if config.Hostnames.IsNull() {
			config.Hostnames = emptySet
		}
	} else if groupType == hgStaticByID {
		hostIDSet, err := types.SetValueFrom(ctx, types.StringType, deviceIDs)
		diags.Append(err...)
		if diags.HasError() {
			return diags
		}
		config.HostIDs = hostIDSet
		if config.HostIDs.IsNull() {
			config.HostIDs = emptySet
		}
	}

	return diags
}

func cleanMatches(m string) []string {
	var result []string
	input := strings.Trim(m, ",'")

	parts := strings.Split(input, ",")
	for _, part := range parts {
		trimmedPart := strings.Trim(strings.TrimSpace(part), "'")

		if trimmedPart != "" {
			result = append(result, trimmedPart)
		}
	}

	return result
}

// generateAssignmentRule returns a valid assignment rule based on the host group type.
func generateAssignmentRule(
	ctx context.Context,
	config hostGroupResourceModel,
) (string, diag.Diagnostics) {
	defaultAssignmentRule := "device_id:[''],hostname:['']"
	var diags diag.Diagnostics

	switch config.GroupType.ValueString() {
	case hgDynamic:
		return config.AssignmentRule.ValueString(), diags
	case hgStatic:
		if len(config.Hostnames.Elements()) > 0 {
			var hostnames []string
			diags.Append(config.Hostnames.ElementsAs(ctx, &hostnames, false)...)
			if diags.HasError() {
				return defaultAssignmentRule, diags
			}
			assignmentRule := fmt.Sprintf(
				"device_id:[''],hostname:[%s%s%s]",
				"'",
				strings.Join(hostnames, "','"),
				"'",
			)
			return assignmentRule, diags
		}
	case hgStaticByID:
		if len(config.HostIDs.Elements()) > 0 {
			var hostIDs []string
			diags.Append(config.HostIDs.ElementsAs(ctx, &hostIDs, false)...)
			if diags.HasError() {
				return defaultAssignmentRule, diags
			}
			assignmentRule := fmt.Sprintf(
				"device_id:[%s%s%s],hostname:['']",
				"'",
				strings.Join(hostIDs, "','"),
				"'",
			)

			return assignmentRule, diags
		}
	}

	return defaultAssignmentRule, diags
}
