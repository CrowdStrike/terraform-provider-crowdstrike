package contentupdatepolicy

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &contentPolicyResource{}
	_ resource.ResourceWithConfigure      = &contentPolicyResource{}
	_ resource.ResourceWithImportState    = &contentPolicyResource{}
	_ resource.ResourceWithValidateConfig = &contentPolicyResource{}
)

// Valid ring assignments.
var validRingAssignments = []string{
	"ga",    // general availability
	"ea",    // early access
	"pause", // pause updates
}

// Valid ring assignments for system_critical (no pause allowed).
var validSystemCriticalRingAssignments = []string{
	"ga", // general availability
	"ea", // early access
}

// Valid delay hours for GA ring.
var validDelayHours = []int64{0, 1, 2, 4, 8, 12, 24, 48, 72}

// NewContentPolicyResource is a helper function to simplify the provider implementation.
func NewContentPolicyResource() resource.Resource {
	return &contentPolicyResource{}
}

// contentPolicyResource is the resource implementation.
type contentPolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

// contentPolicyResourceModel is the resource model.
type contentPolicyResourceModel struct {
	ID                      types.String `tfsdk:"id"`
	Name                    types.String `tfsdk:"name"`
	Description             types.String `tfsdk:"description"`
	Enabled                 types.Bool   `tfsdk:"enabled"`
	HostGroups              types.Set    `tfsdk:"host_groups"`
	SensorOperations        types.Object `tfsdk:"sensor_operations"`
	SystemCritical          types.Object `tfsdk:"system_critical"`
	VulnerabilityManagement types.Object `tfsdk:"vulnerability_management"`
	RapidResponse           types.Object `tfsdk:"rapid_response"`
	LastUpdated             types.String `tfsdk:"last_updated"`

	sensorOperations        *ringAssignmentModel `tfsdk:"-"`
	systemCritical          *ringAssignmentModel `tfsdk:"-"`
	vulnerabilityManagement *ringAssignmentModel `tfsdk:"-"`
	rapidResponse           *ringAssignmentModel `tfsdk:"-"`
}

// ringAssignmentModel represents a content category ring assignment.
type ringAssignmentModel struct {
	RingAssignment types.String `tfsdk:"ring_assignment"`
	DelayHours     types.Int64  `tfsdk:"delay_hours"`
}

// AttributeTypes returns the attribute types for the ring assignment model.
func (r ringAssignmentModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"ring_assignment": types.StringType,
		"delay_hours":     types.Int64Type,
	}
}

// extract extracts the Go values from their terraform wrapped values.
func (d *contentPolicyResourceModel) extract(ctx context.Context) diag.Diagnostics {
	var diags diag.Diagnostics

	if !d.SensorOperations.IsNull() {
		var sensorOps ringAssignmentModel
		diags.Append(d.SensorOperations.As(ctx, &sensorOps, basetypes.ObjectAsOptions{})...)
		d.sensorOperations = &sensorOps
	}

	if !d.SystemCritical.IsNull() {
		var systemCrit ringAssignmentModel
		diags.Append(d.SystemCritical.As(ctx, &systemCrit, basetypes.ObjectAsOptions{})...)
		d.systemCritical = &systemCrit
	}

	if !d.VulnerabilityManagement.IsNull() {
		var vulnMgmt ringAssignmentModel
		diags.Append(d.VulnerabilityManagement.As(ctx, &vulnMgmt, basetypes.ObjectAsOptions{})...)
		d.vulnerabilityManagement = &vulnMgmt
	}

	if !d.RapidResponse.IsNull() {
		var rapidResp ringAssignmentModel
		diags.Append(d.RapidResponse.As(ctx, &rapidResp, basetypes.ObjectAsOptions{})...)
		d.rapidResponse = &rapidResp
	}

	return diags
}

// wrap transforms Go values to their terraform wrapped values.
func (d *contentPolicyResourceModel) wrap(
	ctx context.Context,
	policy models.ContentUpdatePolicyV1,
	validateHostGroups bool,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// fix a backend bug that returns empty host groups if they are deleted
	fixedPolicyHostGroups := []*models.HostGroupsHostGroupV1{}
	for _, hostGroup := range policy.Groups {
		if hostGroup.ID == nil || *hostGroup.ID == "" {
			continue
		}
		fixedPolicyHostGroups = append(fixedPolicyHostGroups, hostGroup)
	}
	policy.Groups = fixedPolicyHostGroups

	d.ID = types.StringValue(*policy.ID)
	d.Name = types.StringValue(*policy.Name)
	d.Description = types.StringPointerValue(policy.Description)
	d.Enabled = types.BoolValue(*policy.Enabled)

	if validateHostGroups {
		policyGroups := make([]string, 0, len(policy.Groups))
		modelGroups := make([]string, 0, len(d.HostGroups.Elements()))

		if len(policy.Groups) > 0 {
			for _, hostGroup := range policy.Groups {
				policyGroups = append(policyGroups, *hostGroup.ID)
			}
		}

		diags.Append(d.HostGroups.ElementsAs(ctx, &modelGroups, true)...)

		if modelGroups == nil {
			modelGroups = []string{}
		}

		if policyGroups == nil {
			policyGroups = []string{}
		}

		less := func(a, b string) bool { return a < b }
		hostGroupDiff := cmp.Diff(policyGroups, modelGroups, cmpopts.SortSlices(less))
		if hostGroupDiff != "" {
			summary := "Apply ran without issue, but content update policy is still missing host groups. This usually happens when an invalid host group is provided."

			if len(policyGroups) > 0 {
				summary = fmt.Sprintf(
					"%s\n\nThe following host groups are valid and assigned to the content update policy:\n\n%s",
					summary,
					strings.Join(policyGroups, "\n"),
				)
			}
			diags.AddAttributeError(path.Root("host_groups"), "Host group mismatch", summary)
		}
	}

	hostGroupSet, diag := hostgroups.ConvertHostGroupsToSet(ctx, policy.Groups)
	diags.Append(diag...)
	if diags.HasError() {
		return diags
	}

	// allow host_groups to stay null instead of defaulting to an empty set when there are no host groups
	if !d.HostGroups.IsNull() || len(hostGroupSet.Elements()) != 0 {
		d.HostGroups = hostGroupSet
	}

	if policy.Settings != nil && policy.Settings.RingAssignmentSettings != nil {
		for _, setting := range policy.Settings.RingAssignmentSettings {
			ringAssignment := ringAssignmentModel{
				RingAssignment: types.StringValue(*setting.RingAssignment),
			}

			if *setting.RingAssignment == "ga" {
				delayHours := int64(0)
				if setting.DelayHours != nil {
					if delayStr := *setting.DelayHours; delayStr != "" {
						if delay, err := strconv.ParseInt(delayStr, 10, 64); err == nil {
							delayHours = delay
						}
					}
				}
				ringAssignment.DelayHours = types.Int64Value(delayHours)
			} else {
				ringAssignment.DelayHours = types.Int64Null()
			}

			objValue, diag := types.ObjectValueFrom(ctx, ringAssignment.AttributeTypes(), ringAssignment)
			diags.Append(diag...)
			if diags.HasError() {
				return diags
			}

			switch *setting.ID {
			case "sensor_operations":
				d.SensorOperations = objValue
			case "system_critical":
				d.SystemCritical = objValue
			case "vulnerability_management":
				d.VulnerabilityManagement = objValue
			case "rapid_response_al_bl_listing":
				d.RapidResponse = objValue
			}
		}
	}

	return diags
}

// Configure adds the provider configured client to the resource.
func (r *contentPolicyResource) Configure(
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
func (r *contentPolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_content_update_policy"
}

// Schema defines the schema for the resource.
func (r *contentPolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Content Update Policy --- This resource allows management of content update policies in the CrowdStrike Falcon platform. Content update policies control how and when CrowdStrike content updates are deployed to hosts.\n\n%s",
			scopes.GenerateScopeDescription(
				[]scopes.Scope{
					{
						Name:  "Content update policies",
						Read:  true,
						Write: true,
					},
				},
			),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the content update policy.",
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
				Description: "Name of the content update policy.",
			},
			"description": schema.StringAttribute{
				Required:    true,
				Description: "Description of the content update policy.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Enable the content update policy.",
				Default:     booldefault.StaticBool(true),
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host Group IDs to attach to the content update policy.",
			},
			"sensor_operations": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Ring assignment settings for sensor operations content category.",
				Attributes: map[string]schema.Attribute{
					"ring_assignment": schema.StringAttribute{
						Required:    true,
						Description: "Ring assignment for the content category (ga, ea, pause).",
						Validators: []validator.String{
							stringvalidator.OneOf(validRingAssignments...),
						},
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators: []validator.Int64{
							int64validator.OneOf(validDelayHours...),
						},
					},
				},
			},
			"system_critical": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Ring assignment settings for system critical content category.",
				Attributes: map[string]schema.Attribute{
					"ring_assignment": schema.StringAttribute{
						Required:    true,
						Description: "Ring assignment for the content category (ga, ea). Note: 'pause' is not allowed for system_critical.",
						Validators: []validator.String{
							stringvalidator.OneOf(validSystemCriticalRingAssignments...),
						},
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators: []validator.Int64{
							int64validator.OneOf(validDelayHours...),
						},
					},
				},
			},
			"vulnerability_management": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Ring assignment settings for vulnerability management content category.",
				Attributes: map[string]schema.Attribute{
					"ring_assignment": schema.StringAttribute{
						Required:    true,
						Description: "Ring assignment for the content category (ga, ea, pause).",
						Validators: []validator.String{
							stringvalidator.OneOf(validRingAssignments...),
						},
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators: []validator.Int64{
							int64validator.OneOf(validDelayHours...),
						},
					},
				},
			},
			"rapid_response": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Ring assignment settings for rapid response allow/block listing content category.",
				Attributes: map[string]schema.Attribute{
					"ring_assignment": schema.StringAttribute{
						Required:    true,
						Description: "Ring assignment for the content category (ga, ea, pause).",
						Validators: []validator.String{
							stringvalidator.OneOf(validRingAssignments...),
						},
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators: []validator.Int64{
							int64validator.OneOf(validDelayHours...),
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *contentPolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan contentPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ringAssignmentSettings := make([]*models.ContentUpdateRingAssignmentSettingsReqV1, 0, 4)

	if plan.sensorOperations != nil {
		delayHours := int64(0)
		if !plan.sensorOperations.DelayHours.IsNull() {
			delayHours = plan.sensorOperations.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "sensor_operations"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: plan.sensorOperations.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	if plan.systemCritical != nil {
		delayHours := int64(0)
		if !plan.systemCritical.DelayHours.IsNull() {
			delayHours = plan.systemCritical.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "system_critical"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: plan.systemCritical.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	if plan.vulnerabilityManagement != nil {
		delayHours := int64(0)
		if !plan.vulnerabilityManagement.DelayHours.IsNull() {
			delayHours = plan.vulnerabilityManagement.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "vulnerability_management"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: plan.vulnerabilityManagement.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	if plan.rapidResponse != nil {
		delayHours := int64(0)
		if !plan.rapidResponse.DelayHours.IsNull() {
			delayHours = plan.rapidResponse.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "rapid_response_al_bl_listing"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: plan.rapidResponse.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	policyParams := content_update_policies.CreateContentUpdatePoliciesParams{
		Context: ctx,
		Body: &models.ContentUpdateCreatePoliciesReqV1{
			Resources: []*models.ContentUpdateCreatePolicyReqV1{
				{
					Name:        plan.Name.ValueStringPointer(),
					Description: plan.Description.ValueString(),
					Settings: &models.ContentUpdateContentUpdateSettingsReqV1{
						RingAssignmentSettings: ringAssignmentSettings,
					},
				},
			},
		},
	}

	res, err := r.client.ContentUpdatePolicies.CreateContentUpdatePolicies(&policyParams)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating content update policy",
			"Could not create content update policy, unexpected error: "+err.Error(),
		)
		return
	}

	policy := res.Payload.Resources[0]

	plan.ID = types.StringValue(*policy.ID)
	plan.LastUpdated = utils.GenerateUpdateTimestamp()

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Enabled.ValueBool() {
		err := r.updatePolicyEnabledState(ctx, plan.ID.ValueString(), true)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error enabling content update policy",
				"Could not enable content update policy, unexpected error: "+err.Error(),
			)
			return
		}
	}

	if len(plan.HostGroups.Elements()) > 0 {
		var hostGroupIDs []string
		resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &hostGroupIDs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		err = r.updateHostGroups(ctx, hostgroups.AddHostGroup, hostGroupIDs, plan.ID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError(
				"Error assigning host group to policy",
				"Could not assign host group to policy, unexpected error: "+err.Error(),
			)
			return
		}
	}

	policy, diags := getContentUpdatePolicy(ctx, r.client, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *policy, true)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *contentPolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state contentPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getContentUpdatePolicy(ctx, r.client, state.ID.ValueString())
	if diags.HasError() {
		for _, diag := range diags {
			if strings.Contains(diag.Summary(), "not found") {
				tflog.Warn(
					ctx,
					fmt.Sprintf("content update policy %s not found, removing from state", state.ID),
				)
				resp.State.RemoveResource(ctx)
				return
			}
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, *policy, false)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *contentPolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan contentPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state contentPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(state.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hostGroupsToAdd, hostGroupsToRemove, diags := utils.SetIDsToModify(
		ctx,
		plan.HostGroups,
		state.HostGroups,
	)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(hostGroupsToAdd) != 0 {
		err := r.updateHostGroups(
			ctx,
			hostgroups.AddHostGroup,
			hostGroupsToAdd,
			plan.ID.ValueString(),
		)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating content update policy",
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
		err := r.updateHostGroups(
			ctx,
			hostgroups.RemoveHostGroup,
			hostGroupsToRemove,
			plan.ID.ValueString(),
		)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating content update policy",
				fmt.Sprintf(
					"Could not remove host groups: (%s) from policy with id: %s \n\n %s",
					strings.Join(hostGroupsToRemove, ", "),
					plan.ID.ValueString(),
					err.Error(),
				),
			)
			return
		}
	}

	ringAssignmentSettings := make([]*models.ContentUpdateRingAssignmentSettingsReqV1, 0, 4)

	if plan.sensorOperations != nil {
		delayHours := int64(0)
		if !plan.sensorOperations.DelayHours.IsNull() {
			delayHours = plan.sensorOperations.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "sensor_operations"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: plan.sensorOperations.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	if plan.systemCritical != nil {
		delayHours := int64(0)
		if !plan.systemCritical.DelayHours.IsNull() {
			delayHours = plan.systemCritical.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "system_critical"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: plan.systemCritical.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	if plan.vulnerabilityManagement != nil {
		delayHours := int64(0)
		if !plan.vulnerabilityManagement.DelayHours.IsNull() {
			delayHours = plan.vulnerabilityManagement.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "vulnerability_management"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: plan.vulnerabilityManagement.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	if plan.rapidResponse != nil {
		delayHours := int64(0)
		if !plan.rapidResponse.DelayHours.IsNull() {
			delayHours = plan.rapidResponse.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "rapid_response_al_bl_listing"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: plan.rapidResponse.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	policyParams := content_update_policies.UpdateContentUpdatePoliciesParams{
		Context: ctx,
		Body: &models.ContentUpdateUpdatePoliciesReqV1{
			Resources: []*models.ContentUpdateUpdatePolicyReqV1{
				{
					ID:          plan.ID.ValueStringPointer(),
					Name:        plan.Name.ValueString(),
					Description: plan.Description.ValueString(),
					Settings: &models.ContentUpdateContentUpdateSettingsReqV1{
						RingAssignmentSettings: ringAssignmentSettings,
					},
				},
			},
		},
	}

	_, err := r.client.ContentUpdatePolicies.UpdateContentUpdatePolicies(&policyParams)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating content update policy",
			"Could not update content update policy with ID: "+plan.ID.ValueString()+": "+err.Error(),
		)
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()

	if plan.Enabled.ValueBool() != state.Enabled.ValueBool() {
		err := r.updatePolicyEnabledState(ctx, plan.ID.ValueString(), plan.Enabled.ValueBool())
		if err != nil {
			resp.Diagnostics.AddError(
				"Error changing content update policy enabled state",
				"Could not change content update policy enabled state, unexpected error: "+err.Error(),
			)
			return
		}
	}

	policy, diags := getContentUpdatePolicy(ctx, r.client, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *policy, true)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *contentPolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state contentPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.updatePolicyEnabledState(ctx, state.ID.ValueString(), false)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			tflog.Warn(
				ctx,
				fmt.Sprintf("content update policy %s not found, removing from state", state.ID),
			)
			return
		}
		resp.Diagnostics.AddError(
			"Error disabling content update policy for delete",
			"Could not disable content update policy, unexpected error: "+err.Error(),
		)
		return
	}

	_, err = r.client.ContentUpdatePolicies.DeleteContentUpdatePolicies(
		&content_update_policies.DeleteContentUpdatePoliciesParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)

	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			tflog.Warn(
				ctx,
				fmt.Sprintf("content update policy %s not found, removing from state", state.ID),
			)
			return
		}
		resp.Diagnostics.AddError(
			"Error deleting content update policy",
			"Could not delete content update policy, unexpected error: "+err.Error(),
		)
		return
	}
}

// ImportState implements the logic to support resource imports.
func (r *contentPolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply to validate resource configuration.
func (r *contentPolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config contentPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(config.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.HostGroups, "host_groups")...)

	if config.sensorOperations != nil {
		if config.sensorOperations.RingAssignment.ValueString() != "ga" && !config.sensorOperations.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("sensor_operations").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf("delay_hours can only be set when ring_assignment is 'ga'. sensor_operations has ring_assignment '%s' but delay_hours is set.",
					config.sensorOperations.RingAssignment.ValueString()),
			)
		}
	}

	if config.systemCritical != nil {
		if config.systemCritical.RingAssignment.ValueString() != "ga" && !config.systemCritical.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("system_critical").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf("delay_hours can only be set when ring_assignment is 'ga'. system_critical has ring_assignment '%s' but delay_hours is set.",
					config.systemCritical.RingAssignment.ValueString()),
			)
		}
	}

	if config.vulnerabilityManagement != nil {
		if config.vulnerabilityManagement.RingAssignment.ValueString() != "ga" && !config.vulnerabilityManagement.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("vulnerability_management").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf("delay_hours can only be set when ring_assignment is 'ga'. vulnerability_management has ring_assignment '%s' but delay_hours is set.",
					config.vulnerabilityManagement.RingAssignment.ValueString()),
			)
		}
	}

	if config.rapidResponse != nil {
		if config.rapidResponse.RingAssignment.ValueString() != "ga" && !config.rapidResponse.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("rapid_response").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf("delay_hours can only be set when ring_assignment is 'ga'. rapid_response has ring_assignment '%s' but delay_hours is set.",
					config.rapidResponse.RingAssignment.ValueString()),
			)
		}
	}
}

// updatePolicyEnabledState enables or disables a content update policy.
func (r *contentPolicyResource) updatePolicyEnabledState(
	ctx context.Context,
	policyID string,
	enabled bool,
) error {
	actionName := "disable"
	if enabled {
		actionName = "enable"
	}

	_, err := r.client.ContentUpdatePolicies.PerformContentUpdatePoliciesAction(
		&content_update_policies.PerformContentUpdatePoliciesActionParams{
			Context:    ctx,
			ActionName: actionName,
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{policyID},
			},
		},
	)

	return err
}

// updateHostGroups will remove or add a slice of host groups to a content update policy.
func (r *contentPolicyResource) updateHostGroups(
	ctx context.Context,
	action hostgroups.HostGroupAction,
	hostGroupIDs []string,
	policyID string,
) error {
	tflog.Debug(ctx, "updateHostGroups called", map[string]interface{}{
		"action":       action.String(),
		"hostGroupIDs": hostGroupIDs,
		"policyID":     policyID,
		"count":        len(hostGroupIDs),
	})
	var actionParams []*models.MsaspecActionParameter
	name := "group_id"

	for _, g := range hostGroupIDs {
		gCopy := g
		actionParam := &models.MsaspecActionParameter{
			Name:  &name,
			Value: &gCopy,
		}

		actionParams = append(actionParams, actionParam)
	}

	tflog.Debug(ctx, "Built action parameters", map[string]interface{}{
		"actionParams": actionParams,
		"paramCount":   len(actionParams),
	})

	_, err := r.client.ContentUpdatePolicies.PerformContentUpdatePoliciesAction(
		&content_update_policies.PerformContentUpdatePoliciesActionParams{
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

// getContentUpdatePolicy retrieves a content update policy by ID.
func getContentUpdatePolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
) (*models.ContentUpdatePolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	res, err := client.ContentUpdatePolicies.GetContentUpdatePolicies(
		&content_update_policies.GetContentUpdatePoliciesParams{
			Context: ctx,
			Ids:     []string{policyID},
		},
	)

	if err != nil {
		diags.AddError(
			"Error reading content update policy",
			"Could not read content update policy: "+policyID+": "+err.Error(),
		)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Content update policy not found",
			fmt.Sprintf("Content update policy with ID %s not found", policyID),
		)
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}
