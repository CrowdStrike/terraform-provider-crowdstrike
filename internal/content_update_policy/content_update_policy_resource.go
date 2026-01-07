package contentupdatepolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &contentPolicyResource{}
	_ resource.ResourceWithConfigure      = &contentPolicyResource{}
	_ resource.ResourceWithImportState    = &contentPolicyResource{}
	_ resource.ResourceWithValidateConfig = &contentPolicyResource{}
	_ resource.ResourceWithModifyPlan     = &contentPolicyResource{}
)

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

	// Direct access - no intermediate wrapper
	sensorOperations        ringAssignmentModel `tfsdk:"-"`
	systemCritical          ringAssignmentModel `tfsdk:"-"`
	vulnerabilityManagement ringAssignmentModel `tfsdk:"-"`
	rapidResponse           ringAssignmentModel `tfsdk:"-"`
}

// extract extracts the Go values from their terraform wrapped values.
func (d *contentPolicyResourceModel) extract(ctx context.Context) diag.Diagnostics {
	var diags diag.Diagnostics

	// Extract sensor operations
	if !d.SensorOperations.IsNull() {
		sensorOpsDiags := d.SensorOperations.As(ctx, &d.sensorOperations, basetypes.ObjectAsOptions{})
		diags.Append(sensorOpsDiags...)
	}

	// Extract system critical
	if !d.SystemCritical.IsNull() {
		systemCritDiags := d.SystemCritical.As(ctx, &d.systemCritical, basetypes.ObjectAsOptions{})
		diags.Append(systemCritDiags...)
	}

	// Extract vulnerability management
	if !d.VulnerabilityManagement.IsNull() {
		vulnMgmtDiags := d.VulnerabilityManagement.As(ctx, &d.vulnerabilityManagement, basetypes.ObjectAsOptions{})
		diags.Append(vulnMgmtDiags...)
	}

	// Extract rapid response
	if !d.RapidResponse.IsNull() {
		rapidRespDiags := d.RapidResponse.As(ctx, &d.rapidResponse, basetypes.ObjectAsOptions{})
		diags.Append(rapidRespDiags...)
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

	// Update ring assignments using the settings from the API response
	if policy.Settings != nil && policy.Settings.RingAssignmentSettings != nil {
		for _, setting := range policy.Settings.RingAssignmentSettings {
			switch *setting.ID {
			case "sensor_operations":
				if !d.SensorOperations.IsNull() {
					d.SensorOperations.As(
						ctx,
						&d.sensorOperations,
						basetypes.ObjectAsOptions{},
					)
				}
				d.sensorOperations.wrap(setting)
			case "system_critical":
				if !d.SystemCritical.IsNull() {
					d.SystemCritical.As(
						ctx,
						&d.systemCritical,
						basetypes.ObjectAsOptions{},
					)
				}
				d.systemCritical.wrap(setting)
			case "vulnerability_management":
				if !d.VulnerabilityManagement.IsNull() {
					d.VulnerabilityManagement.As(
						ctx,
						&d.vulnerabilityManagement,
						basetypes.ObjectAsOptions{},
					)
				}
				d.vulnerabilityManagement.wrap(setting)
			case "rapid_response_al_bl_listing":
				if !d.RapidResponse.IsNull() {
					d.RapidResponse.As(
						ctx,
						&d.rapidResponse,
						basetypes.ObjectAsOptions{},
					)
				}
				d.rapidResponse.wrap(setting)
			}
		}
	}

	// Convert ring assignment models to terraform objects
	if !d.systemCritical.RingAssignment.IsNull() {
		systemCriticalObj, systemCriticalDiags := utils.ConvertModelToTerraformObject(
			ctx,
			&d.systemCritical,
		)
		d.SystemCritical = systemCriticalObj
		diags.Append(systemCriticalDiags...)
	}

	if !d.sensorOperations.RingAssignment.IsNull() {
		sensorOperationsObj, sensorOperationsDiags := utils.ConvertModelToTerraformObject(
			ctx,
			&d.sensorOperations,
		)
		d.SensorOperations = sensorOperationsObj
		diags.Append(sensorOperationsDiags...)
	}

	if !d.rapidResponse.RingAssignment.IsNull() {
		rapidResponseObj, rapidResponseDiags := utils.ConvertModelToTerraformObject(
			ctx,
			&d.rapidResponse,
		)
		d.RapidResponse = rapidResponseObj
		diags.Append(rapidResponseDiags...)
	}

	if !d.vulnerabilityManagement.RingAssignment.IsNull() {
		vulnerabilityMgmtObj, vulnerabilityMgmtDiags := utils.ConvertModelToTerraformObject(
			ctx,
			&d.vulnerabilityManagement,
		)
		d.VulnerabilityManagement = vulnerabilityMgmtObj
		diags.Append(vulnerabilityMgmtDiags...)
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

	config, ok := req.ProviderData.(config.ProviderConfig)

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

	r.client = config.Client
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
			scopes.GenerateScopeDescription(apiScopesReadWrite),
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
						Validators:  ringAssignmentValidators()["ring_assignment"],
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators:  delayHoursValidators(),
					},
					"pinned_content_version": schema.StringAttribute{
						Optional:    true,
						Description: "Pin content category to a specific version. When set, the content category will not automatically update to newer versions.",
						Validators: []validator.String{
							stringvalidator.LengthAtLeast(1),
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
						Validators:  ringAssignmentValidators()["system_critical"],
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators:  delayHoursValidators(),
					},
					"pinned_content_version": schema.StringAttribute{
						Optional:    true,
						Description: "Pin content category to a specific version. When set, the content category will not automatically update to newer versions.",
						Validators: []validator.String{
							stringvalidator.LengthAtLeast(1),
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
						Validators:  ringAssignmentValidators()["ring_assignment"],
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators:  delayHoursValidators(),
					},
					"pinned_content_version": schema.StringAttribute{
						Optional:    true,
						Description: "Pin content category to a specific version. When set, the content category will not automatically update to newer versions.",
						Validators: []validator.String{
							stringvalidator.LengthAtLeast(1),
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
						Validators:  ringAssignmentValidators()["ring_assignment"],
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators:  delayHoursValidators(),
					},
					"pinned_content_version": schema.StringAttribute{
						Optional:    true,
						Description: "Pin content category to a specific version. When set, the content category will not automatically update to newer versions.",
						Validators: []validator.String{
							stringvalidator.LengthAtLeast(1),
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
	tflog.Trace(ctx, "Starting content update policy create")

	var plan contentPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build ring assignment settings using shared function with individual fields
	ringAssignmentSettings := buildRingAssignmentSettings(
		ctx,
		plan.sensorOperations,
		plan.systemCritical,
		plan.vulnerabilityManagement,
		plan.rapidResponse,
	)

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

	tflog.Debug(ctx, "Calling CrowdStrike API to create content update policy")
	res, err := r.client.ContentUpdatePolicies.CreateContentUpdatePolicies(&policyParams)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating content update policy",
			"Could not create content update policy, unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Info(ctx, "Successfully created content update policy", map[string]interface{}{
		"policy_id": *res.Payload.Resources[0].ID,
	})

	policy := res.Payload.Resources[0]

	plan.ID = types.StringValue(*policy.ID)
	plan.LastUpdated = utils.GenerateUpdateTimestamp()

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Enabled.ValueBool() {
		err := updatePolicyEnabledState(ctx, r.client, plan.ID.ValueString(), true)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error enabling content update policy",
				"Could not enable content update policy, unexpected error: "+err.Error(),
			)
			return
		}
	}

	if len(plan.HostGroups.Elements()) > 0 {
		emptySet := types.SetNull(types.StringType)
		resp.Diagnostics.Append(
			syncHostGroups(ctx, r.client, plan.HostGroups, emptySet, plan.ID.ValueString())...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	assignments := categoryAssignments{
		sensorOperations: pinnedContentVersion{
			state: types.StringNull(),
			plan:  plan.sensorOperations.PinnedContentVersion,
		},
		systemCritical: pinnedContentVersion{
			state: types.StringNull(),
			plan:  plan.systemCritical.PinnedContentVersion,
		},
		vulnerabilityManagement: pinnedContentVersion{
			state: types.StringNull(),
			plan:  plan.vulnerabilityManagement.PinnedContentVersion,
		},
		rapidResponse: pinnedContentVersion{
			state: types.StringNull(),
			plan:  plan.rapidResponse.PinnedContentVersion,
		},
	}

	resp.Diagnostics.Append(setPinnedContentVersions(ctx, r.client, plan.ID.ValueString(), assignments)...)
	if resp.Diagnostics.HasError() {
		return
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
	tflog.Trace(ctx, "Starting content update policy read")

	var state contentPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Retrieving content update policy", map[string]interface{}{
		"policy_id": state.ID.ValueString(),
	})
	policy, diags := getContentUpdatePolicy(ctx, r.client, state.ID.ValueString())
	if diags.HasError() {
		for _, diag := range diags {
			if strings.Contains(diag.Summary(), "not found") {
				resp.State.RemoveResource(ctx)
				return
			}
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, *policy, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *contentPolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	tflog.Trace(ctx, "Starting content update policy update")

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

	resp.Diagnostics.Append(
		syncHostGroups(ctx, r.client, plan.HostGroups, state.HostGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	assignments := categoryAssignments{
		sensorOperations: pinnedContentVersion{
			state: state.sensorOperations.PinnedContentVersion,
			plan:  plan.sensorOperations.PinnedContentVersion,
		},
		systemCritical: pinnedContentVersion{
			state: state.systemCritical.PinnedContentVersion,
			plan:  plan.systemCritical.PinnedContentVersion,
		},
		vulnerabilityManagement: pinnedContentVersion{
			state: state.vulnerabilityManagement.PinnedContentVersion,
			plan:  plan.vulnerabilityManagement.PinnedContentVersion,
		},
		rapidResponse: pinnedContentVersion{
			state: state.rapidResponse.PinnedContentVersion,
			plan:  plan.rapidResponse.PinnedContentVersion,
		},
	}

	resp.Diagnostics.Append(removePinnedContentVersions(ctx, r.client, plan.ID.ValueString(), assignments)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ringAssignmentSettings := buildRingAssignmentSettings(
		ctx,
		plan.sensorOperations,
		plan.systemCritical,
		plan.vulnerabilityManagement,
		plan.rapidResponse,
	)

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

	resp.Diagnostics.Append(setPinnedContentVersions(ctx, r.client, plan.ID.ValueString(), assignments)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Enabled.ValueBool() != state.Enabled.ValueBool() {
		err = updatePolicyEnabledState(
			ctx,
			r.client,
			plan.ID.ValueString(),
			plan.Enabled.ValueBool(),
		)
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

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, *policy, true)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *contentPolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	tflog.Trace(ctx, "Starting content update policy delete")

	var state contentPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Disabling content update policy before deletion", map[string]interface{}{
		"policy_id": state.ID.ValueString(),
	})
	err := updatePolicyEnabledState(ctx, r.client, state.ID.ValueString(), false)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
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

	if !config.sensorOperations.RingAssignment.IsNull() {
		if config.sensorOperations.RingAssignment.ValueString() != "ga" &&
			!config.sensorOperations.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("sensor_operations").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf(
					"delay_hours can only be set when ring_assignment is 'ga'. sensor_operations has ring_assignment '%s' but delay_hours is set.",
					config.sensorOperations.RingAssignment.ValueString(),
				),
			)
		}
	}

	if !config.systemCritical.RingAssignment.IsNull() {
		if config.systemCritical.RingAssignment.ValueString() != "ga" &&
			!config.systemCritical.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("system_critical").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf(
					"delay_hours can only be set when ring_assignment is 'ga'. system_critical has ring_assignment '%s' but delay_hours is set.",
					config.systemCritical.RingAssignment.ValueString(),
				),
			)
		}
	}

	if !config.vulnerabilityManagement.RingAssignment.IsNull() {
		if config.vulnerabilityManagement.RingAssignment.ValueString() != "ga" &&
			!config.vulnerabilityManagement.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("vulnerability_management").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf(
					"delay_hours can only be set when ring_assignment is 'ga'. vulnerability_management has ring_assignment '%s' but delay_hours is set.",
					config.vulnerabilityManagement.RingAssignment.ValueString(),
				),
			)
		}
	}

	if !config.rapidResponse.RingAssignment.IsNull() {
		if config.rapidResponse.RingAssignment.ValueString() != "ga" &&
			!config.rapidResponse.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("rapid_response").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf(
					"delay_hours can only be set when ring_assignment is 'ga'. rapid_response has ring_assignment '%s' but delay_hours is set.",
					config.rapidResponse.RingAssignment.ValueString(),
				),
			)
		}
	}
}

// ModifyPlan runs during the plan phase to validate changes between current state and planned configuration.
func (r *contentPolicyResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	// Check if this is a resource creation (state is null)
	if req.State.Raw.IsNull() {
		return
	}

	// Check if this is a resource destruction (plan is null)
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan contentPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if the plan contains the required objects before attempting extraction
	if plan.SensorOperations.IsNull() || plan.SystemCritical.IsNull() ||
		plan.VulnerabilityManagement.IsNull() || plan.RapidResponse.IsNull() {
		return
	}

	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state contentPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if the state contains the required objects before attempting extraction
	if state.SensorOperations.IsNull() || state.SystemCritical.IsNull() ||
		state.VulnerabilityManagement.IsNull() || state.RapidResponse.IsNull() {
		return
	}

	resp.Diagnostics.Append(state.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	validationDiags := validateContentUpdatePolicyModifyPlan(
		ctx,
		state.sensorOperations,
		state.systemCritical,
		state.vulnerabilityManagement,
		state.rapidResponse,
		plan.sensorOperations,
		plan.systemCritical,
		plan.vulnerabilityManagement,
		plan.rapidResponse,
	)
	resp.Diagnostics.Append(validationDiags...)
}
