package contentupdatepolicy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &defaultContentUpdatePolicyResource{}
	_ resource.ResourceWithConfigure      = &defaultContentUpdatePolicyResource{}
	_ resource.ResourceWithImportState    = &defaultContentUpdatePolicyResource{}
	_ resource.ResourceWithValidateConfig = &defaultContentUpdatePolicyResource{}
	_ resource.ResourceWithModifyPlan     = &defaultContentUpdatePolicyResource{}
)

// NewDefaultContentUpdatePolicyResource is a helper function to simplify the provider implementation.
func NewDefaultContentUpdatePolicyResource() resource.Resource {
	return &defaultContentUpdatePolicyResource{}
}

// defaultContentUpdatePolicyResource is the resource implementation.
type defaultContentUpdatePolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

// defaultContentUpdatePolicyResourceModel is the resource model.
type defaultContentUpdatePolicyResourceModel struct {
	ID                      types.String `tfsdk:"id"`
	Description             types.String `tfsdk:"description"`
	SensorOperations        types.Object `tfsdk:"sensor_operations"`
	SystemCritical          types.Object `tfsdk:"system_critical"`
	VulnerabilityManagement types.Object `tfsdk:"vulnerability_management"`
	RapidResponse           types.Object `tfsdk:"rapid_response"`
	LastUpdated             types.String `tfsdk:"last_updated"`

	// Direct access - no intermediate wrapper
	sensorOperationsSettings        *ringAssignmentModel `tfsdk:"-"`
	systemCriticalSettings          *ringAssignmentModel `tfsdk:"-"`
	vulnerabilityManagementSettings *ringAssignmentModel `tfsdk:"-"`
	rapidResponseSettings           *ringAssignmentModel `tfsdk:"-"`
}

// extract extracts the Go values from their terraform wrapped values.
func (d *defaultContentUpdatePolicyResourceModel) extract(ctx context.Context) diag.Diagnostics {
	var diags diag.Diagnostics

	// Extract sensor operations
	if !d.SensorOperations.IsNull() {
		var sensorOperations ringAssignmentModel
		sensorOpsDiags := d.SensorOperations.As(ctx, &sensorOperations, basetypes.ObjectAsOptions{})
		diags.Append(sensorOpsDiags...)
		if !sensorOpsDiags.HasError() {
			d.sensorOperationsSettings = &sensorOperations
		}
	}

	// Extract system critical
	if !d.SystemCritical.IsNull() {
		var systemCritical ringAssignmentModel
		systemCritDiags := d.SystemCritical.As(ctx, &systemCritical, basetypes.ObjectAsOptions{})
		diags.Append(systemCritDiags...)
		if !systemCritDiags.HasError() {
			d.systemCriticalSettings = &systemCritical
		}
	}

	// Extract vulnerability management
	if !d.VulnerabilityManagement.IsNull() {
		var vulnerabilityManagement ringAssignmentModel
		vulnMgmtDiags := d.VulnerabilityManagement.As(ctx, &vulnerabilityManagement, basetypes.ObjectAsOptions{})
		diags.Append(vulnMgmtDiags...)
		if !vulnMgmtDiags.HasError() {
			d.vulnerabilityManagementSettings = &vulnerabilityManagement
		}
	}

	// Extract rapid response
	if !d.RapidResponse.IsNull() {
		var rapidResponse ringAssignmentModel
		rapidRespDiags := d.RapidResponse.As(ctx, &rapidResponse, basetypes.ObjectAsOptions{})
		diags.Append(rapidRespDiags...)
		if !rapidRespDiags.HasError() {
			d.rapidResponseSettings = &rapidResponse
		}
	}

	return diags
}

// wrap transforms Go values to their terraform wrapped values.
func (d *defaultContentUpdatePolicyResourceModel) wrap(
	ctx context.Context,
	policy models.ContentUpdatePolicyV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	d.ID = types.StringValue(*policy.ID)
	d.Description = types.StringPointerValue(policy.Description)

	// Update ring assignments using the settings from the API response
	if policy.Settings != nil && policy.Settings.RingAssignmentSettings != nil {
		for _, setting := range policy.Settings.RingAssignmentSettings {
			switch *setting.ID {
			case "sensor_operations":
				if d.sensorOperationsSettings == nil {
					d.sensorOperationsSettings = &ringAssignmentModel{}
					if !d.SensorOperations.IsNull() {
						d.SensorOperations.As(ctx, d.sensorOperationsSettings, basetypes.ObjectAsOptions{})
					}
				}
				d.sensorOperationsSettings.wrap(setting)
			case "system_critical":
				if d.systemCriticalSettings == nil {
					d.systemCriticalSettings = &ringAssignmentModel{}
					if !d.SystemCritical.IsNull() {
						d.SystemCritical.As(ctx, d.systemCriticalSettings, basetypes.ObjectAsOptions{})
					}
				}
				d.systemCriticalSettings.wrap(setting)
			case "vulnerability_management":
				if d.vulnerabilityManagementSettings == nil {
					d.vulnerabilityManagementSettings = &ringAssignmentModel{}
					if !d.VulnerabilityManagement.IsNull() {
						d.VulnerabilityManagement.As(ctx, d.vulnerabilityManagementSettings, basetypes.ObjectAsOptions{})
					}
				}
				d.vulnerabilityManagementSettings.wrap(setting)
			case "rapid_response_al_bl_listing":
				if d.rapidResponseSettings == nil {
					d.rapidResponseSettings = &ringAssignmentModel{}
					if !d.RapidResponse.IsNull() {
						d.RapidResponse.As(ctx, d.rapidResponseSettings, basetypes.ObjectAsOptions{})
					}
				}
				d.rapidResponseSettings.wrap(setting)
			}
		}
	}

	// Convert ring assignment models to terraform objects
	if d.systemCriticalSettings != nil {
		systemCriticalObj, systemCriticalDiags := utils.ConvertModelToTerraformObject(ctx, d.systemCriticalSettings)
		d.SystemCritical = systemCriticalObj
		diags.Append(systemCriticalDiags...)
	}

	if d.sensorOperationsSettings != nil {
		sensorOperationsObj, sensorOperationsDiags := utils.ConvertModelToTerraformObject(ctx, d.sensorOperationsSettings)
		d.SensorOperations = sensorOperationsObj
		diags.Append(sensorOperationsDiags...)
	}

	if d.rapidResponseSettings != nil {
		rapidResponseObj, rapidResponseDiags := utils.ConvertModelToTerraformObject(ctx, d.rapidResponseSettings)
		d.RapidResponse = rapidResponseObj
		diags.Append(rapidResponseDiags...)
	}

	if d.vulnerabilityManagementSettings != nil {
		vulnerabilityMgmtObj, vulnerabilityMgmtDiags := utils.ConvertModelToTerraformObject(ctx, d.vulnerabilityManagementSettings)
		d.VulnerabilityManagement = vulnerabilityMgmtObj
		diags.Append(vulnerabilityMgmtDiags...)
	}

	return diags
}

// Configure adds the provider configured client to the resource.
func (r *defaultContentUpdatePolicyResource) Configure(
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
func (r *defaultContentUpdatePolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_default_content_update_policy"
}

// Schema defines the schema for the resource.
func (r *defaultContentUpdatePolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Content Update Policy --- This resource allows management of the default content update policy in the CrowdStrike Falcon platform. Destruction of this resource *will not* delete the default content update policy or remove any configured settings.\n\n%s",
			scopes.GenerateScopeDescription(apiScopesReadWrite),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the default content update policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"description": schema.StringAttribute{
				Required:    true,
				Description: "Description of the default content update policy.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
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

// Create imports the resource into state and configures it. The default resource policy can't be created or deleted.
func (r *defaultContentUpdatePolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	tflog.Trace(ctx, "Starting default content update policy create")

	var plan defaultContentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Retrieving default content update policy")
	policy, diags := r.getDefaultPolicy(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue(*policy.ID)

	resp.Diagnostics.Append(
		resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var currentSensorOps, currentSystemCrit, currentVulnMgmt, currentRapidResp ringAssignmentModel
	if policy.Settings != nil && policy.Settings.RingAssignmentSettings != nil {
		for _, setting := range policy.Settings.RingAssignmentSettings {
			ringModel := ringAssignmentModel{
				RingAssignment: types.StringPointerValue(setting.RingAssignment),
			}

			ringModel.PinnedContentVersion = utils.OptionalString(setting.PinnedContentVersion)

			switch *setting.ID {
			case "sensor_operations":
				currentSensorOps = ringModel
			case "system_critical":
				currentSystemCrit = ringModel
			case "vulnerability_management":
				currentVulnMgmt = ringModel
			case "rapid_response_al_bl_listing":
				currentRapidResp = ringModel
			}
		}
	}

	var plannedSensorOps, plannedSystemCrit, plannedVulnMgmt, plannedRapidResp ringAssignmentModel
	if plan.sensorOperationsSettings != nil {
		plannedSensorOps = *plan.sensorOperationsSettings
	}
	if plan.systemCriticalSettings != nil {
		plannedSystemCrit = *plan.systemCriticalSettings
	}
	if plan.vulnerabilityManagementSettings != nil {
		plannedVulnMgmt = *plan.vulnerabilityManagementSettings
	}
	if plan.rapidResponseSettings != nil {
		plannedRapidResp = *plan.rapidResponseSettings
	}

	assignments := categoryAssignments{
		sensorOperations: pinnedContentVersion{
			state: currentSensorOps.PinnedContentVersion,
			plan:  plannedSensorOps.PinnedContentVersion,
		},
		systemCritical: pinnedContentVersion{
			state: currentSystemCrit.PinnedContentVersion,
			plan:  plannedSystemCrit.PinnedContentVersion,
		},
		vulnerabilityManagement: pinnedContentVersion{
			state: currentVulnMgmt.PinnedContentVersion,
			plan:  plannedVulnMgmt.PinnedContentVersion,
		},
		rapidResponse: pinnedContentVersion{
			state: currentRapidResp.PinnedContentVersion,
			plan:  plannedRapidResp.PinnedContentVersion,
		},
	}

	resp.Diagnostics.Append(removePinnedContentVersions(ctx, r.client, plan.ID.ValueString(), assignments)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.updateDefaultPolicy(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(setPinnedContentVersions(ctx, r.client, plan.ID.ValueString(), assignments)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags = r.getDefaultPolicy(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	resp.Diagnostics.Append(plan.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *defaultContentUpdatePolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	tflog.Trace(ctx, "Starting default content update policy read")

	var state defaultContentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Retrieving default content update policy", map[string]interface{}{
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

	resp.Diagnostics.Append(state.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *defaultContentUpdatePolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	tflog.Trace(ctx, "Starting default content update policy update")

	var plan defaultContentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state defaultContentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(state.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var stateSensorOps, stateSystemCrit, stateVulnMgmt, stateRapidResp ringAssignmentModel
	var plannedSensorOps, plannedSystemCrit, plannedVulnMgmt, plannedRapidResp ringAssignmentModel

	if state.sensorOperationsSettings != nil {
		stateSensorOps = *state.sensorOperationsSettings
	}
	if state.systemCriticalSettings != nil {
		stateSystemCrit = *state.systemCriticalSettings
	}
	if state.vulnerabilityManagementSettings != nil {
		stateVulnMgmt = *state.vulnerabilityManagementSettings
	}
	if state.rapidResponseSettings != nil {
		stateRapidResp = *state.rapidResponseSettings
	}

	if plan.sensorOperationsSettings != nil {
		plannedSensorOps = *plan.sensorOperationsSettings
	}
	if plan.systemCriticalSettings != nil {
		plannedSystemCrit = *plan.systemCriticalSettings
	}
	if plan.vulnerabilityManagementSettings != nil {
		plannedVulnMgmt = *plan.vulnerabilityManagementSettings
	}
	if plan.rapidResponseSettings != nil {
		plannedRapidResp = *plan.rapidResponseSettings
	}

	assignments := categoryAssignments{
		sensorOperations: pinnedContentVersion{
			state: stateSensorOps.PinnedContentVersion,
			plan:  plannedSensorOps.PinnedContentVersion,
		},
		systemCritical: pinnedContentVersion{
			state: stateSystemCrit.PinnedContentVersion,
			plan:  plannedSystemCrit.PinnedContentVersion,
		},
		vulnerabilityManagement: pinnedContentVersion{
			state: stateVulnMgmt.PinnedContentVersion,
			plan:  plannedVulnMgmt.PinnedContentVersion,
		},
		rapidResponse: pinnedContentVersion{
			state: stateRapidResp.PinnedContentVersion,
			plan:  plannedRapidResp.PinnedContentVersion,
		},
	}

	resp.Diagnostics.Append(removePinnedContentVersions(ctx, r.client, plan.ID.ValueString(), assignments)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.updateDefaultPolicy(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(setPinnedContentVersions(ctx, r.client, plan.ID.ValueString(), assignments)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getContentUpdatePolicy(ctx, r.client, state.ID.ValueString())
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	resp.Diagnostics.Append(plan.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *defaultContentUpdatePolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	// We can not delete the default content update policy, so we will just remove it from state.
}

// ImportState implements the logic to support resource imports.
func (r *defaultContentUpdatePolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply to validate resource configuration.
func (r *defaultContentUpdatePolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config defaultContentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(config.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.sensorOperationsSettings != nil {
		if config.sensorOperationsSettings.RingAssignment.ValueString() != "ga" &&
			!config.sensorOperationsSettings.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("sensor_operations").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf(
					"delay_hours can only be set when ring_assignment is 'ga'. sensor_operations has ring_assignment '%s' but delay_hours is set.",
					config.sensorOperationsSettings.RingAssignment.ValueString(),
				),
			)
		}
	}

	if config.systemCriticalSettings != nil {
		if config.systemCriticalSettings.RingAssignment.ValueString() != "ga" &&
			!config.systemCriticalSettings.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("system_critical").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf(
					"delay_hours can only be set when ring_assignment is 'ga'. system_critical has ring_assignment '%s' but delay_hours is set.",
					config.systemCriticalSettings.RingAssignment.ValueString(),
				),
			)
		}
	}

	if config.vulnerabilityManagementSettings != nil {
		if config.vulnerabilityManagementSettings.RingAssignment.ValueString() != "ga" &&
			!config.vulnerabilityManagementSettings.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("vulnerability_management").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf(
					"delay_hours can only be set when ring_assignment is 'ga'. vulnerability_management has ring_assignment '%s' but delay_hours is set.",
					config.vulnerabilityManagementSettings.RingAssignment.ValueString(),
				),
			)
		}
	}

	if config.rapidResponseSettings != nil {
		if config.rapidResponseSettings.RingAssignment.ValueString() != "ga" &&
			!config.rapidResponseSettings.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("rapid_response").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf(
					"delay_hours can only be set when ring_assignment is 'ga'. rapid_response has ring_assignment '%s' but delay_hours is set.",
					config.rapidResponseSettings.RingAssignment.ValueString(),
				),
			)
		}
	}
}

// ModifyPlan runs during the plan phase to validate changes between current state and planned configuration.
func (r *defaultContentUpdatePolicyResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	if req.State.Raw.IsNull() {
		return
	}

	if req.Plan.Raw.IsNull() {
		return
	}

	var plan defaultContentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state defaultContentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(state.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var stateSensorOps, stateSystemCrit, stateVulnMgmt, stateRapidResp ringAssignmentModel
	var planSensorOps, planSystemCrit, planVulnMgmt, planRapidResp ringAssignmentModel

	if state.sensorOperationsSettings != nil {
		stateSensorOps = *state.sensorOperationsSettings
	}
	if state.systemCriticalSettings != nil {
		stateSystemCrit = *state.systemCriticalSettings
	}
	if state.vulnerabilityManagementSettings != nil {
		stateVulnMgmt = *state.vulnerabilityManagementSettings
	}
	if state.rapidResponseSettings != nil {
		stateRapidResp = *state.rapidResponseSettings
	}

	if plan.sensorOperationsSettings != nil {
		planSensorOps = *plan.sensorOperationsSettings
	}
	if plan.systemCriticalSettings != nil {
		planSystemCrit = *plan.systemCriticalSettings
	}
	if plan.vulnerabilityManagementSettings != nil {
		planVulnMgmt = *plan.vulnerabilityManagementSettings
	}
	if plan.rapidResponseSettings != nil {
		planRapidResp = *plan.rapidResponseSettings
	}

	validationDiags := validateContentUpdatePolicyModifyPlan(
		ctx,
		stateSensorOps,
		stateSystemCrit,
		stateVulnMgmt,
		stateRapidResp,
		planSensorOps,
		planSystemCrit,
		planVulnMgmt,
		planRapidResp,
	)
	resp.Diagnostics.Append(validationDiags...)
}

func (r *defaultContentUpdatePolicyResource) updateDefaultPolicy(
	ctx context.Context,
	config *defaultContentUpdatePolicyResourceModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// Build ring assignment settings using individual fields
	var sensorOps, systemCrit, vulnMgmt, rapidResp ringAssignmentModel

	if config.sensorOperationsSettings != nil {
		sensorOps = *config.sensorOperationsSettings
	}
	if config.systemCriticalSettings != nil {
		systemCrit = *config.systemCriticalSettings
	}
	if config.vulnerabilityManagementSettings != nil {
		vulnMgmt = *config.vulnerabilityManagementSettings
	}
	if config.rapidResponseSettings != nil {
		rapidResp = *config.rapidResponseSettings
	}

	ringAssignmentSettings := buildRingAssignmentSettings(
		ctx,
		sensorOps,
		systemCrit,
		vulnMgmt,
		rapidResp,
	)

	policyParams := content_update_policies.UpdateContentUpdatePoliciesParams{
		Context: ctx,
		Body: &models.ContentUpdateUpdatePoliciesReqV1{
			Resources: []*models.ContentUpdateUpdatePolicyReqV1{
				{
					ID:          config.ID.ValueStringPointer(),
					Description: config.Description.ValueString(),
					Settings: &models.ContentUpdateContentUpdateSettingsReqV1{
						RingAssignmentSettings: ringAssignmentSettings,
					},
				},
			},
		},
	}

	_, err := r.client.ContentUpdatePolicies.UpdateContentUpdatePolicies(&policyParams)
	if err != nil {
		diags.AddError(
			"Error updating CrowdStrike default content update policy",
			"Could not update default content update policy with ID: "+config.ID.ValueString()+": "+err.Error(),
		)
		return diags
	}

	return diags
}

func (r *defaultContentUpdatePolicyResource) getDefaultPolicy(
	ctx context.Context,
) (*models.ContentUpdatePolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	sort := "precedence.desc"
	filter := "name.raw:'platform_default'"

	res, err := r.client.ContentUpdatePolicies.QueryCombinedContentUpdatePolicies(
		&content_update_policies.QueryCombinedContentUpdatePoliciesParams{
			Context: ctx,
			Sort:    &sort,
			Filter:  &filter,
		},
	)
	if err != nil {
		diags.AddError(
			"Failed to get default content update policy",
			fmt.Sprintf("Failed to query content update policies: %s", err),
		)

		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Unable to find default content update policy",
			"No content update policies found. A default policy should exist. Please report this issue to the provider developers.",
		)

		return nil, diags
	}

	// Sort by ascending precedence, so the default policy (lowest precedence) is first
	defaultPolicy := res.Payload.Resources[0]

	return defaultPolicy, diags
}
