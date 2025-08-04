package sensorvisibilityexclusion

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_visibility_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
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
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &sensorVisibilityExclusionResource{}
	_ resource.ResourceWithConfigure      = &sensorVisibilityExclusionResource{}
	_ resource.ResourceWithImportState    = &sensorVisibilityExclusionResource{}
	_ resource.ResourceWithValidateConfig = &sensorVisibilityExclusionResource{}
)

var apiScopes = []scopes.Scope{
	{
		Name:  "Sensor Visibility Exclusions",
		Read:  true,
		Write: true,
	},
}

// NewSensorVisibilityExclusionResource is a helper function to simplify the provider implementation.
func NewSensorVisibilityExclusionResource() resource.Resource {
	return &sensorVisibilityExclusionResource{}
}

// sensorVisibilityExclusionResource is the resource implementation.
type sensorVisibilityExclusionResource struct {
	client *client.CrowdStrikeAPISpecification
}

// SensorVisibilityExclusionResourceModel maps the resource schema data.
type SensorVisibilityExclusionResourceModel struct {
	ID                         types.String `tfsdk:"id"`
	Value                      types.String `tfsdk:"value"`
	ApplyToDescendantProcesses types.Bool   `tfsdk:"apply_to_descendant_processes"`
	ApplyGlobally              types.Bool   `tfsdk:"apply_globally"`
	HostGroups                 types.Set    `tfsdk:"host_groups"`
	RegexpValue                types.String `tfsdk:"regexp_value"`
	ValueHash                  types.String `tfsdk:"value_hash"`
	LastModified               types.String `tfsdk:"last_modified"`
	ModifiedBy                 types.String `tfsdk:"modified_by"`
	CreatedOn                  types.String `tfsdk:"created_on"`
	CreatedBy                  types.String `tfsdk:"created_by"`
	LastUpdated                types.String `tfsdk:"last_updated"`
}

// getSensorVisibilityExclusion retrieves a sensor visibility exclusion from the API.
func (r *sensorVisibilityExclusionResource) getSensorVisibilityExclusion(
	ctx context.Context,
	exclusionID string,
) (*models.SvExclusionsSVExclusionV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := sensor_visibility_exclusions.NewGetSensorVisibilityExclusionsV1ParamsWithContext(ctx)
	params.SetIds([]string{exclusionID})

	tflog.Debug(ctx, "Calling CrowdStrike API to get sensor visibility exclusion", map[string]any{
		"exclusion_id": exclusionID,
	})

	getResp, err := r.client.SensorVisibilityExclusions.GetSensorVisibilityExclusionsV1(params)
	if err != nil {
		diags.AddError(
			"Unable to Read Sensor Visibility Exclusion",
			"An error occurred while reading the sensor visibility exclusion. "+
				"Original Error: "+err.Error(),
		)
		return nil, diags
	}

	if getResp == nil || getResp.Payload == nil || len(getResp.Payload.Resources) == 0 {
		diags.AddError(
			"Sensor Visibility Exclusion Not Found",
			"The sensor visibility exclusion was not found or the API returned no resources.",
		)
		return nil, diags
	}

	return getResp.Payload.Resources[0], diags
}

// wrap transforms the API response data to Terraform model values.
// This follows the same pattern as content_update_policy's wrap method.
func (m *SensorVisibilityExclusionResourceModel) wrap(
	ctx context.Context,
	exclusion *models.SvExclusionsSVExclusionV1,
	validateHostGroups bool,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(exclusion.ID)
	m.Value = types.StringPointerValue(exclusion.Value)
	m.RegexpValue = types.StringPointerValue(exclusion.RegexpValue)
	m.ValueHash = types.StringPointerValue(exclusion.ValueHash)
	m.ApplyGlobally = types.BoolPointerValue(exclusion.AppliedGlobally)
	m.LastModified = types.StringValue(exclusion.LastModified.String())
	m.ModifiedBy = types.StringPointerValue(exclusion.ModifiedBy)
	m.CreatedOn = types.StringValue(exclusion.CreatedOn.String())
	m.CreatedBy = types.StringPointerValue(exclusion.CreatedBy)
	m.ApplyToDescendantProcesses = types.BoolPointerValue(&exclusion.IsDescendantProcess)

	// Convert API groups to terraform set
	groupsSet, groupsDiags := hostgroups.ConvertHostGroupsToSet(ctx, exclusion.Groups)
	diags.Append(groupsDiags...)
	if diags.HasError() {
		tflog.Error(ctx, "Failed to convert groups to terraform set", map[string]any{
			"groups": exclusion.Groups,
		})
		return diags
	}

	if validateHostGroups {
		exclusionGroups := make([]string, 0, len(exclusion.Groups))
		modelGroups := make([]string, 0, len(m.HostGroups.Elements()))

		if len(exclusion.Groups) > 0 {
			for _, hostGroup := range exclusion.Groups {
				exclusionGroups = append(exclusionGroups, *hostGroup.ID)
			}
		}

		diags.Append(m.HostGroups.ElementsAs(ctx, &modelGroups, true)...)

		if modelGroups == nil {
			modelGroups = []string{}
		}

		if exclusionGroups == nil {
			exclusionGroups = []string{}
		}

		less := func(a, b string) bool { return a < b }
		hostGroupDiff := cmp.Diff(exclusionGroups, modelGroups, cmpopts.SortSlices(less))
		if hostGroupDiff != "" {
			summary := "Apply ran without issue, but sensor visibility exclusion is still missing host groups. This usually happens when an invalid host group is provided."

			if len(exclusionGroups) > 0 {
				summary = fmt.Sprintf(
					"%s\n\nThe following host groups are valid and assigned to the sensor visibility exclusion:\n\n%s",
					summary,
					strings.Join(exclusionGroups, "\n"),
				)
			}
			diags.AddAttributeError(path.Root("host_groups"), "Host group mismatch", summary)
		}
	}

	// allow host_groups to stay null instead of defaulting to an empty set when there are no host groups
	if !m.HostGroups.IsNull() || len(groupsSet.Elements()) != 0 {
		m.HostGroups = groupsSet
	}

	return diags
}

// Configure adds the provider configured client to the resource.
func (r *sensorVisibilityExclusionResource) Configure(
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
func (r *sensorVisibilityExclusionResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_sensor_visibility_exclusion"
}

// Schema defines the schema for the resource.
func (r *sensorVisibilityExclusionResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Sensor Visibility Exclusion --- This resource allows you to manage sensor visibility exclusions in the CrowdStrike Falcon Platform.\n\n"+
				"Sensor visibility exclusions stop all sensor event collection, detections, and preventions for the specified file paths. "+
				"Use with extreme caution as malware or attacks will not be recorded, detected, or prevented in excluded paths.\n\n%s",
			scopes.GenerateScopeDescription(apiScopes),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The unique identifier for the sensor visibility exclusion.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The RFC850 timestamp of the last update to this resource by Terraform.",
			},
			"value": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The file path or pattern to exclude from sensor visibility. Use wildcards (*) for pattern matching.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"apply_to_descendant_processes": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to apply the exclusion to all descendant processes spawned from the specified path. Defaults to `false`.",
			},
			"apply_globally": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether to apply the exclusion globally to all host groups. Cannot be used together with `host_groups`.",
				Default:             booldefault.StaticBool(false),
			},
			"host_groups": schema.SetAttribute{
				Optional:            true,
				MarkdownDescription: "A set of host group IDs to apply this exclusion to. Cannot be used together with `apply_globally`.",
				ElementType:         types.StringType,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
				},
			},
			"regexp_value": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The regular expression representation of the exclusion value.",
			},
			"value_hash": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The hash of the exclusion value.",
			},
			"last_modified": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when the exclusion was last modified.",
			},
			"modified_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who last modified the exclusion.",
			},
			"created_on": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when the exclusion was created.",
			},
			"created_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who created the exclusion.",
			},
		},
	}
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *sensorVisibilityExclusionResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config SensorVisibilityExclusionResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.ApplyGlobally.IsUnknown() || config.HostGroups.IsUnknown() {
		return
	}

	// Validate that either apply_globally is true OR host_groups is provided, but not both
	hasApplyGlobally := config.ApplyGlobally.ValueBool()
	hasHostGroups := len(config.HostGroups.Elements()) > 0

	if hasApplyGlobally && hasHostGroups {
		resp.Diagnostics.AddAttributeError(
			path.Root("apply_globally"),
			"Invalid Configuration",
			"Cannot specify both apply_globally=true and host_groups. Please use either apply_globally=true for global exclusions or provide specific host_groups.",
		)
		return
	}

	if !hasApplyGlobally && !hasHostGroups {
		resp.Diagnostics.AddAttributeError(
			path.Root("apply_globally"),
			"Invalid Configuration",
			"Must specify either apply_globally=true or provide host_groups. The exclusion must target either all host groups or specific ones.",
		)
		return
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *sensorVisibilityExclusionResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan SensorVisibilityExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to get plan data for sensor visibility exclusion creation")
		return
	}

	tflog.Info(ctx, "Starting sensor visibility exclusion creation", map[string]any{
		"value":                         plan.Value.ValueString(),
		"apply_to_descendant_processes": plan.ApplyToDescendantProcesses.ValueBool(),
		"apply_globally":                plan.ApplyGlobally.ValueBool(),
		"host_groups_configured":        !plan.HostGroups.IsNull() && !plan.HostGroups.IsUnknown(),
	})

	var groups []string
	if plan.ApplyGlobally.ValueBool() {
		groups = []string{"all"}
		tflog.Debug(ctx, "Applying exclusion globally due to apply_globally=true", map[string]any{
			"groups": groups,
		})
	} else {
		// Extract host groups from plan
		var groupsList []string
		resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &groupsList, false)...)
		if resp.Diagnostics.HasError() {
			tflog.Error(ctx, "Failed to extract host groups from plan", map[string]any{
				"host_groups_null":    plan.HostGroups.IsNull(),
				"host_groups_unknown": plan.HostGroups.IsUnknown(),
			})
			return
		}
		groups = groupsList
		tflog.Debug(ctx, "Using specific host groups for exclusion", map[string]any{
			"groups_count": len(groups),
			"groups":       groups,
		})
	}

	createReq := &models.SvExclusionsCreateReqV1{
		Value:               plan.Value.ValueString(),
		Comment:             "created by terraform crowdstrike provider",
		Groups:              groups,
		IsDescendantProcess: plan.ApplyToDescendantProcesses.ValueBool(),
	}

	tflog.Debug(ctx, "Preparing API create request", map[string]any{
		"request_value":                 createReq.Value,
		"request_comment":               createReq.Comment,
		"request_groups":                createReq.Groups,
		"request_is_descendant_process": createReq.IsDescendantProcess,
	})

	params := sensor_visibility_exclusions.NewCreateSVExclusionsV1ParamsWithContext(ctx)
	params.SetBody(createReq)

	tflog.Debug(ctx, "Calling CrowdStrike API to create sensor visibility exclusion")
	createResp, err := r.client.SensorVisibilityExclusions.CreateSVExclusionsV1(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create Sensor Visibility Exclusion",
			"An error occurred while creating the sensor visibility exclusion. "+
				"Original Error: "+err.Error(),
		)
		return
	}

	if createResp == nil || createResp.Payload == nil || len(createResp.Payload.Resources) == 0 {
		tflog.Error(
			ctx,
			"API returned empty or invalid response for sensor visibility exclusion creation",
			map[string]any{
				"response_nil": createResp == nil,
				"payload_nil":  createResp != nil && createResp.Payload == nil,
				"resources_empty": createResp != nil && createResp.Payload != nil &&
					len(createResp.Payload.Resources) == 0,
			},
		)
		resp.Diagnostics.AddError(
			"Unable to Create Sensor Visibility Exclusion",
			"An error occurred while creating the sensor visibility exclusion. No resource was returned.",
		)
		return
	}

	createdExclusion := createResp.Payload.Resources[0]

	tflog.Info(ctx, "Successfully created sensor visibility exclusion", map[string]any{
		"exclusion_id":     *createdExclusion.ID,
		"exclusion_value":  *createdExclusion.Value,
		"regexp_value":     *createdExclusion.RegexpValue,
		"value_hash":       *createdExclusion.ValueHash,
		"applied_globally": *createdExclusion.AppliedGlobally,
		"created_by":       *createdExclusion.CreatedBy,
		"created_on":       createdExclusion.CreatedOn.String(),
	})

	// Get the exclusion to ensure we have the correct type for the wrap method
	exclusion, exclusionDiags := r.getSensorVisibilityExclusion(ctx, *createdExclusion.ID)
	resp.Diagnostics.Append(exclusionDiags...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to get exclusion after creation", map[string]any{
			"exclusion_id": *createdExclusion.ID,
		})
		return
	}

	// Use the centralized wrap method
	resp.Diagnostics.Append(plan.wrap(ctx, exclusion, true)...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to map API response to model", map[string]any{
			"exclusion_id": *exclusion.ID,
		})
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()

	tflog.Debug(ctx, "Setting final state for sensor visibility exclusion")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to set state for sensor visibility exclusion")
		return
	}

	tflog.Info(ctx, "Sensor visibility exclusion creation completed successfully", map[string]any{
		"exclusion_id": plan.ID.ValueString(),
	})
}

// Read refreshes the Terraform state with the latest data.
func (r *sensorVisibilityExclusionResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state SensorVisibilityExclusionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to get state data for sensor visibility exclusion read")
		return
	}

	exclusionID := state.ID.ValueString()
	tflog.Info(ctx, "Starting sensor visibility exclusion read", map[string]any{
		"exclusion_id": exclusionID,
	})

	exclusion, diags := r.getSensorVisibilityExclusion(ctx, exclusionID)
	if diags.HasError() {
		for _, diag := range diags {
			if strings.Contains(diag.Summary(), "not found") {
				tflog.Warn(ctx, "Sensor visibility exclusion not found, removing from state", map[string]any{
					"exclusion_id": exclusionID,
				})
				resp.State.RemoveResource(ctx)
				return
			}
		}
		tflog.Error(ctx, "Failed to get sensor visibility exclusion", map[string]any{
			"exclusion_id": exclusionID,
		})
		resp.Diagnostics.Append(diags...)
		return
	}

	tflog.Debug(ctx, "Successfully retrieved sensor visibility exclusion from API", map[string]any{
		"exclusion_id":     *exclusion.ID,
		"exclusion_value":  *exclusion.Value,
		"regexp_value":     *exclusion.RegexpValue,
		"value_hash":       *exclusion.ValueHash,
		"applied_globally": *exclusion.AppliedGlobally,
		"last_modified":    exclusion.LastModified.String(),
		"modified_by":      *exclusion.ModifiedBy,
		"created_on":       exclusion.CreatedOn.String(),
		"created_by":       *exclusion.CreatedBy,
	})

	// Use the centralized wrap method
	resp.Diagnostics.Append(state.wrap(ctx, exclusion, false)...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to map API response to model", map[string]any{
			"exclusion_id": *exclusion.ID,
		})
		return
	}

	tflog.Debug(ctx, "Setting updated state for sensor visibility exclusion")
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to set state for sensor visibility exclusion read")
		return
	}

	tflog.Info(ctx, "Sensor visibility exclusion read completed successfully", map[string]any{
		"exclusion_id": exclusionID,
	})
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *sensorVisibilityExclusionResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan SensorVisibilityExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to get plan data for sensor visibility exclusion update")
		return
	}

	exclusionID := plan.ID.ValueString()
	tflog.Info(ctx, "Starting sensor visibility exclusion update", map[string]any{
		"exclusion_id":                  exclusionID,
		"value":                         plan.Value.ValueString(),
		"apply_to_descendant_processes": plan.ApplyToDescendantProcesses.ValueBool(),
		"apply_globally":                plan.ApplyGlobally.ValueBool(),
		"host_groups_configured":        !plan.HostGroups.IsNull() && !plan.HostGroups.IsUnknown(),
	})

	// Determine host groups based on apply_globally flag
	var groups []string
	if plan.ApplyGlobally.ValueBool() {
		groups = []string{"all"}
		tflog.Debug(ctx, "Applying exclusion globally due to apply_globally=true", map[string]any{
			"exclusion_id": exclusionID,
			"groups":       groups,
		})
	} else {
		// Extract host groups from plan
		var groupsList []string
		resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &groupsList, false)...)
		if resp.Diagnostics.HasError() {
			tflog.Error(ctx, "Failed to extract host groups from plan for update", map[string]any{
				"exclusion_id":        exclusionID,
				"host_groups_null":    plan.HostGroups.IsNull(),
				"host_groups_unknown": plan.HostGroups.IsUnknown(),
			})
			return
		}
		groups = groupsList
		tflog.Debug(ctx, "Using specific host groups for exclusion update", map[string]any{
			"exclusion_id": exclusionID,
			"groups_count": len(groups),
			"groups":       groups,
		})
	}

	id := plan.ID.ValueString()
	updateReq := &models.SvExclusionsUpdateReqV1{
		ID:                  &id,
		Value:               plan.Value.ValueString(),
		Comment:             "updated by terraform crowdstrike provider",
		Groups:              groups,
		IsDescendantProcess: plan.ApplyToDescendantProcesses.ValueBool(),
	}

	tflog.Debug(ctx, "Preparing API update request", map[string]any{
		"exclusion_id":                  exclusionID,
		"request_value":                 updateReq.Value,
		"request_comment":               updateReq.Comment,
		"request_groups":                updateReq.Groups,
		"request_is_descendant_process": updateReq.IsDescendantProcess,
	})

	params := sensor_visibility_exclusions.NewUpdateSensorVisibilityExclusionsV1ParamsWithContext(
		ctx,
	)
	params.SetBody(updateReq)

	tflog.Debug(
		ctx,
		"Calling CrowdStrike API to update sensor visibility exclusion",
		map[string]any{
			"exclusion_id": exclusionID,
		},
	)

	updateResp, err := r.client.SensorVisibilityExclusions.UpdateSensorVisibilityExclusionsV1(
		params,
	)
	if err != nil {
		tflog.Error(ctx, "API call failed for sensor visibility exclusion update", map[string]any{
			"exclusion_id": exclusionID,
			"error":        err.Error(),
		})

		resp.Diagnostics.AddError(
			"Unable to Update Sensor Visibility Exclusion",
			"An error occurred while updating the sensor visibility exclusion. "+
				"Original Error: "+err.Error(),
		)
		return
	}

	if updateResp == nil || updateResp.Payload == nil || len(updateResp.Payload.Resources) == 0 {
		tflog.Error(
			ctx,
			"API returned empty or invalid response for sensor visibility exclusion update",
			map[string]any{
				"exclusion_id": exclusionID,
				"response_nil": updateResp == nil,
				"payload_nil":  updateResp != nil && updateResp.Payload == nil,
				"resources_empty": updateResp != nil && updateResp.Payload != nil &&
					len(updateResp.Payload.Resources) == 0,
			},
		)
		resp.Diagnostics.AddError(
			"Unable to Update Sensor Visibility Exclusion",
			"An error occurred while updating the sensor visibility exclusion. No resource was returned.",
		)
		return
	}

	updatedExclusion := updateResp.Payload.Resources[0]

	tflog.Info(ctx, "Successfully updated sensor visibility exclusion", map[string]any{
		"exclusion_id":     *updatedExclusion.ID,
		"exclusion_value":  *updatedExclusion.Value,
		"regexp_value":     *updatedExclusion.RegexpValue,
		"value_hash":       *updatedExclusion.ValueHash,
		"applied_globally": *updatedExclusion.AppliedGlobally,
		"modified_by":      *updatedExclusion.ModifiedBy,
		"last_modified":    updatedExclusion.LastModified.String(),
	})

	// Get the exclusion to ensure we have the correct type for the wrap method
	exclusion, exclusionDiags := r.getSensorVisibilityExclusion(ctx, *updatedExclusion.ID)
	resp.Diagnostics.Append(exclusionDiags...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to get exclusion after update", map[string]any{
			"exclusion_id": *updatedExclusion.ID,
		})
		return
	}

	// Use the centralized wrap method
	resp.Diagnostics.Append(plan.wrap(ctx, exclusion, true)...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to map API response to model", map[string]any{
			"exclusion_id": *exclusion.ID,
		})
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()

	tflog.Debug(ctx, "Setting updated state for sensor visibility exclusion")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to set state for sensor visibility exclusion update")
		return
	}

	tflog.Info(ctx, "Sensor visibility exclusion update completed successfully", map[string]any{
		"exclusion_id": exclusionID,
	})
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *sensorVisibilityExclusionResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state SensorVisibilityExclusionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to get state data for sensor visibility exclusion deletion")
		return
	}

	exclusionID := state.ID.ValueString()
	tflog.Info(ctx, "Starting sensor visibility exclusion deletion", map[string]any{
		"exclusion_id":    exclusionID,
		"exclusion_value": state.Value.ValueString(),
	})

	params := sensor_visibility_exclusions.NewDeleteSensorVisibilityExclusionsV1ParamsWithContext(
		ctx,
	)
	params.SetIds([]string{exclusionID})

	tflog.Debug(
		ctx,
		"Calling CrowdStrike API to delete sensor visibility exclusion",
		map[string]any{
			"exclusion_id": exclusionID,
		},
	)

	deleteResp, err := r.client.SensorVisibilityExclusions.DeleteSensorVisibilityExclusionsV1(
		params,
	)
	if err != nil {
		tflog.Error(ctx, "API call failed for sensor visibility exclusion deletion", map[string]any{
			"exclusion_id": exclusionID,
			"error":        err.Error(),
		})
		resp.Diagnostics.AddError(
			"Unable to Delete Sensor Visibility Exclusion",
			"An error occurred while deleting the sensor visibility exclusion. "+
				"Original Error: "+err.Error(),
		)
		return
	}

	if deleteResp != nil && deleteResp.Payload != nil {
		tflog.Debug(ctx, "Delete API response received", map[string]any{
			"exclusion_id":      exclusionID,
			"response_received": true,
		})
	}

	tflog.Info(ctx, "Sensor visibility exclusion deleted successfully", map[string]any{
		"exclusion_id": exclusionID,
	})
}

// ImportState implements the logic to support resource imports.
func (r *sensorVisibilityExclusionResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	importID := req.ID
	tflog.Info(ctx, "Starting sensor visibility exclusion import", map[string]any{
		"import_id": importID,
	})

	tflog.Debug(ctx, "Validating import ID format", map[string]any{
		"import_id":    importID,
		"id_length":    len(importID),
		"id_non_empty": importID != "",
	})

	if importID == "" {
		tflog.Error(ctx, "Import ID is empty", map[string]any{
			"import_id": importID,
		})
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			"The import ID cannot be empty. Please provide a valid sensor visibility exclusion ID.",
		)
		return
	}

	tflog.Debug(ctx, "Setting imported ID to state", map[string]any{
		"import_id": importID,
	})

	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)

	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to import sensor visibility exclusion", map[string]any{
			"import_id": importID,
		})
		return
	}

	tflog.Info(ctx, "Sensor visibility exclusion import completed successfully", map[string]any{
		"import_id": importID,
	})
}
