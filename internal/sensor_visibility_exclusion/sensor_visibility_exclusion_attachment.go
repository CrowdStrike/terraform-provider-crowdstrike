package sensorvisibilityexclusion

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_visibility_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
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

var (
	_ resource.Resource                   = &sensorVisibilityExclusionAttachmentResource{}
	_ resource.ResourceWithConfigure      = &sensorVisibilityExclusionAttachmentResource{}
	_ resource.ResourceWithImportState    = &sensorVisibilityExclusionAttachmentResource{}
	_ resource.ResourceWithValidateConfig = &sensorVisibilityExclusionAttachmentResource{}
)

var (
	attachmentDocumentationSection        string         = "Sensor Visibility Exclusion"
	attachmentResourceMarkdownDescription string         = "This resource allows managing the host groups attached to a sensor visibility exclusion policy. By default (when `exclusive` is true), this resource takes exclusive ownership over the host groups assigned to a sensor visibility exclusion policy. When `exclusive` is false, this resource only manages the specific host groups defined in the configuration. If you want to fully create or manage a sensor visibility exclusion please use the `sensor_visibility_exclusion` resource."
	attachmentRequiredScopes              []scopes.Scope = apiScopes
)

func NewSensorVisibilityExclusionAttachmentResource() resource.Resource {
	return &sensorVisibilityExclusionAttachmentResource{}
}

type sensorVisibilityExclusionAttachmentResource struct {
	client *client.CrowdStrikeAPISpecification
}

type sensorVisibilityExclusionAttachmentResourceModel struct {
	ID          types.String `tfsdk:"id"`
	LastUpdated types.String `tfsdk:"last_updated"`
	HostGroups  types.Set    `tfsdk:"host_groups"`
	Exclusive   types.Bool   `tfsdk:"exclusive"`
}

func (m *sensorVisibilityExclusionAttachmentResourceModel) wrap(
	ctx context.Context,
	exclusion *models.SvExclusionsSVExclusionV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(exclusion.ID)

	hostGroups := types.SetNull(types.StringType)

	if m.Exclusive.ValueBool() {
		hostGroupSet, diag := hostgroups.ConvertHostGroupsToSet(ctx, exclusion.Groups)
		diags.Append(diag...)
		if diags.HasError() {
			return diags
		}

		if len(hostGroupSet.Elements()) != 0 {
			hostGroups = hostGroupSet
		}
	} else {
		existingHostGroups := make(map[string]bool)
		for _, hg := range exclusion.Groups {
			if hg != nil && hg.ID != nil {
				existingHostGroups[*hg.ID] = true
			}
		}

		if !m.HostGroups.IsNull() {
			planHostGroups := flex.ExpandSetAs[types.String](ctx, m.HostGroups, &diags)
			if diags.HasError() {
				return diags
			}

			var currentHostGroups []types.String
			for _, hg := range planHostGroups {
				if existingHostGroups[hg.ValueString()] {
					currentHostGroups = append(currentHostGroups, hg)
				}
			}

			hgSet, diag := types.SetValueFrom(ctx, types.StringType, currentHostGroups)
			diags.Append(diag...)
			if diags.HasError() {
				return diags
			}
			hostGroups = hgSet
		}
	}
	m.HostGroups = hostGroups

	return diags
}

func (r *sensorVisibilityExclusionAttachmentResource) Configure(
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

func (r *sensorVisibilityExclusionAttachmentResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_sensor_visibility_exclusion_attachment"
}

func (r *sensorVisibilityExclusionAttachmentResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			attachmentDocumentationSection,
			attachmentResourceMarkdownDescription,
			attachmentRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "The sensor visibility exclusion policy id you want to attach to.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
			"exclusive": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "When true (default), this resource takes exclusive ownership of all host groups attached to the sensor visibility exclusion policy. When false, this resource only manages the specific host groups defined in the configuration, leaving other groups untouched.",
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host Group IDs to attach to the sensor visibility exclusion policy.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(
						validators.StringNotWhitespace(),
					),
				},
			},
		},
	}
}

func (r *sensorVisibilityExclusionAttachmentResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan sensorVisibilityExclusionAttachmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exclusion, diags := r.getSensorVisibilityExclusionForAttachment(ctx, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	existingHostGroups, diag := hostgroups.ConvertHostGroupsToSet(ctx, exclusion.Groups)
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}

	planHostGroups := plan.HostGroups

	if !plan.Exclusive.ValueBool() {
		planHostGroups = flex.MergeStringSet(ctx, existingHostGroups, plan.HostGroups, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(
		r.syncHostGroups(ctx, planHostGroups, existingHostGroups, plan.ID.ValueString(), exclusion)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exclusion, diags = r.getSensorVisibilityExclusionForAttachment(ctx, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, exclusion)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *sensorVisibilityExclusionAttachmentResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state sensorVisibilityExclusionAttachmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exclusion, diags := r.getSensorVisibilityExclusionForAttachment(ctx, state.ID.ValueString())
	if diags.HasError() {
		for _, diag := range diags.Errors() {
			if diag.Summary() == "Sensor Visibility Exclusion Not Found" {
				tflog.Warn(
					ctx,
					fmt.Sprintf("sensor visibility exclusion %s not found, removing from state", state.ID),
				)

				resp.State.RemoveResource(ctx)
				return
			}
		}
	}

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, exclusion)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *sensorVisibilityExclusionAttachmentResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan sensorVisibilityExclusionAttachmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	var state sensorVisibilityExclusionAttachmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	planHostGroups := plan.HostGroups

	if !plan.Exclusive.ValueBool() {
		hostGroupsToRemove := flex.DiffStringSet(ctx, state.HostGroups, plan.HostGroups, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		exclusion, diags := r.getSensorVisibilityExclusionForAttachment(ctx, plan.ID.ValueString())
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		removeMap := make(map[string]bool)
		for _, id := range hostGroupsToRemove {
			removeMap[id.ValueString()] = true
		}

		var existingHostGroups []*models.HostGroupsHostGroupV1
		for _, hg := range exclusion.Groups {
			if hg != nil && hg.ID != nil && !removeMap[*hg.ID] {
				existingHostGroups = append(existingHostGroups, hg)
			}
		}

		existingHostGroupSet, diag := hostgroups.ConvertHostGroupsToSet(ctx, existingHostGroups)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}

		planHostGroups = flex.MergeStringSet(ctx, existingHostGroupSet, plan.HostGroups, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	exclusion, diags := r.getSensorVisibilityExclusionForAttachment(ctx, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		r.syncHostGroups(ctx, planHostGroups, state.HostGroups, plan.ID.ValueString(), exclusion)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exclusion, diags = r.getSensorVisibilityExclusionForAttachment(ctx, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, exclusion)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *sensorVisibilityExclusionAttachmentResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state sensorVisibilityExclusionAttachmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exclusion, diags := r.getSensorVisibilityExclusionForAttachment(ctx, state.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	emptySet := basetypes.SetValue{}

	resp.Diagnostics.Append(
		r.syncHostGroups(ctx, emptySet, state.HostGroups, state.ID.ValueString(), exclusion)...)
}

func (r *sensorVisibilityExclusionAttachmentResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("exclusive"), true)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *sensorVisibilityExclusionAttachmentResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config sensorVisibilityExclusionAttachmentResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)

	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.HostGroups, "host_groups")...)
}

func (r *sensorVisibilityExclusionAttachmentResource) getSensorVisibilityExclusionForAttachment(
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

func (r *sensorVisibilityExclusionAttachmentResource) syncHostGroups(
	ctx context.Context,
	planGroups, stateGroups types.Set,
	id string,
	currentExclusion *models.SvExclusionsSVExclusionV1,
) diag.Diagnostics {
	var diags diag.Diagnostics
	groupsToAdd, groupsToRemove, setDiags := utils.SetIDsToModify(
		ctx,
		planGroups,
		stateGroups,
	)

	diags.Append(setDiags...)
	if diags.HasError() {
		return diags
	}

	if len(groupsToAdd) > 0 || len(groupsToRemove) > 0 {
		var updatedGroups []string

		existingGroups := make(map[string]bool)
		for _, hg := range currentExclusion.Groups {
			if hg != nil && hg.ID != nil {
				existingGroups[*hg.ID] = true
			}
		}

		for _, existingGroup := range currentExclusion.Groups {
			if existingGroup != nil && existingGroup.ID != nil {
				shouldRemove := false
				for _, removeGroup := range groupsToRemove {
					if *existingGroup.ID == removeGroup {
						shouldRemove = true
						break
					}
				}
				if !shouldRemove {
					updatedGroups = append(updatedGroups, *existingGroup.ID)
				}
			}
		}

		for _, addGroup := range groupsToAdd {
			if !existingGroups[addGroup] {
				updatedGroups = append(updatedGroups, addGroup)
			}
		}

		updateReq := &models.SvExclusionsUpdateReqV1{
			ID:                  currentExclusion.ID,
			Value:               *currentExclusion.Value,
			Groups:              updatedGroups,
			IsDescendantProcess: currentExclusion.IsDescendantProcess,
			Comment:             "updated by terraform crowdstrike provider",
		}

		params := sensor_visibility_exclusions.NewUpdateSensorVisibilityExclusionsV1ParamsWithContext(ctx)
		params.SetBody(updateReq)

		tflog.Debug(ctx, "Updating sensor visibility exclusion host groups", map[string]any{
			"exclusion_id":     id,
			"groups_to_add":    groupsToAdd,
			"groups_to_remove": groupsToRemove,
			"updated_groups":   updatedGroups,
		})

		_, err := r.client.SensorVisibilityExclusions.UpdateSensorVisibilityExclusionsV1(params)
		if err != nil {
			diags.AddError(
				"Unable to Update Sensor Visibility Exclusion Host Groups",
				"An error occurred while updating the sensor visibility exclusion host groups. "+
					"Original Error: "+err.Error(),
			)
			return diags
		}
	}

	return diags
}
