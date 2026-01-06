package sensorupdatepolicy

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &sensorUpdatePolicyHostGroupAttachmentResource{}
	_ resource.ResourceWithConfigure      = &sensorUpdatePolicyHostGroupAttachmentResource{}
	_ resource.ResourceWithImportState    = &sensorUpdatePolicyHostGroupAttachmentResource{}
	_ resource.ResourceWithValidateConfig = &sensorUpdatePolicyHostGroupAttachmentResource{}
)

var (
	documentationSection        string         = "Sensor Update Policy"
	resourceMarkdownDescription string         = "This resource allows managing the host groups attached to a sensor update policy. By default (when `exclusive` is true), this resource takes exclusive ownership over the host groups assigned to a sensor update policy. When `exclusive` is false, this resource only manages the specific host groups defined in the configuration. If you want to fully create or manage a sensor update policy please use the `crowdstrike_sensor_update_policy` resource."
	requiredScopes              []scopes.Scope = []scopes.Scope{
		{
			Name:  "Sensor update policies",
			Read:  true,
			Write: true,
		},
	}
)

func NewSensorUpdatePolicyHostGroupAttachmentResource() resource.Resource {
	return &sensorUpdatePolicyHostGroupAttachmentResource{}
}

type sensorUpdatePolicyHostGroupAttachmentResource struct {
	client *client.CrowdStrikeAPISpecification
}

type sensorUpdatePolicyHostGroupAttachmentResourceModel struct {
	ID          types.String `tfsdk:"id"`
	LastUpdated types.String `tfsdk:"last_updated"`
	HostGroups  types.Set    `tfsdk:"host_groups"`
	Exclusive   types.Bool   `tfsdk:"exclusive"`
}

// wrap transforms Go values to their terraform wrapped values.
func (d *sensorUpdatePolicyHostGroupAttachmentResourceModel) wrap(
	ctx context.Context,
	policy models.SensorUpdatePolicyV2,
) diag.Diagnostics {
	var diags diag.Diagnostics

	d.ID = types.StringValue(*policy.ID)

	hostGroups := types.SetNull(types.StringType)

	if d.Exclusive.ValueBool() {
		hostGroupSet, diag := hostgroups.ConvertHostGroupsToSet(ctx, policy.Groups)
		diags.Append(diag...)
		if diags.HasError() {
			return diags
		}

		if len(hostGroupSet.Elements()) != 0 {
			hostGroups = hostGroupSet
		}
	} else {
		existingHostGroups := make(map[string]bool)
		for _, hg := range policy.Groups {
			if hg != nil && hg.ID != nil {
				existingHostGroups[*hg.ID] = true
			}
		}

		if !d.HostGroups.IsNull() {
			planHostGroups := flex.ExpandSetAs[types.String](ctx, d.HostGroups, &diags)
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
	d.HostGroups = hostGroups

	return diags
}

func (r *sensorUpdatePolicyHostGroupAttachmentResource) Configure(
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

func (r *sensorUpdatePolicyHostGroupAttachmentResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_sensor_update_policy_host_group_attachment"
}

func (r *sensorUpdatePolicyHostGroupAttachmentResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			documentationSection,
			resourceMarkdownDescription,
			requiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "The sensor update policy id you want to attach to.",
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
			"exclusive": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "When true (default), this resource takes exclusive ownership of all host groups attached to the sensor update policy. When false, this resource only manages the specific host groups defined in the configuration, leaving other groups untouched.",
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host Group ids to attach to the sensor update policy.",
			},
		},
	}
}

func (r *sensorUpdatePolicyHostGroupAttachmentResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan sensorUpdatePolicyHostGroupAttachmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getSensorUpdatePolicy(ctx, r.client, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	existingHostGroups, diag := hostgroups.ConvertHostGroupsToSet(ctx, policy.Groups)
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
		syncHostGroups(ctx, r.client, planHostGroups, existingHostGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags = getSensorUpdatePolicy(ctx, r.client, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *sensorUpdatePolicyHostGroupAttachmentResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state sensorUpdatePolicyHostGroupAttachmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getSensorUpdatePolicy(ctx, r.client, state.ID.ValueString())
	for _, err := range diags.Errors() {
		if err.Summary() == notFoundErrorSummary {
			tflog.Warn(
				ctx,
				fmt.Sprintf("sensor update policy %s not found, removing from state", state.ID),
			)

			resp.State.RemoveResource(ctx)
			return
		}
	}
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *sensorUpdatePolicyHostGroupAttachmentResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan sensorUpdatePolicyHostGroupAttachmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	var state sensorUpdatePolicyHostGroupAttachmentResourceModel
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

		policy, diags := getSensorUpdatePolicy(ctx, r.client, plan.ID.ValueString())
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		removeMap := make(map[string]bool)
		for _, id := range hostGroupsToRemove {
			removeMap[id.ValueString()] = true
		}

		var existingHostGroups []*models.HostGroupsHostGroupV1
		for _, hg := range policy.Groups {
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

	resp.Diagnostics.Append(
		syncHostGroups(ctx, r.client, planHostGroups, state.HostGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diag := getSensorUpdatePolicy(ctx, r.client, plan.ID.ValueString())
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *sensorUpdatePolicyHostGroupAttachmentResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state sensorUpdatePolicyHostGroupAttachmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	resp.Diagnostics.Append(
		syncHostGroups(
			ctx,
			r.client,
			basetypes.SetValue{},
			state.HostGroups,
			state.ID.ValueString(),
		)...)
}

func (r *sensorUpdatePolicyHostGroupAttachmentResource) ImportState(
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

func (r *sensorUpdatePolicyHostGroupAttachmentResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config sensorUpdatePolicyHostGroupAttachmentResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)

	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.HostGroups, "host_groups")...)
}
