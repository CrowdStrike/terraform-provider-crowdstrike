package preventionpolicy

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/models"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &preventionPolicyAttachmentResource{}
	_ resource.ResourceWithConfigure      = &preventionPolicyAttachmentResource{}
	_ resource.ResourceWithImportState    = &preventionPolicyAttachmentResource{}
	_ resource.ResourceWithValidateConfig = &preventionPolicyAttachmentResource{}
)

var (
	docuementationSection       string         = "Prevention Policy"
	resourceMarkdownDescription string         = "This resource allows managing the host groups and ioa rule groups attached to a prevention policy. This resource takes exclusive ownership over the host groups and ioa rule groups assigned to a prevention policy. If you want to fully create or manage a prevention policy please use the `prevention_policy_*` resource for the platform you want to manage."
	requiredScopes              []scopes.Scope = apiScopes
)

func NewPreventionPolicyAttachmentResource() resource.Resource {
	return &preventionPolicyAttachmentResource{}
}

type preventionPolicyAttachmentResource struct {
	client *client.CrowdStrikeAPISpecification
}

type preventionPolicyAttachmentResourceModel struct {
	ID          types.String `tfsdk:"id"`
	LastUpdated types.String `tfsdk:"last_updated"`
	HostGroups  types.Set    `tfsdk:"host_groups"`
	RuleGroups  types.Set    `tfsdk:"ioa_rule_groups"`
}

// wrap transforms Go values to their terraform wrapped values.
func (d *preventionPolicyAttachmentResourceModel) wrap(
	ctx context.Context,
	policy models.PreventionPolicyV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	d.ID = types.StringValue(*policy.ID)
	hostGroupSet, diag := hostgroups.ConvertHostGroupsToSet(ctx, policy.Groups)
	diags.Append(diag...)
	if diags.HasError() {
		return diags
	}
	if !d.HostGroups.IsNull() || len(hostGroupSet.Elements()) != 0 {
		d.HostGroups = hostGroupSet
	}

	ruleGroupSet, diag := convertRuleGroupToSet(ctx, policy.IoaRuleGroups)
	diags.Append(diag...)
	if diags.HasError() {
		return diags
	}
	if !d.RuleGroups.IsNull() || len(ruleGroupSet.Elements()) != 0 {
		d.RuleGroups = ruleGroupSet
	}

	return diags
}

func (r *preventionPolicyAttachmentResource) Configure(
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

func (r *preventionPolicyAttachmentResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_prevention_policy_attachment"
}

func (r *preventionPolicyAttachmentResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			docuementationSection,
			resourceMarkdownDescription,
			requiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "The prevention policy id you want to attach to.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
			"ioa_rule_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "IOA Rule Group to attach to the prevention policy.",
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host Group ids to attach to the prevention policy.",
			},
		},
	}
}

func (r *preventionPolicyAttachmentResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan preventionPolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getPreventionPolicy(ctx, r.client, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	hostGroups := policy.Groups
	ruleGroups := policy.IoaRuleGroups
	hostGroupSet := types.SetNull(types.StringType)
	ruleGroupSet := types.SetNull(types.StringType)

	if len(hostGroups) > 0 {
		hgIDs := make([]types.String, 0, len(hostGroups))
		for _, hg := range hostGroups {
			hgIDs = append(hgIDs, types.StringValue(*hg.ID))
		}

		hgSet, diags := types.SetValueFrom(ctx, types.StringType, hgIDs)
		hostGroupSet = hgSet

		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	if len(ruleGroups) > 0 {
		rgIDs := make([]types.String, 0, len(hostGroups))
		for _, rg := range ruleGroups {
			rgIDs = append(rgIDs, types.StringValue(*rg.ID))
		}

		rgSet, diags := types.SetValueFrom(ctx, types.StringType, rgIDs)
		ruleGroupSet = rgSet

		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(
		syncHostGroups(ctx, r.client, plan.HostGroups, hostGroupSet, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncRuleGroups(ctx, r.client, plan.RuleGroups, ruleGroupSet, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags = getPreventionPolicy(ctx, r.client, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *preventionPolicyAttachmentResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state preventionPolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getPreventionPolicy(ctx, r.client, state.ID.ValueString())
	for _, err := range diags.Errors() {
		if err.Summary() == notFoundErrorSummary {
			tflog.Warn(
				ctx,
				fmt.Sprintf("prevention policy %s not found, removing from state", state.ID),
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

func (r *preventionPolicyAttachmentResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan preventionPolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	var state preventionPolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	resp.Diagnostics.Append(
		syncHostGroups(ctx, r.client, plan.HostGroups, state.HostGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncRuleGroups(ctx, r.client, plan.RuleGroups, state.RuleGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diag := getPreventionPolicy(ctx, r.client, plan.ID.ValueString())
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *preventionPolicyAttachmentResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state preventionPolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	resp.Diagnostics.Append(
		syncHostGroups(
			ctx,
			r.client,
			basetypes.SetValue{},
			state.HostGroups,
			state.ID.ValueString(),
		)...)
	resp.Diagnostics.Append(
		syncRuleGroups(
			ctx,
			r.client,
			basetypes.SetValue{},
			state.RuleGroups,
			state.ID.ValueString(),
		)...)
}

func (r *preventionPolicyAttachmentResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *preventionPolicyAttachmentResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config preventionPolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)

	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.HostGroups, "host_groups")...)
	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.RuleGroups, "ioa_rule_groups")...)
}
