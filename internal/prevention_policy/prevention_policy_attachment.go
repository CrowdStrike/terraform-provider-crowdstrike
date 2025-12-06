package preventionpolicy

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	ioarulegroup "github.com/crowdstrike/terraform-provider-crowdstrike/internal/ioa_rule_group"
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
	_ resource.Resource                   = &preventionPolicyAttachmentResource{}
	_ resource.ResourceWithConfigure      = &preventionPolicyAttachmentResource{}
	_ resource.ResourceWithImportState    = &preventionPolicyAttachmentResource{}
	_ resource.ResourceWithValidateConfig = &preventionPolicyAttachmentResource{}
)

var (
	documentationSection        string         = "Prevention Policy"
	resourceMarkdownDescription string         = "This resource allows managing the host groups and ioa rule groups attached to a prevention policy. By default (when `exclusive` is true), this resource takes exclusive ownership over the host groups and ioa rule groups assigned to a prevention policy. When `exclusive` is false, this resource only manages the specific host groups and ioa rule groups defined in the configuration. If you want to fully create or manage a prevention policy please use the `prevention_policy_*` resource for the platform you want to manage."
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
	Exclusive   types.Bool   `tfsdk:"exclusive"`
}

// wrap transforms Go values to their terraform wrapped values.
func (d *preventionPolicyAttachmentResourceModel) wrap(
	ctx context.Context,
	policy models.PreventionPolicyV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	d.ID = types.StringValue(*policy.ID)

	if d.Exclusive.ValueBool() {
		hostGroupSet, diag := hostgroups.ConvertHostGroupsToSet(ctx, policy.Groups)
		diags.Append(diag...)
		if diags.HasError() {
			return diags
		}
		if !d.HostGroups.IsNull() || len(hostGroupSet.Elements()) != 0 {
			d.HostGroups = hostGroupSet
		}

		ruleGroupSet, diag := ioarulegroup.ConvertIOARuleGroupToSet(ctx, policy.IoaRuleGroups)
		diags.Append(diag...)
		if diags.HasError() {
			return diags
		}
		if !d.RuleGroups.IsNull() || len(ruleGroupSet.Elements()) != 0 {
			d.RuleGroups = ruleGroupSet
		}
	} else {
		policyHostGroups := make(map[string]bool)
		for _, hg := range policy.Groups {
			if hg.ID != nil {
				policyHostGroups[*hg.ID] = true
			}
		}

		policyRuleGroups := make(map[string]bool)
		for _, rg := range policy.IoaRuleGroups {
			if rg.ID != nil {
				policyRuleGroups[*rg.ID] = true
			}
		}

		if !d.HostGroups.IsNull() {
			currentHostGroups := flex.ExpandSetAs[types.String](ctx, d.HostGroups, &diags)
			if diags.HasError() {
				return diags
			}

			var stillPresentHostGroups []types.String
			for _, hg := range currentHostGroups {
				if policyHostGroups[hg.ValueString()] {
					stillPresentHostGroups = append(stillPresentHostGroups, hg)
				}
			}

			hgSet, diag := types.SetValueFrom(ctx, types.StringType, stillPresentHostGroups)
			diags.Append(diag...)
			if diags.HasError() {
				return diags
			}
			d.HostGroups = hgSet
		}

		if !d.RuleGroups.IsNull() {
			currentRuleGroups := flex.ExpandSetAs[types.String](ctx, d.RuleGroups, &diags)
			if diags.HasError() {
				return diags
			}

			var stillPresentRuleGroups []types.String
			for _, rg := range currentRuleGroups {
				if policyRuleGroups[rg.ValueString()] {
					stillPresentRuleGroups = append(stillPresentRuleGroups, rg)
				}
			}

			rgSet, diag := types.SetValueFrom(ctx, types.StringType, stillPresentRuleGroups)
			diags.Append(diag...)
			if diags.HasError() {
				return diags
			}
			d.RuleGroups = rgSet
		}
	}

	return diags
}

// mergeSetItems merges existing set items with plan set items.
// Returns the merged set or reports diagnostics on error.
func mergeSetItems(
	ctx context.Context,
	existingSet types.Set,
	planSet types.Set,
	diags *diag.Diagnostics,
) types.Set {
	existingItems := flex.ExpandSetAs[types.String](ctx, existingSet, diags)
	if diags.HasError() {
		return types.SetNull(types.StringType)
	}

	planItems := flex.ExpandSetAs[types.String](ctx, planSet, diags)
	if diags.HasError() {
		return types.SetNull(types.StringType)
	}

	mergedItems := append(existingItems, planItems...)
	mergedSet, mergeDiags := types.SetValueFrom(ctx, types.StringType, mergedItems)
	diags.Append(mergeDiags...)

	return mergedSet
}

// findGroupsToRemove compares state and plan sets and returns the IDs that
// exist in state but not in plan (groups that should be removed).
func findGroupsToRemove(
	ctx context.Context,
	stateSet types.Set,
	planSet types.Set,
	diags *diag.Diagnostics,
) []types.String {
	if stateSet.IsNull() {
		return nil
	}

	stateItems := flex.ExpandSetAs[types.String](ctx, stateSet, diags)
	if diags.HasError() {
		return nil
	}

	if planSet.IsNull() {
		return stateItems
	}

	planItems := flex.ExpandSetAs[types.String](ctx, planSet, diags)
	if diags.HasError() {
		return nil
	}

	planMap := make(map[string]bool)
	for _, item := range planItems {
		planMap[item.ValueString()] = true
	}

	var toRemove []types.String
	for _, item := range stateItems {
		if !planMap[item.ValueString()] {
			toRemove = append(toRemove, item)
		}
	}

	return toRemove
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
			documentationSection,
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
			"exclusive": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "When true (default), this resource takes exclusive ownership of all host groups and ioa rule groups attached to the prevention policy. When false, this resource only manages the specific host groups and ioa rule groups defined in the configuration, leaving other attachments untouched.",
			},
			"ioa_rule_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "IOA Rule Group to attach to the prevention policy.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(
						validators.StringNotWhitespace(),
					),
				},
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host Group ids to attach to the prevention policy.",
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

	existingHostGroupSet, diag := hostgroups.ConvertHostGroupsToSet(ctx, policy.Groups)
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}

	existingRuleGroupSet, diag := ioarulegroup.ConvertIOARuleGroupToSet(ctx, policy.IoaRuleGroups)
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}

	planHostGroups := plan.HostGroups
	planRuleGroups := plan.RuleGroups

	if !plan.Exclusive.ValueBool() {
		planHostGroups = mergeSetItems(ctx, existingHostGroupSet, plan.HostGroups, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		planRuleGroups = mergeSetItems(ctx, existingRuleGroupSet, plan.RuleGroups, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(
		syncHostGroups(ctx, r.client, planHostGroups, existingHostGroupSet, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncRuleGroups(ctx, r.client, planRuleGroups, existingRuleGroupSet, plan.ID.ValueString())...)
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

	if resp.Diagnostics.HasError() {
		return
	}

	planHostGroups := plan.HostGroups
	planRuleGroups := plan.RuleGroups

	if !plan.Exclusive.ValueBool() {
		hostGroupsToRemove := findGroupsToRemove(ctx, state.HostGroups, plan.HostGroups, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		ruleGroupsToRemove := findGroupsToRemove(ctx, state.RuleGroups, plan.RuleGroups, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		policy, diags := getPreventionPolicy(ctx, r.client, plan.ID.ValueString())
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
			if hg.ID != nil && !removeMap[*hg.ID] {
				existingHostGroups = append(existingHostGroups, hg)
			}
		}

		existingHostGroupSet, diag := hostgroups.ConvertHostGroupsToSet(ctx, existingHostGroups)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}

		removeRuleGroupMap := make(map[string]bool)
		for _, id := range ruleGroupsToRemove {
			removeRuleGroupMap[id.ValueString()] = true
		}

		var existingRuleGroups []*models.IoaRuleGroupsRuleGroupV1
		for _, rg := range policy.IoaRuleGroups {
			if rg.ID != nil && !removeRuleGroupMap[*rg.ID] {
				existingRuleGroups = append(existingRuleGroups, rg)
			}
		}

		existingRuleGroupSet, diag := ioarulegroup.ConvertIOARuleGroupToSet(ctx, existingRuleGroups)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}

		planHostGroups = mergeSetItems(ctx, existingHostGroupSet, plan.HostGroups, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		planRuleGroups = mergeSetItems(ctx, existingRuleGroupSet, plan.RuleGroups, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(
		syncHostGroups(ctx, r.client, planHostGroups, state.HostGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncRuleGroups(ctx, r.client, planRuleGroups, state.RuleGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getPreventionPolicy(ctx, r.client, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
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
	if resp.Diagnostics.HasError() {
		return
	}

	emptySet := basetypes.SetValue{}
	planHostGroups := emptySet
	planRuleGroups := emptySet

	if !state.Exclusive.ValueBool() {
		policy, diags := getPreventionPolicy(ctx, r.client, state.ID.ValueString())
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		hostGroupsToRemove := findGroupsToRemove(ctx, state.HostGroups, emptySet, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		ruleGroupsToRemove := findGroupsToRemove(ctx, state.RuleGroups, emptySet, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		removeHostGroupMap := make(map[string]bool)
		for _, id := range hostGroupsToRemove {
			removeHostGroupMap[id.ValueString()] = true
		}

		var existingHostGroups []*models.HostGroupsHostGroupV1
		for _, hg := range policy.Groups {
			if hg.ID != nil && !removeHostGroupMap[*hg.ID] {
				existingHostGroups = append(existingHostGroups, hg)
			}
		}

		existingHostGroupSet, diag := hostgroups.ConvertHostGroupsToSet(ctx, existingHostGroups)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}

		removeRuleGroupMap := make(map[string]bool)
		for _, id := range ruleGroupsToRemove {
			removeRuleGroupMap[id.ValueString()] = true
		}

		var existingRuleGroups []*models.IoaRuleGroupsRuleGroupV1
		for _, rg := range policy.IoaRuleGroups {
			if rg.ID != nil && !removeRuleGroupMap[*rg.ID] {
				existingRuleGroups = append(existingRuleGroups, rg)
			}
		}

		existingRuleGroupSet, diag := ioarulegroup.ConvertIOARuleGroupToSet(ctx, existingRuleGroups)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}

		planHostGroups = existingHostGroupSet
		planRuleGroups = existingRuleGroupSet
	}

	resp.Diagnostics.Append(
		syncHostGroups(ctx, r.client, planHostGroups, state.HostGroups, state.ID.ValueString())...)
	resp.Diagnostics.Append(
		syncRuleGroups(ctx, r.client, planRuleGroups, state.RuleGroups, state.ID.ValueString())...)
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
