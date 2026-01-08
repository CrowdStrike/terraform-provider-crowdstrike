package fim

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/filevantage"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
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
	_ resource.Resource                   = &filevantagePolicyAttachmentResource{}
	_ resource.ResourceWithConfigure      = &filevantagePolicyAttachmentResource{}
	_ resource.ResourceWithImportState    = &filevantagePolicyAttachmentResource{}
	_ resource.ResourceWithValidateConfig = &filevantagePolicyAttachmentResource{}
)

var (
	attachmentDocumentationSection        string         = "FileVantage"
	attachmentResourceMarkdownDescription string         = "This resource allows managing the host groups and rule groups attached to a FileVantage policy. By default (when `exclusive` is true), this resource takes exclusive ownership over the host groups and rule groups assigned to a FileVantage policy. When `exclusive` is false, this resource only manages the specific host groups and rule groups defined in the configuration. If you want to fully create or manage a FileVantage policy please use the `filevantage_policy` resource."
	attachmentRequiredScopes              []scopes.Scope = apiScopesReadWrite
)

func NewFilevantagePolicyAttachmentResource() resource.Resource {
	return &filevantagePolicyAttachmentResource{}
}

type filevantagePolicyAttachmentResource struct {
	client *client.CrowdStrikeAPISpecification
}

type filevantagePolicyAttachmentResourceModel struct {
	ID          types.String `tfsdk:"id"`
	LastUpdated types.String `tfsdk:"last_updated"`
	HostGroups  types.Set    `tfsdk:"host_groups"`
	RuleGroups  types.Set    `tfsdk:"rule_groups"`
	Exclusive   types.Bool   `tfsdk:"exclusive"`
}

func (m *filevantagePolicyAttachmentResourceModel) wrap(
	ctx context.Context,
	policy models.PoliciesPolicy,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(policy.ID)

	hostGroups := types.SetNull(types.StringType)
	ruleGroups := types.SetNull(types.StringType)

	if m.Exclusive.ValueBool() {
		hostGroupSet, diag := convertHostGroupsToSet(ctx, policy.HostGroups)
		diags.Append(diag...)
		if diags.HasError() {
			return diags
		}

		if len(hostGroupSet.Elements()) != 0 {
			hostGroups = hostGroupSet
		}

		ruleGroupSet, diag := convertRuleGroupsToSet(ctx, policy.RuleGroups)
		diags.Append(diag...)
		if diags.HasError() {
			return diags
		}
		if len(ruleGroupSet.Elements()) != 0 {
			ruleGroups = ruleGroupSet
		}
	} else {
		existingHostGroups := make(map[string]bool)
		for _, hg := range policy.HostGroups {
			if hg != nil && hg.ID != nil {
				existingHostGroups[*hg.ID] = true
			}
		}

		existingRuleGroups := make(map[string]bool)
		for _, rg := range policy.RuleGroups {
			if rg != nil && rg.ID != nil {
				existingRuleGroups[*rg.ID] = true
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

		if !m.RuleGroups.IsNull() {
			planRuleGroups := flex.ExpandSetAs[types.String](ctx, m.RuleGroups, &diags)
			if diags.HasError() {
				return diags
			}

			var currentRuleGroups []types.String
			for _, rg := range planRuleGroups {
				if existingRuleGroups[rg.ValueString()] {
					currentRuleGroups = append(currentRuleGroups, rg)
				}
			}

			rgSet, diag := types.SetValueFrom(ctx, types.StringType, currentRuleGroups)
			diags.Append(diag...)
			if diags.HasError() {
				return diags
			}
			ruleGroups = rgSet
		}
	}
	m.HostGroups = hostGroups
	m.RuleGroups = ruleGroups

	return diags
}


func (r *filevantagePolicyAttachmentResource) Configure(
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

func (r *filevantagePolicyAttachmentResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_filevantage_policy_attachment"
}

func (r *filevantagePolicyAttachmentResource) Schema(
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
				Description: "The FileVantage policy id you want to attach to.",
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
				Description: "When true (default), this resource takes exclusive ownership of all host groups and rule groups attached to the FileVantage policy. When false, this resource only manages the specific host groups and rule groups defined in the configuration, leaving other groups untouched.",
			},
			"rule_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "FileVantage Rule Group IDs to attach to the FileVantage policy.",
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
				Description: "Host Group IDs to attach to the FileVantage policy.",
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

func (r *filevantagePolicyAttachmentResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan filevantagePolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getFilevantagePolicy(ctx, r.client, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	existingHostGroups, diag := convertHostGroupsToSet(ctx, policy.HostGroups)
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}

	existingRuleGroups, diag := convertRuleGroupsToSet(ctx, policy.RuleGroups)
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}

	planHostGroups := plan.HostGroups
	planRuleGroups := plan.RuleGroups

	if !plan.Exclusive.ValueBool() {
		planHostGroups = flex.MergeStringSet(ctx, existingHostGroups, plan.HostGroups, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		planRuleGroups = flex.MergeStringSet(ctx, existingRuleGroups, plan.RuleGroups, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(
		syncAttachmentHostGroups(ctx, r.client, planHostGroups, existingHostGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncAttachmentRuleGroups(ctx, r.client, planRuleGroups, existingRuleGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags = getFilevantagePolicy(ctx, r.client, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *filevantagePolicyAttachmentResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state filevantagePolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getFilevantagePolicy(ctx, r.client, state.ID.ValueString())
	for _, err := range diags.Errors() {
		if err.Summary() == "Failed to get FileVantage policy" {
			tflog.Warn(
				ctx,
				fmt.Sprintf("FileVantage policy %s not found, removing from state", state.ID),
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

func (r *filevantagePolicyAttachmentResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan filevantagePolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	var state filevantagePolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	planHostGroups := plan.HostGroups
	planRuleGroups := plan.RuleGroups

	if !plan.Exclusive.ValueBool() {
		hostGroupsToRemove := flex.DiffStringSet(ctx, state.HostGroups, plan.HostGroups, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		ruleGroupsToRemove := flex.DiffStringSet(ctx, state.RuleGroups, plan.RuleGroups, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		policy, diags := getFilevantagePolicy(ctx, r.client, plan.ID.ValueString())
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		removeMap := make(map[string]bool)
		for _, id := range hostGroupsToRemove {
			removeMap[id.ValueString()] = true
		}

		var existingHostGroups []*models.PoliciesAssignedHostGroup
		for _, hg := range policy.HostGroups {
			if hg != nil && hg.ID != nil && !removeMap[*hg.ID] {
				existingHostGroups = append(existingHostGroups, hg)
			}
		}

		existingHostGroupSet, diag := convertHostGroupsToSet(ctx, existingHostGroups)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}

		removeRuleGroupMap := make(map[string]bool)
		for _, id := range ruleGroupsToRemove {
			removeRuleGroupMap[id.ValueString()] = true
		}

		var existingRuleGroups []*models.PoliciesAssignedRuleGroup
		for _, rg := range policy.RuleGroups {
			if rg != nil && rg.ID != nil && !removeRuleGroupMap[*rg.ID] {
				existingRuleGroups = append(existingRuleGroups, rg)
			}
		}

		existingRuleGroupSet, diag := convertRuleGroupsToSet(ctx, existingRuleGroups)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}

		planHostGroups = flex.MergeStringSet(ctx, existingHostGroupSet, plan.HostGroups, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		planRuleGroups = flex.MergeStringSet(ctx, existingRuleGroupSet, plan.RuleGroups, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(
		syncAttachmentHostGroups(ctx, r.client, planHostGroups, state.HostGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncAttachmentRuleGroups(ctx, r.client, planRuleGroups, state.RuleGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getFilevantagePolicy(ctx, r.client, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *filevantagePolicyAttachmentResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state filevantagePolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	emptySet := basetypes.SetValue{}

	resp.Diagnostics.Append(
		syncAttachmentHostGroups(ctx, r.client, emptySet, state.HostGroups, state.ID.ValueString())...)
	resp.Diagnostics.Append(
		syncAttachmentRuleGroups(ctx, r.client, emptySet, state.RuleGroups, state.ID.ValueString())...)
}

func (r *filevantagePolicyAttachmentResource) ImportState(
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

func (r *filevantagePolicyAttachmentResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config filevantagePolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)

	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.HostGroups, "host_groups")...)
	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.RuleGroups, "rule_groups")...)
}

func getFilevantagePolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	id string,
) (*models.PoliciesPolicy, diag.Diagnostics) {
	var diags diag.Diagnostics

	res, err := client.Filevantage.GetPolicies(&filevantage.GetPoliciesParams{
		Context: ctx,
		Ids:     []string{id},
	})
	if err != nil {
		diags.AddError(
			"Failed to get FileVantage policy",
			fmt.Sprintf("Failed to get FileVantage policy (%s): %s", id, err),
		)

		return nil, diags
	}

	if len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Failed to get FileVantage policy",
			fmt.Sprintf("FileVantage policy (%s) not found", id),
		)

		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func syncAttachmentHostGroups(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	planHostGroups types.Set,
	stateHostGroups types.Set,
	policyID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	hostGroupsToAdd, hostGroupsToRemove, diag := utils.SetIDsToModify(
		ctx,
		planHostGroups,
		stateHostGroups,
	)
	diags.Append(diag...)
	if diags.HasError() {
		return diags
	}

	if len(hostGroupsToAdd) > 0 {
		_, err := client.Filevantage.UpdatePolicyHostGroups(
			&filevantage.UpdatePolicyHostGroupsParams{
				Context:  ctx,
				Action:   addHostGroup.String(),
				Ids:      hostGroupsToAdd,
				PolicyID: policyID,
			},
		)
		if err != nil {
			diags.AddError(
				"Error updating FileVantage policy host groups",
				fmt.Sprintf(
					"Could not add host groups to FileVantage policy (%s): %s",
					policyID,
					err.Error(),
				),
			)
		}
	}

	if len(hostGroupsToRemove) > 0 {
		_, err := client.Filevantage.UpdatePolicyHostGroups(
			&filevantage.UpdatePolicyHostGroupsParams{
				Context:  ctx,
				Action:   removeHostGroup.String(),
				Ids:      hostGroupsToRemove,
				PolicyID: policyID,
			},
		)
		if err != nil {
			diags.AddError(
				"Error updating FileVantage policy host groups",
				fmt.Sprintf(
					"Could not remove host groups from FileVantage policy (%s): %s",
					policyID,
					err.Error(),
				),
			)
		}
	}

	return diags
}

func syncAttachmentRuleGroups(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	planRuleGroups types.Set,
	stateRuleGroups types.Set,
	policyID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	ruleGroupsToAdd, ruleGroupsToRemove, diag := utils.SetIDsToModify(
		ctx,
		planRuleGroups,
		stateRuleGroups,
	)
	diags.Append(diag...)
	if diags.HasError() {
		return diags
	}

	if len(ruleGroupsToAdd) > 0 {
		_, err := client.Filevantage.UpdatePolicyRuleGroups(
			&filevantage.UpdatePolicyRuleGroupsParams{
				Context:  ctx,
				Action:   addRuleGroup.String(),
				Ids:      ruleGroupsToAdd,
				PolicyID: policyID,
			},
		)
		if err != nil {
			diags.AddError(
				"Error updating FileVantage policy rule groups",
				fmt.Sprintf(
					"Could not add rule groups to FileVantage policy (%s): %s",
					policyID,
					err.Error(),
				),
			)
		}
	}

	if len(ruleGroupsToRemove) > 0 {
		_, err := client.Filevantage.UpdatePolicyRuleGroups(
			&filevantage.UpdatePolicyRuleGroupsParams{
				Context:  ctx,
				Action:   removeRuleGroup.String(),
				Ids:      ruleGroupsToRemove,
				PolicyID: policyID,
			},
		)
		if err != nil {
			diags.AddError(
				"Error updating FileVantage policy rule groups",
				fmt.Sprintf(
					"Could not remove rule groups from FileVantage policy (%s): %s",
					policyID,
					err.Error(),
				),
			)
		}
	}

	return diags
}

func convertHostGroupsToSet(
	ctx context.Context,
	groups []*models.PoliciesAssignedHostGroup,
) (types.Set, diag.Diagnostics) {
	var hostGroups []string
	for _, hostGroup := range groups {
		if hostGroup != nil && hostGroup.ID != nil {
			hostGroups = append(hostGroups, *hostGroup.ID)
		}
	}

	return types.SetValueFrom(ctx, types.StringType, hostGroups)
}

func convertRuleGroupsToSet(
	ctx context.Context,
	groups []*models.PoliciesAssignedRuleGroup,
) (types.Set, diag.Diagnostics) {
	var ruleGroups []string
	for _, ruleGroup := range groups {
		if ruleGroup != nil && ruleGroup.ID != nil {
			ruleGroups = append(ruleGroups, *ruleGroup.ID)
		}
	}

	return types.SetValueFrom(ctx, types.StringType, ruleGroups)
}
