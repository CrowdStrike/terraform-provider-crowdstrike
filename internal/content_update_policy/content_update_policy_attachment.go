package contentupdatepolicy

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
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
)

var (
	_ resource.Resource                = &contentUpdatePolicyAttachmentResource{}
	_ resource.ResourceWithConfigure   = &contentUpdatePolicyAttachmentResource{}
	_ resource.ResourceWithImportState = &contentUpdatePolicyAttachmentResource{}
)

var (
	attachmentDocumentationSection        string         = "Content Update Policy"
	attachmentResourceMarkdownDescription string         = "This resource allows managing the host groups attached to a content update policy. By default (when `exclusive` is true), this resource takes exclusive ownership over the host groups assigned to a content update policy. When `exclusive` is false, this resource only manages the specific host groups defined in the configuration. If you want to fully create or manage a content update policy please use the `content_update_policy` resource."
	attachmentRequiredScopes              []scopes.Scope = apiScopesReadWrite
)

func newPolicyNotFoundError(policyID string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(
		"Content Update Policy Not Found",
		fmt.Sprintf(
			"Content update policy with ID %q does not exist. "+
				"This resource manages attachments to an existing policy and does not create a policy. "+
				"Ensure the correct policy ID was provided or use the crowdstrike_content_update_policy resource to create a policy.",
			policyID,
		),
	)
}

func NewContentUpdatePolicyAttachmentResource() resource.Resource {
	return &contentUpdatePolicyAttachmentResource{}
}

type contentUpdatePolicyAttachmentResource struct {
	client *client.CrowdStrikeAPISpecification
}

type contentUpdatePolicyAttachmentResourceModel struct {
	ID          types.String `tfsdk:"id"`
	LastUpdated types.String `tfsdk:"last_updated"`
	HostGroups  types.Set    `tfsdk:"host_groups"`
	Exclusive   types.Bool   `tfsdk:"exclusive"`
}

func (m *contentUpdatePolicyAttachmentResourceModel) wrap(
	ctx context.Context,
	policy models.ContentUpdatePolicyV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(policy.ID)

	hostGroups := types.SetNull(types.StringType)

	if m.Exclusive.ValueBool() {
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

func (r *contentUpdatePolicyAttachmentResource) Configure(
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

func (r *contentUpdatePolicyAttachmentResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_content_update_policy_attachment"
}

func (r *contentUpdatePolicyAttachmentResource) Schema(
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
				Description: "The content update policy id you want to attach to.",
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
				Description: "When true (default), this resource takes exclusive ownership of all host groups attached to the content update policy. When false, this resource only manages the specific host groups defined in the configuration, leaving other groups untouched.",
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host Group IDs to attach to the content update policy.",
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

func (r *contentUpdatePolicyAttachmentResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan contentUpdatePolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getContentUpdatePolicy(ctx, r.client, plan.ID.ValueString())
	if diags.HasError() {
		if tferrors.HasNotFoundError(diags) {
			resp.Diagnostics.Append(newPolicyNotFoundError(plan.ID.ValueString()))
			return
		}
		resp.Diagnostics.Append(diags...)
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

	policy, diags = getContentUpdatePolicy(ctx, r.client, plan.ID.ValueString())
	if diags.HasError() {
		if tferrors.HasNotFoundError(diags) {
			resp.Diagnostics.Append(newPolicyNotFoundError(plan.ID.ValueString()))
			return
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *contentUpdatePolicyAttachmentResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state contentUpdatePolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getContentUpdatePolicy(ctx, r.client, state.ID.ValueString())
	if diags.HasError() {
		if tferrors.HasNotFoundError(diags) {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *contentUpdatePolicyAttachmentResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan contentUpdatePolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	var state contentUpdatePolicyAttachmentResourceModel
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

		policy, diags := getContentUpdatePolicy(ctx, r.client, plan.ID.ValueString())
		if diags.HasError() {
			if tferrors.HasNotFoundError(diags) {
				resp.Diagnostics.Append(newPolicyNotFoundError(plan.ID.ValueString()))
				return
			}
			resp.Diagnostics.Append(diags...)
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

	policy, diags := getContentUpdatePolicy(ctx, r.client, plan.ID.ValueString())
	if diags.HasError() {
		if tferrors.HasNotFoundError(diags) {
			resp.Diagnostics.Append(newPolicyNotFoundError(plan.ID.ValueString()))
			return
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *contentUpdatePolicyAttachmentResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state contentUpdatePolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncHostGroups(
			ctx,
			r.client,
			basetypes.SetValue{},
			state.HostGroups,
			state.ID.ValueString(),
		)...)
}

func (r *contentUpdatePolicyAttachmentResource) ImportState(
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
