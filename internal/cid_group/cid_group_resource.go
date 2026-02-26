package cidgroup

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/mssp"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &cidGroupResource{}
	_ resource.ResourceWithConfigure   = &cidGroupResource{}
	_ resource.ResourceWithImportState = &cidGroupResource{}
)

var apiScopes = []scopes.Scope{
	{
		Name:  "Flight Control",
		Read:  true,
		Write: true,
	},
}

func NewCIDGroupResource() resource.Resource {
	return &cidGroupResource{}
}

type cidGroupResource struct {
	client *client.CrowdStrikeAPISpecification
}

type CIDGroupResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	CIDs        types.Set    `tfsdk:"cids"`
	CID         types.String `tfsdk:"cid"`
}

func (r *cidGroupResource) Configure(
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

func (r *cidGroupResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cid_group"
}

func (r *cidGroupResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Host Setup and Management",
			"Manages CID groups in CrowdStrike Falcon Flight Control. CID groups allow MSPs to organize and manage child CIDs for multi-tenant environments.",
			apiScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The ID of the CID group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the CID group.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The description of the CID group.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"cids": schema.SetAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Set of CID identifiers that are members of this group.",
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
				},
			},
			"cid": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The CID associated with this group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (m *CIDGroupResourceModel) wrap(cidGroup *models.DomainCIDGroup) {
	if cidGroup.CidGroupID != nil {
		m.ID = types.StringValue(*cidGroup.CidGroupID)
	}
	if cidGroup.Name != nil {
		m.Name = types.StringValue(*cidGroup.Name)
	}
	m.Description = flex.StringPointerToFramework(cidGroup.Description)
	m.CID = types.StringValue(cidGroup.Cid)
}

func (r *cidGroupResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan CIDGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	res, multi, err := r.client.Mssp.CreateCIDGroups(&mssp.CreateCIDGroupsParams{
		Context: ctx,
		Body: &models.DomainCIDGroupsRequestV1{
			Resources: []*models.DomainCIDGroup{
				{
					Name:        flex.FrameworkToStringPointer(plan.Name),
					Description: plan.Description.ValueStringPointer(),
				},
			},
		},
	})
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, apiScopes)
		resp.Diagnostics.Append(diag)
		return
	}

	if multi != nil {
		if diag := tferrors.NewDiagnosticFromAPIError(tferrors.Create, multi, apiScopes); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	plan.wrap(res.Payload.Resources[0])

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.CIDs.IsNull() && len(plan.CIDs.Elements()) > 0 {
		var cids []string
		resp.Diagnostics.Append(plan.CIDs.ElementsAs(ctx, &cids, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		if diag := r.addCIDGroupMembers(ctx, plan.ID.ValueString(), cids); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}

		memberCIDs, diag := r.getCIDGroupMembers(ctx, plan.ID.ValueString())
		if diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}

		cidsSet, d := flex.FlattenStringValueSet(ctx, memberCIDs)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.CIDs = cidsSet
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *cidGroupResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state CIDGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cidGroupID := state.ID.ValueString()

	cidGroup, diag := r.getCIDGroupByID(ctx, cidGroupID)
	if diag != nil {
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	state.wrap(cidGroup)

	memberCIDs, diag := r.getCIDGroupMembers(ctx, cidGroupID)
	if diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	cidsSet, d := flex.FlattenStringValueSet(ctx, memberCIDs)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.CIDs = cidsSet

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cidGroupResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan, state CIDGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	res, multi, err := r.client.Mssp.UpdateCIDGroups(&mssp.UpdateCIDGroupsParams{
		Context: ctx,
		Body: &models.DomainCIDGroupsRequestV1{
			Resources: []*models.DomainCIDGroup{
				{
					CidGroupID:  flex.FrameworkToStringPointer(plan.ID),
					Name:        flex.FrameworkToStringPointer(plan.Name),
					Description: plan.Description.ValueStringPointer(),
				},
			},
		},
	})
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopes)
		resp.Diagnostics.Append(diag)
		return
	}

	if multi != nil {
		if diag := tferrors.NewDiagnosticFromAPIError(tferrors.Update, multi, apiScopes); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	plan.wrap(res.Payload.Resources[0])

	if !plan.CIDs.Equal(state.CIDs) {
		toAdd, toRemove, d := utils.SetIDsToModify(ctx, plan.CIDs, state.CIDs)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}

		if len(toRemove) > 0 {
			if diag := r.deleteCIDGroupMembers(ctx, plan.ID.ValueString(), toRemove); diag != nil {
				resp.Diagnostics.Append(diag)
				return
			}
		}

		if len(toAdd) > 0 {
			if diag := r.addCIDGroupMembers(ctx, plan.ID.ValueString(), toAdd); diag != nil {
				resp.Diagnostics.Append(diag)
				return
			}
		}

		memberCIDs, diag := r.getCIDGroupMembers(ctx, plan.ID.ValueString())
		if diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}

		cidsSet, d := flex.FlattenStringValueSet(ctx, memberCIDs)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.CIDs = cidsSet
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *cidGroupResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state CIDGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !state.CIDs.IsNull() && len(state.CIDs.Elements()) > 0 {
		var cids []string
		resp.Diagnostics.Append(state.CIDs.ElementsAs(ctx, &cids, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		if diag := r.deleteCIDGroupMembers(ctx, state.ID.ValueString(), cids); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	_, multi, err := r.client.Mssp.DeleteCIDGroups(&mssp.DeleteCIDGroupsParams{
		Context:     ctx,
		CidGroupIds: []string{state.ID.ValueString()},
	})
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopes)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	if multi != nil {
		if diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, multi, apiScopes); diag != nil {
			if diag.Summary() == tferrors.NotFoundErrorSummary {
				return
			}
			resp.Diagnostics.Append(diag)
			return
		}
	}
}

func (r *cidGroupResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *cidGroupResource) getCIDGroupByID(ctx context.Context, cidGroupID string) (*models.DomainCIDGroup, diag.Diagnostic) {
	res, multi, err := r.client.Mssp.GetCIDGroupByIDV2(&mssp.GetCIDGroupByIDV2Params{
		Context: ctx,
		Ids:     []string{cidGroupID},
	})
	if err != nil {
		return nil, tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopes)
	}

	if multi != nil {
		return nil, tferrors.NewDiagnosticFromAPIError(tferrors.Read, multi, apiScopes)
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		return nil, tferrors.NewEmptyResponseError(tferrors.Read)
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		return nil, diag
	}

	return res.Payload.Resources[0], nil
}

func (r *cidGroupResource) getCIDGroupMembers(ctx context.Context, cidGroupID string) ([]string, diag.Diagnostic) {
	res, multi, err := r.client.Mssp.GetCIDGroupMembersByV2(&mssp.GetCIDGroupMembersByV2Params{
		Context: ctx,
		Ids:     []string{cidGroupID},
	})
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopes)
		if diag != nil && diag.Summary() != tferrors.NotFoundErrorSummary {
			return nil, diag
		}
	}

	if multi != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, multi, apiScopes)
		if diag != nil && diag.Summary() != tferrors.NotFoundErrorSummary {
			return nil, diag
		}
	}

	var memberCIDs []string
	if res != nil && res.Payload != nil && len(res.Payload.Resources) > 0 {
		for _, memberGroup := range res.Payload.Resources {
			if memberGroup != nil {
				memberCIDs = append(memberCIDs, memberGroup.Cids...)
			}
		}
	}

	return memberCIDs, nil
}

func (r *cidGroupResource) addCIDGroupMembers(ctx context.Context, cidGroupID string, cids []string) diag.Diagnostic {
	res, multi, err := r.client.Mssp.AddCIDGroupMembers(&mssp.AddCIDGroupMembersParams{
		Context: ctx,
		Body: &models.DomainCIDGroupMembersRequestV1{
			Resources: []*models.DomainCIDGroupMembers{
				{
					CidGroupID: &cidGroupID,
					Cids:       cids,
				},
			},
		},
	})
	if err != nil {
		return tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopes)
	}

	if multi != nil {
		if diag := tferrors.NewDiagnosticFromAPIError(tferrors.Update, multi, apiScopes); diag != nil {
			return diag
		}
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		return tferrors.NewEmptyResponseError(tferrors.Update)
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, res.Payload.Errors); diag != nil {
		return diag
	}

	return nil
}

func (r *cidGroupResource) deleteCIDGroupMembers(ctx context.Context, cidGroupID string, cids []string) diag.Diagnostic {
	res, multi, err := r.client.Mssp.DeleteCIDGroupMembersV2(&mssp.DeleteCIDGroupMembersV2Params{
		Context: ctx,
		Body: &models.DomainCIDGroupMembersRequestV1{
			Resources: []*models.DomainCIDGroupMembers{
				{
					CidGroupID: &cidGroupID,
					Cids:       cids,
				},
			},
		},
	})
	if err != nil {
		return tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopes)
	}

	if multi != nil {
		if diag := tferrors.NewDiagnosticFromAPIError(tferrors.Update, multi, apiScopes); diag != nil {
			return diag
		}
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		return tferrors.NewEmptyResponseError(tferrors.Update)
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, res.Payload.Errors); diag != nil {
		return diag
	}

	return nil
}
