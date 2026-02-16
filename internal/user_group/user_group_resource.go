package usergroup

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/mssp"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
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
	_ resource.Resource                = &userGroupResource{}
	_ resource.ResourceWithConfigure   = &userGroupResource{}
	_ resource.ResourceWithImportState = &userGroupResource{}
)

func NewUserGroupResource() resource.Resource {
	return &userGroupResource{}
}

type userGroupResource struct {
	client *client.CrowdStrikeAPISpecification
}

type userGroupResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	UserUuids   types.Set    `tfsdk:"user_uuids"`
	Cid         types.String `tfsdk:"cid"`
	LastUpdated types.String `tfsdk:"last_updated"`
}

func (r *userGroupResource) Configure(
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

func (r *userGroupResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_user_group"
}

func (r *userGroupResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Flight Control",
			"This resource manages user groups in CrowdStrike Falcon Flight Control.",
			apiScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The unique identifier for the user group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the user group.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "A description for the user group.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"user_uuids": schema.SetAttribute{
				Optional:            true,
				MarkdownDescription: "A set of user UUIDs that are members of this user group. Maximum 500 members allowed.",
				ElementType:         types.StringType,
				Validators: []validator.Set{
					setvalidator.SizeAtMost(500),
					setvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
				},
			},
			"cid": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The customer ID associated with the user group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The RFC850 timestamp of the last update to this resource by Terraform.",
			},
		},
	}
}

func (r *userGroupResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan userGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createParams := mssp.NewCreateUserGroupsParams()
	createParams.Context = ctx
	createParams.Body = &models.DomainUserGroupsRequestV1{
		Resources: []*models.DomainUserGroup{
			{
				Name:        plan.Name.ValueStringPointer(),
				Description: plan.Description.ValueStringPointer(),
			},
		},
	}

	res, multi, err := r.client.Mssp.CreateUserGroups(createParams)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, apiScopes))
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

	userGroup := res.Payload.Resources[0]
	plan.wrap(userGroup)

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.UserUuids.IsNull() && len(plan.UserUuids.Elements()) > 0 {
		var userUuids []string
		resp.Diagnostics.Append(plan.UserUuids.ElementsAs(ctx, &userUuids, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		if diag := r.addUserGroupMembers(ctx, plan.ID.ValueString(), userUuids); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *userGroupResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state userGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	userGroup, diag := r.getUserGroupByID(ctx, state.ID.ValueString())
	if diag != nil {
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	state.wrap(userGroup)

	memberUuids, diag := r.getUserGroupMembers(ctx, state.ID.ValueString())
	if diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	if len(memberUuids) > 0 {
		userUuids, diags := types.SetValueFrom(ctx, types.StringType, memberUuids)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.UserUuids = userUuids
	} else {
		state.UserUuids = types.SetNull(types.StringType)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *userGroupResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan userGroupResourceModel
	var state userGroupResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateParams := mssp.NewUpdateUserGroupsParams()
	updateParams.Context = ctx
	updateParams.Body = &models.DomainUserGroupsRequestV1{
		Resources: []*models.DomainUserGroup{
			{
				UserGroupID: plan.ID.ValueString(),
				Name:        plan.Name.ValueStringPointer(),
				Description: plan.Description.ValueStringPointer(),
			},
		},
	}

	res, multi, err := r.client.Mssp.UpdateUserGroups(updateParams)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopes))
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

	userGroup := res.Payload.Resources[0]
	plan.wrap(userGroup)

	if !plan.UserUuids.Equal(state.UserUuids) {
		var planUuids, stateUuids []string

		if !plan.UserUuids.IsNull() {
			resp.Diagnostics.Append(plan.UserUuids.ElementsAs(ctx, &planUuids, false)...)
		}
		if !state.UserUuids.IsNull() {
			resp.Diagnostics.Append(state.UserUuids.ElementsAs(ctx, &stateUuids, false)...)
		}
		if resp.Diagnostics.HasError() {
			return
		}

		toRemove := difference(stateUuids, planUuids)
		toAdd := difference(planUuids, stateUuids)

		if len(toRemove) > 0 {
			if diag := r.deleteUserGroupMembers(ctx, plan.ID.ValueString(), toRemove); diag != nil {
				resp.Diagnostics.Append(diag)
				return
			}
		}

		if len(toAdd) > 0 {
			if diag := r.addUserGroupMembers(ctx, plan.ID.ValueString(), toAdd); diag != nil {
				resp.Diagnostics.Append(diag)
				return
			}
		}
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *userGroupResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state userGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !state.UserUuids.IsNull() && len(state.UserUuids.Elements()) > 0 {
		var userUuids []string
		resp.Diagnostics.Append(state.UserUuids.ElementsAs(ctx, &userUuids, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		if diag := r.deleteUserGroupMembers(ctx, state.ID.ValueString(), userUuids); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	deleteParams := mssp.NewDeleteUserGroupsParams()
	deleteParams.Context = ctx
	deleteParams.UserGroupIds = []string{state.ID.ValueString()}

	_, multi, err := r.client.Mssp.DeleteUserGroups(deleteParams)
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

func (r *userGroupResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *userGroupResource) getUserGroupByID(ctx context.Context, userGroupID string) (*models.DomainUserGroup, diag.Diagnostic) {
	getParams := mssp.NewGetUserGroupsByIDParams()
	getParams.Context = ctx
	getParams.UserGroupIds = []string{userGroupID}

	res, multi, err := r.client.Mssp.GetUserGroupsByID(getParams)
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

func (r *userGroupResource) getUserGroupMembers(ctx context.Context, userGroupID string) ([]string, diag.Diagnostic) {
	getMembersParams := mssp.NewGetUserGroupMembersByIDParams()
	getMembersParams.Context = ctx
	getMembersParams.UserGroupIds = []string{userGroupID}

	res, multi, err := r.client.Mssp.GetUserGroupMembersByID(getMembersParams)
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

	var memberUuids []string
	if res != nil && res.Payload != nil && len(res.Payload.Resources) > 0 {
		if res.Payload.Resources[0] != nil {
			memberUuids = append(memberUuids, res.Payload.Resources[0].UserUuids...)
		}
	}

	return memberUuids, nil
}

func (r *userGroupResource) addUserGroupMembers(ctx context.Context, userGroupID string, userUuids []string) diag.Diagnostic {
	addParams := mssp.NewAddUserGroupMembersParams()
	addParams.Context = ctx
	addParams.Body = &models.DomainUserGroupMembersRequestV1{
		Resources: []*models.DomainUserGroupMembers{
			{
				UserGroupID: &userGroupID,
				UserUuids:   userUuids,
			},
		},
	}

	res, multi, err := r.client.Mssp.AddUserGroupMembers(addParams)
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

func (r *userGroupResource) deleteUserGroupMembers(ctx context.Context, userGroupID string, userUuids []string) diag.Diagnostic {
	deleteParams := mssp.NewDeleteUserGroupMembersParams()
	deleteParams.Context = ctx
	deleteParams.Body = &models.DomainUserGroupMembersRequestV1{
		Resources: []*models.DomainUserGroupMembers{
			{
				UserGroupID: &userGroupID,
				UserUuids:   userUuids,
			},
		},
	}

	res, multi, err := r.client.Mssp.DeleteUserGroupMembers(deleteParams)
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

func (m *userGroupResourceModel) wrap(userGroup *models.DomainUserGroup) {
	m.ID = types.StringValue(userGroup.UserGroupID)
	m.Name = types.StringPointerValue(userGroup.Name)
	// TODO: Re-enable once gofalcon SDK bug is fixed that prevents setting description to null
	// Currently the API returns empty string instead of null, causing Terraform state inconsistencies
	// m.Description = types.StringPointerValue(userGroup.Description)
	m.Cid = types.StringValue(userGroup.Cid)
}

func difference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}
