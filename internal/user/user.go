package user

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &userResource{}
	_ resource.ResourceWithConfigure      = &userResource{}
	_ resource.ResourceWithImportState    = &userResource{}
	_ resource.ResourceWithValidateConfig = &userResource{}
)

func NewUserResource() resource.Resource {
	return &userResource{}
}

type userResource struct {
	client *client.CrowdStrikeAPISpecification
}

type userResourceModel struct {
	UID       types.String `tfsdk:"uid"`
	UUID      types.String `tfsdk:"uuid"`
	FirstName types.String `tfsdk:"first_name"`
	LastName  types.String `tfsdk:"last_name"`
	CID       types.String `tfsdk:"cid"`
}

func (r *userResource) Configure(
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

func (r *userResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (r *userResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"User --- This resource allows management of users in the CrowdStrike Falcon platform.\n\n%s",
			scopes.GenerateScopeDescription(userManagementScopes),
		),
		Attributes: map[string]schema.Attribute{
			"uid": schema.StringAttribute{
				Required:    true,
				Description: "The user's email address.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
			},
			"first_name": schema.StringAttribute{
				Required:    true,
				Description: "The user's first name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_name": schema.StringAttribute{
				Required:    true,
				Description: "The user's last name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cid": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "CID of the user.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
			},
			"uuid": schema.StringAttribute{
				Computed:    true,
				Description: "UUID of the user",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *userResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var state userResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cid, uuid, diags := r.createUser(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.UUID = types.StringValue(uuid)
	state.CID = types.StringValue(cid)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *userResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state userResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	newState, diags := r.getUser(ctx, state.UUID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, newState)...)
}

func (r *userResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var state userResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &state)...)

	diags := r.updateUser(ctx, state.FirstName.ValueString(), state.LastName.ValueString(), state.UUID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *userResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state userResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags := r.deleteUser(ctx, state.UUID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *userResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("uuid"), req, resp)
}

func (r *userResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config userResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if config.CID.ValueString() != "" && config.CID.ValueString() != strings.ToUpper(config.CID.ValueString()) {
		resp.Diagnostics.AddAttributeError(
			path.Root("cid"),
			"Invalid CID format",
			"CID must be in all uppercase.",
		)
	}

	if config.CID.ValueString() != "" {
		if !validateCIDFormat(config.CID.ValueString()) {
			resp.Diagnostics.AddAttributeError(
				path.Root("cid"),
				"Invalid CID format",
				"CID must be a 32-character hexadecimal string.",
			)
		}
	}

	if !validateEmailFormat(config.UID.ValueString()) {
		resp.Diagnostics.AddAttributeError(
			path.Root("uid"),
			"Invalid email format",
			"UID must be a valid email address.",
		)
	}
}

func (r *userResource) createUser(
	ctx context.Context,
	model userResourceModel,
) (cid string, uuid string, diags diag.Diagnostics) {
	createUserModel := &models.DomainCreateUserRequest{
		FirstName: model.FirstName.ValueString(),
		LastName:  model.LastName.ValueString(),
		UID:       model.UID.ValueString(),
	}

	if model.CID.ValueString() != "" {
		createUserModel.Cid = strings.ToLower(model.CID.ValueString())
	}

	params := &user_management.CreateUserV1Params{
		Context: ctx,
		Body:    createUserModel,
	}

	resp, err := r.client.UserManagement.CreateUserV1(params)
	if err != nil {
		diags.AddError(
			"Failed to create Crowdstrike user",
			fmt.Sprintf("Failed to create Crowdstrike user: %s", handleErrors(err)),
		)
		return cid, uuid, diags
	}

	payload := resp.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Failed to create Crowdstrike user",
			fmt.Sprintf("Failed to create Crowdstrike user: %s", payload.Errors[0]),
		)
		return cid, uuid, diags
	}

	cid = strings.ToUpper(payload.Resources[0].Cid)
	uuid = payload.Resources[0].UUID

	return cid, uuid, diags
}

func (r *userResource) deleteUser(
	ctx context.Context,
	uuid string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	params := &user_management.DeleteUserV1Params{
		Context:  ctx,
		UserUUID: uuid,
	}

	resp, err := r.client.UserManagement.DeleteUserV1(params)
	if err != nil {
		diags.AddError(
			"Failed to delete Crowdstrike user",
			fmt.Sprintf("Failed to delete Crowdstrike user: %s", handleErrors(err)),
		)
		return diags
	}

	payload := resp.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Failed to delete Crowdstrike user",
			fmt.Sprintf("Failed to delete Crowdstrike user: %s", err.Error()),
		)
	}
	return diags
}

func (r *userResource) getUser(
	ctx context.Context,
	uuid string,
) (*userResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	params := &user_management.RetrieveUsersGETV1Params{
		Context: ctx,
		Body: &models.MsaspecIdsRequest{
			Ids: []string{uuid},
		},
	}
	resp, err := r.client.UserManagement.RetrieveUsersGETV1(params)
	if err != nil {
		diags.AddError(
			"Failed to get existing Crowdstrike user",
			fmt.Sprintf("Failed to get existing Crowdstrike user: %s", handleErrors(err)),
		)
		return nil, diags
	}

	payload := resp.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Failed to get existing Crowdstrike user",
			fmt.Sprintf("Failed to get existing Crowdstrike user: %s", err.Error()),
		)
		return nil, diags
	}

	resource := payload.Resources[0]
	model := &userResourceModel{
		UID:       types.StringValue(resource.UID),
		UUID:      types.StringValue(resource.UUID),
		FirstName: types.StringValue(resource.FirstName),
		LastName:  types.StringValue(resource.LastName),
		CID:       types.StringValue(strings.ToUpper(resource.Cid)),
	}

	return model, diags
}

func (r *userResource) updateUser(
	ctx context.Context,
	firstName string,
	lastName string,
	uuid string,
) (diags diag.Diagnostics) {
	params := &user_management.UpdateUserV1Params{
		Context: ctx,
		Body: &models.DomainUpdateUserRequest{
			FirstName: firstName,
			LastName:  lastName,
		},
		UserUUID: uuid,
	}
	resp, err := r.client.UserManagement.UpdateUserV1(params)
	if err != nil {
		diags.AddError(
			"Failed to update existing Crowdstrike user",
			fmt.Sprintf("Failed to update existing Crowdstrike user: %s", handleErrors(err)),
		)
		return diags
	}

	payload := resp.GetPayload()
	if err := falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Failed to update existing Crowdstrike user",
			fmt.Sprintf("Failed to update existing Crowdstrike user: %s", err.Error()),
		)
		return diags
	}

	return diags
}

func handleErrors(err error) (errorString string) {
	var code int
	parts := strings.Split(err.Error(), "Code:")
	if len(parts) > 1 {
		codePart := strings.Split(parts[1], " ")[0]
		if num, parseErr := strconv.Atoi(codePart); parseErr == nil {
			code = num
		} else {
			return err.Error()
		}
	}

	switch code {
	case 403:
		return fmt.Sprintf("403 Forbidden\n\n%s", scopes.GenerateScopeDescription(userManagementScopes))
	case 400:
		return "400 Bad Request"
	case 429:
		return "429 Too Many Requests"
	case 500:
		return "500 Internal Server Error"
	}
	return errorString
}

func validateCIDFormat(cid string) bool {
	if len(cid) != 32 {
		return false
	}
	for _, char := range cid {
		if !((char >= '0' && char <= '9') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true

}

func validateEmailFormat(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}
