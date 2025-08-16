package user

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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
		MarkdownDescription: utils.MarkdownDescription(
			"User",
			"This resource allows management of a user on the CrowdStrike Falcon Platform.\n\n"+
				"Users represent the people who access the Falcon console to manage your Falcon environment. Every user account has a home CID. The home CID is where a user account is created, stored, and managed.\n"+
				"For newly created users, the system automatically sends an email containing a link for password configuration, unless the user's CID employs Single Sign-On (SSO).",
			userManagementScopes,
		),
		Attributes: map[string]schema.Attribute{
			"uid": schema.StringAttribute{
				Required:    true,
				Description: "The username to assign to the user. This must be a valid email address. Either uid or uuid must be provided to find an existing user.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$`),
						"must be a valid email address in lowercase",
					),
				},
			},
			"first_name": schema.StringAttribute{
				Required:    true,
				Description: "First name of the user.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_name": schema.StringAttribute{
				Required:    true,
				Description: "Last name of the user.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cid": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "The CrowdStrike Customer ID (CID) for user creation. If not specified, the CID associated with the provider credentials will be used.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[A-F0-9]{32}$`),
						"must be a 32-character hexadecimal string in uppercase",
					),
				},
			},
			"uuid": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier assigned to the user by CrowdStrike.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`),
						"must be in the format of xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
					),
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

	// Import the User into the state if it already exists.
	userState, diags := getUser(ctx, r.client, state.UUID.ValueString(), state.UID.ValueString(), state.CID.ValueString())
	if diags.HasError() {
		userState, diags = getUser(ctx, r.client, "", state.UID.ValueString(), state.CID.ValueString())
		if !diags.HasError() {
			state = userState
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			return
		}
	} else {
		state = userState
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
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

	// Checking drift using UUID
	userState, diags := getUser(ctx, r.client, state.UUID.ValueString(), state.UID.ValueString(), state.CID.ValueString())
	if diags.HasError() {
		// Checking drift using UID in case UUID is corrupted
		userState, diags = getUser(ctx, r.client, "", state.UID.ValueString(), state.CID.ValueString())
		if diags.HasError() {
			if strings.Contains(diags[0].Summary(), "User Not Found") {
				resp.Diagnostics.AddWarning(
					"User Not Found",
					"No user found for the UID and CID combination or UUID.",
				)
				resp.State.RemoveResource(ctx)
				return
			}

			resp.Diagnostics.Append(diags...)
			resp.Diagnostics.AddError(
				"State File Corruption",
				"The state file may be corrupted. Unable to retrieve user information using both UUID and UID.",
			)
			return
		}
	}
	if changed := compareState(state, userState); changed {
		resp.Diagnostics.AddWarning(
			"State Drift Detected",
			"Detected differences between state file and actual UID, UUID, or CID in resource. State will be updated to match reality.\nRun a terraform apply to update the state.",
		)
		resp.Diagnostics.Append(resp.State.Set(ctx, &userState)...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *userResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan userResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	// Fixing drift using UUID
	userState, diags := getUser(ctx, r.client, plan.UUID.ValueString(), plan.UID.ValueString(), plan.CID.ValueString())
	if diags.HasError() {
		// Fixing drift using UID in case UUID is corrupted
		userState, diags = getUser(ctx, r.client, "", plan.UID.ValueString(), plan.CID.ValueString())
		if resp.Diagnostics.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}
	if changed := compareState(plan, userState); changed {
		resp.Diagnostics.AddWarning(
			"State Drift Detected",
			`Detected differences between state file and actual UID, UUID, or CID in resource. State will be updated to match reality before updating User.`,
		)
		plan.UUID = userState.UUID
		plan.UID = userState.UID
		plan.CID = userState.CID
	}

	diags = r.updateUser(ctx, plan.FirstName.ValueString(), plan.LastName.ValueString(), plan.UUID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
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

	if !config.CID.IsNull() && config.CID.ValueString() != strings.ToUpper(config.CID.ValueString()) {
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

	if config.CID.IsNull() {
		resp.Diagnostics.AddWarning(
			"CID Not Provided",
			"CID is not provided. The CID associated with the API credentials will be used.",
		)
	}
}

func (r *userResource) ConfigValidator(ctx context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		// Ensure unique uid and cid combinations
		resourcevalidator.Conflicting(
			path.MatchRoot("uid").AtParent().AtName("cid"),
		),
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
			fmt.Sprintf("Failed to create Crowdstrike user: %s", handleErrors(err, userManagementScopes)),
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
			fmt.Sprintf("Failed to delete Crowdstrike user: %s", handleErrors(err, userManagementScopes)),
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
			fmt.Sprintf("Failed to update existing Crowdstrike user: %s", handleErrors(err, userManagementScopes)),
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

func compareState(previousState userResourceModel, newState userResourceModel) bool {
	return !previousState.UID.Equal(newState.UID) ||
		!previousState.UUID.Equal(newState.UUID) ||
		!previousState.CID.Equal(newState.CID)
}
