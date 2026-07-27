package user

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwtypes "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/types"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                     = &userResource{}
	_ resource.ResourceWithConfigure        = &userResource{}
	_ resource.ResourceWithImportState      = &userResource{}
	_ resource.ResourceWithConfigValidators = &userResource{}
)

var (
	documentationSection        string = "User Management"
	resourceMarkdownDescription string = "This resource allows management of a user on the CrowdStrike Falcon platform.\n\n" +
		"A user account identifies a person who accesses the Falcon console and determines which resources they can access. Every user account has a home CID, which is where the account is created, stored, and managed. A user is identified by their email address, which must be unique: it cannot be used by another user or added in another CID.\n\n" +
		"Assign roles to a user with the `crowdstrike_user_role_assignment` resource.\n\n" +
		"### Password management\n\n" +
		"To set an initial password, provide it with the write-only `password_wo` argument together with `password_wo_version`. If you omit both, the user is created without a password: when SSO is not enabled, CrowdStrike sends the user an automated email prompting them to create a Falcon password and configure MFA. When SSO is enabled, no email is sent.\n\n" +
		"The Falcon API has no in-place password-change endpoint, so changing a password is realized as a resource replacement. Changing `password_wo` alone has no effect, since write-only values are never stored in state and cannot produce a plan diff. To apply a new password, increment `password_wo_version`: this destroys and recreates the user with the current `password_wo` value. The new user has a different `id` (`user_uuid`), which affects any resources that reference it. To change a password without replacing the user, use the Reset password action in the Falcon console instead."
	requiredScopes []scopes.Scope = []scopes.Scope{
		{
			Name:  "User management",
			Read:  true,
			Write: true,
		},
	}
)

func NewUserResource() resource.Resource {
	return &userResource{}
}

type userResource struct {
	client *client.CrowdStrikeAPISpecification
}

type userResourceModel struct {
	ID                types.String    `tfsdk:"id"`
	Email             types.String    `tfsdk:"email"`
	FirstName         types.String    `tfsdk:"first_name"`
	LastName          types.String    `tfsdk:"last_name"`
	Cid               types.String    `tfsdk:"cid"`
	PasswordWO        types.String    `tfsdk:"password_wo"`
	PasswordWOVersion types.Int64     `tfsdk:"password_wo_version"`
	Status            types.String    `tfsdk:"status"`
	Factors           types.Set       `tfsdk:"factors"`
	UserType          types.String    `tfsdk:"user_type"`
	CreatedAt         fwtypes.RFC3339 `tfsdk:"created_at"`
	LastLoginAt       fwtypes.RFC3339 `tfsdk:"last_login_at"`
	UpdatedAt         fwtypes.RFC3339 `tfsdk:"updated_at"`
}

func (m *userResourceModel) wrap(ctx context.Context, user models.DomainUser) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = flex.StringValueToFramework(user.UUID)
	m.Email = flex.StringValueToFramework(user.UID)
	m.FirstName = flex.StringValueToFramework(user.FirstName)
	m.LastName = flex.StringValueToFramework(user.LastName)
	m.Cid = flex.StringValueToFramework(strings.ToUpper(user.Cid))
	m.Status = flex.StringValueToFramework(user.Status)
	m.UserType = flex.StringValueToFramework(user.UserType)

	factors, d := flex.FlattenStringValueSet(ctx, user.Factors)
	diags.Append(d...)
	m.Factors = factors

	m.CreatedAt = flex.DateTimeValueToFwRFC3339(user.CreatedAt)
	m.LastLoginAt = flex.DateTimeValueToFwRFC3339(user.LastLoginAt)
	m.UpdatedAt = flex.DateTimeValueToFwRFC3339(user.UpdatedAt)

	return diags
}

func (r *userResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)

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

	r.client = providerConfig.Client
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
		MarkdownDescription: utils.MarkdownDescription(documentationSection, resourceMarkdownDescription, requiredScopes),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The UUID assigned to the user by CrowdStrike.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"email": schema.StringAttribute{
				Required:    true,
				Description: "The user's email address, which is also their login. Must be unique: it cannot be used by another user or in another CID. The domain must belong to the CID's domain allowlist, which is configured during the CID's initial provisioning (contact Support to change it). In CIDs with single sign-on (SSO) enabled, the email address must exactly match the information in your IdP. Changing this forces a new user to be created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					fwvalidators.StringIsEmailAddress(),
				},
			},
			"first_name": schema.StringAttribute{
				Required:    true,
				Description: "The user's first name.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"last_name": schema.StringAttribute{
				Required:    true,
				Description: "The user's last name.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"cid": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The customer ID (CID) to create the user in, which becomes the user's home CID. Falcon Flight Control (FCTL) customers making requests from the parent CID can set this to the ID of a child CID. If not provided, the user is created in the CID making the request (the CID associated with the provider credentials). Changing this forces a new user to be created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-fA-F0-9]{32}$`),
						"must be a 32-character hexadecimal string",
					),
				},
			},
			"password_wo": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				WriteOnly:   true,
				Description: "The user's initial password. This is a write-only argument: it is never stored in Terraform state. Because the Falcon API has no in-place password-change endpoint, changing the password requires replacing the user; use `password_wo_version` to trigger that replacement. If omitted, the user is created without a password. When SSO is not enabled, CrowdStrike sends the user an automated email prompting them to create a password and configure MFA. Must be set together with `password_wo_version`.",
			},
			"password_wo_version": schema.Int64Attribute{
				Optional:    true,
				Description: "The version of `password_wo`. Increment this value to apply a new password. Because there is no in-place password-change API, changing this forces the user to be replaced (deleted and recreated), which mints a new UUID and drops any role assignments attached to the old UUID. Must be set together with `password_wo`.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "The user's current status.",
			},
			"factors": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "The multi-factor authentication (MFA) factors configured for the user.",
			},
			"user_type": schema.StringAttribute{
				Computed:    true,
				Description: "The user's type.",
			},
			"created_at": schema.StringAttribute{
				CustomType:  fwtypes.RFC3339Type{},
				Computed:    true,
				Description: "When the user was created (RFC-3339 format).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_login_at": schema.StringAttribute{
				CustomType:  fwtypes.RFC3339Type{},
				Computed:    true,
				Description: "When the user last logged in (RFC-3339 format).",
			},
			"updated_at": schema.StringAttribute{
				CustomType:  fwtypes.RFC3339Type{},
				Computed:    true,
				Description: "When the user was last updated (RFC-3339 format).",
			},
		},
	}
}

func (r *userResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.RequiredTogether(
			path.MatchRoot("password_wo"),
			path.MatchRoot("password_wo_version"),
		),
	}
}

func (r *userResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan userResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var config userResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createBody := &models.DomainCreateUserRequest{
		FirstName: plan.FirstName.ValueString(),
		LastName:  plan.LastName.ValueString(),
		UID:       plan.Email.ValueString(),
	}
	if utils.IsKnown(plan.Cid) {
		createBody.Cid = strings.ToLower(plan.Cid.ValueString())
	}
	if !config.PasswordWO.IsNull() {
		createBody.Password = config.PasswordWO.ValueString()
	}

	createParams := user_management.NewCreateUserV1ParamsWithContext(ctx)
	createParams.Body = createBody

	res, err := r.client.UserManagement.CreateUserV1(createParams)
	if err != nil {
		badRequestHint := "The request was rejected. Verify the submitted values are valid for your CID. Common causes include a password that does not meet your CID's password policy, an email domain that is not on the approved list, or an email that is already in use."
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, requiredScopes, tferrors.WithBadRequestDetail(badRequestHint)))
		return
	}

	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), res.Payload.Resources[0].UUID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *res.Payload.Resources[0])...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
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

	user, diag := r.getUserByUUID(ctx, state.ID.ValueString())
	if diag != nil {
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, *user)...)
	if resp.Diagnostics.HasError() {
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
	if resp.Diagnostics.HasError() {
		return
	}

	updateParams := user_management.NewUpdateUserV1ParamsWithContext(ctx)
	updateParams.UserUUID = plan.ID.ValueString()
	updateParams.Body = &models.DomainUpdateUserRequest{
		FirstName: plan.FirstName.ValueString(),
		LastName:  plan.LastName.ValueString(),
	}

	res, err := r.client.UserManagement.UpdateUserV1(updateParams)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, requiredScopes))
		return
	}

	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *res.Payload.Resources[0])...)
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

	deleteParams := user_management.NewDeleteUserV1ParamsWithContext(ctx)
	deleteParams.UserUUID = state.ID.ValueString()

	res, err := r.client.UserManagement.DeleteUserV1(deleteParams)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, requiredScopes)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	if res != nil && res.Payload != nil {
		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Delete, res.Payload.Errors); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}
}

func (r *userResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *userResource) getUserByUUID(
	ctx context.Context,
	uuid string,
) (*models.DomainUser, diag.Diagnostic) {
	params := user_management.NewRetrieveUsersGETV1ParamsWithContext(ctx)
	params.Body = &models.MsaspecIdsRequest{
		Ids: []string{uuid},
	}

	res, err := r.client.UserManagement.RetrieveUsersGETV1(params)
	if err != nil {
		return nil, tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, requiredScopes)
	}

	if res == nil || res.Payload == nil {
		return nil, tferrors.NewResourceNotFoundWarningDiagnostic()
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		return nil, diag
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		return nil, tferrors.NewResourceNotFoundWarningDiagnostic()
	}

	return res.Payload.Resources[0], nil
}
