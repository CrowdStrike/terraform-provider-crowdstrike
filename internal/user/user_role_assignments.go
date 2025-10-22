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
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &userRoleAssignmentsResource{}
	_ resource.ResourceWithConfigure      = &userRoleAssignmentsResource{}
	_ resource.ResourceWithImportState    = &userRoleAssignmentsResource{}
	_ resource.ResourceWithValidateConfig = &userRoleAssignmentsResource{}
)

func NewUserRoleAssignmentsResource() resource.Resource {
	return &userRoleAssignmentsResource{}
}

type userRoleAssignmentsResource struct {
	client *client.CrowdStrikeAPISpecification
}

type userRoleAssignmentsResourceModel struct {
	UUID                types.String `tfsdk:"uuid"`
	UID                 types.String `tfsdk:"uid"`
	CID                 types.String `tfsdk:"cid"`
	AssignedRoleIds     types.Set    `tfsdk:"assigned_role_ids"`
	SkipRevokeOnDestroy types.Bool   `tfsdk:"skip_revoke_on_destroy"`
}

type roleAssignmentAction string

const (
	roleAssignmentActionRevoke roleAssignmentAction = "revoke"
	roleAssignmentActionGrant  roleAssignmentAction = "grant"
	SkipRevokeOnDestroy        bool                 = true
)

func (r *userRoleAssignmentsResource) Configure(
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

func (r *userRoleAssignmentsResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_user_role_assignments"
}

func (r *userRoleAssignmentsResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"User Role Assignments",
			"This resource manages user roles for an existing CrowdStrike user"+
				"User roles determine what a user can see and do in the Falcon console. Every Falcon user is required to have at least one role, which is assigned when a user account is created.\n"+
				"User roles are granted at the CID level, and you can have different roles in each CID you're associated with. In each CID, you have access to all of the features that your roles allow.",
			userManagementScopes,
		),
		Attributes: map[string]schema.Attribute{
			"uuid": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Unique identifier assigned to the user by CrowdStrike. Either uid or uuid must be provided to find an existing user.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`),
						"must be in the format of xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
					),
				},
			},
			"uid": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The user's email address, which serves as their username. Either uid or uuid must be provided to find an existing user.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$`),
						"must be a valid email address in lowercase",
					),
				},
			},
			"cid": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The CrowdStrike Customer ID (CID) where the existing user resides. If not specified, the CID associated with the provider credentials will be used.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[A-F0-9]{32}$`),
						"must be a 32-character hexadecimal string in uppercase",
					),
				},
			},
			"assigned_role_ids": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Roles to assign to the user. All available for a cid can be retrieved with the `crowdstrike_user_roles` data source",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
				},
			},
			"skip_revoke_on_destroy": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Retain user permissions upon resource deletion, bypassing the default revocation process",
				Default:     booldefault.StaticBool(SkipRevokeOnDestroy),
			},
		},
	}
}

func (r *userRoleAssignmentsResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var data userRoleAssignmentsResourceModel
	var diags diag.Diagnostics
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.CID.ValueString() == "" {
		cid, diags := getCIDFromCredentials(ctx, r.client)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		data.CID = types.StringValue(strings.ToUpper(cid))
	}

	// Checking drift using UUID
	userState, diags := getUser(ctx, r.client, data.UUID.ValueString(), data.UID.ValueString(), data.CID.ValueString())
	if diags.HasError() {
		// Checking drift using UID in case UUID is corrupted
		userState, diags = getUser(ctx, r.client, "", data.UID.ValueString(), data.CID.ValueString())
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			resp.Diagnostics.AddWarning(
				"State File Corrupted",
				fmt.Sprintf("The state file in an unrecoverable state for resource. A new resource will be created.\ncid: %s, uid: %s", userState.CID.ValueString(), userState.UID.ValueString()),
			)
			return
		}
	}

	data.UUID = userState.UUID
	data.UID = userState.UID

	var roles []string
	resp.Diagnostics.Append(data.AssignedRoleIds.ElementsAs(ctx, &roles, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = r.manageUserRoles(ctx, roles, data.UUID.ValueString(), data.CID.ValueString(), roleAssignmentActionGrant)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	assignedRoleIds, diags := getUserRoles(ctx, r.client, data.UUID.ValueString(), data.CID.ValueString())
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	newAssignedRoles, diags := types.SetValueFrom(ctx, types.StringType, assignedRoleIds)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	data.AssignedRoleIds = newAssignedRoles

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *userRoleAssignmentsResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var data userRoleAssignmentsResourceModel
	var userState userResourceModel
	var diags diag.Diagnostics
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.CID.IsNull() || data.CID.ValueString() == "" {
		cid, diags := getCIDFromCredentials(ctx, r.client)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		data.CID = types.StringValue(strings.ToUpper(cid))
	}

	// Checking drift using UUID
	userState, diags = getUser(ctx, r.client, data.UUID.ValueString(), data.UID.ValueString(), data.CID.ValueString())
	if diags.HasError() {
		// Checking drift using UID in case UUID is corrupted
		userState, diags = getUser(ctx, r.client, "", data.UID.ValueString(), data.CID.ValueString())
		if diags.HasError() {
			// If we can't find the user we're assuming it's gone so the resource will be removed
			if strings.Contains(diags[0].Summary(), "No user found for the UID and CID combination") {
				resp.Diagnostics.AddWarning(
					"User Not Found",
					"No user found for the UID and CID combination or UUID.",
				)
				resp.State.RemoveResource(ctx)
				return
			}
			resp.Diagnostics.AddWarning(
				"State File Corrupted",
				"The state file appears to be corrupted. The resource will be recreated.",
			)
			resp.State.RemoveResource(ctx)
			return
		}
		if !data.UUID.Equal(userState.UUID) || !data.UID.Equal(userState.UID) {
			resp.Diagnostics.AddWarning(
				"State Drift Detected",
				"Detected differences between state file and actual UID, UUID, or CID in resource. State will be updated to match reality.\nRun a terraform apply to update the state.",
			)
		}
	}

	data.UUID = userState.UUID
	data.UID = userState.UID

	assignedRoleIds, diags := getUserRoles(ctx, r.client, data.UUID.ValueString(), data.CID.ValueString())
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	newAssignedRoles, diags := types.SetValueFrom(ctx, types.StringType, assignedRoleIds)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	data.AssignedRoleIds = newAssignedRoles

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *userRoleAssignmentsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data userRoleAssignmentsResourceModel
	var userState userResourceModel
	var diags diag.Diagnostics
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	userState, diags = getUser(ctx, r.client, data.UUID.ValueString(), data.UID.ValueString(), data.CID.ValueString())
	if diags.HasError() {
		// Checking drift using UID in case UUID is corrupted
		userState, diags = getUser(ctx, r.client, "", data.UID.ValueString(), data.CID.ValueString())
		if diags.HasError() {
			resp.Diagnostics.AddWarning(
				"State File Corrupted",
				"The state file appears to be corrupted. A new resource will be created to recreate the state.",
			)
			resp.State.RemoveResource(ctx)
			return
		}
	}
	if !data.UUID.Equal(userState.UUID) || !data.UID.Equal(userState.UID) || !data.CID.Equal(userState.CID) {
		resp.Diagnostics.AddWarning(
			"State Drift Detected",
			`Detected differences between state file and actual UID, UUID, or CID in resource. State will be updated to match reality.`,
		)

		data.UUID = userState.UUID
		data.UID = userState.UID
		data.CID = userState.CID
	}

	var roleIds []string
	resp.Diagnostics.Append(data.AssignedRoleIds.ElementsAs(ctx, &roleIds, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = r.updateUserRoles(ctx, data.UUID.ValueString(), data.CID.ValueString(), roleIds)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	assignedRoleIds, diags := getUserRoles(ctx, r.client, data.UUID.ValueString(), data.CID.ValueString())
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	newAssignedRoles, diags := types.SetValueFrom(ctx, types.StringType, assignedRoleIds)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	data.AssignedRoleIds = newAssignedRoles

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *userRoleAssignmentsResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state userRoleAssignmentsResourceModel
	var userState userResourceModel
	var diags diag.Diagnostics
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.SkipRevokeOnDestroy.ValueBool() {
		return
	}

	// Checking if user exists usin UUID
	userState, diags = getUser(ctx, r.client, state.UUID.ValueString(), state.UID.ValueString(), state.CID.ValueString())
	if diags.HasError() {
		// Checking if user exists using UID in case UUID is corrupted
		userState, diags = getUser(ctx, r.client, "", state.UID.ValueString(), state.CID.ValueString())
		if diags.HasError() {
			return
		}
	}

	var rolesIds []string
	resp.Diagnostics.Append(state.AssignedRoleIds.ElementsAs(ctx, &rolesIds, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = r.manageUserRoles(
		ctx,
		rolesIds,
		userState.UUID.ValueString(),
		userState.CID.ValueString(),
		roleAssignmentActionRevoke,
	)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
}

func (r *userRoleAssignmentsResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	parts := strings.Split(req.ID, ",")
	if len(parts) < 2 {
		resp.Diagnostics.AddError(
			"Invalid Import Format",
			"Please use the format 'uuid,role1,role2,...'",
		)
		return
	}

	uuid := parts[0]
	roles := parts[1:]

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("uuid"), uuid)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("assigned_role_ids"), roles)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("skip_revoke_on_destroy"), SkipRevokeOnDestroy)...)
}

func (r *userRoleAssignmentsResource) ConfigValidator(ctx context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.Conflicting(
			path.MatchRoot("uuid"),
		),
		resourcevalidator.AtLeastOneOf(
			path.MatchRoot("uuid"),
			path.MatchRoot("uid"),
		),
	}
}

func (r *userRoleAssignmentsResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config userRoleAssignmentsResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if !config.UUID.IsNull() && !config.UID.IsNull() {
		resp.Diagnostics.AddWarning(
			"Redundant Configuration",
			"Both UUID and UID are provided. UUID will be used for lookup.",
		)
	}

	if config.CID.IsNull() {
		resp.Diagnostics.AddWarning(
			"CID Not Provided",
			"CID is not provided. The CID associated with the API credentials will be used.",
		)
	}
}

func (r *userRoleAssignmentsResource) manageUserRoles(ctx context.Context, roles []string, uuid string, cid string, action roleAssignmentAction) diag.Diagnostics {
	var diags diag.Diagnostics
	errorMessage := fmt.Sprintf("Failed to %s roles to existing Crowdstrike user", string(action))

	params := user_management.UserRolesActionV1Params{
		Context: ctx,
		Body: &models.FlightcontrolapiGrantInput{
			Action:  string(action),
			Cid:     strings.ToLower(cid),
			RoleIds: roles,
			UUID:    uuid,
		},
	}

	resp, err := r.client.UserManagement.UserRolesActionV1(&params)
	if err != nil {
		diags.AddError(
			errorMessage,
			fmt.Sprintf("%s: %s", errorMessage, handleErrors(err, userManagementScopes)),
		)
		return diags
	}

	payload := resp.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			errorMessage,
			fmt.Sprintf("%s: %s", errorMessage, err.Error()),
		)
		return diags
	}

	if *payload.Meta.Writes.ResourcesAffected != 1 {
		diags.AddError(
			errorMessage,
			errorMessage,
		)
		return diags
	}

	return diags
}

func (r *userRoleAssignmentsResource) updateUserRoles(ctx context.Context, uuid string, cid string, newRoles []string) (diags diag.Diagnostics) {

	currentRoleIds, diags := getUserRoles(ctx, r.client, uuid, cid)
	if diag.Diagnostics.HasError(diags) {
		return diags
	}

	rolesToAdd := sliceDifference(newRoles, currentRoleIds)
	rolesToRemove := sliceDifference(currentRoleIds, newRoles)

	if len(rolesToAdd) > 0 {
		diags = r.manageUserRoles(ctx, rolesToAdd, uuid, cid, roleAssignmentActionGrant)
		if diag.Diagnostics.HasError(diags) {
			return diags
		}
	}
	if len(rolesToRemove) > 0 {
		diags = r.manageUserRoles(ctx, rolesToRemove, uuid, cid, roleAssignmentActionRevoke)
		if diag.Diagnostics.HasError(diags) {
			return diags
		}
	}

	return diags
}

// Returns elements in slice1 that are not present in slice2.
func sliceDifference(slice1, slice2 []string) []string {
	diff := make([]string, 0)
	set := make(map[string]struct{})

	for _, item := range slice2 {
		set[item] = struct{}{}
	}

	for _, item := range slice1 {
		if _, found := set[item]; !found {
			diff = append(diff, item)
		}
	}

	return diff
}
