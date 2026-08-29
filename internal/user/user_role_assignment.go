package user

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/retry"
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
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &userRoleAssignmentResource{}
	_ resource.ResourceWithConfigure   = &userRoleAssignmentResource{}
	_ resource.ResourceWithImportState = &userRoleAssignmentResource{}
	_ resource.ResourceWithModifyPlan  = &userRoleAssignmentResource{}
)

var (
	roleAssignmentMarkdownDescription string = "This resource manages the complete set of Falcon roles assigned **directly** to an existing user within a customer ID (CID). " +
		"User roles determine what a user can see and do in the Falcon console.\n\n" +
		"The set of `role_ids` is authoritative for permanently, directly-assigned roles: roles present on the user but absent from the configuration are revoked, and roles in the configuration but absent from the user are granted. " +
		"Roles assigned directly outside of Terraform in this CID will be removed on the next apply.\n\n" +
		"Omitting `role_ids` leaves the user with no directly-assigned roles.\n\n" +
		"The roles in `role_ids` are granted to the user in the CID set by `cid`. Use the `crowdstrike_cid` data source to get the CID for the authenticating credentials.\n\n" +
		"Roles a user inherits through a user group or CID group (Falcon Flight Control), and temporary roles (granted with an expiration), are not shown or managed by this resource and are left untouched.\n\n" +
		"## Custom roles\n\n" +
		"Unlike default roles, custom roles are specific to the CID in which they are created. For Flight Control multi-CID environments, custom roles must be created and assigned in the home CID of the user. You can't assign a custom role to a user in a CID that is not their home CID."
	roleAssignmentRequiredScopes []scopes.Scope = []scopes.Scope{
		{
			Name:  "User management",
			Read:  true,
			Write: true,
		},
	}
)

const (
	roleActionGrant  = "grant"
	roleActionRevoke = "revoke"
	// roleActionChunkSize is the maximum number of role IDs sent in a single
	// grant or revoke call. Batches are atomic, so a smaller chunk limits the
	// blast radius of an invalid role ID.
	roleActionChunkSize = 100
	// roleConsistencyTimeout and roleConsistencyInterval bound the wait for the
	// roles read to match the configuration. The read is not immediately
	// consistent after a grant or revoke, and has been observed disagreeing
	// with the applied set for more than 30 seconds.
	roleConsistencyTimeout  = 90 * time.Second
	roleConsistencyInterval = 2 * time.Second
)

// NewUserRoleAssignmentResource is a helper function to simplify the provider implementation.
func NewUserRoleAssignmentResource() resource.Resource {
	return &userRoleAssignmentResource{}
}

type userRoleAssignmentResource struct {
	client *client.CrowdStrikeAPISpecification
}

type userRoleAssignmentResourceModel struct {
	UserUUID types.String `tfsdk:"user_uuid"`
	Cid      types.String `tfsdk:"cid"`
	RoleIDs  types.Set    `tfsdk:"role_ids"`
}

// wrap writes the roles returned by the API to the model. cid is left as
// configured: it is an immutable, required attribute, and on import it is
// carried in the import ID.
func (m *userRoleAssignmentResourceModel) wrap(
	ctx context.Context,
	assigned []*models.FlightcontrolapiCombinedUserRolesResourceV2,
) diag.Diagnostics {
	var diags diag.Diagnostics

	roles, d := flex.FlattenStringValueSet(ctx, roleIDs(assigned))
	diags.Append(d...)
	m.RoleIDs = roles

	return diags
}

// roleIDs returns the role IDs of a roles response.
func roleIDs(assigned []*models.FlightcontrolapiCombinedUserRolesResourceV2) []string {
	ids := make([]string, 0, len(assigned))
	for _, role := range assigned {
		if role == nil || role.RoleID == nil {
			continue
		}
		ids = append(ids, *role.RoleID)
	}
	return ids
}

func (r *userRoleAssignmentResource) Configure(
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

func (r *userRoleAssignmentResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_user_role_assignment"
}

func (r *userRoleAssignmentResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(documentationSection, roleAssignmentMarkdownDescription, roleAssignmentRequiredScopes),
		Attributes: map[string]schema.Attribute{
			"user_uuid": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The UUID of the existing user to assign roles to. Changing this forces a new resource to be created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"cid": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The customer ID (CID) to grant the roles in. Falcon Flight Control (FCTL) customers making requests from the parent CID can set this to the ID of a child CID. Provide the 32-character lowercase hexadecimal CID without the checksum suffix (e.g. `abcdef1234567890abcdef1234567890`, not `ABCDEF1234567890ABCDEF1234567890-0F`); use the `crowdstrike_cid` data source to get the CID for the authenticating credentials. Changing this forces a new resource to be created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					fwvalidators.CID(),
				},
			},
			"role_ids": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "The set of role IDs to assign directly to the user. This set is authoritative for permanently, directly-granted roles. Omit it to revoke every directly-assigned role. Use the `crowdstrike_user_roles` data source to list the role IDs available in a CID.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
				},
			},
		},
	}
}

func (r *userRoleAssignmentResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan userRoleAssignmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	userUUID := plan.UserUUID.ValueString()
	cid := plan.Cid.ValueString()

	planRoleIDs := flex.ExpandSetAs[string](ctx, plan.RoleIDs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// role_ids is authoritative for the CID, so reconcile against the roles the
	// user already has rather than only granting. Roles assigned outside of
	// Terraform are revoked, which is how an update behaves. Granting alone
	// would leave them in place and then fail the consistency check below.
	assigned, diag := r.getAssignedRoles(ctx, tferrors.Create, userUUID, cid)
	if diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	assignedRoleIDs, d := flex.FlattenStringValueSet(ctx, roleIDs(assigned))
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	toGrant, toRevoke, diags := utils.SetIDsToModify(ctx, plan.RoleIDs, assignedRoleIDs)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(toGrant) > 0 {
		if diag := r.roleAction(ctx, tferrors.Create, roleActionGrant, userUUID, cid, toGrant); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	// Record the granted roles before revoking and reading them back so a
	// later failure still leaves enough state to revoke them.
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(toRevoke) > 0 {
		if diag := r.roleAction(ctx, tferrors.Create, roleActionRevoke, userUUID, cid, toRevoke); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	assigned, diag = r.getAssignedRolesAfterAction(ctx, tferrors.Create, userUUID, cid, planRoleIDs)
	if diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, assigned)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// ModifyPlan warns when creating the resource revokes roles that are already
// assigned in the target CID but absent from the configuration.
func (r *userRoleAssignmentResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	// A null plan is a destroy and a non-null state is an update. Only a
	// create hides the revoked roles: an update renders them in the plan diff
	// from prior state.
	if req.Plan.Raw.IsNull() || !req.State.Raw.IsNull() || r.client == nil {
		return
	}

	var plan userRoleAssignmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// cid can still be unknown when it references a resource created in the
	// same apply, which leaves nothing to check against.
	if plan.UserUUID.IsNull() || plan.UserUUID.IsUnknown() ||
		plan.Cid.IsNull() || plan.Cid.IsUnknown() || plan.RoleIDs.IsUnknown() {
		return
	}

	userUUID := plan.UserUUID.ValueString()
	cid := plan.Cid.ValueString()

	assigned, d := r.getAssignedRoles(ctx, tferrors.Read, userUUID, cid)
	if d != nil {
		tflog.Debug(ctx, "skipping unmanaged role check, could not read assigned roles", map[string]any{
			"user_uuid": userUUID,
			"cid":       cid,
			"error":     d.Detail(),
		})

		return
	}

	var configDiags diag.Diagnostics
	configured := flex.ExpandSetAs[string](ctx, plan.RoleIDs, &configDiags)
	if configDiags.HasError() {
		return
	}

	unmanaged := unmanagedRoleIDs(roleIDs(assigned), configured)
	if len(unmanaged) == 0 {
		return
	}

	resp.Diagnostics.AddWarning(
		"User roles will be revoked",
		fmt.Sprintf(
			"User %s has %d directly-assigned role(s) in CID %s that are not in role_ids: %s.\n\n"+
				"role_ids is authoritative for this CID, so applying this plan revokes them. "+
				"To keep these roles, add them to role_ids. To manage the existing assignment "+
				"instead of creating a new one, import it:\n\n"+
				"  terraform import <resource address> %s,%s",
			userUUID,
			len(unmanaged),
			cid,
			strings.Join(unmanaged, ", "),
			userUUID,
			cid,
		),
	)
}

func (r *userRoleAssignmentResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state userRoleAssignmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	assigned, diag := r.getAssignedRoles(ctx, tferrors.Read, state.UserUUID.ValueString(), state.Cid.ValueString())
	if diag != nil {
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, assigned)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *userRoleAssignmentResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan userRoleAssignmentResourceModel
	var state userRoleAssignmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cid := plan.Cid.ValueString()
	userUUID := plan.UserUUID.ValueString()

	toGrant, toRevoke, diags := utils.SetIDsToModify(ctx, plan.RoleIDs, state.RoleIDs)
	resp.Diagnostics.Append(diags...)

	planRoleIDs := flex.ExpandSetAs[string](ctx, plan.RoleIDs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(toGrant) > 0 {
		if diag := r.roleAction(ctx, tferrors.Update, roleActionGrant, userUUID, cid, toGrant); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	if len(toRevoke) > 0 {
		if diag := r.roleAction(ctx, tferrors.Update, roleActionRevoke, userUUID, cid, toRevoke); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	assigned, diag := r.getAssignedRolesAfterAction(ctx, tferrors.Update, userUUID, cid, planRoleIDs)
	if diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, assigned)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *userRoleAssignmentResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state userRoleAssignmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	roleIDs := flex.ExpandSetAs[string](ctx, state.RoleIDs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(roleIDs) == 0 {
		return
	}

	if diag := r.roleAction(ctx, tferrors.Delete, roleActionRevoke, state.UserUUID.ValueString(), state.Cid.ValueString(), roleIDs); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}
}

func (r *userRoleAssignmentResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	idParts := strings.Split(req.ID, ",")
	if len(idParts) != 2 || idParts[0] == "" || idParts[1] == "" {
		resp.Diagnostics.AddError(
			"Unexpected Import Identifier",
			fmt.Sprintf("Expected \"user_uuid,cid\" with both parts set. Got: %q", req.ID),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("user_uuid"), idParts[0])...)
	// The import ID bypasses schema validation, so normalize the CID to the
	// lowercase form the schema requires. Without this, an uppercase CID is
	// imported verbatim and the next plan silently replaces the resource.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("cid"), strings.ToLower(idParts[1]))...)
}

// roleAction grants or revokes the given role IDs for a user within a CID. Role
// IDs are sent in chunks because the underlying action is atomic per call.
func (r *userRoleAssignmentResource) roleAction(
	ctx context.Context,
	op tferrors.Operation,
	action string,
	userUUID string,
	cid string,
	roleIDs []string,
) diag.Diagnostic {
	tflog.Debug(ctx, "performing user role action", map[string]any{
		"user_uuid": userUUID,
		"cid":       cid,
		"action":    action,
		"role_ids":  roleIDs,
	})

	for _, chunk := range chunkStrings(roleIDs, roleActionChunkSize) {
		params := user_management.NewUserRolesActionV1ParamsWithContext(ctx)
		params.Body = &models.FlightcontrolapiGrantInput{
			Action:  action,
			Cid:     cid,
			RoleIds: chunk,
			UUID:    userUUID,
		}

		res, err := r.client.UserManagement.UserRolesActionV1(params)
		if err != nil {
			return tferrors.NewDiagnosticFromAPIError(op, err, roleAssignmentRequiredScopes)
		}

		if res == nil || res.Payload == nil {
			return tferrors.NewEmptyResponseError(op)
		}

		if diag := tferrors.NewDiagnosticFromPayloadErrors(op, res.Payload.Errors); diag != nil {
			return diag
		}
	}

	return nil
}

// getAssignedRolesAfterAction reads the user's roles, retrying until the
// response holds exactly the expected role IDs. The read is not immediately
// consistent after a grant or revoke: it can omit a role that was granted
// earlier and left untouched, so the whole set has to be checked rather than
// only the roles just acted on. Writing such a response to state would be
// reported by Terraform as an inconsistent result after apply.
func (r *userRoleAssignmentResource) getAssignedRolesAfterAction(
	ctx context.Context,
	op tferrors.Operation,
	userUUID string,
	cid string,
	expected []string,
) ([]*models.FlightcontrolapiCombinedUserRolesResourceV2, diag.Diagnostic) {
	var assigned []*models.FlightcontrolapiCombinedUserRolesResourceV2
	var readDiag diag.Diagnostic
	var mismatch string

	err := retry.RetryUntilNoError(ctx, roleConsistencyTimeout, roleConsistencyInterval, func() error {
		assigned, readDiag = r.getAssignedRoles(ctx, op, userUUID, cid)
		if readDiag != nil {
			return nil
		}

		mismatch = roleSetMismatch(roleIDs(assigned), expected)
		if mismatch != "" {
			return fmt.Errorf("%s", mismatch)
		}

		return nil
	})

	if readDiag != nil {
		return nil, readDiag
	}

	if err != nil {
		return nil, tferrors.NewOperationError(op, fmt.Errorf(
			"timed out waiting for the roles of user %s to match the configuration (%s)",
			userUUID,
			mismatch,
		))
	}

	return assigned, nil
}

// unmanagedRoleIDs returns the assigned role IDs that are absent from the
// configuration. These are the roles an apply revokes because role_ids is
// authoritative for the CID.
func unmanagedRoleIDs(assigned, configured []string) []string {
	inConfig := make(map[string]struct{}, len(configured))
	for _, id := range configured {
		inConfig[id] = struct{}{}
	}

	var unmanaged []string
	for _, id := range assigned {
		if _, found := inConfig[id]; !found {
			unmanaged = append(unmanaged, id)
		}
	}
	sort.Strings(unmanaged)

	return unmanaged
}

// roleSetMismatch describes how the actual role IDs differ from the expected
// ones. It returns an empty string when both hold the same IDs.
func roleSetMismatch(actual, expected []string) string {
	actualSet := make(map[string]struct{}, len(actual))
	for _, id := range actual {
		actualSet[id] = struct{}{}
	}

	expectedSet := make(map[string]struct{}, len(expected))
	for _, id := range expected {
		expectedSet[id] = struct{}{}
	}

	var missing, unexpected []string
	for _, id := range expected {
		if _, found := actualSet[id]; !found {
			missing = append(missing, id)
		}
	}
	for _, id := range actual {
		if _, found := expectedSet[id]; !found {
			unexpected = append(unexpected, id)
		}
	}

	var parts []string
	if len(missing) > 0 {
		parts = append(parts, fmt.Sprintf("roles not assigned: %s", strings.Join(missing, ", ")))
	}
	if len(unexpected) > 0 {
		parts = append(parts, fmt.Sprintf("roles assigned outside of the configuration: %s", strings.Join(unexpected, ", ")))
	}

	return strings.Join(parts, "; ")
}

// getAssignedRoles returns the roles owned by this resource: the permanent,
// directly-granted roles of a user. Inherited roles are excluded by the API
// through direct_only, temporary roles are dropped here. A missing user
// surfaces as a not found diagnostic so callers can remove the resource from
// state.
func (r *userRoleAssignmentResource) getAssignedRoles(
	ctx context.Context,
	op tferrors.Operation,
	userUUID string,
	cid string,
) ([]*models.FlightcontrolapiCombinedUserRolesResourceV2, diag.Diagnostic) {
	directOnly := true
	limit := int64(500)

	params := user_management.NewCombinedUserRolesV2ParamsWithContext(ctx)
	params.UserUUID = userUUID
	params.DirectOnly = &directOnly
	params.Limit = &limit
	params.Cid = &cid

	res, err := r.client.UserManagement.CombinedUserRolesV2(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(op, err, roleAssignmentRequiredScopes)
		// A deleted or nonexistent user is reported as an HTTP 400
		// "invalid user uuid" rather than a 404. Map it to not found so
		// the resource is removed from state on read.
		if strings.Contains(diag.Detail(), "invalid user uuid") {
			return nil, tferrors.NewNotFoundError(diag.Detail())
		}
		return nil, diag
	}

	if res == nil || res.Payload == nil {
		return nil, tferrors.NewEmptyResponseError(op)
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(op, res.Payload.Errors); diag != nil {
		return nil, diag
	}

	var assigned []*models.FlightcontrolapiCombinedUserRolesResourceV2
	for _, role := range res.Payload.Resources {
		if role == nil || role.RoleID == nil {
			continue
		}
		// A temporary grant carries an expires_at and is not owned by this
		// resource.
		if !time.Time(role.ExpiresAt).IsZero() {
			continue
		}
		assigned = append(assigned, role)
	}

	return assigned, nil
}

// chunkStrings splits s into consecutive slices of at most size elements.
func chunkStrings(s []string, size int) [][]string {
	if len(s) == 0 {
		return nil
	}
	var chunks [][]string
	for size < len(s) {
		s, chunks = s[size:], append(chunks, s[0:size:size])
	}
	return append(chunks, s)
}
