package userroles

import (
	"context"
	"fmt"
	"regexp"
	"sort"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &userRolesDataSource{}
	_ datasource.DataSourceWithConfigure = &userRolesDataSource{}
)

// entitiesRolesBatchSize is the maximum number of role IDs the
// EntitiesRolesGETV2 endpoint accepts per request.
const entitiesRolesBatchSize = 5000

var (
	documentationSection          = "User Management"
	dataSourceMarkdownDescription = "Lists the Falcon user roles available for a customer (CID), including default and custom roles with their display name, description, scope, and type."
	requiredScopes                = []scopes.Scope{
		{Name: "User Management", Read: true},
	}
)

// NewUserRolesDataSource creates a new instance of the user roles data source.
func NewUserRolesDataSource() datasource.DataSource {
	return &userRolesDataSource{}
}

type userRolesDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type userRolesDataSourceModel struct {
	UserUUID types.String `tfsdk:"user_uuid"`
	CID      types.String `tfsdk:"cid"`
	Roles    types.List   `tfsdk:"roles"`
}

type roleModel struct {
	ID          types.String `tfsdk:"id"`
	DisplayName types.String `tfsdk:"display_name"`
	Description types.String `tfsdk:"description"`
	IsGlobal    types.Bool   `tfsdk:"is_global"`
	Type        types.String `tfsdk:"type"`
	CID         types.String `tfsdk:"cid"`
}

func (m roleModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":           types.StringType,
		"display_name": types.StringType,
		"description":  types.StringType,
		"is_global":    types.BoolType,
		"type":         types.StringType,
		"cid":          types.StringType,
	}
}

func (d *userRolesDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)

		return
	}

	d.client = providerConfig.Client
}

func (d *userRolesDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_user_roles"
}

func (d *userRolesDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(documentationSection, dataSourceMarkdownDescription, requiredScopes),
		Attributes: map[string]schema.Attribute{
			"user_uuid": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The ID of the user to get available roles for.",
			},
			"cid": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "(FCTL customers) When making requests from the parent CID, use cid to specify the ID of the child CID to retrieve user role IDs from. Multiple values are not supported. In FCTL deployments, a user_uuid may be assigned the same role in multiple CIDs. The cid parameter ensures that role IDs are retrieved from the right CID. If a cid is not provided, the user role IDs are retrieved for the CID making the request. Provide the 32-character lowercase hexadecimal CID without the checksum suffix (e.g. `abcdef1234567890abcdef1234567890`, not `ABCDEF1234567890ABCDEF1234567890-0F`).",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-f0-9]{32}$`),
						"must be a 32-character lowercase hexadecimal CID without the checksum suffix",
					),
				},
			},
			"roles": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The user roles available for the CID.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The unique identifier of the role.",
						},
						"display_name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The human-readable name of the role.",
						},
						"description": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The description of the role.",
						},
						"is_global": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Whether the role applies globally across all CIDs.",
						},
						"type": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The role type, either `default` or `custom`.",
						},
						"cid": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The Customer ID (CID) that owns the role. Only set for custom roles; null for default roles.",
						},
					},
				},
			},
		},
	}
}

func (d *userRolesDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var state userRolesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	roleIDs, diags := d.queryRoleIDs(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	roles, diags := d.getRoles(ctx, state, roleIDs)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The API returns roles in a non-deterministic order, so sort by the
	// required, unique ID to keep the state stable across reads.
	sort.Slice(roles, func(i, j int) bool {
		var a, b string
		if roles[i] != nil && roles[i].ID != nil {
			a = *roles[i].ID
		}
		if roles[j] != nil && roles[j].ID != nil {
			b = *roles[j].ID
		}
		return a < b
	})

	roleModels := make([]roleModel, 0, len(roles))
	for _, r := range roles {
		if r == nil {
			continue
		}
		roleModels = append(roleModels, roleModel{
			ID:          flex.StringPointerToFramework(r.ID),
			DisplayName: flex.StringPointerToFramework(r.DisplayName),
			Description: flex.StringPointerToFramework(r.Description),
			IsGlobal:    types.BoolPointerValue(r.IsGlobal),
			Type:        flex.StringValueToFramework(r.Type),
			CID:         flex.StringValueToFramework(r.Cid),
		})
	}

	state.Roles = utils.SliceToListTypeObject(ctx, roleModels, roleModel{}.AttributeTypes(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// queryRoleIDs lists the role IDs available for the requested CID and user.
//
// The undocumented action query parameter is intentionally never set: omitting
// it returns the same roles surfaced in the Falcon console. gofalcon leaves
// Action nil unless SetDefaults/WithAction is called, so neither is used here.
func (d *userRolesDataSource) queryRoleIDs(
	ctx context.Context,
	state userRolesDataSourceModel,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := user_management.NewQueriesRolesV1ParamsWithContext(ctx)
	if utils.IsKnown(state.CID) {
		params.Cid = state.CID.ValueStringPointer()
	}
	if utils.IsKnown(state.UserUUID) {
		params.UserUUID = state.UserUUID.ValueStringPointer()
	}

	res, err := d.client.UserManagement.QueriesRolesV1(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, requiredScopes))
		return nil, diags
	}

	if res == nil || res.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		diags.Append(diag)
		return nil, diags
	}

	tflog.Debug(ctx, "[datasource] Retrieved user role IDs", map[string]any{
		"count": len(res.Payload.Resources),
	})

	return res.Payload.Resources, diags
}

// getRoles hydrates the full details for each role ID, batching requests to
// respect the endpoint's per-request ID limit.
func (d *userRolesDataSource) getRoles(
	ctx context.Context,
	state userRolesDataSourceModel,
	roleIDs []string,
) ([]*models.DomainRole, diag.Diagnostics) {
	var diags diag.Diagnostics
	var roles []*models.DomainRole

	for start := 0; start < len(roleIDs); start += entitiesRolesBatchSize {
		end := start + entitiesRolesBatchSize
		if end > len(roleIDs) {
			end = len(roleIDs)
		}

		params := user_management.NewEntitiesRolesGETV2ParamsWithContext(ctx)
		params.Body = &models.MsaspecIdsRequest{Ids: roleIDs[start:end]}
		if utils.IsKnown(state.CID) {
			params.Cid = state.CID.ValueStringPointer()
		}

		res, err := d.client.UserManagement.EntitiesRolesGETV2(params)
		if err != nil {
			diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, requiredScopes))
			return nil, diags
		}

		if res == nil || res.Payload == nil {
			diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
			return nil, diags
		}

		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
			diags.Append(diag)
			return nil, diags
		}

		roles = append(roles, res.Payload.Resources...)
	}

	tflog.Debug(ctx, "[datasource] Hydrated user roles", map[string]any{
		"count": len(roles),
	})

	return roles, diags
}
