package user

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource                     = &userRolesDataSource{}
	_ datasource.DataSourceWithConfigure        = &userRolesDataSource{}
	_ datasource.DataSourceWithConfigValidators = &userRolesDataSource{}
)

func NewUserRolesDataSource() datasource.DataSource {
	return &userRolesDataSource{}
}

type userRolesDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type userRolesDataSourceValidator struct{}

type userRolesDataSourceModel struct {
	CID     types.String `tfsdk:"cid"`
	RoleIds types.List   `tfsdk:"role_ids"`
}

func (r *userRolesDataSource) Configure(
	ctx context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
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

func (r *userRolesDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_user_roles"
}

func (r *userRolesDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"User Roles",
			"This data source retrieves available roles for a specified CID.",
			getRolesScopes),
		Attributes: map[string]schema.Attribute{
			"cid": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The CrowdStrike Customer ID (CID) associated with the user roles to be retrieved. If not specified, the CID associated with the provider credentials will be used.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[A-F0-9]{32}$`),
						"must be a 32-character hexadecimal string in uppercase",
					),
				},
			},
			"role_ids": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "List of role IDs associated with the specified CID",
			},
		},
	}
}

func (r *userRolesDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data userRolesDataSourceModel
	var diags diag.Diagnostics

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
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

	roleIds, diags := r.getUserRoleIdsByCID(ctx, data.CID.ValueString())
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	data.RoleIds = convertStringSliceToTypesList(roleIds)

	// Set State
	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *userRolesDataSource) ConfigValidators(ctx context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		&userRolesDataSourceValidator{},
	}
}

func (v *userRolesDataSourceValidator) Description(ctx context.Context) string {
	return "Validates the user roles data source configuration"
}

func (v *userRolesDataSourceValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v *userRolesDataSourceValidator) ValidateDataSource(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var data userRolesDataSourceModel
	diags := req.Config.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.CID.IsNull() {
		resp.Diagnostics.AddWarning(
			"CID Not Provided",
			"CID is not provided. The CID associated with the API credentials will be used.",
		)
	}
}

func (r *userRolesDataSource) getUserRoleIdsByCID(ctx context.Context, cid string) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	formattedCid := strings.ToLower(cid)

	params := user_management.QueriesRolesV1Params{
		Context: ctx,
		Cid:     &formattedCid,
	}

	resp, err := r.client.UserManagement.QueriesRolesV1(&params)
	if err != nil {
		diags.AddError(
			"Failed to query user role IDs for CID",
			fmt.Sprintf("Failed to query user role IDs for CID: %s", handleErrors(err, getRolesScopes)),
		)
		return nil, diags
	}

	payload := resp.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Failed to query user role IDs for CID",
			fmt.Sprintf("Failed to query user role IDs for CID: %s", err.Error()),
		)
		return nil, diags
	}

	return payload.Resources, diags
}
