package user

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource                     = &userDataSource{}
	_ datasource.DataSourceWithConfigure        = &userDataSource{}
	_ datasource.DataSourceWithConfigValidators = &userDataSource{}
)

func NewUserDataSource() datasource.DataSource {
	return &userDataSource{}
}

type userDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type userDataSourceValidator struct{}

type userDataSourceModel struct {
	UID       types.String `tfsdk:"uid"`
	UUID      types.String `tfsdk:"uuid"`
	FirstName types.String `tfsdk:"first_name"`
	LastName  types.String `tfsdk:"last_name"`
	CID       types.String `tfsdk:"cid"`
}

func (u userDataSourceModel) GetUID() types.String       { return u.UID }
func (u userDataSourceModel) GetUUID() types.String      { return u.UUID }
func (u userDataSourceModel) GetFirstName() types.String { return u.FirstName }
func (u userDataSourceModel) GetLastName() types.String  { return u.LastName }
func (u userDataSourceModel) GetCID() types.String       { return u.CID }

func (r *userDataSource) Configure(
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

func (r *userDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (r *userDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"User",
			"This data source provides information about an existing CrowdStrike user in the Falcon Console.",
			userManagementScopes,
		),
		Attributes: map[string]schema.Attribute{
			"uuid": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Unique identifier assigned to the user by CrowdStrike. Either uid or uuid must be provided to find an existing user",
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
				Description: "The user's email address, which serves as their username. Either this or the UUID must be provided to locate an existing user.",
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
				Description: "The CrowdStrike Customer ID (CID) where the existing user resides. If not assigned, the CID associated with the provider credentials will be used.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[A-F0-9]{32}$`),
						"must be a 32-character hexadecimal string in uppercase",
					),
				},
			},
			"first_name": schema.StringAttribute{
				Computed:    true,
				Description: "First name of the user.",
			},
			"last_name": schema.StringAttribute{
				Computed:    true,
				Description: "Last name of the user.",
			},
		},
	}
}

func (r *userDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data userDataSourceModel
	var actualUserData userResourceModel
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

	// Getting user by UUID
	actualUserData, diags = getUser(ctx, r.client, data.UUID.ValueString(), data.UID.ValueString(), data.CID.ValueString())
	if diags.HasError() {
		// Getting user by CID and UID
		actualUserData, diags = getUser(ctx, r.client, "", data.UID.ValueString(), data.CID.ValueString())
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}

	data.UUID = actualUserData.UUID
	data.UID = actualUserData.UID
	data.FirstName = actualUserData.FirstName
	data.LastName = actualUserData.LastName

	// Set State
	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *userDataSource) ConfigValidators(ctx context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		&userDataSourceValidator{},
		datasourcevalidator.Conflicting(
			path.MatchRoot("uuid"),
		),
		datasourcevalidator.AtLeastOneOf(
			path.MatchRoot("uuid"),
			path.MatchRoot("uid"),
		),
	}
}

func (v *userDataSourceValidator) Description(ctx context.Context) string {
	return "Validates the user data source configuration"
}

func (v *userDataSourceValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v *userDataSourceValidator) ValidateDataSource(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var data userDataSourceModel
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
	if data.UUID.IsNull() && data.UID.IsNull() {
		resp.Diagnostics.AddError(
			"Missing Required Attribute",
			"Either 'uuid' or 'uid' must be provided.",
		)
	}
}
