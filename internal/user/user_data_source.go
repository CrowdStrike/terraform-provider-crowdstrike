package user

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	dataSourceDocumentationSection = "User Management"
	dataSourceMarkdownDescription  = "This data source provides information about a single Falcon user. Use this to look up a user by user UUID or email and reference their attributes in other resources."
)

var dataSourceApiScopes = []scopes.Scope{
	{
		Name:  "User management",
		Read:  true,
		Write: false,
	},
}

var (
	_ datasource.DataSource              = &userDataSource{}
	_ datasource.DataSourceWithConfigure = &userDataSource{}
)

func NewUserDataSource() datasource.DataSource {
	return &userDataSource{}
}

type userDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type userDataSourceModel struct {
	UUID      types.String `tfsdk:"user_uuid"`
	Email     types.String `tfsdk:"email"`
	FirstName types.String `tfsdk:"first_name"`
	LastName  types.String `tfsdk:"last_name"`
	CID       types.String `tfsdk:"cid"`
	Status    types.String `tfsdk:"status"`
}

func (m *userDataSourceModel) wrap(user models.DomainUser) {
	m.UUID = flex.StringValueToFramework(user.UUID)
	m.Email = flex.StringValueToFramework(user.UID)
	m.FirstName = flex.StringValueToFramework(user.FirstName)
	m.LastName = flex.StringValueToFramework(user.LastName)
	m.CID = flex.StringValueToFramework(user.Cid)
	m.Status = flex.StringValueToFramework(user.Status)
}

func (d *userDataSource) Configure(
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

func (d *userDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (d *userDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			dataSourceDocumentationSection,
			dataSourceMarkdownDescription,
			dataSourceApiScopes,
		),
		Attributes: map[string]schema.Attribute{
			"user_uuid": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The unique identifier (UUID) assigned to the user by CrowdStrike. Exactly one of 'user_uuid' or 'email' must be provided.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					stringvalidator.ExactlyOneOf(path.MatchRoot("user_uuid"), path.MatchRoot("email")),
				},
			},
			"email": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The user's email address, which serves as their username. Exactly one of 'user_uuid' or 'email' must be provided.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"first_name": schema.StringAttribute{
				Computed:    true,
				Description: "The user's first name.",
			},
			"last_name": schema.StringAttribute{
				Computed:    true,
				Description: "The user's last name.",
			},
			"cid": schema.StringAttribute{
				Computed:    true,
				Description: "The Customer ID (CID) the user belongs to.",
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "The user's status (for example, active).",
			},
		},
	}
}

func (d *userDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data userDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	uuid := data.UUID.ValueString()

	if !utils.IsKnown(data.UUID) {
		// Look up the UUID by email using an FQL filter on the uid field.
		email := data.Email.ValueString()

		tflog.Debug(ctx, "[datasource] Looking up user by email", map[string]any{
			"email": email,
		})

		filter := fmt.Sprintf("uid:'%s'", strings.ToLower(email))
		res, err := d.client.UserManagement.QueryUserV1(&user_management.QueryUserV1Params{
			Context: ctx,
			Filter:  &filter,
		})
		notFoundDetail := fmt.Sprintf("No user found with email %q.", email)
		if err != nil {
			resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, dataSourceApiScopes, tferrors.WithNotFoundDetail(notFoundDetail)))
			return
		}

		if res == nil || res.Payload == nil {
			resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Read))
			return
		}

		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}

		if len(res.Payload.Resources) == 0 {
			resp.Diagnostics.Append(tferrors.NewNotFoundError(notFoundDetail))
			return
		}

		if len(res.Payload.Resources) > 1 {
			resp.Diagnostics.AddError(
				"Multiple users found",
				fmt.Sprintf("Found %d users with email %q. User emails are expected to be unique.", len(res.Payload.Resources), email),
			)
			return
		}

		uuid = res.Payload.Resources[0]
	}

	tflog.Debug(ctx, "[datasource] Retrieving user by uuid", map[string]any{
		"uuid": uuid,
	})

	res, err := d.client.UserManagement.RetrieveUsersGETV1(&user_management.RetrieveUsersGETV1Params{
		Context: ctx,
		Body:    &models.MsaspecIdsRequest{Ids: []string{uuid}},
	})
	notFoundDetail := fmt.Sprintf("No user found with uuid %q.", uuid)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, dataSourceApiScopes, tferrors.WithNotFoundDetail(notFoundDetail)))
		return
	}

	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewNotFoundError(notFoundDetail))
		return
	}

	data.wrap(*res.Payload.Resources[0])

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
