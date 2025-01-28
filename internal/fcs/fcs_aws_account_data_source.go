package fcs

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_aws_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &fcsAwsAccountDataSource{}
	_ datasource.DataSourceWithConfigure = &fcsAwsAccountDataSource{}
)

// cspmAwsAccountDataSource is the data source implementation.
type fcsAwsAccountDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type fcsAwsAccountDataSourceModel struct {
	ID        types.String          `tfsdk:"id"`
	AccountID types.String          `tfsdk:"account_id"`
	Account   *cloudAWSAccountModel `tfsdk:"account"`
	// Account types.Set `tfsdk:"account"`
}

// NewFcsAwsAccountDataSource is a helper function to simplify the provider implementation.
func NewFcsAwsAccountDataSource() datasource.DataSource {
	return &fcsAwsAccountDataSource{}
}

// Metadata returns the data source type name.
func (d *fcsAwsAccountDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloud_aws_accounts"
}

// Schema defines the schema for the data source.
func (d *fcsAwsAccountDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches the list of coffees.",
		MarkdownDescription: fmt.Sprintf(
			"FCS AWS Accounts --- This data source provides information about CSPM AWS accounts.\n\n%s",
			scopes.GenerateScopeDescription(fcsScopes),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Placeholder identifier attribute.",
				Computed:    true,
			},
			"account_id": schema.StringAttribute{
				Required:    true,
				Description: "The AWS Account ID.",
			},
			"account": schema.SingleNestedAttribute{
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"account_id": schema.StringAttribute{
						Computed:    true,
						Description: "The AWS Account ID.",
					},
					"organization_id": schema.StringAttribute{
						Computed:    true,
						Description: "The AWS Organization ID",
					},
					"is_organization_management_account": schema.BoolAttribute{
						Computed:    true,
						Description: "Indicates whether this is the management account (formerly known as the root account) of an AWS Organization",
					},
					"account_type": schema.StringAttribute{
						Computed:    true,
						Description: "The type of account. Not needed for non-govcloud environment",
					},
					"csp_events": schema.BoolAttribute{
						Computed:    true,
						Description: "",
					},
					"products": schema.SetNestedAttribute{
						Computed:    true,
						Description: "The list of products to enable for this account",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"product": schema.StringAttribute{
									Required: true,
								},
								"features": schema.SetAttribute{
									Required:    true,
									ElementType: types.StringType,
								},
							},
						},
					},
				},
			},
		},
	}
}

func (d *fcsAwsAccountDataSource) getAccount(
	ctx context.Context,
	accountID string,
) (*models.DomainCloudAWSAccountV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	tflog.Debug(ctx, "[datasource] Getting FCS AWS Accounts ", map[string]interface{}{"accountID": accountID})
	res, status, err := d.client.CloudAwsRegistration.CloudRegistrationAwsGetAccounts(&cloud_aws_registration.CloudRegistrationAwsGetAccountsParams{
		Context: ctx,
		Ids:     []string{accountID},
	})
	if err != nil {
		diags.AddError(
			"Failed to read FCS AWS account",
			fmt.Sprintf("Failed to get FCS AWS account: %s", err.Error()),
		)
		return nil, diags
	}
	if status != nil {
		for _, error := range status.Payload.Errors {
			diags.AddError(
				"Failed to read FCS AWS account",
				fmt.Sprintf("Failed to get FCS AWS account: %s", *error.Message),
			)
		}
	}
	var ret *models.DomainCloudAWSAccountV1
	if res != nil && res.Payload != nil && len(res.Payload.Resources) != 0 {
		ret = res.Payload.Resources[0]
	}

	return ret, diags
}

// Read refreshes the Terraform state with the latest data.
func (d *fcsAwsAccountDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data fcsAwsAccountDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	account, diags := d.getAccount(ctx, data.AccountID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var m cloudAWSAccountModel
	if account != nil {
		m.AccountID = types.StringValue(account.AccountID)
		m.OrganizationID = types.StringValue(account.OrganizationID)
		m.AccountType = types.StringValue(account.AccountType)
		m.IsOrgManagementAccount = types.BoolValue(account.IsMaster)
		m.CSPEvents = types.BoolValue(account.CspEvents)
		products, d := productsToState(ctx, account.Products)
		if d.HasError() {
			resp.Diagnostics.Append(d...)
			return
		}
		m.Products = products
		data.Account = &m
	}
	data.ID = types.StringValue("placeholder")

	// Set state
	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Configure adds the provider configured client to the data source.
func (d *fcsAwsAccountDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.CrowdStrikeAPISpecification)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf(
				"Expected *client.CrowdStrikeAPISpecification, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	d.client = client
}
