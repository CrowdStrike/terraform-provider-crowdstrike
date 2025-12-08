package fcs

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_aws_registration"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &cloudAwsAccountValidationDataSource{}
	_ datasource.DataSourceWithConfigure = &cloudAwsAccountValidationDataSource{}
)

// cloudAwsAccountsDataSource is the data source implementation.
type cloudAwsAccountValidationDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudAwsAccountValidationDataSourceModel struct {
	AccountID types.String `tfsdk:"account_id"`
	Validated types.Bool   `tfsdk:"validated"`
}

// NewCloudAwsAccountValidationDataSource is a helper function to simplify the provider implementation.
func NewCloudAwsAccountValidationDataSource() datasource.DataSource {
	return &cloudAwsAccountValidationDataSource{}
}

// Metadata returns the data source type name.
func (d *cloudAwsAccountValidationDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_aws_account_validation"
}

// Schema defines the schema for the data source.
func (d *cloudAwsAccountValidationDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Falcon Cloud Security --- This data source validate account configuration and connection status for an integrated AWS account.\n\n%s",
			scopes.GenerateScopeDescription(cloudSecurityScopes),
		),
		Attributes: map[string]schema.Attribute{
			"account_id": schema.StringAttribute{
				Required:    true,
				Description: "AWS account to be validated",
			},
			"validated": schema.BoolAttribute{
				Computed:    true,
				Description: "Indicates whether the AWS account is validated successfully",
			},
		},
	}
}

func (d *cloudAwsAccountValidationDataSource) validateAccount(ctx context.Context, accountID string) diag.Diagnostics {
	var diags diag.Diagnostics
	tflog.Info(ctx, "[datasource] Validate Cloud AWS Accounts ",
		map[string]interface{}{"accountID": accountID})

	_, err := d.client.CloudAwsRegistration.CloudRegistrationAwsValidateAccounts(
		&cloud_aws_registration.CloudRegistrationAwsValidateAccountsParams{
			Context:   ctx,
			AccountID: &accountID,
		},
	)
	if err != nil {
		diags.AddWarning(
			"Failed to validate AWS account. Please go to the Falcon console and trigger health check scan manually to reflect the latest state.",
			fmt.Sprintf("Failed to validate AWS account for AWS account: %s", falcon.ErrorExplain(err)),
		)
	}
	return diags
}

// Read refreshes the Terraform state with the latest data.
func (d *cloudAwsAccountValidationDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data cloudAwsAccountValidationDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	diags := d.validateAccount(ctx, data.AccountID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Validated = types.BoolValue(true)

	// Set state
	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Configure adds the provider configured client to the data source.
func (d *cloudAwsAccountValidationDataSource) Configure(
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
