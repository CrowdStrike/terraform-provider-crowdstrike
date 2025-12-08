package fcs

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_aws_registration"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
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
	AccountID      types.String `tfsdk:"account_id"`
	OrganizationID types.String `tfsdk:"organization_id"`
	WaitTime       types.Int32  `tfsdk:"wait_time"`
	Validated      types.Bool   `tfsdk:"validated"`
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
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^\d{12}$`),
						"must be in AWS account ID format",
					),
				},
			},
			"organization_id": schema.StringAttribute{
				Optional:    true,
				Description: "AWS organization to be validated",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^o-[0-9a-z]{10,32}$`),
						"must be in AWS organization ID format",
					),
				},
			},
			"wait_time": schema.Int32Attribute{
				Optional:    true,
				Description: "Time in seconds to wait before starting validation. Defaults to 15 seconds. Set to 0 to validate immediately",
			},
			"validated": schema.BoolAttribute{
				Computed:    true,
				Description: "Indicates whether the AWS account validation completed successfully without errors or warnings. Visit the Falcon console for detailed validation status and any issues found",
			},
		},
	}
}

func (d *cloudAwsAccountValidationDataSource) triggerHealthCheck(ctx context.Context, accountID, orgID string) diag.Diagnostics {
	var diags diag.Diagnostics
	tflog.Info(ctx, "[datasource] Trigger Health Check Scan",
		map[string]interface{}{"accountID": accountID, "organizationID": orgID})

	params := &cloud_aws_registration.CloudRegistrationAwsTriggerHealthCheckParams{
		Context: ctx,
	}
	if len(orgID) > 0 {
		params.OrganizationIds = []string{orgID}
	} else {
		params.AccountIds = []string{accountID}
	}
	_, err := d.client.CloudAwsRegistration.CloudRegistrationAwsTriggerHealthCheck(params)
	if err != nil {
		diags.AddWarning(
			"Failed to trigger health check scan. Please go to the Falcon console and trigger health check scan manually to reflect the latest state.",
			fmt.Sprintf("Failed to trigger health check: %s", falcon.ErrorExplain(err)),
		)
	}
	return diags
}

func (d *cloudAwsAccountValidationDataSource) validateAccount(ctx context.Context, accountID string) diag.Diagnostics {
	var diags diag.Diagnostics
	tflog.Info(ctx, "[datasource] Validate Cloud AWS Account",
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
			fmt.Sprintf("Failed to validate AWS account: %s", falcon.ErrorExplain(err)),
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

	waitTime := 15
	if !data.WaitTime.IsNull() {
		waitTime = int(data.WaitTime.ValueInt32())
	}

	if waitTime > 0 {
		time.Sleep(time.Duration(waitTime) * time.Second)
	}

	diags := d.validateAccount(ctx, data.AccountID.ValueString())
	resp.Diagnostics.Append(diags...)
	data.Validated = types.BoolValue(!diags.HasError() && diags.WarningsCount() == 0)

	if data.Validated.ValueBool() {
		diags = d.triggerHealthCheck(ctx, data.OrganizationID.ValueString(), data.OrganizationID.ValueString())
		resp.Diagnostics.Append(diags...)
	}

	// Set state
	resp.State.Set(ctx, &data)
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

	cfg, ok := req.ProviderData.(config.ProviderConfig)
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

	d.client = cfg.Client
}
