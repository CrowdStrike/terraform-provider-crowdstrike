package fcs

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_aws_registration"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
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
				Optional:    true,
				Description: "AWS account to be validated",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^\d{12}$`),
						"must be in AWS account ID format",
					),
					stringvalidator.ConflictsWith(path.MatchRoot("organization_id")),
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
					stringvalidator.ConflictsWith(path.MatchRoot("account_id")),
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

func (d *cloudAwsAccountValidationDataSource) triggerHealthCheck(ctx context.Context, accountID, orgID types.String) diag.Diagnostics {
	var diags diag.Diagnostics
	tflog.Info(ctx, "[datasource] Trigger Health Check Scan",
		map[string]interface{}{"accountID": accountID.ValueString(), "organizationID": orgID.ValueString()})

	params := &cloud_aws_registration.CloudRegistrationAwsTriggerHealthCheckParams{
		Context: ctx,
	}
	if !orgID.IsNull() {
		params.OrganizationIds = []string{orgID.ValueString()}
	} else {
		params.AccountIds = []string{accountID.ValueString()}
	}
	_, err := d.client.CloudAwsRegistration.CloudRegistrationAwsTriggerHealthCheck(params)
	if err != nil {
		var hcErr *cloud_aws_registration.CloudRegistrationAwsTriggerHealthCheckForbidden
		if errors.As(err, &hcErr) {
			diags.Append(tferrors.NewForbiddenError(tferrors.Read, cloudSecurityScopes))
			return diags
		}
		diags.AddWarning(
			"Failed to trigger health check scan. Please go to the Falcon console and trigger health check scan manually to reflect the latest state.",
			fmt.Sprintf("Failed to trigger health check: %s", falcon.ErrorExplain(err)),
		)
	}
	return diags
}

func (d *cloudAwsAccountValidationDataSource) validateAccount(ctx context.Context, accountID, orgID types.String) diag.Diagnostics {
	var diags diag.Diagnostics
	tflog.Info(ctx, "[datasource] Validate Cloud AWS Account",
		map[string]interface{}{"accountID": accountID.ValueString(), "organizationID": orgID.ValueString()})

	params := &cloud_aws_registration.CloudRegistrationAwsValidateAccountsParams{
		Context: ctx,
	}

	if !orgID.IsNull() {
		params.OrganizationID = orgID.ValueStringPointer()
	} else {
		params.AccountID = accountID.ValueStringPointer()
	}

	_, err := d.client.CloudAwsRegistration.CloudRegistrationAwsValidateAccounts(params)
	if err != nil {
		var validateErr *cloud_aws_registration.CloudRegistrationAwsValidateAccountsForbidden
		if errors.As(err, &validateErr) {
			diags.Append(tferrors.NewForbiddenError(tferrors.Read, cloudSecurityScopes))
			return diags
		}
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

	diags := d.validateAccount(ctx, data.AccountID, data.OrganizationID)
	resp.Diagnostics.Append(diags...)
	data.Validated = types.BoolValue(!diags.HasError() && diags.WarningsCount() == 0)

	if data.Validated.ValueBool() {
		diags = d.triggerHealthCheck(ctx, data.AccountID, data.OrganizationID)
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
