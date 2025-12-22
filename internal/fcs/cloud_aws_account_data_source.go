package fcs

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_aws_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &cloudAwsAccountsDataSource{}
	_ datasource.DataSourceWithConfigure = &cloudAwsAccountsDataSource{}
)

// cloudAwsAccountsDataSource is the data source implementation.
type cloudAwsAccountsDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudAWSAccountDataModel struct {
	AccountID                     types.String `tfsdk:"account_id"`
	OrganizationID                types.String `tfsdk:"organization_id"`
	TargetOUs                     types.List   `tfsdk:"target_ous"`
	IsOrgManagementAccount        types.Bool   `tfsdk:"is_organization_management_account"`
	ResourceNamePrefix            types.String `tfsdk:"resource_name_prefix"`
	ResourceNameSuffix            types.String `tfsdk:"resource_name_suffix"`
	AccountType                   types.String `tfsdk:"account_type"`
	ExternalID                    types.String `tfsdk:"external_id"`
	IntermediateRoleArn           types.String `tfsdk:"intermediate_role_arn"`
	IamRoleArn                    types.String `tfsdk:"iam_role_arn"`
	IamRoleName                   types.String `tfsdk:"iam_role_name"`
	EventbusName                  types.String `tfsdk:"eventbus_name"`
	EventbusArn                   types.String `tfsdk:"eventbus_arn"`
	CloudTrailRegion              types.String `tfsdk:"cloudtrail_region"`
	CloudTrailBucketName          types.String `tfsdk:"cloudtrail_bucket_name"`
	DspmRoleArn                   types.String `tfsdk:"dspm_role_arn"`
	DspmRoleName                  types.String `tfsdk:"dspm_role_name"`
	VulnerabilityScanningRoleArn  types.String `tfsdk:"vulnerability_scanning_role_arn"`
	VulnerabilityScanningRoleName types.String `tfsdk:"vulnerability_scanning_role_name"`
	AgentlessScanningRoleName     types.String `tfsdk:"agentless_scanning_role_name"`
	AssetInventoryEnabled         types.Bool   `tfsdk:"asset_inventory_enabled"`
	RealtimeVisibilityEnabled     types.Bool   `tfsdk:"realtime_visibility_enabled"`
	IDPEnabled                    types.Bool   `tfsdk:"idp_enabled"`
	SensorManagementEnabled       types.Bool   `tfsdk:"sensor_management_enabled"`
	DSPMEnabled                   types.Bool   `tfsdk:"dspm_enabled"`
	VulnerabilityScanningEnabled  types.Bool   `tfsdk:"vulnerability_scanning_enabled"`
}

type cloudAwsAccountsDataSourceModel struct {
	AccountID      types.String                `tfsdk:"account_id"`
	OrganizationID types.String                `tfsdk:"organization_id"`
	Accounts       []*cloudAWSAccountDataModel `tfsdk:"accounts"`
}

// NewCloudAwsAccountsDataSource is a helper function to simplify the provider implementation.
func NewCloudAwsAccountsDataSource() datasource.DataSource {
	return &cloudAwsAccountsDataSource{}
}

// Metadata returns the data source type name.
func (d *cloudAwsAccountsDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_aws_account"
}

// Schema defines the schema for the data source.
func (d *cloudAwsAccountsDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Falcon Cloud Security --- This data source provides information about AWS accounts in Falcon.\n\n%s",
			scopes.GenerateScopeDescription(cloudSecurityScopes),
		),
		Attributes: map[string]schema.Attribute{
			"account_id": schema.StringAttribute{
				Optional:    true,
				Description: "Filter the results to a specific AWS Account ID. When specified, returns details for the matching AWS account. Can be used together with organization_id filter for OR matching",
			},
			"organization_id": schema.StringAttribute{
				Optional:    true,
				Description: "Filter the results to accounts within a specific AWS Organization. When specified, returns all AWS accounts associated with this organization ID. Can be used together with account_id filter for OR matching",
			},
			"accounts": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of AWS accounts",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"account_id": schema.StringAttribute{
							Computed:    true,
							Description: "The AWS Account ID",
						},
						"organization_id": schema.StringAttribute{
							Computed:    true,
							Description: "The AWS Organization ID",
						},
						"target_ous": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "The list of AWS Organizational Units (OUs) targeted for this account",
						},
						"is_organization_management_account": schema.BoolAttribute{
							Computed:    true,
							Description: "Indicates whether this is the management account (formerly known as the root account) of an AWS Organization",
						},
						"account_type": schema.StringAttribute{
							Computed:    true,
							Description: "The AWS account type. Value is 'commercial' for Commercial cloud accounts. For GovCloud environments, value can be either 'commercial' or 'gov' depending on the account type",
						},
						"external_id": schema.StringAttribute{
							Computed:    true,
							Description: "The external ID used to assume the AWS IAM role",
						},
						"intermediate_role_arn": schema.StringAttribute{
							Computed:    true,
							Description: "The ARN of the intermediate role used to assume the AWS IAM role",
						},
						"iam_role_arn": schema.StringAttribute{
							Computed:    true,
							Description: "The ARN of the AWS IAM role used to access this AWS account",
						},
						"iam_role_name": schema.StringAttribute{
							Computed:    true,
							Description: "The name of the AWS IAM role used to access this AWS account",
						},
						"eventbus_name": schema.StringAttribute{
							Computed:    true,
							Description: "The name of the Amazon EventBridge used by CrowdStrike to forward messages",
						},
						"eventbus_arn": schema.StringAttribute{
							Computed:    true,
							Description: "The ARN of the Amazon EventBridge used by CrowdStrike to forward messages",
						},
						"cloudtrail_bucket_name": schema.StringAttribute{
							Computed:    true,
							Description: "The name of the CloudTrail S3 bucket used for real-time visibility",
						},
						"cloudtrail_region": schema.StringAttribute{
							Computed:    true,
							Description: "The AWS region of the CloudTrail bucket",
						},
						"dspm_role_arn": schema.StringAttribute{
							Computed:    true,
							Description: "The ARN of the IAM role to be used by CrowdStrike DSPM",
						},
						"dspm_role_name": schema.StringAttribute{
							Computed:    true,
							Description: "The name of the IAM role to be used by CrowdStrike DSPM",
						},
						"vulnerability_scanning_role_arn": schema.StringAttribute{
							Computed:    true,
							Description: "The ARN of the IAM role to be used by CrowdStrike Vulnerability Scanning",
						},
						"vulnerability_scanning_role_name": schema.StringAttribute{
							Computed:    true,
							Description: "The name of the IAM role to be used by CrowdStrike Vulnerability Scanning",
						},
						"agentless_scanning_role_name": schema.StringAttribute{
							Computed:    true,
							Description: "The name of the IAM role to be used by CrowdStrike Agentless Scanning (DSPM/Vulnerability scanning). If both are configured, the DSPM role takes precedence.",
						},
						"asset_inventory_enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether asset inventory is enabled",
						},
						"realtime_visibility_enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether real-time visibility is enabled",
						},
						"idp_enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether Identity Protection is enabled",
						},
						"sensor_management_enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether 1-click sensor deployment is enabled",
						},
						"dspm_enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether Data Security Posture Management is enabled",
						},
						"vulnerability_scanning_enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether Vulnerability Scanning is enabled",
						},
						"resource_name_prefix": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "The prefix to be added to all resource names",
						},
						"resource_name_suffix": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "The suffix to be added to all resource names",
						},
					},
				},
			},
		},
	}
}

func (d *cloudAwsAccountsDataSource) getCloudAccounts(
	ctx context.Context,
	accounts []string,
) ([]*models.DomainCloudAWSAccountV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	tflog.Debug(
		ctx,
		"[datasource] Getting Cloud AWS Accounts ",
		map[string]interface{}{"accounts": accounts},
	)
	res, status, err := d.client.CloudAwsRegistration.CloudRegistrationAwsGetAccounts(
		&cloud_aws_registration.CloudRegistrationAwsGetAccountsParams{
			Context: ctx,
			Ids:     accounts,
		},
	)
	if err != nil {
		if _, ok := err.(*cloud_aws_registration.CloudRegistrationAwsGetAccountsForbidden); ok {
			diags.AddError(
				"Failed to read Cloud Registration AWS accounts:: 403 Forbidden",
				scopes.GenerateScopeDescription(cloudSecurityScopes),
			)
			return nil, diags
		}
		diags.AddError(
			"Failed to read Cloud Registration AWS accounts",
			fmt.Sprintf("Failed to get Cloud AWS accounts: %s", err.Error()),
		)
		return nil, diags
	}
	if status != nil {
		for _, err := range status.Payload.Errors {
			diags.AddError(
				"Failed to read Cloud Registration AWS accounts",
				fmt.Sprintf("Failed to get Cloud AWS accounts: %s", *err.Message),
			)
		}
		return nil, diags
	}
	return res.Payload.Resources, diags
}

// Read refreshes the Terraform state with the latest data.
func (d *cloudAwsAccountsDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data cloudAwsAccountsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Get all cloud accounts without filtering first
	cloudAccounts, diags := d.getCloudAccounts(ctx, []string{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Filter accounts based on the request filters
	accountFilter := data.AccountID.ValueString()
	orgFilter := data.OrganizationID.ValueString()

	data.Accounts = make([]*cloudAWSAccountDataModel, 0)
	for _, a := range cloudAccounts {
		if a == nil {
			continue
		}

		// Apply filters
		if accountFilter != "" && a.AccountID != accountFilter {
			continue
		}
		if orgFilter != "" && a.OrganizationID != orgFilter {
			continue
		}
		// Get fields from the shared helper
		fields := extractCloudAccountFields(ctx, a)

		// Handle target OUs
		targetOUs := types.ListNull(types.StringType)
		if len(fields.TargetOUs) > 0 {
			ouValues := make([]attr.Value, 0, len(fields.TargetOUs))
			for _, ou := range fields.TargetOUs {
				ouValues = append(ouValues, types.StringValue(ou))
			}
			targetOUs = types.ListValueMust(types.StringType, ouValues)
		}

		m := &cloudAWSAccountDataModel{
			AccountID:                     types.StringValue(fields.AccountID),
			OrganizationID:                types.StringValue(fields.OrganizationID),
			TargetOUs:                     targetOUs,
			IsOrgManagementAccount:        types.BoolValue(fields.IsOrgManagementAccount),
			AccountType:                   types.StringValue(fields.AccountType),
			ExternalID:                    types.StringValue(fields.ExternalID),
			IntermediateRoleArn:           types.StringValue(fields.IntermediateRoleArn),
			IamRoleArn:                    types.StringValue(fields.IamRoleArn),
			IamRoleName:                   types.StringValue(getRoleNameFromArn(fields.IamRoleArn)),
			EventbusName:                  types.StringValue(fields.EventbusName),
			EventbusArn:                   types.StringValue(fields.EventbusArn),
			CloudTrailBucketName:          types.StringValue(fields.CloudTrailBucketName),
			CloudTrailRegion:              types.StringValue(fields.CloudTrailRegion),
			DspmRoleArn:                   types.StringValue(fields.DspmRoleArn),
			DspmRoleName:                  types.StringValue(fields.DspmRoleName),
			VulnerabilityScanningRoleArn:  types.StringValue(fields.VulnerabilityScanningRoleArn),
			VulnerabilityScanningRoleName: types.StringValue(fields.VulnerabilityScanningRoleName),
			AgentlessScanningRoleName:     types.StringValue(fields.AgentlessScanningRoleName),
			AssetInventoryEnabled:         types.BoolValue(fields.AssetInventoryEnabled),
			RealtimeVisibilityEnabled:     types.BoolValue(fields.RealtimeVisibilityEnabled),
			IDPEnabled:                    types.BoolValue(fields.IDPEnabled),
			SensorManagementEnabled:       types.BoolValue(fields.SensorManagementEnabled),
			DSPMEnabled:                   types.BoolValue(fields.DSPMEnabled),
			VulnerabilityScanningEnabled:  types.BoolValue(fields.VulnerabilityScanningEnabled),
			ResourceNamePrefix:            types.StringValue(fields.ResourceNamePrefix),
			ResourceNameSuffix:            types.StringValue(fields.ResourceNameSuffix),
		}

		data.Accounts = append(data.Accounts, m)
	}

	// Set state
	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Configure adds the provider configured client to the data source.
func (d *cloudAwsAccountsDataSource) Configure(
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
