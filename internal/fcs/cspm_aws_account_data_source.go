package fcs

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cspm_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
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
	_ datasource.DataSource              = &cspmAwsAccountDataSource{}
	_ datasource.DataSourceWithConfigure = &cspmAwsAccountDataSource{}
)

// cspmAwsAccountDataSource is the data source implementation.
type cspmAwsAccountDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type cspmAwsAccountDataSourceModel struct {
	ID             types.String              `tfsdk:"id"`
	AccountID      types.String              `tfsdk:"account_id"`
	OrganizationID types.String              `tfsdk:"organization_id"`
	Accounts       []cspmAwsAccountDataModel `tfsdk:"accounts"`
}

type cspmAwsAccountDataModel struct {
	AccountID                types.String `tfsdk:"account_id"`
	OrganizationID           types.String `tfsdk:"organization_id"`
	TargetOUs                types.List   `tfsdk:"target_ous"`
	IsOrgManagementAccount   types.Bool   `tfsdk:"is_organization_management_account"`
	AccountType              types.String `tfsdk:"account_type"`
	EnableRealtimeVisibility types.Bool   `tfsdk:"enable_realtime_visibility"`
	EnableSensorManagement   types.Bool   `tfsdk:"enable_sensor_management"`
	EnableDSPM               types.Bool   `tfsdk:"enable_dspm"`
	ExternalID               types.String `tfsdk:"external_id"`
	IntermediateRoleArn      types.String `tfsdk:"intermediate_role_arn"`
	IamRoleArn               types.String `tfsdk:"iam_role_arn"`
	EventbusName             types.String `tfsdk:"eventbus_name"`
	EventbusArn              types.String `tfsdk:"eventbus_arn"`
	CloudTrailBucketName     types.String `tfsdk:"cloudtrail_bucket_name"`
	CloudTrailRegion         types.String `tfsdk:"cloudtrail_region"`
	DSPMRoleArn              types.String `tfsdk:"dspm_role_arn"`
}

// NewCspmAwsAccountDataSource is a helper function to simplify the provider implementation.
func NewCspmAwsAccountDataSource() datasource.DataSource {
	return &cspmAwsAccountDataSource{}
}

// Metadata returns the data source type name.
func (d *cspmAwsAccountDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cspm_aws_accounts"
}

// Schema defines the schema for the data source.
func (d *cspmAwsAccountDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches the list of coffees.",
		MarkdownDescription: fmt.Sprintf(
			"CSPM AWS Accounts --- This data source provides information about CSPM AWS accounts.\n\n%s",
			scopes.GenerateScopeDescription(cspmScopes),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Placeholder identifier attribute.",
				Computed:    true,
			},
			"account_id": schema.StringAttribute{
				Optional:    true,
				Description: "The AWS Account ID.",
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("account_id"),
						path.MatchRoot("organization_id"),
					),
				},
			},
			"organization_id": schema.StringAttribute{
				Optional:    true,
				Description: "The AWS Organization ID",
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("account_id"),
						path.MatchRoot("organization_id"),
					),
				},
			},
			"accounts": schema.ListNestedAttribute{
				Description: "The list of CSPM AWS accounts.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"account_id": schema.StringAttribute{
							Computed:    true,
							Description: "The AWS Account ID.",
						},
						"organization_id": schema.StringAttribute{
							Computed:    true,
							Description: "The AWS Organization ID",
						},
						"target_ous": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "The list of target OUs",
						},
						"is_organization_management_account": schema.BoolAttribute{
							Computed:    true,
							Description: "Indicates whether this is the management account (formerly known as the root account) of an AWS Organization",
						},
						"account_type": schema.StringAttribute{
							Computed:    true,
							Description: "The type of account. Not needed for non-govcloud environment",
						},
						"enable_realtime_visibility": schema.BoolAttribute{
							Computed:    true,
							Description: "Enable the Realtime Visibility feature",
						},
						"enable_sensor_management": schema.BoolAttribute{
							Computed:    true,
							Description: "Enable the 1-Click Sensor Management feature",
						},
						"enable_dspm": schema.BoolAttribute{
							Computed:    true,
							Description: "Enable the Data Security Posture Management feature",
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
						"eventbus_name": schema.StringAttribute{
							Computed:    true,
							Description: "The name of CrowdStrike Event Bridge to forward messages to",
						},
						"eventbus_arn": schema.StringAttribute{
							Computed:    true,
							Description: "The ARN of CrowdStrike Event Bridge to forward messages to",
						},
						"cloudtrail_bucket_name": schema.StringAttribute{
							Computed:    true,
							Description: "The name of the CloudTrail bucket used for realtime visibility",
						},
						"cloudtrail_region": schema.StringAttribute{
							Optional:    true,
							Description: "The AWS region of the CloudTrail bucket",
						},
						"dspm_role_arn": schema.StringAttribute{
							Computed:    true,
							Description: "The ARN of the IAM role to be used by CrowdStrike DSPM",
						},
					},
				},
			},
		},
	}
}

func (d *cspmAwsAccountDataSource) getAccounts(
	ctx context.Context,
	accountID string,
	organizationID string,
) ([]*models.DomainAWSAccountV2, diag.Diagnostics) {
	var diags diag.Diagnostics
	tflog.Debug(ctx, "[datasource] Getting CSPM AWS Accounts ", map[string]interface{}{"accountID": accountID, "organizationID": organizationID})
	res, status, err := d.client.CspmRegistration.GetCSPMAwsAccount(&cspm_registration.GetCSPMAwsAccountParams{
		Context:         ctx,
		Ids:             []string{accountID},
		OrganizationIds: []string{organizationID},
	})
	if err != nil {
		diags.AddError(
			"Failed to read CSPM AWS account",
			fmt.Sprintf("Failed to get CSPM AWS account: %s", err.Error()),
		)
		return nil, diags
	}
	if status != nil {
		for _, error := range status.Payload.Errors {
			diags.AddError(
				"Failed to read CSPM AWS account",
				fmt.Sprintf("Failed to get CSPM AWS account: %s", *error.Message),
			)
		}
		return status.Payload.Resources, diags
	}
	return res.Payload.Resources, diags
}

// Read refreshes the Terraform state with the latest data.
func (d *cspmAwsAccountDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data cspmAwsAccountDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	accounts, diags := d.getAccounts(ctx, data.AccountID.ValueString(), data.OrganizationID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Accounts = make([]cspmAwsAccountDataModel, 0)

	// Map response body to model
	for _, account := range accounts {
		if account == nil {
			continue
		}
		targetOUs := make([]attr.Value, 0, len(account.TargetOus))
		for _, ou := range account.TargetOus {
			targetOUs = append(targetOUs, types.StringValue(ou))
		}
		data.Accounts = append(data.Accounts, cspmAwsAccountDataModel{
			AccountID:              types.StringValue(account.AccountID),
			OrganizationID:         types.StringValue(account.OrganizationID),
			TargetOUs:              types.ListValueMust(types.StringType, targetOUs),
			IsOrgManagementAccount: types.BoolValue(account.IsMaster),
			AccountType:            types.StringValue(account.AccountType),

			EnableRealtimeVisibility: types.BoolValue(account.BehaviorAssessmentEnabled),
			EnableSensorManagement:   types.BoolPointerValue(account.SensorManagementEnabled),
			EnableDSPM:               types.BoolValue(account.DspmEnabled),
			ExternalID:               types.StringValue(account.ExternalID),
			IntermediateRoleArn:      types.StringValue(account.IntermediateRoleArn),
			IamRoleArn:               types.StringValue(account.IamRoleArn),
			EventbusName:             types.StringValue(account.EventbusName),
			EventbusArn:              types.StringValue(account.AwsEventbusArn),
			CloudTrailBucketName:     types.StringValue(account.AwsCloudtrailBucketName),
			CloudTrailRegion:         types.StringValue(account.AwsCloudtrailRegion),
			DSPMRoleArn:              types.StringValue(account.DspmRoleArn),
		})
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
func (d *cspmAwsAccountDataSource) Configure(
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
