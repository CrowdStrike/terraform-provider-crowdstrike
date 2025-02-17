package fcs

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_aws_registration"
	"github.com/crowdstrike/gofalcon/falcon/client/cspm_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
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
	AccountID                 types.String `tfsdk:"account_id"`
	OrganizationID            types.String `tfsdk:"organization_id"`
	TargetOUs                 types.List   `tfsdk:"target_ous"`
	IsOrgManagementAccount    types.Bool   `tfsdk:"is_organization_management_account"`
	AccountType               types.String `tfsdk:"account_type"`
	ExternalID                types.String `tfsdk:"external_id"`
	IntermediateRoleArn       types.String `tfsdk:"intermediate_role_arn"`
	IamRoleArn                types.String `tfsdk:"iam_role_arn"`
	EventbusName              types.String `tfsdk:"eventbus_name"`
	EventbusArn               types.String `tfsdk:"eventbus_arn"`
	CloudTrailRegion          types.String `tfsdk:"cloudtrail_region"`
	CloudTrailBucketName      types.String `tfsdk:"cloudtrail_bucket_name"`
	DspmRoleArn               types.String `tfsdk:"dspm_role_arn"`
	AssetInventoryEnabled     types.Bool   `tfsdk:"asset_inventory_enabled"`
	RealtimeVisibilityEnabled types.Bool   `tfsdk:"realtime_visibility_enabled"`
	IDPEnabled                types.Bool   `tfsdk:"idp_enabled"`
	SensorManagementEnabled   types.Bool   `tfsdk:"sensor_management_enabled"`
	DSPMEnabled               types.Bool   `tfsdk:"dspm_enabled"`
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
func (d *cloudAwsAccountsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloud_aws_accounts"
}

// Schema defines the schema for the data source.
func (d *cloudAwsAccountsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches Cloud AWS accounts by account_id or organization_id",
		MarkdownDescription: fmt.Sprintf(
			"Cloud AWS Accounts --- This data source provides information about AWS accounts in Falcon.\n\n%s",
			scopes.GenerateScopeDescription(cloudSecurityScopes),
		),
		Attributes: map[string]schema.Attribute{
			"account_id": schema.StringAttribute{
				Optional:    true,
				Description: "Filter the results to a specific AWS Account ID. When specified, returns details for the matching AWS account. Can be used together with organization_id filter for OR matching.",
			},
			"organization_id": schema.StringAttribute{
				Optional:    true,
				Description: "Filter the results to accounts within a specific AWS Organization. When specified, returns all AWS accounts associated with this organization ID. Can be used together with account_id filter for OR matching.",
			},
			"accounts": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of AWS accounts",
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
							Description: "",
						},
						"cloudtrail_region": schema.StringAttribute{
							Optional:    true,
							Description: "The AWS region of the CloudTrail bucket",
						},
						"dspm_role_arn": schema.StringAttribute{
							Computed:    true,
							Description: "The ARN of the IAM role to be used by CrowdStrike DSPM",
						},
						"asset_inventory_enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Weather asset inventory is enabled",
						},
						"realtime_visibility_enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Weather realtime visibility is enabled",
						},
						"idp_enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Weather IDP is enabled",
						},
						"sensor_management_enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Weather sensor management is enabled",
						},
						"dspm_enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Weather DSPM is enabled",
						},
					},
				},
			},
		},
	}
}

func (d *cloudAwsAccountsDataSource) getCSPMAccounts(
	ctx context.Context,
	accountID string,
	organizationID string,
) ([]*models.DomainAWSAccountV2, diag.Diagnostics) {
	var diags diag.Diagnostics
	tflog.Info(ctx, "[datasource] Getting CSPM AWS Accounts ", map[string]interface{}{"accountID": accountID, "organizationID": organizationID})
	params := &cspm_registration.GetCSPMAwsAccountParams{
		Context: ctx,
	}
	if len(accountID) > 0 {
		params.Ids = []string{accountID}
	}
	if len(organizationID) > 0 {
		params.OrganizationIds = []string{organizationID}
	}
	res, status, err := d.client.CspmRegistration.GetCSPMAwsAccount(params)
	if err != nil {
		if _, ok := err.(*cspm_registration.GetCSPMAwsAccountForbidden); ok {
			diags.AddError(
				"Failed to read CSPM AWS account: 403 Forbidden",
				scopes.GenerateScopeDescription(cloudSecurityScopes),
			)
			return nil, diags
		}
		diags.AddError(
			"Failed to read CSPM AWS accounts",
			fmt.Sprintf("Failed to get CSPM AWS accounts: %s", err.Error()),
		)
		return nil, diags
	}
	if status != nil {
		for _, error := range status.Payload.Errors {
			diags.AddError(
				"Failed to read CSPM AWS accounts",
				fmt.Sprintf("Failed to get CSPM AWS accounts: %s", *error.Message),
			)
		}
		return status.Payload.Resources, diags
	}
	return res.Payload.Resources, diags
}

func (d *cloudAwsAccountsDataSource) getCloudAccounts(
	ctx context.Context,
	accounts []string,
) ([]*models.DomainCloudAWSAccountV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	tflog.Debug(ctx, "[datasource] Getting Cloud AWS Accounts ", map[string]interface{}{"accounts": accounts})
	res, status, err := d.client.CloudAwsRegistration.CloudRegistrationAwsGetAccounts(&cloud_aws_registration.CloudRegistrationAwsGetAccountsParams{
		Context: ctx,
		Ids:     accounts,
	})
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
		for _, error := range status.Payload.Errors {
			diags.AddError(
				"Failed to read Cloud Registration AWS accounts",
				fmt.Sprintf("Failed to get Cloud AWS accounts: %s", *error.Message),
			)
		}
		return nil, diags
	}
	return res.Payload.Resources, diags
}

// Read refreshes the Terraform state with the latest data.
func (d *cloudAwsAccountsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data cloudAwsAccountsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	cspmAccounts, diags := d.getCSPMAccounts(ctx, data.AccountID.ValueString(), data.OrganizationID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Accounts = make([]*cloudAWSAccountDataModel, 0, len(cspmAccounts))
	ids := make([]string, 0, len(cspmAccounts))
	idToModel := make(map[string]*cloudAWSAccountDataModel, len(cspmAccounts))

	managementAccts := make(map[string]*models.DomainAWSAccountV2)
	for _, a := range cspmAccounts {
		if a.IsMaster {
			managementAccts[a.OrganizationID] = a
		}
	}

	for _, a := range cspmAccounts {
		if a == nil {
			continue
		}
		targetOus := make([]attr.Value, 0, len(a.TargetOus))
		for _, ou := range a.TargetOus {
			targetOus = append(targetOus, types.StringValue(ou))
		}
		m := &cloudAWSAccountDataModel{
			AccountID:                 types.StringValue(a.AccountID),
			OrganizationID:            types.StringValue(a.OrganizationID),
			TargetOUs:                 types.ListValueMust(types.StringType, targetOus),
			IsOrgManagementAccount:    types.BoolValue(a.IsMaster),
			AccountType:               types.StringValue(a.AccountType),
			ExternalID:                types.StringValue(a.ExternalID),
			IntermediateRoleArn:       types.StringValue(a.IntermediateRoleArn),
			IamRoleArn:                types.StringValue(a.IamRoleArn),
			EventbusName:              types.StringValue(a.EventbusName),
			EventbusArn:               types.StringValue(a.AwsEventbusArn),
			CloudTrailBucketName:      types.StringValue(a.AwsCloudtrailBucketName),
			CloudTrailRegion:          types.StringValue(a.AwsCloudtrailRegion),
			DspmRoleArn:               types.StringValue(a.DspmRoleArn),
			AssetInventoryEnabled:     types.BoolValue(true), // this feature is always enabled
			RealtimeVisibilityEnabled: types.BoolValue(a.BehaviorAssessmentEnabled),
			IDPEnabled:                types.BoolValue(false),
			SensorManagementEnabled:   types.BoolValue(a.SensorManagementEnabled != nil && *a.SensorManagementEnabled),
			DSPMEnabled:               types.BoolValue(a.DspmEnabled),
		}
		// For org child accounts, the feature values are not always set.
		// The management account should be the source of truth in this case.
		if !a.IsMaster && a.OrganizationID != "" {
			managementAcct, ok := managementAccts[a.OrganizationID]
			if ok {
				m.RealtimeVisibilityEnabled = types.BoolValue(managementAcct.BehaviorAssessmentEnabled)
				m.IDPEnabled = types.BoolValue(false)
				m.SensorManagementEnabled = types.BoolValue(managementAcct.SensorManagementEnabled != nil && *managementAcct.SensorManagementEnabled)
				m.DSPMEnabled = types.BoolValue(managementAcct.DspmEnabled)
			} else {
				tflog.Warn(ctx, "Got a child account from a different organization.", map[string]interface{}{"account_id": a.AccountID, "organization_id": a.OrganizationID})
			}
		}
		ids = append(ids, a.AccountID)
		idToModel[a.AccountID] = m
		data.Accounts = append(data.Accounts, m)
	}
	// Set state
	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Now we need to read and update the IDP status from Cloud Registration
	cloudAccounts, diags := d.getCloudAccounts(ctx, ids)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	for _, a := range cloudAccounts {
		for _, p := range a.Products {
			if *p.Product == "idp" {
				if m, ok := idToModel[a.AccountID]; ok {
					m.IDPEnabled = types.BoolValue(true)
				}
				break
			}
		}
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
