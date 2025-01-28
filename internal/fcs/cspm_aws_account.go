package fcs

import (
	"context"
	"fmt"
	"regexp"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cspm_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type cspmAWSAccountResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cspmAWSAccountModel struct {
	AccountID              types.String `tfsdk:"account_id"`
	OrganizationID         types.String `tfsdk:"organization_id"`
	TargetOUs              types.List   `tfsdk:"target_ous"`
	IsOrgManagementAccount types.Bool   `tfsdk:"is_organization_management_account"`
	AccountType            types.String `tfsdk:"account_type"`
	DeploymentMethod       types.String `tfsdk:"deployment_method"`

	// Feature related fields
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
	DSPMRoleName             types.String `tfsdk:"dspm_role_name"`
	DSPMRoleArn              types.String `tfsdk:"dspm_role_arn"`
}

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &cspmAWSAccountResource{}
	_ resource.ResourceWithConfigure      = &cspmAWSAccountResource{}
	_ resource.ResourceWithImportState    = &cspmAWSAccountResource{}
	_ resource.ResourceWithValidateConfig = &cspmAWSAccountResource{}
)

// NewCSPMAWSAccountResource is a helper function to simplify the provider implementation.
func NewCSPMAWSAccountResource() resource.Resource {
	return &cspmAWSAccountResource{}
}

// Metadata returns the resource type name.
func (r *cspmAWSAccountResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cspm_aws_account"
}

// Schema defines the schema for the resource.
func (r *cspmAWSAccountResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"CSPM AWS Account --- This resource allows management of a CSPM Account. A FileVantage policy is a collection of file integrity rules and rule groups that you can apply to host groups.\n\n%s",
			scopes.GenerateScopeDescription(cspmScopes),
		),
		Attributes: map[string]schema.Attribute{
			"account_id": schema.StringAttribute{
				Required:    true,
				Description: "The AWS Account ID.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(12, 12),
					stringvalidator.RegexMatches(regexp.MustCompile(`^[0-9]+$`), "must be exactly 12 digits"),
				},
			},
			"organization_id": schema.StringAttribute{
				Optional:    true,
				Description: "The AWS Organization ID",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.Any(
						stringvalidator.LengthAtMost(0),
						stringvalidator.All(
							stringvalidator.LengthBetween(12, 34),
							stringvalidator.RegexMatches(regexp.MustCompile(`^o-[a-z0-9]{10,32}$`), "must be in the format of o-xxxxxxxxxx"),
						),
					),
				},
			},
			"target_ous": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The list of target OUs",
				Default:     listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
				ElementType: types.StringType,
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.RegexMatches(regexp.MustCompile(`^(ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}|r-[0-9a-z]{4,32})$`), "must be in the format of ou-xxxx-xxxxxxxx or r-xxxx"),
					),
				},
			},
			"is_organization_management_account": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Indicates whether this is the management account (formerly known as the root account) of an AWS Organization",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},
			"account_type": schema.StringAttribute{
				Optional:    true,
				Default:     stringdefault.StaticString("commercial"),
				Computed:    true,
				Description: "The type of account. Not needed for non-govcloud environment",
				Validators: []validator.String{
					stringvalidator.OneOf("commercial", "gov"),
				},
			},
			"deployment_method": schema.StringAttribute{
				Optional:    true,
				Default:     stringdefault.StaticString("terraform-native"),
				Computed:    true,
				Description: "How the account was deployed. Valid values are 'terraform-native' and 'terraform-cft'",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("terraform-native", "terraform-cft"),
				},
			},
			"enable_realtime_visibility": schema.BoolAttribute{
				Optional:    true,
				Default:     booldefault.StaticBool(false),
				Computed:    true,
				Description: "Enable the Realtime Visibility feature",
			},
			"enable_sensor_management": schema.BoolAttribute{
				Optional:    true,
				Default:     booldefault.StaticBool(false),
				Computed:    true,
				Description: "Enable the 1-Click Sensor Management feature",
			},
			"enable_dspm": schema.BoolAttribute{
				Optional:    true,
				Default:     booldefault.StaticBool(false),
				Computed:    true,
				Description: "Enable the Data Security Posture Management feature",
			},
			"external_id": schema.StringAttribute{
				Computed:    true,
				Description: "The external ID used to assume the AWS IAM role",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"intermediate_role_arn": schema.StringAttribute{
				Computed:    true,
				Description: "The ARN of the intermediate role used to assume the AWS IAM role",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"iam_role_arn": schema.StringAttribute{
				Computed: true,
				// Optional: true, //todo: make optional
				Description: "The ARN of the AWS IAM role used to access this AWS account",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"eventbus_name": schema.StringAttribute{
				Computed:    true,
				Description: "The name of CrowdStrike Event Bridge to forward messages to",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"eventbus_arn": schema.StringAttribute{
				Computed:    true,
				Description: "The ARN of CrowdStrike Event Bridge to forward messages to",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cloudtrail_bucket_name": schema.StringAttribute{
				Computed:    true,
				Description: "",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cloudtrail_region": schema.StringAttribute{
				Optional:    true,
				Description: "The AWS region of the CloudTrail bucket",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.AlsoRequires(path.MatchRoot("enable_realtime_visibility")),
				},
			},
			"dspm_role_name": schema.StringAttribute{
				Optional:    true,
				Description: "The name of the IAM role to be used by CrowdStrike DSPM",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"dspm_role_arn": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "The ARN of the IAM role to be used by CrowdStrike DSPM",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *cspmAWSAccountResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cspmAWSAccountModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	account, diags := r.createAccount(ctx, plan)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "fcs cspm account created", map[string]interface{}{"account": account})

	plan.AccountID = types.StringValue(account.AccountID)
	if account.OrganizationID != "" {
		plan.OrganizationID = types.StringValue(account.OrganizationID)
	}
	plan.AccountType = types.StringValue(account.AccountType)
	plan.IsOrgManagementAccount = types.BoolValue(account.IsMaster)
	plan.TargetOUs, diags = types.ListValueFrom(ctx, types.StringType, []string{})
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}
	if len(account.TargetOus) != 0 {
		targetOUs, diags := types.ListValueFrom(ctx, types.StringType, account.TargetOus)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
		}
		plan.TargetOUs = targetOUs
	}

	plan.EnableRealtimeVisibility = types.BoolValue(account.BehaviorAssessmentEnabled)
	plan.EnableSensorManagement = types.BoolValue(*account.SensorManagementEnabled)
	plan.EnableDSPM = types.BoolValue(account.DspmEnabled)
	plan.ExternalID = types.StringValue(account.ExternalID)
	plan.IntermediateRoleArn = types.StringValue(account.IntermediateRoleArn)
	plan.IamRoleArn = types.StringValue(account.IamRoleArn)
	plan.EventbusName = types.StringValue(account.EventbusName)
	plan.EventbusArn = types.StringValue(account.AwsEventbusArn)
	plan.CloudTrailBucketName = types.StringValue(account.AwsCloudtrailBucketName)
	if account.AwsCloudtrailRegion != "" {
		plan.CloudTrailRegion = types.StringValue(account.AwsCloudtrailRegion)
	}
	plan.DSPMRoleArn = types.StringValue(account.DspmRoleArn)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *cspmAWSAccountResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cspmAWSAccountModel
	var oldState cspmAWSAccountModel
	diags := req.State.Get(ctx, &oldState)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if oldState.AccountID.ValueString() == "" {
		return
	}
	account, diags := r.getAccount(ctx, oldState.AccountID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.AccountID = types.StringValue(account.AccountID)
	if account.OrganizationID != "" {
		state.OrganizationID = types.StringValue(account.OrganizationID)
	}
	state.AccountType = types.StringValue(account.AccountType)
	state.IsOrgManagementAccount = types.BoolValue(account.IsMaster)
	state.DeploymentMethod = oldState.DeploymentMethod
	state.TargetOUs, diags = types.ListValueFrom(ctx, types.StringType, []string{})
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}
	if len(account.TargetOus) != 0 {
		targetOUs, diags := types.ListValueFrom(ctx, types.StringType, account.TargetOus)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
		}
		state.TargetOUs = targetOUs
	} else {
		state.TargetOUs = oldState.TargetOUs
	}
	state.EnableRealtimeVisibility = types.BoolValue(account.BehaviorAssessmentEnabled)
	state.EnableSensorManagement = types.BoolValue(*account.SensorManagementEnabled)
	state.EnableDSPM = types.BoolValue(account.DspmEnabled)
	state.ExternalID = types.StringValue(account.ExternalID)
	state.IntermediateRoleArn = types.StringValue(account.IntermediateRoleArn)
	state.IamRoleArn = types.StringValue(account.IamRoleArn)
	state.EventbusName = types.StringValue(account.EventbusName)
	state.EventbusArn = types.StringValue(account.AwsEventbusArn)
	state.CloudTrailBucketName = types.StringValue(account.AwsCloudtrailBucketName)
	if account.AwsCloudtrailRegion != "" {
		state.CloudTrailRegion = types.StringValue(account.AwsCloudtrailRegion)
	}
	state.DSPMRoleArn = types.StringValue(account.DspmRoleArn)
	state.DSPMRoleName = oldState.DSPMRoleName

	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *cspmAWSAccountResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	// Retrieve values from plan
	var plan, oldState cspmAWSAccountModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	diags = req.State.Get(ctx, &oldState)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Retrieve values from state
	var state cspmAWSAccountModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	account, diags := r.updateAccount(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.AccountID = types.StringValue(account.AccountID)
	if account.OrganizationID != "" {
		plan.OrganizationID = types.StringValue(account.OrganizationID)
	}
	plan.AccountType = types.StringValue(account.AccountType)
	plan.IsOrgManagementAccount = types.BoolValue(account.IsMaster)
	plan.DeploymentMethod = state.DeploymentMethod
	if len(account.TargetOus) != 0 {
		targetOUs, diags := types.ListValueFrom(ctx, types.StringType, account.TargetOus)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
		}
		plan.TargetOUs = targetOUs
	}
	plan.EnableRealtimeVisibility = types.BoolValue(account.BehaviorAssessmentEnabled)
	plan.EnableSensorManagement = types.BoolValue(*account.SensorManagementEnabled)
	plan.EnableDSPM = types.BoolValue(account.DspmEnabled)
	plan.ExternalID = types.StringValue(account.ExternalID)
	plan.IntermediateRoleArn = types.StringValue(account.IntermediateRoleArn)
	plan.IamRoleArn = types.StringValue(account.IamRoleArn)
	plan.EventbusName = types.StringValue(account.EventbusName)
	plan.EventbusArn = types.StringValue(account.AwsEventbusArn)
	plan.CloudTrailBucketName = types.StringValue(account.AwsCloudtrailBucketName)
	if account.AwsCloudtrailRegion != "" {
		plan.CloudTrailRegion = types.StringValue(account.AwsCloudtrailRegion)
	}
	plan.DSPMRoleArn = types.StringValue(account.DspmRoleArn)
	plan.DSPMRoleName = oldState.DSPMRoleName

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *cspmAWSAccountResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cspmAWSAccountModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.deleteAccount(ctx, state)...)
}

// Configure adds the provider configured client to the resource.
func (r *cspmAWSAccountResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
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

// ImportState implements the logic to support resource imports.
func (r *cspmAWSAccountResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("account_id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *cspmAWSAccountResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config cspmAWSAccountModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// createAccount creates a new CSPM AWS account from the resource model.
func (r *cspmAWSAccountResource) createAccount(
	ctx context.Context,
	config cspmAWSAccountModel,
) (*models.DomainAWSAccountV2, diag.Diagnostics) {
	var diags diag.Diagnostics
	var targetOUs []string

	diags.Append(config.TargetOUs.ElementsAs(ctx, &targetOUs, false)...)
	res, status, err := r.client.CspmRegistration.CreateCSPMAwsAccount(&cspm_registration.CreateCSPMAwsAccountParams{
		Context: ctx,
		Body: &models.RegistrationAWSAccountCreateRequestExtV2{
			Resources: []*models.RegistrationAWSAccountExtV2{
				{
					AccountID:                 config.AccountID.ValueStringPointer(),
					OrganizationID:            config.OrganizationID.ValueStringPointer(),
					TargetOus:                 targetOUs,
					IsMaster:                  config.IsOrgManagementAccount.ValueBool(),
					AccountType:               config.AccountType.ValueString(),
					DeploymentMethod:          config.DeploymentMethod.ValueString(),
					CloudtrailRegion:          config.CloudTrailRegion.ValueStringPointer(),
					BehaviorAssessmentEnabled: config.EnableRealtimeVisibility.ValueBool(),
					SensorManagementEnabled:   config.EnableSensorManagement.ValueBool(),
					DspmEnabled:               config.EnableDSPM.ValueBool(),
					DspmRole:                  config.DSPMRoleName.ValueString(),
				},
			},
		},
	})
	if err != nil {
		diags.AddError(
			"Failed to create CSPM AWS account",
			fmt.Sprintf("Failed to create CSPM AWS account: %s", err.Error()),
		)
		return nil, diags
	}
	if status != nil {
		diags.AddError(
			"Failed to create CSPM AWS account",
			fmt.Sprintf("Failed to create CSPM AWS account: %s", status.Error()),
		)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Failed to create CSPM AWS account",
			"No error returned from api but CSPM account was not created. Please report this issue to the provider developers.",
		)

		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func (r *cspmAWSAccountResource) getAccount(
	ctx context.Context,
	accountID string,
) (*models.DomainAWSAccountV2, diag.Diagnostics) {
	var diags diag.Diagnostics
	res, status, err := r.client.CspmRegistration.GetCSPMAwsAccount(&cspm_registration.GetCSPMAwsAccountParams{
		Context: ctx,
		Ids:     []string{accountID},
	})
	if err != nil {
		diags.AddError(
			"Failed to read CSPM AWS account",
			fmt.Sprintf("Failed to get CSPM AWS account: %s", err.Error()),
		)
		return nil, diags
	}
	if status != nil {
		diags.AddError(
			"Failed to read CSPM AWS account",
			fmt.Sprintf("Failed to get CSPM AWS account: %s", status.Error()),
		)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Failed to get CSPM AWS account",
			"No error returned from api but CSPM account was not returned. Please report this issue to the provider developers.",
		)

		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func (r *cspmAWSAccountResource) updateAccount(
	ctx context.Context,
	account cspmAWSAccountModel,
) (*models.DomainAWSAccountV2, diag.Diagnostics) {
	var diags diag.Diagnostics
	var targetOUs []string

	diags.Append(account.TargetOUs.ElementsAs(ctx, &targetOUs, false)...)
	res, status, err := r.client.CspmRegistration.PatchCSPMAwsAccount(&cspm_registration.PatchCSPMAwsAccountParams{
		Context: ctx,
		Body: &models.RegistrationAWSAccountPatchRequest{
			Resources: []*models.RegistrationAWSAccountPatch{
				{
					AccountID:                 account.AccountID.ValueStringPointer(),
					TargetOus:                 targetOUs,
					CloudtrailRegion:          account.CloudTrailRegion.ValueString(),
					BehaviorAssessmentEnabled: account.EnableRealtimeVisibility.ValueBool(),
					SensorManagementEnabled:   account.EnableSensorManagement.ValueBool(),
					DspmEnabled:               account.EnableDSPM.ValueBool(),
					DspmRole:                  account.DSPMRoleName.ValueString(),
				},
			},
		},
	})

	if err != nil {
		diags.AddError(
			"Failed to update CSPM AWS account",
			fmt.Sprintf("Failed to update CSPM AWS account: %s", err.Error()),
		)
		return nil, diags
	}
	if status != nil {
		diags.AddError(
			"Failed to update CSPM AWS account",
			fmt.Sprintf("Failed to update CSPM AWS account: %s", status.Error()),
		)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Failed to update CSPM AWS account",
			"No error returned from api but CSPM account was not returned. Please report this issue to the provider developers.",
		)
		return nil, diags
	}
	return res.Payload.Resources[0], diags
}

func (r *cspmAWSAccountResource) deleteAccount(
	ctx context.Context,
	account cspmAWSAccountModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// deleting a resource that does not exist.
	if account.AccountID.ValueString() == "" && account.OrganizationID.ValueString() == "" {
		return diags
	}
	params := &cspm_registration.DeleteCSPMAwsAccountParams{
		Context: ctx,
	}
	tflog.Info(ctx, "deleting account", map[string]interface{}{
		"account_id":                account.AccountID.ValueString(),
		"organization_id":           account.OrganizationID.ValueString(),
		"is_org_management_account": account.IsOrgManagementAccount.ValueBool(),
	})
	if account.IsOrgManagementAccount.ValueBool() {
		params.OrganizationIds = []string{account.OrganizationID.ValueString()}
	} else {
		params.Ids = []string{account.AccountID.ValueString()}
	}

	_, status, err := r.client.CspmRegistration.DeleteCSPMAwsAccount(params)
	if err != nil {
		diags.AddError(
			"Failed to delete CSPM AWS account",
			fmt.Sprintf("Failed to delete CSPM AWS account: %s", err.Error()),
		)
		return diags
	}
	if status != nil {
		diags.AddError(
			"Failed to delete CSPM AWS account",
			fmt.Sprintf("Failed to delete CSPM AWS account: %s", status.Error()),
		)
		return diags
	}
	return diags
}
