package fcs

import (
	"context"
	"fmt"
	"regexp"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_aws_registration"
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

type cloudAWSAccountResource struct {
	client *client.CrowdStrikeAPISpecification
}

type assetInventory struct {
	Enabled  types.Bool   `tfsdk:"enabled"`
	RoleName types.String `tfsdk:"role_name"`
}
type realtimeVisibility struct {
	Enabled               types.Bool   `tfsdk:"enabled"`
	CloudTrailRegion      types.String `tfsdk:"cloudtrail_region"`
	UseExistingCloudTrail types.Bool   `tfsdk:"use_existing_cloudtrail"`
}

type idp struct {
	Enabled     types.Bool   `tfsdk:"enabled"`
	Status      types.String `tfsdk:"status"`
	LastUpdated types.String `tfsdk:"last_updated"`
}

type sensorManagement struct {
	Enabled types.Bool `tfsdk:"enabled"`
}

type dspm struct {
	Enabled  types.Bool   `tfsdk:"enabled"`
	RoleName types.String `tfsdk:"role_name"`
}

type cloudAWSAccountModel struct {
	AccountID              types.String        `tfsdk:"account_id"`
	OrganizationID         types.String        `tfsdk:"organization_id"`
	TargetOUs              types.List          `tfsdk:"target_ous"`
	IsOrgManagementAccount types.Bool          `tfsdk:"is_organization_management_account"`
	AccountType            types.String        `tfsdk:"account_type"`
	DeploymentMethod       types.String        `tfsdk:"deployment_method"`
	AssetInventory         *assetInventory     `tfsdk:"asset_inventory"`
	RealtimeVisibility     *realtimeVisibility `tfsdk:"realtime_visibility"`
	IDP                    *idp                `tfsdk:"idp"`
	SensorManagement       *sensorManagement   `tfsdk:"sensor_management"`
	DSPM                   *dspm               `tfsdk:"dspm"`
	// Computed
	ExternalID           types.String `tfsdk:"external_id"`
	IntermediateRoleArn  types.String `tfsdk:"intermediate_role_arn"`
	IamRoleArn           types.String `tfsdk:"iam_role_arn"`
	EventbusName         types.String `tfsdk:"eventbus_name"`
	EventbusArn          types.String `tfsdk:"eventbus_arn"`
	CloudTrailBucketName types.String `tfsdk:"cloudtrail_bucket_name"`
	DspmRoleArn          types.String `tfsdk:"dspm_role_arn"`
}

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &cloudAWSAccountResource{}
	_ resource.ResourceWithConfigure      = &cloudAWSAccountResource{}
	_ resource.ResourceWithImportState    = &cloudAWSAccountResource{}
	_ resource.ResourceWithValidateConfig = &cloudAWSAccountResource{}
)

// NewCloudAWSAccountResource a helper function to simplify the provider implementation.
func NewCloudAWSAccountResource() resource.Resource {
	return &cloudAWSAccountResource{}
}

// Metadata returns the resource type name.
func (r *cloudAWSAccountResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_aws_account"
}

// Schema defines the schema for the resource.
func (r *cloudAWSAccountResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Cloud AWS Account --- This resource allows management of an AWS account in Falcon.\n\n%s",
			scopes.GenerateScopeDescription(fcsScopes),
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
			"asset_inventory": schema.SingleNestedAttribute{
				Required: false,
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:    true,
						Description: "Enable asset inventory",
					},
					"role_name": schema.StringAttribute{
						Optional:    true,
						Description: "Custom AWS IAM role name",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
				},
			},
			"realtime_visibility": schema.SingleNestedAttribute{
				Required: false,
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:    true,
						Description: "Enable realtime visibility",
					},
					"cloudtrail_region": schema.StringAttribute{
						Required:    true,
						Description: "Custom AWS IAM role name",
					},
					"use_existing_cloudtrail": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Set to true if a Cloudtrail already exists",
					},
				},
			},
			"idp": schema.SingleNestedAttribute{
				Required: false,
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:    true,
						Description: "Enable realtime visibility",
					},
					"status": schema.StringAttribute{
						Computed:    true,
						Description: "Current status of the IDP integration",
					},
					"last_updated": schema.StringAttribute{
						Computed:    true,
						Description: "Timestamp of last IDP configuration update",
					},
				},
			},
			"sensor_management": schema.SingleNestedAttribute{
				Required: false,
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:    true,
						Description: "Enable realtime visibility",
					},
				},
			},
			"dspm": schema.SingleNestedAttribute{
				Required: false,
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:    true,
						Description: "Enable asset inventory",
					},
					"role_name": schema.StringAttribute{
						Optional:    true,
						Description: "Custom AWS IAM role name for Data Security Posture Management",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},
				},
			},
			// Computed values
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
				Computed:    true,
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
				Description: "The name of the CloudTrail bucket used for realtime visibility",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"dspm_role_arn": schema.StringAttribute{
				Computed:    true,
				Description: "The ARN of the IAM role to be used by CrowdStrike DSPM",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *cloudAWSAccountResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudAWSAccountModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	cspmAccount, diags := r.createCSPMAccount(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "cspm account created", map[string]interface{}{"account": cspmAccount})

	plan.AccountID = types.StringValue(cspmAccount.AccountID)
	if cspmAccount.OrganizationID != "" {
		plan.OrganizationID = types.StringValue(cspmAccount.OrganizationID)
	}
	plan.AccountType = types.StringValue(cspmAccount.AccountType)
	plan.IsOrgManagementAccount = types.BoolValue(cspmAccount.IsMaster)
	plan.TargetOUs, diags = types.ListValueFrom(ctx, types.StringType, []string{})
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}
	if len(cspmAccount.TargetOus) != 0 {
		targetOUs, diags := types.ListValueFrom(ctx, types.StringType, cspmAccount.TargetOus)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
		}
		plan.TargetOUs = targetOUs
	}
	plan.ExternalID = types.StringValue(cspmAccount.ExternalID)
	plan.IntermediateRoleArn = types.StringValue(cspmAccount.IntermediateRoleArn)
	plan.IamRoleArn = types.StringValue(cspmAccount.IamRoleArn)
	plan.EventbusName = types.StringValue(cspmAccount.EventbusName)
	plan.EventbusArn = types.StringValue(cspmAccount.AwsEventbusArn)
	plan.CloudTrailBucketName = types.StringValue(cspmAccount.AwsCloudtrailBucketName)
	if cspmAccount.AwsCloudtrailRegion != "" {
		if plan.RealtimeVisibility != nil {
			plan.RealtimeVisibility.CloudTrailRegion = types.StringValue(cspmAccount.AwsCloudtrailRegion)
		}
	}
	plan.DspmRoleArn = types.StringValue(cspmAccount.DspmRoleArn)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	cloudAccount, diags := r.createCloudAccount(ctx, plan)
	if plan.IDP != nil {
		plan.IDP.Status = types.StringValue("configured")
		plan.IDP.LastUpdated = types.StringValue(cloudAccount.UpdatedAt.String())
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// createCSPMAccount creates a new CSPM AWS account from the resource model.
func (r *cloudAWSAccountResource) createCSPMAccount(
	ctx context.Context,
	model cloudAWSAccountModel,
) (*models.DomainAWSAccountV2, diag.Diagnostics) {
	var diags diag.Diagnostics

	var targetOUs []string
	diags.Append(model.TargetOUs.ElementsAs(ctx, &targetOUs, false)...)

	createAccount := models.RegistrationAWSAccountExtV2{
		AccountID:        model.AccountID.ValueStringPointer(),
		OrganizationID:   model.OrganizationID.ValueStringPointer(),
		TargetOus:        targetOUs,
		IsMaster:         model.IsOrgManagementAccount.ValueBool(),
		AccountType:      model.AccountType.ValueString(),
		DeploymentMethod: model.DeploymentMethod.ValueString(),
	}

	if model.AssetInventory != nil && model.AssetInventory.RoleName.ValueString() != "" {
		partition := "aws"
		if model.AccountType.ValueString() == "gov" {
			partition = "aws-us-gov"
		}
		roleArn := fmt.Sprintf(
			"arn:%s:iam::%s:role/%s",
			partition,
			model.AccountID.ValueString(),
			model.AssetInventory.RoleName.ValueString(),
		)
		createAccount.IamRoleArn = &roleArn
	}
	if model.RealtimeVisibility != nil {
		createAccount.BehaviorAssessmentEnabled = model.RealtimeVisibility.Enabled.ValueBool()
		createAccount.CloudtrailRegion = model.RealtimeVisibility.CloudTrailRegion.ValueStringPointer()
		createAccount.UseExistingCloudtrail = model.RealtimeVisibility.UseExistingCloudTrail.ValueBool()
	}
	if model.SensorManagement != nil {
		createAccount.SensorManagementEnabled = model.SensorManagement.Enabled.ValueBool()
	}
	if model.DSPM != nil {
		createAccount.DspmEnabled = model.DSPM.Enabled.ValueBool()
		createAccount.DspmRole = model.DSPM.RoleName.ValueString()
	}

	tflog.Info(ctx, "creating CSPM account")
	res, status, err := r.client.CspmRegistration.CreateCSPMAwsAccount(&cspm_registration.CreateCSPMAwsAccountParams{
		Context: ctx,
		Body: &models.RegistrationAWSAccountCreateRequestExtV2{
			Resources: []*models.RegistrationAWSAccountExtV2{
				&createAccount,
			},
		},
	},
	)
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

	if res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Failed to create CSPM AWS account",
			"No error returned from api but CSPM account was not created. Please report this issue to the provider developers.",
		)

		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

// createAccount creates a new Cloud AWS account from the resource model.
func (r *cloudAWSAccountResource) createCloudAccount(
	ctx context.Context,
	model cloudAWSAccountModel,

) (*models.DomainCloudAWSAccountV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	createAccount := models.RestCloudAWSAccountCreateExtV1{
		AccountID:      model.AccountID.ValueString(),
		OrganizationID: model.OrganizationID.ValueStringPointer(),
		IsMaster:       model.IsOrgManagementAccount.ValueBool(),
		AccountType:    model.AccountType.ValueString(),
	}
	if model.AssetInventory != nil && model.AssetInventory.Enabled.ValueBool() {
		createAccount.CspEvents = true
	}
	if model.IDP != nil && model.IDP.Enabled.ValueBool() {
		createAccount.CspEvents = true
		productString := "idp"
		createAccount.Products = []*models.RestAccountProductUpsertRequestExtV1{
			{
				Product:  &productString,
				Features: []string{"default"},
			},
		}
	}

	res, status, err := r.client.CloudAwsRegistration.CloudRegistrationAwsCreateAccount(&cloud_aws_registration.CloudRegistrationAwsCreateAccountParams{
		Context: ctx,
		Body: &models.RestAWSAccountCreateRequestExtv1{
			Resources: []*models.RestCloudAWSAccountCreateExtV1{
				&createAccount,
			},
		},
	})
	if err != nil {
		diags.AddError(
			"Failed to create Cloud Registration AWS account",
			fmt.Sprintf("Failed to create Cloud Registration AWS account: %s", err.Error()),
		)
		return nil, diags
	}
	if status != nil {
		diags.AddError(
			"Failed to create Cloud Registration AWS account",
			fmt.Sprintf("Failed to create Cloud Registration AWS account: %s", status.Error()),
		)
		return nil, diags
	}

	if res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Failed to create Cloud Registration AWS account",
			"No error returned from api but Cloud Registration account was not created. Please report this issue to the provider developers.",
		)

		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

// Read refreshes the Terraform state with the latest data.
func (r *cloudAWSAccountResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudAWSAccountModel
	var oldState cloudAWSAccountModel
	diags := req.State.Get(ctx, &oldState)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if oldState.AccountID.ValueString() == "" {
		return
	}
	cspmAccount, diags := r.getCSPMAccount(ctx, oldState.AccountID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.AccountID = types.StringValue(cspmAccount.AccountID)
	if cspmAccount.OrganizationID != "" {
		state.OrganizationID = types.StringValue(cspmAccount.OrganizationID)
	}
	state.AccountType = types.StringValue(cspmAccount.AccountType)
	state.IsOrgManagementAccount = types.BoolValue(cspmAccount.IsMaster)
	state.DeploymentMethod = oldState.DeploymentMethod
	state.TargetOUs, diags = types.ListValueFrom(ctx, types.StringType, []string{})
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}
	if len(cspmAccount.TargetOus) != 0 {
		targetOUs, diags := types.ListValueFrom(ctx, types.StringType, cspmAccount.TargetOus)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
		}
		state.TargetOUs = targetOUs
	} else {
		state.TargetOUs = oldState.TargetOUs
	}
	state.ExternalID = types.StringValue(cspmAccount.ExternalID)
	state.IntermediateRoleArn = types.StringValue(cspmAccount.IntermediateRoleArn)
	state.IamRoleArn = types.StringValue(cspmAccount.IamRoleArn)
	state.EventbusName = types.StringValue(cspmAccount.EventbusName)
	state.EventbusArn = types.StringValue(cspmAccount.AwsEventbusArn)
	state.CloudTrailBucketName = types.StringValue(cspmAccount.AwsCloudtrailBucketName)
	if cspmAccount.AwsCloudtrailRegion != "" {
		if state.RealtimeVisibility != nil {
			state.RealtimeVisibility.CloudTrailRegion = types.StringValue(cspmAccount.AwsCloudtrailRegion)
		}
	}
	state.AssetInventory = oldState.AssetInventory
	state.RealtimeVisibility = oldState.RealtimeVisibility

	cloudAccount, found, diags := r.getCloudAccount(ctx, oldState.AccountID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if oldState.IDP != nil && found {
		state.IDP = oldState.IDP
		for _, p := range cloudAccount.Products {
			if *p.Product == "idp" {
				state.IDP.Enabled = types.BoolValue(true)
				break
			}
		}
	}
	state.SensorManagement = &sensorManagement{
		Enabled: types.BoolValue(*cspmAccount.SensorManagementEnabled),
	}
	state.DSPM = &dspm{
		Enabled: types.BoolValue(cspmAccount.DspmEnabled),
	}
	state.DspmRoleArn = types.StringValue(cspmAccount.DspmRoleArn)

	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *cloudAWSAccountResource) getCSPMAccount(
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

func (r *cloudAWSAccountResource) getCloudAccount(
	ctx context.Context,
	accountID string,
) (*models.DomainCloudAWSAccountV1, bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	res, status, err := r.client.CloudAwsRegistration.CloudRegistrationAwsGetAccounts(&cloud_aws_registration.CloudRegistrationAwsGetAccountsParams{
		Context: ctx,
		Ids:     []string{accountID},
	})
	if err != nil {
		diags.AddError(
			"Failed to read Cloud Registration AWS account",
			fmt.Sprintf("Failed to read Cloud Registration AWS account: %s", err.Error()),
		)
		return nil, false, diags
	}
	if status != nil {
		diags.AddWarning(
			"Failed to read Cloud Registration AWS account",
			fmt.Sprintf("Failed to read Cloud Registration AWS account: %s", status.Error()),
		)
		return nil, false, diags
	}

	if len(res.Payload.Resources) == 0 {
		diags.AddWarning(
			"Failed to read Cloud Registration AWS account",
			"No error returned from api but Cloud Registration account was not returned. Please report this issue to the provider developers.",
		)

		return nil, false, diags
	}

	return res.Payload.Resources[0], true, diags
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *cloudAWSAccountResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	// Retrieve values from plan
	var plan cloudAWSAccountModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Retrieve values from state
	var state cloudAWSAccountModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	cspmAccount, diags := r.updateCSPMAccount(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.AccountID = types.StringValue(cspmAccount.AccountID)
	if cspmAccount.OrganizationID != "" {
		plan.OrganizationID = types.StringValue(cspmAccount.OrganizationID)
	}
	plan.AccountType = types.StringValue(cspmAccount.AccountType)
	plan.IsOrgManagementAccount = types.BoolValue(cspmAccount.IsMaster)
	plan.DeploymentMethod = state.DeploymentMethod
	plan.TargetOUs = state.TargetOUs
	if len(cspmAccount.TargetOus) != 0 {
		targetOUs, diags := types.ListValueFrom(ctx, types.StringType, cspmAccount.TargetOus)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
		}
		plan.TargetOUs = targetOUs
	}
	plan.ExternalID = types.StringValue(cspmAccount.ExternalID)
	plan.IntermediateRoleArn = types.StringValue(cspmAccount.IntermediateRoleArn)
	plan.IamRoleArn = types.StringValue(cspmAccount.IamRoleArn)
	plan.EventbusName = types.StringValue(cspmAccount.EventbusName)
	plan.EventbusArn = types.StringValue(cspmAccount.AwsEventbusArn)
	plan.CloudTrailBucketName = types.StringValue(cspmAccount.AwsCloudtrailBucketName)
	if cspmAccount.AwsCloudtrailRegion != "" {
		if plan.RealtimeVisibility != nil {
			plan.RealtimeVisibility.CloudTrailRegion = types.StringValue(cspmAccount.AwsCloudtrailRegion)
		}
	}
	if plan.DSPM != nil {
		plan.DSPM.Enabled = types.BoolValue(cspmAccount.DspmEnabled)
	}
	plan.DspmRoleArn = types.StringValue(cspmAccount.DspmRoleArn)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	cloudAccount, diags := r.updateCloudAccount(ctx, plan)
	if plan.IDP != nil {
		plan.IDP.Status = types.StringValue("configured")
		plan.IDP.LastUpdated = types.StringValue(cloudAccount.UpdatedAt.String())
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *cloudAWSAccountResource) updateCSPMAccount(
	ctx context.Context,
	model cloudAWSAccountModel,
) (*models.DomainAWSAccountV2, diag.Diagnostics) {
	var diags diag.Diagnostics
	var targetOUs []string

	diags.Append(model.TargetOUs.ElementsAs(ctx, &targetOUs, false)...)
	patchAccount := models.RegistrationAWSAccountPatch{
		AccountID: model.AccountID.ValueStringPointer(),
		TargetOus: targetOUs,
	}
	if model.RealtimeVisibility != nil {
		patchAccount.BehaviorAssessmentEnabled = model.RealtimeVisibility.Enabled.ValueBool()
		patchAccount.CloudtrailRegion = model.RealtimeVisibility.CloudTrailRegion.ValueString()
	}
	if model.SensorManagement != nil {
		patchAccount.SensorManagementEnabled = model.SensorManagement.Enabled.ValueBool()
	}
	if model.DSPM != nil {
		patchAccount.DspmEnabled = model.DSPM.Enabled.ValueBool()
		patchAccount.DspmRole = model.DSPM.RoleName.ValueString()
	}
	res, status, err := r.client.CspmRegistration.PatchCSPMAwsAccount(&cspm_registration.PatchCSPMAwsAccountParams{
		Context: ctx,
		Body: &models.RegistrationAWSAccountPatchRequest{
			Resources: []*models.RegistrationAWSAccountPatch{
				&patchAccount,
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

	if res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Failed to update CSPM AWS account",
			"No error returned from api but CSPM account was not returned. Please report this issue to the provider developers.",
		)
		return nil, diags
	}
	return res.Payload.Resources[0], diags
}

func (r *cloudAWSAccountResource) updateCloudAccount(
	ctx context.Context,
	model cloudAWSAccountModel,
) (*models.DomainCloudAWSAccountV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	patchAccount := models.RestCloudAWSAccountCreateExtV1{
		AccountID:      model.AccountID.ValueString(),
		OrganizationID: model.OrganizationID.ValueStringPointer(),
		IsMaster:       model.IsOrgManagementAccount.ValueBool(),
		AccountType:    model.AccountType.ValueString(),
	}
	if model.AssetInventory != nil && model.AssetInventory.Enabled.ValueBool() {
		patchAccount.CspEvents = true
	}
	productString := "idp"
	patchAccount.Products = []*models.RestAccountProductUpsertRequestExtV1{
		{
			Product:  &productString,
			Features: []string{},
		},
	}
	if model.IDP != nil && model.IDP.Enabled.ValueBool() {
		patchAccount.CspEvents = true
		patchAccount.Products[0].Features = append(patchAccount.Products[0].Features, "default")
	}
	res, status, err := r.client.CloudAwsRegistration.CloudRegistrationAwsUpdateAccount(&cloud_aws_registration.CloudRegistrationAwsUpdateAccountParams{
		Context: ctx,
		Body: &models.RestAWSAccountCreateRequestExtv1{
			Resources: []*models.RestCloudAWSAccountCreateExtV1{
				&patchAccount,
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

// Delete deletes the resource and removes the Terraform state on success.
func (r *cloudAWSAccountResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudAWSAccountModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.IDP != nil {
		resp.Diagnostics.Append(r.deleteCloudAccount(ctx, state)...)
	}

	resp.Diagnostics.Append(r.deleteCSPMAccount(ctx, state)...)
}

func (r *cloudAWSAccountResource) deleteCSPMAccount(
	ctx context.Context,
	model cloudAWSAccountModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// deleting a resource that does not exist.
	if model.AccountID.ValueString() == "" && model.OrganizationID.ValueString() == "" {
		return diags
	}
	params := &cspm_registration.DeleteCSPMAwsAccountParams{
		Context: ctx,
	}
	tflog.Info(ctx, "deleting CSPM account", map[string]interface{}{
		"account_id":                model.AccountID.ValueString(),
		"organization_id":           model.OrganizationID.ValueString(),
		"is_org_management_account": model.IsOrgManagementAccount.ValueBool(),
	})
	if model.IsOrgManagementAccount.ValueBool() {
		params.OrganizationIds = []string{model.OrganizationID.ValueString()}
	} else {
		params.Ids = []string{model.AccountID.ValueString()}
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

func (r *cloudAWSAccountResource) deleteCloudAccount(
	ctx context.Context,
	model cloudAWSAccountModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// deleting a resource that does not exist.
	if model.AccountID.ValueString() == "" && model.OrganizationID.ValueString() == "" {
		return diags
	}
	params := &cloud_aws_registration.CloudRegistrationAwsDeleteAccountParams{
		Context: ctx,
	}
	tflog.Info(ctx, "deleting Cloud Registration account", map[string]interface{}{
		"account_id":                model.AccountID.ValueString(),
		"organization_id":           model.OrganizationID.ValueString(),
		"is_org_management_account": model.IsOrgManagementAccount.ValueBool(),
	})
	if model.IsOrgManagementAccount.ValueBool() {
		params.OrganizationIds = []string{model.OrganizationID.ValueString()}
	} else {
		params.Ids = []string{model.AccountID.ValueString()}
	}

	_, status, err := r.client.CloudAwsRegistration.CloudRegistrationAwsDeleteAccount(params)
	if err != nil {
		diags.AddError(
			"Failed to delete Cloud Registration AWS account",
			fmt.Sprintf("Failed to delete Cloud Registration AWS account: %s", err.Error()),
		)
		return diags
	}
	if status != nil {
		diags.AddError(
			"Failed to delete Cloud Registration AWS account",
			fmt.Sprintf("Failed to delete Cloud Registration AWS account: %s", status.Error()),
		)
		return diags
	}
	return diags
}

// Configure adds the provider configured client to the resource.
func (r *cloudAWSAccountResource) Configure(
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
func (r *cloudAWSAccountResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("account_id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *cloudAWSAccountResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config cloudAWSAccountModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
}
