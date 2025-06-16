package fcs

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_aws_registration"
	"github.com/crowdstrike/gofalcon/falcon/client/cspm_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	privatestate "github.com/crowdstrike/terraform-provider-crowdstrike/internal/private_state"
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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/exp/maps"
)

type cloudAWSAccountResource struct {
	client *client.CrowdStrikeAPISpecification
}

type assetInventoryOptions struct {
	Enabled  types.Bool   `tfsdk:"enabled"`
	RoleName types.String `tfsdk:"role_name"`
}
type realtimeVisibilityOptions struct {
	Enabled               types.Bool   `tfsdk:"enabled"`
	CloudTrailRegion      types.String `tfsdk:"cloudtrail_region"`
	UseExistingCloudTrail types.Bool   `tfsdk:"use_existing_cloudtrail"`
}

type idpOptions struct {
	Enabled types.Bool   `tfsdk:"enabled"`
	Status  types.String `tfsdk:"status"`
}

type sensorManagementOptions struct {
	Enabled types.Bool `tfsdk:"enabled"`
}

type dspmOptions struct {
	Enabled  types.Bool   `tfsdk:"enabled"`
	RoleName types.String `tfsdk:"role_name"`
}

// cloudStateKey the private state key used in terraform.
const cloudStateKey = "accountState"

// cloudAccState tracks if the cloud registration account has been created.
type cloudAccState struct {
	Created bool `json:"created"`
}

type cloudAWSAccountModel struct {
	AccountID              types.String               `tfsdk:"account_id"`
	OrganizationID         types.String               `tfsdk:"organization_id"`
	TargetOUs              types.List                 `tfsdk:"target_ous"`
	IsOrgManagementAccount types.Bool                 `tfsdk:"is_organization_management_account"`
	AccountType            types.String               `tfsdk:"account_type"`
	DeploymentMethod       types.String               `tfsdk:"deployment_method"`
	AssetInventory         *assetInventoryOptions     `tfsdk:"asset_inventory"`
	RealtimeVisibility     *realtimeVisibilityOptions `tfsdk:"realtime_visibility"`
	IDP                    *idpOptions                `tfsdk:"idp"`
	SensorManagement       *sensorManagementOptions   `tfsdk:"sensor_management"`
	DSPM                   *dspmOptions               `tfsdk:"dspm"`
	ResourceNamePrefix     types.String               `tfsdk:"resource_name_prefix"`
	ResourceNameSuffix     types.String               `tfsdk:"resource_name_suffix"`
	// Computed
	ExternalID           types.String `tfsdk:"external_id"`
	IntermediateRoleArn  types.String `tfsdk:"intermediate_role_arn"`
	IamRoleArn           types.String `tfsdk:"iam_role_arn"`
	IamRoleName          types.String `tfsdk:"iam_role_name"`
	EventbusName         types.String `tfsdk:"eventbus_name"`
	EventbusArn          types.String `tfsdk:"eventbus_arn"`
	CloudTrailBucketName types.String `tfsdk:"cloudtrail_bucket_name"`
	DspmRoleArn          types.String `tfsdk:"dspm_role_arn"`
	DspmRoleName         types.String `tfsdk:"dspm_role_name"`
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
			"Falcon Cloud Security --- This resource registers an AWS account or organization in Falcon Cloud Security.\n\n%s",
			scopes.GenerateScopeDescription(cloudSecurityScopes),
		),
		Attributes: map[string]schema.Attribute{
			"account_id": schema.StringAttribute{
				Required:    true,
				Description: "The AWS Account ID",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(12, 12),
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[0-9]+$`),
						"must be exactly 12 digits",
					),
				},
			},
			"organization_id": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
				Description:         "The AWS Organization ID (starts with 'o-'). When specified, accounts within the organization will be registered. If target_ous is empty, all accounts in the organization will be registered. The account_id must be the organization's management account ID.",
				MarkdownDescription: "The AWS Organization ID (starts with `o-`). When specified, accounts within the organization will be registered. If `target_ous` is empty, all accounts in the organization will be registered. The `account_id` must be the organization's management account ID.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.Any(
						stringvalidator.LengthAtMost(0),
						stringvalidator.All(
							stringvalidator.LengthBetween(12, 34),
							stringvalidator.RegexMatches(
								regexp.MustCompile(`^o-[a-z0-9]{10,32}$`),
								"must be in the format of o-xxxxxxxxxx",
							),
						),
					),
				},
			},
			"target_ous": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The list of target Organizational Units",
				Default: listdefault.StaticValue(
					types.ListValueMust(types.StringType, []attr.Value{}),
				),
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
				ElementType: types.StringType,
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.RegexMatches(
							regexp.MustCompile(
								`^(ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}|r-[0-9a-z]{4,32})$`,
							),
							"must be in the format of ou-xxxx-xxxxxxxx or r-xxxx",
						),
					),
				},
			},
			"resource_name_prefix": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
				Description:         "The prefix to be added to all resource names",
				MarkdownDescription: "The prefix to be added to all resource names",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.Any(
						stringvalidator.LengthAtMost(28),
					),
				},
			},
			"resource_name_suffix": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
				Description:         "The suffix to be added to all resource names",
				MarkdownDescription: "The suffix to be added to all resource names",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.Any(
						stringvalidator.LengthAtMost(28),
					),
				},
			},
			"account_type": schema.StringAttribute{
				Optional:    true,
				Default:     stringdefault.StaticString("commercial"),
				Computed:    true,
				Description: "The AWS account type. Value is 'commercial' for Commercial cloud accounts. For GovCloud environments, value can be either 'commercial' or 'gov' depending on the account type",
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
				Computed: true,
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
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"enabled":   types.BoolType,
							"role_name": types.StringType,
						},
						map[string]attr.Value{
							"enabled":   types.BoolValue(true),
							"role_name": types.StringNull(),
						},
					),
				),
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
			},
			"realtime_visibility": schema.SingleNestedAttribute{
				Required: false,
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:    true,
						Description: "Enable real-time visibility and detection",
					},
					"cloudtrail_region": schema.StringAttribute{
						Required:    true,
						Description: "The AWS region of the CloudTrail bucket",
					},
					"use_existing_cloudtrail": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(true),
						Description: "Set to true if a CloudTrail already exists",
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"enabled":                 types.BoolType,
							"cloudtrail_region":       types.StringType,
							"use_existing_cloudtrail": types.BoolType,
						},
						map[string]attr.Value{
							"enabled":                 types.BoolValue(false),
							"cloudtrail_region":       types.StringNull(),
							"use_existing_cloudtrail": types.BoolValue(true),
						},
					),
				),
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
			},
			"idp": schema.SingleNestedAttribute{
				Required: false,
				Computed: true,
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:    true,
						Description: "Enable Identity Protection",
						PlanModifiers: []planmodifier.Bool{
							boolplanmodifier.UseStateForUnknown(),
						},
					},
					"status": schema.StringAttribute{
						Computed:    true,
						Description: "Current status of the Identity Protection integration",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"enabled": types.BoolType,
							"status":  types.StringType,
						},
						map[string]attr.Value{
							"enabled": types.BoolValue(false),
							"status":  types.StringNull(),
						},
					),
				),
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
			},
			"sensor_management": schema.SingleNestedAttribute{
				Required: false,
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:    true,
						Description: "Enable 1-click sensor deployment",
						PlanModifiers: []planmodifier.Bool{
							boolplanmodifier.UseStateForUnknown(),
						},
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"enabled": types.BoolType,
						},
						map[string]attr.Value{
							"enabled": types.BoolValue(false),
						},
					),
				),
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
			},
			"dspm": schema.SingleNestedAttribute{
				Required: false,
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:    true,
						Description: "Enable Data Security Posture Management",
						PlanModifiers: []planmodifier.Bool{
							boolplanmodifier.UseStateForUnknown(),
						},
					},
					"role_name": schema.StringAttribute{
						Optional:    true,
						Description: "Custom AWS IAM role name for Data Security Posture Management",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"enabled":   types.BoolType,
							"role_name": types.StringType,
						},
						map[string]attr.Value{
							"enabled":   types.BoolValue(false),
							"role_name": types.StringNull(),
						},
					),
				),
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
			},
			// Computed values
			"is_organization_management_account": schema.BoolAttribute{
				Computed:    true,
				Description: "Indicates whether this is the management account (formerly known as the root account) of an AWS Organization",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
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
				Computed:    true,
				Description: "The ARN of the AWS IAM role used to access this AWS account",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"iam_role_name": schema.StringAttribute{
				Computed:    true,
				Description: "The name of the AWS IAM role used to access this AWS account",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"eventbus_name": schema.StringAttribute{
				Computed:    true,
				Description: "The name of the Amazon EventBridge used by CrowdStrike to forward messages",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"eventbus_arn": schema.StringAttribute{
				Computed:    true,
				Description: "The ARN of the Amazon EventBridge used by CrowdStrike to forward messages",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cloudtrail_bucket_name": schema.StringAttribute{
				Computed:    true,
				Description: "The name of the CloudTrail S3 bucket used for real-time visibility",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"dspm_role_arn": schema.StringAttribute{
				Computed:    true,
				Description: "The ARN of the IAM role to be used by CrowdStrike Data Security Posture Management",
				PlanModifiers: []planmodifier.String{
					DSPMArnStateModifier(),
				},
			},
			"dspm_role_name": schema.StringAttribute{
				Computed:    true,
				Description: "The name of the IAM role to be used by CrowdStrike Data Security Posture Management",
				PlanModifiers: []planmodifier.String{
					DSPMArnStateModifier(),
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
	state := plan
	state.AccountID = types.StringValue(cspmAccount.AccountID)
	state.OrganizationID = types.StringValue(cspmAccount.OrganizationID)
	state.AccountType = types.StringValue(cspmAccount.AccountType)
	if cspmAccount.IsMaster && len(cspmAccount.TargetOus) > 0 {
		targetOUs, diags := types.ListValueFrom(ctx, types.StringType, cspmAccount.TargetOus)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
		}
		state.TargetOUs = targetOUs
	}
	state.IsOrgManagementAccount = types.BoolValue(cspmAccount.IsMaster)
	state.ExternalID = types.StringValue(cspmAccount.ExternalID)
	state.IntermediateRoleArn = types.StringValue(cspmAccount.IntermediateRoleArn)
	state.IamRoleArn = types.StringValue(cspmAccount.IamRoleArn)
	state.IamRoleName = types.StringValue(getRoleNameFromArn(cspmAccount.IamRoleArn))
	state.EventbusName = types.StringValue(cspmAccount.EventbusName)
	state.EventbusArn = types.StringValue(cspmAccount.AwsEventbusArn)
	state.CloudTrailBucketName = types.StringValue(cspmAccount.AwsCloudtrailBucketName)
	state.DspmRoleArn = types.StringValue(cspmAccount.DspmRoleArn)
	state.DspmRoleName = types.StringValue(getRoleNameFromArn(cspmAccount.DspmRoleArn))

	// for each feature options
	// update with data from backend

	state.RealtimeVisibility.Enabled = types.BoolValue(cspmAccount.BehaviorAssessmentEnabled)
	if cspmAccount.AwsCloudtrailRegion != "" {
		state.RealtimeVisibility.CloudTrailRegion = types.StringValue(
			cspmAccount.AwsCloudtrailRegion,
		)
	}

	state.SensorManagement.Enabled = types.BoolValue(*cspmAccount.SensorManagementEnabled)

	state.DSPM.Enabled = types.BoolValue(cspmAccount.DspmEnabled)

	// save current state
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// create Cloud Registration account
	cloudAccount, diags := r.createCloudAccount(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.IDP = &idpOptions{
		Enabled: types.BoolValue(false),
		Status:  types.StringValue("configured"),
	}
	for _, p := range cloudAccount.Products {
		if *p.Product == "idp" {
			state.IDP.Enabled = types.BoolValue(true)
			break
		}
	}

	// if IDP or realtime visibility are enabled wait until we get all values back
	if state.IDP.Enabled.ValueBool() || state.RealtimeVisibility.Enabled.ValueBool() {
		resp.Diagnostics.Append(r.pollMissingValues(ctx, &state)...)
	}

	// Set refreshed state
	diags = resp.State.Set(ctx, state)
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
	if model.OrganizationID.ValueString() != "" {
		diags.Append(model.TargetOUs.ElementsAs(ctx, &targetOUs, false)...)
	}

	createAccount := models.RegistrationAWSAccountExtV2{
		AccountID:        model.AccountID.ValueStringPointer(),
		OrganizationID:   model.OrganizationID.ValueStringPointer(),
		TargetOus:        targetOUs,
		IsMaster:         model.OrganizationID.ValueString() != "",
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
	res, status, err := r.client.CspmRegistration.CreateCSPMAwsAccount(
		&cspm_registration.CreateCSPMAwsAccountParams{
			Context: ctx,
			Body: &models.RegistrationAWSAccountCreateRequestExtV2{
				Resources: []*models.RegistrationAWSAccountExtV2{
					&createAccount,
				},
			},
		},
	)
	if err != nil {
		if _, ok := err.(*cspm_registration.CreateCSPMAwsAccountForbidden); ok {
			diags.AddError(
				"Failed to create CSPM AWS account: 403 Forbidden",
				scopes.GenerateScopeDescription(cloudSecurityScopes),
			)
			return nil, diags
		}
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
		AccountID:          model.AccountID.ValueString(),
		OrganizationID:     model.OrganizationID.ValueString(),
		IsMaster:           model.OrganizationID.ValueString() != "",
		AccountType:        model.AccountType.ValueString(),
		ResourceNamePrefix: model.ResourceNamePrefix.ValueString(),
		ResourceNameSuffix: model.ResourceNameSuffix.ValueString(),
	}
	if model.RealtimeVisibility != nil && model.RealtimeVisibility.Enabled.ValueBool() {
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

	res, status, err := r.client.CloudAwsRegistration.CloudRegistrationAwsCreateAccount(
		&cloud_aws_registration.CloudRegistrationAwsCreateAccountParams{
			Context: ctx,
			Body: &models.RestAWSAccountCreateRequestExtv1{
				Resources: []*models.RestCloudAWSAccountCreateExtV1{
					&createAccount,
				},
			},
		},
	)
	if err != nil {
		if _, ok := err.(*cloud_aws_registration.CloudRegistrationAwsCreateAccountForbidden); ok {
			diags.AddError(
				"Failed to create Cloud Registration AWS account: 403 Forbidden",
				scopes.GenerateScopeDescription(cloudSecurityScopes),
			)
			return nil, diags
		}
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
	isImport, diags := privatestate.IsImportRead(ctx, req, resp)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	cloudAccState := cloudAccState{
		Created: true,
	}

	var state cloudAWSAccountModel
	var oldState cloudAWSAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &oldState)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if oldState.AccountID.ValueString() == "" {
		return
	}

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	cspmAccount, diags := r.getCSPMAccount(ctx, oldState.AccountID.ValueString())
	for _, diagErr := range diags.Errors() {
		if strings.Contains(diagErr.Detail(), "404 Not Found") {
			tflog.Warn(
				ctx,
				fmt.Sprintf("cspm account %s not found, removing from state", state.AccountID),
				map[string]interface{}{"resp": diagErr.Detail()},
			)
			resp.State.RemoveResource(ctx)
			return
		}
	}

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.AccountID = types.StringValue(cspmAccount.AccountID)

	// imports should use the org id from the API since state will be nil.
	if isImport {
		state.OrganizationID = types.StringValue(cspmAccount.OrganizationID)
	} else {
		state.OrganizationID = oldState.OrganizationID
	}

	state.AccountType = types.StringValue(cspmAccount.AccountType)
	state.DeploymentMethod = oldState.DeploymentMethod
	if state.DeploymentMethod.IsNull() {
		state.DeploymentMethod = types.StringValue("terraform-native")
	}

	ous := []string{}
	if cspmAccount.IsMaster && len(cspmAccount.TargetOus) != 0 {
		ous = cspmAccount.TargetOus
	}

	targetOUs, diags := types.ListValueFrom(ctx, types.StringType, ous)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}
	state.TargetOUs = targetOUs

	state.IsOrgManagementAccount = types.BoolValue(cspmAccount.IsMaster)
	state.ExternalID = types.StringValue(cspmAccount.ExternalID)
	state.IntermediateRoleArn = types.StringValue(cspmAccount.IntermediateRoleArn)
	state.IamRoleArn = types.StringValue(cspmAccount.IamRoleArn)
	state.IamRoleName = types.StringValue(getRoleNameFromArn(cspmAccount.IamRoleArn))
	state.EventbusName = types.StringValue(cspmAccount.EventbusName)
	state.EventbusArn = types.StringValue(cspmAccount.AwsEventbusArn)
	state.CloudTrailBucketName = types.StringValue(cspmAccount.AwsCloudtrailBucketName)
	state.DspmRoleArn = types.StringValue(cspmAccount.DspmRoleArn)
	state.DspmRoleName = types.StringValue(getRoleNameFromArn(cspmAccount.DspmRoleArn))

	// for each feature options
	// if old state is nil, we are importing
	// if not, copy old state and then update with data from backend
	if oldState.AssetInventory != nil {
		state.AssetInventory = oldState.AssetInventory
	} else {
		state.AssetInventory = &assetInventoryOptions{
			Enabled: types.BoolValue(true), // asset inventory is always enabled
		}
	}

	if oldState.RealtimeVisibility != nil {
		state.RealtimeVisibility = oldState.RealtimeVisibility
	} else {
		state.RealtimeVisibility = &realtimeVisibilityOptions{
			UseExistingCloudTrail: types.BoolValue(false),
		}
	}
	state.RealtimeVisibility.Enabled = types.BoolValue(cspmAccount.BehaviorAssessmentEnabled)
	if cspmAccount.AwsCloudtrailRegion != "" {
		state.RealtimeVisibility.CloudTrailRegion = types.StringValue(
			cspmAccount.AwsCloudtrailRegion,
		)
	}

	if oldState.SensorManagement != nil {
		state.SensorManagement = oldState.SensorManagement
	} else {
		state.SensorManagement = &sensorManagementOptions{}
	}
	state.SensorManagement.Enabled = types.BoolValue(*cspmAccount.SensorManagementEnabled)

	if oldState.DSPM != nil {
		state.DSPM = oldState.DSPM
	} else {
		state.DSPM = &dspmOptions{}
	}
	state.DSPM.Enabled = types.BoolValue(cspmAccount.DspmEnabled)

	// save current state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	cloudAccount, _, diags := r.getCloudAccount(ctx, oldState.AccountID.ValueString())

	for _, diagErr := range diags.Errors() {
		if strings.Contains(diagErr.Detail(), "404 Not Found") {
			tflog.Warn(
				ctx,
				fmt.Sprintf("cloud account %s not found", state.AccountID),
				map[string]interface{}{"resp": diagErr.Detail()},
			)

			cloudAccState.Created = false
		} else {
			resp.Diagnostics.Append(diagErr)
		}
	}

	if resp.Diagnostics.HasError() {
		return
	}

	if oldState.IDP != nil {
		state.IDP = oldState.IDP
	} else {
		state.IDP = &idpOptions{
			Enabled: types.BoolValue(false),
		}
	}

	if cloudAccState.Created {
		tflog.Info(
			ctx,
			"found cloud registration account",
			map[string]interface{}{"account_id": cloudAccount.AccountID},
		)
		for _, p := range cloudAccount.Products {
			if *p.Product == "idp" {
				state.IDP.Enabled = types.BoolValue(true)
				state.IDP.Status = types.StringValue("configured")
				break
			}
		}
		state.ResourceNamePrefix = types.StringValue(cloudAccount.ResourceNamePrefix)
		state.ResourceNameSuffix = types.StringValue(cloudAccount.ResourceNameSuffix)
	}

	cloudAccPrivateState, err := json.Marshal(cloudAccState)
	if err != nil {
		resp.Diagnostics.AddError("Unable to marshal private account state in read", err.Error())
	}

	resp.Diagnostics.Append(resp.Private.SetKey(ctx, cloudStateKey, cloudAccPrivateState)...)

	// Set refreshed state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cloudAWSAccountResource) getCSPMAccount(
	ctx context.Context,
	accountID string,
) (*models.DomainAWSAccountV2, diag.Diagnostics) {
	var diags diag.Diagnostics
	res, status, err := r.client.CspmRegistration.GetCSPMAwsAccount(
		&cspm_registration.GetCSPMAwsAccountParams{
			Context: ctx,
			Ids:     []string{accountID},
		},
	)
	if err != nil {
		if forbidden, ok := err.(*cspm_registration.GetCSPMAwsAccountForbidden); ok {
			tflog.Info(ctx, "forbidden", map[string]interface{}{"resp": forbidden})
			diags.AddError(
				"Failed to read CSPM AWS account: 403 Forbidden",
				scopes.GenerateScopeDescription(cloudSecurityScopes),
			)
			return nil, diags
		}
		diags.AddError(
			"Failed to read CSPM AWS account",
			fmt.Sprintf("Failed to get CSPM AWS account: %s", err.Error()),
		)
		return nil, diags
	}

	// todo: the backend needs to be updated to properly return 404
	if status != nil {
		diags.AddError(
			"Failed to read CSPM AWS account",
			fmt.Sprintf("Failed to get CSPM AWS account: 404 Not Found %s", status.Error()),
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
	res, status, err := r.client.CloudAwsRegistration.CloudRegistrationAwsGetAccounts(
		&cloud_aws_registration.CloudRegistrationAwsGetAccountsParams{
			Context: ctx,
			Ids:     []string{accountID},
		},
	)
	if err != nil {
		if _, ok := err.(*cloud_aws_registration.CloudRegistrationAwsGetAccountsForbidden); ok {
			diags.AddError(
				"Failed to read Cloud Registration AWS account: 403 Forbidden",
				scopes.GenerateScopeDescription(cloudSecurityScopes),
			)
			return nil, false, diags
		}
		diags.AddError(
			"Failed to read Cloud Registration AWS account",
			fmt.Sprintf("Failed to read Cloud Registration AWS account: %s", err.Error()),
		)
		return nil, false, diags
	}
	if status != nil {
		diags.AddError(
			"Failed to read Cloud Registration AWS account",
			fmt.Sprintf(
				"Failed to read Cloud Registration AWS account: 404 Not Found %s",
				status.Error(),
			),
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
	accPrivateState, diags := req.Private.GetKey(ctx, cloudStateKey)
	resp.Diagnostics.Append(diags...)
	var cloudAccState cloudAccState
	err := json.Unmarshal(accPrivateState, &cloudAccState)
	if err != nil {
		resp.Diagnostics.AddError(
			"Internal provider error",
			"Failed to unmarshal private account state: "+err.Error(),
		)
	}

	// Retrieve values from plan
	var plan cloudAWSAccountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Retrieve values from state
	var state cloudAWSAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cspmAccount, diags := r.updateCSPMAccount(ctx, plan)

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.AccountID = types.StringValue(cspmAccount.AccountID)
	plan.OrganizationID = state.OrganizationID
	plan.AccountType = types.StringValue(cspmAccount.AccountType)
	plan.DeploymentMethod = state.DeploymentMethod
	if state.DeploymentMethod.IsNull() {
		plan.DeploymentMethod = types.StringValue("terraform-native")
	}
	plan.TargetOUs = state.TargetOUs
	if cspmAccount.IsMaster && len(cspmAccount.TargetOus) != 0 {
		targetOUs, diags := types.ListValueFrom(ctx, types.StringType, cspmAccount.TargetOus)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
		}
		plan.TargetOUs = targetOUs
	}
	plan.IsOrgManagementAccount = types.BoolValue(cspmAccount.IsMaster)
	plan.ExternalID = types.StringValue(cspmAccount.ExternalID)
	plan.IntermediateRoleArn = types.StringValue(cspmAccount.IntermediateRoleArn)
	plan.IamRoleArn = types.StringValue(cspmAccount.IamRoleArn)
	plan.IamRoleName = types.StringValue(getRoleNameFromArn(cspmAccount.IamRoleArn))
	plan.EventbusName = types.StringValue(cspmAccount.EventbusName)
	plan.EventbusArn = types.StringValue(cspmAccount.AwsEventbusArn)
	plan.CloudTrailBucketName = types.StringValue(cspmAccount.AwsCloudtrailBucketName)
	plan.DspmRoleArn = types.StringValue(cspmAccount.DspmRoleArn)
	plan.DspmRoleName = types.StringValue(getRoleNameFromArn(cspmAccount.DspmRoleArn))

	plan.RealtimeVisibility.Enabled = types.BoolValue(cspmAccount.BehaviorAssessmentEnabled)
	if cspmAccount.AwsCloudtrailRegion != "" {
		plan.RealtimeVisibility.CloudTrailRegion = types.StringValue(
			cspmAccount.AwsCloudtrailRegion,
		)
	}

	plan.SensorManagement.Enabled = types.BoolValue(*cspmAccount.SensorManagementEnabled)

	plan.DSPM.Enabled = types.BoolValue(cspmAccount.DspmEnabled)

	// save current state
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var cloudAccount *models.DomainCloudAWSAccountV1
	if cloudAccState.Created {
		cloudAccount, diags = r.updateCloudAccount(ctx, plan)
	} else {
		cloudAccount, diags = r.createCloudAccount(ctx, plan)
	}

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.IDP = &idpOptions{
		Enabled: types.BoolValue(false),
		Status:  types.StringValue("configured"),
	}
	for _, p := range cloudAccount.Products {
		if *p.Product == "idp" {
			plan.IDP.Enabled = types.BoolValue(true)
			break
		}
	}

	// Set refreshed state
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
		patchAccount.BehaviorAssessmentEnabled = model.RealtimeVisibility.Enabled.ValueBoolPointer()
		patchAccount.CloudtrailRegion = model.RealtimeVisibility.CloudTrailRegion.ValueString()
	}
	if model.SensorManagement != nil {
		patchAccount.SensorManagementEnabled = model.SensorManagement.Enabled.ValueBoolPointer()
	}
	if model.DSPM != nil {
		patchAccount.DspmEnabled = model.DSPM.Enabled.ValueBoolPointer()
		patchAccount.DspmRole = model.DSPM.RoleName.ValueString()
	}
	res, status, err := r.client.CspmRegistration.PatchCSPMAwsAccount(
		&cspm_registration.PatchCSPMAwsAccountParams{
			Context: ctx,
			Body: &models.RegistrationAWSAccountPatchRequest{
				Resources: []*models.RegistrationAWSAccountPatch{
					&patchAccount,
				},
			},
		},
	)

	if err != nil {
		if _, ok := err.(*cspm_registration.PatchCSPMAwsAccountForbidden); ok {
			diags.AddError(
				"Failed to update CSPM AWS account: 403 Forbidden",
				scopes.GenerateScopeDescription(cloudSecurityScopes),
			)
			return nil, diags
		}
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
		AccountID:          model.AccountID.ValueString(),
		OrganizationID:     model.OrganizationID.ValueString(),
		IsMaster:           model.OrganizationID.ValueString() != "",
		AccountType:        model.AccountType.ValueString(),
		ResourceNamePrefix: model.ResourceNamePrefix.ValueString(),
		ResourceNameSuffix: model.ResourceNameSuffix.ValueString(),
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
	res, status, err := r.client.CloudAwsRegistration.CloudRegistrationAwsUpdateAccount(
		&cloud_aws_registration.CloudRegistrationAwsUpdateAccountParams{
			Context: ctx,
			Body: &models.RestAWSAccountCreateRequestExtv1{
				Resources: []*models.RestCloudAWSAccountCreateExtV1{
					&patchAccount,
				},
			},
		},
	)

	if err != nil {
		if _, ok := err.(*cloud_aws_registration.CloudRegistrationAwsUpdateAccountForbidden); ok {
			diags.AddError(
				"Failed to update Cloud Registration AWS account: 403 Forbidden",
				scopes.GenerateScopeDescription(cloudSecurityScopes),
			)
			return nil, diags
		}
		diags.AddError(
			"Failed to update Cloud Registration AWS account",
			fmt.Sprintf("Failed to update Cloud Registration AWS account: %s", err.Error()),
		)
		return nil, diags
	}
	if status != nil {
		diags.AddError(
			"Failed to update Cloud Registration AWS account",
			fmt.Sprintf("Failed to update Cloud Registration AWS account: %s", status.Error()),
		)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Failed to update Cloud Registration AWS account",
			"No error returned from api but Cloud Registration account was not returned. Please report this issue to the provider developers.",
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

	if state.IDP.Status.ValueString() != "" {
		diags = append(diags, r.deleteCloudAccount(ctx, state)...)
	}
	diags = append(diags, r.deleteCSPMAccount(ctx, state)...)

	resp.Diagnostics.Append(diags...)
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
		if _, ok := err.(*cspm_registration.DeleteCSPMAwsAccountForbidden); ok {
			diags.AddError(
				"Failed to delete CSPM AWS account: 403 Forbidden",
				scopes.GenerateScopeDescription(cloudSecurityScopes),
			)
			return diags
		}
		diags.AddError(
			"Failed to delete CSPM AWS account",
			fmt.Sprintf("Failed to delete CSPM AWS account: %s", err.Error()),
		)
		return diags
	}
	if status != nil {
		// treating this as a 404 not found which is not an error when deleting
		// diags.AddError(
		// 	"Failed to delete CSPM AWS account",
		// 	fmt.Sprintf("Failed to delete CSPM AWS account: %s", status.Error()),
		// )
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
		if _, ok := err.(*cloud_aws_registration.CloudRegistrationAwsDeleteAccountForbidden); ok {
			diags.AddError(
				"Failed to delete Cloud Registration AWS account: 403 Forbidden",
				scopes.GenerateScopeDescription(cloudSecurityScopes),
			)
			return diags
		}
		diags.AddError(
			"Failed to delete Cloud Registration AWS account",
			fmt.Sprintf("Failed to delete Cloud Registration AWS account: %s", err.Error()),
		)
		return diags
	}
	if status != nil {
		// treating this as a 404 not found which is not an error when deleting
		// diags.AddError(
		// 	"Failed to delete Cloud Registration AWS account",
		// 	fmt.Sprintf("Failed to delete Cloud Registration AWS account: %s", status.Error()),
		// )
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
	resp.Diagnostics.Append(privatestate.MarkPrivateStateForImport(ctx, resp)...)
	if resp.Diagnostics.HasError() {
		return
	}
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

// pollMissingValues waits for missing backend values [eventbus_arn, eventbus_name, cloudtrail_bucket_name] to be set.
func (r *cloudAWSAccountResource) pollMissingValues(
	ctx context.Context,
	config *cloudAWSAccountModel,
) diag.Diagnostics {
	var diags diag.Diagnostics
	missingValues := make(map[string]interface{})

	if config.EventbusArn.ValueString() == "" {
		missingValues["eventbus_arn"] = nil
	}

	if config.EventbusName.ValueString() == "" {
		missingValues["eventbus_name"] = nil
	}

	if config.CloudTrailBucketName.ValueString() == "" {
		missingValues["cloudtrail_bucket_name"] = nil
	}

	if len(missingValues) == 0 {
		return diags
	}

	pollCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			account, diag := r.getCSPMAccount(pollCtx, config.AccountID.ValueString())
			if diag.HasError() {
				return diag
			}

			if _, ok := missingValues["eventbus_arn"]; ok && account.AwsEventbusArn != "" {
				config.EventbusArn = types.StringValue(account.AwsEventbusArn)
				delete(missingValues, "eventbus_arn")
			}

			if _, ok := missingValues["eventbus_name"]; ok && account.EventbusName != "" {
				config.EventbusName = types.StringValue(account.EventbusName)
				delete(missingValues, "eventbus_name")
			}

			if _, ok := missingValues["cloudtrail_bucket_name"]; ok &&
				account.AwsCloudtrailBucketName != "" {
				config.CloudTrailBucketName = types.StringValue(account.AwsCloudtrailBucketName)
				delete(missingValues, "cloudtrail_bucket_name")
			}

			if len(missingValues) == 0 {
				return diags
			}

			fields := strings.Join(maps.Keys(missingValues), ", ")
			tflog.Debug(
				pollCtx,
				fmt.Sprintf("[%s] not yet available, polling again in 10s...", fields),
			)

		case <-pollCtx.Done():
			if pollCtx.Err() != context.DeadlineExceeded {
				return diags
			}

			if len(missingValues) == 0 {
				return diags
			}

			fields := strings.Join(maps.Keys(missingValues), ", ")
			diags.AddError(
				"Timed out waiting for missing fields to populate",
				fmt.Sprintf(
					"Timed out on create waiting for missing fields [%s] to return from API.",
					fields,
				),
			)
			return diags
		}
	}
}
