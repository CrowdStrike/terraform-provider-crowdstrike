package fcs

import (
	"context"
	"fmt"
	"regexp"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cspm_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type cspmAWSAccountResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cspmAWSAccountModel struct {
	AccountID                types.String `tfsdk:"account_id"`
	OrganizationID           types.String `tfsdk:"organization_id"`
	EnableRealtimeVisibility types.Bool   `tfsdk:"enable_realtime_visibility"`
	EnableSensorManagement   types.Bool   `tfsdk:"enable_sensor_management"`
	EnableDSPM               types.Bool   `tfsdk:"enable_dspm"`
	ExternalID               types.String `tfsdk:"external_id"`
	IntermediateRoleArn      types.String `tfsdk:"intermediate_role_arn"`
	IamRoleArn               types.String `tfsdk:"iam_role_arn"`
}

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &cspmAWSAccountResource{}
	_ resource.ResourceWithConfigure      = &cspmAWSAccountResource{}
	_ resource.ResourceWithImportState    = &cspmAWSAccountResource{}
	_ resource.ResourceWithValidateConfig = &cspmAWSAccountResource{}
)

// NewFIMPolicyResource is a helper function to simplify the provider implementation.
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
					// stringplanmodifier.RequiresReplace(),
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
					// stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(12, 34),
					stringvalidator.RegexMatches(regexp.MustCompile(`^o-[a-z0-9]{10,32}$`), "must be in the format of o-xxxxxxxxxx"),
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
	plan.EnableRealtimeVisibility = types.BoolValue(account.BehaviorAssessmentEnabled)
	plan.EnableSensorManagement = types.BoolValue(*account.SensorManagementEnabled)
	plan.EnableDSPM = types.BoolValue(account.DspmEnabled)
	plan.ExternalID = types.StringValue(account.ExternalID)
	plan.IntermediateRoleArn = types.StringValue(account.IntermediateRoleArn)
	plan.IamRoleArn = types.StringValue(account.IamRoleArn)

	//todo: add other fields

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
	if account != nil {
		state.AccountID = types.StringValue(account.AccountID)
		state.OrganizationID = types.StringValue(account.OrganizationID)
		//todo: add other fields
		state.EnableRealtimeVisibility = types.BoolValue(account.BehaviorAssessmentEnabled)
		state.EnableSensorManagement = types.BoolValue(*account.SensorManagementEnabled)
		state.EnableDSPM = types.BoolValue(account.DspmEnabled)
		state.ExternalID = types.StringValue(account.ExternalID)
		state.IntermediateRoleArn = types.StringValue(account.IntermediateRoleArn)
		state.IamRoleArn = types.StringValue(account.IamRoleArn)
	}

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
	var plan cspmAWSAccountModel
	diags := req.Plan.Get(ctx, &plan)
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
	// todo: add other fields

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

	// for i, exclusion := range config.ScheduledExclusions {
	// 	repeated := exclusion.Repeated
	// 	attrPath := path.Root("scheduled_exclusions").AtListIndex(i)
	//
	// 	_, err := time.LoadLocation(exclusion.Timezone.ValueString())
	// 	if err != nil {
	// 		resp.Diagnostics.AddAttributeError(
	// 			attrPath,
	// 			"Invalid timezone in scheduled exclusion",
	// 			"Invalid timezone see https://en.wikipedia.org/wiki/List_of_tz_database_time_zones for valid timezones.",
	// 		)
	// 	}
	//
	// 	resp.Diagnostics.Append(
	// 		valideDate(attrPath, exclusion.StartDate.ValueString())...)
	// 	resp.Diagnostics.Append(
	// 		valideDate(attrPath, exclusion.EndDate.ValueString())...)
	// 	resp.Diagnostics.Append(
	// 		valideTime(attrPath, exclusion.StartTime.ValueString())...)
	// 	resp.Diagnostics.Append(
	// 		valideTime(attrPath, exclusion.EndTime.ValueString())...)
	//
	// 	// validate repeated
	// 	if repeated == nil {
	// 		continue
	// 	}
	//
	// 	resp.Diagnostics.Append(
	// 		valideTime(attrPath, repeated.StartTime.ValueString())...)
	// 	resp.Diagnostics.Append(
	// 		valideTime(attrPath, repeated.EndTime.ValueString())...)
	//
	// 	summaryMsg := "Invalid repeated attribute on scheduled exclusion"
	//
	// 	if !repeated.AllDay.ValueBool() && repeated.StartTime.ValueString() == "" {
	// 		resp.Diagnostics.AddAttributeError(
	// 			attrPath,
	// 			summaryMsg,
	// 			"start_time is required if all_day is false",
	// 		)
	// 	}
	// 	if !repeated.AllDay.ValueBool() && repeated.EndTime.ValueString() == "" {
	// 		resp.Diagnostics.AddAttributeError(
	// 			attrPath,
	// 			summaryMsg,
	// 			"end_time is required in repeated if all_day is false",
	// 		)
	// 	}
	//
	// 	// required attributes for when frequency is weekly
	// 	if repeated.Frequency.ValueString() == "weekly" &&
	// 		len(repeated.DaysOfWeek.Elements()) == 0 {
	// 		resp.Diagnostics.AddAttributeError(
	// 			attrPath,
	// 			summaryMsg,
	// 			"days_of_week is required in repeated if frequency is weekly",
	// 		)
	// 	}
	//
	// 	// required attributes for when frequency is monthly
	// 	if repeated.Frequency.ValueString() == "monthly" {
	// 		switch repeated.MonthlyOccurrence.ValueString() {
	// 		case "":
	// 			resp.Diagnostics.AddAttributeError(
	// 				attrPath,
	// 				summaryMsg,
	// 				"monthly_occurrence is required in repeated if frequency is monthly",
	// 			)
	// 		case "Days":
	// 			if len(repeated.DaysOfMonth.Elements()) == 0 {
	// 				resp.Diagnostics.AddAttributeError(
	// 					attrPath,
	// 					summaryMsg,
	// 					"days_of_month is required in repeated if frequency is monthly and monthly_occurrence is days",
	// 				)
	// 			}
	// 		case "1st", "2nd", "3rd", "4th", "Last":
	// 			if len(repeated.DaysOfWeek.Elements()) == 0 {
	// 				resp.Diagnostics.AddAttributeError(
	// 					attrPath,
	// 					summaryMsg,
	// 					"days_of_week is required in repeated if frequency is monthly and monthly_occurrence is set to a week",
	// 				)
	// 			}
	// 		}
	// 	}
	// }
}

// createAccount creates a new CSPM AWS account from the resource model.
func (r *cspmAWSAccountResource) createAccount(
	ctx context.Context,
	config cspmAWSAccountModel,
) (*models.DomainAWSAccountV2, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "creating cspm aws account", map[string]interface{}{
		"account_id":                  config.AccountID.ValueString(),
		"organization_id":             config.OrganizationID.ValueString(),
		"behavior_assessment_enabled": config.EnableRealtimeVisibility.ValueBool(),
	})

	res, status, err := r.client.CspmRegistration.CreateCSPMAwsAccount(&cspm_registration.CreateCSPMAwsAccountParams{
		Context: ctx,
		Body: &models.RegistrationAWSAccountCreateRequestExtV2{
			Resources: []*models.RegistrationAWSAccountExtV2{
				{
					AccountID:                 config.AccountID.ValueStringPointer(),
					OrganizationID:            config.OrganizationID.ValueStringPointer(),
					BehaviorAssessmentEnabled: config.EnableRealtimeVisibility.ValueBool(),
					SensorManagementEnabled:   config.EnableSensorManagement.ValueBool(),
					DspmEnabled:               config.EnableDSPM.ValueBool(),
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
	r.client.CspmRegistration.PatchCSPMAwsAccount(&cspm_registration.PatchCSPMAwsAccountParams{
		// res, status, err := r.client.CspmRegistration.PatchCSPMAwsAccount(&cspm_registration.PatchCSPMAwsAccountParams{
		Context: ctx,
		Body: &models.RegistrationAWSAccountPatchRequest{
			Resources: []*models.RegistrationAWSAccountPatch{
				{
					AccountID: account.AccountID.ValueStringPointer(),
				},
			},
		},
	})

	// TODO: remove this when gofalcon is fixed and revert to previous code
	return &models.DomainAWSAccountV2{
		AccountID:      account.AccountID.ValueString(),
		OrganizationID: account.OrganizationID.ValueString(),
	}, diags

	// if err != nil {
	// 	diags.AddError(
	// 		"Failed to update CSPM AWS account",
	// 		fmt.Sprintf("Failed to update CSPM AWS account: %s", err.Error()),
	// 	)
	// 	return nil, diags
	// }
	// if status != nil {
	// 	diags.AddError(
	// 		"Failed to update CSPM AWS account",
	// 		fmt.Sprintf("Failed to update CSPM AWS account: %s", status.Error()),
	// 	)
	// 	return nil, diags
	// }

	// if len(res.Payload.Resources) == 0 {
	// 	diags.AddError(
	// 		"Failed to update CSPM AWS account",
	// 		"No error returned from api but CSPM account was not returned. Please report this issue to the provider developers.",
	// 	)
	// 	return nil, diags
	// }
	// return res.Payload.Resources[0], diags
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

	_, status, err := r.client.CspmRegistration.DeleteCSPMAwsAccount(&cspm_registration.DeleteCSPMAwsAccountParams{
		Context:         ctx,
		Ids:             []string{account.AccountID.ValueString()},
		OrganizationIds: []string{account.OrganizationID.ValueString()},
	})
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
