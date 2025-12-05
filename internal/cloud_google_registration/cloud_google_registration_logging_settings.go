package cloudgoogleregistration

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_google_cloud_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &cloudGoogleRegistrationLoggingSettingsResource{}
	_ resource.ResourceWithConfigure      = &cloudGoogleRegistrationLoggingSettingsResource{}
	_ resource.ResourceWithImportState    = &cloudGoogleRegistrationLoggingSettingsResource{}
	_ resource.ResourceWithValidateConfig = &cloudGoogleRegistrationLoggingSettingsResource{}
)

func NewCloudGoogleRegistrationLoggingSettingsResource() resource.Resource {
	return &cloudGoogleRegistrationLoggingSettingsResource{}
}

type cloudGoogleRegistrationLoggingSettingsResource struct {
	client *client.CrowdStrikeAPISpecification
}

func (r *cloudGoogleRegistrationLoggingSettingsResource) Configure(
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

func (r *cloudGoogleRegistrationLoggingSettingsResource) Metadata(
	ctx context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_google_registration_logging_settings"
}

type cloudGoogleRegistrationLoggingSettingsModel struct {
	RegistrationID               types.String `tfsdk:"registration_id"`
	LogIngestionSinkName         types.String `tfsdk:"log_ingestion_sink_name"`
	LogIngestionTopicID          types.String `tfsdk:"log_ingestion_topic_id"`
	LogIngestionSubscriptionName types.String `tfsdk:"log_ingestion_subscription_name"`
	WifProjectID                 types.String `tfsdk:"wif_project"`
	WifProjectNumber             types.String `tfsdk:"wif_project_number"`
}

func (r *cloudGoogleRegistrationLoggingSettingsResource) Schema(
	ctx context.Context,
	req resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Falcon Cloud Security",
			"This resource manages the log ingestion settings for a Google Cloud project registration in Falcon Cloud Security.",
			gcpRegistrationScopes,
		),
		Attributes: map[string]schema.Attribute{
			"registration_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The Google Cloud registration ID to configure log ingestion settings for.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"log_ingestion_sink_name": schema.StringAttribute{
				Optional:    true,
				Description: "The name of the log sink for ingestion.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"log_ingestion_topic_id": schema.StringAttribute{
				Optional:    true,
				Description: "The Pub/Sub topic ID for log ingestion.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"log_ingestion_subscription_name": schema.StringAttribute{
				Optional:    true,
				Description: "The Pub/Sub subscription name for log ingestion.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"wif_project": schema.StringAttribute{
				Required:    true,
				Description: "The Google Cloud project ID for Workload Identity Federation.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"wif_project_number": schema.StringAttribute{
				Required:    true,
				Description: "The Google Cloud project number for Workload Identity Federation.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
		},
	}
}

func (m *cloudGoogleRegistrationLoggingSettingsModel) wrap(
	registration *models.DtoGCPRegistration,
) {
	m.RegistrationID = types.StringValue(registration.RegistrationID)

	var sinkName, topicID, subscriptionID string
	if registration.LogIngestionProperties != nil {
		sinkName = registration.LogIngestionProperties.SinkName
		topicID = registration.LogIngestionProperties.TopicID
		subscriptionID = registration.LogIngestionProperties.SubscriptionID
	}
	m.LogIngestionSinkName = flex.StringValueToFramework(sinkName)
	m.LogIngestionTopicID = flex.StringValueToFramework(topicID)
	m.LogIngestionSubscriptionName = flex.StringValueToFramework(subscriptionID)

	var wifProjectID, wifProjectNumber string
	if registration.WifProperties != nil {
		wifProjectID = registration.WifProperties.ProjectID
		wifProjectNumber = registration.WifProperties.ProjectNumber
	}
	m.WifProjectID = types.StringValue(wifProjectID)
	m.WifProjectNumber = types.StringValue(wifProjectNumber)
}

func (r *cloudGoogleRegistrationLoggingSettingsResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var data cloudGoogleRegistrationLoggingSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	registration, diags := r.updateRegistration(ctx, &data)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	if !r.isIOAEnabled(registration) {
		resp.Diagnostics.AddError(
			"IOA Not Enabled",
			fmt.Sprintf(
				"Log ingestion settings cannot be configured because IOA (Indicator of Attack) is not enabled for registration %s. Enable realtime_visibility with IOA in the cloud_google_registration resource first.",
				data.RegistrationID.ValueString(),
			),
		)
		return
	}

	diags = r.triggerHealthCheck(ctx, data.RegistrationID.ValueString())
	resp.Diagnostics.Append(diags...)

	data.wrap(registration)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudGoogleRegistrationLoggingSettingsResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var data cloudGoogleRegistrationLoggingSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	registration, diags := r.getRegistration(ctx, data.RegistrationID.ValueString())
	if tferrors.HasNotFoundError(diags) {
		tflog.Warn(
			ctx,
			fmt.Sprintf(
				"registration %s not found, removing from state",
				data.RegistrationID.ValueString(),
			),
		)

		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.wrap(registration)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudGoogleRegistrationLoggingSettingsResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var data cloudGoogleRegistrationLoggingSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	registration, diags := r.updateRegistration(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.isIOAEnabled(registration) {
		resp.Diagnostics.AddError(
			"IOA Not Enabled",
			fmt.Sprintf(
				"Log ingestion settings cannot be configured because IOA (Indicator of Attack) is not enabled for registration %s. Enable realtime_visibility with IOA in the cloud_google_registration resource first.",
				data.RegistrationID.ValueString(),
			),
		)
		return
	}

	diags = r.triggerHealthCheck(ctx, data.RegistrationID.ValueString())
	resp.Diagnostics.Append(diags...)

	data.wrap(registration)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudGoogleRegistrationLoggingSettingsResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var data cloudGoogleRegistrationLoggingSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.LogIngestionSinkName = types.StringValue("")
	data.LogIngestionTopicID = types.StringValue("")
	data.LogIngestionSubscriptionName = types.StringValue("")
	data.WifProjectID = types.StringValue("")
	data.WifProjectNumber = types.StringValue("")

	registration, err := r.updateRegistration(ctx, &data)
	resp.Diagnostics.Append(err...)

	if tferrors.HasNotFoundError(resp.Diagnostics) {
		return
	}

	if resp.Diagnostics.HasError() {
		return
	}

	data.wrap(registration)

	if registration.LogIngestionProperties != nil && (registration.LogIngestionProperties.SinkName != "" ||
		registration.LogIngestionProperties.TopicID != "" ||
		registration.LogIngestionProperties.SubscriptionID != "") {
		resp.Diagnostics.AddAttributeError(
			path.Root("log_ingestion_sink_name"),
			"Delete failed.",
			"Log ingestion settings were returned after the attempt to remove them. This is a bug in the provider. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues"+registration.LogIngestionProperties.SinkName+registration.LogIngestionProperties.TopicID+registration.LogIngestionProperties.SubscriptionID,
		)
	}
}

func (r *cloudGoogleRegistrationLoggingSettingsResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("registration_id"), req, resp)
}

func (r *cloudGoogleRegistrationLoggingSettingsResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config cloudGoogleRegistrationLoggingSettingsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *cloudGoogleRegistrationLoggingSettingsResource) isIOAEnabled(
	registration *models.DtoGCPRegistration,
) bool {
	if registration == nil {
		return false
	}

	for _, product := range registration.Products {
		if product.Product != nil && *product.Product == "cspm" {
			for _, feature := range product.Features {
				if feature == "ioa" {
					return true
				}
			}
		}
	}

	return false
}

func (r *cloudGoogleRegistrationLoggingSettingsResource) getRegistration(
	ctx context.Context,
	registrationID string,
) (*models.DtoGCPRegistration, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := cloud_google_cloud_registration.NewCloudRegistrationGcpGetRegistrationParams()
	params.SetContext(ctx)
	params.SetIds(registrationID)

	res, err := r.client.CloudGoogleCloudRegistration.CloudRegistrationGcpGetRegistration(params)
	if err != nil {
		if _, ok := err.(*cloud_google_cloud_registration.CloudRegistrationGcpGetRegistrationNotFound); ok {
			diags.Append(tferrors.NewNotFoundError(
				fmt.Sprintf("No registration found for registration ID: %s.", registrationID),
			))
			return nil, diags
		}

		if _, ok := err.(*cloud_google_cloud_registration.CloudRegistrationGcpGetRegistrationForbidden); ok {
			diags.Append(tferrors.NewForbiddenError(tferrors.Read, gcpRegistrationScopes))
			return nil, diags
		}

		diags.Append(tferrors.NewOperationError(tferrors.Read, err))
		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))

		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func (r *cloudGoogleRegistrationLoggingSettingsResource) updateRegistration(
	ctx context.Context,
	data *cloudGoogleRegistrationLoggingSettingsModel,
) (*models.DtoGCPRegistration, diag.Diagnostics) {
	var diags diag.Diagnostics

	deploymentMethod := "terraform-native"
	updateReq := &models.DtoUpdateGCPRegistrationRequest{
		DeploymentMethod:             &deploymentMethod,
		LogIngestionSinkName:         flex.FrameworkToStringPointer(data.LogIngestionSinkName),
		LogIngestionTopicID:          flex.FrameworkToStringPointer(data.LogIngestionTopicID),
		LogIngestionSubscriptionName: flex.FrameworkToStringPointer(data.LogIngestionSubscriptionName),
		WifProjectID:                 data.WifProjectID.ValueString(),
		WifProjectNumber:             data.WifProjectNumber.ValueString(),
	}

	params := &cloud_google_cloud_registration.CloudRegistrationGcpUpdateRegistrationParams{
		Context: ctx,
		Ids:     data.RegistrationID.ValueString(),
		Body: &models.DtoGCPRegistrationUpdateRequestExtV1{
			Resources: []*models.DtoUpdateGCPRegistrationRequest{updateReq},
		},
	}

	res, err := r.client.CloudGoogleCloudRegistration.CloudRegistrationGcpUpdateRegistration(params)
	if err != nil {
		if _, ok := err.(*cloud_google_cloud_registration.CloudRegistrationGcpUpdateRegistrationNotFound); ok {
			diags.Append(tferrors.NewNotFoundError(
				fmt.Sprintf(
					"No registration found for registration ID: %s.",
					data.RegistrationID.ValueString(),
				),
			))
			return nil, diags
		}

		if _, ok := err.(*cloud_google_cloud_registration.CloudRegistrationGcpUpdateRegistrationForbidden); ok {
			diags.Append(tferrors.NewForbiddenError(tferrors.Update, gcpRegistrationScopes))
			return nil, diags
		}

		diags.Append(tferrors.NewOperationError(tferrors.Update, err))
		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))

		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func (r *cloudGoogleRegistrationLoggingSettingsResource) triggerHealthCheck(
	ctx context.Context,
	registrationID string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	params := cloud_google_cloud_registration.CloudRegistrationGcpTriggerHealthCheckParams{
		Ids:     []string{registrationID},
		Context: ctx,
	}

	_, err := r.client.CloudGoogleCloudRegistration.CloudRegistrationGcpTriggerHealthCheck(&params)
	if err != nil {
		diags.AddWarning(
			"Failed to trigger health check scan.",
			fmt.Sprintf("Failed to trigger health check scan for Google Cloud registration: %s", falcon.ErrorExplain(err)),
		)
	}

	return diags
}
