package fcs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_azure_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
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
	_ resource.Resource                   = &cloudAzureTenantEventhubSettingsResource{}
	_ resource.ResourceWithConfigure      = &cloudAzureTenantEventhubSettingsResource{}
	_ resource.ResourceWithImportState    = &cloudAzureTenantEventhubSettingsResource{}
	_ resource.ResourceWithValidateConfig = &cloudAzureTenantEventhubSettingsResource{}
)

func NewCloudAzureTenantEventhubSettingsResource() resource.Resource {
	return &cloudAzureTenantEventhubSettingsResource{}
}

type cloudAzureTenantEventhubSettingsResource struct {
	client *client.CrowdStrikeAPISpecification
}

// Configure adds the provider configured client to the resource.
func (r *cloudAzureTenantEventhubSettingsResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(config.ProviderConfig)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)

		return
	}

	r.client = config.Client
}

func (r *cloudAzureTenantEventhubSettingsResource) Metadata(
	ctx context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_azure_tenant_eventhub_settings"
}

type cloudAzureTenantEventhubSettingsModel struct {
	TenantId types.String `tfsdk:"tenant_id"`
	Settings types.List   `tfsdk:"settings"`
}

type eventhubSettings struct {
	Id            types.String `tfsdk:"id"`
	Type          types.String `tfsdk:"type"`
	ConsumerGroup types.String `tfsdk:"consumer_group"`
}

func (f eventhubSettings) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":             types.StringType,
		"type":           types.StringType,
		"consumer_group": types.StringType,
	}
}

func (r *cloudAzureTenantEventhubSettingsResource) Schema(
	ctx context.Context,
	req resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Falcon Cloud Security --- This resource manages the eventhub settings on an Azure Tenant in Falcon Cloud Security.\n\n%s",
			scopes.GenerateScopeDescription(azureRegistrationScopes),
		),
		Attributes: map[string]schema.Attribute{
			"tenant_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The Azure Tenant ID to attach the eventhub settings to.",
			},
			"settings": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Eventhub settings for an Azure tenant registration.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Required:    true,
							Description: "The Azure eventhub ID.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"type": schema.StringAttribute{
							Required:    true,
							Description: "The type of eventhub.",
							Validators: []validator.String{
								stringvalidator.OneOfCaseInsensitive("activity_logs", "entra_logs"),
							},
						},
						"consumer_group": schema.StringAttribute{
							Required:    true,
							Description: "The Azure Event Hub consumer group name used to read events from the Event Hub.",
						},
					},
				},
			},
		},
	}
}

// wrap transforms Go values to their terraform wrapped values.
func (m *cloudAzureTenantEventhubSettingsModel) wrap(
	ctx context.Context,
	registration models.AzureTenantRegistration,
) diag.Diagnostics {
	var diags diag.Diagnostics

	eventhubSettingsSlice := make([]*eventhubSettings, 0, len(registration.EventHubSettings))
	for _, setting := range registration.EventHubSettings {
		eventhubSettingsSlice = append(eventhubSettingsSlice, &eventhubSettings{
			ConsumerGroup: types.StringPointerValue(setting.ConsumerGroup),
			Id:            types.StringPointerValue(setting.EventHubID),
			Type:          types.StringPointerValue(setting.Purpose),
		})
	}

	eventhubSettingsList := utils.SliceToListTypeObject(
		ctx,
		eventhubSettingsSlice,
		eventhubSettings{}.attrTypes(),
		&diags,
	)
	if m.Settings.IsNull() && len(eventhubSettingsList.Elements()) == 0 {
		eventhubSettingsList = types.ListNull(
			types.ObjectType{AttrTypes: eventhubSettings{}.attrTypes()},
		)
	}

	m.TenantId = types.StringValue(*registration.TenantID)
	m.Settings = eventhubSettingsList

	return diags
}

func (r *cloudAzureTenantEventhubSettingsResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var data cloudAzureTenantEventhubSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	registration, diags := r.updateRegistration(ctx, &data)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	diags = r.validateRegistrationAndTriggerHealthCheck(ctx, data.TenantId.ValueString())
	resp.Diagnostics.Append(diags...)

	resp.Diagnostics.Append(data.wrap(ctx, *registration)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudAzureTenantEventhubSettingsResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var data cloudAzureTenantEventhubSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	registration, diags := r.getRegistration(ctx, data.TenantId.ValueString())
	for _, err := range diags.Errors() {
		if err.Summary() == notFoundErrorSummary {
			tflog.Warn(
				ctx,
				fmt.Sprintf(
					"registration for tenant %s not found, removing from state",
					data.TenantId.ValueString(),
				),
			)

			resp.State.RemoveResource(ctx)
			return
		}
	}
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(data.wrap(ctx, *registration)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudAzureTenantEventhubSettingsResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var data cloudAzureTenantEventhubSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	registration, err := r.updateRegistration(ctx, &data)
	resp.Diagnostics.Append(err...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags := r.validateRegistrationAndTriggerHealthCheck(ctx, data.TenantId.ValueString())
	resp.Diagnostics.Append(diags...)

	resp.Diagnostics.Append(data.wrap(ctx, *registration)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudAzureTenantEventhubSettingsResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var data cloudAzureTenantEventhubSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.Settings = types.ListNull(types.ObjectType{AttrTypes: eventhubSettings{}.attrTypes()})
	registration, err := r.updateRegistration(ctx, &data)
	resp.Diagnostics.Append(err...)

	for _, err := range resp.Diagnostics.Errors() {
		if err.Summary() == notFoundErrorSummary {
			return
		}
	}

	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(data.wrap(ctx, *registration)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !data.Settings.IsNull() {
		resp.Diagnostics.AddAttributeError(
			path.Root("settings"),
			"Delete failed.",
			"A value for event_hub_settings was returned after the attempt to remove it. This is a bug in the provider. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
		)
	}
}

func (r *cloudAzureTenantEventhubSettingsResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("tenant_id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *cloudAzureTenantEventhubSettingsResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config cloudAzureTenantEventhubSettingsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *cloudAzureTenantEventhubSettingsResource) getRegistration(
	ctx context.Context,
	tenantID string,
) (*models.AzureTenantRegistration, diag.Diagnostics) {
	var diags diag.Diagnostics

	res, err := r.client.CloudAzureRegistration.CloudRegistrationAzureGetRegistration(
		&cloud_azure_registration.CloudRegistrationAzureGetRegistrationParams{
			TenantID: tenantID,
			Context:  ctx,
		},
	)
	if err != nil {
		if _, ok := err.(*cloud_azure_registration.CloudRegistrationAzureGetRegistrationNotFound); ok {
			diags.Append(
				newNotFoundError(
					fmt.Sprintf("No registration found for tenant: %s.", tenantID),
				),
			)
			return nil, diags
		}

		if _, ok := err.(*cloud_azure_registration.CloudRegistrationAzureGetRegistrationForbidden); ok {
			diags.Append(tferrors.NewForbiddenError(tferrors.Read, azureRegistrationScopes))
			return nil, diags
		}

		diags.Append(tferrors.NewOperationError(tferrors.Read, err))
		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Failed to get registration",
			"Get registration api call returned a successful status code, but no registration information was returned. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
		)

		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func (r *cloudAzureTenantEventhubSettingsResource) updateRegistration(
	ctx context.Context,
	data *cloudAzureTenantEventhubSettingsModel,
) (*models.AzureTenantRegistration, diag.Diagnostics) {
	var diags diag.Diagnostics

	settings := utils.ListTypeAs[*eventhubSettings](ctx, data.Settings, &diags)
	if diags.HasError() {
		return nil, diags
	}

	settingsSlice := make([]*models.AzureEventHubSettings, 0, len(settings))
	for _, setting := range settings {
		settingsSlice = append(settingsSlice, &models.AzureEventHubSettings{
			EventHubID:    setting.Id.ValueStringPointer(),
			ConsumerGroup: setting.ConsumerGroup.ValueStringPointer(),
			Purpose:       setting.Type.ValueStringPointer(),
		})
	}

	params := cloud_azure_registration.CloudRegistrationAzureUpdateRegistrationParams{
		Body: &models.AzureAzureRegistrationUpdateRequestExtV1{
			Resource: &models.AzureAzureRegistrationUpdateInput{
				TenantID:         data.TenantId.ValueStringPointer(),
				EventHubSettings: settingsSlice,
			},
		},
		Context: ctx,
	}

	res, err := r.client.CloudAzureRegistration.CloudRegistrationAzureUpdateRegistration(&params)
	if err != nil {
		if _, ok := err.(*cloud_azure_registration.CloudRegistrationAzureUpdateRegistrationNotFound); ok {
			diags.Append(
				newNotFoundError(
					fmt.Sprintf(
						"No registration found for tenant: %s.",
						data.TenantId.ValueString(),
					),
				),
			)
			return nil, diags
		}

		if _, ok := err.(*cloud_azure_registration.CloudRegistrationAzureUpdateRegistrationForbidden); ok {
			diags.Append(tferrors.NewForbiddenError(tferrors.Update, azureRegistrationScopes))
			return nil, diags
		}

		diags.Append(tferrors.NewOperationError(tferrors.Update, err))
		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Failed to update registration",
			"Update registration api call returned a successful status code, but no registration information was returned. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
		)

		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func (r *cloudAzureTenantEventhubSettingsResource) triggerHealthCheck(
	ctx context.Context,
	tenantID string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	params := cloud_azure_registration.CloudRegistrationAzureTriggerHealthCheckParams{
		TenantIds: []string{tenantID},
		Context:   ctx,
	}

	_, err := r.client.CloudAzureRegistration.CloudRegistrationAzureTriggerHealthCheck(&params)
	if err != nil {
		var hcErr *cloud_azure_registration.CloudRegistrationAzureTriggerHealthCheckForbidden
		if errors.As(err, &hcErr) {
			diags.Append(tferrors.NewForbiddenError(tferrors.Read, azureRegistrationScopes))
			return diags
		}
		diags.AddWarning(
			"Failed to trigger health check scan. Please go to the Falcon console and trigger health check scan manually to reflect the latest state.",
			err.Error(),
		)
	}

	return diags
}

func (r *cloudAzureTenantEventhubSettingsResource) validateRegistration(
	ctx context.Context,
	tenantID string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	params := cloud_azure_registration.CloudRegistrationAzureValidateRegistrationParams{
		Context:  ctx,
		TenantID: tenantID,
	}

	_, err := r.client.CloudAzureRegistration.CloudRegistrationAzureValidateRegistration(&params)
	if err != nil {
		var validateErr *cloud_azure_registration.CloudRegistrationAzureValidateRegistrationForbidden
		if errors.As(err, &validateErr) {
			diags.Append(tferrors.NewForbiddenError(tferrors.Read, azureRegistrationScopes))
			return diags
		}
		diags.AddWarning(
			"Failed to validate registration. Please go to the Falcon console and trigger health check scan manually to reflect the latest state.",
			err.Error(),
		)
	}

	return diags
}

func (r *cloudAzureTenantEventhubSettingsResource) validateRegistrationAndTriggerHealthCheck(
	ctx context.Context,
	tenantID string,
) diag.Diagnostics {
	time.Sleep(30 * time.Second)
	diags := r.validateRegistration(ctx, tenantID)
	if diags.HasError() || diags.WarningsCount() > 0 {
		return diags
	}

	hcDiags := r.triggerHealthCheck(ctx, tenantID)
	return hcDiags
}
