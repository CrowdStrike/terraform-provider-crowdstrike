package fcs

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_azure_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &cloudAzureTenantResource{}
	_ resource.ResourceWithConfigure      = &cloudAzureTenantResource{}
	_ resource.ResourceWithImportState    = &cloudAzureTenantResource{}
	_ resource.ResourceWithValidateConfig = &cloudAzureTenantResource{}
)

func NewCloudAzureTenantResource() resource.Resource {
	return &cloudAzureTenantResource{}
}

type cloudAzureTenantResource struct {
	client *client.CrowdStrikeAPISpecification
}

// Configure adds the provider configured client to the resource.
func (r *cloudAzureTenantResource) Configure(
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

func (r *cloudAzureTenantResource) Metadata(
	ctx context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_azure_tenant"
}

type cloudAzureTenantModel struct {
	AccountType                 types.String        `tfsdk:"account_type"`
	AppRegistrationId           types.String        `tfsdk:"cs_azure_client_id"`
	CsInfraRegion               types.String        `tfsdk:"cs_infra_location"`
	CsInfraSubscriptionId       types.String        `tfsdk:"cs_infra_subscription_id"`
	Environment                 types.String        `tfsdk:"environment"`
	ManagementGroupIds          types.List          `tfsdk:"management_group_ids"`
	MicrosoftGraphPermissionIds types.List          `tfsdk:"microsoft_graph_permission_ids"`
	ResourceNamePrefix          types.String        `tfsdk:"resource_name_prefix"`
	ResourceNameSuffix          types.String        `tfsdk:"resource_name_suffix"`
	SubscriptionIds             types.List          `tfsdk:"subscription_ids"`
	Tags                        types.Map           `tfsdk:"tags"`
	TenantId                    types.String        `tfsdk:"tenant_id"`
	RealtimeVisibility          *realtimeVisibility `tfsdk:"realtime_visibility"`
}

type realtimeVisibility struct {
	Enabled types.Bool `tfsdk:"enabled"`
}

func (f realtimeVisibility) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"enabled": types.BoolType,
	}
}

func (r *cloudAzureTenantResource) Schema(
	ctx context.Context,
	req resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"account_type": schema.StringAttribute{
				Optional:    true,
				Default:     stringdefault.StaticString("commercial"),
				Computed:    true,
				Description: "The Azure Tenant account type. Value is 'commercial' for Commercial cloud accounts. For GovCloud environments, value can be either 'commercial' or 'gov' depending on the account type",
				Validators: []validator.String{
					stringvalidator.OneOf("commercial", "gov"),
				},
			},
			"cs_azure_client_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Client ID of CrowdStrike's multi-tenant application in Azure. This is used to establish the connection between Azure and Falcon Cloud Security.",
			},
			// reguired if realtime_visibility is enabled todo validate
			"cs_infra_location": schema.StringAttribute{
				MarkdownDescription: "Azure location where CrowdStrike infrastructure resources (such as Event Hubs) were deployed.",
				Optional:            true,
			},
			// reguired if realtime_visibility is enabled todo validate
			"cs_infra_subscription_id": schema.StringAttribute{
				MarkdownDescription: "Azure subscription ID where CrowdStrike infrastructure resources (such as Event Hubs) were deployed.",
				Optional:            true,
			},
			"management_group_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "A list of Azure management group IDs to monitor. All subscriptions under the management groups will be monitored.",
			},
			"microsoft_graph_permission_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				Required:            true,
				MarkdownDescription: "A list of Microsoft Graph permission IDs to assign to the service principal.",
			},
			"subscription_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "A list of subscription IDs to register in addition to any subscriptions that are targeted by management_group_ids.",
			},
			"tenant_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The Azure Tenant ID to register into Falcon Cloud Security. If subscription_ids and management_group_ids are not provided, then all subscriptions in the tenant are targeted.",
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
			"resource_name_prefix": schema.StringAttribute{
				MarkdownDescription: "The prefix added to resources created during onboarding. It will be used if you generate new .tfvars from the UI.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"resource_name_suffix": schema.StringAttribute{
				MarkdownDescription: "The suffix added to resources created during onboarding. It will be used if you generate new .tfvars from the UI.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"environment": schema.StringAttribute{
				MarkdownDescription: "The environment added to resources created during onboarding. It will be used if you generate new .tfvars from the UI.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"tags": schema.MapAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Tags applied to managed resources. This does not effect the registration of the tenant. It will be used if you generate new .tfvars from the UI.",
			},
		},
	}
}

func wrap(
	ctx context.Context,
	model *cloudAzureTenantModel,
	registration models.AzureTenantRegistration,
) diag.Diagnostics {
	var diags diag.Diagnostics

	graphPermissionIDs, err := types.ListValueFrom(
		ctx,
		types.StringType,
		registration.MicrosoftGraphPermissionIds,
	)
	diags.Append(err...)
	subscriptionIDs, err := types.ListValueFrom(
		ctx,
		types.StringType,
		registration.SubscriptionIds,
	)
	diags.Append(err...)
	managementGroupIDs, err := types.ListValueFrom(
		ctx,
		types.StringType,
		registration.ManagementGroupIds,
	)
	diags.Append(err...)
	tags, err := types.MapValueFrom(ctx, types.StringType, registration.Tags)
	diags.Append(err...)

	model.TenantId = types.StringValue(*registration.TenantID)
	model.AppRegistrationId = types.StringValue(registration.AppRegistrationID)
	model.AccountType = types.StringValue(registration.AccountType)
	model.CsInfraRegion = types.StringPointerValue(registration.CsInfraRegion)
	model.CsInfraSubscriptionId = types.StringPointerValue(registration.CsInfraSubscriptionID)
	model.Environment = types.StringPointerValue(registration.Environment)
	model.ResourceNamePrefix = types.StringPointerValue(registration.ResourceNamePrefix)
	model.ResourceNameSuffix = types.StringPointerValue(registration.ResourceNameSuffix)
	model.MicrosoftGraphPermissionIds = graphPermissionIDs
	model.Tags = tags
	model.SubscriptionIds = subscriptionIDs
	model.ManagementGroupIds = managementGroupIDs

	if model.RealtimeVisibility == nil {
		model.RealtimeVisibility = &realtimeVisibility{}
	}
	model.RealtimeVisibility.Enabled = types.BoolValue(false)
	for _, product := range registration.Products {
		if *product.Product == "cspm" {
			for _, feature := range product.Features {
				if feature == "ioa" || feature == "iom" {
					model.RealtimeVisibility.Enabled = types.BoolValue(true)
				}
			}
		}
	}

	return diags
}

func (r *cloudAzureTenantResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var data cloudAzureTenantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	registration, err := r.createRegistration(ctx, &data)
	resp.Diagnostics.Append(err...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		resp.State.SetAttribute(
			ctx,
			path.Root("tenant_id"),
			types.StringPointerValue(registration.TenantID),
		)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(wrap(ctx, &data, *registration)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudAzureTenantResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var data cloudAzureTenantModel
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

	resp.Diagnostics.Append(wrap(ctx, &data, *registration)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudAzureTenantResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var data cloudAzureTenantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	registration, err := r.updateRegistration(ctx, &data)
	resp.Diagnostics.Append(err...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(wrap(ctx, &data, *registration)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudAzureTenantResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var data cloudAzureTenantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.deleteRegistration(ctx, data.TenantId.ValueString())...)
}

func (r *cloudAzureTenantResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("tenant_id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *cloudAzureTenantResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config cloudAzureTenantModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		utils.ValidateEmptyIDsList(ctx, types.Set(config.SubscriptionIds), "subscription_ids")...)
	resp.Diagnostics.Append(
		utils.ValidateEmptyIDsList(
			ctx,
			types.Set(config.ManagementGroupIds),
			"management_group_ids",
		)...)
	resp.Diagnostics.Append(
		utils.ValidateEmptyIDsList(
			ctx,
			types.Set(config.MicrosoftGraphPermissionIds),
			"microsoft_graph_permission_ids",
		)...)
}

func (r *cloudAzureTenantResource) deleteRegistration(
	ctx context.Context,
	tenantID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	_, err := r.client.CloudAzureRegistration.CloudRegistrationAzureDeleteRegistration(
		&cloud_azure_registration.CloudRegistrationAzureDeleteRegistrationParams{
			TenantIds: []string{tenantID},
			Context:   ctx,
		},
	)

	if err != nil {
		diags.AddError(
			"Failed to delete registration",
			fmt.Sprintf("Failed to delete azure tenant registration: %s", err),
		)

		return diags
	}

	return diags
}

func (r *cloudAzureTenantResource) getRegistration(
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

		diags.AddError(
			"Failed to get registration",
			fmt.Sprintf("Failed to get azure tenant registration: %s", err),
		)

		return nil, diags
	}

	if res == nil || res.Payload == nil || res.Payload.Resource == nil {
		diags.AddError(
			"Failed to get registration",
			"Get registration api call returned a successful status code, but no registration information was returned. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
		)

		return nil, diags
	}

	return res.Payload.Resource, diags
}

func (r *cloudAzureTenantResource) createRegistration(
	ctx context.Context,
	data *cloudAzureTenantModel,
) (*models.AzureTenantRegistration, diag.Diagnostics) {
	var diags diag.Diagnostics

	microsoftGraphPermissionIDs := utils.ListTypeAs[string](
		ctx,
		data.MicrosoftGraphPermissionIds,
		&diags,
	)

	if diags.HasError() {
		return nil, diags
	}

	cspmProductFeatures := models.DomainProductFeatures{
		Product:  utils.Addr("cspm"),
		Features: []string{},
	}

	if data.RealtimeVisibility.Enabled.ValueBool() {
		features := []string{"ioa", "iom"}
		cspmProductFeatures.Features = append(cspmProductFeatures.Features, features...)
	}

	params := cloud_azure_registration.CloudRegistrationAzureCreateRegistrationParams{
		Body: &models.AzureAzureRegistrationCreateRequestExtV1{
			Resource: &models.AzureTenantRegistrationBase{
				AccountType:                 data.AccountType.ValueString(),
				TenantID:                    data.TenantId.ValueStringPointer(),
				CsInfraRegion:               data.CsInfraRegion.ValueString(),
				CsInfraSubscriptionID:       data.CsInfraSubscriptionId.ValueString(),
				Environment:                 data.Environment.ValueString(),
				ResourceNamePrefix:          data.ResourceNamePrefix.ValueString(),
				ResourceNameSuffix:          data.ResourceNamePrefix.ValueString(),
				MicrosoftGraphPermissionIds: microsoftGraphPermissionIDs,
				DeploymentMethod:            "terraform-native",
				ManagementGroupIds: utils.ListTypeAs[string](
					ctx,
					data.ManagementGroupIds,
					&diags,
				),
				SubscriptionIds: utils.ListTypeAs[string](ctx, data.SubscriptionIds, &diags),
				Products: []*models.DomainProductFeatures{
					&cspmProductFeatures,
				},
				Tags: utils.MapTypeAs[string](ctx, data.Tags, &diags),
			},
		},
		Context: ctx,
	}

	if diags.HasError() {
		return nil, diags
	}

	res, err := r.client.CloudAzureRegistration.CloudRegistrationAzureCreateRegistration(&params)

	if err != nil {
		diags.AddError(
			"Failed to register tenant",
			fmt.Sprintf("Failed to register azure tenant: %s", falcon.ErrorExplain(err)),
		)

		return nil, diags
	}

	if res == nil || res.Payload == nil || res.Payload.Resource == nil {
		diags.AddError(
			"Failed to register tenant",
			"Registration api call returned a successful status code, but no registration information was returned. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
		)

		return nil, diags
	}

	return res.Payload.Resource, diags
}

func (r *cloudAzureTenantResource) updateRegistration(
	ctx context.Context,
	data *cloudAzureTenantModel,
) (*models.AzureTenantRegistration, diag.Diagnostics) {
	var diags diag.Diagnostics

	microsoftGraphPermissionIDs := utils.ListTypeAs[string](
		ctx,
		data.MicrosoftGraphPermissionIds,
		&diags,
	)

	if diags.HasError() {
		return nil, diags
	}

	cspmProductFeatures := models.DomainProductFeatures{
		Product:  utils.Addr("cspm"),
		Features: []string{},
	}

	if data.RealtimeVisibility != nil && data.RealtimeVisibility.Enabled.ValueBool() {
		features := []string{"ioa", "iom"}
		cspmProductFeatures.Features = append(cspmProductFeatures.Features, features...)
	}

	tags := utils.MapTypeAs[string](ctx, data.Tags, &diags)
	if tags == nil {
		tags = map[string]string{}
	}

	params := cloud_azure_registration.CloudRegistrationAzureUpdateRegistrationParams{
		Body: &models.AzureAzureRegistrationUpdateRequestExtV1{
			Resource: &models.AzureTenantRegistrationBase{
				AccountType:                 data.AccountType.ValueString(),
				TenantID:                    data.TenantId.ValueStringPointer(),
				CsInfraRegion:               data.CsInfraRegion.ValueString(),
				CsInfraSubscriptionID:       data.CsInfraSubscriptionId.ValueString(),
				Environment:                 data.Environment.ValueString(),
				ResourceNamePrefix:          data.ResourceNamePrefix.ValueString(),
				ResourceNameSuffix:          data.ResourceNamePrefix.ValueString(),
				MicrosoftGraphPermissionIds: microsoftGraphPermissionIDs,
				DeploymentMethod:            "terraform-native",
				ManagementGroupIds: utils.ListTypeAs[string](
					ctx,
					data.ManagementGroupIds,
					&diags,
				),
				SubscriptionIds: utils.ListTypeAs[string](ctx, data.SubscriptionIds, &diags),
				Products: []*models.DomainProductFeatures{
					&cspmProductFeatures,
				},
				Tags: tags,
			},
		},
		Context: ctx,
	}

	if diags.HasError() {
		return nil, diags
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

		diags.AddError(
			"Failed to update registration",
			fmt.Sprintf("Failed to update azure tenant registration: %s", err),
		)

		return nil, diags
	}

	if res == nil || res.Payload == nil || res.Payload.Resource == nil {
		diags.AddError(
			"Failed to update registration",
			"Update registration api call returned a successful status code, but no registration information was returned. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
		)

		return nil, diags
	}

	return res.Payload.Resource, diags
}
