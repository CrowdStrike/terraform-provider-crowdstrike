package fcs

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_azure_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &cloudAzureTenantResource{}
	_ resource.ResourceWithConfigure      = &cloudAzureTenantResource{}
	_ resource.ResourceWithImportState    = &cloudAzureTenantResource{}
	_ resource.ResourceWithValidateConfig = &cloudAzureTenantResource{}
	_ resource.ResourceWithModifyPlan     = &cloudAzureTenantResource{}
)

func NewCloudAzureTenantResource() resource.Resource {
	return &cloudAzureTenantResource{}
}

type cloudAzureTenantResource struct {
	client   *client.CrowdStrikeAPISpecification
	clientId string
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
	r.clientId = config.ClientId
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

func (r *cloudAzureTenantResource) Schema(
	ctx context.Context,
	req resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Falcon Cloud Security --- This resource registers an Azure Tenant in Falcon Cloud Security.\n\n%s",
			scopes.GenerateScopeDescription(azureRegistrationScopes),
		),
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
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
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
				Validators:          []validator.String{stringvalidator.LengthAtMost(4)},
			},
			"tags": schema.MapAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Tags applied to managed resources. This does not effect the registration of the tenant. It will be used if you generate new .tfvars from the UI.",
			},
		},
	}
}

func (m *cloudAzureTenantModel) wrap(
	ctx context.Context,
	registration models.AzureTenantRegistration,
) diag.Diagnostics {
	var diags diag.Diagnostics

	graphPermissionIDs := utils.SliceToListTypeString(
		ctx,
		registration.MicrosoftGraphPermissionIds,
		&diags,
	)
	if m.MicrosoftGraphPermissionIds.IsNull() && len(graphPermissionIDs.Elements()) == 0 {
		graphPermissionIDs = types.ListNull(types.StringType)
	}

	subscriptionsIDs := utils.SliceToListTypeString(ctx, registration.SubscriptionIds, &diags)
	if m.SubscriptionIds.IsNull() && len(subscriptionsIDs.Elements()) == 0 {
		subscriptionsIDs = types.ListNull(types.StringType)
	}

	managementGroupIDs := utils.SliceToListTypeString(ctx, registration.ManagementGroupIds, &diags)
	if m.ManagementGroupIds.IsNull() && len(managementGroupIDs.Elements()) == 0 {
		managementGroupIDs = types.ListNull(types.StringType)
	}

	tags, err := types.MapValueFrom(ctx, types.StringType, registration.Tags)
	if m.Tags.IsNull() && len(tags.Elements()) == 0 {
		tags = types.MapNull(types.StringType)
	}
	diags.Append(err...)

	m.TenantId = types.StringValue(*registration.TenantID)
	m.AppRegistrationId = types.StringValue(registration.AppRegistrationID)
	m.AccountType = types.StringValue(registration.AccountType)
	m.CsInfraRegion = types.StringPointerValue(registration.CsInfraRegion)
	m.CsInfraSubscriptionId = types.StringPointerValue(registration.CsInfraSubscriptionID)
	m.Environment = types.StringPointerValue(registration.Environment)
	m.ResourceNamePrefix = types.StringPointerValue(registration.ResourceNamePrefix)
	m.ResourceNameSuffix = types.StringPointerValue(registration.ResourceNameSuffix)
	m.MicrosoftGraphPermissionIds = graphPermissionIDs
	m.Tags = tags
	m.SubscriptionIds = subscriptionsIDs
	m.ManagementGroupIds = managementGroupIDs

	if m.RealtimeVisibility == nil {
		m.RealtimeVisibility = &realtimeVisibility{}
	}
	m.RealtimeVisibility.Enabled = types.BoolValue(false)
	for _, product := range registration.Products {
		if *product.Product == "cspm" {
			for _, feature := range product.Features {
				if feature == "ioa" {
					m.RealtimeVisibility.Enabled = types.BoolValue(true)
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

	resp.Diagnostics.Append(data.wrap(ctx, *registration)...)
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

	resp.Diagnostics.Append(data.wrap(ctx, *registration)...)
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

	resp.Diagnostics.Append(data.wrap(ctx, *registration)...)
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

	affixCount := 0

	if utils.IsKnown(config.ResourceNamePrefix) {
		affixCount += len(config.ResourceNamePrefix.ValueString())
	}

	if utils.IsKnown(config.ResourceNameSuffix) {
		affixCount += len(config.ResourceNameSuffix.ValueString())
	}

	if affixCount > 10 {
		summary := "Invalid affixes"
		detail := "The combined length of resource_name_prefix and resource_name_suffix can not be greater than 10."
		resp.Diagnostics.Append(
			diag.NewAttributeErrorDiagnostic(path.Root("resource_name_prefix"), summary, detail),
		)
		resp.Diagnostics.Append(
			diag.NewAttributeErrorDiagnostic(path.Root("resource_name_suffix"), summary, detail),
		)
	}
}

func (r cloudAzureTenantResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}

	var state, plan cloudAzureTenantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if !state.MicrosoftGraphPermissionIds.Equal(plan.MicrosoftGraphPermissionIds) {
		plan.AppRegistrationId = types.StringUnknown()
	}

	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
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
			fmt.Sprintf("Failed to delete Azure tenant registration: %s", falcon.ErrorExplain(err)),
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
			fmt.Sprintf("Failed to get Azure tenant registration: %s", falcon.ErrorExplain(err)),
		)

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
		Features: []string{"iom"},
	}

	if data.RealtimeVisibility.Enabled.ValueBool() {
		cspmProductFeatures.Features = append(cspmProductFeatures.Features, "ioa")
	}

	params := cloud_azure_registration.CloudRegistrationAzureCreateRegistrationParams{
		Body: &models.AzureAzureRegistrationCreateRequestExtV1{
			Resource: &models.AzureAzureRegistrationCreateInput{
				AccountType:                 data.AccountType.ValueString(),
				TenantID:                    data.TenantId.ValueStringPointer(),
				CsInfraRegion:               data.CsInfraRegion.ValueString(),
				CsInfraSubscriptionID:       data.CsInfraSubscriptionId.ValueString(),
				APIClientKeyID:              r.clientId,
				APIClientKeyType:            "customer",
				Environment:                 data.Environment.ValueStringPointer(),
				ResourceNamePrefix:          data.ResourceNamePrefix.ValueStringPointer(),
				ResourceNameSuffix:          data.ResourceNameSuffix.ValueStringPointer(),
				MicrosoftGraphPermissionIds: microsoftGraphPermissionIDs,
				DeploymentMethod:            utils.Addr("terraform-native"),
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
			fmt.Sprintf("Failed to register Azure tenant: %s", falcon.ErrorExplain(err)),
		)

		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Failed to register tenant",
			"Registration api call returned a successful status code, but no registration information was returned. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
		)

		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func (r *cloudAzureTenantResource) updateRegistration(
	ctx context.Context,
	data *cloudAzureTenantModel,
) (*models.AzureTenantRegistration, diag.Diagnostics) {
	var diags diag.Diagnostics

	cspmProductFeatures := models.DomainProductFeatures{
		Product:  utils.Addr("cspm"),
		Features: []string{"iom"},
	}

	if data.RealtimeVisibility != nil && data.RealtimeVisibility.Enabled.ValueBool() {
		cspmProductFeatures.Features = append(cspmProductFeatures.Features, "ioa")
	}

	params := cloud_azure_registration.CloudRegistrationAzureUpdateRegistrationParams{
		Body: &models.AzureAzureRegistrationUpdateRequestExtV1{
			Resource: &models.AzureAzureRegistrationUpdateInput{
				AccountType:           data.AccountType.ValueString(),
				TenantID:              data.TenantId.ValueStringPointer(),
				CsInfraRegion:         data.CsInfraRegion.ValueString(),
				CsInfraSubscriptionID: data.CsInfraSubscriptionId.ValueString(),
				APIClientKeyID:        r.clientId,
				APIClientKeyType:      "customer",
				Environment:           data.Environment.ValueStringPointer(),
				ResourceNamePrefix:    data.ResourceNamePrefix.ValueStringPointer(),
				ResourceNameSuffix:    data.ResourceNameSuffix.ValueStringPointer(),
				MicrosoftGraphPermissionIds: utils.ListTypeAs[string](
					ctx,
					data.MicrosoftGraphPermissionIds,
					&diags,
				),
				DeploymentMethod: "terraform-native",
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

	if params.Body.Resource.Tags == nil {
		params.Body.Resource.Tags = map[string]string{}
	}

	if params.Body.Resource.ManagementGroupIds == nil {
		params.Body.Resource.ManagementGroupIds = []string{}
	}

	if params.Body.Resource.SubscriptionIds == nil {
		params.Body.Resource.SubscriptionIds = []string{}
	}

	if params.Body.Resource.MicrosoftGraphPermissionIds == nil {
		params.Body.Resource.MicrosoftGraphPermissionIds = []string{}
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
			fmt.Sprintf("Failed to update Azure tenant registration: %s", falcon.ErrorExplain(err)),
		)

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
