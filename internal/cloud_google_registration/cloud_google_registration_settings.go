package cloudgoogleregistration

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_google_cloud_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
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
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &cloudGoogleRegistrationSettingsResource{}
	_ resource.ResourceWithConfigure      = &cloudGoogleRegistrationSettingsResource{}
	_ resource.ResourceWithImportState    = &cloudGoogleRegistrationSettingsResource{}
	_ resource.ResourceWithValidateConfig = &cloudGoogleRegistrationSettingsResource{}
)

func NewCloudGoogleRegistrationSettingsResource() resource.Resource {
	return &cloudGoogleRegistrationSettingsResource{}
}

type cloudGoogleRegistrationSettingsResource struct {
	client *client.CrowdStrikeAPISpecification
}

func (r *cloudGoogleRegistrationSettingsResource) Configure(
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

func (r *cloudGoogleRegistrationSettingsResource) Metadata(
	ctx context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_google_registration_settings"
}

type cloudGoogleRegistrationSettingsModel struct {
	RegistrationID               types.String `tfsdk:"registration_id"`
	LogIngestionSinkName         types.String `tfsdk:"log_ingestion_sink_name"`
	LogIngestionTopicID          types.String `tfsdk:"log_ingestion_topic_id"`
	LogIngestionSubscriptionName types.String `tfsdk:"log_ingestion_subscription_name"`
	WifPoolName                  types.String `tfsdk:"wif_pool_name"`
	WifProviderName              types.String `tfsdk:"wif_provider_name"`
	AgentlessScanningSettings    types.Object `tfsdk:"agentless_scanning_settings"`
}

// TF schema ↔ provider mapping layer for agentless_scanning_settings.
type agentlessScanningSettingsModel struct {
	WIFPrincipal             types.String `tfsdk:"wif_principal"`
	DeploymentVersion        types.String `tfsdk:"deployment_version"`
	Regions                  types.Set    `tfsdk:"regions"`
	HostProjectID            types.String `tfsdk:"host_project_id"`
	OrgID                    types.String `tfsdk:"org_id"`
	NetworkConfigurationType types.String `tfsdk:"network_configuration_type"`
	CustomNetwork            types.Object `tfsdk:"custom_network"`
	Infra                    types.Map    `tfsdk:"infra"`
}

func (d *agentlessScanningSettingsModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"wif_principal":              types.StringType,
		"deployment_version":         types.StringType,
		"regions":                    types.SetType{ElemType: types.StringType},
		"host_project_id":            types.StringType,
		"org_id":                     types.StringType,
		"network_configuration_type": types.StringType,
		"custom_network":             types.ObjectType{AttrTypes: (&networkConfigModel{}).AttributeTypes()},
		"infra":                      types.MapType{ElemType: types.ObjectType{AttrTypes: (&infraProjectModel{}).AttributeTypes()}},
	}
}

func (d *agentlessScanningSettingsModel) ToObject(ctx context.Context) (types.Object, diag.Diagnostics) {
	return types.ObjectValueFrom(ctx, d.AttributeTypes(), d)
}

func (d *agentlessScanningSettingsModel) FromObject(ctx context.Context, obj types.Object) diag.Diagnostics {
	return obj.As(ctx, d, basetypes.ObjectAsOptions{})
}

type infraProjectModel struct {
	ScannerSAEmail              types.String `tfsdk:"scanner_sa_email"`
	ClientCredentialsSecretName types.String `tfsdk:"client_credentials_secret_name"`
	Network                     types.Object `tfsdk:"network"`
}

func (i *infraProjectModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"scanner_sa_email":               types.StringType,
		"client_credentials_secret_name": types.StringType,
		"network":                        types.ObjectType{AttrTypes: (&networkConfigModel{}).AttributeTypes()},
	}
}

func (i *infraProjectModel) ToObject(ctx context.Context) (types.Object, diag.Diagnostics) {
	return types.ObjectValueFrom(ctx, i.AttributeTypes(), i)
}

func (i *infraProjectModel) FromObject(ctx context.Context, obj types.Object) diag.Diagnostics {
	return obj.As(ctx, i, basetypes.ObjectAsOptions{})
}

type networkConfigModel struct {
	VpcName types.String `tfsdk:"vpc_name"`
	Subnets types.Map    `tfsdk:"subnets"`
}

func (n *networkConfigModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"vpc_name": types.StringType,
		"subnets":  types.MapType{ElemType: types.StringType},
	}
}

func (n *networkConfigModel) ToObject(ctx context.Context) (types.Object, diag.Diagnostics) {
	return types.ObjectValueFrom(ctx, n.AttributeTypes(), n)
}

func (n *networkConfigModel) FromObject(ctx context.Context, obj types.Object) diag.Diagnostics {
	return obj.As(ctx, n, basetypes.ObjectAsOptions{})
}

func (r *cloudGoogleRegistrationSettingsResource) Schema(
	ctx context.Context,
	req resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Falcon Cloud Security",
			"This resource manages settings for a Google Cloud registration in Falcon Cloud Security that may not be known until after the registration has been created, such as log ingestion and Workload Identity Federation (WIF) configuration.",
			gcpRegistrationScopes,
		),
		Attributes: map[string]schema.Attribute{
			"registration_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The Google Cloud registration ID to configure settings for.",
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
			"wif_pool_name": schema.StringAttribute{
				Optional:    true,
				Description: "The Workload Identity Federation (WIF) pool name.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"wif_provider_name": schema.StringAttribute{
				Optional:    true,
				Description: "The Workload Identity Federation (WIF) provider name.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"agentless_scanning_settings": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Agentless scanning settings. Only configurable after the agentless scanning infrastructure has been created via Terraform.",
				Attributes: map[string]schema.Attribute{
					"wif_principal": schema.StringAttribute{
						Required:    true,
						Description: "The Workload Identity Federation principal for the agentless scanning.",
						Validators: []validator.String{
							validators.StringNotWhitespace(),
						},
					},
					"deployment_version": schema.StringAttribute{
						Required:    true,
						Description: "The TF module deployment version for tracking.",
					},
					"regions": schema.SetAttribute{
						Required:    true,
						ElementType: types.StringType,
						Description: "The GCP regions where agentless scanning infrastructure is deployed.",
					},
					"host_project_id": schema.StringAttribute{
						Optional:    true,
						Description: "The GCP project hosting shared scanning infrastructure. When set, indicates cross-project mode.",
						Validators: []validator.String{
							validators.StringNotWhitespace(),
						},
					},
					"org_id": schema.StringAttribute{
						Optional:    true,
						Description: "The GCP organization ID. Required only for folder-scoped registrations.",
						Validators: []validator.String{
							validators.StringNotWhitespace(),
						},
					},
					"network_configuration_type": schema.StringAttribute{
						Required:    true,
						Description: "Network configuration type for scanner VMs: managed (with NAT), managed_no_nat, or custom (BYO VPC).",
						Validators: []validator.String{
							stringvalidator.OneOf("managed", "managed_no_nat", "custom"),
						},
					},
					"custom_network": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "Custom (BYO) network configuration. Required when network_configuration_type is 'custom'.",
						Attributes: map[string]schema.Attribute{
							"vpc_name": schema.StringAttribute{
								Required:    true,
								Description: "The name of the customer-provided VPC network.",
								Validators: []validator.String{
									validators.StringNotWhitespace(),
								},
							},
							"subnets": schema.MapAttribute{
								Required:    true,
								ElementType: types.StringType,
								Description: "Map of region to subnet name within the custom VPC.",
							},
						},
					},
					"infra": schema.MapNestedAttribute{
						Required:    true,
						Description: "Per-project scanning infrastructure details, keyed by GCP project ID. In cross-project mode this contains a single entry for the host project.",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"scanner_sa_email": schema.StringAttribute{
									Required:    true,
									Description: "The service account email used by the scanner in this project.",
									Validators: []validator.String{
										validators.StringNotWhitespace(),
									},
								},
								"client_credentials_secret_name": schema.StringAttribute{
									Required:    true,
									Description: "The Secret Manager secret name containing Falcon client credentials for scanner authentication.",
									Validators: []validator.String{
										validators.StringNotWhitespace(),
									},
								},
								"network": schema.SingleNestedAttribute{
									Required:    true,
									Description: "Network configuration for scanner VMs in this project.",
									Attributes: map[string]schema.Attribute{
										"vpc_name": schema.StringAttribute{
											Required:    true,
											Description: "The VPC network name used by scanner VMs.",
											Validators: []validator.String{
												validators.StringNotWhitespace(),
											},
										},
										"subnets": schema.MapAttribute{
											Required:    true,
											ElementType: types.StringType,
											Description: "Map of region to subnet name for scanner VMs.",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// wrap maps the BE response to TF state.
func (m *cloudGoogleRegistrationSettingsModel) wrap(
	ctx context.Context,
	registration *models.DtoGCPRegistration,
) diag.Diagnostics {
	var diags diag.Diagnostics

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

	var wifPoolName, wifProviderName string
	if registration.WifProperties != nil {
		wifPoolName = registration.WifProperties.PoolName
		wifProviderName = registration.WifProperties.ProviderName
	}
	m.WifPoolName = flex.StringValueToFramework(wifPoolName)
	m.WifProviderName = flex.StringValueToFramework(wifProviderName)

	// Both features share the same infra — read from whichever is set
	agentlessSettings := registration.DspmSettings
	if agentlessSettings == nil {
		agentlessSettings = registration.VulnerabilityScanningSettings
	}
	d := m.wrapAgentlessScanningSettings(ctx, agentlessSettings)
	diags.Append(d...)

	return diags
}

// Maps BE agentless settings to TF state.
// Both dspm_settings and vulnerability_scanning_settings share the same infra — we read from whichever is set.
func (m *cloudGoogleRegistrationSettingsModel) wrapAgentlessScanningSettings(
	ctx context.Context,
	dspmSettings *models.GcpAgentlessScanningSettings,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if dspmSettings == nil {
		m.AgentlessScanningSettings = types.ObjectNull((&agentlessScanningSettingsModel{}).AttributeTypes())
		return diags
	}

	settings := agentlessScanningSettingsModel{
		WIFPrincipal:             flex.StringValueToFramework(dspmSettings.WifPrincipal),
		DeploymentVersion:        flex.StringValueToFramework(dspmSettings.DeploymentVersion),
		NetworkConfigurationType: flex.StringValueToFramework("managed"),
	}

	if dspmSettings.UserInputs != nil {
		regionsSet, d := flex.FlattenStringValueSet(ctx, dspmSettings.UserInputs.Regions)
		diags.Append(d...)
		settings.Regions = regionsSet

		settings.HostProjectID = flex.StringValueToFramework(dspmSettings.UserInputs.HostProjectID)
		settings.OrgID = flex.StringValueToFramework(dspmSettings.UserInputs.OrgID)
		settings.NetworkConfigurationType = flex.StringPointerToFramework(dspmSettings.UserInputs.NetworkConfigurationType)

		if dspmSettings.UserInputs.CustomNetwork != nil {
			subnetsMap, d := types.MapValueFrom(ctx, types.StringType, dspmSettings.UserInputs.CustomNetwork.Subnets)
			diags.Append(d...)
			cnModel := networkConfigModel{
				VpcName: flex.StringPointerToFramework(dspmSettings.UserInputs.CustomNetwork.VpcName),
				Subnets: subnetsMap,
			}
			cnObj, d := cnModel.ToObject(ctx)
			diags.Append(d...)
			settings.CustomNetwork = cnObj
		} else {
			settings.CustomNetwork = types.ObjectNull((&networkConfigModel{}).AttributeTypes())
		}
	} else {
		settings.Regions = types.SetNull(types.StringType)
		settings.HostProjectID = types.StringNull()
		settings.OrgID = types.StringNull()
		settings.CustomNetwork = types.ObjectNull((&networkConfigModel{}).AttributeTypes())
	}

	// Build infra map
	infraMap := make(map[string]attr.Value)
	for projectID, infraEntry := range dspmSettings.Infra {
		var networkObj types.Object
		if infraEntry.Network != nil {
			subnetsMap, d := types.MapValueFrom(ctx, types.StringType, infraEntry.Network.Subnets)
			diags.Append(d...)
			netModel := networkConfigModel{
				VpcName: flex.StringPointerToFramework(infraEntry.Network.VpcName),
				Subnets: subnetsMap,
			}
			obj, d := netModel.ToObject(ctx)
			diags.Append(d...)
			networkObj = obj
		} else {
			networkObj = types.ObjectNull((&networkConfigModel{}).AttributeTypes())
		}

		projModel := infraProjectModel{
			ScannerSAEmail:              flex.StringPointerToFramework(infraEntry.ScannerSaEmail),
			ClientCredentialsSecretName: flex.StringPointerToFramework(infraEntry.ClientCredentialsSecretName),
			Network:                     networkObj,
		}
		obj, d := projModel.ToObject(ctx)
		diags.Append(d...)
		infraMap[projectID] = obj
	}

	if len(infraMap) > 0 {
		infraMapValue, d := types.MapValue(
			types.ObjectType{AttrTypes: (&infraProjectModel{}).AttributeTypes()},
			infraMap,
		)
		diags.Append(d...)
		settings.Infra = infraMapValue
	} else {
		settings.Infra = types.MapNull(types.ObjectType{AttrTypes: (&infraProjectModel{}).AttributeTypes()})
	}

	settingsObj, d := settings.ToObject(ctx)
	diags.Append(d...)
	m.AgentlessScanningSettings = settingsObj

	return diags
}

func (r *cloudGoogleRegistrationSettingsResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var data cloudGoogleRegistrationSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	registration, diags := r.updateRegistration(ctx, &data)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	hasLogSettings := !data.LogIngestionSinkName.IsNull() ||
		!data.LogIngestionTopicID.IsNull() ||
		!data.LogIngestionSubscriptionName.IsNull()

	if hasLogSettings && !r.isIOAEnabled(registration) {
		resp.Diagnostics.AddError(
			"IOA Not Enabled",
			fmt.Sprintf(
				"Log ingestion settings cannot be configured because IOA (Indicator of Attack) is not enabled for registration %s. Enable realtime_visibility with IOA in the cloud_google_registration resource first.",
				data.RegistrationID.ValueString(),
			),
		)
		return
	}

	if !data.AgentlessScanningSettings.IsNull() && !isFeatureEnabled(registration, featureDSPM) && !isFeatureEnabled(registration, featureVulnerabilityScanning) {
		resp.Diagnostics.AddError(
			"Agentless Scanning Not Enabled",
			fmt.Sprintf(
				"Agentless scanning settings cannot be configured because neither DSPM nor vulnerability scanning is enabled for registration %s. Enable dspm or vulnerability_scanning in the cloud_google_registration resource first.",
				data.RegistrationID.ValueString(),
			),
		)
		return
	}

	diags = r.triggerHealthCheck(ctx, data.RegistrationID.ValueString())
	resp.Diagnostics.Append(diags...)

	d := data.wrap(ctx, registration)
	resp.Diagnostics.Append(d...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudGoogleRegistrationSettingsResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var data cloudGoogleRegistrationSettingsModel
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

	d := data.wrap(ctx, registration)
	resp.Diagnostics.Append(d...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudGoogleRegistrationSettingsResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var data cloudGoogleRegistrationSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	registration, diags := r.updateRegistration(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasLogSettings := !data.LogIngestionSinkName.IsNull() ||
		!data.LogIngestionTopicID.IsNull() ||
		!data.LogIngestionSubscriptionName.IsNull()

	if hasLogSettings && !r.isIOAEnabled(registration) {
		resp.Diagnostics.AddError(
			"IOA Not Enabled",
			fmt.Sprintf(
				"Log ingestion settings cannot be configured because IOA (Indicator of Attack) is not enabled for registration %s. Enable realtime_visibility with IOA in the cloud_google_registration resource first.",
				data.RegistrationID.ValueString(),
			),
		)
		return
	}

	if !data.AgentlessScanningSettings.IsNull() && !isFeatureEnabled(registration, featureDSPM) && !isFeatureEnabled(registration, featureVulnerabilityScanning) {
		resp.Diagnostics.AddError(
			"Agentless Scanning Not Enabled",
			fmt.Sprintf(
				"Agentless scanning settings cannot be configured because neither DSPM nor vulnerability scanning is enabled for registration %s. Enable dspm or vulnerability_scanning in the cloud_google_registration resource first.",
				data.RegistrationID.ValueString(),
			),
		)
		return
	}

	diags = r.triggerHealthCheck(ctx, data.RegistrationID.ValueString())
	resp.Diagnostics.Append(diags...)

	d := data.wrap(ctx, registration)
	resp.Diagnostics.Append(d...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudGoogleRegistrationSettingsResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var data cloudGoogleRegistrationSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.LogIngestionSinkName = types.StringValue("")
	data.LogIngestionTopicID = types.StringValue("")
	data.LogIngestionSubscriptionName = types.StringValue("")
	data.WifPoolName = types.StringValue("")
	data.WifProviderName = types.StringValue("")
	data.AgentlessScanningSettings = types.ObjectNull((&agentlessScanningSettingsModel{}).AttributeTypes())

	registration, err := r.updateRegistration(ctx, &data)
	resp.Diagnostics.Append(err...)

	if tferrors.HasNotFoundError(resp.Diagnostics) {
		return
	}

	if resp.Diagnostics.HasError() {
		return
	}

	d := data.wrap(ctx, registration)
	resp.Diagnostics.Append(d...)

	if registration.LogIngestionProperties != nil {
		if registration.LogIngestionProperties.SinkName != "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("log_ingestion_sink_name"),
				"Delete failed.",
				"Log ingestion sink name was returned after the attempt to remove it. This is a bug in the provider. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
			)
		}
		if registration.LogIngestionProperties.TopicID != "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("log_ingestion_topic_id"),
				"Delete failed.",
				"Log ingestion topic ID was returned after the attempt to remove it. This is a bug in the provider. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
			)
		}
		if registration.LogIngestionProperties.SubscriptionID != "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("log_ingestion_subscription_name"),
				"Delete failed.",
				"Log ingestion subscription name was returned after the attempt to remove it. This is a bug in the provider. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
			)
		}
	}

	if registration.WifProperties != nil {
		if registration.WifProperties.PoolName != "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("wif_pool_name"),
				"Delete failed.",
				"WIF pool name was returned after the attempt to remove it. This is a bug in the provider. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
			)
		}
		if registration.WifProperties.ProviderName != "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("wif_provider_name"),
				"Delete failed.",
				"WIF provider name was returned after the attempt to remove it. This is a bug in the provider. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
			)
		}
	}
}

func (r *cloudGoogleRegistrationSettingsResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("registration_id"), req, resp)
}

func (r *cloudGoogleRegistrationSettingsResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config cloudGoogleRegistrationSettingsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *cloudGoogleRegistrationSettingsResource) isIOAEnabled(
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

func isFeatureEnabled(registration *models.DtoGCPRegistration, feature string) bool {
	if registration == nil {
		return false
	}

	for _, product := range registration.Products {
		if product.Product != nil && *product.Product == "cspm" {
			for _, f := range product.Features {
				if f == feature {
					return true
				}
			}
		}
	}

	return false
}

func (r *cloudGoogleRegistrationSettingsResource) getRegistration(
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

// updateRegistration sends settings (WIF, log ingestion, agentless scanning) to the BE.
func (r *cloudGoogleRegistrationSettingsResource) updateRegistration(
	ctx context.Context,
	data *cloudGoogleRegistrationSettingsModel,
) (*models.DtoGCPRegistration, diag.Diagnostics) {
	var diags diag.Diagnostics

	updateReq := &models.DtoUpdateGCPRegistrationRequest{
		LogIngestionSinkName:         flex.FrameworkToStringPointer(data.LogIngestionSinkName),
		LogIngestionTopicID:          flex.FrameworkToStringPointer(data.LogIngestionTopicID),
		LogIngestionSubscriptionName: flex.FrameworkToStringPointer(data.LogIngestionSubscriptionName),
		WifPoolName:                  flex.FrameworkToStringPointer(data.WifPoolName),
		WifProviderName:              flex.FrameworkToStringPointer(data.WifProviderName),
	}

	d := marshalAgentlessScanningSettings(ctx, data.AgentlessScanningSettings, updateReq)
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
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

// marshalAgentlessScanningSettings maps TF state (agentlessScanningSettingsModel) → gofalcon update request.
// Sends to both dspm_settings and vulnerability_scanning_settings — BE handles routing based on enabled features.
func marshalAgentlessScanningSettings(
	ctx context.Context,
	settingsObj types.Object,
	updateReq *models.DtoUpdateGCPRegistrationRequest,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if settingsObj.IsNull() || settingsObj.IsUnknown() {
		return diags
	}

	var settings agentlessScanningSettingsModel
	diags.Append(settings.FromObject(ctx, settingsObj)...)
	if diags.HasError() {
		return diags
	}

	regions := flex.ExpandSetAs[string](ctx, settings.Regions, &diags)
	if diags.HasError() {
		return diags
	}

	userInputs := &models.GcpAgentlessScanningUserInputs{
		Regions:                  regions,
		HostProjectID:            settings.HostProjectID.ValueString(),
		OrgID:                    settings.OrgID.ValueString(),
		NetworkConfigurationType: settings.NetworkConfigurationType.ValueStringPointer(),
	}

	if !settings.CustomNetwork.IsNull() {
		var cn networkConfigModel
		diags.Append(cn.FromObject(ctx, settings.CustomNetwork)...)
		if diags.HasError() {
			return diags
		}

		subnets := make(map[string]string)
		if !cn.Subnets.IsNull() {
			diags.Append(cn.Subnets.ElementsAs(ctx, &subnets, false)...)
		}

		userInputs.CustomNetwork = &models.GcpNetworkConfig{
			VpcName: cn.VpcName.ValueStringPointer(),
			Subnets: subnets,
		}
	}

	infraMap := make(map[string]models.GcpAgentlessScanningInfra)
	if !settings.Infra.IsNull() {
		var infraEntries map[string]infraProjectModel
		diags.Append(settings.Infra.ElementsAs(ctx, &infraEntries, false)...)
		if diags.HasError() {
			return diags
		}

		for projectID, entry := range infraEntries {
			infra := models.GcpAgentlessScanningInfra{
				ScannerSaEmail:              entry.ScannerSAEmail.ValueStringPointer(),
				ClientCredentialsSecretName: entry.ClientCredentialsSecretName.ValueStringPointer(),
			}

			if !entry.Network.IsNull() {
				var net networkConfigModel
				diags.Append(net.FromObject(ctx, entry.Network)...)
				if diags.HasError() {
					return diags
				}

				subnets := make(map[string]string)
				if !net.Subnets.IsNull() {
					diags.Append(net.Subnets.ElementsAs(ctx, &subnets, false)...)
				}

				infra.Network = &models.GcpNetworkConfig{
					VpcName: net.VpcName.ValueStringPointer(),
					Subnets: subnets,
				}
			}

			infraMap[projectID] = infra
		}
	}

	agentlessSettings := &models.GcpAgentlessScanningSettings{
		WifPrincipal:      settings.WIFPrincipal.ValueString(),
		DeploymentVersion: settings.DeploymentVersion.ValueString(),
		UserInputs:        userInputs,
		Infra:             infraMap,
	}

	updateReq.DspmSettings = agentlessSettings
	updateReq.VulnerabilityScanningSettings = agentlessSettings

	return diags
}

func (r *cloudGoogleRegistrationSettingsResource) triggerHealthCheck(
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
