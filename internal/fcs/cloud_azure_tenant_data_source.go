package fcs

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_azure_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	dataSourceDocumentationSection                string = "Falcon Cloud Security"
	cloudAzureTenantDataSourceMarkdownDescription string = "This data source provides information about a single Azure Tenant registered in Falcon Cloud Security. Look the tenant up by its Azure tenant ID or by its Falcon Cloud Security registration ID, and reference its attributes in other resources.\n\nThe tenant's Event Hub settings are returned in `eventhub_settings`. They are managed by the `crowdstrike_cloud_azure_tenant_eventhub_settings` resource."
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &cloudAzureTenantDataSource{}
	_ datasource.DataSourceWithConfigure = &cloudAzureTenantDataSource{}
)

// NewCloudAzureTenantDataSource is a helper function to simplify the provider implementation.
func NewCloudAzureTenantDataSource() datasource.DataSource {
	return &cloudAzureTenantDataSource{}
}

// cloudAzureTenantDataSource is the data source implementation.
type cloudAzureTenantDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

// cloudAzureTenantDataSourceModel represents the data source model. It mirrors the
// crowdstrike_cloud_azure_tenant resource's attributes, with all non-lookup fields
// marked Computed, plus eventhub_settings.
//
// Collections are lists rather than the sets the managed resources use. A set is
// what a configurable attribute wants, so Terraform can diff config against state
// without ordering mattering. These attributes are computed only and never diffed
// against config, so a list costs nothing and lets callers index the result.
type cloudAzureTenantDataSourceModel struct {
	TenantId                         types.String `tfsdk:"tenant_id"`
	RegistrationId                   types.String `tfsdk:"registration_id"`
	AccountType                      types.String `tfsdk:"account_type"`
	AppRegistrationId                types.String `tfsdk:"cs_azure_client_id"`
	CsInfraRegion                    types.String `tfsdk:"cs_infra_location"`
	CsInfraSubscriptionId            types.String `tfsdk:"cs_infra_subscription_id"`
	Environment                      types.String `tfsdk:"environment"`
	SubscriptionIds                  types.List   `tfsdk:"subscription_ids"`
	ManagementGroupIds               types.List   `tfsdk:"management_group_ids"`
	MicrosoftGraphPermissionIds      types.List   `tfsdk:"microsoft_graph_permission_ids"`
	ResourceNamePrefix               types.String `tfsdk:"resource_name_prefix"`
	ResourceNameSuffix               types.String `tfsdk:"resource_name_suffix"`
	Tags                             types.Map    `tfsdk:"tags"`
	RealtimeVisibility               types.Object `tfsdk:"realtime_visibility"`
	DSPM                             types.Object `tfsdk:"dspm"`
	VulnerabilityScanning            types.Object `tfsdk:"vulnerability_scanning"`
	AgentlessScanningSubscriptionIds types.List   `tfsdk:"agentless_scanning_subscription_ids"`
	EventhubSettings                 types.List   `tfsdk:"eventhub_settings"`
}

// wrap converts an API registration into the data source model.
//
// Every collection reports empty as empty rather than null, so callers can use
// for_each and length() on the result without guarding with coalesce.
func (m *cloudAzureTenantDataSourceModel) wrap(
	ctx context.Context,
	registration models.AzureTenantRegistration,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.TenantId = types.StringPointerValue(registration.TenantID)
	m.RegistrationId = flex.StringValueToFramework(registration.RegistrationID)
	m.AccountType = types.StringValue(registration.AccountType)
	m.AppRegistrationId = types.StringValue(registration.AppRegistrationID)
	m.CsInfraRegion = types.StringPointerValue(registration.CsInfraRegion)
	m.CsInfraSubscriptionId = types.StringPointerValue(registration.CsInfraSubscriptionID)
	m.Environment = types.StringPointerValue(registration.Environment)
	m.ResourceNamePrefix = types.StringPointerValue(registration.ResourceNamePrefix)
	m.ResourceNameSuffix = types.StringPointerValue(registration.ResourceNameSuffix)

	subscriptionIds, d := flex.FlattenStringValueListOrEmpty(ctx, registration.SubscriptionIds)
	diags.Append(d...)
	m.SubscriptionIds = subscriptionIds

	managementGroupIds, d := flex.FlattenStringValueListOrEmpty(ctx, registration.ManagementGroupIds)
	diags.Append(d...)
	m.ManagementGroupIds = managementGroupIds

	graphPermissionIds, d := flex.FlattenStringValueListOrEmpty(ctx, registration.MicrosoftGraphPermissionIds)
	diags.Append(d...)
	m.MicrosoftGraphPermissionIds = graphPermissionIds

	tags, d := flex.FlattenStringValueMapOrEmpty(ctx, registration.Tags)
	diags.Append(d...)
	m.Tags = tags

	features, d := flattenAzureTenantFeatures(ctx, registration)
	diags.Append(d...)
	m.RealtimeVisibility = features.RealtimeVisibility
	m.DSPM = features.DSPM
	m.VulnerabilityScanning = features.VulnerabilityScanning

	agentlessSubscriptionIds, d := flex.FlattenStringValueListOrEmpty(
		ctx,
		features.AgentlessScanningSubscriptions,
	)
	diags.Append(d...)
	m.AgentlessScanningSubscriptionIds = agentlessSubscriptionIds

	// flattenEventhubSettings never returns a nil slice, so this is an empty list
	// when the tenant has no event hubs.
	eventhubSettingsList, d := types.ListValueFrom(
		ctx,
		types.ObjectType{AttrTypes: eventhubSettings{}.attrTypes()},
		flattenEventhubSettings(registration),
	)
	diags.Append(d...)
	m.EventhubSettings = eventhubSettingsList

	return diags
}

// Configure adds the provider configured client to the data source.
func (d *cloudAzureTenantDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	d.client = providerConfig.Client
}

// Metadata returns the data source type name.
func (d *cloudAzureTenantDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_azure_tenant"
}

// Schema defines the schema for the data source.
func (d *cloudAzureTenantDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			dataSourceDocumentationSection,
			cloudAzureTenantDataSourceMarkdownDescription,
			azureRegistrationReadScopes,
		),
		Attributes: map[string]schema.Attribute{
			"tenant_id": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The Azure tenant ID (directory ID) of the registered tenant, for example `00000000-0000-0000-0000-000000000000`. Exactly one of `tenant_id` or `registration_id` must be provided.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("tenant_id"),
						path.MatchRoot("registration_id"),
					),
				},
			},
			"registration_id": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The Falcon Cloud Security registration ID of the Azure Tenant. This is an internal identifier for the registration record. Exactly one of `tenant_id` or `registration_id` must be provided.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"account_type": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The Azure Tenant account type. Value is 'commercial' for Commercial cloud accounts. For GovCloud environments, value can be either 'commercial' or 'gov' depending on the account type",
			},
			"cs_azure_client_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Client ID of CrowdStrike's multi-tenant application in Azure. This is used to establish the connection between Azure and Falcon Cloud Security.",
			},
			"cs_infra_location": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Azure location where CrowdStrike infrastructure resources (such as Event Hubs) were deployed.",
			},
			"cs_infra_subscription_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Azure subscription ID where CrowdStrike infrastructure resources (such as Event Hubs) were deployed.",
			},
			"management_group_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				MarkdownDescription: "A list of Azure management group IDs monitored. All subscriptions under the management groups are monitored.",
			},
			"microsoft_graph_permission_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				MarkdownDescription: "A list of Microsoft Graph permission IDs assigned to the service principal.",
			},
			"subscription_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				MarkdownDescription: "A list of subscription IDs registered in addition to any subscriptions that are targeted by management_group_ids.",
			},
			"realtime_visibility": schema.SingleNestedAttribute{
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether real-time visibility and detection is enabled",
					},
				},
				MarkdownDescription: "Real-time visibility and detection configuration.",
			},
			"dspm": schema.SingleNestedAttribute{
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether data security posture management (DSPM) is enabled",
					},
				},
				MarkdownDescription: "Data security posture management (DSPM) configuration.",
			},
			"vulnerability_scanning": schema.SingleNestedAttribute{
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether Vulnerability Scanning is enabled",
					},
				},
				MarkdownDescription: "Vulnerability Scanning configuration.",
			},
			"resource_name_prefix": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The prefix added to resources created during onboarding.",
			},
			"resource_name_suffix": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The suffix added to resources created during onboarding.",
			},
			"environment": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The environment added to resources created during onboarding.",
			},
			"tags": schema.MapAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				MarkdownDescription: "Tags applied to managed resources.",
			},
			"agentless_scanning_subscription_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				MarkdownDescription: "Azure subscription IDs where agentless scanning is enabled.",
			},
			"eventhub_settings": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The Azure Event Hub settings attached to the tenant registration, empty when none are attached. These are managed by the `crowdstrike_cloud_azure_tenant_eventhub_settings` resource.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The Azure Event Hub ID.",
						},
						"type": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The type of Event Hub, either `activity_logs` or `entra_logs`.",
						},
						"consumer_group": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The Azure Event Hub consumer group name used to read events from the Event Hub.",
						},
					},
				},
			},
		},
	}
}

// Read refreshes the Terraform state with the latest data.
func (d *cloudAzureTenantDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	tflog.Trace(ctx, "Starting Azure Tenant data source read")

	var data cloudAzureTenantDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	registration, diags := d.lookupAzureTenant(
		ctx,
		data.TenantId.ValueString(),
		data.RegistrationId.ValueString(),
	)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(data.wrap(ctx, *registration)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// lookupAzureTenant resolves a single Azure Tenant registration by Azure tenant ID
// or by Falcon Cloud Security registration ID, whichever the configuration set.
func (d *cloudAzureTenantDataSource) lookupAzureTenant(
	ctx context.Context,
	tenantID string,
	registrationID string,
) (*models.AzureTenantRegistration, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := &cloud_azure_registration.CloudRegistrationAzureGetRegistrationParams{Context: ctx}
	attribute, value := "tenant_id", tenantID
	if tenantID != "" {
		params.TenantID = &tenantID
	} else {
		attribute, value = "registration_id", registrationID
		params.RegistrationID = &registrationID
	}

	tflog.Debug(ctx, "[datasource] Looking up Azure Tenant", map[string]any{
		attribute: value,
	})

	lookup := fmt.Sprintf("%s %q", attribute, value)
	notFoundDetail := fmt.Sprintf("No Azure Tenant found with %s.", lookup)

	res, err := d.client.CloudAzureRegistration.CloudRegistrationAzureGetRegistration(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Read, err, azureRegistrationReadScopes, tferrors.WithNotFoundDetail(notFoundDetail),
		))
		return nil, diags
	}

	if res == nil || res.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		diags.Append(diag)
		return nil, diags
	}

	resources := res.Payload.Resources

	if len(resources) == 0 {
		diags.Append(tferrors.NewNotFoundError(notFoundDetail))
		return nil, diags
	}

	if len(resources) > 1 {
		diags.AddError(
			"Multiple Azure Tenants Found",
			fmt.Sprintf(
				"%d Azure Tenants matched %s, but exactly one is required. That identifier is expected to be unique, so this likely indicates duplicate registrations in Falcon Cloud Security...",
				len(resources),
				lookup,
			),
		)
		return nil, diags
	}

	if resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	return resources[0], diags
}
