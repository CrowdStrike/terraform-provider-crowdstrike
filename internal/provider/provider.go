package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	cloudcompliance "github.com/crowdstrike/terraform-provider-crowdstrike/internal/cloud_compliance"
	cloudposture "github.com/crowdstrike/terraform-provider-crowdstrike/internal/cloud_posture"
	contentupdatepolicy "github.com/crowdstrike/terraform-provider-crowdstrike/internal/content_update_policy"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fcs"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fim"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	preventionpolicy "github.com/crowdstrike/terraform-provider-crowdstrike/internal/prevention_policy"
	sensorupdatepolicy "github.com/crowdstrike/terraform-provider-crowdstrike/internal/sensor_update_policy"
	sensorvisibilityexclusion "github.com/crowdstrike/terraform-provider-crowdstrike/internal/sensor_visibility_exclusion"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
)

// Ensure ScaffoldingProvider satisfies various provider interfaces.
var _ provider.Provider = &CrowdStrikeProvider{}
var _ provider.ProviderWithFunctions = &CrowdStrikeProvider{}

// CrowdStrikeProvider defines the provider implementation.
type CrowdStrikeProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// CrowdStrikeProviderModel describes the provider data model.
type CrowdStrikeProviderModel struct {
	Cloud        types.String `tfsdk:"cloud"`
	ClientSecret types.String `tfsdk:"client_secret"`
	ClientId     types.String `tfsdk:"client_id"`
	MemberCID    types.String `tfsdk:"member_cid"`
}

func (p *CrowdStrikeProvider) Metadata(
	ctx context.Context,
	req provider.MetadataRequest,
	resp *provider.MetadataResponse,
) {
	resp.TypeName = "crowdstrike"
	resp.Version = p.version
}

func (p *CrowdStrikeProvider) Schema(
	ctx context.Context,
	req provider.SchemaRequest,
	resp *provider.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Use the CrowdStrike provider to interact & manage many resources supported by the CrowdStrike Falcon Platform. You must configure the provider with your CrowdStrike API credentials before you can use it.",
		Attributes: map[string]schema.Attribute{
			"client_id": schema.StringAttribute{
				MarkdownDescription: "Falcon Client Id for authenticating to the CrowdStrike APIs. Will use FALCON_CLIENT_ID environment variable when left blank.",
				Optional:            true,
				Sensitive:           true,
			},
			"client_secret": schema.StringAttribute{
				MarkdownDescription: "Falcon Client Secret used for authenticating to the CrowdStrike APIs. Will use FALCON_CLIENT_SECRET environment variable when left blank.",
				Optional:            true,
				Sensitive:           true,
			},
			"member_cid": schema.StringAttribute{
				MarkdownDescription: "For MSSP Master CIDs, optionally lock the token to act on behalf of this member CID",
				Optional:            true,
				Sensitive:           false,
			},
			"cloud": schema.StringAttribute{
				MarkdownDescription: "Falcon Cloud to authenticate to. Valid values are autodiscover, us-1, us-2, eu-1, us-gov-1. Will use FALCON_CLOUD environment variable when left blank.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive(
						"autodiscover",
						"us-1",
						"us-2",
						"eu-1",
						"us-gov-1",
					),
				},
			},
		},
	}
}

func (p *CrowdStrikeProvider) Configure(
	ctx context.Context,
	req provider.ConfigureRequest,
	resp *provider.ConfigureResponse,
) {
	var config CrowdStrikeProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if config.Cloud.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("cloud"),
			"Unknown CrowdStrike API Cloud",
			"The provider cannot create the CrowdStrike API client as there is an unknown configuration value for the CrowdStrike API cloud. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the FALCON_CLOUD environment variable.",
		)
	}

	if config.ClientId.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("client_id"),
			"Unknown CrowdStrike API Client ID",
			"The provider cannot create the CrowdStrike API client as there is an unknown configuration value for the CrowdStrike API Client ID. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the FALCON_CLIENT_ID environment variable.",
		)
	}

	if config.ClientSecret.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("client_secret"),
			"Unknown CrowdStrike API Client Secret",
			"The provider cannot create the CrowdStrike API client as there is an unknown configuration value for the CrowdStrike API Client Secret. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the FALCON_CLIENT_SECRET environment variable.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Default to env variables, but override
	// with Terraform configuration if set.
	cloud := os.Getenv("FALCON_CLOUD")
	clientId := os.Getenv("FALCON_CLIENT_ID")
	clientSecret := os.Getenv("FALCON_CLIENT_SECRET")

	if !config.Cloud.IsNull() {
		cloud = config.Cloud.ValueString()
	}

	if cloud == "" {
		cloud = "autodiscover"
	}

	if !config.ClientId.IsNull() {
		clientId = config.ClientId.ValueString()
	}

	if !config.ClientSecret.IsNull() {
		clientSecret = config.ClientSecret.ValueString()
	}

	if clientId == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("client_id"),
			"Missing CrowdStrike API Client ID",
			"The provider cannot create the CrowdStrike API client as there is a missing or empty value for the CrowdStrike API Client ID. "+
				"Set the client_id value in the configuration or use the FALCON_CLIENT_ID environment variable. "+
				"If either is already set, ensure the value is not empty.",
		)
	}

	if clientSecret == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("client_secret"),
			"Missing CrowdStrike API Client Secret",
			"The provider cannot create the CrowdStrike API client as there is a missing or empty value for the CrowdStrike API Client Secret. "+
				"Set the client_secret value in the configuration or use the FALCON_CLIENT_SECRET environment variable. "+
				"If either is already set, ensure the value is not empty.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "crowdstrike_cloud", cloud)
	ctx = tflog.SetField(ctx, "crowdstrike_client_id", clientId)
	ctx = tflog.SetField(ctx, "crowdstrike_client_secret", clientSecret)
	ctx = tflog.SetField(ctx, "crowdstrike_member_cid", config.MemberCID.ValueString())
	ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "crowdstrike_client_id")
	ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "crowdstrike_client_secret")

	tflog.Debug(ctx, "Creating CrowdStrike client")

	apiConfig := falcon.ApiConfig{
		Cloud:             falcon.Cloud(cloud),
		ClientId:          clientId,
		ClientSecret:      clientSecret,
		UserAgentOverride: fmt.Sprintf("terraform-provider-crowdstrike/%s", p.version),
		Context:           context.Background(),
		HostOverride:      os.Getenv("HOST_OVERRIDE"),
		TransportDecorator: falcon.TransportDecorator(func(r http.RoundTripper) http.RoundTripper {
			return logging.NewLoggingHTTPTransport(r)
		}),
	}

	if !config.MemberCID.IsNull() {
		apiConfig.MemberCID = config.MemberCID.ValueString()
	}

	client, err := falcon.NewClient(&apiConfig)

	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create CrowdStrike API Client",
			"An unexpected error occurred when creating the CrowdStrike API client. "+
				"If the error is not clear, please open a issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike\n\n"+
				"CrowdStrike Client Error: "+err.Error(),
		)
	}

	resp.DataSourceData = client
	resp.ResourceData = client

	tflog.Info(ctx, "Configured CrowdStrike client", map[string]any{"success": true})
}

func (p *CrowdStrikeProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		sensorupdatepolicy.NewSensorUpdatePolicyResource,
		sensorupdatepolicy.NewDefaultSensorUpdatePolicyResource,
		sensorupdatepolicy.NewSensorUpdatePolicyHostGroupAttachmentResource,
		sensorupdatepolicy.NewSensorUpdatePolicyPrecedenceResource,
		hostgroups.NewHostGroupResource,
		preventionpolicy.NewPreventionPolicyWindowsResource,
		preventionpolicy.NewDefaultPreventionPolicyMacResource,
		preventionpolicy.NewDefaultPreventionPolicyLinuxResource,
		preventionpolicy.NewDefaultPreventionPolicyWindowsResource,
		preventionpolicy.NewPreventionPolicyLinuxResource,
		preventionpolicy.NewPreventionPolicyMacResource,
		preventionpolicy.NewPreventionPolicyAttachmentResource,
		preventionpolicy.NewPreventionPolicyPrecedenceResource,
		fim.NewFIMPolicyResource,
		fim.NewFilevantageRuleGroupResource,
		fim.NewFilevantagePolicyPrecedenceResource,
		fcs.NewCloudAWSAccountResource,
		fcs.NewCloudAzureTenantEventhubSettingsResource,
		fcs.NewCloudAzureTenantResource,
		contentupdatepolicy.NewContentPolicyResource,
		contentupdatepolicy.NewDefaultContentUpdatePolicyResource,
		contentupdatepolicy.NewContentUpdatePolicyPrecedenceResource,
		sensorvisibilityexclusion.NewSensorVisibilityExclusionResource,
		cloudposture.NewCloudPostureCustomRuleResource,
	}
}

func (p *CrowdStrikeProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		sensorupdatepolicy.NewSensorUpdateBuildsDataSource,
		fcs.NewCloudAwsAccountsDataSource,
		contentupdatepolicy.NewContentCategoryVersionsDataSource,
		cloudposture.NewCloudPostureRulesDataSource,
		cloudcompliance.NewCloudComplianceFrameworkControlDataSource,
	}
}

func (p *CrowdStrikeProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &CrowdStrikeProvider{
			version: version,
		}
	}
}
