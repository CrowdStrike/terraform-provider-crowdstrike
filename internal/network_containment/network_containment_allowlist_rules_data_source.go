package networkcontainment

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/containment_allowlist_rules"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &networkContainmentAllowlistRulesDataSource{}
	_ datasource.DataSourceWithConfigure = &networkContainmentAllowlistRulesDataSource{}
)

// getRulesBatchSize bounds how many IDs go into one GET request. IDs are sent
// as repeated query parameters, so this keeps the request URL short.
const getRulesBatchSize = 100

var dataSourceRequiredScopes = []scopes.Scope{
	{Name: "Network Containment Allowlist", Read: true},
}

// NewNetworkContainmentAllowlistRulesDataSource creates a new network containment allowlist rules data source.
func NewNetworkContainmentAllowlistRulesDataSource() datasource.DataSource {
	return &networkContainmentAllowlistRulesDataSource{}
}

// networkContainmentAllowlistRulesDataSource lists every network containment allowlist rule in the CID.
type networkContainmentAllowlistRulesDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

// networkContainmentAllowlistRulesDataSourceModel is the Terraform model of the data source.
type networkContainmentAllowlistRulesDataSourceModel struct {
	Rules types.List `tfsdk:"rules"`
}

func (d *networkContainmentAllowlistRulesDataSource) Configure(
	ctx context.Context,
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

func (d *networkContainmentAllowlistRulesDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_network_containment_allowlist_rules"
}

func (d *networkContainmentAllowlistRulesDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(documentationSection, "Lists every network containment allowlist rule in the CID: the IP ranges, DNS servers, and FQDNs that contained hosts can always communicate with.", dataSourceRequiredScopes),
		Attributes: map[string]schema.Attribute{
			"rules": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The allowlist rules, sorted by `id`.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Identifier of the allowlist rule.",
						},
						"type": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Rule type: `ip_range`, `ip_dns`, or `fqdn`.",
						},
						"rule": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The allowed IP address, CIDR block, DNS server, or domain.",
						},
						"name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Name of the allowlist rule.",
						},
						"allow_subdomains": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Whether one level of subdomains is also allowed. Always `false` for rules other than `fqdn`.",
						},
					},
				},
			},
		},
	}
}

func (d *networkContainmentAllowlistRulesDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data networkContainmentAllowlistRulesDataSourceModel

	rules, err := listAllowlistRules(ctx, d.client)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, dataSourceRequiredScopes))
		return
	}

	ruleModels := make([]allowlistRuleModel, len(rules))
	for i, rule := range rules {
		ruleModels[i].flatten(*rule)
	}

	data.Rules = utils.SliceToListTypeObject(ctx, ruleModels, allowlistRuleModel{}.AttributeTypes(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// listAllowlistRules returns every allowlist rule in the CID, sorted by ID.
// The query endpoint takes no paging parameters and returns every ID at once.
// API errors are returned unwrapped so callers can inspect the status code.
func listAllowlistRules(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
) ([]*models.IpwhitelistinteractorAllowlistRule, error) {
	queryParams := containment_allowlist_rules.NewQueryContainmentAllowlistRulesParamsWithContext(ctx).
		WithFilter(utils.Addr(fmt.Sprintf("context:'%s'", allowlistContext)))

	queryRes, err := apiClient.ContainmentAllowlistRules.QueryContainmentAllowlistRules(queryParams)
	if err != nil {
		return nil, err
	}

	if queryRes == nil || queryRes.Payload == nil {
		return nil, nil
	}

	if err := falcon.AssertNoError(queryRes.Payload.Errors); err != nil {
		return nil, err
	}

	var rules []*models.IpwhitelistinteractorAllowlistRule
	for ids := range slices.Chunk(queryRes.Payload.Resources, getRulesBatchSize) {
		getParams := containment_allowlist_rules.NewGetContainmentAllowlistRulesParamsWithContext(ctx).
			WithIds(ids)

		getRes, err := apiClient.ContainmentAllowlistRules.GetContainmentAllowlistRules(getParams)
		if err != nil {
			return nil, err
		}

		if getRes == nil || getRes.Payload == nil {
			continue
		}

		if err := falcon.AssertNoError(getRes.Payload.Errors); err != nil {
			return nil, err
		}

		for _, rule := range getRes.Payload.Resources {
			if rule != nil {
				rules = append(rules, rule)
			}
		}
	}

	slices.SortFunc(rules, func(a, b *models.IpwhitelistinteractorAllowlistRule) int {
		return cmp.Compare(a.ID, b.ID)
	})

	return rules, nil
}
