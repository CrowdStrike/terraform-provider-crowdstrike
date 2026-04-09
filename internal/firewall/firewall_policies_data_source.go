package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource                   = &firewallPoliciesDataSource{}
	_ datasource.DataSourceWithConfigure      = &firewallPoliciesDataSource{}
	_ datasource.DataSourceWithValidateConfig = &firewallPoliciesDataSource{}
)

// NewFirewallPoliciesDataSource is a helper function to simplify the provider implementation.
func NewFirewallPoliciesDataSource() datasource.DataSource {
	return &firewallPoliciesDataSource{}
}

// firewallPoliciesDataSource is the data source implementation.
type firewallPoliciesDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type firewallPolicyDataModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Description       types.String `tfsdk:"description"`
	PlatformName      types.String `tfsdk:"platform_name"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	CreatedBy         types.String `tfsdk:"created_by"`
	CreatedTimestamp  types.String `tfsdk:"created_timestamp"`
	ModifiedBy        types.String `tfsdk:"modified_by"`
	ModifiedTimestamp types.String `tfsdk:"modified_timestamp"`
}

func (m firewallPolicyDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                 types.StringType,
		"name":               types.StringType,
		"description":        types.StringType,
		"platform_name":      types.StringType,
		"enabled":            types.BoolType,
		"created_by":         types.StringType,
		"created_timestamp":  types.StringType,
		"modified_by":        types.StringType,
		"modified_timestamp": types.StringType,
	}
}

type firewallPoliciesDataSourceModel struct {
	Filter       types.String `tfsdk:"filter"`
	IDs          types.List   `tfsdk:"ids"`
	Name         types.String `tfsdk:"name"`
	PlatformName types.String `tfsdk:"platform_name"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	Policies     types.List   `tfsdk:"policies"`
}

func (m *firewallPoliciesDataSourceModel) wrap(ctx context.Context, policies []*models.FirewallPolicyV1) diag.Diagnostics {
	var diags diag.Diagnostics
	policyModels := make([]firewallPolicyDataModel, 0, len(policies))
	for _, policy := range policies {
		if policy == nil {
			continue
		}

		policyModel := firewallPolicyDataModel{}
		policyModel.ID = types.StringPointerValue(policy.ID)
		policyModel.Name = types.StringPointerValue(policy.Name)
		policyModel.Description = types.StringPointerValue(policy.Description)
		policyModel.PlatformName = types.StringPointerValue(policy.PlatformName)
		policyModel.Enabled = types.BoolPointerValue(policy.Enabled)
		policyModel.CreatedBy = types.StringPointerValue(policy.CreatedBy)
		if policy.CreatedTimestamp != nil {
			policyModel.CreatedTimestamp = types.StringValue(policy.CreatedTimestamp.String())
		}
		policyModel.ModifiedBy = types.StringPointerValue(policy.ModifiedBy)
		if policy.ModifiedTimestamp != nil {
			policyModel.ModifiedTimestamp = types.StringValue(policy.ModifiedTimestamp.String())
		}

		policyModels = append(policyModels, policyModel)
	}

	m.Policies = utils.SliceToListTypeObject(ctx, policyModels, firewallPolicyDataModel{}.AttributeTypes(), &diags)
	return diags
}

func (m firewallPoliciesDataSourceModel) hasIndividualFilters() bool {
	return utils.IsKnown(m.Name) ||
		utils.IsKnown(m.Enabled) ||
		utils.IsKnown(m.PlatformName)
}

// Configure adds the provider configured client to the data source.
func (d *firewallPoliciesDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(config.ProviderConfig)
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

	d.client = config.Client
}

// Metadata returns the data source type name.
func (d *firewallPoliciesDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_firewall_policies"
}

// Schema defines the schema for the data source.
func (d *firewallPoliciesDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Firewall Management",
			"This data source provides information about firewall policies in Falcon.",
			apiScopesRead,
		),
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				Optional:    true,
				Description: "FQL filter to apply to the firewall policies query. Cannot be used together with 'ids' or other filter attributes.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of firewall policy IDs to retrieve. Cannot be used together with 'filter' or other filter attributes.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.LengthBetween(32, 32),
					),
					listvalidator.SizeAtLeast(1),
					listvalidator.UniqueValues(),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by name. Supports wildcard matching with '*'. Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"platform_name": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by platform (Windows, Linux, Mac). Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Linux", "Mac"),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Filter policies by enabled status. Cannot be used together with 'filter' or 'ids'.",
			},
			"policies": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of firewall policies",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The firewall policy ID",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "The firewall policy name",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "The firewall policy description",
						},
						"platform_name": schema.StringAttribute{
							Computed:    true,
							Description: "The platform name (Windows, Linux, Mac)",
						},
						"enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the firewall policy is enabled",
						},
						"created_by": schema.StringAttribute{
							Computed:    true,
							Description: "User who created the policy",
						},
						"created_timestamp": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the policy was created",
						},
						"modified_by": schema.StringAttribute{
							Computed:    true,
							Description: "User who last modified the policy",
						},
						"modified_timestamp": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the policy was last modified",
						},
					},
				},
			},
		},
	}
}

// ValidateConfig validates the data source configuration.
func (d *firewallPoliciesDataSource) ValidateConfig(
	ctx context.Context,
	req datasource.ValidateConfigRequest,
	resp *datasource.ValidateConfigResponse,
) {
	var data firewallPoliciesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasFilter := utils.IsKnown(data.Filter) && data.Filter.ValueString() != ""
	hasIDs := utils.IsKnown(data.IDs) && len(data.IDs.Elements()) > 0

	filterCount := 0
	if hasFilter {
		filterCount++
	}
	if hasIDs {
		filterCount++
	}
	if data.hasIndividualFilters() {
		filterCount++
	}

	if filterCount > 1 {
		resp.Diagnostics.AddError(
			"Invalid Attribute Combination",
			"Cannot specify 'filter', 'ids', and individual filter attributes together. Please use only one filtering method.",
		)
	}
}

// Read refreshes the Terraform state with the latest data.
func (d *firewallPoliciesDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data firewallPoliciesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := d.getFirewallPolicies(ctx, data.Filter.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if utils.IsKnown(data.IDs) {
		requestedIDs := utils.ListTypeAs[string](ctx, data.IDs, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		policies = filterFirewallPoliciesByIDs(policies, requestedIDs)
	}

	if data.hasIndividualFilters() {
		policies = filterFirewallPoliciesByAttributes(policies, &data)
	}

	resp.Diagnostics.Append(data.wrap(ctx, policies)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *firewallPoliciesDataSource) getFirewallPolicies(
	ctx context.Context,
	filter string,
) ([]*models.FirewallPolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allPolicies []*models.FirewallPolicyV1

	tflog.Debug(ctx, "[datasource] Getting all firewall policies")

	limit := int64(5000)
	offset := int64(0)

	for {
		params := &firewall_policies.QueryCombinedFirewallPoliciesParams{
			Context: ctx,
			Limit:   &limit,
			Offset:  &offset,
		}

		if filter != "" {
			params.Filter = &filter
		}

		res, err := d.client.FirewallPolicies.QueryCombinedFirewallPolicies(params)
		if err != nil {
			diags.AddError(
				"Failed to query firewall policies",
				fmt.Sprintf("Failed to query firewall policies: %s", err.Error()),
			)
			return allPolicies, diags
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			break
		}

		allPolicies = append(allPolicies, res.Payload.Resources...)

		if res.Payload.Meta == nil || res.Payload.Meta.Pagination == nil ||
			res.Payload.Meta.Pagination.Total == nil {
			break
		}

		offset += limit
		if offset >= *res.Payload.Meta.Pagination.Total {
			break
		}
	}

	return allPolicies, diags
}

func filterFirewallPoliciesByIDs(policies []*models.FirewallPolicyV1, requestedIDs []string) []*models.FirewallPolicyV1 {
	idMap := make(map[string]bool, len(requestedIDs))
	for _, id := range requestedIDs {
		idMap[id] = true
	}

	filtered := make([]*models.FirewallPolicyV1, 0, len(requestedIDs))
	for _, policy := range policies {
		if policy != nil && policy.ID != nil && idMap[*policy.ID] {
			filtered = append(filtered, policy)
		}
	}
	return filtered
}

func filterFirewallPoliciesByAttributes(policies []*models.FirewallPolicyV1, filters *firewallPoliciesDataSourceModel) []*models.FirewallPolicyV1 {
	filtered := make([]*models.FirewallPolicyV1, 0, len(policies))
	for _, policy := range policies {
		if policy == nil {
			continue
		}

		if !filters.Name.IsNull() {
			if policy.Name == nil || !utils.MatchesWildcard(*policy.Name, filters.Name.ValueString()) {
				continue
			}
		}

		if !filters.Enabled.IsNull() {
			if policy.Enabled == nil || *policy.Enabled != filters.Enabled.ValueBool() {
				continue
			}
		}

		if !filters.PlatformName.IsNull() {
			if policy.PlatformName == nil || !strings.EqualFold(*policy.PlatformName, filters.PlatformName.ValueString()) {
				continue
			}
		}

		filtered = append(filtered, policy)
	}
	return filtered
}
