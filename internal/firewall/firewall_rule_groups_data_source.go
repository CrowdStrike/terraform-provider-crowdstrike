package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_management"
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
	_ datasource.DataSource                   = &firewallRuleGroupsDataSource{}
	_ datasource.DataSourceWithConfigure      = &firewallRuleGroupsDataSource{}
	_ datasource.DataSourceWithValidateConfig = &firewallRuleGroupsDataSource{}
)

// NewFirewallRuleGroupsDataSource is a helper function to simplify the provider implementation.
func NewFirewallRuleGroupsDataSource() datasource.DataSource {
	return &firewallRuleGroupsDataSource{}
}

// firewallRuleGroupsDataSource is the data source implementation.
type firewallRuleGroupsDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type firewallRuleGroupDataModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Platform    types.String `tfsdk:"platform"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	CreatedBy   types.String `tfsdk:"created_by"`
	CreatedOn   types.String `tfsdk:"created_on"`
	ModifiedBy  types.String `tfsdk:"modified_by"`
	ModifiedOn  types.String `tfsdk:"modified_on"`
	RuleCount   types.Int64  `tfsdk:"rule_count"`
}

func (m firewallRuleGroupDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":          types.StringType,
		"name":        types.StringType,
		"description": types.StringType,
		"platform":    types.StringType,
		"enabled":     types.BoolType,
		"created_by":  types.StringType,
		"created_on":  types.StringType,
		"modified_by": types.StringType,
		"modified_on": types.StringType,
		"rule_count":  types.Int64Type,
	}
}

type firewallRuleGroupsDataSourceModel struct {
	Filter     types.String `tfsdk:"filter"`
	IDs        types.List   `tfsdk:"ids"`
	Name       types.String `tfsdk:"name"`
	Platform   types.String `tfsdk:"platform"`
	Enabled    types.Bool   `tfsdk:"enabled"`
	RuleGroups types.List   `tfsdk:"rule_groups"`
}

func (m *firewallRuleGroupsDataSourceModel) wrap(ctx context.Context, ruleGroups []*models.FwmgrAPIRuleGroupV1) diag.Diagnostics {
	var diags diag.Diagnostics
	rgModels := make([]firewallRuleGroupDataModel, 0, len(ruleGroups))
	for _, rg := range ruleGroups {
		if rg == nil {
			continue
		}

		rgModel := firewallRuleGroupDataModel{}
		rgModel.ID = types.StringPointerValue(rg.ID)
		rgModel.Name = types.StringPointerValue(rg.Name)
		rgModel.Description = types.StringPointerValue(rg.Description)
		rgModel.Platform = types.StringPointerValue(rg.Platform)
		rgModel.Enabled = types.BoolPointerValue(rg.Enabled)
		rgModel.CreatedBy = types.StringPointerValue(rg.CreatedBy)
		rgModel.CreatedOn = types.StringPointerValue(rg.CreatedOn)
		rgModel.ModifiedBy = types.StringPointerValue(rg.ModifiedBy)
		rgModel.ModifiedOn = types.StringPointerValue(rg.ModifiedOn)
		if rg.RuleIds != nil {
			rgModel.RuleCount = types.Int64Value(int64(len(rg.RuleIds)))
		} else {
			rgModel.RuleCount = types.Int64Value(0)
		}

		rgModels = append(rgModels, rgModel)
	}

	m.RuleGroups = utils.SliceToListTypeObject(ctx, rgModels, firewallRuleGroupDataModel{}.AttributeTypes(), &diags)
	return diags
}

func (m firewallRuleGroupsDataSourceModel) hasIndividualFilters() bool {
	return utils.IsKnown(m.Name) ||
		utils.IsKnown(m.Enabled) ||
		utils.IsKnown(m.Platform)
}

// Configure adds the provider configured client to the data source.
func (d *firewallRuleGroupsDataSource) Configure(
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
func (d *firewallRuleGroupsDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_firewall_rule_groups"
}

// Schema defines the schema for the data source.
func (d *firewallRuleGroupsDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Firewall Management",
			"This data source provides information about firewall rule groups in Falcon.",
			apiScopesRead,
		),
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				Optional:    true,
				Description: "FQL filter to apply to the firewall rule groups query. Cannot be used together with 'ids' or other filter attributes.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of firewall rule group IDs to retrieve. Cannot be used together with 'filter' or other filter attributes.",
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
				Description: "Filter rule groups by name. Supports wildcard matching with '*'. Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"platform": schema.StringAttribute{
				Optional:    true,
				Description: "Filter rule groups by platform (Windows, Linux, Mac). Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Linux", "Mac"),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Filter rule groups by enabled status. Cannot be used together with 'filter' or 'ids'.",
			},
			"rule_groups": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of firewall rule groups",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The firewall rule group ID",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "The firewall rule group name",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "The firewall rule group description",
						},
						"platform": schema.StringAttribute{
							Computed:    true,
							Description: "The platform (Windows, Linux, Mac)",
						},
						"enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the rule group is enabled",
						},
						"created_by": schema.StringAttribute{
							Computed:    true,
							Description: "User who created the rule group",
						},
						"created_on": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the rule group was created",
						},
						"modified_by": schema.StringAttribute{
							Computed:    true,
							Description: "User who last modified the rule group",
						},
						"modified_on": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the rule group was last modified",
						},
						"rule_count": schema.Int64Attribute{
							Computed:    true,
							Description: "Number of rules in the rule group",
						},
					},
				},
			},
		},
	}
}

// ValidateConfig validates the data source configuration.
func (d *firewallRuleGroupsDataSource) ValidateConfig(
	ctx context.Context,
	req datasource.ValidateConfigRequest,
	resp *datasource.ValidateConfigResponse,
) {
	var data firewallRuleGroupsDataSourceModel
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
func (d *firewallRuleGroupsDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data firewallRuleGroupsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleGroups, diags := d.getFirewallRuleGroups(ctx, data.Filter.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if utils.IsKnown(data.IDs) {
		requestedIDs := utils.ListTypeAs[string](ctx, data.IDs, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		ruleGroups = filterRuleGroupsByIDs(ruleGroups, requestedIDs)
	}

	if data.hasIndividualFilters() {
		ruleGroups = filterRuleGroupsByAttributes(ruleGroups, &data)
	}

	resp.Diagnostics.Append(data.wrap(ctx, ruleGroups)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *firewallRuleGroupsDataSource) getFirewallRuleGroups(
	ctx context.Context,
	filter string,
) ([]*models.FwmgrAPIRuleGroupV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allRuleGroups []*models.FwmgrAPIRuleGroupV1

	tflog.Debug(ctx, "[datasource] Getting all firewall rule groups")

	// First, query for IDs
	queryParams := &firewall_management.QueryRuleGroupsParams{
		Context: ctx,
	}
	if filter != "" {
		queryParams.Filter = &filter
	}

	queryRes, err := d.client.FirewallManagement.QueryRuleGroups(queryParams)
	if err != nil {
		diags.AddError(
			"Failed to query firewall rule groups",
			fmt.Sprintf("Failed to query firewall rule groups: %s", err.Error()),
		)
		return allRuleGroups, diags
	}

	if queryRes == nil || queryRes.Payload == nil || len(queryRes.Payload.Resources) == 0 {
		return allRuleGroups, diags
	}

	// Then get full details
	getParams := &firewall_management.GetRuleGroupsParams{
		Context: ctx,
		Ids:     queryRes.Payload.Resources,
	}

	getRes, err := d.client.FirewallManagement.GetRuleGroups(getParams)
	if err != nil {
		diags.AddError(
			"Failed to get firewall rule groups",
			fmt.Sprintf("Failed to get firewall rule groups: %s", err.Error()),
		)
		return allRuleGroups, diags
	}

	if getRes != nil && getRes.Payload != nil {
		allRuleGroups = getRes.Payload.Resources
	}

	return allRuleGroups, diags
}

func filterRuleGroupsByIDs(ruleGroups []*models.FwmgrAPIRuleGroupV1, requestedIDs []string) []*models.FwmgrAPIRuleGroupV1 {
	idMap := make(map[string]bool, len(requestedIDs))
	for _, id := range requestedIDs {
		idMap[id] = true
	}

	filtered := make([]*models.FwmgrAPIRuleGroupV1, 0, len(requestedIDs))
	for _, rg := range ruleGroups {
		if rg != nil && rg.ID != nil && idMap[*rg.ID] {
			filtered = append(filtered, rg)
		}
	}
	return filtered
}

func filterRuleGroupsByAttributes(ruleGroups []*models.FwmgrAPIRuleGroupV1, filters *firewallRuleGroupsDataSourceModel) []*models.FwmgrAPIRuleGroupV1 {
	filtered := make([]*models.FwmgrAPIRuleGroupV1, 0, len(ruleGroups))
	for _, rg := range ruleGroups {
		if rg == nil {
			continue
		}

		if !filters.Name.IsNull() {
			if rg.Name == nil || !utils.MatchesWildcard(*rg.Name, filters.Name.ValueString()) {
				continue
			}
		}

		if !filters.Enabled.IsNull() {
			if rg.Enabled == nil || *rg.Enabled != filters.Enabled.ValueBool() {
				continue
			}
		}

		if !filters.Platform.IsNull() {
			if rg.Platform == nil || !strings.EqualFold(*rg.Platform, filters.Platform.ValueString()) {
				continue
			}
		}

		filtered = append(filtered, rg)
	}
	return filtered
}
