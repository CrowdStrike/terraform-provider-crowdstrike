package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
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
	Rules       types.List   `tfsdk:"rules"`
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
		"rules":       types.ListType{ElemType: types.ObjectType{AttrTypes: dataSourceFirewallRuleModel{}.attrTypes()}},
	}
}

type dataSourceFirewallRuleModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Description     types.String `tfsdk:"description"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	Action          types.String `tfsdk:"action"`
	Direction       types.String `tfsdk:"direction"`
	Protocol        types.String `tfsdk:"protocol"`
	AddressFamily   types.String `tfsdk:"address_family"`
	LocalAddress    types.List   `tfsdk:"local_address"`
	RemoteAddress   types.List   `tfsdk:"remote_address"`
	LocalPort       types.List   `tfsdk:"local_port"`
	RemotePort      types.List   `tfsdk:"remote_port"`
	Fqdn            types.String `tfsdk:"fqdn"`
	NetworkLocation types.String `tfsdk:"network_location"`
	ExecutablePath  types.String `tfsdk:"executable_path"`
	ServiceName     types.String `tfsdk:"service_name"`
	IcmpType        types.String `tfsdk:"icmp_type"`
	IcmpCode        types.String `tfsdk:"icmp_code"`
	WatchMode       types.Bool   `tfsdk:"watch_mode"`
}

func (f dataSourceFirewallRuleModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":               types.StringType,
		"name":             types.StringType,
		"description":      types.StringType,
		"enabled":          types.BoolType,
		"action":           types.StringType,
		"direction":        types.StringType,
		"protocol":         types.StringType,
		"address_family":   types.StringType,
		"local_address":    types.ListType{ElemType: types.ObjectType{AttrTypes: addressRangeAttrTypes()}},
		"remote_address":   types.ListType{ElemType: types.ObjectType{AttrTypes: addressRangeAttrTypes()}},
		"local_port":       types.ListType{ElemType: types.ObjectType{AttrTypes: portRangeAttrTypes()}},
		"remote_port":      types.ListType{ElemType: types.ObjectType{AttrTypes: portRangeAttrTypes()}},
		"fqdn":             types.StringType,
		"network_location": types.StringType,
		"executable_path":  types.StringType,
		"service_name":     types.StringType,
		"icmp_type":        types.StringType,
		"icmp_code":        types.StringType,
		"watch_mode":       types.BoolType,
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

func (m *firewallRuleGroupsDataSourceModel) wrap(
	ctx context.Context,
	ruleGroups []*models.FwmgrAPIRuleGroupV1,
	rulesByFamily map[string]*models.FwmgrFirewallRuleV1,
) diag.Diagnostics {
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
		rgModel.Platform = types.StringNull()
		if rg.Platform != nil {
			rgModel.Platform = types.StringValue(normalizePlatform(*rg.Platform))
		}
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

		rulesList, d := wrapRuleGroupRules(ctx, rg.RuleIds, rulesByFamily)
		diags.Append(d...)
		rgModel.Rules = rulesList

		rgModels = append(rgModels, rgModel)
	}

	m.RuleGroups = utils.SliceToListTypeObject(ctx, rgModels, firewallRuleGroupDataModel{}.AttributeTypes(), &diags)
	return diags
}

// wrapRuleGroupRules maps a rule group's rule IDs to the data source rules list,
// reusing the resource's wrapRules logic.
// A rule group's RuleIds are rule family IDs, so rulesByFamily is keyed by family.
func wrapRuleGroupRules(
	ctx context.Context,
	ruleIDs []string,
	rulesByFamily map[string]*models.FwmgrFirewallRuleV1,
) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	dsRuleType := types.ObjectType{AttrTypes: dataSourceFirewallRuleModel{}.attrTypes()}

	orderedRules := make([]*models.FwmgrFirewallRuleV1, 0, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		if rule, ok := rulesByFamily[ruleID]; ok && rule != nil {
			orderedRules = append(orderedRules, rule)
		}
	}

	if len(orderedRules) == 0 {
		return types.ListNull(dsRuleType), diags
	}

	nullPlan := types.ListNull(types.ObjectType{AttrTypes: firewallRuleModel{}.attrTypes()})
	rulesList, d := wrapRules(ctx, orderedRules, nullPlan)
	diags.Append(d...)
	if diags.HasError() {
		return types.ListNull(dsRuleType), diags
	}

	var resourceRules []firewallRuleModel
	diags.Append(rulesList.ElementsAs(ctx, &resourceRules, false)...)
	if diags.HasError() {
		return types.ListNull(dsRuleType), diags
	}

	dsRules := make([]dataSourceFirewallRuleModel, 0, len(resourceRules))
	for _, r := range resourceRules {
		dsRules = append(dsRules, dataSourceFirewallRuleModel(r))
	}

	return utils.SliceToListTypeObject(ctx, dsRules, dataSourceFirewallRuleModel{}.attrTypes(), &diags), diags
}

func (m firewallRuleGroupsDataSourceModel) hasIndividualFilters() bool {
	return utils.IsKnown(m.Name) ||
		utils.IsKnown(m.Enabled) ||
		utils.IsKnown(m.Platform)
}

// dataSourceRuleSchemaAttributes returns the read-only rule schema for the data source.
// It mirrors the resource rule schema without the log field, which the API does not return.
func dataSourceRuleSchemaAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Identifier for the firewall rule",
		},
		"name": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Name of the firewall rule",
		},
		"description": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Description of the firewall rule",
		},
		"enabled": schema.BoolAttribute{
			Computed:            true,
			MarkdownDescription: "Whether the rule is enabled",
		},
		"action": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Action to take when the rule matches",
		},
		"direction": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Traffic direction for the rule",
		},
		"protocol": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Protocol for the rule",
		},
		"address_family": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Address family for the rule",
		},
		"local_address": schema.ListNestedAttribute{
			Computed:            true,
			MarkdownDescription: "Local IP addresses for the rule",
			NestedObject: schema.NestedAttributeObject{
				Attributes: dataSourceAddressRangeSchemaAttributes(),
			},
		},
		"remote_address": schema.ListNestedAttribute{
			Computed:            true,
			MarkdownDescription: "Remote IP addresses for the rule",
			NestedObject: schema.NestedAttributeObject{
				Attributes: dataSourceAddressRangeSchemaAttributes(),
			},
		},
		"local_port": schema.ListNestedAttribute{
			Computed:            true,
			MarkdownDescription: "Local ports for the rule",
			NestedObject: schema.NestedAttributeObject{
				Attributes: dataSourcePortRangeSchemaAttributes(),
			},
		},
		"remote_port": schema.ListNestedAttribute{
			Computed:            true,
			MarkdownDescription: "Remote ports for the rule",
			NestedObject: schema.NestedAttributeObject{
				Attributes: dataSourcePortRangeSchemaAttributes(),
			},
		},
		"fqdn": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Fully qualified domain name for the rule",
		},
		"network_location": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Network location restriction",
		},
		"executable_path": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Path to executable that this rule applies to",
		},
		"service_name": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Windows service name that this rule applies to",
		},
		"icmp_type": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "ICMP type for ICMP protocol rules",
		},
		"icmp_code": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "ICMP code for ICMP protocol rules",
		},
		"watch_mode": schema.BoolAttribute{
			Computed:            true,
			MarkdownDescription: "Whether watch mode (monitoring) is enabled for this rule",
		},
	}
}

func dataSourceAddressRangeSchemaAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"address": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "IP address or `*` for any",
		},
		"netmask": schema.Int64Attribute{
			Computed:            true,
			MarkdownDescription: "CIDR netmask",
		},
	}
}

func dataSourcePortRangeSchemaAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"start": schema.Int64Attribute{
			Computed:            true,
			MarkdownDescription: "Start port",
		},
		"end": schema.Int64Attribute{
			Computed:            true,
			MarkdownDescription: "End port for range, 0 for single port",
		},
	}
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
				Optional:            true,
				MarkdownDescription: "FQL filter to apply to the firewall rule groups query. Cannot be used together with 'ids' or other filter attributes.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"ids": schema.ListAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "List of firewall rule group IDs to retrieve. Cannot be used together with 'filter' or other filter attributes.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.LengthBetween(32, 32),
					),
					listvalidator.SizeAtLeast(1),
					listvalidator.UniqueValues(),
				},
			},
			"name": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Filter rule groups by name. Supports wildcard matching with '*'. Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"platform": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Filter rule groups by platform (Windows, Linux, Mac). Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Linux", "Mac"),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Filter rule groups by enabled status. Cannot be used together with 'filter' or 'ids'.",
			},
			"rule_groups": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The list of firewall rule groups",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The firewall rule group ID",
						},
						"name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The firewall rule group name",
						},
						"description": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The firewall rule group description",
						},
						"platform": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The platform (Windows, Linux, Mac)",
						},
						"enabled": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Whether the rule group is enabled",
						},
						"created_by": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "User who created the rule group",
						},
						"created_on": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Timestamp when the rule group was created",
						},
						"modified_by": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "User who last modified the rule group",
						},
						"modified_on": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Timestamp when the rule group was last modified",
						},
						"rule_count": schema.Int64Attribute{
							Computed:            true,
							MarkdownDescription: "Number of rules in the rule group",
						},
						"rules": schema.ListNestedAttribute{
							Computed:            true,
							MarkdownDescription: "The list of firewall rules in this rule group, in precedence order",
							NestedObject: schema.NestedAttributeObject{
								Attributes: dataSourceRuleSchemaAttributes(),
							},
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

	ruleIDs := make([]string, 0)
	for _, rg := range ruleGroups {
		if rg != nil {
			ruleIDs = append(ruleIDs, rg.RuleIds...)
		}
	}

	rulesByID, diags := d.getFirewallRules(ctx, ruleIDs)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(data.wrap(ctx, ruleGroups, rulesByID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// getFirewallRules fetches firewall rules for the given rule family IDs, keyed by
// family ID (which is what a rule group's RuleIds contains). IDs are fetched in
// batches to stay within request limits.
func (d *firewallRuleGroupsDataSource) getFirewallRules(
	ctx context.Context,
	ids []string,
) (map[string]*models.FwmgrFirewallRuleV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	rulesByFamily := make(map[string]*models.FwmgrFirewallRuleV1, len(ids))

	const batchSize = 100
	for start := 0; start < len(ids); start += batchSize {
		end := min(start+batchSize, len(ids))

		params := firewall_management.NewGetRulesParams().
			WithContext(ctx).
			WithIds(ids[start:end])

		res, err := d.client.FirewallManagement.GetRules(params)
		if err != nil {
			diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesRead))
			return rulesByFamily, diags
		}

		if res == nil || res.Payload == nil {
			continue
		}

		for _, rule := range res.Payload.Resources {
			if rule != nil && rule.Family != nil {
				rulesByFamily[*rule.Family] = rule
			}
		}
	}

	return rulesByFamily, diags
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
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesRead))
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
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesRead))
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
