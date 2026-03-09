package correlationrules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/correlation_rules"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource                   = &correlationRulesDataSource{}
	_ datasource.DataSourceWithConfigure      = &correlationRulesDataSource{}
	_ datasource.DataSourceWithValidateConfig = &correlationRulesDataSource{}
)

var dataSourceAPIScopes = []scopes.Scope{
	{
		Name: "Correlation Rules",
		Read: true,
	},
}

// NewCorrelationRulesDataSource creates a new instance of the data source.
func NewCorrelationRulesDataSource() datasource.DataSource {
	return &correlationRulesDataSource{}
}

type correlationRulesDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type correlationRuleDataModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	CustomerID  types.String `tfsdk:"customer_id"`
	Severity    types.Int32  `tfsdk:"severity"`
	Status      types.String `tfsdk:"status"`
	Tactic      types.String `tfsdk:"tactic"`
	Technique   types.String `tfsdk:"technique"`
	TemplateID  types.String `tfsdk:"template_id"`
	CreatedOn   types.String `tfsdk:"created_on"`
	UpdatedOn   types.String `tfsdk:"updated_on"`
}

func (m correlationRuleDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":          types.StringType,
		"name":        types.StringType,
		"description": types.StringType,
		"customer_id": types.StringType,
		"severity":    types.Int32Type,
		"status":      types.StringType,
		"tactic":      types.StringType,
		"technique":   types.StringType,
		"template_id": types.StringType,
		"created_on":  types.StringType,
		"updated_on":  types.StringType,
	}
}

type correlationRulesDataSourceModel struct {
	Filter types.String `tfsdk:"filter"`
	Name   types.String `tfsdk:"name"`
	Status types.String `tfsdk:"status"`
	Rules  types.List   `tfsdk:"rules"`
}

// hasIndividualFilters returns true if any typed filter attributes are set.
func (m correlationRulesDataSourceModel) hasIndividualFilters() bool {
	return utils.IsKnown(m.Name) || utils.IsKnown(m.Status)
}

// buildFQLFilter composes individual typed attributes into an FQL filter string.
func (m correlationRulesDataSourceModel) buildFQLFilter() string {
	var parts []string
	if utils.IsKnown(m.Name) {
		parts = append(parts, fmt.Sprintf("name:'%s'", m.Name.ValueString()))
	}
	if utils.IsKnown(m.Status) {
		parts = append(parts, fmt.Sprintf("status:'%s'", m.Status.ValueString()))
	}
	return strings.Join(parts, "+")
}

func (d *correlationRulesDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}
	cfg, ok := req.ProviderData.(config.ProviderConfig)
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
	d.client = cfg.Client
}

func (d *correlationRulesDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_correlation_rules"
}

func (d *correlationRulesDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"NGSIEM",
			"Use this data source to query existing CrowdStrike NGSIEM Correlation Rules.",
			dataSourceAPIScopes,
		),
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "FQL filter to apply. Supported fields: `created_on`, `customer_id`, `last_updated_on`, `name`, `status`, `user_id`, `user_uuid`. Cannot be used together with `name` or `status` attributes. Example: `status:'active'+name:'My Rule'`.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"name": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Filter rules by name. Supports FQL wildcards (`*`). Cannot be used together with `filter`.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"status": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Filter rules by status. Cannot be used together with `filter`.",
				Validators: []validator.String{
					stringvalidator.OneOf("active", "inactive"),
				},
			},
			"rules": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The list of correlation rules matching the query.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The correlation rule ID.",
						},
						"name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The correlation rule name.",
						},
						"description": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The correlation rule description.",
						},
						"customer_id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The CID of the environment.",
						},
						"severity": schema.Int32Attribute{
							Computed:            true,
							MarkdownDescription: "The severity level (10, 30, 50, 70, 90).",
						},
						"status": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The rule status (`active` or `inactive`).",
						},
						"tactic": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The MITRE ATT&CK tactic ID.",
						},
						"technique": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The MITRE ATT&CK technique ID.",
						},
						"template_id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The template ID this rule was created from.",
						},
						"created_on": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Timestamp when the rule was created.",
						},
						"updated_on": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Timestamp when the rule was last updated.",
						},
					},
				},
			},
		},
	}
}

func (d *correlationRulesDataSource) ValidateConfig(
	ctx context.Context,
	req datasource.ValidateConfigRequest,
	resp *datasource.ValidateConfigResponse,
) {
	var data correlationRulesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasFilter := utils.IsKnown(data.Filter) && data.Filter.ValueString() != ""

	if hasFilter && data.hasIndividualFilters() {
		resp.Diagnostics.AddError(
			"Invalid Attribute Combination",
			"Cannot specify 'filter' together with 'name' or 'status'. Use either 'filter' for raw FQL queries, or individual filter attributes, but not both.",
		)
	}
}

func (d *correlationRulesDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data correlationRulesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Determine the FQL filter to use.
	var filter *string
	if utils.IsKnown(data.Filter) && data.Filter.ValueString() != "" {
		f := data.Filter.ValueString()
		filter = &f
	} else if data.hasIndividualFilters() {
		f := data.buildFQLFilter()
		filter = &f
	}

	rules, diags := d.fetchAllRules(ctx, filter)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleModels := make([]correlationRuleDataModel, 0, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		ruleModels = append(ruleModels, mapRuleToDataModel(rule))
	}

	data.Rules = utils.SliceToListTypeObject(ctx, ruleModels, correlationRuleDataModel{}.AttributeTypes(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *correlationRulesDataSource) fetchAllRules(
	ctx context.Context,
	filter *string,
) ([]*models.CorrelationrulesapiRuleV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allRules []*models.CorrelationrulesapiRuleV1
	var offset int64
	limit := int64(100)

	for {
		params := &correlation_rules.CombinedRulesGetV1Params{
			Context: ctx,
			Offset:  &offset,
			Limit:   &limit,
		}
		if filter != nil {
			params.Filter = filter
		}

		res, err := d.client.CorrelationRules.CombinedRulesGetV1(params)
		if err != nil {
			diags.AddError(
				"Failed to query correlation rules",
				fmt.Sprintf("API call failed: %s", err),
			)
			return nil, diags
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			break
		}

		allRules = append(allRules, res.Payload.Resources...)
		tflog.Debug(ctx, "[datasource] Retrieved correlation rules page",
			map[string]any{
				"page_count":  len(res.Payload.Resources),
				"total_count": len(allRules),
			})

		if len(res.Payload.Resources) < int(limit) {
			break
		}
		offset += limit
	}

	return allRules, diags
}

func mapRuleToDataModel(rule *models.CorrelationrulesapiRuleV1) correlationRuleDataModel {
	m := correlationRuleDataModel{
		Description: types.StringValue(rule.Description),
	}
	if rule.ID != nil {
		m.ID = types.StringValue(*rule.ID)
	}
	if rule.Name != nil {
		m.Name = types.StringValue(*rule.Name)
	}
	if rule.CustomerID != nil {
		m.CustomerID = types.StringValue(*rule.CustomerID)
	}
	if rule.Severity != nil {
		m.Severity = types.Int32Value(*rule.Severity)
	}
	if rule.Status != nil {
		m.Status = types.StringValue(*rule.Status)
	}
	if rule.Tactic != nil {
		m.Tactic = types.StringValue(*rule.Tactic)
	}
	if rule.Technique != nil {
		m.Technique = types.StringValue(*rule.Technique)
	}
	if rule.TemplateID != nil {
		m.TemplateID = types.StringValue(*rule.TemplateID)
	}
	if rule.CreatedOn != nil {
		m.CreatedOn = types.StringValue(time.Time(*rule.CreatedOn).Format(time.RFC3339))
	}
	if rule.LastUpdatedOn != nil {
		m.UpdatedOn = types.StringValue(time.Time(*rule.LastUpdatedOn).Format(time.RFC3339))
	}
	return m
}
