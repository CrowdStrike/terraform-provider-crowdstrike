package cloudposture

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
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
	_ datasource.DataSource              = &cloudPostureRulesDataSource{}
	_ datasource.DataSourceWithConfigure = &cloudPostureRulesDataSource{}
)

func NewCloudPostureRulesDataSource() datasource.DataSource {
	return &cloudPostureRulesDataSource{}
}

type cloudPostureRulesDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudPostureRulesDataSourceModel struct {
	CloudProvider types.String `tfsdk:"cloud_provider"`
	RuleName      types.String `tfsdk:"rule_name"`
	ResourceType  types.String `tfsdk:"resource_type"`
	Benchmark     types.String `tfsdk:"benchmark"`
	Framework     types.String `tfsdk:"framework"`
	Service       types.String `tfsdk:"service"`
	FQL           types.String `tfsdk:"fql"`
	Rules         types.Set    `tfsdk:"rules"`
}

type cloudPostureRulesDataSourceRuleModel struct {
	ID              types.String `tfsdk:"id"`
	AlertInfo       types.List   `tfsdk:"alert_info"`
	Controls        types.Set    `tfsdk:"controls"`
	Description     types.String `tfsdk:"description"`
	AutoRemediable  types.Bool   `tfsdk:"auto_remediable"`
	Domain          types.String `tfsdk:"domain"`
	Logic           types.String `tfsdk:"logic"`
	Name            types.String `tfsdk:"name"`
	ParentRuleID    types.String `tfsdk:"parent_rule_id"`
	CloudPlatform   types.String `tfsdk:"cloud_platform"`
	CloudProvider   types.String `tfsdk:"cloud_provider"`
	RemediationInfo types.List   `tfsdk:"remediation_info"`
	ResourceType    types.String `tfsdk:"resource_type"`
	Severity        types.String `tfsdk:"severity"`
	Subdomain       types.String `tfsdk:"subdomain"`
	AttackTypes     types.Set    `tfsdk:"attack_types"`
}

func (m cloudPostureRulesDataSourceRuleModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id": types.StringType,
		"alert_info": types.ListType{
			ElemType: types.StringType,
		},
		"controls": types.SetType{

			ElemType: types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"authority": types.StringType,
					"code":      types.StringType,
				},
			},
		},
		"description":     types.StringType,
		"auto_remediable": types.BoolType,
		"domain":          types.StringType,
		"logic":           types.StringType,
		"name":            types.StringType,
		"parent_rule_id":  types.StringType,
		"cloud_platform":  types.StringType,
		"cloud_provider":  types.StringType,
		"remediation_info": types.ListType{
			ElemType: types.StringType,
		},
		"resource_type": types.StringType,
		"severity":      types.StringType,
		"subdomain":     types.StringType,
		"attack_types": types.SetType{
			ElemType: types.StringType,
		},
	}
}

func (r *cloudPostureRulesDataSource) Configure(
	ctx context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
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

func (r *cloudPostureRulesDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_posture_rules"
}

func (r *cloudPostureRulesDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Cloud Posture",
			"This data source retrieves detailed information about a specific cloud posture rule, including its unique identifier (ID) and associated attributes."+
				"All non-FQL fields can accept wildcards `*` and query Falcon using logical AND. If FQL is defined, all other fields will be ignored. "+
				"For advanced queries to further narrow your search, please use a Falcon Query Language (FQL) filter. "+
				"For additional information on FQL filtering and usage, refer to the official CrowdStrike documentation: "+
				"[Falcon Query Language (FQL)](https://falcon.crowdstrike.com/documentation/page/d3c84a1b/falcon-query-language-fql)",
			cloudPostureRuleScopes,
		),
		Attributes: map[string]schema.Attribute{
			"cloud_provider": schema.StringAttribute{
				Optional:    true,
				Description: "Cloud provider for where the rule resides.",
			},
			"rule_name": schema.StringAttribute{
				Optional:    true,
				Description: "Name of the rule to search for. If no name is defined all rules in a cloud provider will be returned.",
			},
			"resource_type": schema.StringAttribute{
				Optional:    true,
				Description: "Name of the resource type to search for. Examples: `AWS::IAM::CredentialReport`, `Microsoft.Compute/virtualMachines`, `container.googleapis.com/Cluster`.",
			},
			"benchmark": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Name of the benchmark that this rule is attached to. Note that rules can be associated with multiple benchmarks. Example: `CIS 1.0.0 AWS*`",
			},
			"framework": schema.StringAttribute{
				Optional:    true,
				Description: "Name of the framework that this rule is attached to. Note that rules can be associated with multiple benchmarks. Examples: CIS, NIST ",
			},
			"service": schema.StringAttribute{
				Optional:    true,
				Description: "Name of the service within the cloud provider that rule is for. Examples: IAM, S3, Microsoft.Compute",
			},
			"fql": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Falcon Query Language (FQL) filter for advanced control searches. " +
					"FQL filter, allowed props: " +
					"`rule_origin`, " +
					"`rule_parent_uuid`, " +
					"`rule_name`, " +
					"`rule_description`, " +
					"`rule_domain`, " +
					"`rule_status`, " +
					"`rule_severity`, " +
					"`rule_short_code`, " +
					"`rule_service`, " +
					"`rule_resource_type`, " +
					"`rule_provider`, " +
					"`rule_subdomain`, " +
					"`rule_auto_remediable`, " +
					"`rule_control_requirement`, " +
					"`rule_control_section`, " +
					"`rule_compliance_benchmark`, " +
					"`rule_compliance_framework`, " +
					"`rule_mitre_tactic`, " +
					"`rule_mitre_technique`, " +
					"`rule_created_at`, " +
					"`rule_updated_at`, " +
					"`rule_updated_by`",
			},
			"rules": schema.SetNestedAttribute{
				Computed:    true,
				Description: "List of cloud posture rules",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Unique identifier of the policy rule.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
									"must be a valid ID in the format of 7c86a274-c04b-4292-9f03-dafae42bde97",
								),
							},
						},
						"alert_info": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "A list of the alert logic and detection criteria for rule violations.",
						},
						"controls": schema.SetNestedAttribute{
							Computed:    true,
							Description: "Security framework and compliance rule information.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"authority": schema.StringAttribute{
										Required:    true,
										Description: "The compliance framework",
									},
									"code": schema.StringAttribute{
										Required:    true,
										Description: "The compliance framework rule code",
									},
								},
							},
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "Description of the policy rule.",
						},
						"auto_remediable": schema.BoolAttribute{
							Computed:    true,
							Description: "Autoremediation enabled for the policy rule",
						},
						"domain": schema.StringAttribute{
							Computed:    true,
							Description: "Domain for the policy rule.",
						},
						"logic": schema.StringAttribute{
							Computed:    true,
							Description: "Rego logic for the policy rule.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the policy rule.",
						},
						"parent_rule_id": schema.StringAttribute{
							Computed:    true,
							Description: "Id of the parent rule to inherit properties from.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
									"must be a valid ID in the format of 7c86a274-c04b-4292-9f03-dafae42bde97",
								),
							},
						},
						"cloud_platform": schema.StringAttribute{
							Computed:    true,
							Description: "Cloud platform for the policy rule.",
						},
						"cloud_provider": schema.StringAttribute{
							Computed:    true,
							Description: "Cloud provider for the policy rule.",
						},
						"attack_types": schema.SetAttribute{
							Computed:    true,
							Description: "Specific attack types associated with the rule.",
							ElementType: types.StringType,
						},
						"remediation_info": schema.ListAttribute{
							Computed:    true,
							Description: "Information about how to remediate issues detected by this rule.",
							ElementType: types.StringType,
						},
						"resource_type": schema.StringAttribute{
							Computed: true,
							MarkdownDescription: "The full resource type. Format examples: " +
								"`AWS::IAM::CredentialReport`, " +
								"`Microsoft.Compute/virtualMachines`, " +
								"`container.googleapis.com/Cluster`",
						},
						"severity": schema.StringAttribute{
							Computed:    true,
							Description: "Severity of the rule. Valid values are `critical`, `high`, `medium`, `informational`.",
							Validators: []validator.String{
								stringvalidator.OneOf("critical", "high", "medium", "informational"),
							},
						},
						"subdomain": schema.StringAttribute{
							Computed:    true,
							Description: "Subdomain for the policy rule. Valid values are 'IOM' (Indicators of Misconfiguration) or 'IAC' (Infrastructure as Code). IOM is only supported at this time.",
						},
					},
				},
			},
		},
	}
}

func (r *cloudPostureRulesDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data cloudPostureRulesDataSourceModel
	var diags diag.Diagnostics

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	fqlFilters := []fqlFilters{
		{data.CloudProvider.ValueString(), "rule_provider"},
		{data.RuleName.ValueString(), "rule_name"},
		{data.ResourceType.ValueString(), "rule_resource_type"},
		{data.Benchmark.ValueString(), "rule_compliance_benchmark"},
		{data.Service.ValueString(), "rule_service"},
		{data.Framework.ValueString(), "rule_compliance_framework"},
	}

	data.Rules, diags = r.getRules(
		ctx,
		data.FQL.ValueString(),
		fqlFilters,
	)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Set State
	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *cloudPostureRulesDataSource) getRules(
	ctx context.Context,
	fql string,
	fqlFilters []fqlFilters,
) (types.Set, diag.Diagnostics) {
	var rules []cloudPostureRulesDataSourceRuleModel
	var diags diag.Diagnostics
	var filter string
	limit := int64(500)
	offset := int64(0)
	defaultResponse := types.SetValueMust(types.ObjectType{AttrTypes: cloudPostureRulesDataSourceRuleModel{}.AttributeTypes()}, []attr.Value{})

	queryParams := cloud_policies.QueryRuleParams{
		Context: ctx,
		Limit:   &limit,
	}

	if fql == "" {
		var filters []string
		for _, f := range fqlFilters {
			if f.value != "" {
				value := strings.ReplaceAll(f.value, "\\", "\\\\\\\\")
				filters = append(filters, fmt.Sprintf("%s:*'%s'", f.field, value))
			}
		}

		if len(filters) > 0 {
			filter = strings.Join(filters, "+")
		}

		if filter != "" {
			queryParams.Filter = &filter
		}
	} else {
		queryParams.Filter = &fql
	}

	for {
		queryResp, err := r.client.CloudPolicies.QueryRule(&queryParams)

		if err != nil {
			if badRequest, ok := err.(*cloud_policies.QueryRuleBadRequest); ok {
				diags.AddError(
					"Error Querying Rules",
					fmt.Sprintf("Failed to query rules: %s", *badRequest.Payload.Errors[0].Message),
				)
				return types.SetValueMust(types.ObjectType{AttrTypes: cloudPostureRulesDataSourceRuleModel{}.AttributeTypes()}, []attr.Value{}), diags
			}

			if internalServerError, ok := err.(*cloud_policies.QueryRuleInternalServerError); ok {
				diags.AddError(
					"Error Querying Rules",
					fmt.Sprintf("Failed to query rules: %s", *internalServerError.Payload.Errors[0].Message),
				)
				return defaultResponse, diags
			}

			diags.AddError(
				"Error Querying Rules",
				fmt.Sprintf("Failed to query rules: %s", err),
			)

			return defaultResponse, diags
		}

		if queryResp == nil || queryResp.Payload == nil || len(queryResp.Payload.Resources) == 0 {
			return defaultResponse, diags
		}

		queryPayload := queryResp.GetPayload()

		if err = falcon.AssertNoError(queryPayload.Errors); err != nil {
			diags.AddError(
				"Error Querying Rules",
				fmt.Sprintf("Failed to query rules: %s", err.Error()),
			)
			return defaultResponse, diags
		}

		if len(queryPayload.Resources) == 0 {
			return defaultResponse, diags
		}

		ruleParams := cloud_policies.GetRuleParams{
			Context: ctx,
			Ids:     queryPayload.Resources,
		}

		getRulesResp, err := r.client.CloudPolicies.GetRule(&ruleParams)
		if err != nil {
			if !strings.Contains(err.Error(), "rule resource doesn't exist") {
				diags.AddError(
					"Failed to Fetch Rule Information",
					fmt.Sprintf("Failed to fetch rule information: %s", err),
				)
			}
			return defaultResponse, diags
		}

		if getRulesResp == nil || getRulesResp.Payload == nil || len(getRulesResp.Payload.Resources) == 0 {
			diags.AddError(
				"Error Fetching Rule Information",
				"Failed to fetch rule information: The API returned an empty payload.",
			)
			return defaultResponse, diags
		}

		getRulesPayload := getRulesResp.GetPayload()

		if err = falcon.AssertNoError(getRulesPayload.Errors); err != nil {
			diags.AddError(
				"Error Fetching Rule Information",
				fmt.Sprintf("Failed to fetch rule information: %s", err.Error()),
			)
			return defaultResponse, diags
		}

		for _, resource := range getRulesPayload.Resources {
			rule := cloudPostureRulesDataSourceRuleModel{
				ID:             types.StringValue(*resource.UUID),
				Description:    types.StringPointerValue(resource.Description),
				AutoRemediable: types.BoolPointerValue(resource.AutoRemediable),
				Domain:         types.StringPointerValue(resource.Domain),
				Logic:          types.StringValue(resource.Logic),
				Name:           types.StringPointerValue(resource.Name),
				ParentRuleID:   types.StringValue(resource.ParentRuleShortUUID),
				CloudPlatform:  types.StringValue(resource.Platform),
				CloudProvider:  types.StringPointerValue(resource.Provider),
				Severity:       types.StringValue(int64ToSeverity[*resource.Severity]),
				Subdomain:      types.StringPointerValue(resource.Subdomain),
			}

			var policyControls []policyControl
			for _, control := range resource.Controls {
				policyControls = append(policyControls, policyControl{
					Authority: types.StringPointerValue(control.Authority),
					Code:      types.StringPointerValue(control.Code),
				})
			}

			rule.Controls, diags = types.SetValueFrom(
				ctx,
				types.ObjectType{AttrTypes: policyControl{}.AttributeTypes()},
				policyControls,
			)

			if diags.HasError() {
				return defaultResponse, diags
			}

			rule.AttackTypes, diags = types.SetValueFrom(ctx, types.StringType, resource.AttackTypes)
			if diags.HasError() {
				return defaultResponse, diags
			}

			if resource.RuleLogicList != nil {
				rule.RemediationInfo = convertAlertRemediationInfoToTerraformState(resource.RuleLogicList[0].RemediationInfo)
			}

			if resource.AlertInfo != nil {
				rule.AlertInfo = convertAlertRemediationInfoToTerraformState(resource.AlertInfo)
			}

			if resource.ResourceTypes != nil {
				rule.ResourceType = types.StringPointerValue(resource.ResourceTypes[0].ResourceType)
			}

			rules = append(rules, rule)
		}

		if queryPayload.Meta != nil && queryPayload.Meta.Pagination != nil {
			pagination := queryPayload.Meta.Pagination
			if pagination.Offset != nil && pagination.Total != nil && *pagination.Offset >= int32(*pagination.Total) {
				tflog.Info(ctx, "Pagination complete", map[string]any{"meta": queryPayload.Meta})
				break
			}
		}

		offset += limit
	}

	rulesSet, diags := types.SetValueFrom(
		ctx,
		types.ObjectType{AttrTypes: cloudPostureRulesDataSourceRuleModel{}.AttributeTypes()},
		rules,
	)
	if diags.HasError() {
		return defaultResponse, diags
	}
	return rulesSet, diags
}
