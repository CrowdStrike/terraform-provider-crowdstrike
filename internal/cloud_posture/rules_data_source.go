package cloud_posture

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
	CloudProvider types.String                           `tfsdk:"cloud_provider"`
	RuleName      types.String                           `tfsdk:"rule_name"`
	Rules         []cloudPostureRulesDataSourceRuleModel `tfsdk:"rules"`
}

type cloudPostureRulesDataSourceRuleModel struct {
	UUID      types.String `tfsdk:"uuid"`
	AlertInfo types.List   `tfsdk:"alert_info"`
	Controls  []struct {
		Authority types.String `tfsdk:"authority"`
		Code      types.String `tfsdk:"code"`
	} `tfsdk:"controls"`
	Description     types.String `tfsdk:"description"`
	AutoRemediable  types.Bool   `tfsdk:"auto_remediable"`
	Domain          types.String `tfsdk:"domain"`
	Logic           types.String `tfsdk:"logic"`
	Name            types.String `tfsdk:"name"`
	ParentRuleID    types.String `tfsdk:"parent_rule_id"`
	CloudPlatform   types.String `tfsdk:"cloud_platform"`
	CloudProvider   types.String `tfsdk:"cloud_provider"`
	RemediationInfo types.String `tfsdk:"remediation_info"`
	ResourceType    types.String `tfsdk:"resource_type"`
	Severity        types.Int32  `tfsdk:"severity"`
	Subdomain       types.String `tfsdk:"subdomain"`
	AttackTypes     types.Set    `tfsdk:"attack_types"`
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
			"This data source retrieves detailed information about a specific cloud posture rule, including its unique identifier (UUID) and associated attributes.",
			cloudPostureRuleScopes,
		),
		Attributes: map[string]schema.Attribute{
			"cloud_provider": schema.StringAttribute{
				Required:    true,
				Description: "Cloud provider for where the rule resides.",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"AWS",
						"Azure",
						"GCP",
					),
				},
			},
			"rule_name": schema.StringAttribute{
				Optional:    true,
				Description: "Name of the rule to search for. If no name is defined all rules in cloud provider will be returned.",
			},
			"rules": schema.ListNestedAttribute{
				Optional:    true,
				Computed:    true,
				Description: "List of cloud posture rules",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"uuid": schema.StringAttribute{
							Computed:    true,
							Description: "Unique identifier of the policy rule.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
									"must be a valid UUID in the format of 7c86a274-c04b-4292-9f03-dafae42bde97",
								),
							},
						},
						"alert_info": schema.ListAttribute{
							Optional:    true,
							Computed:    true,
							ElementType: types.StringType,
							Description: "A list of the alert logic and detection criteria for rule violations. Parent value will be used when parent_rule_id is defined.",
						},
						"controls": schema.SetNestedAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Security framework and compliance rule information.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"authority": schema.StringAttribute{
										Required:    true,
										Description: "This compliance framework",
									},
									"code": schema.StringAttribute{
										Required:    true,
										Description: "The compliance framework rule code",
									},
								},
							},
						},
						"description": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Description of the policy rule.",
						},
						"auto_remediable": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Autoremediation enabled for rule",
						},
						"domain": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Timestamp of the last Terraform update of the resource.",
						},
						"logic": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Rego logic for the rule. If this is not defined, then parent_rule_id must be defined.",
						},
						"name": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Name of the policy rule.",
						},
						"parent_rule_id": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "UUID of the parent rule to inherit properties from. Required if logic is not specified.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
									"must be a valid UUID in the format of 7c86a274-c04b-4292-9f03-dafae42bde97",
								),
							},
						},
						"cloud_platform": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Cloud platform for the policy rule.",
							Validators: []validator.String{
								stringvalidator.OneOf(
									"AWS",
									"Azure",
									"OCI",
									"GCP",
								),
							},
						},
						"cloud_provider": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Cloud provider for the policy rule.",
							Validators: []validator.String{
								stringvalidator.OneOf(
									"AWS",
									"Azure",
									"OCI",
									"GCP",
								),
							},
						},
						"attack_types": schema.SetAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Specific attack types associated with the rule.",
							ElementType: types.StringType,
						},
						"remediation_info": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Information about how to remediate issues detected by this rule.",
						},
						"resource_type": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "The full resource type. Format examples: AWS: AWS::IAM::CredentialReport, Azure: Microsoft.Compute/virtualMachines, GCP: container.googleapis.com/Cluster",
						},
						"severity": schema.Int32Attribute{
							Optional:    true,
							Computed:    true,
							Description: "Severity of the rule. Valid values are 0 (critical), 1 (high), 2 (medium), 3 (informational).",
							Validators: []validator.Int32{
								int32validator.OneOf(0, 1, 2, 3),
							},
						},
						"subdomain": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Subdomain for the policy rule. Valid values are 'IOM' (Indicators of Misconfiguration) or 'IAC' (Infrastructure as Code). IOM is only supported at this time.",
							Validators: []validator.String{
								stringvalidator.OneOf(
									"IOM",
									"IAC",
								),
							},
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

	data.Rules, diags = r.getRules(ctx, data.CloudProvider.ValueString(), data.RuleName.ValueString())
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

func (r *cloudPostureRulesDataSource) getRules(ctx context.Context, cloudProvider string, ruleName string) (rules []cloudPostureRulesDataSourceRuleModel, diags diag.Diagnostics) {
	filter := fmt.Sprintf("rule_provider:'%s'", cloudProvider)

	if ruleName != "" {
		filter = fmt.Sprintf("%s+rule_name:'%s'", filter, ruleName)
	}

	queryParams := cloud_policies.QueryRuleParams{
		Context: ctx,
		Filter:  &filter,
	}

	queryResp, err := r.client.CloudPolicies.QueryRule(&queryParams)

	if err != nil {
		if notFound, ok := err.(*cloud_policies.QueryRuleBadRequest); ok {
			diags.AddError(
				"Error Querying Rules",
				fmt.Sprintf("Failed to create rule: %s", *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if notFound, ok := err.(*cloud_policies.QueryRuleInternalServerError); ok {
			diags.AddError(
				"Error Querying Rules",
				fmt.Sprintf("Failed to create rule: %s", *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Failed to create rule.",
			fmt.Sprintf("Failed to create rule: %s", err),
		)

		return nil, diags
	}

	queryPayload := queryResp.GetPayload()

	if err = falcon.AssertNoError(queryPayload.Errors); err != nil {
		diags.AddError(
			"Failed to query rules",
			fmt.Sprintf("Failed to query rules: %s", err.Error()),
		)
		return nil, diags
	}

	if len(queryPayload.Resources) == 0 {
		diags.AddWarning(
			"No Rules Found",
			"The query returned no rules. Please check your filter criteria.",
		)
		return nil, diags
	}

	ruleParams := cloud_policies.GetRuleParams{
		Context: ctx,
		Ids:     queryPayload.Resources,
	}

	getRulesResp, err := r.client.CloudPolicies.GetRule(&ruleParams)
	if err != nil {

		if !strings.Contains(err.Error(), "rule resource doesn't exist") {
			diags.AddError(
				"Failed to get rule",
				fmt.Sprintf("Failed to get rule: %s", err),
			)
		}
		return nil, diags
	}

	getRulesPayload := getRulesResp.GetPayload()

	if err = falcon.AssertNoError(getRulesPayload.Errors); err != nil {
		diags.AddError(
			"Failed to get rules",
			fmt.Sprintf("Failed to get rule: %s", err.Error()),
		)
		return nil, diags
	}

	for _, resource := range getRulesPayload.Resources {
		alertInfo := convertAlertRemediationInfoToTerraformState(resource.AlertInfo)

		rule := cloudPostureRulesDataSourceRuleModel{
			UUID:            types.StringValue(*resource.UUID),
			AlertInfo:       alertInfo,
			Description:     types.StringPointerValue(resource.Description),
			AutoRemediable:  types.BoolPointerValue(resource.AutoRemediable),
			Domain:          types.StringPointerValue(resource.Domain),
			Logic:           types.StringValue(resource.Logic),
			Name:            types.StringPointerValue(resource.Name),
			ParentRuleID:    types.StringValue(resource.ParentRuleShortUUID),
			CloudPlatform:   types.StringValue(resource.Platform),
			CloudProvider:   types.StringPointerValue(resource.Provider),
			RemediationInfo: types.StringPointerValue(resource.RuleLogicList[0].RemediationInfo),
			ResourceType:    types.StringPointerValue(resource.ResourceTypes[0].ResourceType),
			Severity: func() types.Int32 {
				if resource.Severity != nil {
					return types.Int32Value(int32(*resource.Severity))
				}
				return types.Int32Null()
			}(),
			Subdomain: types.StringPointerValue(resource.Subdomain),
		}

		for _, control := range resource.Controls {
			rule.Controls = append(rule.Controls, struct {
				Authority types.String `tfsdk:"authority"`
				Code      types.String `tfsdk:"code"`
			}{
				Authority: types.StringPointerValue(control.Authority),
				Code:      types.StringPointerValue(control.Code),
			})
		}

		rule.AttackTypes = types.SetValueMust(types.StringType, []attr.Value{})
		for _, attackType := range resource.AttackTypes {
			rule.AttackTypes, diags = types.SetValue(types.StringType, append(rule.AttackTypes.Elements(), types.StringValue(attackType)))
			if diags.HasError() {
				return nil, diags
			}
		}

		rules = append(rules, rule)
	}

	return rules, diags
}
