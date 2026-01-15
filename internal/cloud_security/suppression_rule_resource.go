package cloudsecurity

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwmodifiers "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/modifiers"
	fwtypes "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/types"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

var (
	ruleSelectionTypeDefault   = "all_rules"
	ruleSelectionTypeFilter    = "rule_selection_filter"
	scopeTypeDefault           = "all_assets"
	scopeTypeFilter            = "asset_filter"
	suppressionRuleTypeDefault = "IOM"
)

var (
	_ resource.Resource                   = &cloudSecuritySuppressionRuleResource{}
	_ resource.ResourceWithConfigure      = &cloudSecuritySuppressionRuleResource{}
	_ resource.ResourceWithImportState    = &cloudSecuritySuppressionRuleResource{}
	_ resource.ResourceWithValidateConfig = &cloudSecuritySuppressionRuleResource{}
	_ resource.ResourceWithModifyPlan     = &cloudSecuritySuppressionRuleResource{}
)

var (
	suppressionRuleResourceDocumentationSection string = "Falcon Cloud Security"
	suppressionRuleResourceMarkdownDescription  string = "A suppression rule defines criteria for automatically suppressing findings, such as IOMs, across your environment. " +
		"When a finding matches a suppression rule's conditions, such as specific rule types, asset tags, or cloud accounts, the finding will be suppressed."
	suppressionRuleResourceRequiredScopes []scopes.Scope = cloudSecurityRuleScopes
)

func NewCloudSecuritySuppressionRuleResource() resource.Resource {
	return &cloudSecuritySuppressionRuleResource{}
}

type cloudSecuritySuppressionRuleResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudSecuritySuppressionRuleResourceModel struct {
	ID                        types.String `tfsdk:"id"`
	Type                      types.String `tfsdk:"type"`
	Description               types.String `tfsdk:"description"`
	Name                      types.String `tfsdk:"name"`
	RuleSelectionFilter       types.Object `tfsdk:"rule_selection_filter"`
	AssetFilter               types.Object `tfsdk:"asset_filter"`
	SuppressionComment        types.String `tfsdk:"comment"`
	SuppressionExpirationDate types.String `tfsdk:"expiration_date"`
	SuppressionReason         types.String `tfsdk:"reason"`
}

type ruleSelectionFilterModel struct {
	RuleIds        types.Set `tfsdk:"rule_ids"`
	RuleNames      types.Set `tfsdk:"rule_names"`
	RuleOrigins    types.Set `tfsdk:"rule_origins"`
	RuleServices   types.Set `tfsdk:"rule_services"`
	RuleProviders  types.Set `tfsdk:"rule_providers"`
	RuleSeverities types.Set `tfsdk:"rule_severities"`
}

func (m ruleSelectionFilterModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"rule_ids":        types.SetType{ElemType: types.StringType},
		"rule_names":      types.SetType{ElemType: types.StringType},
		"rule_origins":    types.SetType{ElemType: types.StringType},
		"rule_providers":  types.SetType{ElemType: types.StringType},
		"rule_services":   types.SetType{ElemType: types.StringType},
		"rule_severities": types.SetType{ElemType: types.StringType},
	}
}

type scopeAssetFilterModel struct {
	AccountIds        types.Set `tfsdk:"account_ids"`
	CloudGroupIds     types.Set `tfsdk:"cloud_group_ids"`
	CloudProviders    types.Set `tfsdk:"cloud_providers"`
	Regions           types.Set `tfsdk:"regions"`
	ResourceIds       types.Set `tfsdk:"resource_ids"`
	ResourceNames     types.Set `tfsdk:"resource_names"`
	ResourceTypes     types.Set `tfsdk:"resource_types"`
	ServiceCategories types.Set `tfsdk:"service_categories"`
	Tags              types.Set `tfsdk:"tags"`
}

func (m scopeAssetFilterModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"account_ids":        types.SetType{ElemType: types.StringType},
		"cloud_group_ids":    types.SetType{ElemType: types.StringType},
		"cloud_providers":    types.SetType{ElemType: types.StringType},
		"regions":            types.SetType{ElemType: types.StringType},
		"resource_ids":       types.SetType{ElemType: types.StringType},
		"resource_names":     types.SetType{ElemType: types.StringType},
		"resource_types":     types.SetType{ElemType: types.StringType},
		"service_categories": types.SetType{ElemType: types.StringType},
		"tags":               types.SetType{ElemType: types.StringType},
	}
}

func (m *cloudSecuritySuppressionRuleResourceModel) wrap(
	ctx context.Context,
	rule models.ApimodelsSuppressionRule,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = flex.StringPointerToFramework(rule.ID)
	m.Description = types.StringValue(rule.Description)
	m.Name = flex.StringPointerToFramework(rule.Name)
	m.SuppressionComment = types.StringValue(rule.SuppressionComment)
	m.SuppressionExpirationDate = flex.StringValueToFramework(rule.SuppressionExpirationDate)
	m.SuppressionReason = flex.StringPointerToFramework(rule.SuppressionReason)

	// Set type based on Domain and Subdomain from API response
	if rule.Domain != nil && rule.Subdomain != nil {
		if *rule.Domain == iomRuleDomainConfig.Domain && *rule.Subdomain == iomRuleDomainConfig.Subdomain {
			m.Type = types.StringValue(suppressionRuleTypeDefault)
		} else {
			// Default to IOM if we don't recognize the domain/subdomain combination
			m.Type = types.StringValue(suppressionRuleTypeDefault)
		}
	} else {
		// Default to IOM if domain/subdomain are not provided
		m.Type = types.StringValue(suppressionRuleTypeDefault)
	}

	diags.Append(m.setRuleSelectionFilter(ctx, rule)...)
	if diags.HasError() {
		return diags
	}

	diags.Append(m.setAssetFilter(ctx, rule)...)
	if diags.HasError() {
		return diags
	}

	return diags
}

func (r *cloudSecuritySuppressionRuleResource) Configure(
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

func (r *cloudSecuritySuppressionRuleResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_security_suppression_rule"
}

func (r *cloudSecuritySuppressionRuleResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			suppressionRuleResourceDocumentationSection,
			suppressionRuleResourceMarkdownDescription,
			suppressionRuleResourceRequiredScopes),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier of the suppression rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"type": schema.StringAttribute{
				Description: "Type of suppression rule. Defaults to IOM.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(suppressionRuleTypeDefault),
				Validators: []validator.String{
					stringvalidator.OneOf(suppressionRuleTypeDefault),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of the suppression rule.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"name": schema.StringAttribute{
				Description: "Name of the suppression rule",
				Required:    true,
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"comment": schema.StringAttribute{
				Description: "Comment for suppression. This will be attached to the Findings suppressed by this rule.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"expiration_date": schema.StringAttribute{
				MarkdownDescription: "Expiration date for suppression. If defined, must be in RFC3339 format (e.g., `2025-08-11T10:00:00Z`). Once set, this field cannot be cleared. The suppression rule will still exist after expiration and can be reset by updating the expiration date.",
				Optional:            true,
				Validators: []validator.String{
					fwvalidators.ValidateRFC3339(),
					fwvalidators.StringNotWhitespace(),
				},
				PlanModifiers: []planmodifier.String{
					fwmodifiers.PreventStringClearing("Suppression Expiration Date"),
				},
			},
			"reason": schema.StringAttribute{
				Description: "Reason for suppression. One of: accept-risk, compensating-control, false-positive.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						"accept-risk",
						"compensating-control",
						"false-positive",
					),
				},
			},
			"rule_selection_filter": schema.SingleNestedAttribute{
				MarkdownDescription: "Filter criteria for rule selection.",
				Optional:            true,
				Attributes: map[string]schema.Attribute{
					"rule_ids": schema.SetAttribute{
						Description: "Set of rule IDs. A rule will match if its ID is included in this set.",
						ElementType: types.StringType,
						Optional:    true,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.LengthAtLeast(1),
								fwvalidators.StringNotWhitespace(),
							),
						},
					},
					"rule_names": schema.SetAttribute{
						Description: "Set of rule names. A rule will match if its name is included in this set.",
						ElementType: types.StringType,
						Optional:    true,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.LengthAtLeast(1),
								fwvalidators.StringNotWhitespace(),
							),
						},
					},
					"rule_origins": schema.SetAttribute{
						MarkdownDescription: "Set of rule origins. One of: `Custom`, `Default`. A rule will match if its origin is included in this set.",
						ElementType:         types.StringType,
						Optional:            true,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.OneOf("Custom", "Default"),
							),
						},
					},
					"rule_providers": schema.SetAttribute{
						MarkdownDescription: "Set of rule cloud providers. Examples: `AWS`, `Azure`, `GCP`, `OCI`. A rule will match if its cloud provider is included in this set.",
						ElementType:         types.StringType,
						Optional:            true,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.LengthAtLeast(1),
								fwvalidators.StringNotWhitespace(),
							),
						},
					},
					"rule_services": schema.SetAttribute{
						MarkdownDescription: "Set of cloud services. Examples: `Azure Cosmos DB`, `CloudFront`, `Compute Engine`, `EC2`, `Elasticache`, `Virtual Network`. A rule will match if its cloud service is included in this set.",
						ElementType:         types.StringType,
						Optional:            true,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.LengthAtLeast(1),
								fwvalidators.StringNotWhitespace(),
							),
						},
					},
					"rule_severities": schema.SetAttribute{
						MarkdownDescription: "Set of rule severities. One of: `critical`, `high`, `medium`, `informational`. A rule will match if its severity is included in this set.",
						ElementType:         types.StringType,
						Optional:            true,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.OneOf("critical", "high", "medium", "informational"),
							),
						},
					},
				},
			},
			"asset_filter": schema.SingleNestedAttribute{
				MarkdownDescription: "Filter criteria for scope assets.",
				Optional:            true,
				Attributes: map[string]schema.Attribute{
					"account_ids": schema.SetAttribute{
						Description: "Set of account IDs. An Asset will match if it belongs to an account included in this set.",
						ElementType: types.StringType,
						Optional:    true,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.LengthAtLeast(1),
								fwvalidators.StringNotWhitespace(),
							),
						},
					},
					"cloud_group_ids": schema.SetAttribute{
						Description: "Set of cloud group IDs. An Asset will match if it belongs to a Cloud Group whose ID is included in this set.",
						ElementType: types.StringType,
						Optional:    true,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.LengthAtLeast(1),
								fwvalidators.StringNotWhitespace(),
							),
						},
					},
					"cloud_providers": schema.SetAttribute{
						MarkdownDescription: "Set of cloud providers. Examples: `aws`, `azure`, `gcp`. An Asset will match if it belongs to a cloud provider included in this set.",
						ElementType:         types.StringType,
						Optional:            true,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.LengthAtLeast(1),
								fwvalidators.StringNotWhitespace(),
							),
						},
					},
					"regions": schema.SetAttribute{
						MarkdownDescription: "Set of regions. Examples: `eu-central-1`, `eastus`, `us-west-1`. An Asset will match if it is located in a region included in this set.",
						ElementType:         types.StringType,
						Optional:            true,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.LengthAtLeast(1),
								fwvalidators.StringNotWhitespace(),
							),
						},
					},
					"resource_ids": schema.SetAttribute{
						Description: "Set of resource IDs. An Asset will match if its resource ID is included in this set.",
						ElementType: types.StringType,
						Optional:    true,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.LengthAtLeast(1),
								fwvalidators.StringNotWhitespace(),
							),
						},
					},
					"resource_names": schema.SetAttribute{
						Description: "Set of resource names.  An Asset will match if its resource name is included in this set.",
						ElementType: types.StringType,
						Optional:    true,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.LengthAtLeast(1),
								fwvalidators.StringNotWhitespace(),
							),
						},
					},
					"resource_types": schema.SetAttribute{
						MarkdownDescription: "Set of resource types. Examples: `AWS::S3::Bucket`, `compute.googleapis.com/Instance`, `Microsoft.ContainerService/managedClusters`. An Asset will match if its resource type is included in this set.",
						ElementType:         types.StringType,
						Optional:            true,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.LengthAtLeast(1),
								fwvalidators.StringNotWhitespace(),
							),
						},
					},
					"service_categories": schema.SetAttribute{
						MarkdownDescription: "Set of service categories. Examples: `Compute`, `Identity`, `Networking`.  An Asset will match if its cloud service category is included in this set.",
						ElementType:         types.StringType,
						Optional:            true,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.LengthAtLeast(1),
								fwvalidators.StringNotWhitespace(),
							),
						},
					},
					"tags": schema.SetAttribute{
						Description: "Set of tags. These must match the k=v format. An Asset will match if at least one of its tags is included in this set. ",
						ElementType: types.StringType,
						Optional:    true,
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.RegexMatches(
									regexp.MustCompile(`^[^=]+=.+$`),
									"must be in the format 'key=value'",
								),
							),
						},
					},
				},
			},
		},
	}
}

func (r *cloudSecuritySuppressionRuleResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var requestConfig cloudSecuritySuppressionRuleResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &requestConfig)...)

	if resp.Diagnostics.HasError() {
		return
	}

	r.validateSuppressionExpirationDate(requestConfig, resp)
	if resp.Diagnostics.HasError() {
		return
	}

	r.validateRequiredFilters(requestConfig, resp)
	if resp.Diagnostics.HasError() {
		return
	}

	r.validateRuleSelectionFilter(ctx, requestConfig, resp)
	if resp.Diagnostics.HasError() {
		return
	}

	r.validateAssetFilter(ctx, requestConfig, resp)
}

// validateSuppressionExpirationDate validates the suppression expiration date format.
func (r *cloudSecuritySuppressionRuleResource) validateSuppressionExpirationDate(
	requestConfig cloudSecuritySuppressionRuleResourceModel,
	resp *resource.ValidateConfigResponse,
) {
	if utils.IsKnown(requestConfig.SuppressionExpirationDate) && requestConfig.SuppressionExpirationDate.ValueString() != "" {
		_, err := time.Parse(time.RFC3339, requestConfig.SuppressionExpirationDate.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("expiration_date"),
				"Invalid Date Format",
				"The expiration_date must be in RFC3339 format (e.g., '2006-01-02T15:04:05Z').",
			)
		}
	}
}

// validateRequiredFilters validates that at least one filter is defined.
func (r *cloudSecuritySuppressionRuleResource) validateRequiredFilters(
	requestConfig cloudSecuritySuppressionRuleResourceModel,
	resp *resource.ValidateConfigResponse,
) {
	if requestConfig.RuleSelectionFilter.IsNull() && requestConfig.AssetFilter.IsNull() {
		resp.Diagnostics.AddError(
			"Missing Required Filter",
			"At least one of 'rule_selection_filter' or 'asset_filter' must be defined.",
		)
	}
}

// validateRuleSelectionFilter validates the rule selection filter is not empty when defined.
func (r *cloudSecuritySuppressionRuleResource) validateRuleSelectionFilter(
	ctx context.Context,
	requestConfig cloudSecuritySuppressionRuleResourceModel,
	resp *resource.ValidateConfigResponse,
) {
	if !utils.IsKnown(requestConfig.RuleSelectionFilter) {
		return
	}

	var ruleSelectionFilter ruleSelectionFilterModel
	diags := requestConfig.RuleSelectionFilter.As(ctx, &ruleSelectionFilter, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	if r.isRuleSelectionFilterEmpty(ruleSelectionFilter) {
		resp.Diagnostics.AddAttributeError(
			path.Root("rule_selection_filter"),
			"Empty Rule Selection Filter",
			"When rule_selection_filter is defined, at least one filter criterion must be specified (rule_ids, rule_names, rule_origins, rule_providers, rule_services, or rule_severities).",
		)
	}
}

// isRuleSelectionFilterEmpty checks if all rule selection filter fields are empty.
func (r *cloudSecuritySuppressionRuleResource) isRuleSelectionFilterEmpty(filter ruleSelectionFilterModel) bool {
	return (filter.RuleIds.IsNull() || len(filter.RuleIds.Elements()) == 0) &&
		(filter.RuleNames.IsNull() || len(filter.RuleNames.Elements()) == 0) &&
		(filter.RuleOrigins.IsNull() || len(filter.RuleOrigins.Elements()) == 0) &&
		(filter.RuleProviders.IsNull() || len(filter.RuleProviders.Elements()) == 0) &&
		(filter.RuleServices.IsNull() || len(filter.RuleServices.Elements()) == 0) &&
		(filter.RuleSeverities.IsNull() || len(filter.RuleSeverities.Elements()) == 0)
}

// validateAssetFilter validates the scope asset filter is not empty when defined.
func (r *cloudSecuritySuppressionRuleResource) validateAssetFilter(
	ctx context.Context,
	requestConfig cloudSecuritySuppressionRuleResourceModel,
	resp *resource.ValidateConfigResponse,
) {
	if !utils.IsKnown(requestConfig.AssetFilter) {
		return
	}

	var scopeAssetFilter scopeAssetFilterModel
	diags := requestConfig.AssetFilter.As(ctx, &scopeAssetFilter, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	if r.isAssetFilterEmpty(scopeAssetFilter) {
		resp.Diagnostics.AddAttributeError(
			path.Root("asset_filter"),
			"Empty Asset Filter",
			"When asset_filter is defined, at least one filter criterion must be specified (account_ids, cloud_group_ids, cloud_providers, regions, resource_ids, resource_names, resource_types, service_categories, or tags).",
		)
	}
}

// isAssetFilterEmpty checks if all scope asset filter fields are empty.
func (r *cloudSecuritySuppressionRuleResource) isAssetFilterEmpty(filter scopeAssetFilterModel) bool {
	return (filter.AccountIds.IsNull() || len(filter.AccountIds.Elements()) == 0) &&
		(filter.CloudGroupIds.IsNull() || len(filter.CloudGroupIds.Elements()) == 0) &&
		(filter.CloudProviders.IsNull() || len(filter.CloudProviders.Elements()) == 0) &&
		(filter.Regions.IsNull() || len(filter.Regions.Elements()) == 0) &&
		(filter.ResourceIds.IsNull() || len(filter.ResourceIds.Elements()) == 0) &&
		(filter.ResourceNames.IsNull() || len(filter.ResourceNames.Elements()) == 0) &&
		(filter.ResourceTypes.IsNull() || len(filter.ResourceTypes.Elements()) == 0) &&
		(filter.ServiceCategories.IsNull() || len(filter.ServiceCategories.Elements()) == 0) &&
		(filter.Tags.IsNull() || len(filter.Tags.Elements()) == 0)
}

func (r *cloudSecuritySuppressionRuleResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	// Skip validation for destroy operations
	if req.Plan.Raw.IsNull() {
		return
	}

	var planConfig cloudSecuritySuppressionRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &planConfig)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate suppression expiration date for all operations (including destroy)
	if utils.IsKnown(planConfig.SuppressionExpirationDate) && planConfig.SuppressionExpirationDate.ValueString() != "" {
		expired, diags := isTimestampExpired(planConfig.SuppressionExpirationDate.ValueString())
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
		} else if expired {
			resp.Diagnostics.AddAttributeError(
				path.Root("expiration_date"),
				"Expired Date",
				"The expiration_date has already passed. If you are attempting to run a destroy operation, use 'terraform destroy -refresh=false' to skip the expiration check.",
			)
		}
	}
}

func (r *cloudSecuritySuppressionRuleResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudSecuritySuppressionRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, diags := r.createSuppressionRule(ctx, plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *rule)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cloudSecuritySuppressionRuleResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudSecuritySuppressionRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, diags := r.getSuppressionRule(ctx, state.ID.ValueString())
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, *rule)...)

	if state.SuppressionExpirationDate.ValueString() != "" {
		if expired, diags := isTimestampExpired(state.SuppressionExpirationDate.ValueString()); diags.HasError() {
			resp.Diagnostics.AddWarning(
				"Timestamp Parsing Warning",
				fmt.Sprintf("Could not parse suppression expiration date: %s", diags.Errors()[0].Summary()),
			)
		} else if expired {
			resp.Diagnostics.AddWarning(
				"Rule Suppression Expired",
				fmt.Sprintf("The suppression rule with ID %s has expired but still exists in the backend. You can either update the expiration date to a future date or use 'terraform destroy' to remove it.", state.ID.ValueString()),
			)
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cloudSecuritySuppressionRuleResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudSecuritySuppressionRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	rule, diags := r.updateSuppressionRule(ctx, plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *rule)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *cloudSecuritySuppressionRuleResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudSecuritySuppressionRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.deleteSuppressionRule(ctx, state.ID.ValueString())...)
}

func (r *cloudSecuritySuppressionRuleResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *cloudSecuritySuppressionRuleResource) getSuppressionRule(ctx context.Context, id string) (*models.ApimodelsSuppressionRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := cloud_policies.GetSuppressionRulesParams{
		Context: ctx,
		Ids:     []string{id},
	}

	resp, err := r.client.CloudPolicies.GetSuppressionRules(&params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.GetSuppressionRulesBadRequest); ok {
			diags.AddError(
				"Error Retrieving Suppression Rule",
				fmt.Sprintf("Failed to retrieve suppression rule (400): %s, %s", id, tferrors.GetPayloadErrorMessage(badRequest.Payload)),
			)
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.GetSuppressionRulesInternalServerError); ok {
			diags.AddError(
				"Error Retrieving Suppression Rule",
				fmt.Sprintf("Failed to retrieve suppression rule (500): %s, %s", id, tferrors.GetPayloadErrorMessage(internalServerError.Payload)),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Retrieving Suppression Rule",
			fmt.Sprintf("Failed to retrieve rule %s: %+v", id, err),
		)

		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Retrieving Suppression Rule",
			fmt.Sprintf("Failed to retrieve suppression rule %s: API returned an empty response", id),
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Retrieving Suppression Rule",
			fmt.Sprintf("Failed to retrieve suppression rule: %s", err.Error()),
		)
		return nil, diags
	}

	return payload.Resources[0], nil
}

func (r *cloudSecuritySuppressionRuleResource) createSuppressionRule(ctx context.Context, rule cloudSecuritySuppressionRuleResourceModel) (*models.ApimodelsSuppressionRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Get domain configuration based on type
	domainConfig := getDomainConfig(rule.Type.ValueString())

	// Required Params
	body := &models.SuppressionrulesCreateSuppressionRuleRequest{
		Name:                      rule.Name.ValueStringPointer(),
		Domain:                    &domainConfig.Domain,
		RuleSelectionType:         &ruleSelectionTypeDefault,
		ScopeType:                 &scopeTypeDefault,
		Subdomain:                 &domainConfig.Subdomain,
		SuppressionReason:         rule.SuppressionReason.ValueStringPointer(),
		Description:               rule.Description.ValueString(),
		SuppressionComment:        rule.SuppressionComment.ValueString(),
		SuppressionExpirationDate: rule.SuppressionExpirationDate.ValueString(),
	}

	if !rule.RuleSelectionFilter.IsNull() {
		var ruleSelectionFilter ruleSelectionFilterModel
		diags = rule.RuleSelectionFilter.As(ctx, &ruleSelectionFilter, basetypes.ObjectAsOptions{})
		if diags.HasError() {
			return nil, diags
		}

		body.RuleSelectionFilter, diags = ruleSelectionFilter.Expand(ctx)
		if diags.HasError() {
			return nil, diags
		}

		body.RuleSelectionType = &ruleSelectionTypeFilter
	}

	if !rule.AssetFilter.IsNull() {
		var scopeAssetFilter scopeAssetFilterModel
		diags = rule.AssetFilter.As(ctx, &scopeAssetFilter, basetypes.ObjectAsOptions{})
		if diags.HasError() {
			return nil, diags
		}

		body.ScopeAssetFilter, diags = scopeAssetFilter.Expand(ctx)
		if diags.HasError() {
			return nil, diags
		}

		body.ScopeType = &scopeTypeFilter
	}

	params := cloud_policies.CreateSuppressionRuleParams{
		Context: ctx,
		Body:    body,
	}

	resp, err := r.client.CloudPolicies.CreateSuppressionRule(&params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.CreateSuppressionRuleBadRequest); ok {
			diags.AddError(
				"Error Creating Suppression Rule",
				fmt.Sprintf("Failed to create suppression rule (400): %s, %s", rule.Name.ValueString(), tferrors.GetPayloadErrorMessage(badRequest.Payload)),
			)
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.CreateSuppressionRuleInternalServerError); ok {
			diags.AddError(
				"Error Creating Suppression Rule",
				fmt.Sprintf("Failed to create suppression rule (500): %s, %s", rule.Name.ValueString(), tferrors.GetPayloadErrorMessage(internalServerError.Payload)),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Creating Suppression Rule",
			fmt.Sprintf("Failed to create suppression rule %s: %+v", rule.Name.ValueString(), err),
		)

		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Creating Suppression Rule",
			fmt.Sprintf("Failed to create suppression rule %s: API returned an empty response", rule.Name.ValueString()),
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Creating Suppression Rule",
			fmt.Sprintf("Failed to create suppression rule: %s", err.Error()),
		)
		return nil, diags
	}

	return r.getSuppressionRule(ctx, payload.Resources[0])
}

func (r *cloudSecuritySuppressionRuleResource) updateSuppressionRule(ctx context.Context, rule cloudSecuritySuppressionRuleResourceModel) (*models.ApimodelsSuppressionRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	body := models.SuppressionrulesUpdateSuppressionRuleRequest{
		ID:                        rule.ID.ValueStringPointer(),
		Name:                      rule.Name.ValueString(),
		RuleSelectionType:         ruleSelectionTypeDefault,
		ScopeType:                 scopeTypeDefault,
		SuppressionComment:        rule.SuppressionComment.ValueStringPointer(),
		SuppressionExpirationDate: rule.SuppressionExpirationDate.ValueString(),
		SuppressionReason:         rule.SuppressionReason.ValueString(),
		Description:               rule.Description.ValueStringPointer(),
	}

	if !rule.RuleSelectionFilter.IsNull() {
		var ruleSelectionFilter ruleSelectionFilterModel
		diags = rule.RuleSelectionFilter.As(ctx, &ruleSelectionFilter, basetypes.ObjectAsOptions{})
		if diags.HasError() {
			return nil, diags
		}

		body.RuleSelectionFilter, diags = ruleSelectionFilter.Expand(ctx)
		if diags.HasError() {
			return nil, diags
		}

		body.RuleSelectionType = ruleSelectionTypeFilter
	}

	if !rule.AssetFilter.IsNull() {
		var scopeAssetFilter scopeAssetFilterModel
		diags = rule.AssetFilter.As(ctx, &scopeAssetFilter, basetypes.ObjectAsOptions{})
		if diags.HasError() {
			return nil, diags
		}

		body.ScopeAssetFilter, diags = scopeAssetFilter.Expand(ctx)
		if diags.HasError() {
			return nil, diags
		}

		body.ScopeType = scopeTypeFilter
	}

	params := cloud_policies.UpdateSuppressionRuleParams{
		Context: ctx,
		Body:    &body,
	}

	resp, err := r.client.CloudPolicies.UpdateSuppressionRule(&params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.UpdateSuppressionRuleBadRequest); ok {
			diags.AddError(
				"Error Updating Suppression Rule",
				fmt.Sprintf("Failed to update suppression rule (400): %s, %s", rule.ID.ValueString(), tferrors.GetPayloadErrorMessage(badRequest.Payload)),
			)
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.UpdateSuppressionRuleInternalServerError); ok {
			diags.AddError(
				"Error Updating Suppression Rule",
				fmt.Sprintf("Failed to update suppression rule (500): %s, %s", rule.ID.ValueString(), tferrors.GetPayloadErrorMessage(internalServerError.Payload)),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Updating Suppression Rule",
			fmt.Sprintf("Failed to update suppression rule %s: %+v", rule.ID.ValueString(), err),
		)

		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Updating Rule",
			fmt.Sprintf("Failed to update rule %s: API returned an empty response", rule.ID.ValueString()),
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Updating Suppression Rule",
			fmt.Sprintf("Failed to update suppression rule: %s", err.Error()),
		)
		return nil, diags
	}

	return payload.Resources[0], diags
}

func (r *cloudSecuritySuppressionRuleResource) deleteSuppressionRule(ctx context.Context, id string) diag.Diagnostics {
	var diags diag.Diagnostics

	params := cloud_policies.DeleteSuppressionRulesParams{
		Context: ctx,
		Ids:     []string{id},
	}

	_, err := r.client.CloudPolicies.DeleteSuppressionRules(&params)
	if err != nil {
		diags.AddError(
			"Error Deleting Rule",
			fmt.Sprintf("Failed to delete rule %s: \n\n %s", id, err.Error()),
		)
	}

	return diags
}

// Expand converts the Terraform model to an API Rule Selection Filter.
func (c ruleSelectionFilterModel) Expand(ctx context.Context) (*models.SuppressionrulesRuleSelectionFilter, diag.Diagnostics) {
	var ruleSelectionFilter models.SuppressionrulesRuleSelectionFilter
	var diags diag.Diagnostics

	if diags = c.RuleIds.ElementsAs(ctx, &ruleSelectionFilter.RuleIds, false); diags.HasError() {
		return nil, diags
	}

	if diags = c.RuleNames.ElementsAs(ctx, &ruleSelectionFilter.RuleNames, false); diags.HasError() {
		return nil, diags
	}

	if diags = c.RuleOrigins.ElementsAs(ctx, &ruleSelectionFilter.RuleOrigins, false); diags.HasError() {
		return nil, diags
	}

	if diags = c.RuleProviders.ElementsAs(ctx, &ruleSelectionFilter.RuleProviders, false); diags.HasError() {
		return nil, diags
	}

	if diags = c.RuleServices.ElementsAs(ctx, &ruleSelectionFilter.RuleServices, false); diags.HasError() {
		return nil, diags
	}

	if diags = c.RuleSeverities.ElementsAs(ctx, &ruleSelectionFilter.RuleSeverities, false); diags.HasError() {
		return nil, diags
	}

	convertedRuleSeverities := make([]string, 0, len(ruleSelectionFilter.RuleSeverities))
	for _, severity := range ruleSelectionFilter.RuleSeverities {
		if converted, ok := severityToString[severity]; ok {
			convertedRuleSeverities = append(convertedRuleSeverities, converted)
		}
	}
	ruleSelectionFilter.RuleSeverities = convertedRuleSeverities

	return &ruleSelectionFilter, diags
}

// Expand converts the Terraform model to an API Scope Asset Filter.
func (c scopeAssetFilterModel) Expand(ctx context.Context) (*models.SuppressionrulesScopeAssetFilter, diag.Diagnostics) {
	var scopeAssetFilter models.SuppressionrulesScopeAssetFilter
	var diags diag.Diagnostics

	if diags = c.AccountIds.ElementsAs(ctx, &scopeAssetFilter.AccountIds, false); diags.HasError() {
		return nil, diags
	}

	if diags = c.CloudGroupIds.ElementsAs(ctx, &scopeAssetFilter.CloudGroupIds, false); diags.HasError() {
		return nil, diags
	}

	if diags = c.CloudProviders.ElementsAs(ctx, &scopeAssetFilter.CloudProviders, false); diags.HasError() {
		return nil, diags
	}

	if diags = c.Regions.ElementsAs(ctx, &scopeAssetFilter.Regions, false); diags.HasError() {
		return nil, diags
	}

	if diags = c.ResourceIds.ElementsAs(ctx, &scopeAssetFilter.ResourceIds, false); diags.HasError() {
		return nil, diags
	}

	if diags = c.ResourceNames.ElementsAs(ctx, &scopeAssetFilter.ResourceNames, false); diags.HasError() {
		return nil, diags
	}

	if diags = c.ResourceTypes.ElementsAs(ctx, &scopeAssetFilter.ResourceTypes, false); diags.HasError() {
		return nil, diags
	}

	if diags = c.ServiceCategories.ElementsAs(ctx, &scopeAssetFilter.ServiceCategories, false); diags.HasError() {
		return nil, diags
	}

	if diags = c.Tags.ElementsAs(ctx, &scopeAssetFilter.Tags, false); diags.HasError() {
		return nil, diags
	}

	return &scopeAssetFilter, diags
}

func isTimestampExpired(timestampStr string) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	timestamp, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		diags.AddError(
			"Error Parsing Timestamp",
			fmt.Sprintf("Failed to parse timestamp: %+v", err),
		)
	}

	return timestamp.Before(time.Now()), diags
}

func (m *cloudSecuritySuppressionRuleResourceModel) setAssetFilter(ctx context.Context, rule models.ApimodelsSuppressionRule) (diags diag.Diagnostics) {
	cloudGroupIDs := make([]string, 0)
	if rule.ScopeAssetFilter != nil && len(rule.ScopeAssetFilter.CloudGroups) != 0 {
		for _, cloudGroup := range rule.ScopeAssetFilter.CloudGroups {
			if cloudGroup != nil && cloudGroup.ID != nil {
				cloudGroupIDs = append(cloudGroupIDs, *cloudGroup.ID)
			}
		}
	}

	scopeAssetFilter := make(map[string]attr.Value)
	if rule.ScopeAssetFilter != nil {
		scopeAssetFilter["account_ids"], diags = fwtypes.OptionalStringSet(ctx, rule.ScopeAssetFilter.AccountIds)
		if diags.HasError() {
			return diags
		}
		scopeAssetFilter["cloud_group_ids"], diags = fwtypes.OptionalStringSet(ctx, cloudGroupIDs)
		if diags.HasError() {
			return diags
		}
		scopeAssetFilter["cloud_providers"], diags = fwtypes.OptionalStringSet(ctx, rule.ScopeAssetFilter.CloudProviders)
		if diags.HasError() {
			return diags
		}
		scopeAssetFilter["regions"], diags = fwtypes.OptionalStringSet(ctx, rule.ScopeAssetFilter.Regions)
		if diags.HasError() {
			return diags
		}
		scopeAssetFilter["resource_ids"], diags = fwtypes.OptionalStringSet(ctx, rule.ScopeAssetFilter.ResourceIds)
		if diags.HasError() {
			return diags
		}
		scopeAssetFilter["resource_names"], diags = fwtypes.OptionalStringSet(ctx, rule.ScopeAssetFilter.ResourceNames)
		if diags.HasError() {
			return diags
		}
		scopeAssetFilter["resource_types"], diags = fwtypes.OptionalStringSet(ctx, rule.ScopeAssetFilter.ResourceTypes)
		if diags.HasError() {
			return diags
		}
		scopeAssetFilter["service_categories"], diags = fwtypes.OptionalStringSet(ctx, rule.ScopeAssetFilter.ServiceCategories)
		if diags.HasError() {
			return diags
		}
		scopeAssetFilter["tags"], diags = fwtypes.OptionalStringSet(ctx, rule.ScopeAssetFilter.Tags)
		if diags.HasError() {
			return diags
		}
	}

	m.AssetFilter = types.ObjectValueMust(
		scopeAssetFilterModel{}.AttributeTypes(),
		scopeAssetFilter,
	)

	return diags
}

func (m *cloudSecuritySuppressionRuleResourceModel) setRuleSelectionFilter(ctx context.Context, rule models.ApimodelsSuppressionRule) (diags diag.Diagnostics) {
	ruleSelectionFilter := make(map[string]attr.Value)

	if rule.RuleSelectionFilter != nil {
		convertedRuleSeverities := make([]string, 0, len(rule.RuleSelectionFilter.RuleSeverities))
		for _, severity := range rule.RuleSelectionFilter.RuleSeverities {
			if converted, ok := stringToSeverity[severity]; ok {
				convertedRuleSeverities = append(convertedRuleSeverities, converted)
			} else {
				convertedRuleSeverities = append(convertedRuleSeverities, severity)
			}
		}

		ruleSelectionFilter["rule_ids"], diags = fwtypes.OptionalStringSet(ctx, rule.RuleSelectionFilter.RuleIds)
		if diags.HasError() {
			return diags
		}
		ruleSelectionFilter["rule_names"], diags = fwtypes.OptionalStringSet(ctx, rule.RuleSelectionFilter.RuleNames)
		if diags.HasError() {
			return diags
		}
		ruleSelectionFilter["rule_origins"], diags = fwtypes.OptionalStringSet(ctx, rule.RuleSelectionFilter.RuleOrigins)
		if diags.HasError() {
			return diags
		}
		ruleSelectionFilter["rule_providers"], diags = fwtypes.OptionalStringSet(ctx, rule.RuleSelectionFilter.RuleProviders)
		if diags.HasError() {
			return diags
		}
		ruleSelectionFilter["rule_services"], diags = fwtypes.OptionalStringSet(ctx, rule.RuleSelectionFilter.RuleServices)
		if diags.HasError() {
			return diags
		}
		ruleSelectionFilter["rule_severities"], diags = fwtypes.OptionalStringSet(ctx, convertedRuleSeverities)
		if diags.HasError() {
			return diags
		}
	} else {
		ruleSelectionFilter["rule_ids"], diags = fwtypes.OptionalStringSet(ctx, nil)
		if diags.HasError() {
			return diags
		}
		ruleSelectionFilter["rule_names"], diags = fwtypes.OptionalStringSet(ctx, nil)
		if diags.HasError() {
			return diags
		}
		ruleSelectionFilter["rule_origins"], diags = fwtypes.OptionalStringSet(ctx, nil)
		if diags.HasError() {
			return diags
		}
		ruleSelectionFilter["rule_providers"], diags = fwtypes.OptionalStringSet(ctx, nil)
		if diags.HasError() {
			return diags
		}
		ruleSelectionFilter["rule_services"], diags = fwtypes.OptionalStringSet(ctx, nil)
		if diags.HasError() {
			return diags
		}
		ruleSelectionFilter["rule_severities"], diags = fwtypes.OptionalStringSet(ctx, nil)
		if diags.HasError() {
			return diags
		}
	}

	m.RuleSelectionFilter = types.ObjectValueMust(
		ruleSelectionFilterModel{}.AttributeTypes(),
		ruleSelectionFilter,
	)

	return diags
}
