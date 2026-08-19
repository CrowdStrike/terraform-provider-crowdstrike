package cloudcompliance

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
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

// keyFromNameRegexp matches every run of characters that is not allowed in a
// generated section or control map key.
var keyFromNameRegexp = regexp.MustCompile(`[^a-z0-9.]+`)

// fqlEscapeReplacer escapes the characters that terminate a single-quoted FQL
// string literal so values sourced from the API, such as framework and
// section names, cannot break out of the literal they are interpolated into.
var fqlEscapeReplacer = strings.NewReplacer(`\`, `\\`, `'`, `\'`)

// escapeFQLValue escapes value for safe interpolation into a single-quoted FQL
// string literal.
func escapeFQLValue(value string) string {
	return fqlEscapeReplacer.Replace(value)
}

const (
	// frameworkFilterQueryLimit caps the page size of the filter lookup.
	// Resolving to a single framework only requires knowing whether more than one
	// matched, and the pagination metadata carries the true match count for the
	// error message.
	frameworkFilterQueryLimit int64 = 2

	// filterFrameworkControlsByBenchmark looks up the controls belonging to a
	// framework by name. Unlike filterComplianceControlsByFramework, it is not
	// restricted to controls with the Custom authority, since this data source
	// also looks up built-in frameworks such as CIS.
	filterFrameworkControlsByBenchmark = "compliance_control_benchmark_name:'%s'"
)

var (
	_ datasource.DataSource              = &cloudComplianceFrameworkDataSource{}
	_ datasource.DataSourceWithConfigure = &cloudComplianceFrameworkDataSource{}
)

var (
	frameworkDataSourceDocumentationSection = "Falcon Cloud Security"
	frameworkDataSourceMarkdownDescription  = "This data source provides information about a single compliance framework, built-in or custom, in the CrowdStrike Falcon Platform. Look the framework up by ID, or with an FQL filter that matches exactly one framework, and reference its attributes in other resources."
	frameworkDataSourceRequiredScopes       = cloudComplianceFrameworkScopes
)

// NewCloudComplianceFrameworkDataSource is a helper function to simplify the provider implementation.
func NewCloudComplianceFrameworkDataSource() datasource.DataSource {
	return &cloudComplianceFrameworkDataSource{}
}

// cloudComplianceFrameworkDataSource is the data source implementation.
type cloudComplianceFrameworkDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

// cloudComplianceFrameworkDataSourceModel represents the data source model. Its
// non-lookup attributes mirror cloudComplianceCustomFrameworkResourceModel 1:1.
type cloudComplianceFrameworkDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	Filter      types.String `tfsdk:"filter"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Sections    types.Map    `tfsdk:"sections"`
}

// wrap transforms API response values to their terraform model values.
func (d *cloudComplianceFrameworkDataSourceModel) wrap(
	framework *models.ApimodelsSecurityFramework,
) {
	d.ID = types.StringValue(framework.UUID)
	d.Name = types.StringPointerValue(framework.Name)
	d.Description = types.StringValue(framework.Description)

	// Sections is populated separately by readControlsForFramework.
}

// Configure adds the provider configured client to the data source.
func (d *cloudComplianceFrameworkDataSource) Configure(
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
func (d *cloudComplianceFrameworkDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_compliance_framework"
}

// Schema defines the schema for the data source.
func (d *cloudComplianceFrameworkDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			frameworkDataSourceDocumentationSection,
			frameworkDataSourceMarkdownDescription,
			frameworkDataSourceRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Identifier for the compliance framework. Exactly one of `id` or `filter` must be provided.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					stringvalidator.ExactlyOneOf(path.MatchRoot("filter"), path.MatchRoot("id")),
				},
			},
			"filter": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "FQL filter used to find the compliance framework. The filter must resolve to exactly one framework: the lookup fails if it matches none or more than one. Exactly one of `id` or `filter` must be provided. The only filterable properties are `compliance_framework_name`, `compliance_framework_version`, and `compliance_framework_authority`. The framework identifier is not a filterable property, so use `id` to look a framework up by identifier. Framework names are unique, so a name equality filter is the reliable way to resolve one framework, for example `compliance_framework_name:'PCI DSS Internal'`; equality matches the whole name and is case sensitive. See the Filtering section above for the operators and the full set of caveats.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The name of the compliance framework.",
			},
			"description": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "A description of the compliance framework.",
			},
			"sections": schema.MapNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Map of sections within the framework. Key is an immutable unique string.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Display name of the compliance framework section.",
						},
						"controls": schema.MapNestedAttribute{
							Computed:            true,
							MarkdownDescription: "Map of controls within the section. Key is an immutable unique string.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"id": schema.StringAttribute{
										Computed:            true,
										MarkdownDescription: "Identifier for the compliance framework control.",
									},
									"name": schema.StringAttribute{
										Computed:            true,
										MarkdownDescription: "Display name of the compliance framework control.",
									},
									"description": schema.StringAttribute{
										Computed:            true,
										MarkdownDescription: "Description of the control.",
									},
									"rules": schema.SetAttribute{
										Computed:            true,
										ElementType:         types.StringType,
										MarkdownDescription: "Set of rule IDs assigned to this control.",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// Read refreshes the Terraform state with the latest data.
func (d *cloudComplianceFrameworkDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data cloudComplianceFrameworkDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reading compliance framework", map[string]any{
		"id":     data.ID.ValueString(),
		"filter": data.Filter.ValueString(),
	})

	framework, lookupDiags := d.lookupFramework(ctx, data.ID.ValueString(), data.Filter.ValueString())
	resp.Diagnostics.Append(lookupDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.wrap(framework)

	sectionsMap, sectionsDiags := readControlsForFramework(ctx, d.client, data.Name.ValueString(), nil)
	resp.Diagnostics.Append(sectionsDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Sections = sectionsMap

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// lookupFramework resolves a single compliance framework by ID or by
// FQL filter. Exactly one of id or filter must be non-empty; the schema
// validator enforces that.
func (d *cloudComplianceFrameworkDataSource) lookupFramework(
	ctx context.Context,
	id string,
	filter string,
) (*models.ApimodelsSecurityFramework, diag.Diagnostics) {
	var diags diag.Diagnostics

	if id == "" {
		resolvedID, resolveDiags := d.resolveFrameworkIDFromFilter(ctx, filter)
		diags.Append(resolveDiags...)
		if diags.HasError() {
			return nil, diags
		}

		id = resolvedID
	}

	framework, getDiags := d.getFrameworkByID(ctx, id)
	diags.Append(getDiags...)
	if diags.HasError() {
		return nil, diags
	}

	return framework, diags
}

// resolveFrameworkIDFromFilter returns the identifier of the single compliance
// framework matching filter, erroring when the filter matches none or
// more than one.
func (d *cloudComplianceFrameworkDataSource) resolveFrameworkIDFromFilter(
	ctx context.Context,
	filter string,
) (string, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "[datasource] Looking up compliance framework by filter", map[string]any{
		"filter": filter,
	})

	limit := frameworkFilterQueryLimit
	queryResp, err := d.client.CloudPolicies.QueryComplianceFrameworks(
		cloud_policies.NewQueryComplianceFrameworksParamsWithContext(ctx).
			WithFilter(&filter).
			WithLimit(&limit),
	)
	notFoundDetail := fmt.Sprintf("No compliance framework matched the filter %q.", filter)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Read,
			err,
			frameworkDataSourceRequiredScopes,
			tferrors.WithNotFoundDetail(notFoundDetail),
		))
		return "", diags
	}

	if queryResp == nil || queryResp.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return "", diags
	}

	if payloadDiag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, queryResp.Payload.Errors); payloadDiag != nil {
		diags.Append(payloadDiag)
		return "", diags
	}

	if len(queryResp.Payload.Resources) == 0 {
		diags.Append(tferrors.NewNotFoundError(notFoundDetail))
		return "", diags
	}

	// The page is capped at customFrameworkFilterQueryLimit, so the pagination
	// total is the only reliable source for how many frameworks actually matched.
	matched := int64(len(queryResp.Payload.Resources))
	if queryResp.Payload.Meta != nil && queryResp.Payload.Meta.Pagination != nil &&
		queryResp.Payload.Meta.Pagination.Total != nil {
		matched = *queryResp.Payload.Meta.Pagination.Total
	}

	if matched > 1 {
		diags.AddError(
			"Multiple compliance frameworks matched",
			fmt.Sprintf(
				"The filter %q matched %d compliance frameworks, but exactly one is required. Narrow the filter until it matches a single framework, or look the framework up by id.",
				filter,
				matched,
			),
		)
		return "", diags
	}

	return queryResp.Payload.Resources[0], diags
}

// getFrameworkByID returns the compliance framework with the supplied identifier.
func (d *cloudComplianceFrameworkDataSource) getFrameworkByID(
	ctx context.Context,
	id string,
) (*models.ApimodelsSecurityFramework, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "[datasource] Looking up compliance framework by ID", map[string]any{
		"id": id,
	})

	getResp, err := d.client.CloudPolicies.GetComplianceFrameworks(
		cloud_policies.NewGetComplianceFrameworksParamsWithContext(ctx).WithIds([]string{id}),
	)
	notFoundDetail := fmt.Sprintf("No compliance framework found with ID %q.", id)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Read,
			err,
			frameworkDataSourceRequiredScopes,
			tferrors.WithNotFoundDetail(notFoundDetail),
		))
		return nil, diags
	}

	if getResp == nil || getResp.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	if payloadDiag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, getResp.Payload.Errors); payloadDiag != nil {
		diags.Append(payloadDiag)
		return nil, diags
	}

	if len(getResp.Payload.Resources) == 0 || getResp.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewNotFoundError(notFoundDetail))
		return nil, diags
	}

	return getResp.Payload.Resources[0], diags
}

// readControlsForFramework reads controls and rules for a framework and returns sections as terraform map.
// sectionsMapByKey carries the section and control map keys already known to Terraform so they are
// preserved across reads; pass nil to generate keys from the section and control names.
func readControlsForFramework(
	ctx context.Context,
	falconClient *client.CrowdStrikeAPISpecification,
	frameworkName string,
	sectionsMapByKey map[string]SectionTFModel,
) (types.Map, diag.Diagnostics) {
	var diags diag.Diagnostics

	controlIDs, queryDiags := queryFrameworkControls(ctx, falconClient, frameworkName)
	diags.Append(queryDiags...)
	if diags.HasError() {
		return types.MapNull(types.ObjectType{AttrTypes: sectionAttrTypes}), diags
	}

	// If no controls found, return null sections map
	if len(controlIDs) == 0 {
		return types.MapNull(types.ObjectType{AttrTypes: sectionAttrTypes}), diags
	}

	// Get detailed control information
	apiControls, apiControlDiags := getControlDetails(ctx, falconClient, controlIDs)
	diags.Append(apiControlDiags...)
	if diags.HasError() {
		return types.MapNull(types.ObjectType{AttrTypes: sectionAttrTypes}), diags
	}

	sectionsDomainMapByName, sectionsDomainMapDiags := convertSectionsTFMapToDomainMapByName(ctx, sectionsMapByKey)
	diags.Append(sectionsDomainMapDiags...)
	if diags.HasError() {
		return types.MapNull(types.ObjectType{AttrTypes: sectionAttrTypes}), diags
	}

	// Organize controls by section
	nameToKey := make(map[string]string)
	respSectionsMapByNames := make(map[string]map[string]ControlTFModel)
	for _, apiControl := range apiControls {
		sectionName := apiControl.SectionName
		controlName := *apiControl.Name
		var sectionKey string
		var controlKey string

		section, sectionExists := sectionsDomainMapByName[sectionName]
		if !sectionExists {
			sectionKey = generateKeyFromName(sectionName)
		} else {
			sectionKey = section.Key
		}

		control, controlExists := sectionsDomainMapByName[sectionName].Controls[controlName]
		if !controlExists {
			controlKey = generateKeyFromName(controlName)
		} else {
			controlKey = control.Key
		}

		if _, exists := nameToKey[sectionName]; !exists {
			nameToKey[sectionName] = sectionKey
		}

		nameToKey[controlName] = controlKey

		// Initialize section if it does not exist
		if _, exists := respSectionsMapByNames[sectionName]; !exists {
			respSectionsMapByNames[sectionName] = make(map[string]ControlTFModel)
		}

		controlModel, controlDiags := readControlWithRules(ctx, falconClient, apiControl, frameworkName)
		diags.Append(controlDiags...)
		if diags.HasError() {
			continue
		}

		respSectionsMapByNames[sectionName][controlName] = controlModel
	}

	// Convert sections and controls to terraform maps
	sectionsMap := make(map[string]SectionTFModel)
	for sectionName, section := range respSectionsMapByNames {
		controlsMap, controlsMapDiags := convertControlsMapToTerraformMap(ctx, section, nameToKey)
		diags.Append(controlsMapDiags...)
		if diags.HasError() {
			continue
		}

		sectionKey := nameToKey[sectionName]
		sectionsMap[sectionKey] = SectionTFModel{
			Name:     types.StringValue(sectionName),
			Controls: controlsMap,
		}
	}

	sectionsTFMap, sectionsMapDiags := convertSectionsMapToTerraformMap(ctx, sectionsMap)
	diags.Append(sectionsMapDiags...)

	return sectionsTFMap, diags
}

// queryFrameworkControls returns the IDs of the controls belonging to a framework.
func queryFrameworkControls(
	ctx context.Context,
	falconClient *client.CrowdStrikeAPISpecification,
	frameworkName string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	frameworkNameFilter := fmt.Sprintf(filterFrameworkControlsByBenchmark, escapeFQLValue(frameworkName))
	queryControlsParams := cloud_policies.NewQueryComplianceControlsParamsWithContext(ctx).
		WithFilter(&frameworkNameFilter).
		WithSort(&sortComplianceControlsByRequirementAsc).
		WithLimit(&limitComplianceControlsMax)

	queryControlsResp, err := falconClient.CloudPolicies.QueryComplianceControls(queryControlsParams)
	if err != nil {
		diags.AddError(errorQueryingControls,
			fmt.Sprintf("Failed to query controls for framework %s: %s", frameworkName, falcon.ErrorExplain(err)))
		return nil, diags
	}

	if queryControlsResp == nil || queryControlsResp.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	if payloadDiag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, queryControlsResp.Payload.Errors); payloadDiag != nil {
		diags.Append(payloadDiag)
		return nil, diags
	}

	if len(queryControlsResp.Payload.Resources) == 0 {
		return []string{}, diags
	}

	return queryControlsResp.Payload.Resources, diags
}

// getControlDetails returns the full control records for the supplied control IDs.
func getControlDetails(
	ctx context.Context,
	falconClient *client.CrowdStrikeAPISpecification,
	controlIDs []string,
) ([]*models.ApimodelsControl, diag.Diagnostics) {
	var diags diag.Diagnostics

	getControlsParams := cloud_policies.NewGetComplianceControlsParamsWithContext(ctx).WithIds(controlIDs)
	getControlsResp, err := falconClient.CloudPolicies.GetComplianceControls(getControlsParams)
	if err != nil {
		diags.Append(handleAPIError(err, apiOperationReadControls, strings.Join(controlIDs, ","))...)
		return nil, diags
	}

	payload := getControlsResp.GetPayload()
	diags.Append(validateAPIResponse(payload, errorGettingControls)...)
	if diags.HasError() {
		return nil, diags
	}

	return getControlsResp.Payload.Resources, diags
}

// readControlWithRules converts an API control into its terraform model, including the
// rule IDs assigned to it.
func readControlWithRules(
	ctx context.Context,
	falconClient *client.CrowdStrikeAPISpecification,
	control *models.ApimodelsControl,
	frameworkName string,
) (ControlTFModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Query rules for this control
	ruleIDs, ruleDiags := queryControlRules(ctx, falconClient, frameworkName, control.SectionName, control.Requirement)
	diags.Append(ruleDiags...)
	if diags.HasError() {
		return ControlTFModel{}, diags
	}

	// Convert rules to Terraform set
	rulesSet, setDiags := convertRulesToTerraformSet(ruleIDs)
	diags.Append(setDiags...)
	if diags.HasError() {
		return ControlTFModel{}, diags
	}

	return ControlTFModel{
		ID:          types.StringValue(*control.UUID),
		Name:        types.StringValue(*control.Name),
		Description: types.StringValue(control.Description),
		Rules:       rulesSet,
	}, diags
}

// queryControlRules returns the IDs of the rules assigned to a control.
func queryControlRules(
	ctx context.Context,
	falconClient *client.CrowdStrikeAPISpecification,
	frameworkName, sectionName, requirement string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	rulesByControlFilter := fmt.Sprintf(
		filterComplianceRulesByControl,
		escapeFQLValue(frameworkName),
		escapeFQLValue(sectionName),
		escapeFQLValue(requirement),
	)
	queryRulesParams := cloud_policies.NewQueryRuleParamsWithContext(ctx).
		WithFilter(&rulesByControlFilter).
		WithSort(&sortComplianceRulesByUpdatedAtAsc).
		WithLimit(&limitComplianceRulesMax)

	queryRulesResp, queryRuleErr := falconClient.CloudPolicies.QueryRule(queryRulesParams)
	if queryRuleErr != nil {
		diags.AddError(errorQueryingRules,
			fmt.Sprintf("Failed to query rules for control: %s", falcon.ErrorExplain(queryRuleErr)))
		return nil, diags
	}

	if queryRulesResp == nil || queryRulesResp.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	if payloadDiag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, queryRulesResp.Payload.Errors); payloadDiag != nil {
		diags.Append(payloadDiag)
		return nil, diags
	}

	return queryRulesResp.Payload.Resources, diags
}

// generateKeyFromName converts "Section 1" to "section-1".
func generateKeyFromName(name string) string {
	key := strings.ToLower(name)
	key = keyFromNameRegexp.ReplaceAllString(key, "-")
	key = strings.Trim(key, "-")

	return key
}
