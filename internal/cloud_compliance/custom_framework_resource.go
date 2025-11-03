package cloudcompliance

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// FQL filter constants
var (
	filterComplianceControlsByFramework        = "compliance_control_benchmark_name:'%s'+compliance_control_authority:'Custom'"
	sortComplianceControlsByRequirementAsc     = "compliance_control_requirement|asc"
	limitComplianceControlsMax                 = int64(500)
	complianceControlsByFrameworkSectionFilter = "compliance_control_benchmark_name:'%s'+compliance_control_authority:'Custom'+compliance_control_section:'%s'"
	filterComplianceRulesByControl             = "rule_compliance_benchmark:'%s'+rule_control_section:'%s'+rule_control_requirement:'%s'+rule_domain:'CSPM'+rule_subdomain:'IOM'"
	sortComplianceRulesByUpdatedAtAsc          = "rule_updated_at|asc"
	limitComplianceRulesMax                    = int64(500)
)

var (
	_ resource.Resource                   = &cloudComplianceCustomFrameworkResource{}
	_ resource.ResourceWithConfigure      = &cloudComplianceCustomFrameworkResource{}
	_ resource.ResourceWithImportState    = &cloudComplianceCustomFrameworkResource{}
	_ resource.ResourceWithValidateConfig = &cloudComplianceCustomFrameworkResource{}
)

var (
	customFrameworkDocumentationSection        = "Cloud Compliance"
	customFrameworkResourceMarkdownDescription = "This resource allows managing custom compliance frameworks in the CrowdStrike Falcon Platform."
	customFrameworkRequiredScopes              = cloudComplianceCustomFrameworkScopes
)

func NewCloudComplianceCustomFrameworkResource() resource.Resource {
	return &cloudComplianceCustomFrameworkResource{}
}

type cloudComplianceCustomFrameworkResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudComplianceCustomFrameworkResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Active      types.Bool   `tfsdk:"active"`
	Sections    types.Map    `tfsdk:"sections"`
}

type SectionTFModel struct {
	Name     types.String `tfsdk:"name"`
	Controls types.Map    `tfsdk:"controls"`
}

type ControlTFModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Rules       types.Set    `tfsdk:"rules"`
}

// wrap transforms API response values to their terraform model values.
func (d *cloudComplianceCustomFrameworkResourceModel) wrap(
	_ context.Context,
	framework *models.ApimodelsSecurityFramework,
) diag.Diagnostics {
	var diags diag.Diagnostics

	d.ID = types.StringValue(framework.UUID)
	d.Name = types.StringPointerValue(framework.Name)
	d.Description = types.StringValue(framework.Description)
	d.Active = types.BoolValue(framework.Active)

	// Don't warp Sections here - it is handled by readControlsForFramework

	return diags
}

func (r *cloudComplianceCustomFrameworkResource) Configure(
	_ context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
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

// Metadata returns the resource type name.
func (r *cloudComplianceCustomFrameworkResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_compliance_custom_framework"
}

// Schema defines the schema for the resource.
func (r *cloudComplianceCustomFrameworkResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			customFrameworkDocumentationSection,
			customFrameworkResourceMarkdownDescription,
			customFrameworkRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Identifier for the custom compliance framework.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the custom compliance framework.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"description": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "A description of the custom compliance framework.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"active": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the custom compliance framework is active. Defaults to false on create. Once set to true, cannot be changed back to false.",
			},
			"sections": schema.MapNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Map of sections within the framework. Key is an immutable unique string. Changing the section key will trigger a complete delete and create of the section. Sections cannot exist without controls.",
				Validators: []validator.Map{
					mapvalidator.KeysAre(stringvalidator.LengthAtLeast(1)),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Display name of the compliance framework section.",
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
							},
						},
						"controls": schema.MapNestedAttribute{
							Required:            true,
							MarkdownDescription: "Map of controls within the section. Key is an immutable unique string. Changing the control key will trigger a complete delete and create of the control.",
							Validators: []validator.Map{
								mapvalidator.KeysAre(stringvalidator.LengthAtLeast(1)),
							},
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"id": schema.StringAttribute{
										Computed:            true,
										MarkdownDescription: "Identifier for the compliance framework control.",
										PlanModifiers: []planmodifier.String{
											stringplanmodifier.UseStateForUnknown(),
										},
									},
									"name": schema.StringAttribute{
										Required:            true,
										MarkdownDescription: "Display name of the compliance framework control.",
										Validators: []validator.String{
											stringvalidator.LengthAtLeast(1),
										},
									},
									"description": schema.StringAttribute{
										Required:            true,
										MarkdownDescription: "Description of the control.",
										Validators: []validator.String{
											stringvalidator.LengthAtLeast(1),
										},
									},
									"rules": schema.SetAttribute{
										Optional:            true,
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

// Create creates the resource and sets the initial Terraform state.
func (r *cloudComplianceCustomFrameworkResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudComplianceCustomFrameworkResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Creating custom compliance framework", map[string]any{
		"name": plan.Name.ValueString(),
	})

	framework, createFrameworkDiags := r.createFramework(ctx, plan)
	resp.Diagnostics.Append(createFrameworkDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set the ID early for proper cleanup
	plan.ID = types.StringValue(framework.UUID)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create controls and assign rules if sections are provided
	var planSectionsMapByKey map[string]SectionTFModel
	if !plan.Sections.IsNull() && !plan.Sections.IsUnknown() {
		resp.Diagnostics.Append(plan.Sections.ElementsAs(ctx, &planSectionsMapByKey, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Create controls for this framework
		resp.Diagnostics.Append(r.createControlsForFramework(ctx, framework.UUID, planSectionsMapByKey)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Update the plan with the API response
	resp.Diagnostics.Append(plan.wrap(ctx, framework)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read controls and sections data if sections were created
	if !plan.Sections.IsNull() && !plan.Sections.IsUnknown() {
		sections, sectionsDiags := r.readControlsForFramework(ctx, *framework.Name, planSectionsMapByKey)
		resp.Diagnostics.Append(sectionsDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.Sections = sections
	}

	// Set state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *cloudComplianceCustomFrameworkResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudComplianceCustomFrameworkResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reading custom compliance framework", map[string]any{
		"id": state.ID.ValueString(),
	})

	framework, getFrameworkDiags, frameworkNotFound := r.getFramework(ctx, state.ID.ValueString())
	resp.Diagnostics.Append(getFrameworkDiags...)
	if frameworkNotFound {
		resp.State.RemoveResource(ctx)
		return
	}

	if framework == nil {
		return
	}

	// Update state with API response
	resp.Diagnostics.Append(state.wrap(ctx, framework)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var stateSectionsMap map[string]SectionTFModel
	resp.Diagnostics.Append(state.Sections.ElementsAs(ctx, &stateSectionsMap, false)...)
	sectionsMap, sectionsDiags := r.readControlsForFramework(ctx, *framework.Name, stateSectionsMap)
	resp.Diagnostics.Append(sectionsDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Only set sections if the map is not empty or if state.Sections was previously configured
	// This prevents creating drift for frameworks without any controls
	if len(sectionsMap.Elements()) > 0 || (!state.Sections.IsNull() && !state.Sections.IsUnknown()) {
		state.Sections = sectionsMap
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *cloudComplianceCustomFrameworkResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudComplianceCustomFrameworkResourceModel
	var state cloudComplianceCustomFrameworkResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate that active cannot be changed from true to false
	resp.Diagnostics.Append(validateActiveFieldTransition(state.Active, plan.Active)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Updating custom compliance framework", map[string]any{
		"id": plan.ID.ValueString(),
	})

	if plan.Name.Equal(state.Name) || plan.Description.Equal(state.Description) || plan.Active.Equal(state.Active) {
		params := buildUpdateFrameworkParams(ctx, plan)
		updateResp, err := r.client.CloudPolicies.UpdateComplianceFramework(params)
		if err != nil {
			resp.Diagnostics.Append(handleAPIError(err, apiOperationUpdateFramework, state.ID.ValueString())...)
			return
		}

		payload := updateResp.GetPayload()
		resp.Diagnostics.Append(validateAPIResponse(payload, errorUpdatingFramework)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	frameworkID := state.ID.ValueString()
	framework, getFrameworkDiags, frameworkNotFound := r.getFramework(ctx, frameworkID)
	resp.Diagnostics.Append(getFrameworkDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if frameworkNotFound {
		var diags diag.Diagnostics
		framework, diags = r.createFramework(ctx, plan)
		resp.Diagnostics.Append(diags...)
	}

	if framework == nil || resp.Diagnostics.HasError() {
		return
	}

	// Update the plan with the API response
	resp.Diagnostics.Append(plan.wrap(ctx, framework)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If the plan for sections is the same as state, set the new state without processing sections
	if !plan.Sections.Equal(state.Sections) {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}

	var stateSections map[string]SectionTFModel
	var planSections map[string]SectionTFModel
	if !state.Sections.IsNull() && !state.Sections.IsUnknown() {
		resp.Diagnostics.Append(state.Sections.ElementsAs(ctx, &stateSections, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	if !plan.Sections.IsNull() && !plan.Sections.IsUnknown() {
		resp.Diagnostics.Append(plan.Sections.ElementsAs(ctx, &planSections, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		resp.Diagnostics.Append(r.processSectionUpdates(ctx, frameworkID, stateSections, planSections)...)
		if resp.Diagnostics.HasError() {
			return
		}
	} else if !state.Sections.IsNull() && !state.Sections.IsUnknown() {
		// If plan has no sections but state does, delete all existing controls
		resp.Diagnostics.Append(r.deleteAllControlsForFramework(ctx, plan.Name.ValueString())...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Read back the controls to ensure state consistency only if sections are configured
	if !plan.Sections.IsNull() && !plan.Sections.IsUnknown() {
		sectionsMap, sectionsDiags := r.readControlsForFramework(ctx, *framework.Name, planSections)
		resp.Diagnostics.Append(sectionsDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.Sections = sectionsMap
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *cloudComplianceCustomFrameworkResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudComplianceCustomFrameworkResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Deleting custom compliance framework", map[string]any{
		"id": state.ID.ValueString(),
	})

	// First delete all controls associated with this framework
	resp.Diagnostics.Append(r.deleteAllControlsForFramework(ctx, state.Name.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := cloud_policies.NewDeleteComplianceFrameworkParamsWithContext(ctx)
	params.SetIds(state.ID.ValueString())

	deleteResp, err := r.client.CloudPolicies.DeleteComplianceFramework(params)
	if err != nil {
		if _, ok := err.(*cloud_policies.DeleteComplianceFrameworkNotFound); ok {
			// Framework already deleted, consider this success
			tflog.Info(ctx, "Custom compliance framework not found during delete, considering as already deleted", map[string]any{
				"id": state.ID.ValueString(),
			})
			return
		}
		resp.Diagnostics.Append(handleAPIError(err, apiOperationDeleteFramework, state.ID.ValueString())...)
		return
	}

	if deleteResp != nil && deleteResp.Payload != nil {
		payload := deleteResp.GetPayload()
		if err := falcon.AssertNoError(payload.Errors); err != nil {
			resp.Diagnostics.AddError(
				errorDeletingFramework,
				fmt.Sprintf("Failed to delete custom compliance framework: %s", falcon.ErrorExplain(err)),
			)
			return
		}
	}

	tflog.Info(ctx, "Successfully deleted custom compliance framework", map[string]any{
		"id": state.ID.ValueString(),
	})
}

// ImportState imports the resource into Terraform state.
func (r *cloudComplianceCustomFrameworkResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *cloudComplianceCustomFrameworkResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config cloudComplianceCustomFrameworkResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Skip validation if sections is null or unknown
	if config.Sections.IsNull() || config.Sections.IsUnknown() {
		return
	}

	// Validate that no sections are empty
	var sections map[string]SectionTFModel
	resp.Diagnostics.Append(config.Sections.ElementsAs(ctx, &sections, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	for _, section := range sections {
		var controls map[string]ControlTFModel
		resp.Diagnostics.Append(section.Controls.ElementsAs(ctx, &controls, false)...)
		if resp.Diagnostics.HasError() {
			continue
		}

		if len(controls) == 0 {
			sectionName := section.Name.ValueString()
			resp.Diagnostics.AddAttributeError(
				path.Root("sections"),
				"Empty Section Not Allowed",
				fmt.Sprintf("Section '%s' cannot be empty. Each section must contain at least one control.", sectionName),
			)
		}
	}
}

func (r *cloudComplianceCustomFrameworkResource) createFramework(
	ctx context.Context,
	plan cloudComplianceCustomFrameworkResourceModel,
) (*models.ApimodelsSecurityFramework, diag.Diagnostics) {
	var diags diag.Diagnostics
	params := buildCreateFrameworkParams(ctx, plan)
	createResp, err := r.client.CloudPolicies.CreateComplianceFramework(params)
	if err != nil {
		diags.Append(handleAPIError(err, apiOperationCreateFramework, "")...)
		return nil, diags
	}

	payload := createResp.GetPayload()
	diags.Append(validateAPIResponse(payload, errorCreatingFramework)...)
	if diags.HasError() {
		return nil, diags
	}

	return payload.Resources[0], diags
}

// createControlsForFramework creates controls and assigns rules for a framework
func (r *cloudComplianceCustomFrameworkResource) createControlsForFramework(
	ctx context.Context,
	frameworkID string,
	sectionsByKey map[string]SectionTFModel,
) diag.Diagnostics {
	diags := diag.Diagnostics{}

	for _, section := range sectionsByKey {
		var sectionControls map[string]ControlTFModel
		diags.Append(section.Controls.ElementsAs(ctx, &sectionControls, false)...)
		if diags.HasError() {
			continue
		}

		for _, control := range sectionControls {
			diags.Append(r.createSingleControl(ctx, frameworkID, section.Name.ValueString(), control)...)
		}
	}

	return diags
}

// createSingleControl creates a single control
func (r *cloudComplianceCustomFrameworkResource) createSingleControl(
	ctx context.Context,
	frameworkID string,
	sectionName string,
	control ControlTFModel,
) diag.Diagnostics {
	diags := diag.Diagnostics{}
	controlDesc := control.Description.ValueString()
	controlName := control.Name.ValueString()
	params := buildCreateControlParams(ctx, frameworkID, sectionName, controlName, controlDesc)

	createResp, err := r.client.CloudPolicies.CreateComplianceControl(params)
	if err != nil {
		diags.Append(handleAPIError(err, apiOperationCreateControl, "")...)
		return diags
	}

	payload := createResp.GetPayload()
	diags.Append(validateAPIResponse(payload, errorCreatingControl)...)
	if diags.HasError() {
		return diags
	}

	// Assign rules to control if any
	controlID := createResp.Payload.Resources[0].UUID
	var ruleIds []string
	if !control.Rules.IsNull() && len(control.Rules.Elements()) > 0 {
		diags.Append(control.Rules.ElementsAs(ctx, &ruleIds, false)...)
		if diags.HasError() {
			return diags
		}

		tflog.Info(ctx, "Assigning rules to control", map[string]any{
			"controlID":   *controlID,
			"controlName": controlName,
			"ruleIds":     ruleIds,
		})

		assignRulesReq := &models.CommonAssignRulesToControlRequest{RuleIds: ruleIds}
		assignParams := cloud_policies.NewReplaceControlRulesParamsWithContext(ctx).
			WithUID(*controlID).
			WithBody(assignRulesReq)

		_, assignRulesErr := r.client.CloudPolicies.ReplaceControlRules(assignParams)
		if assignRulesErr != nil {
			diags.AddError(
				"Error Assigning Rules",
				fmt.Sprintf("Failed to assign rules to control %s: %s", controlName, falcon.ErrorExplain(assignRulesErr)),
			)
			return diags
		}
	}

	return diags
}

func (r *cloudComplianceCustomFrameworkResource) getFramework(
	ctx context.Context,
	frameworkId string,
) (*models.ApimodelsSecurityFramework, diag.Diagnostics, bool) {
	var diags diag.Diagnostics
	params := cloud_policies.NewGetComplianceFrameworksParamsWithContext(ctx)
	params.SetIds([]string{frameworkId})

	getResp, err := r.client.CloudPolicies.GetComplianceFrameworks(params)
	if err != nil {
		diags.Append(handleAPIError(err, apiOperationReadFramework, frameworkId)...)
		if _, ok := err.(*cloud_policies.GetComplianceFrameworksNotFound); ok {
			return nil, diags, true
		}

		return nil, diags, false
	}

	payload := getResp.GetPayload()
	diags.Append(validateAPIResponse(payload, errorReadingFramework)...)
	if diags.HasError() {
		return nil, diags, false
	}

	if len(payload.Resources) == 0 {
		return nil, diags, true
	}

	return payload.Resources[0], diags, false
}

// readControlsForFramework reads controls and rules for a framework and returns sections as terraform map
func (r *cloudComplianceCustomFrameworkResource) readControlsForFramework(
	ctx context.Context,
	frameworkName string,
	sectionsMapByKey map[string]SectionTFModel,
) (types.Map, diag.Diagnostics) {
	var diags diag.Diagnostics

	controlIDs, queryDiags := r.queryFrameworkControls(ctx, frameworkName)
	diags.Append(queryDiags...)
	if diags.HasError() {
		return types.MapNull(types.ObjectType{}), diags
	}

	// If no controls found, return empty sections map
	if len(controlIDs) == 0 {
		emptyMap, mapDiags := convertSectionsMapToTerraformMap(ctx, map[string]SectionTFModel{})
		diags.Append(mapDiags...)
		return emptyMap, diags
	}

	// Get detailed control information
	apiControls, apiControlDiags := r.getControlDetails(ctx, controlIDs)
	diags.Append(apiControlDiags...)
	if diags.HasError() {
		return types.MapNull(types.ObjectType{}), diags
	}

	sectionsDomainMapByName, sectionsDomainMapDiags := convertSectionsTFMapToDomainMapByName(ctx, sectionsMapByKey)
	diags.Append(sectionsDomainMapDiags...)
	if diags.HasError() {
		return types.MapNull(types.ObjectType{}), diags
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
			sectionKey = r.generateKeyFromName(sectionName)
		} else {
			sectionKey = section.Key
		}

		control, controlExists := sectionsDomainMapByName[sectionName].Controls[controlName]
		if !controlExists {
			controlKey = r.generateKeyFromName(controlName)
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

		controlModel, controlDiags := r.readControlWithRules(ctx, apiControl, frameworkName)
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

func (r *cloudComplianceCustomFrameworkResource) queryFrameworkControls(
	ctx context.Context,
	frameworkName string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	frameworkNameFilter := fmt.Sprintf(filterComplianceControlsByFramework, frameworkName)
	queryControlsParams := cloud_policies.NewQueryComplianceControlsParamsWithContext(ctx).
		WithFilter(&frameworkNameFilter).
		WithSort(&sortComplianceControlsByRequirementAsc).
		WithLimit(&limitComplianceControlsMax)

	queryControlsResp, err := r.client.CloudPolicies.QueryComplianceControls(queryControlsParams)
	if err != nil {
		diags.AddError(errorQueryingControls,
			fmt.Sprintf("Failed to query controls for framework %s: %s", frameworkName, falcon.ErrorExplain(err)))
		return nil, diags
	}

	if queryControlsResp == nil || queryControlsResp.Payload == nil || len(queryControlsResp.Payload.Resources) == 0 {
		return []string{}, diags
	}

	return queryControlsResp.Payload.Resources, diags
}

func (r *cloudComplianceCustomFrameworkResource) getControlDetails(
	ctx context.Context,
	controlIds []string,
) ([]*models.ApimodelsControl, diag.Diagnostics) {
	var diags diag.Diagnostics

	getControlsParams := cloud_policies.NewGetComplianceControlsParamsWithContext(ctx).WithIds(controlIds)
	getControlsResp, err := r.client.CloudPolicies.GetComplianceControls(getControlsParams)
	if err != nil {
		diags.Append(handleAPIError(err, apiOperationReadControls, strings.Join(controlIds, ","))...)
		return nil, diags
	}

	payload := getControlsResp.GetPayload()
	diags.Append(validateAPIResponse(payload, errorGettingControls)...)
	if diags.HasError() {
		return nil, diags
	}

	return getControlsResp.Payload.Resources, diags
}

func (r *cloudComplianceCustomFrameworkResource) queryControlRules(
	ctx context.Context,
	frameworkName, sectionName, requirement string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	rulesByControlFilter := fmt.Sprintf(filterComplianceRulesByControl, frameworkName, sectionName, requirement)
	queryRulesParams := cloud_policies.NewQueryRuleParamsWithContext(ctx).
		WithFilter(&rulesByControlFilter).
		WithSort(&sortComplianceRulesByUpdatedAtAsc).
		WithLimit(&limitComplianceRulesMax)

	queryRulesResp, queryRuleErr := r.client.CloudPolicies.QueryRule(queryRulesParams)
	if queryRuleErr != nil {
		diags.AddError(errorQueryingRules,
			fmt.Sprintf("Failed to query rules for control: %s", falcon.ErrorExplain(queryRuleErr)))
		return nil, diags
	}

	if queryRulesResp == nil || queryRulesResp.Payload == nil {
		return []string{}, diags
	}

	return queryRulesResp.Payload.Resources, diags
}

func (r *cloudComplianceCustomFrameworkResource) readControlWithRules(
	ctx context.Context,
	control *models.ApimodelsControl,
	frameworkName string,
) (ControlTFModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Query rules for this control
	ruleIDs, ruleDiags := r.queryControlRules(ctx, frameworkName, control.SectionName, control.Requirement)
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

func (r *cloudComplianceCustomFrameworkResource) processSectionUpdates(
	ctx context.Context,
	frameworkID string,
	stateSections map[string]SectionTFModel,
	planSections map[string]SectionTFModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// Process each section in the plan
	keyToName := make(map[string]string)
	for sectionKey, planSection := range planSections {
		sectionName := planSection.Name.ValueString()
		keyToName[sectionKey] = sectionName
		stateSection, isSectionInState := stateSections[sectionKey]

		var stateSectionControls map[string]ControlTFModel
		if isSectionInState {
			diags.Append(stateSection.Controls.ElementsAs(ctx, &stateSectionControls, false)...)
			if diags.HasError() {
				continue
			}
		}

		if isSectionInState && !planSection.Name.Equal(stateSection.Name) {
			diags.Append(r.handleSectionRename(ctx, frameworkID, stateSection.Name.ValueString(), sectionName)...)
		}

		var planSectionControls map[string]ControlTFModel
		diags.Append(planSection.Controls.ElementsAs(ctx, &planSectionControls, false)...)
		if diags.HasError() {
			continue
		}

		diags.Append(r.updateSectionControls(ctx, frameworkID, sectionName, stateSectionControls, planSectionControls)...)
	}

	for sectionKey, stateSection := range stateSections {
		if _, isInPlan := keyToName[sectionKey]; !isInPlan {
			var stateSectionControls map[string]ControlTFModel
			diags.Append(stateSection.Controls.ElementsAs(ctx, &stateSectionControls, false)...)
			if diags.HasError() {
				continue
			}

			diags.Append(r.deleteRemovedControls(ctx, stateSectionControls, nil)...)
		}
	}

	return diags
}

// updateSectionControls updates controls differentially to preserve existing control IDs.
func (r *cloudComplianceCustomFrameworkResource) updateSectionControls(
	ctx context.Context,
	frameworkID, sectionName string,
	stateControls, planControls map[string]ControlTFModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	for controlKey, planControl := range planControls {
		// If state controls does not exist create all new controls
		if stateControls == nil {
			diags.Append(r.createSingleControl(ctx, frameworkID, sectionName, planControl)...)
			continue
		}

		stateControl, controlExists := stateControls[controlKey]
		if controlExists {
			if !planControl.Name.Equal(stateControl.Name) || !planControl.Description.Equal(stateControl.Description) {
				diags.Append(r.updateExistingControl(ctx, planControl, sectionName)...)
			}

			// Update rules, if necessary
			if !planControl.Rules.Equal(stateControl.Rules) {
				diags.Append(r.updateControlRules(ctx, planControl)...)
			}

			continue
		}

		diags.Append(r.createSingleControl(ctx, frameworkID, sectionName, planControl)...)
	}

	if diags.HasError() {
		return diags
	}

	// Delete controls that no longer exist in plan
	diags.Append(r.deleteRemovedControls(ctx, stateControls, planControls)...)
	return diags
}

func (r *cloudComplianceCustomFrameworkResource) updateExistingControl(
	ctx context.Context,
	planControl ControlTFModel,
	sectionName string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	controlID := planControl.ID.ValueString()
	controlName := planControl.Name.ValueString()
	controlDesc := planControl.Description.ValueString()
	updateReq := &models.CommonUpdateComplianceControlRequest{
		Name:        &controlName,
		Description: &controlDesc,
	}

	updateParams := cloud_policies.NewUpdateComplianceControlParamsWithContext(ctx).
		WithIds(controlID).
		WithBody(updateReq)

	_, err := r.client.CloudPolicies.UpdateComplianceControl(updateParams)
	if err != nil {
		diags.AddError(errorUpdatingControl,
			fmt.Sprintf("Failed to update control %s in section %s: %s", controlID, sectionName, falcon.ErrorExplain(err)))
	}

	return diags
}

func (r *cloudComplianceCustomFrameworkResource) updateControlRules(
	ctx context.Context,
	planControl ControlTFModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	var planRuleIds []string
	if !planControl.Rules.IsNull() && len(planControl.Rules.Elements()) > 0 {
		diags.Append(planControl.Rules.ElementsAs(ctx, &planRuleIds, false)...)
		if diags.HasError() {
			return diags
		}
	}

	// Always replace rules to ensure consistency
	assignReq := &models.CommonAssignRulesToControlRequest{
		RuleIds: planRuleIds,
	}

	assignParams := cloud_policies.NewReplaceControlRulesParamsWithContext(ctx).
		WithUID(planControl.ID.ValueString()).
		WithBody(assignReq)

	_, assignRulesErr := r.client.CloudPolicies.ReplaceControlRules(assignParams)
	if assignRulesErr != nil {
		diags.AddError(errorAssigningRules,
			fmt.Sprintf("Failed to assign rules to control %s: %s", planControl.Name.ValueString(), falcon.ErrorExplain(assignRulesErr)))
	}

	return diags
}

func (r *cloudComplianceCustomFrameworkResource) deleteRemovedControls(
	ctx context.Context,
	stateControls map[string]ControlTFModel,
	planControls map[string]ControlTFModel,
) diag.Diagnostics {
	var diags diag.Diagnostics
	controlIDsToDelete := make([]string, 0)

	// Delete controls that exist in state but not in plan
	for stateControlKey, stateControl := range stateControls {
		// If plan controls is nil, add all state controls to list of control IDs to be deleted
		if planControls == nil {
			controlIDsToDelete = append(controlIDsToDelete, stateControl.ID.ValueString())
			continue
		}

		if _, isControlInPlan := planControls[stateControlKey]; isControlInPlan {
			continue
		}

		// Delete the control if there is a plan and the control is not in the plan
		controlIDsToDelete = append(controlIDsToDelete, stateControl.ID.ValueString())
	}

	if len(controlIDsToDelete) > 0 {
		deleteParams := cloud_policies.NewDeleteComplianceControlParamsWithContext(ctx).WithIds(controlIDsToDelete)
		_, err := r.client.CloudPolicies.DeleteComplianceControl(deleteParams)
		if err != nil {
			diags.AddWarning("Error Deleting Control",
				fmt.Sprintf("Failed to delete controls %s: %s", controlIDsToDelete, falcon.ErrorExplain(err)))
		}
	}

	return diags
}

func (r *cloudComplianceCustomFrameworkResource) handleSectionRename(
	ctx context.Context,
	frameworkID, oldSectionName, newSectionName string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// Execute section renames using the special API
	tflog.Info(ctx, "Renaming section", map[string]any{
		"frameworkID":    frameworkID,
		"oldSectionName": oldSectionName,
		"newSectionName": newSectionName,
	})

	params := buildRenameSectionParams(ctx, frameworkID, oldSectionName, newSectionName)
	_, err := r.client.CloudPolicies.RenameSectionComplianceFramework(params)
	if err != nil {
		diags.AddError(
			"Error Renaming Section",
			fmt.Sprintf("Failed to rename section from '%s' to '%s': %s", oldSectionName, newSectionName, falcon.ErrorExplain(err)),
		)
	}

	return diags
}

func (r *cloudComplianceCustomFrameworkResource) deleteAllControlsForFramework(
	ctx context.Context,
	frameworkName string,
) diag.Diagnostics {
	diags := diag.Diagnostics{}

	controlIds, controlDiag := r.queryFrameworkControls(ctx, frameworkName)
	if controlDiag.HasError() {
		return controlDiag
	}

	deleteParams := cloud_policies.NewDeleteComplianceControlParamsWithContext(ctx).WithIds(controlIds)
	_, err := r.client.CloudPolicies.DeleteComplianceControl(deleteParams)
	if err != nil {
		// Continue deleting other controls even if one fails
		diags.AddWarning(
			"Error Deleting Controls",
			fmt.Sprintf("Failed to delete controls %s: %s", controlIds, falcon.ErrorExplain(err)),
		)
	}

	return diags
}

// generateKeyFromName converts "Section 1" to "section-1"
func (r *cloudComplianceCustomFrameworkResource) generateKeyFromName(name string) string {
	key := strings.ToLower(name)
	key = regexp.MustCompile(`[^a-z0-9.]+`).ReplaceAllString(key, "-")
	key = strings.Trim(key, "-")

	return key
}

// Validation and business logic utilities

func validateActiveFieldTransition(currentActive, newActive types.Bool) diag.Diagnostics {
	var diags diag.Diagnostics

	if !currentActive.IsNull() && currentActive.ValueBool() && !newActive.ValueBool() {
		diags.AddAttributeError(
			path.Root("active"),
			"Invalid Active Field Change",
			"The active field cannot be changed from true to false. Once a custom compliance framework is activated, it must remain active.",
		)
	}

	return diags
}
