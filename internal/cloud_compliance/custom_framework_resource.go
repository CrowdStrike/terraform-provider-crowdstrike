package cloudcompliance

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"regexp"
	"strings"

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

	params := buildCreateFrameworkParams(ctx, plan)
	createResp, err := r.client.CloudPolicies.CreateComplianceFramework(params)
	if err != nil {
		resp.Diagnostics.Append(handleAPIError(err, apiOperationCreateFramework, "")...)
		return
	}

	payload := createResp.GetPayload()
	resp.Diagnostics.Append(validateAPIResponse(payload, errorCreatingFramework)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the created framework from response
	framework := payload.Resources[0]

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
		sections, sectionsDiags := r.readControlsForFramework(ctx, *framework, planSectionsMapByKey)
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

	params := cloud_policies.NewGetComplianceFrameworksParamsWithContext(ctx)
	params.SetIds([]string{state.ID.ValueString()})

	getResp, err := r.client.CloudPolicies.GetComplianceFrameworks(params)
	if err != nil {
		resp.Diagnostics.Append(handleAPIError(err, apiOperationReadFramework, state.ID.ValueString())...)
		if _, ok := err.(*cloud_policies.GetComplianceFrameworksNotFound); ok {
			// Framework not found, remove from state
			resp.State.RemoveResource(ctx)
		}
		return
	}

	payload := getResp.GetPayload()
	resp.Diagnostics.Append(validateAPIResponse(payload, errorReadingFramework)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(payload.Resources) < 1 {
		// Framework not found, remove from state
		resp.State.RemoveResource(ctx)
		return
	}

	framework := payload.Resources[0]

	// Update state with API response
	resp.Diagnostics.Append(state.wrap(ctx, framework)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var stateSectionsMap map[string]SectionTFModel
	resp.Diagnostics.Append(state.Sections.ElementsAs(ctx, &stateSectionsMap, false)...)
	sectionsMap, sectionsDiags := r.readControlsForFramework(ctx, *framework, stateSectionsMap)
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

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get current state to check if we're trying to change active from true to false
	var state cloudComplianceCustomFrameworkResourceModel
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

	params := buildUpdateFrameworkParams(ctx, plan)
	updateResp, err := r.client.CloudPolicies.UpdateComplianceFramework(params)
	if err != nil {
		resp.Diagnostics.Append(handleAPIError(err, apiOperationUpdateFramework, plan.ID.ValueString())...)
		return
	}

	payload := updateResp.GetPayload()
	resp.Diagnostics.Append(validateAPIResponse(payload, errorUpdatingFramework)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the updated framework from response
	framework := payload.Resources[0]

	// Get current state sections to compare
	stateSections := make(map[string]SectionTFModel)
	if !state.Sections.IsNull() && !state.Sections.IsUnknown() {
		resp.Diagnostics.Append(state.Sections.ElementsAs(ctx, &stateSections, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Handle sections/controls/rules updates using differential approach
	// This preserves existing control IDs and only creates/updates/deletes as needed
	var planSections map[string]SectionTFModel
	if !plan.Sections.IsNull() && !plan.Sections.IsUnknown() && !plan.Sections.Equal(state.Sections) {
		resp.Diagnostics.Append(plan.Sections.ElementsAs(ctx, &planSections, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Update controls differentially
		updatedPlanSections, updateDiags := r.updateControlsForFramework(ctx, plan.ID.ValueString(), stateSections, planSections)
		resp.Diagnostics.Append(updateDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.Sections = updatedPlanSections
	} else if !state.Sections.IsNull() && !state.Sections.IsUnknown() {
		// If plan has no sections but state does, delete all existing controls
		resp.Diagnostics.Append(r.deleteControlsForFramework(ctx, plan.Name.ValueString())...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Update the plan with the API response
	resp.Diagnostics.Append(plan.wrap(ctx, framework)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read back the controls to ensure state consistency only if sections are configured

	if !plan.Sections.IsNull() && !plan.Sections.IsUnknown() {
		sectionsSet, sectionsDiags := r.readControlsForFramework(ctx, *framework, planSections)
		resp.Diagnostics.Append(sectionsDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.Sections = sectionsSet
	}

	// Set state
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
	resp.Diagnostics.Append(r.deleteControlsForFramework(ctx, state.Name.ValueString())...)
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
	// Retrieve import ID and save to id attribute
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
			_, createDiags := r.createSingleControlAndReturn(ctx, frameworkID, section.Name.ValueString(), control)
			diags.Append(createDiags...)
			if diags.HasError() {
				continue
			}
		}
	}

	return diags
}

// createSingleControlAndReturn creates a single control and returns the control model with ID
func (r *cloudComplianceCustomFrameworkResource) createSingleControlAndReturn(
	ctx context.Context,
	frameworkID string,
	sectionName string,
	control ControlTFModel,
) (ControlTFModel, diag.Diagnostics) {
	diags := diag.Diagnostics{}
	emptyControl := ControlTFModel{}

	controlDesc := control.Description.ValueString()
	controlName := control.Name.ValueString()
	params := buildCreateControlParams(ctx, frameworkID, sectionName, controlName, controlDesc)

	createResp, err := r.client.CloudPolicies.CreateComplianceControl(params)
	if err != nil {
		diags.Append(handleAPIError(err, apiOperationCreateControl, "")...)
		return emptyControl, diags
	}

	payload := createResp.GetPayload()
	diags.Append(validateAPIResponse(payload, errorCreatingControl)...)
	if diags.HasError() {
		return emptyControl, diags
	}

	// Assign rules to control if any
	controlID := createResp.Payload.Resources[0].UUID
	var ruleIds []string
	if !control.Rules.IsNull() && len(control.Rules.Elements()) > 0 {
		diags.Append(control.Rules.ElementsAs(ctx, &ruleIds, false)...)
		if diags.HasError() {
			return emptyControl, diags
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
			return emptyControl, diags
		}
	}

	// Return the control model with the new ID
	return ControlTFModel{
		ID:          types.StringValue(*controlID),
		Name:        control.Name,
		Description: control.Description,
		Rules:       control.Rules,
	}, diags
}

// readControlsForFramework reads controls and rules for a framework and returns sections as terraform map
func (r *cloudComplianceCustomFrameworkResource) readControlsForFramework(
	ctx context.Context,
	framework models.ApimodelsSecurityFramework,
	sectionsMapByKey map[string]SectionTFModel,
) (types.Map, diag.Diagnostics) {
	var diags diag.Diagnostics
	frameworkName := *framework.Name

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

	// convert sectionsTFModelMap to sectionsDomainModelsMap
	sectionsDomainMapByName, sectionsDomainMapDiags := convertSectionsTFMapToDomainMapByName(ctx, sectionsMapByKey)
	diags.Append(sectionsDomainMapDiags...)
	if diags.HasError() {
		return types.MapNull(types.ObjectType{}), diags
	}

	// Organize controls by section
	nameToKey := make(map[string]string)
	keyToName := make(map[string]string)
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
			keyToName[sectionKey] = sectionName
			nameToKey[sectionName] = sectionKey
		}

		keyToName[controlKey] = controlName
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

// updateControlsForFramework updates controls differentially to preserve existing control IDs
func (r *cloudComplianceCustomFrameworkResource) updateControlsForFramework(
	ctx context.Context,
	frameworkID string,
	stateSections map[string]SectionTFModel,
	planSections map[string]SectionTFModel,
) (types.Map, diag.Diagnostics) {
	var diags diag.Diagnostics

	for planSectionKey, planSection := range planSections {
		if planSection.Controls.Equal(stateSections[planSectionKey].Controls) && planSection.Name.Equal(stateSections[planSectionKey].Name) {
			continue
		}

	}

	// Build existing controls map for lookup
	stateControls, buildDiags := r.buildControlsMapById(ctx, stateSections)
	diags.Append(buildDiags...)
	if diags.HasError() {
		return types.MapNull(types.ObjectType{}), diags
	}

	// Process control updates
	updatedSections, processDiags := r.processControlUpdates(ctx, frameworkID, stateControls, planSections)
	diags.Append(processDiags...)
	if diags.HasError() {
		return types.MapNull(types.ObjectType{}), diags
	}

	// Delete controls that no longer exist in plan
	deleteDiags := r.deleteRemovedControls(ctx, stateControls, planSections)
	diags.Append(deleteDiags...)

	// Convert to Terraform map
	sectionsMap, mapDiags := convertSectionsMapToTerraformMap(ctx, updatedSections)
	diags.Append(mapDiags...)

	return sectionsMap, diags
}

// Helper functions for updateControlsForFramework
func (r *cloudComplianceCustomFrameworkResource) buildControlsMapById(
	ctx context.Context,
	stateSections map[string]SectionTFModel,
) (map[string]map[string]ControlTFModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	stateControls := make(map[string]map[string]ControlTFModel)

	for sectionName, section := range stateSections {
		var sectionControls map[string]ControlTFModel
		diags.Append(section.Controls.ElementsAs(ctx, &sectionControls, false)...)
		if diags.HasError() {
			continue
		}
		stateControls[sectionName] = sectionControls
	}

	return stateControls, diags
}

func (r *cloudComplianceCustomFrameworkResource) processControlUpdates(
	ctx context.Context,
	frameworkID string,
	stateControlsByKey map[string]map[string]ControlTFModel,
	planSections map[string]SectionTFModel,
) (map[string]SectionTFModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	updatedSections := make(map[string]SectionTFModel)

	// Process each section in the plan
	for sectionKey, planSection := range planSections {
		sectionName := planSection.Name.ValueString()

		var planControlsByKey map[string]ControlTFModel
		diags.Append(planSection.Controls.ElementsAs(ctx, &planControlsByKey, false)...)
		if diags.HasError() {
			continue
		}

		updatedControls := make(map[string]ControlTFModel)

		// Process each control in this section
		nameToKey := make(map[string]string)
		for controlKey, planControl := range planControlsByKey {
			// Store map of name to key for later
			nameToKey[planControl.Name.ValueString()] = controlKey

			// Check if control exists in current state
			if existingSection, sectionExists := stateControlsByKey[sectionKey]; sectionExists {
				if existingControl, controlExists := existingSection[controlKey]; controlExists {
					updateDiags := r.updateExistingControl(ctx, planControl, sectionName)
					diags.Append(updateDiags...)

					// Update rules, if necessary
					if existingControl.Rules.Equal(planControl.Rules) {
						rulesDiags := r.updateControlRules(ctx, planControl)
						diags.Append(rulesDiags...)
					}

					updatedControls[controlKey] = planControl
					continue
				} else {
					// No existing control found, create new one
					tflog.Debug(ctx, "PROCESS: Creating new control", map[string]any{
						"controlName": planControl.Name.ValueString(),
						"sectionName": sectionName,
					})
					createdControl, createDiags := r.createSingleControlAndReturn(ctx, frameworkID, sectionName, planControl)
					diags.Append(createDiags...)
					if !diags.HasError() {
						updatedControls[controlKey] = createdControl
					}
				}
			}

			// No existing control found, create new one
			tflog.Debug(ctx, "PROCESS: Creating new control", map[string]any{
				"controlName": planControl.Name.ValueString(),
				"sectionName": sectionName,
			})
			createdControl, createDiags := r.createSingleControlAndReturn(ctx, frameworkID, sectionName, planControl)
			diags.Append(createDiags...)
			if !diags.HasError() {
				updatedControls[controlKey] = createdControl
			}
		}

		// Convert to Terraform map
		controlsMap, controlsMapDiags := convertControlsMapToTerraformMap(ctx, updatedControls, nameToKey)
		diags.Append(controlsMapDiags...)
		if diags.HasError() {
			continue
		}

		updatedSections[sectionKey] = SectionTFModel{
			Name:     planSection.Name,
			Controls: controlsMap,
		}
	}

	return updatedSections, diags
}

func (r *cloudComplianceCustomFrameworkResource) updateExistingControl(
	ctx context.Context,
	planControl ControlTFModel,
	sectionName string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	controlID := planControl.ID.ValueString()
	controlName := planControl.Name.ValueString()
	//controlDesc := planControl.Description.ValueString()
	updateReq := &models.CommonUpdateComplianceControlRequest{
		Name: &controlName,
		//Description: &controlDesc,
	}

	updateParams := cloud_policies.NewUpdateComplianceControlParamsWithContext(ctx).
		WithIds(controlID).
		WithBody(updateReq)

	_, err := r.client.CloudPolicies.UpdateComplianceControl(updateParams)
	if err != nil {
		diags.AddError(errorUpdatingControl,
			fmt.Sprintf("Failed to update control %s in section %s: %s", controlName, sectionName, falcon.ErrorExplain(err)))
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
	stateControls map[string]map[string]ControlTFModel,
	planSections map[string]SectionTFModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// Delete controls that exist in state but not in plan
	for stateSectionName, stateSection := range stateControls {
		for stateControlName, stateControl := range stateSection {
			// Check if this control still exists in the plan
			controlStillExists := false
			if _, sectionExists := planSections[stateSectionName]; sectionExists {
				var planControls map[string]ControlTFModel
				diags.Append(planSections[stateSectionName].Controls.ElementsAs(ctx, &planControls, false)...)
				if !diags.HasError() {
					if _, controlExists := planControls[stateControlName]; controlExists {
						controlStillExists = true
					}
				}
			}

			if !controlStillExists {
				// Delete this control
				controlID := stateControl.ID.ValueString()
				deleteParams := cloud_policies.NewDeleteComplianceControlParamsWithContext(ctx).WithIds([]string{controlID})
				_, err := r.client.CloudPolicies.DeleteComplianceControl(deleteParams)
				if err != nil {
					diags.AddWarning("Error Deleting Control",
						fmt.Sprintf("Failed to delete control %s: %s", stateControlName, falcon.ErrorExplain(err)))
				}
			}
		}
	}

	return diags
}

// detectSectionRenames identifies section renames by comparing section IDs with different names
func (r *cloudComplianceCustomFrameworkResource) detectSectionRenames(
	ctx context.Context,
	stateSections, planSections map[string]SectionTFModel,
) map[string]string {
	renames := make(map[string]string)

	// Check for sections with same ID but different names
	for sectionID, planSection := range planSections {
		if stateSection, exists := stateSections[sectionID]; exists {
			stateName := stateSection.Name.ValueString()
			planName := planSection.Name.ValueString()

			// If same ID but different names, it's a rename
			if stateName != planName {
				renames[stateName] = planName
			}
		}
	}

	return renames
}

// handleSectionRenames detects and processes section renames using section IDs
func (r *cloudComplianceCustomFrameworkResource) handleSectionRenames(
	ctx context.Context,
	frameworkID string,
	stateSections map[string]SectionTFModel,
	planSections map[string]SectionTFModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// Use private state to detect renames
	sectionRenames := r.detectSectionRenames(ctx, stateSections, planSections)

	// Execute section renames using the special API
	for oldSectionName, newSectionName := range sectionRenames {
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
	}

	return diags
}

func (r *cloudComplianceCustomFrameworkResource) deleteControlsForFramework(
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
	key = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(key, "-")
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
