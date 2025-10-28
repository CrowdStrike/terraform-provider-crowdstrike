package cloudcompliance

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
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

const (
	complianceControlsByFrameworkFilter        = "compliance_control_benchmark_name:'%s'+compliance_control_authority:'Custom'"
	complianceControlsByFrameworkVersionFilter = "compliance_control_benchmark_name:'%s'+compliance_control_authority:'Custom'+compliance_control_benchmark_version:'%s'"
	complianceControlsByFrameworkSectionFilter = "compliance_control_benchmark_name:'%s'+compliance_control_authority:'Custom'+compliance_control_section:'%s'"
	complianceRulesByControlFilter             = "rule_compliance_benchmark:'%s'+rule_control_section:'%s'+rule_control_requirement:'%s'"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &cloudComplianceCustomFrameworkResource{}
	_ resource.ResourceWithConfigure   = &cloudComplianceCustomFrameworkResource{}
	_ resource.ResourceWithImportState = &cloudComplianceCustomFrameworkResource{}
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

type SectionModel struct {
	Controls types.Map `tfsdk:"controls"`
}

type ControlModel struct {
	ID          types.String `tfsdk:"id"`
	Description types.String `tfsdk:"description"`
	Rules       types.Set    `tfsdk:"rules"`
}

func (r *cloudComplianceCustomFrameworkResource) Configure(
	_ context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	falconClient, ok := req.ProviderData.(*client.CrowdStrikeAPISpecification)

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

	r.client = falconClient
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
				MarkdownDescription: "The unique identifier for the custom compliance framework.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the custom compliance framework.",
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
				MarkdownDescription: "Map of sections within the framework. Key is the section name. Sections cannot exist without controls.",
				Validators: []validator.Map{
					mapvalidator.KeysAre(stringvalidator.LengthAtLeast(1)),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"controls": schema.MapNestedAttribute{
							Required:            true,
							MarkdownDescription: "Map of controls within the section. Key is the control name.",
							Validators: []validator.Map{
								mapvalidator.KeysAre(stringvalidator.LengthAtLeast(1)),
							},
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"id": schema.StringAttribute{
										Computed:            true,
										MarkdownDescription: "The unique identifier for the framework control.",
										PlanModifiers: []planmodifier.String{
											stringplanmodifier.UseStateForUnknown(),
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

	// Create the framework request
	name := plan.Name.ValueString()
	description := plan.Description.ValueString()
	createReq := &models.CommonCreateComplianceFrameworkRequest{
		Name:        &name,
		Description: &description,
		Active:      plan.Active.ValueBool(),
	}

	params := cloud_policies.NewCreateComplianceFrameworkParamsWithContext(ctx)
	params.SetBody(createReq)

	createResp, err := r.client.CloudPolicies.CreateComplianceFramework(params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.CreateComplianceFrameworkBadRequest); ok {
			resp.Diagnostics.AddError(
				"Error Creating Custom Compliance Framework",
				fmt.Sprintf("Failed to create custom compliance framework (%+v): %s", *badRequest.Payload.Errors[0].Code, *badRequest.Payload.Errors[0].Message),
			)
			return
		}

		resp.Diagnostics.AddError(
			"Error Creating Custom Compliance Framework",
			fmt.Sprintf("Failed to create custom compliance framework: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if createResp == nil || createResp.Payload == nil {
		resp.Diagnostics.AddError(
			"Error Creating Custom Compliance Framework",
			"The API returned an empty response.",
		)
		return
	}

	payload := createResp.GetPayload()
	if err := falcon.AssertNoError(payload.Errors); err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Custom Compliance Framework",
			fmt.Sprintf("Failed to create custom compliance framework: %s", err.Error()),
		)
		return
	}

	if len(payload.Resources) < 1 {
		resp.Diagnostics.AddError(
			"Error Creating Custom Compliance Framework",
			"No framework returned from API.",
		)
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
	var sections map[string]SectionModel
	if !plan.Sections.IsNull() && !plan.Sections.IsUnknown() {
		resp.Diagnostics.Append(plan.Sections.ElementsAs(ctx, &sections, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Create controls for this framework
		resp.Diagnostics.Append(r.createControlsForFramework(ctx, framework.UUID, sections)...)
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
		sectionsMap, sectionsDiags := r.readControlsForFramework(ctx, *framework)
		resp.Diagnostics.Append(sectionsDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.Sections = sectionsMap
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
		if badRequest, ok := err.(*cloud_policies.GetComplianceFrameworksBadRequest); ok {
			resp.Diagnostics.AddError(
				"Error Reading Custom Compliance Framework",
				fmt.Sprintf("Failed to read custom compliance framework (400): %+v", *badRequest.Payload.Errors[0].Message),
			)
			return
		}

		if _, ok := err.(*cloud_policies.GetComplianceFrameworksNotFound); ok {
			// Framework not found, remove from state
			resp.State.RemoveResource(ctx)
			return
		}

		if internalServerError, ok := err.(*cloud_policies.GetComplianceFrameworksInternalServerError); ok {
			resp.Diagnostics.AddError(
				"Error Reading Custom Compliance Framework",
				fmt.Sprintf("Failed to read custom compliance framework (500): %+v", *internalServerError.Payload.Errors[0].Message),
			)
			return
		}

		resp.Diagnostics.AddError(
			"Error Reading Custom Compliance Framework",
			fmt.Sprintf("Failed to read custom compliance framework: %+v", err),
		)
		return
	}

	if getResp == nil || getResp.Payload == nil {
		resp.Diagnostics.AddError(
			"Error Reading Custom Compliance Framework",
			"The API returned an empty response.",
		)
		return
	}

	payload := getResp.GetPayload()
	if err := falcon.AssertNoError(payload.Errors); err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Custom Compliance Framework",
			fmt.Sprintf("Failed to read custom compliance framework: %s", err.Error()),
		)
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

	sectionsMap, sectionsDiags := r.readControlsForFramework(ctx, *framework)
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
	if !state.Active.IsNull() && state.Active.ValueBool() && !plan.Active.ValueBool() {
		resp.Diagnostics.AddAttributeError(
			path.Root("active"),
			"Invalid Active Field Change",
			"The active field cannot be changed from true to false. Once a custom compliance framework is activated, it must remain active.",
		)
		return
	}

	tflog.Info(ctx, "Updating custom compliance framework", map[string]any{
		"id": plan.ID.ValueString(),
	})

	// Create the update request
	name := plan.Name.ValueString()
	description := plan.Description.ValueString()
	updateReq := &models.CommonUpdateComplianceFrameworkRequest{
		Name:        &name,
		Description: &description,
		Active:      plan.Active.ValueBool(),
	}

	params := cloud_policies.NewUpdateComplianceFrameworkParamsWithContext(ctx)
	params.SetIds(plan.ID.ValueString()) // Should be params.SetId (update in gofalcon)
	params.SetBody(updateReq)

	updateResp, err := r.client.CloudPolicies.UpdateComplianceFramework(params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.UpdateComplianceFrameworkBadRequest); ok {
			resp.Diagnostics.AddError(
				"Error Updating Custom Compliance Framework",
				fmt.Sprintf("Failed to update custom compliance framework (400): %+v", *badRequest.Payload.Errors[0].Message),
			)
			return
		}

		if notFound, ok := err.(*cloud_policies.UpdateComplianceFrameworkNotFound); ok {
			resp.Diagnostics.AddError(
				"Custom Compliance Framework Not Found",
				fmt.Sprintf("Custom compliance framework with ID %s was not found (404): %+v", plan.ID.ValueString(), *notFound.Payload.Errors[0].Message),
			)
			return
		}

		resp.Diagnostics.AddError(
			"Error Updating Custom Compliance Framework",
			fmt.Sprintf("Failed to update custom compliance framework: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if updateResp == nil || updateResp.Payload == nil {
		resp.Diagnostics.AddError(
			"Error Updating Custom Compliance Framework",
			"The API returned an empty response.",
		)
		return
	}

	payload := updateResp.GetPayload()
	if err := falcon.AssertNoError(payload.Errors); err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Custom Compliance Framework",
			fmt.Sprintf("Failed to update custom compliance framework: %s", err.Error()),
		)
		return
	}

	if len(payload.Resources) < 1 {
		resp.Diagnostics.AddError(
			"Error Updating Custom Compliance Framework",
			"No framework returned from API.",
		)
		return
	}

	// Get the updated framework from response
	framework := payload.Resources[0]

	// Handle sections/controls/rules updates using differential approach
	// This preserves existing control IDs and only creates/updates/deletes as needed
	if !plan.Sections.IsNull() && !plan.Sections.IsUnknown() {
		var planSections map[string]SectionModel
		resp.Diagnostics.Append(plan.Sections.ElementsAs(ctx, &planSections, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Get current state sections to compare
		var stateSections map[string]SectionModel
		if !state.Sections.IsNull() && !state.Sections.IsUnknown() {
			resp.Diagnostics.Append(state.Sections.ElementsAs(ctx, &stateSections, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
		} else {
			stateSections = make(map[string]SectionModel)
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
		sectionsMap, sectionsDiags := r.readControlsForFramework(ctx, *framework)
		resp.Diagnostics.Append(sectionsDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.Sections = sectionsMap
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
		if badRequest, ok := err.(*cloud_policies.DeleteComplianceFrameworkBadRequest); ok {
			resp.Diagnostics.AddError(
				"Error Deleting Custom Compliance Framework",
				fmt.Sprintf("Failed to delete custom compliance framework (400): %+v", *badRequest.Payload.Errors[0].Message),
			)
			return
		}

		if _, ok := err.(*cloud_policies.DeleteComplianceFrameworkNotFound); ok {
			// Framework already deleted, consider this success
			tflog.Info(ctx, "Custom compliance framework not found during delete, considering as already deleted", map[string]any{
				"id": state.ID.ValueString(),
			})
			return
		}

		resp.Diagnostics.AddError(
			"Error Deleting Custom Compliance Framework",
			fmt.Sprintf("Failed to delete custom compliance framework: %+v", err),
		)
		return
	}

	if deleteResp != nil && deleteResp.Payload != nil {
		payload := deleteResp.GetPayload()
		if err := falcon.AssertNoError(payload.Errors); err != nil {
			resp.Diagnostics.AddError(
				"Error Deleting Custom Compliance Framework",
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

// wrap transforms API response values to their terraform model values.
func (d *cloudComplianceCustomFrameworkResourceModel) wrap(
	ctx context.Context,
	framework *models.ApimodelsSecurityFramework,
) diag.Diagnostics {
	var diags diag.Diagnostics

	d.ID = types.StringValue(framework.UUID)
	d.Name = types.StringPointerValue(framework.Name)
	d.Description = types.StringValue(framework.Description)
	d.Active = types.BoolValue(framework.Active)

	// Don't modify Sections here - it will be handled by readControlsForFramework
	// in the Read method or set explicitly in Create/Update methods

	return diags
}

// updateControlsForFramework updates controls differentially to preserve existing control IDs
func (r *cloudComplianceCustomFrameworkResource) updateControlsForFramework(
	ctx context.Context,
	frameworkID string,
	stateSections map[string]SectionModel,
	planSections map[string]SectionModel,
) (types.Map, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	// Build maps of existing controls by section and name for easy lookup
	existingControls := make(map[string]map[string]ControlModel)
	for sectionName, section := range stateSections {
		var sectionControls map[string]ControlModel
		diags.Append(section.Controls.ElementsAs(ctx, &sectionControls, false)...)
		if diags.HasError() {
			continue
		}
		existingControls[sectionName] = sectionControls
	}

	// Build the updated sections map to return
	updatedSections := make(map[string]SectionModel)

	// Process each section in the plan
	for sectionName, planSection := range planSections {
		var planControls map[string]ControlModel
		diags.Append(planSection.Controls.ElementsAs(ctx, &planControls, false)...)
		if diags.HasError() {
			continue
		}

		updatedControls := make(map[string]ControlModel)

		// Process each control in this section
		for controlName, planControl := range planControls {
			// Check if control exists in current state
			if existingSection, sectionExists := existingControls[sectionName]; sectionExists {
				if existingControl, controlExists := existingSection[controlName]; controlExists {
					// Control exists, update it if description changed
					if existingControl.Description.ValueString() != planControl.Description.ValueString() {
						controlID := existingControl.ID.ValueString()
						controlDesc := planControl.Description.ValueString()
						updateReq := &models.CommonUpdateComplianceControlRequest{
							Description: &controlDesc,
						}

						updateParams := cloud_policies.NewUpdateComplianceControlParamsWithContext(ctx).
							WithIds(controlID).
							WithBody(updateReq)

						_, err := r.client.CloudPolicies.UpdateComplianceControl(updateParams)
						if err != nil {
							diags.AddError(
								"Error Updating Control",
								fmt.Sprintf("Failed to update control %s in section %s: %s", controlName, sectionName, falcon.ErrorExplain(err)),
							)
							continue
						}
					}

					// Handle rule assignments separately (always update rules to match plan)
					controlID := existingControl.ID.ValueString()
					var planRuleIds []string
					if !planControl.Rules.IsNull() && len(planControl.Rules.Elements()) > 0 {
						diags.Append(planControl.Rules.ElementsAs(ctx, &planRuleIds, false)...)
						if diags.HasError() {
							continue
						}
					}

					// Always replace rules to ensure consistency
					assignReq := &models.CommonAssignRulesToControlRequest{
						RuleIds: planRuleIds,
					}

					assignParams := cloud_policies.NewReplaceControlRulesParamsWithContext(ctx).
						WithUID(controlID).
						WithBody(assignReq)

					_, assignRulesErr := r.client.CloudPolicies.ReplaceControlRules(assignParams)
					if assignRulesErr != nil {
						diags.AddError(
							"Error Assigning Rules",
							fmt.Sprintf("Failed to assign rules to control %s: %s", controlName, falcon.ErrorExplain(assignRulesErr)),
						)
					}

					// Use existing control with updated data
					updatedControls[controlName] = ControlModel{
						ID:          existingControl.ID,      // Keep existing ID
						Description: planControl.Description, // Use plan description
						Rules:       planControl.Rules,       // Use plan rules
					}
				} else {
					// Control doesn't exist in this section, create it
					createdControl, createDiags := r.createSingleControlAndReturn(ctx, frameworkID, sectionName, controlName, planControl)
					diags.Append(createDiags...)
					if !diags.HasError() {
						updatedControls[controlName] = createdControl
					}
				}
			} else {
				// Section doesn't exist, create the control
				createdControl, createDiags := r.createSingleControlAndReturn(ctx, frameworkID, sectionName, controlName, planControl)
				diags.Append(createDiags...)
				if !diags.HasError() {
					updatedControls[controlName] = createdControl
				}
			}
		}

		// Convert updatedControls to terraform Map
		controlsAttrValue := make(map[string]attr.Value)
		for controlName, control := range updatedControls {
			controlValue, controlDiags := types.ObjectValue(
				map[string]attr.Type{
					"id":          types.StringType,
					"description": types.StringType,
					"rules":       types.SetType{ElemType: types.StringType},
				},
				map[string]attr.Value{
					"id":          control.ID,
					"description": control.Description,
					"rules":       control.Rules,
				},
			)
			diags.Append(controlDiags...)
			if diags.HasError() {
				continue
			}
			controlsAttrValue[controlName] = controlValue
		}

		controlsMap, controlsMapDiags := types.MapValue(
			types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"id":          types.StringType,
					"description": types.StringType,
					"rules":       types.SetType{ElemType: types.StringType},
				},
			},
			controlsAttrValue,
		)
		diags.Append(controlsMapDiags...)
		if diags.HasError() {
			continue
		}

		updatedSections[sectionName] = SectionModel{
			Controls: controlsMap,
		}
	}

	// Delete controls that exist in state but not in plan
	for stateSectionName, stateSection := range existingControls {
		for stateControlName, stateControl := range stateSection {
			// Check if this control still exists in the plan
			controlStillExists := false
			if _, sectionExists := planSections[stateSectionName]; sectionExists {
				var planControls map[string]ControlModel
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
					diags.AddWarning(
						"Error Deleting Control",
						fmt.Sprintf("Failed to delete control %s: %s", stateControlName, falcon.ErrorExplain(err)),
					)
				}
			}
		}
	}

	// Convert updatedSections to terraform Map
	sectionsAttrValue := make(map[string]attr.Value)
	for sectionName, section := range updatedSections {
		sectionValue, sectionDiags := types.ObjectValue(
			map[string]attr.Type{
				"controls": types.MapType{
					ElemType: types.ObjectType{
						AttrTypes: map[string]attr.Type{
							"id":          types.StringType,
							"description": types.StringType,
							"rules":       types.SetType{ElemType: types.StringType},
						},
					},
				},
			},
			map[string]attr.Value{
				"controls": section.Controls,
			},
		)
		diags.Append(sectionDiags...)
		if diags.HasError() {
			continue
		}
		sectionsAttrValue[sectionName] = sectionValue
	}

	// Create final sections Map
	sectionsMap, sectionsMapDiags := types.MapValue(
		types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"controls": types.MapType{
					ElemType: types.ObjectType{
						AttrTypes: map[string]attr.Type{
							"id":          types.StringType,
							"description": types.StringType,
							"rules":       types.SetType{ElemType: types.StringType},
						},
					},
				},
			},
		},
		sectionsAttrValue,
	)
	diags.Append(sectionsMapDiags...)

	return sectionsMap, diags
}

// createSingleControlAndReturn creates a single control and returns the control model with ID
func (r *cloudComplianceCustomFrameworkResource) createSingleControlAndReturn(
	ctx context.Context,
	frameworkID string,
	sectionName string,
	controlName string,
	control ControlModel,
) (ControlModel, diag.Diagnostics) {
	diags := diag.Diagnostics{}
	emptyControl := ControlModel{}

	controlDesc := control.Description.ValueString()
	createReq := &models.CommonCreateComplianceControlRequest{
		Name:        &controlName,
		Description: &controlDesc,
		FrameworkID: &frameworkID,
		SectionName: &sectionName,
	}

	params := cloud_policies.NewCreateComplianceControlParamsWithContext(ctx)
	params.SetBody(createReq)

	createResp, err := r.client.CloudPolicies.CreateComplianceControl(params)
	if err != nil {
		diags.AddError(
			"Error Creating Control",
			fmt.Sprintf("Failed to create control %s in section %s: %s", controlName, sectionName, falcon.ErrorExplain(err)),
		)
		return emptyControl, diags
	}

	if createResp == nil || createResp.Payload == nil || len(createResp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Creating Control",
			fmt.Sprintf("No control returned from API for %s in section %s", controlName, sectionName),
		)
		return emptyControl, diags
	}

	// Get created control ID
	createdControl := createResp.Payload.Resources[0]
	if createdControl == nil {
		diags.AddError(
			"Error Creating Control",
			fmt.Sprintf("No control resource returned for %s in section %s", controlName, sectionName),
		)
		return emptyControl, diags
	}

	controlID := createdControl.UUID
	if controlID == nil || *controlID == "" {
		diags.AddError(
			"Error Creating Control",
			fmt.Sprintf("Empty control ID returned for %s in section %s", controlName, sectionName),
		)
		return emptyControl, diags
	}

	// Assign rules to control if any
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

		assignReq := &models.CommonAssignRulesToControlRequest{
			RuleIds: ruleIds,
		}

		assignParams := cloud_policies.NewReplaceControlRulesParamsWithContext(ctx).
			WithUID(*controlID).
			WithBody(assignReq)

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
	return ControlModel{
		ID:          types.StringValue(*controlID),
		Description: control.Description,
		Rules:       control.Rules,
	}, diags
}

// createControlsForFramework creates controls and assigns rules for a framework
func (r *cloudComplianceCustomFrameworkResource) createControlsForFramework(
	ctx context.Context,
	frameworkID string,
	sections map[string]SectionModel,
) diag.Diagnostics {
	diags := diag.Diagnostics{}

	for sectionName, section := range sections {
		var sectionControls map[string]ControlModel
		diags.Append(section.Controls.ElementsAs(ctx, &sectionControls, false)...)
		if diags.HasError() {
			continue
		}

		for controlName, control := range sectionControls {
			_, createDiags := r.createSingleControlAndReturn(ctx, frameworkID, sectionName, controlName, control)
			diags.Append(createDiags...)
			if diags.HasError() {
				continue
			}
		}
	}

	return diags
}

// readControlsForFramework reads controls and rules for a framework and returns sections data
func (r *cloudComplianceCustomFrameworkResource) readControlsForFramework(
	ctx context.Context,
	framework models.ApimodelsSecurityFramework,
) (types.Map, diag.Diagnostics) {
	diags := diag.Diagnostics{}
	frameworkName := *framework.Name

	// Query controls for this framework
	frameworkNameFilter := fmt.Sprintf(complianceControlsByFrameworkVersionFilter, frameworkName, *framework.Version)
	queryControlsParams := cloud_policies.NewQueryComplianceControlsParamsWithContext(ctx).WithFilter(&frameworkNameFilter)

	queryControlsResp, err := r.client.CloudPolicies.QueryComplianceControls(queryControlsParams)
	if err != nil {
		diags.AddError(
			"Error Querying Controls",
			fmt.Sprintf("Failed to query controls for framework %s: %s", frameworkName, falcon.ErrorExplain(err)),
		)
		return types.MapNull(types.ObjectType{}), diags
	}

	if queryControlsResp == nil || queryControlsResp.Payload == nil || len(queryControlsResp.Payload.Resources) == 0 {
		// No controls found, return empty sections
		emptyMap, mapDiags := types.MapValue(
			types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"controls": types.MapType{
						ElemType: types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"id":          types.StringType,
								"description": types.StringType,
								"rules":       types.SetType{ElemType: types.StringType},
							},
						},
					},
				},
			},
			map[string]attr.Value{},
		)
		diags.Append(mapDiags...)
		return emptyMap, diags
	}

	// Get detailed control information
	controlIDs := queryControlsResp.Payload.Resources
	getControlsParams := cloud_policies.NewGetComplianceControlsParamsWithContext(ctx).
		WithIds(controlIDs)

	getControlsResp, err := r.client.CloudPolicies.GetComplianceControls(getControlsParams)
	if err != nil {
		diags.AddError(
			"Error Getting Controls",
			fmt.Sprintf("Failed to get controls for framework %s: %s", frameworkName, falcon.ErrorExplain(err)),
		)
		return types.MapNull(types.ObjectType{}), diags
	}

	if getControlsResp == nil || getControlsResp.Payload == nil {
		diags.AddError(
			"Error Getting Controls",
			"The API returned an empty response when getting controls.",
		)
		return types.MapNull(types.ObjectType{}), diags
	}

	// Organize controls by section
	sectionMap := make(map[string]map[string]ControlModel)
	for _, control := range getControlsResp.Payload.Resources {
		sectionName := control.SectionName
		controlName := *control.Name

		// Initialize section if not exists
		if _, exists := sectionMap[sectionName]; !exists {
			sectionMap[sectionName] = make(map[string]ControlModel)
		}

		// Convert ruleIds to a terraform list
		rulesByControlFilter := fmt.Sprintf(complianceRulesByControlFilter, frameworkName, control.SectionName, control.Requirement)
		queryRulesParams := cloud_policies.NewQueryRuleParamsWithContext(ctx).WithFilter(&rulesByControlFilter)

		queryRulesResp, queryRuleErr := r.client.CloudPolicies.QueryRule(queryRulesParams)
		if queryRuleErr != nil {
			diags.AddError(
				"Error Querying Rules",
				fmt.Sprintf("Failed to query rules for control %s: %s", *control.Name, falcon.ErrorExplain(queryRuleErr)),
			)
			return types.MapNull(types.ObjectType{}), diags
		}

		ruleValues := make([]attr.Value, 0)
		if len(queryRulesResp.Payload.Resources) > 0 {
			ruleValues = make([]attr.Value, len(queryRulesResp.Payload.Resources))
			for i, ruleId := range queryRulesResp.Payload.Resources {
				ruleValues[i] = types.StringValue(ruleId)
			}
		}
		rulesSet, setDiags := types.SetValue(types.StringType, ruleValues)
		diags.Append(setDiags...)

		if diags.HasError() {
			continue
		}

		// Create control model
		controlModel := ControlModel{
			ID:          types.StringValue(*control.UUID),
			Description: types.StringValue(control.Description),
			Rules:       rulesSet,
		}

		sectionMap[sectionName][controlName] = controlModel
	}

	// Convert to terraform Map structure
	sectionsAttrValue := make(map[string]attr.Value)

	for sectionName, controls := range sectionMap {
		// Convert controls to terraform Map
		controlsAttrValue := make(map[string]attr.Value)
		for controlName, control := range controls {
			controlValue, controlDiags := types.ObjectValue(
				map[string]attr.Type{
					"id":          types.StringType,
					"description": types.StringType,
					"rules":       types.SetType{ElemType: types.StringType},
				},
				map[string]attr.Value{
					"id":          control.ID,
					"description": control.Description,
					"rules":       control.Rules,
				},
			)
			diags.Append(controlDiags...)
			if diags.HasError() {
				continue
			}
			controlsAttrValue[controlName] = controlValue
		}

		controlsMap, controlsMapDiags := types.MapValue(
			types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"id":          types.StringType,
					"description": types.StringType,
					"rules":       types.SetType{ElemType: types.StringType},
				},
			},
			controlsAttrValue,
		)
		diags.Append(controlsMapDiags...)
		if diags.HasError() {
			continue
		}

		// Create section object
		sectionValue, sectionDiags := types.ObjectValue(
			map[string]attr.Type{
				"controls": types.MapType{
					ElemType: types.ObjectType{
						AttrTypes: map[string]attr.Type{
							"id":          types.StringType,
							"description": types.StringType,
							"rules":       types.SetType{ElemType: types.StringType},
						},
					},
				},
			},
			map[string]attr.Value{
				"controls": controlsMap,
			},
		)
		diags.Append(sectionDiags...)
		if diags.HasError() {
			continue
		}

		sectionsAttrValue[sectionName] = sectionValue
	}

	// Create final sections Map
	sectionsMap, sectionsMapDiags := types.MapValue(
		types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"controls": types.MapType{
					ElemType: types.ObjectType{
						AttrTypes: map[string]attr.Type{
							"id":          types.StringType,
							"description": types.StringType,
							"rules":       types.SetType{ElemType: types.StringType},
						},
					},
				},
			},
		},
		sectionsAttrValue,
	)
	diags.Append(sectionsMapDiags...)

	return sectionsMap, diags
}

// deleteControlsForFramework deletes all controls for a framework
func (r *cloudComplianceCustomFrameworkResource) deleteControlsForFramework(
	ctx context.Context,
	frameworkName string,
) diag.Diagnostics {
	diags := diag.Diagnostics{}

	// Query controls for this framework
	frameworkNameFilter := fmt.Sprintf(complianceControlsByFrameworkFilter, frameworkName)
	params := cloud_policies.NewQueryComplianceControlsParamsWithContext(ctx).
		WithFilter(&frameworkNameFilter)

	queryControlsResp, err := r.client.CloudPolicies.QueryComplianceControls(params)
	if err != nil {
		diags.AddError(
			"Error Querying Controls for Deletion",
			fmt.Sprintf("Failed to query controls for framework %s: %s", frameworkName, falcon.ErrorExplain(err)),
		)
		return diags
	}

	if queryControlsResp == nil || queryControlsResp.Payload == nil || len(queryControlsResp.Payload.Resources) == 0 {
		// No controls found, nothing to delete
		return diags
	}

	// Delete controls
	controlIds := queryControlsResp.Payload.Resources
	deleteParams := cloud_policies.NewDeleteComplianceControlParamsWithContext(ctx).WithIds(controlIds)
	_, err = r.client.CloudPolicies.DeleteComplianceControl(deleteParams)
	if err != nil {
		// Continue deleting other controls even if one fails
		diags.AddWarning(
			"Error Deleting Controls",
			fmt.Sprintf("Failed to delete controls %s: %s", controlIds, falcon.ErrorExplain(err)),
		)
	}

	return diags
}
