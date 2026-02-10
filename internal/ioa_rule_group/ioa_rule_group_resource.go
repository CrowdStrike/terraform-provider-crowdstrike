package ioarulegroup

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/custom_ioa"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &ioaRuleGroupResource{}
	_ resource.ResourceWithConfigure   = &ioaRuleGroupResource{}
	_ resource.ResourceWithImportState = &ioaRuleGroupResource{}
)

// NewIOARuleGroupResource is a helper function to simplify the provider implementation.
func NewIOARuleGroupResource() resource.Resource {
	return &ioaRuleGroupResource{}
}

// ioaRuleGroupResource defines the resource implementation.
type ioaRuleGroupResource struct {
	client *client.CrowdStrikeAPISpecification
}

// ioaRuleGroupResourceModel describes the resource data model.
type ioaRuleGroupResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Comment     types.String `tfsdk:"comment"`
	Platform    types.String `tfsdk:"platform"`
	CreatedAt   types.String `tfsdk:"created_at"`
	CreatedBy   types.String `tfsdk:"created_by"`
	ModifiedAt  types.String `tfsdk:"modified_at"`
	ModifiedBy  types.String `tfsdk:"modified_by"`
	CustomerId  types.String `tfsdk:"customer_id"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Deleted     types.Bool   `tfsdk:"deleted"`
	RuleIds     types.List   `tfsdk:"rule_ids"`
	Rules       types.Set    `tfsdk:"rules"`
	Version     types.Int64  `tfsdk:"version"`
	LastUpdated types.String `tfsdk:"last_updated"`
}

// ioaRuleResourceModel describes the nested rule data model.
type ioaRuleResourceModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Description     types.String `tfsdk:"description"`
	PatternSeverity types.String `tfsdk:"pattern_severity"`
	RuletypeID      types.String `tfsdk:"ruletype_id"`
	DispositionID   types.Int64  `tfsdk:"disposition_id"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	FieldValues     types.Set    `tfsdk:"field_values"`
}

// ioaRuleFieldValueModel describes the field value data model.
type ioaRuleFieldValueModel struct {
	Name   types.String `tfsdk:"name"`
	Label  types.String `tfsdk:"label"`
	Type   types.String `tfsdk:"type"`
	Values types.Set    `tfsdk:"values"`
}

// ioaRuleFieldValueValueModel describes individual field value options.
type ioaRuleFieldValueValueModel struct {
	Label types.String `tfsdk:"label"`
	Value types.String `tfsdk:"value"`
}

// ToCreateRequest converts the model to an API create request.
func (m ioaRuleGroupResourceModel) ToCreateRequest(
	ctx context.Context,
) (*models.APIRuleGroupCreateRequestV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	request := &models.APIRuleGroupCreateRequestV1{
		Name:        m.Name.ValueStringPointer(),
		Description: m.Description.ValueStringPointer(),
		Comment:     m.Comment.ValueStringPointer(),
		Platform:    m.Platform.ValueStringPointer(),
	}

	return request, diags
}

// syncRulesAndReturnIDs creates rules and returns a map of rule names to IDs.
func (r *ioaRuleGroupResource) syncRulesAndReturnIDs(
	ctx context.Context,
	ruleGroupID *string,
	plannedRules types.Set,
) (map[string]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	ruleNameToID := make(map[string]string)

	if ruleGroupID == nil {
		diags.AddError(
			"Rule group ID is missing",
			"Cannot sync rules without a valid rule group ID",
		)
		return ruleNameToID, diags
	}

	// Convert planned rules from Terraform set to our rule models
	var rules []ioaRuleResourceModel
	if !plannedRules.IsNull() && !plannedRules.IsUnknown() {
		diagsConvert := plannedRules.ElementsAs(ctx, &rules, false)
		diags.Append(diagsConvert...)
		if diags.HasError() {
			return ruleNameToID, diags
		}
	}

	tflog.Info(ctx, "Syncing IOA rules", map[string]interface{}{
		"ruleGroupId": *ruleGroupID,
		"ruleCount":   len(rules),
	})

	// For each planned rule, create it using the API
	for i, rule := range rules {
		tflog.Debug(ctx, "Creating IOA rule", map[string]interface{}{
			"index":       i,
			"ruleName":    rule.Name.ValueString(),
			"ruleGroupId": *ruleGroupID,
		})

		createRequest, createDiags := rule.ToCreateRequest(ctx, *ruleGroupID)
		diags.Append(createDiags...)
		if diags.HasError() {
			continue
		}

		res, err := r.client.CustomIoa.CreateRule(
			&custom_ioa.CreateRuleParams{
				Context: ctx,
				Body:    createRequest,
			},
		)
		if err != nil {
			diags.AddError(
				"Failed to create IOA rule",
				fmt.Sprintf("Failed to create IOA rule '%s': %s", rule.Name.ValueString(), falcon.ErrorExplain(err)),
			)
			continue
		}

		if res == nil || res.Payload == nil || res.Payload.Resources == nil || len(res.Payload.Resources) == 0 {
			diags.AddError(
				"Failed to create IOA rule",
				fmt.Sprintf("No data returned from API for rule '%s'", rule.Name.ValueString()),
			)
			continue
		}

		// Use InstanceID from APIRuleV1 response
		if res.Payload.Resources[0].InstanceID != nil {
			ruleNameToID[rule.Name.ValueString()] = *res.Payload.Resources[0].InstanceID
			tflog.Info(ctx, "Successfully created IOA rule", map[string]interface{}{
				"ruleName": rule.Name.ValueString(),
				"ruleId":   *res.Payload.Resources[0].InstanceID,
			})
		}
	}

	return ruleNameToID, diags
}

// updateRulesWithIDs updates the planned rules with actual IDs from creation.
func (r *ioaRuleGroupResource) updateRulesWithIDs(
	ctx context.Context,
	plannedRules types.Set,
	ruleNameToID map[string]string,
) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Convert planned rules to slice for modification
	var rules []ioaRuleResourceModel
	if !plannedRules.IsNull() && !plannedRules.IsUnknown() {
		diagsConvert := plannedRules.ElementsAs(ctx, &rules, false)
		diags.Append(diagsConvert...)
		if diags.HasError() {
			return plannedRules, diags
		}
	}

	// Update each rule with its ID if we have it
	for i, rule := range rules {
		if ruleID, exists := ruleNameToID[rule.Name.ValueString()]; exists {
			rules[i].ID = types.StringValue(ruleID)
		}
	}

	// Convert back to Set
	updatedSet, setDiags := types.SetValueFrom(ctx, plannedRules.ElementType(ctx), rules)
	diags.Append(setDiags...)

	return updatedSet, diags
}

// convertAPIRulesToTerraform converts API rules back to Terraform format, preserving planned configuration.
func (r *ioaRuleGroupResource) convertAPIRulesToTerraform(
	ctx context.Context,
	apiRules []*models.APIRuleV1,
	plannedRules types.Set,
) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Convert planned rules to map for lookup
	var plannedRuleModels []ioaRuleResourceModel
	if !plannedRules.IsNull() && !plannedRules.IsUnknown() {
		diagsConvert := plannedRules.ElementsAs(ctx, &plannedRuleModels, false)
		diags.Append(diagsConvert...)
		if diags.HasError() {
			return types.SetNull(plannedRules.ElementType(ctx)), diags
		}
	}

	plannedRuleMap := make(map[string]ioaRuleResourceModel)
	for _, rule := range plannedRuleModels {
		plannedRuleMap[rule.Name.ValueString()] = rule
	}

	// Convert API rules to Terraform models, merging with planned configuration
	var resultRules []ioaRuleResourceModel
	for _, apiRule := range apiRules {
		if apiRule.Name == nil {
			continue
		}

		ruleName := *apiRule.Name

		// Start with planned rule if it exists, otherwise create new
		var rule ioaRuleResourceModel
		if plannedRule, exists := plannedRuleMap[ruleName]; exists {
			rule = plannedRule
		} else {
			// Create basic rule from API data
			rule = ioaRuleResourceModel{
				Name:            types.StringValue(ruleName),
				Description:     types.StringNull(),
				PatternSeverity: types.StringNull(),
				RuletypeID:      types.StringNull(),
				DispositionID:   types.Int64Null(),
				Enabled:         types.BoolValue(false),
				FieldValues: types.SetNull(types.ObjectType{AttrTypes: map[string]attr.Type{
					"name":  types.StringType,
					"label": types.StringType,
					"type":  types.StringType,
					"values": types.SetType{ElemType: types.ObjectType{AttrTypes: map[string]attr.Type{
						"label": types.StringType,
						"value": types.StringType,
					}}},
				}}),
			}
		}

		// Set the ID from API response
		if apiRule.InstanceID != nil {
			rule.ID = types.StringValue(*apiRule.InstanceID)
		}

		// Update other fields from API if not set in plan
		if apiRule.Description != nil && rule.Description.IsNull() {
			rule.Description = types.StringValue(*apiRule.Description)
		}
		if apiRule.PatternSeverity != nil && rule.PatternSeverity.IsNull() {
			rule.PatternSeverity = types.StringValue(*apiRule.PatternSeverity)
		}
		if apiRule.RuletypeID != nil && rule.RuletypeID.IsNull() {
			rule.RuletypeID = types.StringValue(*apiRule.RuletypeID)
		}
		if apiRule.DispositionID != nil && rule.DispositionID.IsNull() {
			rule.DispositionID = types.Int64Value(int64(*apiRule.DispositionID))
		}
		if apiRule.Enabled != nil {
			rule.Enabled = types.BoolValue(*apiRule.Enabled)
		}

		resultRules = append(resultRules, rule)
	}

	// Convert back to Set
	resultSet, setDiags := types.SetValueFrom(ctx, plannedRules.ElementType(ctx), resultRules)
	diags.Append(setDiags...)

	return resultSet, diags
}

// ToUpdateRequest converts the IOA rule model to an API update request.
func (m ioaRuleResourceModel) ToUpdateRequest(
	ctx context.Context,
	instanceID string,
	ruleGroupVersion int64,
) (*models.APIRuleUpdateV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Convert field values from Terraform model to API model
	var fieldValues []*models.DomainFieldValue
	if !m.FieldValues.IsNull() && !m.FieldValues.IsUnknown() {
		var tfFieldValues []ioaRuleFieldValueModel
		diagsConvert := m.FieldValues.ElementsAs(ctx, &tfFieldValues, false)
		diags.Append(diagsConvert...)
		if !diags.HasError() {
			for _, tfFieldValue := range tfFieldValues {
				fieldValue := &models.DomainFieldValue{
					Name: tfFieldValue.Name.ValueStringPointer(),
					Type: tfFieldValue.Type.ValueStringPointer(),
				}

				// Label is a string, not *string
				if !tfFieldValue.Label.IsNull() {
					fieldValue.Label = tfFieldValue.Label.ValueString()
				}

				// Convert nested values to DomainValueItem
				if !tfFieldValue.Values.IsNull() && !tfFieldValue.Values.IsUnknown() {
					var tfValues []ioaRuleFieldValueValueModel
					diagsValueConvert := tfFieldValue.Values.ElementsAs(ctx, &tfValues, false)
					diags.Append(diagsValueConvert...)
					if !diags.HasError() {
						var values []*models.DomainValueItem
						for _, tfValue := range tfValues {
							values = append(values, &models.DomainValueItem{
								Label: tfValue.Label.ValueStringPointer(),
								Value: tfValue.Value.ValueStringPointer(),
							})
						}
						fieldValue.Values = values
					}
				}

				fieldValues = append(fieldValues, fieldValue)
			}
		}
	}

	// Convert disposition_id from int64 to int32
	dispositionID := int32(m.DispositionID.ValueInt64())
	enabled := m.Enabled.ValueBool()

	request := &models.APIRuleUpdateV1{
		InstanceID:       &instanceID,
		Name:             m.Name.ValueStringPointer(),
		Description:      m.Description.ValueStringPointer(),
		PatternSeverity:  m.PatternSeverity.ValueStringPointer(),
		DispositionID:    &dispositionID,
		Enabled:          &enabled,
		FieldValues:      fieldValues,
		RulegroupVersion: &ruleGroupVersion,
	}

	return request, diags
}

// ToUpdateRequest converts the model to an API update request.
func (m ioaRuleGroupResourceModel) ToUpdateRequest(
	ctx context.Context,
	id string,
	currentVersion int64,
	currentEnabled bool,
) (*models.APIRuleGroupModifyRequestV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Get name, description, and comment values
	name := m.Name.ValueString()
	description := ""
	if !m.Description.IsNull() {
		description = m.Description.ValueString()
	}
	comment := m.Comment.ValueString() // Comment is required for updates

	// Create the request struct with all necessary fields including comment
	request := &models.APIRuleGroupModifyRequestV1{}
	request.ID = &id
	request.Name = &name
	request.Description = &description
	request.Comment = &comment // Include comment for updates
	request.Enabled = &currentEnabled
	request.RulegroupVersion = &currentVersion

	return request, diags
}

// Metadata returns the resource type name.
func (r *ioaRuleGroupResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_ioa_rule_group"
}

// Schema defines the schema for the resource.
func (r *ioaRuleGroupResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"IOA Rule Group",
			"This resource manages CrowdStrike IOA (Indicator of Attack) rule groups for organizing custom IOA rules.",
			[]scopes.Scope{
				{
					Name:  "Custom IOA Rules",
					Read:  true,
					Write: true,
				},
			},
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the IOA rule group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the IOA rule group.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 100),
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "The description of the IOA rule group.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 500),
					fwvalidators.StringNotWhitespace(),
				},
			},
			"comment": schema.StringAttribute{
				Optional:    true,
				Description: "A comment about the IOA rule group. Required for updates.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 500),
					fwvalidators.StringNotWhitespace(),
				},
			},
			"platform": schema.StringAttribute{
				Required:    true,
				Description: "The platform for the IOA rule group. Valid values: windows, linux, mac.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("windows", "linux", "mac"),
				},
			},
			// Computed attributes
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "The timestamp when the rule group was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_by": schema.StringAttribute{
				Computed:    true,
				Description: "The API client ID that created the rule group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"modified_at": schema.StringAttribute{
				Computed:    true,
				Description: "The timestamp when the rule group was last modified.",
			},
			"modified_by": schema.StringAttribute{
				Computed:    true,
				Description: "The API client ID that last modified the rule group.",
			},
			"customer_id": schema.StringAttribute{
				Computed:    true,
				Description: "The customer ID that owns the rule group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the rule group is enabled.",
			},
			"deleted": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the rule group is deleted.",
			},
			"rule_ids": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "List of rule IDs in this rule group.",
			},
			"version": schema.Int64Attribute{
				Computed:    true,
				Description: "The version of the rule group.",
			},
			"rules": schema.SetNestedAttribute{
				Optional:    true,
				Description: "Set of IOA rules within this rule group.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The ID of the IOA rule.",
						},
						"name": schema.StringAttribute{
							Required:    true,
							Description: "The name of the IOA rule.",
							Validators: []validator.String{
								stringvalidator.LengthBetween(1, 100),
								fwvalidators.StringNotWhitespace(),
							},
						},
						"description": schema.StringAttribute{
							Optional:    true,
							Description: "The description of the IOA rule.",
							Validators: []validator.String{
								stringvalidator.LengthBetween(1, 500),
								fwvalidators.StringNotWhitespace(),
							},
						},
						"pattern_severity": schema.StringAttribute{
							Required:    true,
							Description: "The severity level for the IOA rule. Valid values: critical, high, medium, low, informational.",
							Validators: []validator.String{
								stringvalidator.OneOf("critical", "high", "medium", "low", "informational"),
							},
						},
						"ruletype_id": schema.StringAttribute{
							Required:    true,
							Description: "The rule type ID. Use the /ioarules/queries/rule-types/v1 endpoint to get available rule type IDs.",
						},
						"disposition_id": schema.Int64Attribute{
							Required:    true,
							Description: "The disposition ID for the rule action (e.g., 20 for Detect, 30 for Kill Process).",
						},
						"enabled": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Whether the IOA rule is enabled. Defaults to false.",
						},
						"field_values": schema.SetNestedAttribute{
							Optional:    true,
							Description: "Set of field values for the IOA rule configuration.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Required:    true,
										Description: "The field name (e.g., 'ImageFilename', 'CommandLine').",
									},
									"label": schema.StringAttribute{
										Optional:    true,
										Description: "The human-readable label for the field.",
									},
									"type": schema.StringAttribute{
										Optional:    true,
										Description: "The field type (e.g., 'excludable').",
									},
									"values": schema.SetNestedAttribute{
										Required:    true,
										Description: "Set of field value options.",
										NestedObject: schema.NestedAttributeObject{
											Attributes: map[string]schema.Attribute{
												"label": schema.StringAttribute{
													Required:    true,
													Description: "The label for the field value (e.g., 'include', 'exclude').",
												},
												"value": schema.StringAttribute{
													Required:    true,
													Description: "The actual value/pattern for the field.",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "The timestamp when this resource was last updated.",
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *ioaRuleGroupResource) Configure(
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

// Create creates the resource and sets the initial Terraform state.
func (r *ioaRuleGroupResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan ioaRuleGroupResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createRequest, diags := plan.ToCreateRequest(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Creating IOA rule group", map[string]interface{}{"name": plan.Name.ValueString()})

	res, err := r.client.CustomIoa.CreateRuleGroupMixin0(
		&custom_ioa.CreateRuleGroupMixin0Params{
			Context: ctx,
			Body:    createRequest,
		},
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to create IOA rule group",
			fmt.Sprintf("Failed to create IOA rule group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if res == nil || res.Payload == nil || res.Payload.Resources == nil || len(res.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Failed to create IOA rule group",
			"No data returned from API",
		)
		return
	}

	ruleGroup := res.Payload.Resources[0]
	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, ruleGroup)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Sync individual rules if specified
	if !plan.Rules.IsNull() && !plan.Rules.IsUnknown() {
		createdRuleIDs, diags := r.syncRulesAndReturnIDs(ctx, ruleGroup.ID, plan.Rules)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Update plan with the created rule IDs by updating the rules in place
		if len(createdRuleIDs) > 0 {
			updatedRules, updateDiags := r.updateRulesWithIDs(ctx, plan.Rules, createdRuleIDs)
			resp.Diagnostics.Append(updateDiags...)
			if !resp.Diagnostics.HasError() {
				plan.Rules = updatedRules
			}
		}

		// After creating rules, re-read the rule group to get updated rule IDs in the rule_ids field
		readRes, err := r.client.CustomIoa.GetRuleGroupsMixin0(
			&custom_ioa.GetRuleGroupsMixin0Params{
				Context: ctx,
				Ids:     []string{*ruleGroup.ID},
			},
		)
		if err == nil && readRes != nil && readRes.Payload != nil &&
			readRes.Payload.Resources != nil && len(readRes.Payload.Resources) > 0 {
			// Update plan with the latest rule group info including rule IDs
			resp.Diagnostics.Append(plan.wrap(ctx, readRes.Payload.Resources[0])...)
			if resp.Diagnostics.HasError() {
				return
			}
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *ioaRuleGroupResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state ioaRuleGroupResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.ID.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Resource ID missing",
			"IOA rule group ID is missing from state",
		)
		resp.State.RemoveResource(ctx)
		return
	}

	tflog.Info(ctx, "Reading IOA rule group", map[string]interface{}{"id": state.ID.ValueString()})

	res, err := r.client.CustomIoa.GetRuleGroupsMixin0(
		&custom_ioa.GetRuleGroupsMixin0Params{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			tflog.Warn(ctx, "IOA rule group not found, removing from state", map[string]interface{}{"id": state.ID.ValueString()})
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Failed to read IOA rule group",
			fmt.Sprintf("Failed to read IOA rule group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if res == nil || res.Payload == nil || res.Payload.Resources == nil || len(res.Payload.Resources) == 0 {
		tflog.Warn(ctx, "IOA rule group not found, removing from state", map[string]interface{}{"id": state.ID.ValueString()})
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, res.Payload.Resources[0])...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *ioaRuleGroupResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan ioaRuleGroupResourceModel
	var state ioaRuleGroupResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate that comment is provided for updates
	if plan.Comment.IsNull() || plan.Comment.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Comment required for updates",
			"The 'comment' field is required when updating IOA rule groups. Please provide a comment and try again.",
		)
		return
	}

	updateRequest, diags := plan.ToUpdateRequest(
		ctx,
		state.ID.ValueString(),
		state.Version.ValueInt64(),
		state.Enabled.ValueBool(),
	)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Updating IOA rule group", map[string]interface{}{
		"id":   state.ID.ValueString(),
		"name": plan.Name.ValueString(),
	})

	res, err := r.client.CustomIoa.UpdateRuleGroupMixin0(
		&custom_ioa.UpdateRuleGroupMixin0Params{
			Context: ctx,
			Body:    updateRequest,
		},
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to update IOA rule group",
			fmt.Sprintf("Failed to update IOA rule group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if res == nil || res.Payload == nil || res.Payload.Resources == nil || len(res.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Failed to update IOA rule group",
			"No data returned from API",
		)
		return
	}

	ruleGroup := res.Payload.Resources[0]
	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, ruleGroup)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Handle rule updates if rules are specified
	if !plan.Rules.IsNull() && !plan.Rules.IsUnknown() {
		// Convert current rule IDs to slice
		var currentRuleIds []string
		if !state.RuleIds.IsNull() && !state.RuleIds.IsUnknown() {
			diagsConvert := state.RuleIds.ElementsAs(ctx, &currentRuleIds, false)
			resp.Diagnostics.Append(diagsConvert...)
		}

		// Sync rule changes (create, update, delete as needed)
		diags := r.syncRulesForUpdate(ctx, ruleGroup.ID, ruleGroup.Version, currentRuleIds, plan.Rules)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		// After updating rules, re-read the rule group to get updated rule IDs
		readRes, err := r.client.CustomIoa.GetRuleGroupsMixin0(
			&custom_ioa.GetRuleGroupsMixin0Params{
				Context: ctx,
				Ids:     []string{*ruleGroup.ID},
			},
		)
		if err == nil && readRes != nil && readRes.Payload != nil &&
			readRes.Payload.Resources != nil && len(readRes.Payload.Resources) > 0 {
			// Update plan with the latest rule group info including rule IDs
			resp.Diagnostics.Append(plan.wrap(ctx, readRes.Payload.Resources[0])...)
			if resp.Diagnostics.HasError() {
				return
			}

			// Now fetch the individual rules to get their complete data with IDs
			if len(readRes.Payload.Resources[0].RuleIds) > 0 {
				rulesRes, err := r.client.CustomIoa.GetRulesMixin0(
					&custom_ioa.GetRulesMixin0Params{
						Context: ctx,
						Ids:     readRes.Payload.Resources[0].RuleIds,
					},
				)
				if err == nil && rulesRes != nil && rulesRes.Payload != nil && rulesRes.Payload.Resources != nil {
					// Map the rule names to IDs for updating
					ruleNameToID := make(map[string]string)
					for _, apiRule := range rulesRes.Payload.Resources {
						if apiRule.Name != nil && apiRule.InstanceID != nil {
							ruleNameToID[*apiRule.Name] = *apiRule.InstanceID
						}
					}

					// Update plan rules with actual IDs
					if len(ruleNameToID) > 0 {
						updatedRules, updateDiags := r.updateRulesWithIDs(ctx, plan.Rules, ruleNameToID)
						resp.Diagnostics.Append(updateDiags...)
						if !resp.Diagnostics.HasError() {
							plan.Rules = updatedRules
						}
					}
				}
			}
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *ioaRuleGroupResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state ioaRuleGroupResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.ID.ValueString() == "" {
		return
	}

	tflog.Info(ctx, "Deleting IOA rule group", map[string]interface{}{"id": state.ID.ValueString()})

	_, err := r.client.CustomIoa.DeleteRuleGroupsMixin0(
		&custom_ioa.DeleteRuleGroupsMixin0Params{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)
	if err != nil {
		if !strings.Contains(err.Error(), "404") {
			resp.Diagnostics.AddError(
				"Failed to delete IOA rule group",
				fmt.Sprintf("Failed to delete IOA rule group: %s", falcon.ErrorExplain(err)),
			)
			return
		}
	}
}

// ImportState implements the logic to support resource imports.
func (r *ioaRuleGroupResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// wrap converts API response to Terraform state model.
func (m *ioaRuleGroupResourceModel) wrap(
	ctx context.Context,
	apiRuleGroup *models.APIRuleGroupV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if apiRuleGroup == nil {
		return diags
	}

	if apiRuleGroup.ID != nil {
		m.ID = types.StringValue(*apiRuleGroup.ID)
	} else {
		m.ID = types.StringNull()
	}

	if apiRuleGroup.Name != nil {
		m.Name = types.StringValue(*apiRuleGroup.Name)
	} else {
		m.Name = types.StringNull()
	}

	if apiRuleGroup.Description != nil && *apiRuleGroup.Description != "" {
		m.Description = types.StringValue(*apiRuleGroup.Description)
	} else {
		m.Description = types.StringNull()
	}

	if apiRuleGroup.Comment != nil && *apiRuleGroup.Comment != "" {
		m.Comment = types.StringValue(*apiRuleGroup.Comment)
	} else {
		m.Comment = types.StringNull()
	}

	if apiRuleGroup.Platform != nil {
		m.Platform = types.StringValue(*apiRuleGroup.Platform)
	} else {
		m.Platform = types.StringNull()
	}

	if apiRuleGroup.CreatedBy != nil {
		m.CreatedBy = types.StringValue(*apiRuleGroup.CreatedBy)
	} else {
		m.CreatedBy = types.StringNull()
	}

	if apiRuleGroup.ModifiedBy != nil {
		m.ModifiedBy = types.StringValue(*apiRuleGroup.ModifiedBy)
	} else {
		m.ModifiedBy = types.StringNull()
	}

	if apiRuleGroup.CustomerID != nil {
		m.CustomerId = types.StringValue(*apiRuleGroup.CustomerID)
	} else {
		m.CustomerId = types.StringNull()
	}

	// Note: Timestamp fields may not be available in APIRuleGroupV1
	m.CreatedAt = types.StringNull()
	m.ModifiedAt = types.StringNull()

	if apiRuleGroup.Enabled != nil {
		m.Enabled = types.BoolValue(*apiRuleGroup.Enabled)
	} else {
		m.Enabled = types.BoolNull()
	}

	if apiRuleGroup.Deleted != nil {
		m.Deleted = types.BoolValue(*apiRuleGroup.Deleted)
	} else {
		m.Deleted = types.BoolNull()
	}

	if apiRuleGroup.Version != nil {
		m.Version = types.Int64Value(*apiRuleGroup.Version)
	} else {
		m.Version = types.Int64Null()
	}

	if len(apiRuleGroup.RuleIds) > 0 {
		ruleIdsList, listDiags := types.ListValueFrom(ctx, types.StringType, apiRuleGroup.RuleIds)
		diags.Append(listDiags...)
		m.RuleIds = ruleIdsList
	} else {
		m.RuleIds = types.ListNull(types.StringType)
	}

	return diags
}

// syncRules manages individual rules within the rule group for creates and updates.
func (r *ioaRuleGroupResource) syncRules(
	ctx context.Context,
	ruleGroupID *string,
	plannedRules types.Set,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if ruleGroupID == nil {
		diags.AddError(
			"Rule group ID is missing",
			"Cannot sync rules without a valid rule group ID",
		)
		return diags
	}

	// Convert planned rules from Terraform set to our rule models
	var rules []ioaRuleResourceModel
	if !plannedRules.IsNull() && !plannedRules.IsUnknown() {
		diagsConvert := plannedRules.ElementsAs(ctx, &rules, false)
		diags.Append(diagsConvert...)
		if diags.HasError() {
			return diags
		}
	}

	tflog.Info(ctx, "Syncing IOA rules", map[string]interface{}{
		"ruleGroupId": *ruleGroupID,
		"ruleCount":   len(rules),
	})

	// For each planned rule, create it using the API
	for i, rule := range rules {
		tflog.Debug(ctx, "Creating IOA rule", map[string]interface{}{
			"index":       i,
			"ruleName":    rule.Name.ValueString(),
			"ruleGroupId": *ruleGroupID,
		})

		createRequest, createDiags := rule.ToCreateRequest(ctx, *ruleGroupID)
		diags.Append(createDiags...)
		if diags.HasError() {
			continue
		}

		res, err := r.client.CustomIoa.CreateRule(
			&custom_ioa.CreateRuleParams{
				Context: ctx,
				Body:    createRequest,
			},
		)
		if err != nil {
			diags.AddError(
				"Failed to create IOA rule",
				fmt.Sprintf("Failed to create IOA rule '%s': %s", rule.Name.ValueString(), falcon.ErrorExplain(err)),
			)
			continue
		}

		if res == nil || res.Payload == nil || res.Payload.Resources == nil || len(res.Payload.Resources) == 0 {
			diags.AddError(
				"Failed to create IOA rule",
				fmt.Sprintf("No data returned from API for rule '%s'", rule.Name.ValueString()),
			)
			continue
		}

		// Use InstanceID from APIRuleV1 response
		ruleID := ""
		if res.Payload.Resources[0].InstanceID != nil {
			ruleID = *res.Payload.Resources[0].InstanceID
		}

		tflog.Info(ctx, "Successfully created IOA rule", map[string]interface{}{
			"ruleName": rule.Name.ValueString(),
			"ruleId":   ruleID,
		})
	}

	return diags
}

// syncRulesForUpdate manages rule changes during updates.
// For now, we only create new rules and leave existing ones unchanged.
// This is a conservative approach to avoid API issues with rule deletion/updates.
func (r *ioaRuleGroupResource) syncRulesForUpdate(
	ctx context.Context,
	ruleGroupID *string,
	ruleGroupVersion *int64,
	currentRuleIds []string,
	plannedRules types.Set,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if ruleGroupID == nil || ruleGroupVersion == nil {
		diags.AddError(
			"Rule group info is missing",
			"Cannot sync rules without valid rule group ID and version",
		)
		return diags
	}

	tflog.Info(ctx, "Syncing IOA rules for update (conservative approach)", map[string]interface{}{
		"ruleGroupId":      *ruleGroupID,
		"ruleGroupVersion": *ruleGroupVersion,
		"currentRuleCount": len(currentRuleIds),
	})

	// Get current rules to see what names exist
	var existingRuleNames map[string]bool
	if len(currentRuleIds) > 0 {
		currentRules, getCurrentDiags := r.getCurrentRules(ctx, currentRuleIds)
		diags.Append(getCurrentDiags...)
		if diags.HasError() {
			return diags
		}

		existingRuleNames = make(map[string]bool)
		for _, rule := range currentRules {
			if rule.Name != nil {
				existingRuleNames[*rule.Name] = true
			}
		}
	}

	// Convert planned rules to slice
	var plannedRuleModels []ioaRuleResourceModel
	if !plannedRules.IsNull() && !plannedRules.IsUnknown() {
		diagsConvert := plannedRules.ElementsAs(ctx, &plannedRuleModels, false)
		diags.Append(diagsConvert...)
		if diags.HasError() {
			return diags
		}
	}

	// Only create rules that don't already exist
	var rulesToCreate []ioaRuleResourceModel
	for _, rule := range plannedRuleModels {
		if existingRuleNames == nil || !existingRuleNames[rule.Name.ValueString()] {
			rulesToCreate = append(rulesToCreate, rule)
			tflog.Debug(ctx, "Will create new rule", map[string]interface{}{
				"ruleName": rule.Name.ValueString(),
			})
		} else {
			tflog.Debug(ctx, "Rule already exists, skipping", map[string]interface{}{
				"ruleName": rule.Name.ValueString(),
			})
		}
	}

	if len(rulesToCreate) > 0 {
		// Convert slice back to Set for syncRulesAndReturnIDs
		rulesToCreateSet, setDiags := types.SetValueFrom(ctx, plannedRules.ElementType(ctx), rulesToCreate)
		diags.Append(setDiags...)
		if diags.HasError() {
			return diags
		}

		// Create the new rules
		createdRuleIDs, createDiags := r.syncRulesAndReturnIDs(ctx, ruleGroupID, rulesToCreateSet)
		diags.Append(createDiags...)

		if len(createdRuleIDs) > 0 {
			tflog.Info(ctx, "Successfully created new IOA rules", map[string]interface{}{
				"ruleCount": len(createdRuleIDs),
			})
		}
	} else {
		tflog.Info(ctx, "No new rules to create", map[string]interface{}{})
	}

	return diags
}

// getCurrentRules fetches the current rules by their IDs.
func (r *ioaRuleGroupResource) getCurrentRules(
	ctx context.Context,
	ruleIds []string,
) ([]*models.APIRuleV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(ruleIds) == 0 {
		return nil, diags
	}

	res, err := r.client.CustomIoa.GetRulesMixin0(
		&custom_ioa.GetRulesMixin0Params{
			Context: ctx,
			Ids:     ruleIds,
		},
	)
	if err != nil {
		diags.AddError(
			"Failed to get current IOA rules",
			fmt.Sprintf("Failed to fetch current rules: %s", falcon.ErrorExplain(err)),
		)
		return nil, diags
	}

	if res == nil || res.Payload == nil || res.Payload.Resources == nil {
		return nil, diags
	}

	return res.Payload.Resources, diags
}

// ToCreateRequest converts the IOA rule model to an API create request.
func (m ioaRuleResourceModel) ToCreateRequest(
	ctx context.Context,
	ruleGroupID string,
) (*models.APIRuleCreateV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Convert field values from Terraform model to API model
	var fieldValues []*models.DomainFieldValue
	if !m.FieldValues.IsNull() && !m.FieldValues.IsUnknown() {
		var tfFieldValues []ioaRuleFieldValueModel
		diagsConvert := m.FieldValues.ElementsAs(ctx, &tfFieldValues, false)
		diags.Append(diagsConvert...)
		if !diags.HasError() {
			for _, tfFieldValue := range tfFieldValues {
				fieldValue := &models.DomainFieldValue{
					Name: tfFieldValue.Name.ValueStringPointer(),
					Type: tfFieldValue.Type.ValueStringPointer(),
				}

				// Label is a string, not *string
				if !tfFieldValue.Label.IsNull() {
					fieldValue.Label = tfFieldValue.Label.ValueString()
				}

				// Convert nested values to DomainValueItem
				if !tfFieldValue.Values.IsNull() && !tfFieldValue.Values.IsUnknown() {
					var tfValues []ioaRuleFieldValueValueModel
					diagsValueConvert := tfFieldValue.Values.ElementsAs(ctx, &tfValues, false)
					diags.Append(diagsValueConvert...)
					if !diags.HasError() {
						var values []*models.DomainValueItem
						for _, tfValue := range tfValues {
							values = append(values, &models.DomainValueItem{
								Label: tfValue.Label.ValueStringPointer(),
								Value: tfValue.Value.ValueStringPointer(),
							})
						}
						fieldValue.Values = values
					}
				}

				fieldValues = append(fieldValues, fieldValue)
			}
		}
	}

	// Convert disposition_id from int64 to int32
	dispositionID := int32(m.DispositionID.ValueInt64())

	request := &models.APIRuleCreateV1{
		Name:            m.Name.ValueStringPointer(),
		Description:     m.Description.ValueStringPointer(),
		PatternSeverity: m.PatternSeverity.ValueStringPointer(),
		RuletypeID:      m.RuletypeID.ValueStringPointer(),
		DispositionID:   &dispositionID,
		RulegroupID:     &ruleGroupID,
		FieldValues:     fieldValues,
		Comment:         m.Description.ValueStringPointer(), // Use description as comment for now
	}

	return request, diags
}
