package contentupdatepolicy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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
	_ resource.Resource                   = &defaultContentUpdatePolicyResource{}
	_ resource.ResourceWithConfigure      = &defaultContentUpdatePolicyResource{}
	_ resource.ResourceWithImportState    = &defaultContentUpdatePolicyResource{}
	_ resource.ResourceWithValidateConfig = &defaultContentUpdatePolicyResource{}
)

// NewDefaultContentUpdatePolicyResource is a helper function to simplify the provider implementation.
func NewDefaultContentUpdatePolicyResource() resource.Resource {
	return &defaultContentUpdatePolicyResource{}
}

// defaultContentUpdatePolicyResource is the resource implementation.
type defaultContentUpdatePolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

// defaultContentUpdatePolicyResourceModel is the resource model.
type defaultContentUpdatePolicyResourceModel struct {
	ID                      types.String `tfsdk:"id"`
	Description             types.String `tfsdk:"description"`
	SensorOperations        types.Object `tfsdk:"sensor_operations"`
	SystemCritical          types.Object `tfsdk:"system_critical"`
	VulnerabilityManagement types.Object `tfsdk:"vulnerability_management"`
	RapidResponse           types.Object `tfsdk:"rapid_response"`
	LastUpdated             types.String `tfsdk:"last_updated"`

	settings *contentUpdatePolicySettings `tfsdk:"-"`
}

// extract extracts the Go values from their terraform wrapped values.
func (d *defaultContentUpdatePolicyResourceModel) extract(ctx context.Context) diag.Diagnostics {
	var diags diag.Diagnostics

	d.settings, diags = extractRingAssignments(
		ctx,
		d.SensorOperations,
		d.SystemCritical,
		d.VulnerabilityManagement,
		d.RapidResponse,
	)

	return diags
}

// wrap transforms Go values to their terraform wrapped values.
func (d *defaultContentUpdatePolicyResourceModel) wrap(
	ctx context.Context,
	policy models.ContentUpdatePolicyV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	d.ID = types.StringValue(*policy.ID)
	d.Description = types.StringPointerValue(policy.Description)

	d.SensorOperations, d.SystemCritical, d.VulnerabilityManagement, d.RapidResponse, diags = populateRingAssignments(
		ctx,
		policy,
	)

	return diags
}

// Configure adds the provider configured client to the resource.
func (r *defaultContentUpdatePolicyResource) Configure(
	ctx context.Context,
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
func (r *defaultContentUpdatePolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_default_content_update_policy"
}

// Schema defines the schema for the resource.
func (r *defaultContentUpdatePolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Default Content Update Policy --- This resource allows management of the default content update policy in the CrowdStrike Falcon platform. Destruction of this resource *will not* delete the default content update policy or remove any configured settings.\n\n%s",
			scopes.GenerateScopeDescription(
				[]scopes.Scope{
					{
						Name:  "Content update policies",
						Read:  true,
						Write: true,
					},
				},
			),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the default content update policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"description": schema.StringAttribute{
				Required:    true,
				Description: "Description of the default content update policy.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
			"sensor_operations": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Ring assignment settings for sensor operations content category.",
				Attributes: map[string]schema.Attribute{
					"ring_assignment": schema.StringAttribute{
						Required:    true,
						Description: "Ring assignment for the content category (ga, ea, pause).",
						Validators: []validator.String{
							stringvalidator.OneOf(validRingAssignments...),
						},
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators: []validator.Int64{
							int64validator.OneOf(validDelayHours...),
						},
					},
				},
			},
			"system_critical": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Ring assignment settings for system critical content category.",
				Attributes: map[string]schema.Attribute{
					"ring_assignment": schema.StringAttribute{
						Required:    true,
						Description: "Ring assignment for the content category (ga, ea). Note: 'pause' is not allowed for system_critical.",
						Validators: []validator.String{
							stringvalidator.OneOf(validSystemCriticalRingAssignments...),
						},
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators: []validator.Int64{
							int64validator.OneOf(validDelayHours...),
						},
					},
				},
			},
			"vulnerability_management": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Ring assignment settings for vulnerability management content category.",
				Attributes: map[string]schema.Attribute{
					"ring_assignment": schema.StringAttribute{
						Required:    true,
						Description: "Ring assignment for the content category (ga, ea, pause).",
						Validators: []validator.String{
							stringvalidator.OneOf(validRingAssignments...),
						},
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators: []validator.Int64{
							int64validator.OneOf(validDelayHours...),
						},
					},
				},
			},
			"rapid_response": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Ring assignment settings for rapid response allow/block listing content category.",
				Attributes: map[string]schema.Attribute{
					"ring_assignment": schema.StringAttribute{
						Required:    true,
						Description: "Ring assignment for the content category (ga, ea, pause).",
						Validators: []validator.String{
							stringvalidator.OneOf(validRingAssignments...),
						},
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators: []validator.Int64{
							int64validator.OneOf(validDelayHours...),
						},
					},
				},
			},
		},
	}
}

// Create imports the resource into state and configures it. The default resource policy can't be created or deleted.
func (r *defaultContentUpdatePolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	tflog.Debug(ctx, "Starting default content update policy create operation")

	var plan defaultContentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Retrieving default content update policy")
	policy, diags := r.getDefaultPolicy(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue(*policy.ID)
	tflog.Debug(ctx, "Found default content update policy", map[string]any{
		"policy_id": *policy.ID,
	})

	resp.Diagnostics.Append(
		resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update the policy with the planned configuration
	tflog.Debug(ctx, "Updating default content update policy with planned configuration")
	policy, diags = r.updateDefaultPolicy(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	resp.Diagnostics.Append(plan.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Default content update policy create operation completed successfully")
}

// Read refreshes the Terraform state with the latest data.
func (r *defaultContentUpdatePolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state defaultContentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading default content update policy", map[string]any{
		"policy_id": state.ID.ValueString(),
	})

	policy, diags := getContentUpdatePolicy(ctx, r.client, state.ID.ValueString())
	if diags.HasError() {
		for _, diag := range diags {
			if strings.Contains(diag.Summary(), "not found") {
				tflog.Warn(
					ctx,
					fmt.Sprintf(
						"default content update policy %s not found, removing from state",
						state.ID,
					),
				)
				resp.State.RemoveResource(ctx)
				return
			}
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	tflog.Debug(ctx, "Successfully retrieved default content update policy", map[string]any{
		"policy_id": state.ID.ValueString(),
	})

	resp.Diagnostics.Append(state.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *defaultContentUpdatePolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan defaultContentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(
		ctx,
		"Starting default content update policy update operation",
		map[string]any{
			"policy_id": plan.ID.ValueString(),
		},
	)

	policy, diags := r.updateDefaultPolicy(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(plan.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Default content update policy update operation completed successfully")
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *defaultContentUpdatePolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	tflog.Debug(
		ctx,
		"Default content update policy delete operation - resource will be removed from state only (cannot delete default policy)",
	)
	// We can not delete the default content update policy, so we will just remove it from state.
}

// ImportState implements the logic to support resource imports.
func (r *defaultContentUpdatePolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply to validate resource configuration.
func (r *defaultContentUpdatePolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config defaultContentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(config.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.settings.sensorOperations != nil {
		if config.settings.sensorOperations.RingAssignment.ValueString() != "ga" &&
			!config.settings.sensorOperations.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("sensor_operations").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf(
					"delay_hours can only be set when ring_assignment is 'ga'. sensor_operations has ring_assignment '%s' but delay_hours is set.",
					config.settings.sensorOperations.RingAssignment.ValueString(),
				),
			)
		}
	}

	if config.settings.systemCritical != nil {
		if config.settings.systemCritical.RingAssignment.ValueString() != "ga" &&
			!config.settings.systemCritical.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("system_critical").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf(
					"delay_hours can only be set when ring_assignment is 'ga'. system_critical has ring_assignment '%s' but delay_hours is set.",
					config.settings.systemCritical.RingAssignment.ValueString(),
				),
			)
		}
	}

	if config.settings.vulnerabilityManagement != nil {
		if config.settings.vulnerabilityManagement.RingAssignment.ValueString() != "ga" &&
			!config.settings.vulnerabilityManagement.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("vulnerability_management").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf(
					"delay_hours can only be set when ring_assignment is 'ga'. vulnerability_management has ring_assignment '%s' but delay_hours is set.",
					config.settings.vulnerabilityManagement.RingAssignment.ValueString(),
				),
			)
		}
	}

	if config.settings.rapidResponse != nil {
		if config.settings.rapidResponse.RingAssignment.ValueString() != "ga" &&
			!config.settings.rapidResponse.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("rapid_response").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf(
					"delay_hours can only be set when ring_assignment is 'ga'. rapid_response has ring_assignment '%s' but delay_hours is set.",
					config.settings.rapidResponse.RingAssignment.ValueString(),
				),
			)
		}
	}
}

func (r *defaultContentUpdatePolicyResource) updateDefaultPolicy(
	ctx context.Context,
	config *defaultContentUpdatePolicyResourceModel,
) (*models.ContentUpdatePolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	ringAssignmentSettings := buildRingAssignmentSettings(config.settings)

	tflog.Debug(
		ctx,
		"Building ring assignment settings for default policy update",
		map[string]any{
			"policy_id":     config.ID.ValueString(),
			"setting_count": len(ringAssignmentSettings),
		},
	)

	policyParams := content_update_policies.UpdateContentUpdatePoliciesParams{
		Context: ctx,
		Body: &models.ContentUpdateUpdatePoliciesReqV1{
			Resources: []*models.ContentUpdateUpdatePolicyReqV1{
				{
					ID:          config.ID.ValueStringPointer(),
					Description: config.Description.ValueString(),
					Settings: &models.ContentUpdateContentUpdateSettingsReqV1{
						RingAssignmentSettings: ringAssignmentSettings,
					},
				},
			},
		},
	}

	tflog.Debug(ctx, "Calling UpdateContentUpdatePolicies API for default policy")
	res, err := r.client.ContentUpdatePolicies.UpdateContentUpdatePolicies(&policyParams)

	if err != nil {
		diags.AddError(
			"Error updating CrowdStrike default content update policy",
			"Could not update default content update policy with ID: "+config.ID.ValueString()+": "+err.Error(),
		)
		return nil, diags
	}

	policy := res.Payload.Resources[0]

	tflog.Debug(ctx, "Successfully updated default content update policy", map[string]any{
		"policy_id": *policy.ID,
	})

	return policy, diags
}

func (r *defaultContentUpdatePolicyResource) getDefaultPolicy(
	ctx context.Context,
) (*models.ContentUpdatePolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	sort := "precedence.desc"
	filter := "name.raw:'platform_default'"

	tflog.Debug(
		ctx,
		"Querying content update policies to find default policy",
		map[string]any{
			"sort":   sort,
			"filter": filter,
		},
	)

	res, err := r.client.ContentUpdatePolicies.QueryCombinedContentUpdatePolicies(
		&content_update_policies.QueryCombinedContentUpdatePoliciesParams{
			Context: ctx,
			Sort:    &sort,
			Filter:  &filter,
		},
	)

	if err != nil {
		diags.AddError(
			"Failed to get default content update policy",
			fmt.Sprintf("Failed to query content update policies: %s", err),
		)

		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Unable to find default content update policy",
			"No content update policies found. A default policy should exist. Please report this issue to the provider developers.",
		)

		return nil, diags
	}

	// Sort by ascending precedence, so the default policy (lowest precedence) is first
	defaultPolicy := res.Payload.Resources[0]

	tflog.Debug(ctx, "Found default content update policy", map[string]any{
		"policy_id":      *defaultPolicy.ID,
		"policy_name":    *defaultPolicy.Name,
		"total_policies": len(res.Payload.Resources),
	})

	return defaultPolicy, diags
}
