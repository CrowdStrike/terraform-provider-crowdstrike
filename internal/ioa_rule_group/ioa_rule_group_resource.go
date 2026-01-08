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
	Version     types.Int64  `tfsdk:"version"`
	LastUpdated types.String `tfsdk:"last_updated"`
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
