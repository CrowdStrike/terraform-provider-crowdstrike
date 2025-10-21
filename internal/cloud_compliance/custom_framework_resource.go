package cloudcompliance

import (
	"context"
	"fmt"

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
}

func (r *cloudComplianceCustomFrameworkResource) Configure(
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

	// Update the plan with the API response
	resp.Diagnostics.Append(plan.wrap(ctx, framework)...)
	if resp.Diagnostics.HasError() {
		return
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

	// Set state
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

	// Update the plan with the API response
	resp.Diagnostics.Append(plan.wrap(ctx, framework)...)
	if resp.Diagnostics.HasError() {
		return
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

	return diags
}
