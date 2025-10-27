package cloudsecuritygroup

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
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
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                     = &cloudSecurityGroupResource{}
	_ resource.ResourceWithConfigure        = &cloudSecurityGroupResource{}
	_ resource.ResourceWithImportState      = &cloudSecurityGroupResource{}
	_ resource.ResourceWithValidateConfig   = &cloudSecurityGroupResource{}
)

// cloudSecurityGroupScopes defines the required API scopes for Cloud Security Groups.
var cloudSecurityGroupScopes = []scopes.Scope{
	{
		Name:  "Cloud security",
		Read:  true,
		Write: true,
	},
}

// NewCloudSecurityGroupResource is a helper function to simplify the provider implementation.
func NewCloudSecurityGroupResource() resource.Resource {
	return &cloudSecurityGroupResource{}
}

// cloudSecurityGroupResource defines the resource implementation.
type cloudSecurityGroupResource struct {
	client *client.CrowdStrikeAPISpecification
}

// cloudResourceFiltersModel represents the cloud resource filters.
type cloudResourceFiltersModel struct {
	Region types.List `tfsdk:"region"`
	Tags   types.List `tfsdk:"tags"`
}

// AttributeTypes returns the attribute types for cloud resource filters.
// includeTags determines whether to include the tags field (false for GCP).
func (cloudResourceFiltersModel) AttributeTypes(includeTags bool) map[string]attr.Type {
	attrTypes := map[string]attr.Type{
		"region": types.ListType{ElemType: types.StringType},
	}

	if includeTags {
		attrTypes["tags"] = types.ListType{ElemType: types.StringType}
	}

	return attrTypes
}

// cloudProviderConfigModel represents cloud provider configuration.
type cloudProviderConfigModel struct {
	AccountIds types.List   `tfsdk:"account_ids"`
	Filters    types.Object `tfsdk:"filters"`
}

// AttributeTypes returns the attribute types for cloud provider config.
// includeTags determines whether to include tags in filters (false for GCP).
func (cloudProviderConfigModel) AttributeTypes(includeTags bool) map[string]attr.Type {
	return map[string]attr.Type{
		"account_ids": types.ListType{ElemType: types.StringType},
		"filters": types.ObjectType{
			AttrTypes: cloudResourceFiltersModel{}.AttributeTypes(includeTags),
		},
	}
}

// imageSelectorModel represents an image selector.
type imageSelectorModel struct {
	Registry   types.String `tfsdk:"registry"`
	Repository types.String `tfsdk:"repository"`
	Tag        types.String `tfsdk:"tag"`
}

// cloudSecurityGroupResourceModel describes the resource data model.
type cloudSecurityGroupResourceModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	Description    types.String `tfsdk:"description"`
	BusinessImpact types.String `tfsdk:"business_impact"`
	BusinessUnit   types.String `tfsdk:"business_unit"`
	Environment    types.String `tfsdk:"environment"`
	Owners         types.List   `tfsdk:"owners"`
	AWS            types.Object `tfsdk:"aws"`
	Azure          types.Object `tfsdk:"azure"`
	GCP            types.Object `tfsdk:"gcp"`
	Images         types.List   `tfsdk:"images"`
	// Computed fields
	CreatedAt types.String `tfsdk:"created_at"`
	UpdatedAt types.String `tfsdk:"updated_at"`
	CreatedBy types.String `tfsdk:"created_by"`
}

// Metadata returns the resource type name.
func (r *cloudSecurityGroupResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_security_group"
}

// Schema defines the schema for the resource.
func (r *cloudSecurityGroupResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"CrowdStrike Cloud Security Group --- This resource manages CrowdStrike Cloud Security Groups for organizing cloud resources and container images.\n\n%s",
			scopes.GenerateScopeDescription(cloudSecurityGroupScopes),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the cloud security group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the cloud security group.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 100),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "The description of the cloud security group.",
				Validators: []validator.String{
					stringvalidator.LengthAtMost(1000),
				},
			},
			"business_impact": schema.StringAttribute{
				Optional:    true,
				Description: "Business impact level for the group.",
				Validators: []validator.String{
					stringvalidator.OneOf("high", "moderate", "low"),
				},
			},
			"business_unit": schema.StringAttribute{
				Optional:    true,
				Description: "Business unit for the group.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 100),
				},
			},
			"environment": schema.StringAttribute{
				Optional:    true,
				Description: "Environment for the group.",
				Validators: []validator.String{
					stringvalidator.OneOf("dev", "test", "stage", "prod"),
				},
			},
			"owners": schema.ListAttribute{
				Optional:    true,
				Description: "List of owner email addresses for the group.",
				ElementType: types.StringType,
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.RegexMatches(
							regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
							"must be a valid email address",
						),
					),
				},
			},
			"aws": schema.SingleNestedAttribute{
				Description: "AWS cloud resource configuration",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"account_ids": schema.ListAttribute{
						Description: "List of AWS account IDs",
						Required:    true,
						ElementType: types.StringType,
						Validators: []validator.List{
							listvalidator.SizeAtLeast(1),
						},
					},
					"filters": schema.SingleNestedAttribute{
						Description: "Filters for AWS cloud resources",
						Optional:    true,
						Attributes: map[string]schema.Attribute{
							"region": schema.ListAttribute{
								Description: "List of AWS regions to include",
								Optional:    true,
								ElementType: types.StringType,
							},
							"tags": schema.ListAttribute{
								Description: "List of tags to filter by (format: key=value)",
								Optional:    true,
								ElementType: types.StringType,
							},
						},
					},
				},
			},
			"azure": schema.SingleNestedAttribute{
				Description: "Azure cloud resource configuration",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"account_ids": schema.ListAttribute{
						Description: "List of Azure subscription IDs",
						Required:    true,
						ElementType: types.StringType,
						Validators: []validator.List{
							listvalidator.SizeAtLeast(1),
						},
					},
					"filters": schema.SingleNestedAttribute{
						Description: "Filters for Azure cloud resources",
						Optional:    true,
						Attributes: map[string]schema.Attribute{
							"region": schema.ListAttribute{
								Description: "List of Azure regions to include",
								Optional:    true,
								ElementType: types.StringType,
							},
							"tags": schema.ListAttribute{
								Description: "List of tags to filter by (format: key=value)",
								Optional:    true,
								ElementType: types.StringType,
							},
						},
					},
				},
			},
			"gcp": schema.SingleNestedAttribute{
				Description: "GCP cloud resource configuration",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"account_ids": schema.ListAttribute{
						Description: "List of GCP project IDs",
						Required:    true,
						ElementType: types.StringType,
						Validators: []validator.List{
							listvalidator.SizeAtLeast(1),
						},
					},
					"filters": schema.SingleNestedAttribute{
						Description: "Filters for GCP cloud resources. Note: GCP does not support tag filtering.",
						Optional:    true,
						Attributes: map[string]schema.Attribute{
							"region": schema.ListAttribute{
								Description: "List of GCP regions to include",
								Optional:    true,
								ElementType: types.StringType,
							},
						},
					},
				},
			},
			"images": schema.ListNestedAttribute{
				Description: "Container image selectors for grouping container images",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"registry": schema.StringAttribute{
							Description: "Container registry hostname",
							Required:    true,
						},
						"repository": schema.StringAttribute{
							Description: "Repository name",
							Required:    true,
						},
						"tag": schema.StringAttribute{
							Description: "Image tag (optional, defaults to any tag if not specified)",
							Optional:    true,
						},
					},
				},
			},
			// Computed attributes
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "The timestamp when the group was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "The timestamp when the group was last updated.",
			},
			"created_by": schema.StringAttribute{
				Computed:    true,
				Description: "The API client ID that created the group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *cloudSecurityGroupResource) Configure(
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

// ValidateConfig validates the resource configuration.
func (r *cloudSecurityGroupResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config cloudSecurityGroupResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate that GCP configuration does not use tags filter
	if !config.GCP.IsNull() && !config.GCP.IsUnknown() {
		var gcpConfig cloudProviderConfigModel
		resp.Diagnostics.Append(config.GCP.As(ctx, &gcpConfig, basetypes.ObjectAsOptions{})...)
		if resp.Diagnostics.HasError() {
			return
		}

		if !gcpConfig.Filters.IsNull() && !gcpConfig.Filters.IsUnknown() {
			// Extract filters attributes to check for tags
			filterValues := gcpConfig.Filters.Attributes()

			// Check if tags field exists and has values
			if tagsValue, ok := filterValues["tags"]; ok && !tagsValue.IsNull() {
				var tags []string
				resp.Diagnostics.Append(tagsValue.(types.List).ElementsAs(ctx, &tags, false)...)
				if len(tags) > 0 {
					resp.Diagnostics.AddAttributeError(
						path.Root("gcp").AtName("filters").AtName("tags"),
						"Invalid Configuration",
						"GCP cloud resources do not support tag filtering. Remove the tags filter from the GCP configuration.",
					)
				}
			}
		}
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *cloudSecurityGroupResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudSecurityGroupResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert plan to API request
	createRequest, diags := r.planToCreateRequest(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Creating cloud security group", map[string]interface{}{"name": plan.Name.ValueString()})

	// Call the API
	res, err := r.client.CloudSecurity.CreateCloudGroupExternal(
		&cloud_security.CreateCloudGroupExternalParams{
			Context: ctx,
			Body:    createRequest,
		},
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to create cloud security group",
			fmt.Sprintf("Failed to create cloud security group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if res.Payload == nil || res.Payload.Resources == nil || len(res.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Failed to create cloud security group",
			"No data returned from API",
		)
		return
	}

	// Get the created group by ID since the create response only returns the ID
	groupID := res.Payload.Resources[0]
	getRes, err := r.client.CloudSecurity.ListCloudGroupsByIDExternal(
		&cloud_security.ListCloudGroupsByIDExternalParams{
			Context: ctx,
			Ids:     []string{groupID},
		},
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read created cloud security group",
			fmt.Sprintf("Failed to read created cloud security group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if getRes.Payload == nil || getRes.Payload.Resources == nil || len(getRes.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Failed to read created cloud security group",
			"No data returned from API after creation",
		)
		return
	}

	// Update state with response data
	state, diags := r.responseToState(ctx, getRes.Payload.Resources[0], plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *cloudSecurityGroupResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudSecurityGroupResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.ID.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Resource ID missing",
			"Cloud security group ID is missing from state",
		)
		return
	}

	tflog.Info(ctx, "Reading cloud security group", map[string]interface{}{"id": state.ID.ValueString()})

	// Get the cloud security group by ID
	res, err := r.client.CloudSecurity.ListCloudGroupsByIDExternal(
		&cloud_security.ListCloudGroupsByIDExternalParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			tflog.Warn(ctx, "Cloud security group not found, removing from state", map[string]interface{}{"id": state.ID.ValueString()})
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Failed to read cloud security group",
			fmt.Sprintf("Failed to read cloud security group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if res.Payload == nil || res.Payload.Resources == nil || len(res.Payload.Resources) == 0 {
		tflog.Warn(ctx, "Cloud security group not found, removing from state", map[string]interface{}{"id": state.ID.ValueString()})
		resp.State.RemoveResource(ctx)
		return
	}

	// Update state with response data
	newState, diags := r.responseToState(ctx, res.Payload.Resources[0], state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &newState)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *cloudSecurityGroupResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudSecurityGroupResourceModel
	var state cloudSecurityGroupResourceModel

	// Get plan and current state
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert plan to API request
	updateRequest, diags := r.planToUpdateRequest(ctx, plan, state.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Updating cloud security group", map[string]interface{}{
		"id":   state.ID.ValueString(),
		"name": plan.Name.ValueString(),
	})

	// Call the API
	res, err := r.client.CloudSecurity.UpdateCloudGroupExternal(
		&cloud_security.UpdateCloudGroupExternalParams{
			Context: ctx,
			Group:   updateRequest,
		},
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to update cloud security group",
			fmt.Sprintf("Failed to update cloud security group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if res.Payload == nil || res.Payload.Resources == nil || len(res.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Failed to update cloud security group",
			"No data returned from API",
		)
		return
	}

	// Get the updated group by ID to get full data
	getRes, err := r.client.CloudSecurity.ListCloudGroupsByIDExternal(
		&cloud_security.ListCloudGroupsByIDExternalParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read updated cloud security group",
			fmt.Sprintf("Failed to read updated cloud security group: %s", err.Error()),
		)
		return
	}

	if getRes.Payload == nil || getRes.Payload.Resources == nil || len(getRes.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Failed to read updated cloud security group",
			"No data returned from API after update",
		)
		return
	}

	// Update state with response data
	newState, diags := r.responseToState(ctx, getRes.Payload.Resources[0], plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &newState)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *cloudSecurityGroupResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudSecurityGroupResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.ID.ValueString() == "" {
		return // Resource doesn't exist
	}

	tflog.Info(ctx, "Deleting cloud security group", map[string]interface{}{"id": state.ID.ValueString()})

	// Call the API
	_, err := r.client.CloudSecurity.DeleteCloudGroupsExternal(
		&cloud_security.DeleteCloudGroupsExternalParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)
	if err != nil {
		// If the resource is already deleted (404), that's okay
		if !strings.Contains(err.Error(), "404") {
			resp.Diagnostics.AddError(
				"Failed to delete cloud security group",
				fmt.Sprintf("Failed to delete cloud security group: %s", falcon.ErrorExplain(err)),
			)
			return
		}
	}
}

// ImportState implements the logic to support resource imports.
func (r *cloudSecurityGroupResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Import using the UUID
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// Helper functions for conversions between Terraform model and API requests/responses

// planToCreateRequest converts the Terraform plan to an API create request.
func (r *cloudSecurityGroupResource) planToCreateRequest(
	ctx context.Context,
	plan cloudSecurityGroupResourceModel,
) (*models.AssetgroupmanagerV1CreateCloudGroupRequest, diag.Diagnostics) {
	var diags diag.Diagnostics

	request := &models.AssetgroupmanagerV1CreateCloudGroupRequest{
		Name:           plan.Name.ValueStringPointer(),
		Description:    plan.Description.ValueStringPointer(),
		BusinessImpact: plan.BusinessImpact.ValueStringPointer(),
		BusinessUnit:   plan.BusinessUnit.ValueStringPointer(),
		Environment:    plan.Environment.ValueStringPointer(),
	}

	// Convert owners
	if !plan.Owners.IsNull() {
		var owners []string
		diags.Append(plan.Owners.ElementsAs(ctx, &owners, false)...)
		request.Owners = owners
	}

	// Convert selectors
	selectors, selectorDiags := r.convertSelectorsToAPI(ctx, plan.AWS, plan.Azure, plan.GCP, plan.Images)
	diags.Append(selectorDiags...)
	if selectors != nil {
		request.Selectors = selectors
	}

	return request, diags
}

// planToUpdateRequest converts the Terraform plan to an API update request.
func (r *cloudSecurityGroupResource) planToUpdateRequest(
	ctx context.Context,
	plan cloudSecurityGroupResourceModel,
	id string,
) (*models.AssetgroupmanagerV1UpdateCloudGroupMessage, diag.Diagnostics) {
	var diags diag.Diagnostics

	request := &models.AssetgroupmanagerV1UpdateCloudGroupMessage{
		ID:             id,
		Name:           plan.Name.ValueString(),
		Description:    utils.Addr(plan.Description.ValueString()),
		BusinessImpact: utils.Addr(plan.BusinessImpact.ValueString()),
		BusinessUnit:   utils.Addr(plan.BusinessUnit.ValueString()),
		Environment:    utils.Addr(plan.Environment.ValueString()),
	}

	// Convert owners
	if !plan.Owners.IsNull() {
		var owners []string
		diags.Append(plan.Owners.ElementsAs(ctx, &owners, false)...)
		request.Owners = owners
	}

	// Convert selectors
	selectors, selectorDiags := r.convertSelectorsToAPI(ctx, plan.AWS, plan.Azure, plan.GCP, plan.Images)
	diags.Append(selectorDiags...)
	if selectors != nil {
		request.Selectors = selectors
	}

	return request, diags
}

// convertSelectorsToAPI converts the Terraform selectors model to API format.
func (r *cloudSecurityGroupResource) convertSelectorsToAPI(
	ctx context.Context,
	awsObj types.Object,
	azureObj types.Object,
	gcpObj types.Object,
	imagesList types.List,
) (*models.AssetgroupmanagerV1WriteCloudGroupSelectors, diag.Diagnostics) {
	var diags diag.Diagnostics
	apiSelectors := &models.AssetgroupmanagerV1WriteCloudGroupSelectors{}

	// Helper function to convert cloud provider config to API selector
	convertCloudProvider := func(providerObj types.Object, providerName string, includeTags bool) (*models.AssetgroupmanagerV1CloudResourceSelector, diag.Diagnostics) {
		var diags diag.Diagnostics
		if providerObj.IsNull() || providerObj.IsUnknown() {
			return nil, diags
		}

		var config cloudProviderConfigModel
		diags.Append(providerObj.As(ctx, &config, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return nil, diags
		}

		apiSelector := &models.AssetgroupmanagerV1CloudResourceSelector{
			CloudProvider: &providerName,
		}

		// Convert account IDs
		if !config.AccountIds.IsNull() {
			var accountIds []string
			diags.Append(config.AccountIds.ElementsAs(ctx, &accountIds, false)...)
			apiSelector.AccountIds = accountIds
		}

		// Convert filters
		if !config.Filters.IsNull() && !config.Filters.IsUnknown() {
			// Extract filters attributes to avoid struct mismatch
			filterValues := config.Filters.Attributes()

			apiFilters := &models.AssetgroupmanagerV1CloudResourceFilters{}

			// Extract region if present
			if regionValue, ok := filterValues["region"]; ok && !regionValue.IsNull() {
				var regions []string
				diags.Append(regionValue.(types.List).ElementsAs(ctx, &regions, false)...)
				apiFilters.Region = regions
			}

			// Extract tags if present and includeTags is true
			if includeTags {
				if tagsValue, ok := filterValues["tags"]; ok && !tagsValue.IsNull() {
					var tags []string
					diags.Append(tagsValue.(types.List).ElementsAs(ctx, &tags, false)...)
					apiFilters.Tags = tags
				}
			}

			apiSelector.Filters = apiFilters
		}

		return apiSelector, diags
	}

	// Convert AWS
	if awsSelector, awsDiags := convertCloudProvider(awsObj, "aws", true); awsSelector != nil {
		diags.Append(awsDiags...)
		apiSelectors.CloudResources = append(apiSelectors.CloudResources, awsSelector)
	} else {
		diags.Append(awsDiags...)
	}

	// Convert Azure
	if azureSelector, azureDiags := convertCloudProvider(azureObj, "azure", true); azureSelector != nil {
		diags.Append(azureDiags...)
		apiSelectors.CloudResources = append(apiSelectors.CloudResources, azureSelector)
	} else {
		diags.Append(azureDiags...)
	}

	// Convert GCP
	if gcpSelector, gcpDiags := convertCloudProvider(gcpObj, "gcp", false); gcpSelector != nil {
		diags.Append(gcpDiags...)
		apiSelectors.CloudResources = append(apiSelectors.CloudResources, gcpSelector)
	} else {
		diags.Append(gcpDiags...)
	}

	// Convert image selectors
	if !imagesList.IsNull() && !imagesList.IsUnknown() {
		var images []imageSelectorModel
		diags.Append(imagesList.ElementsAs(ctx, &images, false)...)

		for _, img := range images {
			apiSelector := &models.AssetgroupmanagerV1ImageSelector{
				Registry: img.Registry.ValueStringPointer(),
			}

			// Set up filters if we have repository or tag
			if !img.Repository.IsNull() || !img.Tag.IsNull() {
				filters := &models.AssetgroupmanagerV1ImageFilters{}

				if !img.Repository.IsNull() {
					filters.Repository = []string{img.Repository.ValueString()}
				}

				if !img.Tag.IsNull() {
					filters.Tag = []string{img.Tag.ValueString()}
				}

				apiSelector.Filters = filters
			}

			apiSelectors.Images = append(apiSelectors.Images, apiSelector)
		}
	}

	return apiSelectors, diags
}

// responseToState converts API response to Terraform state model.
func (r *cloudSecurityGroupResource) responseToState(
	ctx context.Context,
	apiGroup *models.AssetgroupmanagerV1CloudGroup,
	currentState cloudSecurityGroupResourceModel,
) (cloudSecurityGroupResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	state := currentState

	// Set basic fields from API response
	if apiGroup.ID != "" {
		state.ID = types.StringValue(apiGroup.ID)
	}

	if apiGroup.Name != "" {
		state.Name = types.StringValue(apiGroup.Name)
	}

	// Only set optional fields if they have values or were set in current state
	if apiGroup.Description != "" {
		state.Description = types.StringValue(apiGroup.Description)
	} else if currentState.Description.IsNull() {
		state.Description = types.StringNull()
	}

	if apiGroup.BusinessImpact != "" {
		state.BusinessImpact = types.StringValue(apiGroup.BusinessImpact)
	} else if currentState.BusinessImpact.IsNull() {
		state.BusinessImpact = types.StringNull()
	}

	if apiGroup.BusinessUnit != "" {
		state.BusinessUnit = types.StringValue(apiGroup.BusinessUnit)
	} else if currentState.BusinessUnit.IsNull() {
		state.BusinessUnit = types.StringNull()
	}

	if apiGroup.Environment != "" {
		state.Environment = types.StringValue(apiGroup.Environment)
	} else if currentState.Environment.IsNull() {
		state.Environment = types.StringNull()
	}

	// Set computed fields - always set to avoid unknown values
	if !apiGroup.CreatedAt.IsZero() {
		state.CreatedAt = types.StringValue(apiGroup.CreatedAt.String())
	} else if state.CreatedAt.IsUnknown() {
		state.CreatedAt = types.StringValue("")
	}

	if !apiGroup.UpdatedAt.IsZero() {
		state.UpdatedAt = types.StringValue(apiGroup.UpdatedAt.String())
	} else {
		// Always set updated_at to avoid unknown value errors
		state.UpdatedAt = types.StringValue(apiGroup.CreatedAt.String())
	}

	if apiGroup.CreatedBy != "" {
		state.CreatedBy = types.StringValue(apiGroup.CreatedBy)
	} else if state.CreatedBy.IsUnknown() {
		state.CreatedBy = types.StringValue("")
	}

	// Convert owners
	if len(apiGroup.Owners) > 0 {
		ownersList, listDiags := types.ListValueFrom(ctx, types.StringType, apiGroup.Owners)
		diags.Append(listDiags...)
		state.Owners = ownersList
	} else {
		state.Owners = types.ListNull(types.StringType)
	}

	// Convert selectors - convert to separate cloud provider fields
	if apiGroup.Selectors != nil {
		aws, azure, gcp, images, selectorDiags := r.convertAPISelectorsToTerraform(ctx, apiGroup.Selectors)
		diags.Append(selectorDiags...)
		state.AWS = aws
		state.Azure = azure
		state.GCP = gcp
		state.Images = images
	} else {
		// Set to null if no selectors in API response - use helper methods
		state.AWS = types.ObjectNull(cloudProviderConfigModel{}.AttributeTypes(true))
		state.Azure = types.ObjectNull(cloudProviderConfigModel{}.AttributeTypes(true))
		state.GCP = types.ObjectNull(cloudProviderConfigModel{}.AttributeTypes(false))
		state.Images = types.ListNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"registry":   types.StringType,
				"repository": types.StringType,
				"tag":        types.StringType,
			},
		})
	}

	return state, diags
}

// convertAPISelectorsToTerraform converts API selectors to Terraform model.
func (r *cloudSecurityGroupResource) convertAPISelectorsToTerraform(
	ctx context.Context,
	apiSelectors *models.AssetgroupmanagerV1CloudGroupSelectors,
) (types.Object, types.Object, types.Object, types.List, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Helper function to convert API selector to cloud provider config
	convertToCloudProviderConfig := func(cr *models.AssetgroupmanagerV1CloudResourceSelector, includeTags bool) (cloudProviderConfigModel, diag.Diagnostics) {
		var diags diag.Diagnostics
		config := cloudProviderConfigModel{}

		// Convert account IDs
		if len(cr.AccountIds) > 0 {
			accountIdsList, listDiags := types.ListValueFrom(ctx, types.StringType, cr.AccountIds)
			diags.Append(listDiags...)
			config.AccountIds = accountIdsList
		} else {
			config.AccountIds = types.ListNull(types.StringType)
		}

		// Convert filters
		if cr.Filters != nil && (len(cr.Filters.Region) > 0 || (includeTags && len(cr.Filters.Tags) > 0)) {
			// Build attribute values map
			filterValues := make(map[string]attr.Value)

			// Always include region
			if len(cr.Filters.Region) > 0 {
				regionsList, listDiags := types.ListValueFrom(ctx, types.StringType, cr.Filters.Region)
				diags.Append(listDiags...)
				filterValues["region"] = regionsList
			} else {
				filterValues["region"] = types.ListNull(types.StringType)
			}

			// Conditionally include tags
			if includeTags {
				if len(cr.Filters.Tags) > 0 {
					tagsList, listDiags := types.ListValueFrom(ctx, types.StringType, cr.Filters.Tags)
					diags.Append(listDiags...)
					filterValues["tags"] = tagsList
				} else {
					filterValues["tags"] = types.ListNull(types.StringType)
				}
			}

			// Create object from map
			filtersObjVal, objDiags := types.ObjectValue(cloudResourceFiltersModel{}.AttributeTypes(includeTags), filterValues)
			diags.Append(objDiags...)
			config.Filters = filtersObjVal
		} else {
			// Null filters object
			config.Filters = types.ObjectNull(cloudResourceFiltersModel{}.AttributeTypes(includeTags))
		}

		return config, diags
	}

	// Initialize null values using helper methods
	var awsObj, azureObj, gcpObj types.Object
	awsObj = types.ObjectNull(cloudProviderConfigModel{}.AttributeTypes(true))
	azureObj = types.ObjectNull(cloudProviderConfigModel{}.AttributeTypes(true))
	gcpObj = types.ObjectNull(cloudProviderConfigModel{}.AttributeTypes(false))

	// Convert cloud resource selectors by provider
	for _, cr := range apiSelectors.CloudResources {
		if cr.CloudProvider == nil {
			continue
		}

		switch *cr.CloudProvider {
		case "aws":
			config, configDiags := convertToCloudProviderConfig(cr, true)
			diags.Append(configDiags...)
			awsObjVal, objDiags := types.ObjectValueFrom(ctx, cloudProviderConfigModel{}.AttributeTypes(true), config)
			diags.Append(objDiags...)
			awsObj = awsObjVal

		case "azure":
			config, configDiags := convertToCloudProviderConfig(cr, true)
			diags.Append(configDiags...)
			azureObjVal, objDiags := types.ObjectValueFrom(ctx, cloudProviderConfigModel{}.AttributeTypes(true), config)
			diags.Append(objDiags...)
			azureObj = azureObjVal

		case "gcp":
			config, configDiags := convertToCloudProviderConfig(cr, false) // GCP doesn't support tags
			diags.Append(configDiags...)
			gcpObjVal, objDiags := types.ObjectValueFrom(ctx, cloudProviderConfigModel{}.AttributeTypes(false), config)
			diags.Append(objDiags...)
			gcpObj = gcpObjVal
		}
	}

	// Convert image selectors
	var imagesList types.List
	if len(apiSelectors.Images) > 0 {
		var images []imageSelectorModel
		for _, img := range apiSelectors.Images {
			selector := imageSelectorModel{
				Registry: types.StringValue(*img.Registry),
			}

			// Extract repository and tag from filters
			if img.Filters != nil {
				if len(img.Filters.Repository) > 0 {
					selector.Repository = types.StringValue(img.Filters.Repository[0])
				} else {
					selector.Repository = types.StringNull()
				}

				if len(img.Filters.Tag) > 0 {
					selector.Tag = types.StringValue(img.Filters.Tag[0])
				} else {
					selector.Tag = types.StringNull()
				}
			} else {
				selector.Repository = types.StringNull()
				selector.Tag = types.StringNull()
			}

			images = append(images, selector)
		}

		imagesListVal, listDiags := types.ListValueFrom(ctx, types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"registry":   types.StringType,
				"repository": types.StringType,
				"tag":        types.StringType,
			},
		}, images)
		diags.Append(listDiags...)
		imagesList = imagesListVal
	} else {
		imagesList = types.ListNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"registry":   types.StringType,
				"repository": types.StringType,
				"tag":        types.StringType,
			},
		})
	}

	return awsObj, azureObj, gcpObj, imagesList, diags
}
