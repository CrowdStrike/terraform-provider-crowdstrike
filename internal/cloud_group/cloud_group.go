package cloudgroup

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	fwtypes "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/types"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
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
	_ resource.Resource                = &cloudGroupResource{}
	_ resource.ResourceWithConfigure   = &cloudGroupResource{}
	_ resource.ResourceWithImportState = &cloudGroupResource{}
)

// NewCloudGroupResource is a helper function to simplify the provider implementation.
func NewCloudGroupResource() resource.Resource {
	return &cloudGroupResource{}
}

// cloudGroupResource defines the resource implementation.
type cloudGroupResource struct {
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

// Expand converts the Terraform model to an API cloud resource selector.
func (c cloudProviderConfigModel) Expand(
	ctx context.Context,
	providerName string,
	includeTags bool,
) (*models.AssetgroupmanagerV1CloudResourceSelector, diag.Diagnostics) {
	var diags diag.Diagnostics

	apiSelector := &models.AssetgroupmanagerV1CloudResourceSelector{
		CloudProvider: &providerName,
	}

	if !c.AccountIds.IsNull() {
		var accountIds []string
		diags.Append(c.AccountIds.ElementsAs(ctx, &accountIds, false)...)
		apiSelector.AccountIds = accountIds
	}

	if utils.IsKnown(c.Filters) {
		filterValues := c.Filters.Attributes()

		apiFilters := &models.AssetgroupmanagerV1CloudResourceFilters{}

		if regionValue, ok := filterValues["region"]; ok && !regionValue.IsNull() {
			var regions []string
			regionList, ok := regionValue.(types.List)
			if !ok {
				diags.AddError(
					"Invalid Type",
					"Expected region to be a list type.",
				)
				return nil, diags
			}
			diags.Append(regionList.ElementsAs(ctx, &regions, false)...)
			apiFilters.Region = regions
		}

		if includeTags {
			if tagsValue, ok := filterValues["tags"]; ok && !tagsValue.IsNull() {
				var tags []string
				tagsList, ok := tagsValue.(types.List)
				if !ok {
					diags.AddError(
						"Invalid Type",
						"Expected tags to be a list type.",
					)
					return nil, diags
				}
				diags.Append(tagsList.ElementsAs(ctx, &tags, false)...)
				apiFilters.Tags = tags
			}
		}

		apiSelector.Filters = apiFilters
	}

	return apiSelector, diags
}

// Flatten converts an API cloud resource selector to the Terraform model.
func (c *cloudProviderConfigModel) Flatten(
	ctx context.Context,
	cr *models.AssetgroupmanagerV1CloudResourceSelector,
	includeTags bool,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if cr == nil {
		return diags
	}

	if len(cr.AccountIds) > 0 {
		accountIdsList, listDiags := types.ListValueFrom(ctx, types.StringType, cr.AccountIds)
		diags.Append(listDiags...)
		if diags.HasError() {
			return diags
		}
		c.AccountIds = accountIdsList
	} else {
		c.AccountIds = types.ListNull(types.StringType)
	}

	if cr.Filters != nil && (len(cr.Filters.Region) > 0 || (includeTags && len(cr.Filters.Tags) > 0)) {
		filterValues := make(map[string]attr.Value)

		if len(cr.Filters.Region) > 0 {
			regionsList, listDiags := types.ListValueFrom(ctx, types.StringType, cr.Filters.Region)
			diags.Append(listDiags...)
			if diags.HasError() {
				return diags
			}
			filterValues["region"] = regionsList
		} else {
			filterValues["region"] = types.ListNull(types.StringType)
		}

		if includeTags {
			if len(cr.Filters.Tags) > 0 {
				tagsList, listDiags := types.ListValueFrom(ctx, types.StringType, cr.Filters.Tags)
				diags.Append(listDiags...)
				if diags.HasError() {
					return diags
				}
				filterValues["tags"] = tagsList
			} else {
				filterValues["tags"] = types.ListNull(types.StringType)
			}
		}

		filtersObjVal, objDiags := types.ObjectValue(cloudResourceFiltersModel{}.AttributeTypes(includeTags), filterValues)
		diags.Append(objDiags...)
		if diags.HasError() {
			return diags
		}
		c.Filters = filtersObjVal
	} else {
		c.Filters = types.ObjectNull(cloudResourceFiltersModel{}.AttributeTypes(includeTags))
	}

	return diags
}

// imageSelectorModel represents an image selector.
type imageSelectorModel struct {
	Registry     types.String `tfsdk:"registry"`
	Repositories types.List   `tfsdk:"repositories"`
	Tags         types.List   `tfsdk:"tags"`
}

// Expand converts the Terraform model to an API image selector.
func (i imageSelectorModel) Expand(ctx context.Context) (*models.AssetgroupmanagerV1ImageSelector, diag.Diagnostics) {
	var diags diag.Diagnostics

	apiSelector := &models.AssetgroupmanagerV1ImageSelector{
		Registry: i.Registry.ValueStringPointer(),
	}

	if !i.Repositories.IsNull() || !i.Tags.IsNull() {
		filters := &models.AssetgroupmanagerV1ImageFilters{}

		if !i.Repositories.IsNull() {
			repos := utils.ListTypeAs[string](ctx, i.Repositories, &diags)
			if diags.HasError() {
				return nil, diags
			}
			filters.Repository = repos
		}

		if !i.Tags.IsNull() {
			tags := utils.ListTypeAs[string](ctx, i.Tags, &diags)
			if diags.HasError() {
				return nil, diags
			}
			filters.Tag = tags
		}

		apiSelector.Filters = filters
	}

	return apiSelector, diags
}

// Flatten converts an API image selector to the Terraform model.
func (s *imageSelectorModel) Flatten(ctx context.Context, img *models.AssetgroupmanagerV1ImageSelector) diag.Diagnostics {
	var diags diag.Diagnostics

	if img == nil {
		return diags
	}

	s.Registry = types.StringPointerValue(img.Registry)

	if img.Filters != nil {
		repoList, listDiags := fwtypes.OptionalStringList(ctx, img.Filters.Repository)
		diags.Append(listDiags...)
		if diags.HasError() {
			return diags
		}
		s.Repositories = repoList

		tagList, listDiags := fwtypes.OptionalStringList(ctx, img.Filters.Tag)
		diags.Append(listDiags...)
		if diags.HasError() {
			return diags
		}
		s.Tags = tagList
	} else {
		s.Repositories = types.ListNull(types.StringType)
		s.Tags = types.ListNull(types.StringType)
	}

	return diags
}

// cloudGroupResourceModel describes the resource data model.
type cloudGroupResourceModel struct {
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
	CreatedAt      types.String `tfsdk:"created_at"`
	LastUpdated    types.String `tfsdk:"last_updated"`
	CreatedBy      types.String `tfsdk:"created_by"`
}

// ToCreateRequest converts the model to an API create request.
func (m cloudGroupResourceModel) ToCreateRequest(
	ctx context.Context,
) (*models.AssetgroupmanagerV1CreateCloudGroupRequest, diag.Diagnostics) {
	var diags diag.Diagnostics

	request := &models.AssetgroupmanagerV1CreateCloudGroupRequest{
		Name:           m.Name.ValueStringPointer(),
		Description:    m.Description.ValueStringPointer(),
		BusinessImpact: m.BusinessImpact.ValueStringPointer(),
		BusinessUnit:   m.BusinessUnit.ValueStringPointer(),
		Environment:    m.Environment.ValueStringPointer(),
	}

	if !m.Owners.IsNull() {
		var owners []string
		diags.Append(m.Owners.ElementsAs(ctx, &owners, false)...)
		if diags.HasError() {
			return nil, diags
		}
		request.Owners = owners
	}

	selectors, selectorDiags := m.convertSelectorsToAPI(ctx)
	diags.Append(selectorDiags...)
	if selectors != nil {
		request.Selectors = selectors
	}

	return request, diags
}

// ToUpdateRequest converts the model to an API update request.
func (m cloudGroupResourceModel) ToUpdateRequest(
	ctx context.Context,
	id string,
) (*models.AssetgroupmanagerV1UpdateCloudGroupMessage, diag.Diagnostics) {
	var diags diag.Diagnostics

	request := &models.AssetgroupmanagerV1UpdateCloudGroupMessage{
		ID:             id,
		Name:           m.Name.ValueString(),
		Description:    utils.Addr(m.Description.ValueString()),
		BusinessImpact: utils.Addr(m.BusinessImpact.ValueString()),
		BusinessUnit:   utils.Addr(m.BusinessUnit.ValueString()),
		Environment:    utils.Addr(m.Environment.ValueString()),
	}

	if !m.Owners.IsNull() {
		var owners []string
		diags.Append(m.Owners.ElementsAs(ctx, &owners, false)...)
		if diags.HasError() {
			return nil, diags
		}
		request.Owners = owners
	}

	selectors, selectorDiags := m.convertSelectorsToAPI(ctx)
	diags.Append(selectorDiags...)
	if selectors != nil {
		request.Selectors = selectors
	}

	return request, diags
}

// convertSelectorsToAPI converts the model's selectors to API format.
func (m cloudGroupResourceModel) convertSelectorsToAPI(
	ctx context.Context,
) (*models.AssetgroupmanagerV1WriteCloudGroupSelectors, diag.Diagnostics) {
	var diags diag.Diagnostics
	apiSelectors := &models.AssetgroupmanagerV1WriteCloudGroupSelectors{}

	convertCloudProvider := func(providerObj types.Object, providerName string) (*models.AssetgroupmanagerV1CloudResourceSelector, diag.Diagnostics) {
		var diags diag.Diagnostics
		if !utils.IsKnown(providerObj) {
			return nil, diags
		}

		var config cloudProviderConfigModel
		diags.Append(providerObj.As(ctx, &config, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return nil, diags
		}

		includeTags := providerName != "gcp"
		return config.Expand(ctx, providerName, includeTags)
	}

	awsSelector, awsDiags := convertCloudProvider(m.AWS, "aws")
	diags.Append(awsDiags...)
	if awsSelector != nil {
		apiSelectors.CloudResources = append(apiSelectors.CloudResources, awsSelector)
	}

	azureSelector, azureDiags := convertCloudProvider(m.Azure, "azure")
	diags.Append(azureDiags...)
	if azureSelector != nil {
		apiSelectors.CloudResources = append(apiSelectors.CloudResources, azureSelector)
	}

	gcpSelector, gcpDiags := convertCloudProvider(m.GCP, "gcp")
	diags.Append(gcpDiags...)
	if gcpSelector != nil {
		apiSelectors.CloudResources = append(apiSelectors.CloudResources, gcpSelector)
	}

	if utils.IsKnown(m.Images) {
		var images []imageSelectorModel
		diags.Append(m.Images.ElementsAs(ctx, &images, false)...)
		if diags.HasError() {
			return nil, diags
		}

		for _, img := range images {
			apiSelector, expandDiags := img.Expand(ctx)
			diags.Append(expandDiags...)
			if diags.HasError() {
				return nil, diags
			}
			apiSelectors.Images = append(apiSelectors.Images, apiSelector)
		}
	}

	return apiSelectors, diags
}

// Metadata returns the resource type name.
func (r *cloudGroupResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_group"
}

// Schema defines the schema for the resource.
func (r *cloudGroupResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Falcon Cloud Security",
			"This resource manages CrowdStrike Cloud Groups for organizing cloud resources and container images.",
			[]scopes.Scope{
				{
					Name:  "Cloud Groups V2",
					Read:  true,
					Write: true,
				},
			},
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the cloud group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the cloud group.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 100),
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "The description of the cloud group.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 1000),
					fwvalidators.StringNotWhitespace(),
				},
			},
			"business_impact": schema.StringAttribute{
				Optional:    true,
				Description: "An impact level that reflects how critical the cloud group's assets are to business operations. Valid values: high, moderate, low.",
				Validators: []validator.String{
					stringvalidator.OneOf("high", "moderate", "low"),
				},
			},
			"business_unit": schema.StringAttribute{
				Optional:    true,
				Description: "A free-text label used to associate the cloud group with an internal team.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 100),
					fwvalidators.StringNotWhitespace(),
				},
			},
			"environment": schema.StringAttribute{
				Optional:    true,
				Description: "Environment designation for the group. Valid values: dev, test, stage, prod.",
				Validators: []validator.String{
					stringvalidator.OneOf("dev", "test", "stage", "prod"),
				},
			},
			"owners": schema.ListAttribute{
				Optional:    true,
				Description: "Contact information for stakeholders responsible for the cloud group. List of email addresses.",
				ElementType: types.StringType,
				Validators: []validator.List{
					listvalidator.UniqueValues(),
					listvalidator.NoNullValues(),
					listvalidator.ValueStringsAre(
						fwvalidators.StringIsEmailAddress(),
					),
				},
			},
			"aws": schema.SingleNestedAttribute{
				Description: "AWS cloud resource configuration",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"account_ids": schema.ListAttribute{
						Description: "The cloud account identifiers (AWS account IDs) to include in the group. This field limits access to cloud resources in the specified accounts. When not provided, resources across all accounts in the cloud provider are accessible to the group.",
						Optional:    true,
						ElementType: types.StringType,
						Validators: []validator.List{
							listvalidator.SizeAtLeast(1),
							listvalidator.NoNullValues(),
							listvalidator.UniqueValues(),
							listvalidator.ValueStringsAre(
								fwvalidators.StringNotWhitespace(),
							),
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
								Validators: []validator.List{
									listvalidator.SizeAtLeast(1),
									listvalidator.UniqueValues(),
									listvalidator.NoNullValues(),
									listvalidator.ValueStringsAre(
										fwvalidators.StringNotWhitespace(),
									),
								},
							},
							"tags": schema.ListAttribute{
								Description: "List of tags to filter by (format: key=value)",
								Optional:    true,
								ElementType: types.StringType,
								Validators: []validator.List{
									listvalidator.SizeAtLeast(1),
									listvalidator.UniqueValues(),
									listvalidator.NoNullValues(),
									listvalidator.ValueStringsAre(
										fwvalidators.StringNotWhitespace(),
									),
								},
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
						Description: "The cloud account identifiers (Azure subscription IDs) to include in the group. This field limits access to cloud resources in the specified accounts. When not provided, resources across all accounts in the cloud provider are accessible to the group.",
						Optional:    true,
						ElementType: types.StringType,
						Validators: []validator.List{
							listvalidator.SizeAtLeast(1),
							listvalidator.UniqueValues(),
							listvalidator.NoNullValues(),
							listvalidator.ValueStringsAre(
								fwvalidators.StringNotWhitespace(),
							),
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
								Validators: []validator.List{
									listvalidator.SizeAtLeast(1),
									listvalidator.UniqueValues(),
									listvalidator.NoNullValues(),
									listvalidator.ValueStringsAre(
										fwvalidators.StringNotWhitespace(),
									),
								},
							},
							"tags": schema.ListAttribute{
								Description: "List of tags to filter by (format: key=value)",
								Optional:    true,
								ElementType: types.StringType,
								Validators: []validator.List{
									listvalidator.SizeAtLeast(1),
									listvalidator.UniqueValues(),
									listvalidator.NoNullValues(),
									listvalidator.ValueStringsAre(
										fwvalidators.StringNotWhitespace(),
									),
								},
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
						Description: "The cloud account identifiers (GCP project IDs) to include in the group. This field limits access to cloud resources in the specified accounts. When not provided, resources across all accounts in the cloud provider are accessible to the group.",
						Optional:    true,
						ElementType: types.StringType,
						Validators: []validator.List{
							listvalidator.SizeAtLeast(1),
							listvalidator.UniqueValues(),
							listvalidator.NoNullValues(),
							listvalidator.ValueStringsAre(
								fwvalidators.StringNotWhitespace(),
							),
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
								Validators: []validator.List{
									listvalidator.SizeAtLeast(1),
									listvalidator.UniqueValues(),
									listvalidator.NoNullValues(),
									listvalidator.ValueStringsAre(
										fwvalidators.StringNotWhitespace(),
									),
								},
							},
						},
					},
				},
			},
			"images": schema.ListNestedAttribute{
				Description: "The container images accessible to the group. Each entry includes a registry and filters for repositories and tags.",
				Optional:    true,
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.NoNullValues(),
					fwvalidators.ListObjectUniqueString("registry"),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"registry": schema.StringAttribute{
							Description: "The container registry to include in the group. Must be a complete HTTPS URL for a supported registry. For info about supported registries and URL format, see https://docs.crowdstrike.com/r/ved836f1",
							Required:    true,
							Validators: []validator.String{
								fwvalidators.StringNotWhitespace(),
							},
						},
						"repositories": schema.ListAttribute{
							Description: "The container image repositories within the specified registry to filter by. When specified, only images within these repositories are accessible to the group. When omitted, all repositories in the registry are included.",
							Optional:    true,
							ElementType: types.StringType,
							Validators: []validator.List{
								listvalidator.SizeAtLeast(1),
								listvalidator.UniqueValues(),
								listvalidator.NoNullValues(),
								listvalidator.ValueStringsAre(
									fwvalidators.StringNotWhitespace(),
								),
							},
						},
						"tags": schema.ListAttribute{
							Description: "The container image tags to filter by. Tag matching is scoped to the specified repositories values, or across all repositories in the given registry if repositories are not provided.",
							Optional:    true,
							ElementType: types.StringType,
							Validators: []validator.List{
								listvalidator.SizeAtLeast(1),
								listvalidator.UniqueValues(),
								listvalidator.NoNullValues(),
								listvalidator.ValueStringsAre(
									fwvalidators.StringNotWhitespace(),
								),
							},
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
			"last_updated": schema.StringAttribute{
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
func (r *cloudGroupResource) Configure(
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
func (r *cloudGroupResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudGroupResourceModel
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

	tflog.Info(ctx, "Creating cloud group", map[string]interface{}{"name": plan.Name.ValueString()})

	res, err := r.client.CloudSecurity.CreateCloudGroupExternal(
		&cloud_security.CreateCloudGroupExternalParams{
			Context: ctx,
			Body:    createRequest,
		},
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to create cloud group",
			fmt.Sprintf("Failed to create cloud group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if res == nil || res.Payload == nil || res.Payload.Resources == nil || len(res.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Failed to create cloud group",
			"No data returned from API",
		)
		return
	}

	groupID := res.Payload.Resources[0]
	getRes, err := r.client.CloudSecurity.ListCloudGroupsByIDExternal(
		&cloud_security.ListCloudGroupsByIDExternalParams{
			Context: ctx,
			Ids:     []string{groupID},
		},
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read created cloud group",
			fmt.Sprintf("Failed to read created cloud group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if getRes == nil || getRes.Payload == nil || getRes.Payload.Resources == nil || len(getRes.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Failed to read created cloud group",
			"No data returned from API after creation",
		)
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, getRes.Payload.Resources[0])...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cloudGroupResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudGroupResourceModel
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
		resp.State.RemoveResource(ctx)
		return
	}

	tflog.Info(ctx, "Reading cloud group", map[string]interface{}{"id": state.ID.ValueString()})

	res, err := r.client.CloudSecurity.ListCloudGroupsByIDExternal(
		&cloud_security.ListCloudGroupsByIDExternalParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			tflog.Warn(ctx, "cloud group not found, removing from state", map[string]interface{}{"id": state.ID.ValueString()})
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Failed to read cloud group",
			fmt.Sprintf("Failed to read cloud group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if res == nil || res.Payload == nil || res.Payload.Resources == nil || len(res.Payload.Resources) == 0 {
		tflog.Warn(ctx, "cloud group not found, removing from state", map[string]interface{}{"id": state.ID.ValueString()})
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
func (r *cloudGroupResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudGroupResourceModel
	var state cloudGroupResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateRequest, diags := plan.ToUpdateRequest(ctx, state.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Updating cloud group", map[string]interface{}{
		"id":   state.ID.ValueString(),
		"name": plan.Name.ValueString(),
	})

	res, err := r.client.CloudSecurity.UpdateCloudGroupExternal(
		&cloud_security.UpdateCloudGroupExternalParams{
			Context: ctx,
			Group:   updateRequest,
		},
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to update cloud group",
			fmt.Sprintf("Failed to update cloud group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if res == nil || res.Payload == nil || res.Payload.Resources == nil || len(res.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Failed to update cloud group",
			"No data returned from API",
		)
		return
	}

	getRes, err := r.client.CloudSecurity.ListCloudGroupsByIDExternal(
		&cloud_security.ListCloudGroupsByIDExternalParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read updated cloud group",
			fmt.Sprintf("Failed to read updated cloud group: %s", err.Error()),
		)
		return
	}

	if getRes == nil || getRes.Payload == nil || getRes.Payload.Resources == nil || len(getRes.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Failed to read updated cloud group",
			"No data returned from API after update",
		)
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, getRes.Payload.Resources[0])...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *cloudGroupResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudGroupResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.ID.ValueString() == "" {
		return
	}

	tflog.Info(ctx, "Deleting cloud group", map[string]interface{}{"id": state.ID.ValueString()})

	_, err := r.client.CloudSecurity.DeleteCloudGroupsExternal(
		&cloud_security.DeleteCloudGroupsExternalParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)
	if err != nil {
		if !strings.Contains(err.Error(), "404") {
			resp.Diagnostics.AddError(
				"Failed to delete cloud group",
				fmt.Sprintf("Failed to delete cloud group: %s", falcon.ErrorExplain(err)),
			)
			return
		}
	}
}

// ImportState implements the logic to support resource imports.
func (r *cloudGroupResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// wrap converts API response to Terraform state model.
func (m *cloudGroupResourceModel) wrap(
	ctx context.Context,
	apiGroup *models.AssetgroupmanagerV1CloudGroup,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if apiGroup == nil {
		return diags
	}

	m.ID = fwtypes.OptionalString(apiGroup.ID)
	m.Name = fwtypes.OptionalString(apiGroup.Name)
	m.Description = fwtypes.OptionalString(apiGroup.Description)
	m.BusinessImpact = fwtypes.OptionalString(apiGroup.BusinessImpact)
	m.BusinessUnit = fwtypes.OptionalString(apiGroup.BusinessUnit)
	m.Environment = fwtypes.OptionalString(apiGroup.Environment)
	m.CreatedBy = fwtypes.OptionalString(apiGroup.CreatedBy)

	if !apiGroup.CreatedAt.IsZero() {
		m.CreatedAt = types.StringValue(apiGroup.CreatedAt.String())
	} else if m.CreatedAt.IsUnknown() {
		m.CreatedAt = types.StringNull()
	}

	if len(apiGroup.Owners) > 0 {
		ownersList, listDiags := types.ListValueFrom(ctx, types.StringType, apiGroup.Owners)
		diags.Append(listDiags...)
		m.Owners = ownersList
	} else {
		m.Owners = types.ListNull(types.StringType)
	}

	if apiGroup.Selectors != nil {
		m.AWS = types.ObjectNull(cloudProviderConfigModel{}.AttributeTypes(true))
		m.Azure = types.ObjectNull(cloudProviderConfigModel{}.AttributeTypes(true))
		m.GCP = types.ObjectNull(cloudProviderConfigModel{}.AttributeTypes(false))

		for _, cr := range apiGroup.Selectors.CloudResources {
			if cr.CloudProvider == nil {
				continue
			}

			switch *cr.CloudProvider {
			case "aws":
				var config cloudProviderConfigModel
				diags.Append(config.Flatten(ctx, cr, true)...)
				if diags.HasError() {
					return diags
				}
				awsObjVal, objDiags := types.ObjectValueFrom(ctx, cloudProviderConfigModel{}.AttributeTypes(true), config)
				diags.Append(objDiags...)
				if diags.HasError() {
					return diags
				}
				m.AWS = awsObjVal

			case "azure":
				var config cloudProviderConfigModel
				diags.Append(config.Flatten(ctx, cr, true)...)
				if diags.HasError() {
					return diags
				}
				azureObjVal, objDiags := types.ObjectValueFrom(ctx, cloudProviderConfigModel{}.AttributeTypes(true), config)
				diags.Append(objDiags...)
				if diags.HasError() {
					return diags
				}
				m.Azure = azureObjVal

			case "gcp":
				var config cloudProviderConfigModel
				diags.Append(config.Flatten(ctx, cr, false)...)
				if diags.HasError() {
					return diags
				}
				gcpObjVal, objDiags := types.ObjectValueFrom(ctx, cloudProviderConfigModel{}.AttributeTypes(false), config)
				diags.Append(objDiags...)
				if diags.HasError() {
					return diags
				}
				m.GCP = gcpObjVal
			}
		}

		if len(apiGroup.Selectors.Images) > 0 {
			var images []imageSelectorModel
			for _, img := range apiGroup.Selectors.Images {
				if img == nil {
					continue
				}
				var flatImg imageSelectorModel
				diags.Append(flatImg.Flatten(ctx, img)...)
				if diags.HasError() {
					return diags
				}
				images = append(images, flatImg)
			}

			imagesListVal, listDiags := types.ListValueFrom(ctx, types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"registry":     types.StringType,
					"repositories": types.ListType{ElemType: types.StringType},
					"tags":         types.ListType{ElemType: types.StringType},
				},
			}, images)
			diags.Append(listDiags...)
			m.Images = imagesListVal
		} else {
			m.Images = types.ListNull(types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"registry":     types.StringType,
					"repositories": types.ListType{ElemType: types.StringType},
					"tags":         types.ListType{ElemType: types.StringType},
				},
			})
		}
	} else {
		m.AWS = types.ObjectNull(cloudProviderConfigModel{}.AttributeTypes(true))
		m.Azure = types.ObjectNull(cloudProviderConfigModel{}.AttributeTypes(true))
		m.GCP = types.ObjectNull(cloudProviderConfigModel{}.AttributeTypes(false))
		m.Images = types.ListNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"registry":     types.StringType,
				"repositories": types.ListType{ElemType: types.StringType},
				"tags":         types.ListType{ElemType: types.StringType},
			},
		})
	}

	return diags
}
