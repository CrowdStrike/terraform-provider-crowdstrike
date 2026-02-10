package cloudgoogleregistration

import (
	"context"
	"fmt"
	"regexp"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_google_cloud_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                     = &cloudGoogleRegistrationResource{}
	_ resource.ResourceWithConfigure        = &cloudGoogleRegistrationResource{}
	_ resource.ResourceWithImportState      = &cloudGoogleRegistrationResource{}
	_ resource.ResourceWithConfigValidators = &cloudGoogleRegistrationResource{}
	_ resource.ResourceWithValidateConfig   = &cloudGoogleRegistrationResource{}
	_ resource.ResourceWithModifyPlan       = &cloudGoogleRegistrationResource{}
)

var gcpRegistrationScopes = []scopes.Scope{
	{
		Name:  "Cloud Security Google Cloud Registration",
		Read:  true,
		Write: true,
	},
}

const maxResourceNameCombinedLength = 13

func NewCloudGoogleRegistrationResource() resource.Resource {
	return &cloudGoogleRegistrationResource{}
}

type cloudGoogleRegistrationResource struct {
	client   *client.CrowdStrikeAPISpecification
	clientId string
}

type realtimeVisibilityModel struct {
	Enabled types.Bool `tfsdk:"enabled"`
}

func (r *realtimeVisibilityModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"enabled": types.BoolType,
	}
}

func (r *realtimeVisibilityModel) ToObject(ctx context.Context) (types.Object, diag.Diagnostics) {
	return types.ObjectValueFrom(ctx, r.AttributeTypes(), r)
}

func (r *realtimeVisibilityModel) FromObject(ctx context.Context, obj types.Object) diag.Diagnostics {
	return obj.As(ctx, r, basetypes.ObjectAsOptions{})
}

type cloudGoogleRegistrationResourceModel struct {
	ID                          types.String `tfsdk:"id"`
	Name                        types.String `tfsdk:"name"`
	RegistrationScope           types.String `tfsdk:"registration_scope"`
	Organization                types.String `tfsdk:"organization"`
	Folders                     types.Set    `tfsdk:"folders"`
	Projects                    types.Set    `tfsdk:"projects"`
	DeploymentMethod            types.String `tfsdk:"deployment_method"`
	InfrastructureManagerRegion types.String `tfsdk:"infrastructure_manager_region"`
	InfraProjectID              types.String `tfsdk:"infra_project"`
	WifProjectID                types.String `tfsdk:"wif_project"`
	ExcludedProjectPatterns     types.List   `tfsdk:"excluded_project_patterns"`
	ResourceNamePrefix          types.String `tfsdk:"resource_name_prefix"`
	ResourceNameSuffix          types.String `tfsdk:"resource_name_suffix"`
	Labels                      types.Map    `tfsdk:"labels"`
	Tags                        types.Map    `tfsdk:"tags"`
	RealtimeVisibility          types.Object `tfsdk:"realtime_visibility"`
	Status                      types.String `tfsdk:"status"`
	WifPoolID                   types.String `tfsdk:"wif_pool_id"`
	WifPoolName                 types.String `tfsdk:"wif_pool_name"`
	WifProjectNumber            types.String `tfsdk:"wif_project_number"`
	WifProviderID               types.String `tfsdk:"wif_provider_id"`
	WifProviderName             types.String `tfsdk:"wif_provider_name"`
}

func (m *cloudGoogleRegistrationResourceModel) getEntityIDs(ctx context.Context) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var entityIDs []string

	switch {
	case !m.Organization.IsNull():
		entityIDs = []string{m.Organization.ValueString()}
	case !m.Folders.IsNull():
		diags.Append(m.Folders.ElementsAs(ctx, &entityIDs, false)...)
	case !m.Projects.IsNull():
		diags.Append(m.Projects.ElementsAs(ctx, &entityIDs, false)...)
	}

	return entityIDs, diags
}

func (m *cloudGoogleRegistrationResourceModel) getRegistrationScope() string {
	switch {
	case !m.Organization.IsNull():
		return "organization"
	case !m.Folders.IsNull():
		return "folder"
	case !m.Projects.IsNull():
		return "project"
	}
	return ""
}

func (m *cloudGoogleRegistrationResourceModel) wrap(
	ctx context.Context,
	registration *models.DtoGCPRegistration,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringValue(registration.RegistrationID)
	m.Name = types.StringValue(registration.RegistrationName)
	m.RegistrationScope = types.StringValue(registration.RegistrationScope)
	m.DeploymentMethod = types.StringValue(registration.DeploymentMethod)
	m.InfraProjectID = types.StringValue(registration.InfraProjectID)
	m.Status = types.StringValue(registration.Status)

	var infraManagerRegion string
	if registration.InfraManagerProperties != nil {
		infraManagerRegion = registration.InfraManagerProperties.Region
	}
	m.InfrastructureManagerRegion = flex.StringValueToFramework(infraManagerRegion)

	switch registration.RegistrationScope {
	case "organization":
		if registration.Organization != nil {
			m.Organization = types.StringValue(registration.Organization.OrganizationID)
		}
	case "folder":
		folderIDs := make([]string, len(registration.Folders))
		for i, folder := range registration.Folders {
			folderIDs[i] = folder.FolderID
		}
		if len(folderIDs) > 0 {
			folderIDSet, d := types.SetValueFrom(ctx, types.StringType, folderIDs)
			diags.Append(d...)
			m.Folders = folderIDSet
		}
	case "project":
		projectIDs := make([]string, len(registration.Projects))
		for i, proj := range registration.Projects {
			projectIDs[i] = proj.ProjectID
		}
		if len(projectIDs) > 0 {
			projectIDSet, d := types.SetValueFrom(ctx, types.StringType, projectIDs)
			diags.Append(d...)
			m.Projects = projectIDSet
		}
	}

	if registration.ResourceNamePrefix != "" {
		m.ResourceNamePrefix = types.StringValue(registration.ResourceNamePrefix)
	}
	if registration.ResourceNameSuffix != "" {
		m.ResourceNameSuffix = types.StringValue(registration.ResourceNameSuffix)
	}

	if len(registration.ExcludedProjectPatterns) > 0 {
		patterns := make([]attr.Value, len(registration.ExcludedProjectPatterns))
		for i, pattern := range registration.ExcludedProjectPatterns {
			patterns[i] = types.StringValue(pattern)
		}
		list, d := types.ListValue(types.StringType, patterns)
		diags.Append(d...)
		m.ExcludedProjectPatterns = list
	}

	if len(registration.Labels) > 0 {
		labels, d := types.MapValueFrom(ctx, types.StringType, registration.Labels)
		diags.Append(d...)
		m.Labels = labels
	}

	if len(registration.Tags) > 0 {
		tags, d := types.MapValueFrom(ctx, types.StringType, registration.Tags)
		diags.Append(d...)
		m.Tags = tags
	}

	var wifProjectID, wifPoolID, wifPoolName, wifProjectNumber, wifProviderID, wifProviderName string
	if registration.WifProperties != nil {
		wifProjectID = registration.WifProperties.ProjectID
		wifPoolID = registration.WifProperties.PoolID
		wifPoolName = registration.WifProperties.PoolName
		wifProjectNumber = registration.WifProperties.ProjectNumber
		wifProviderID = registration.WifProperties.ProviderID
		wifProviderName = registration.WifProperties.ProviderName
	}
	m.WifProjectID = flex.StringValueToFramework(wifProjectID)
	m.WifPoolID = flex.StringValueToFramework(wifPoolID)
	m.WifPoolName = flex.StringValueToFramework(wifPoolName)
	m.WifProjectNumber = flex.StringValueToFramework(wifProjectNumber)
	m.WifProviderID = flex.StringValueToFramework(wifProviderID)
	m.WifProviderName = flex.StringValueToFramework(wifProviderName)

	hasIOA := false
	for _, product := range registration.Products {
		if product.Product != nil && *product.Product == "cspm" {
			for _, feature := range product.Features {
				if feature == "ioa" {
					hasIOA = true
					break
				}
			}
			break
		}
	}

	switch {
	case hasIOA:
		rtvModel := realtimeVisibilityModel{Enabled: types.BoolValue(true)}
		rtvObj, d := rtvModel.ToObject(ctx)
		diags.Append(d...)
		m.RealtimeVisibility = rtvObj
	case !m.RealtimeVisibility.IsNull():
		rtvModel := realtimeVisibilityModel{Enabled: types.BoolValue(false)}
		rtvObj, d := rtvModel.ToObject(ctx)
		diags.Append(d...)
		m.RealtimeVisibility = rtvObj
	default:
		m.RealtimeVisibility = types.ObjectNull((&realtimeVisibilityModel{}).AttributeTypes())
	}

	return diags
}

func (r *cloudGoogleRegistrationResource) Configure(
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
	r.clientId = config.ClientId
}

func (r *cloudGoogleRegistrationResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_google_registration"
}

func (r *cloudGoogleRegistrationResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Falcon Cloud Security",
			"This resource registers a Google Cloud project, folder, or organization in Falcon Cloud Security.",
			gcpRegistrationScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The registration ID",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the registration",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"registration_scope": schema.StringAttribute{
				Computed:            true,
				Description:         "The scope of the registration. One of: organization, folder, project",
				MarkdownDescription: "The scope of the registration. One of: `organization`, `folder`, `project`",
			},
			"organization": schema.StringAttribute{
				Optional:            true,
				Description:         "Google Cloud organization ID to register. Must be numeric. Mutually exclusive with folders and projects",
				MarkdownDescription: "Google Cloud organization ID to register. Must be numeric. Mutually exclusive with `folders` and `projects`",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[0-9]+$`),
						"must be numeric",
					),
				},
			},
			"folders": schema.SetAttribute{
				Optional:            true,
				Description:         "Google Cloud folder IDs to register. Each must be numeric. Mutually exclusive with organization and projects",
				MarkdownDescription: "Google Cloud folder IDs to register. Each must be numeric. Mutually exclusive with `organization` and `projects`",
				ElementType:         types.StringType,
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(
						validators.StringNotWhitespace(),
						stringvalidator.RegexMatches(
							regexp.MustCompile(`^[0-9]+$`),
							"must be numeric",
						),
					),
				},
			},
			"projects": schema.SetAttribute{
				Optional:            true,
				Description:         "Google Cloud project IDs to register. Each must be 6-30 characters, start with a lowercase letter, and contain only lowercase letters, numbers, and hyphens. Mutually exclusive with organization and folders",
				MarkdownDescription: "Google Cloud project IDs to register. Each must be 6-30 characters, start with a lowercase letter, and contain only lowercase letters, numbers, and hyphens. Mutually exclusive with `organization` and `folders`",
				ElementType:         types.StringType,
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(
						validators.StringNotWhitespace(),
						stringvalidator.LengthBetween(6, 30),
						stringvalidator.RegexMatches(
							regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$`),
							"must be 6-30 characters, start with a lowercase letter, and contain only lowercase letters, numbers, and hyphens",
						),
					),
				},
			},
			"deployment_method": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("terraform-native"),
				Description: "The deployment method for the registration. Can be either terraform-native or infrastructure-manager. Defaults to terraform-native",
				Validators: []validator.String{
					stringvalidator.OneOf("terraform-native", "infrastructure-manager"),
				},
			},
			"infrastructure_manager_region": schema.StringAttribute{
				Optional:    true,
				Description: "The Google Cloud region for Infrastructure Manager. Required when deployment_method is infrastructure-manager",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"infra_project": schema.StringAttribute{
				Required:    true,
				Description: "The Google Cloud project ID where CrowdStrike infrastructure resources will be created",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
					stringvalidator.LengthBetween(6, 30),
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$`),
						"must be 6-30 characters, start with a lowercase letter, and contain only lowercase letters, numbers, and hyphens",
					),
				},
			},
			"wif_project": schema.StringAttribute{
				Required:    true,
				Description: "The Google Cloud project ID for Workload Identity Federation",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
					stringvalidator.LengthBetween(6, 30),
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$`),
						"must be 6-30 characters, start with a lowercase letter, and contain only lowercase letters, numbers, and hyphens",
					),
				},
			},
			"wif_project_number": schema.StringAttribute{
				Required:    true,
				Description: "Google Cloud project number for Workload Identity Federation",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[0-9]+$`),
						"must be numeric",
					),
				},
			},

			"excluded_project_patterns": schema.ListAttribute{
				Optional:    true,
				Description: "Regex patterns to exclude specific projects from registration. Each pattern must start with 'sys-' (case insensitive)",
				ElementType: types.StringType,
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						validators.StringNotWhitespace(),
						stringvalidator.RegexMatches(
							regexp.MustCompile(`^(?i)sys-`),
							"must start with 'sys-' (case insensitive)",
						),
					),
				},
			},
			"resource_name_prefix": schema.StringAttribute{
				Optional:    true,
				Description: fmt.Sprintf("Prefix to add to created Google Cloud resource names. The combined length of prefix and suffix must not exceed %d characters", maxResourceNameCombinedLength),
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"resource_name_suffix": schema.StringAttribute{
				Optional:    true,
				Description: fmt.Sprintf("Suffix to add to created Google Cloud resource names. The combined length of prefix and suffix must not exceed %d characters", maxResourceNameCombinedLength),
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"labels": schema.MapAttribute{
				Optional:    true,
				Description: "Google Cloud labels to apply to created resources",
				ElementType: types.StringType,
				Validators: []validator.Map{
					mapvalidator.KeysAre(validators.StringNotWhitespace()),
					mapvalidator.ValueStringsAre(validators.StringNotWhitespace()),
				},
			},
			"tags": schema.MapAttribute{
				Optional:    true,
				Description: "Google Cloud tags to apply to created resources",
				ElementType: types.StringType,
				Validators: []validator.Map{
					mapvalidator.KeysAre(validators.StringNotWhitespace()),
					mapvalidator.ValueStringsAre(validators.StringNotWhitespace()),
				},
			},
			"realtime_visibility": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:    true,
						Description: "Enable real-time visibility and detection",
					},
				},
			},
			"status": schema.StringAttribute{
				Computed:            true,
				Description:         "The current status of the registration. Possible values: partial (registration is in setup incomplete status), complete (registration was setup successfully and validation succeeded), validation_failed (registration was setup successfully, but validation failed)",
				MarkdownDescription: "The current status of the registration. Possible values: `partial` (registration is in setup incomplete status), `complete` (registration was setup successfully and validation succeeded), `validation_failed` (registration was setup successfully, but validation failed)",
			},
			"wif_pool_id": schema.StringAttribute{
				Computed:    true,
				Description: "Workload Identity Federation pool ID",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"wif_pool_name": schema.StringAttribute{
				Computed:    true,
				Description: "Workload Identity Federation pool name",
			},
			"wif_provider_id": schema.StringAttribute{
				Computed:    true,
				Description: "Workload Identity Federation provider ID",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"wif_provider_name": schema.StringAttribute{
				Computed:    true,
				Description: "Workload Identity Federation provider name",
			},
		},
	}
}

func (r *cloudGoogleRegistrationResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.ExactlyOneOf(
			path.MatchRoot("organization"),
			path.MatchRoot("folders"),
			path.MatchRoot("projects"),
		),
	}
}

func (r *cloudGoogleRegistrationResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config cloudGoogleRegistrationResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if utils.IsKnown(config.ResourceNamePrefix) && utils.IsKnown(config.ResourceNameSuffix) {
		prefixLen := len(config.ResourceNamePrefix.ValueString())
		suffixLen := len(config.ResourceNameSuffix.ValueString())
		totalLen := prefixLen + suffixLen

		if totalLen > maxResourceNameCombinedLength {
			resp.Diagnostics.AddError(
				"Invalid resource name prefix and suffix combination",
				fmt.Sprintf(
					"The combined length of resource_name_prefix (%d characters) and resource_name_suffix (%d characters) should not exceed %d characters, currently %d characters",
					prefixLen,
					suffixLen,
					maxResourceNameCombinedLength,
					totalLen,
				),
			)
		}
	}

	if utils.IsKnown(config.DeploymentMethod) {
		if config.DeploymentMethod.ValueString() == "infrastructure-manager" && config.InfrastructureManagerRegion.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("infrastructure_manager_region"),
				"Missing Required Attribute",
				"infrastructure_manager_region is required when deployment_method is 'infrastructure-manager'",
			)
		}
	}
}

func (r *cloudGoogleRegistrationResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudGoogleRegistrationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	entityIDs, diags := plan.getEntityIDs(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	registrationScope := plan.getRegistrationScope()

	deploymentMethod := plan.DeploymentMethod.ValueString()
	registrationName := plan.Name.ValueString()
	infraProjectID := plan.InfraProjectID.ValueString()
	wifProjectID := plan.WifProjectID.ValueString()

	createReq := &models.DtoCreateGCPRegistrationRequest{
		DeploymentMethod:  &deploymentMethod,
		EntityID:          entityIDs,
		InfraProjectID:    &infraProjectID,
		RegistrationName:  &registrationName,
		RegistrationScope: &registrationScope,
		WifProjectID:      &wifProjectID,
	}

	if !plan.InfrastructureManagerRegion.IsNull() {
		createReq.InfraManagerRegion = plan.InfrastructureManagerRegion.ValueString()
	}

	createReq.ResourceNameSuffix = flex.FrameworkToStringPointer(plan.ResourceNameSuffix)
	createReq.ResourceNamePrefix = flex.FrameworkToStringPointer(plan.ResourceNamePrefix)

	patterns := []string{}
	if !plan.ExcludedProjectPatterns.IsNull() {
		resp.Diagnostics.Append(plan.ExcludedProjectPatterns.ElementsAs(ctx, &patterns, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	createReq.ExcludedProjectPatterns = patterns

	// todo: labels and tags currently can not be nulled out due to the api
	if !plan.Labels.IsNull() {
		var labels map[string]string
		resp.Diagnostics.Append(plan.Labels.ElementsAs(ctx, &labels, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		createReq.Labels = labels
	}

	if !plan.Tags.IsNull() {
		var tags map[string]string
		resp.Diagnostics.Append(plan.Tags.ElementsAs(ctx, &tags, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		createReq.Tags = tags
	}

	cspmProductFeatures := models.DomainProductFeatures{
		Product:  utils.Addr("cspm"),
		Features: []string{"iom"},
	}

	if !plan.RealtimeVisibility.IsNull() {
		var rtv realtimeVisibilityModel
		resp.Diagnostics.Append(rtv.FromObject(ctx, plan.RealtimeVisibility)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if rtv.Enabled.ValueBool() {
			cspmProductFeatures.Features = append(cspmProductFeatures.Features, "ioa")
		}
	}

	createReq.Products = []*models.DomainProductFeatures{
		&cspmProductFeatures,
	}

	params := &cloud_google_cloud_registration.CloudRegistrationGcpPutRegistrationParams{
		Context: ctx,
		Body: &models.DtoGCPRegistrationCreateRequestExtV1{
			Resources: []*models.DtoCreateGCPRegistrationRequest{createReq},
		},
	}

	res, err := r.client.CloudGoogleCloudRegistration.CloudRegistrationGcpPutRegistration(params)
	if err != nil {
		if _, ok := err.(*cloud_google_cloud_registration.CloudRegistrationGcpPutRegistrationForbidden); ok {
			resp.Diagnostics.Append(tferrors.NewForbiddenError(tferrors.Create, gcpRegistrationScopes))
			return
		}
		resp.Diagnostics.Append(tferrors.NewOperationError(tferrors.Create, err))
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	registration := res.Payload.Resources[0]
	plan.ID = types.StringValue(registration.RegistrationID)
	resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)

	if !plan.WifProjectNumber.IsNull() {
		updateReq := &models.DtoUpdateGCPRegistrationRequest{
			WifProjectNumber:  plan.WifProjectNumber.ValueString(),
			FalconClientKeyID: r.clientId,
		}

		patchParams := &cloud_google_cloud_registration.CloudRegistrationGcpUpdateRegistrationParams{
			Context: ctx,
			Ids:     registration.RegistrationID,
			Body: &models.DtoGCPRegistrationUpdateRequestExtV1{
				Resources: []*models.DtoUpdateGCPRegistrationRequest{updateReq},
			},
		}

		patchRes, err := r.client.CloudGoogleCloudRegistration.CloudRegistrationGcpUpdateRegistration(patchParams)
		if err != nil {
			if _, ok := err.(*cloud_google_cloud_registration.CloudRegistrationGcpUpdateRegistrationForbidden); ok {
				resp.Diagnostics.Append(tferrors.NewForbiddenError(tferrors.Create, gcpRegistrationScopes))
				return
			}
			resp.Diagnostics.Append(tferrors.NewOperationError(tferrors.Create, err))
			return
		}

		if patchRes == nil || patchRes.Payload == nil || len(patchRes.Payload.Resources) == 0 || patchRes.Payload.Resources[0] == nil {
			resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
			return
		}

		registration = patchRes.Payload.Resources[0]
	}

	resp.Diagnostics.Append(plan.wrap(ctx, registration)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Google Cloud registration created", map[string]interface{}{"registration_id": registration.RegistrationID})
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cloudGoogleRegistrationResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudGoogleRegistrationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := &cloud_google_cloud_registration.CloudRegistrationGcpGetRegistrationParams{
		Context: ctx,
		Ids:     state.ID.ValueString(),
	}

	res, err := r.client.CloudGoogleCloudRegistration.CloudRegistrationGcpGetRegistration(params)
	if err != nil {
		if _, ok := err.(*cloud_google_cloud_registration.CloudRegistrationGcpGetRegistrationNotFound); ok {
			tflog.Warn(ctx, "Google Cloud registration not found, removing from state", map[string]interface{}{"id": state.ID.ValueString()})
			resp.State.RemoveResource(ctx)
			return
		}

		if _, ok := err.(*cloud_google_cloud_registration.CloudRegistrationGcpGetRegistrationForbidden); ok {
			resp.Diagnostics.Append(tferrors.NewForbiddenError(tferrors.Read, gcpRegistrationScopes))
			return
		}
		resp.Diagnostics.Append(tferrors.NewOperationError(tferrors.Read, err))
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		tflog.Warn(ctx, "Google Cloud registration not found, removing from state", map[string]interface{}{"id": state.ID.ValueString()})
		resp.State.RemoveResource(ctx)
		return
	}

	registration := res.Payload.Resources[0]
	resp.Diagnostics.Append(state.wrap(ctx, registration)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cloudGoogleRegistrationResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudGoogleRegistrationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	entityIDs, diags := plan.getEntityIDs(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateReq := &models.DtoUpdateGCPRegistrationRequest{
		DeploymentMethod:  plan.DeploymentMethod.ValueString(),
		EntityID:          entityIDs,
		RegistrationScope: plan.getRegistrationScope(),
		RegistrationName:  plan.Name.ValueString(),
		InfraProjectID:    plan.InfraProjectID.ValueString(),
		WifProjectID:      plan.WifProjectID.ValueString(),
		WifProjectNumber:  plan.WifProjectNumber.ValueString(),
		FalconClientKeyID: r.clientId,
	}

	if !plan.InfrastructureManagerRegion.IsNull() {
		updateReq.InfraManagerRegion = plan.InfrastructureManagerRegion.ValueString()
	}

	updateReq.ResourceNameSuffix = flex.FrameworkToStringPointer(plan.ResourceNameSuffix)
	updateReq.ResourceNamePrefix = flex.FrameworkToStringPointer(plan.ResourceNamePrefix)

	if !plan.ExcludedProjectPatterns.IsNull() {
		var patterns []string
		resp.Diagnostics.Append(plan.ExcludedProjectPatterns.ElementsAs(ctx, &patterns, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		updateReq.ExcludedProjectPatterns = patterns
	}

	if !plan.Labels.IsNull() {
		var labels map[string]string
		resp.Diagnostics.Append(plan.Labels.ElementsAs(ctx, &labels, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		updateReq.Labels = labels
	}

	if !plan.Tags.IsNull() {
		var tags map[string]string
		resp.Diagnostics.Append(plan.Tags.ElementsAs(ctx, &tags, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		updateReq.Tags = tags
	}

	cspmProductFeatures := models.DomainProductFeatures{
		Product:  utils.Addr("cspm"),
		Features: []string{"iom"},
	}

	if !plan.RealtimeVisibility.IsNull() {
		var rtv realtimeVisibilityModel
		resp.Diagnostics.Append(rtv.FromObject(ctx, plan.RealtimeVisibility)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if rtv.Enabled.ValueBool() {
			cspmProductFeatures.Features = append(cspmProductFeatures.Features, "ioa")
		}
	}

	updateReq.Products = []*models.DomainProductFeatures{
		&cspmProductFeatures,
	}

	params := &cloud_google_cloud_registration.CloudRegistrationGcpUpdateRegistrationParams{
		Context: ctx,
		Ids:     plan.ID.ValueString(),
		Body: &models.DtoGCPRegistrationUpdateRequestExtV1{
			Resources: []*models.DtoUpdateGCPRegistrationRequest{updateReq},
		},
	}

	res, err := r.client.CloudGoogleCloudRegistration.CloudRegistrationGcpUpdateRegistration(params)
	if err != nil {
		if _, ok := err.(*cloud_google_cloud_registration.CloudRegistrationGcpUpdateRegistrationForbidden); ok {
			resp.Diagnostics.Append(tferrors.NewForbiddenError(tferrors.Update, gcpRegistrationScopes))
			return
		}
		resp.Diagnostics.Append(tferrors.NewOperationError(tferrors.Update, err))
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	registration := res.Payload.Resources[0]
	state := plan
	resp.Diagnostics.Append(state.wrap(ctx, registration)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *cloudGoogleRegistrationResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudGoogleRegistrationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := &cloud_google_cloud_registration.CloudRegistrationGcpDeleteRegistrationParams{
		Context: ctx,
		Ids:     state.ID.ValueString(),
	}

	_, err := r.client.CloudGoogleCloudRegistration.CloudRegistrationGcpDeleteRegistration(params)
	if err != nil {
		if _, ok := err.(*cloud_google_cloud_registration.CloudRegistrationGcpDeleteRegistrationForbidden); ok {
			resp.Diagnostics.Append(tferrors.NewForbiddenError(tferrors.Delete, gcpRegistrationScopes))
			return
		}
		resp.Diagnostics.Append(tferrors.NewOperationError(tferrors.Delete, err))
		return
	}

	tflog.Info(ctx, "Google Cloud registration deleted", map[string]interface{}{"registration_id": state.ID.ValueString()})
}

func (r *cloudGoogleRegistrationResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}

	var stateOrg, planOrg types.String
	req.State.GetAttribute(ctx, path.Root("organization"), &stateOrg)
	req.Plan.GetAttribute(ctx, path.Root("organization"), &planOrg)

	var stateFolders, planFolders types.Set
	req.State.GetAttribute(ctx, path.Root("folders"), &stateFolders)
	req.Plan.GetAttribute(ctx, path.Root("folders"), &planFolders)

	var stateProjects, planProjects types.Set
	req.State.GetAttribute(ctx, path.Root("projects"), &stateProjects)
	req.Plan.GetAttribute(ctx, path.Root("projects"), &planProjects)

	stateHasOrg := utils.IsKnown(stateOrg)
	stateHasFolders := utils.IsKnown(stateFolders)
	stateHasProjects := utils.IsKnown(stateProjects)

	planHasOrg := utils.IsKnown(planOrg)
	planHasFolders := utils.IsKnown(planFolders)
	planHasProjects := utils.IsKnown(planProjects)

	scopeChanged := false
	switch {
	case stateHasOrg && (planHasFolders || planHasProjects):
		scopeChanged = true
	case stateHasFolders && (planHasOrg || planHasProjects):
		scopeChanged = true
	case stateHasProjects && (planHasOrg || planHasFolders):
		scopeChanged = true
	}

	if scopeChanged {
		resp.RequiresReplace = append(resp.RequiresReplace, path.Root("organization"), path.Root("folders"), path.Root("projects"))
	}
}

func (r *cloudGoogleRegistrationResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
