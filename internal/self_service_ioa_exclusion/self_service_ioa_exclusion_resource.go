package selfserviceioaexclusion

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ioa_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &selfServiceIOAExclusionResource{}
	_ resource.ResourceWithConfigure   = &selfServiceIOAExclusionResource{}
	_ resource.ResourceWithImportState = &selfServiceIOAExclusionResource{}
)

var selfServiceIOAExclusionRequiredScopes = []scopes.Scope{
	{Name: "Self Service IOA Exclusions", Read: true, Write: true},
}

func NewSelfServiceIOAExclusionResource() resource.Resource {
	return &selfServiceIOAExclusionResource{}
}

type selfServiceIOAExclusionResource struct {
	client *client.CrowdStrikeAPISpecification
}

type SelfServiceIOAExclusionResourceModel struct {
	ID                  types.String      `tfsdk:"id"`
	LastUpdated         types.String      `tfsdk:"last_updated"`
	Name                types.String      `tfsdk:"name"`
	Description         types.String      `tfsdk:"description"`
	PatternID           types.String      `tfsdk:"pattern_id"`
	PatternName         types.String      `tfsdk:"pattern_name"`
	ClRegex             types.String      `tfsdk:"cl_regex"`
	IfnRegex            types.String      `tfsdk:"ifn_regex"`
	ParentClRegex       types.String      `tfsdk:"parent_cl_regex"`
	ParentIfnRegex      types.String      `tfsdk:"parent_ifn_regex"`
	GrandparentClRegex  types.String      `tfsdk:"grandparent_cl_regex"`
	GrandparentIfnRegex types.String      `tfsdk:"grandparent_ifn_regex"`
	DetectionJSON       types.String      `tfsdk:"detection_json"`
	Groups              types.Set         `tfsdk:"host_groups"`
	Comment             types.String      `tfsdk:"comment"`
	AppliedGlobally     types.Bool        `tfsdk:"applied_globally"`
	CreatedBy           types.String      `tfsdk:"created_by"`
	CreatedOn           timetypes.RFC3339 `tfsdk:"created_on"`
	ModifiedBy          types.String      `tfsdk:"modified_by"`
	LastModified        timetypes.RFC3339 `tfsdk:"last_modified"`
}

func (m *SelfServiceIOAExclusionResourceModel) wrap(
	ctx context.Context,
	exclusion *models.DomainSsIoaExclusionsV2,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(exclusion.ID)
	m.Name = flex.StringValueToFramework(exclusion.Name)
	m.Description = flex.StringValueToFramework(exclusion.Description)
	m.PatternID = flex.StringValueToFramework(exclusion.PatternID)
	m.PatternName = preserveConfiguredString(m.PatternName, exclusion.PatternName)
	m.ClRegex = flex.StringValueToFramework(exclusion.ClRegex)
	m.IfnRegex = flex.StringValueToFramework(exclusion.IfnRegex)
	m.ParentClRegex = flex.StringValueToFramework(exclusion.ParentClRegex)
	m.ParentIfnRegex = flex.StringValueToFramework(exclusion.ParentIfnRegex)
	m.GrandparentClRegex = flex.StringValueToFramework(exclusion.GrandparentClRegex)
	m.GrandparentIfnRegex = flex.StringValueToFramework(exclusion.GrandparentIfnRegex)
	m.DetectionJSON = flex.StringValueToFramework(exclusion.DetectionJSON)
	m.AppliedGlobally = types.BoolValue(exclusion.AppliedGlobally)
	m.CreatedBy = flex.StringValueToFramework(exclusion.CreatedBy)
	m.CreatedOn = flex.DateTimeValueToFramework(exclusion.CreatedOn)
	m.ModifiedBy = flex.StringValueToFramework(exclusion.ModifiedBy)
	m.LastModified = flex.DateTimeValueToFramework(exclusion.LastModified)

	if exclusion.Comment != "" {
		m.Comment = flex.StringValueToFramework(exclusion.Comment)
	}

	var groupDiags diag.Diagnostics
	if exclusion.AppliedGlobally {
		m.Groups, groupDiags = types.SetValueFrom(ctx, types.StringType, []string{"all"})
	} else {
		m.Groups, groupDiags = flex.FlattenStringValueSet(ctx, exclusion.HostGroups)
	}
	diags.Append(groupDiags...)

	return diags
}

func preserveConfiguredString(current types.String, value string) types.String {
	if value == "" && !current.IsNull() && !current.IsUnknown() {
		return current
	}

	return flex.StringValueToFramework(value)
}

func (r *selfServiceIOAExclusionResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_self_service_ioa_exclusion"
}

func (r *selfServiceIOAExclusionResource) Configure(
	_ context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = providerConfig.Client
}

func (r *selfServiceIOAExclusionResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Endpoint Security",
			"A self-service IOA exclusion prevents a specific IOA detection pattern from triggering for matching child, parent, and grandparent command-line and image-filename regex values.",
			selfServiceIOAExclusionRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier of the self-service IOA exclusion.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "RFC850 timestamp of the last Terraform update to this resource.",
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Display name of the self-service IOA exclusion.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Description of the self-service IOA exclusion.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"pattern_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Identifier of the IOA pattern to exclude.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"pattern_name": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Name of the IOA pattern. Falcon can resolve this from pattern_id when omitted.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"cl_regex": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Command-line regex pattern for exclusion matching.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"ifn_regex": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Image filename regex pattern for exclusion matching.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"parent_cl_regex": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Parent process command-line regex pattern for exclusion matching.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"parent_ifn_regex": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Parent process image filename regex pattern for exclusion matching.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"grandparent_cl_regex": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Grandparent process command-line regex pattern for exclusion matching.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"grandparent_ifn_regex": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Grandparent process image filename regex pattern for exclusion matching.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"detection_json": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Detection JSON context associated with the self-service IOA exclusion.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"host_groups": schema.SetAttribute{
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Host group IDs that receive this exclusion. When omitted, Falcon applies the API default.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
				},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Additional context stored when creating, updating, or deleting the exclusion.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"applied_globally": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the exclusion is applied globally to all hosts.",
			},
			"created_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "User who created the exclusion.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_on": schema.StringAttribute{
				Computed:            true,
				CustomType:          timetypes.RFC3339Type{},
				MarkdownDescription: "Timestamp when the exclusion was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"modified_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "User who last modified the exclusion.",
			},
			"last_modified": schema.StringAttribute{
				Computed:            true,
				CustomType:          timetypes.RFC3339Type{},
				MarkdownDescription: "Timestamp when the exclusion was last modified.",
			},
		},
	}
}

func (r *selfServiceIOAExclusionResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan SelfServiceIOAExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createRequest, createDiags := expandCreateRequest(ctx, plan)
	resp.Diagnostics.Append(createDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := ioa_exclusions.NewSsIoaExclusionsCreateV2ParamsWithContext(ctx)
	params.SetBody(&models.DomainSsIoaExclusionsCreateReqV2{
		Exclusions: []*models.DomainSsIoaExclusionCreateReqV2{createRequest},
	})

	createResp, err := r.client.IoaExclusions.SsIoaExclusionsCreateV2(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, selfServiceIOAExclusionRequiredScopes))
		return
	}

	exclusion, payloadDiags := extractSelfServiceIOAExclusionFromPayload(tferrors.Create, createResp.GetPayload(), "")
	resp.Diagnostics.Append(payloadDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringPointerValue(exclusion.ID)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, exclusion)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *selfServiceIOAExclusionResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state SelfServiceIOAExclusionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exclusion, readDiags := getSelfServiceIOAExclusion(ctx, r.client, state.ID.ValueString())
	if tferrors.HasNotFoundError(readDiags) {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(readDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, exclusion)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *selfServiceIOAExclusionResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan SelfServiceIOAExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateRequest, updateDiags := expandUpdateRequest(ctx, plan)
	resp.Diagnostics.Append(updateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := ioa_exclusions.NewSsIoaExclusionsUpdateV2ParamsWithContext(ctx)
	params.SetBody(&models.DomainSsIoaExclusionsUpdateReqV2{
		Exclusions: []*models.DomainSsIoaExclusionUpdateReqV2{updateRequest},
	})

	updateResp, err := r.client.IoaExclusions.SsIoaExclusionsUpdateV2(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, selfServiceIOAExclusionRequiredScopes))
		return
	}

	exclusion, payloadDiags := extractSelfServiceIOAExclusionFromPayload(tferrors.Update, updateResp.GetPayload(), plan.ID.ValueString())
	resp.Diagnostics.Append(payloadDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, exclusion)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *selfServiceIOAExclusionResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state SelfServiceIOAExclusionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := ioa_exclusions.NewSsIoaExclusionsDeleteV2ParamsWithContext(ctx)
	params.SetIds([]string{state.ID.ValueString()})
	if !state.Comment.IsNull() && !state.Comment.IsUnknown() {
		params.SetComment(flex.FrameworkToStringPointer(state.Comment))
	}

	deleteResp, err := r.client.IoaExclusions.SsIoaExclusionsDeleteV2(params)
	if err != nil {
		diagErr := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, selfServiceIOAExclusionRequiredScopes)
		if diagErr != nil && diagErr.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diagErr)
		return
	}

	if deleteResp != nil && deleteResp.GetPayload() != nil {
		diagErr := diagnosticFromSelfServiceIOAPayload(tferrors.Delete, deleteResp.GetPayload().Errors)
		if diagErr != nil && diagErr.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diagErr)
	}
}

func (r *selfServiceIOAExclusionResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func expandCreateRequest(
	ctx context.Context,
	plan SelfServiceIOAExclusionResourceModel,
) (*models.DomainSsIoaExclusionCreateReqV2, diag.Diagnostics) {
	var diags diag.Diagnostics

	return &models.DomainSsIoaExclusionCreateReqV2{
		Name:                flex.FrameworkToStringPointer(plan.Name),
		Description:         frameworkStringValue(plan.Description),
		PatternID:           flex.FrameworkToStringPointer(plan.PatternID),
		PatternName:         frameworkStringValue(plan.PatternName),
		ClRegex:             flex.FrameworkToStringPointer(plan.ClRegex),
		IfnRegex:            flex.FrameworkToStringPointer(plan.IfnRegex),
		ParentClRegex:       frameworkStringValue(plan.ParentClRegex),
		ParentIfnRegex:      frameworkStringValue(plan.ParentIfnRegex),
		GrandparentClRegex:  frameworkStringValue(plan.GrandparentClRegex),
		GrandparentIfnRegex: frameworkStringValue(plan.GrandparentIfnRegex),
		DetectionJSON:       frameworkStringValue(plan.DetectionJSON),
		HostGroups:          expandOptionalStringSet(ctx, plan.Groups, &diags),
		Comment:             frameworkStringValue(plan.Comment),
	}, diags
}

func expandUpdateRequest(
	ctx context.Context,
	plan SelfServiceIOAExclusionResourceModel,
) (*models.DomainSsIoaExclusionUpdateReqV2, diag.Diagnostics) {
	var diags diag.Diagnostics

	return &models.DomainSsIoaExclusionUpdateReqV2{
		ID:                  flex.FrameworkToStringPointer(plan.ID),
		Name:                frameworkStringValue(plan.Name),
		Description:         frameworkStringValue(plan.Description),
		PatternID:           frameworkStringValue(plan.PatternID),
		PatternName:         frameworkStringValue(plan.PatternName),
		ClRegex:             frameworkStringValue(plan.ClRegex),
		IfnRegex:            frameworkStringValue(plan.IfnRegex),
		ParentClRegex:       frameworkStringValue(plan.ParentClRegex),
		ParentIfnRegex:      frameworkStringValue(plan.ParentIfnRegex),
		GrandparentClRegex:  frameworkStringValue(plan.GrandparentClRegex),
		GrandparentIfnRegex: frameworkStringValue(plan.GrandparentIfnRegex),
		DetectionJSON:       frameworkStringValue(plan.DetectionJSON),
		HostGroups:          expandOptionalStringSet(ctx, plan.Groups, &diags),
		Comment:             frameworkStringValue(plan.Comment),
	}, diags
}

func expandOptionalStringSet(ctx context.Context, value types.Set, diags *diag.Diagnostics) []string {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}

	return flex.ExpandSetAs[string](ctx, value, diags)
}

func frameworkStringValue(value types.String) string {
	if value.IsNull() || value.IsUnknown() {
		return ""
	}

	return value.ValueString()
}
