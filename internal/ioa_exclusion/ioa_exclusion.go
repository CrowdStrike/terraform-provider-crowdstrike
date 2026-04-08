package ioaexclusion

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
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &ioaExclusionResource{}
	_ resource.ResourceWithConfigure      = &ioaExclusionResource{}
	_ resource.ResourceWithImportState    = &ioaExclusionResource{}
	_ resource.ResourceWithValidateConfig = &ioaExclusionResource{}
)

var ioaExclusionRequiredScopes = []scopes.Scope{
	{Name: "IOA Exclusions", Read: true, Write: true},
}

func NewIOAExclusionResource() resource.Resource {
	return &ioaExclusionResource{}
}

type ioaExclusionResource struct {
	client *client.CrowdStrikeAPISpecification
}

type IOAExclusionResourceModel struct {
	ID              types.String      `tfsdk:"id"`
	LastUpdated     types.String      `tfsdk:"last_updated"`
	Name            types.String      `tfsdk:"name"`
	Description     types.String      `tfsdk:"description"`
	PatternID       types.String      `tfsdk:"pattern_id"`
	PatternName     types.String      `tfsdk:"pattern_name"`
	ClRegex         types.String      `tfsdk:"cl_regex"`
	IfnRegex        types.String      `tfsdk:"ifn_regex"`
	Groups          types.Set         `tfsdk:"host_groups"`
	Comment         types.String      `tfsdk:"comment"`
	AppliedGlobally types.Bool        `tfsdk:"applied_globally"`
	CreatedBy       types.String      `tfsdk:"created_by"`
	CreatedOn       timetypes.RFC3339 `tfsdk:"created_on"`
	ModifiedBy      types.String      `tfsdk:"modified_by"`
	LastModified    timetypes.RFC3339 `tfsdk:"last_modified"`
}

func (m *IOAExclusionResourceModel) wrap(
	ctx context.Context,
	exclusion *models.IoaExclusionsIoaExclusionRespV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(exclusion.ID)
	m.Name = types.StringPointerValue(exclusion.Name)
	m.Description = flex.StringPointerToFramework(exclusion.Description)
	m.PatternID = types.StringPointerValue(exclusion.PatternID)
	m.PatternName = types.StringPointerValue(exclusion.PatternName)
	m.ClRegex = types.StringPointerValue(exclusion.ClRegex)
	m.IfnRegex = types.StringPointerValue(exclusion.IfnRegex)
	m.AppliedGlobally = types.BoolPointerValue(exclusion.AppliedGlobally)
	m.CreatedBy = types.StringPointerValue(exclusion.CreatedBy)
	m.CreatedOn = flex.DateTimePointerToFramework(exclusion.CreatedOn)
	m.ModifiedBy = types.StringPointerValue(exclusion.ModifiedBy)
	m.LastModified = flex.DateTimePointerToFramework(exclusion.LastModified)

	var groupDiags diag.Diagnostics
	if exclusion.AppliedGlobally != nil && *exclusion.AppliedGlobally {
		m.Groups, groupDiags = types.SetValueFrom(ctx, types.StringType, []string{"all"})
	} else {
		m.Groups, groupDiags = flex.FlattenHostGroupsToSet(ctx, exclusion.Groups)
	}
	diags.Append(groupDiags...)

	return diags
}

func (r *ioaExclusionResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_ioa_exclusion"
}

func (r *ioaExclusionResource) Configure(
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

func (r *ioaExclusionResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Endpoint Security",
			"An IOA exclusion prevents a specific IOA detection pattern from triggering for matching command line and image filename regex values.",
			ioaExclusionRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier of the IOA exclusion.",
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
				MarkdownDescription: "Display name of the IOA exclusion.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Description of the IOA exclusion.",
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
			// TODO: verify if pattern_name should be Optional+Computed (user-settable).
			// The API ignores pattern_name on create (resolves it from pattern_id)
			// but accepts and persists a custom value on update. Keeping Computed-only
			// until this asymmetry is confirmed as intended behavior.
			"pattern_name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Name of the IOA pattern.",
			},
			"cl_regex": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Command-line regex pattern for exclusion matching. Maximum length is 256 characters.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.LengthAtMost(256),
				},
			},
			"ifn_regex": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Image filename regex pattern for exclusion matching. Maximum length is 256 characters.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.LengthAtMost(256),
				},
			},
			"host_groups": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Host group IDs that receive this exclusion. Use `[\"all\"]` to apply globally.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
				},
			},
			// The API accepts comment on create/update but never returns it
			// in responses (the key is absent, not empty). wrap() intentionally
			// does not touch this field so the plan/state value is preserved.
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Additional context stored when creating or updating the exclusion. Falcon does not return this field on reads, so imported resources cannot populate it automatically.",
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

func (r *ioaExclusionResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config IOAExclusionResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.Groups.IsNull() || config.Groups.IsUnknown() {
		return
	}

	for _, elem := range config.Groups.Elements() {
		if elem.IsUnknown() {
			return
		}
	}

	groups := flex.ExpandSetAs[string](ctx, config.Groups, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := validateGroups(groups); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("host_groups"), "Invalid host_groups value", err.Error())
	}
}

func (r *ioaExclusionResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan IOAExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createRequest, createDiags := expandCreateRequest(ctx, plan)
	resp.Diagnostics.Append(createDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := ioa_exclusions.NewCreateIOAExclusionsV1ParamsWithContext(ctx)
	params.SetBody(createRequest)

	createResp, err := r.client.IoaExclusions.CreateIOAExclusionsV1(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, ioaExclusionRequiredScopes))
		return
	}

	exclusion, payloadDiags := extractIOAExclusionFromPayload(tferrors.Create, createResp.GetPayload(), "")
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

func (r *ioaExclusionResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state IOAExclusionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exclusion, readDiags := getIOAExclusion(ctx, r.client, state.ID.ValueString())
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

func (r *ioaExclusionResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan IOAExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateRequest, updateDiags := expandUpdateRequest(ctx, plan)
	resp.Diagnostics.Append(updateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := ioa_exclusions.NewUpdateIOAExclusionsV1ParamsWithContext(ctx)
	params.SetBody(updateRequest)

	updateResp, err := r.client.IoaExclusions.UpdateIOAExclusionsV1(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, ioaExclusionRequiredScopes))
		return
	}

	exclusion, payloadDiags := extractIOAExclusionFromPayload(tferrors.Update, updateResp.GetPayload(), plan.ID.ValueString())
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

func (r *ioaExclusionResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state IOAExclusionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := ioa_exclusions.NewDeleteIOAExclusionsV1ParamsWithContext(ctx)
	params.SetIds([]string{state.ID.ValueString()})

	deleteResp, err := r.client.IoaExclusions.DeleteIOAExclusionsV1(params)
	if err != nil {
		diagErr := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, ioaExclusionRequiredScopes)
		if diagErr != nil && diagErr.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diagErr)
		return
	}

	if deleteResp != nil {
		if diagErr := diagnosticFromQueryPayload(tferrors.Delete, deleteResp.GetPayload()); diagErr != nil {
			if diagErr.Summary() == tferrors.NotFoundErrorSummary {
				return
			}
			resp.Diagnostics.Append(diagErr)
		}
	}
}

func (r *ioaExclusionResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func expandCreateRequest(
	ctx context.Context,
	plan IOAExclusionResourceModel,
) (*models.IoaExclusionsIoaExclusionCreateReqV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	groups := flex.ExpandSetAs[string](ctx, plan.Groups, &diags)
	if diags.HasError() {
		return nil, diags
	}

	return &models.IoaExclusionsIoaExclusionCreateReqV1{
		Name:          flex.FrameworkToStringPointer(plan.Name),
		Description:   flex.FrameworkToStringPointer(plan.Description),
		PatternID:     flex.FrameworkToStringPointer(plan.PatternID),
		PatternName:   flex.FrameworkToStringPointer(plan.PatternName),
		ClRegex:       flex.FrameworkToStringPointer(plan.ClRegex),
		IfnRegex:      flex.FrameworkToStringPointer(plan.IfnRegex),
		Groups:        groups,
		Comment:       plan.Comment.ValueString(),
		DetectionJSON: detectionJSONPointer(),
	}, diags
}

func expandUpdateRequest(
	ctx context.Context,
	plan IOAExclusionResourceModel,
) (*models.IoaExclusionsIoaExclusionUpdateReqV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	groups := flex.ExpandSetAs[string](ctx, plan.Groups, &diags)
	if diags.HasError() {
		return nil, diags
	}

	return &models.IoaExclusionsIoaExclusionUpdateReqV1{
		ID:            flex.FrameworkToStringPointer(plan.ID),
		Name:          flex.FrameworkToStringPointer(plan.Name),
		Description:   flex.FrameworkToStringPointer(plan.Description),
		PatternID:     flex.FrameworkToStringPointer(plan.PatternID),
		PatternName:   flex.FrameworkToStringPointer(plan.PatternName),
		ClRegex:       flex.FrameworkToStringPointer(plan.ClRegex),
		IfnRegex:      flex.FrameworkToStringPointer(plan.IfnRegex),
		Groups:        groups,
		Comment:       plan.Comment.ValueString(),
		DetectionJSON: detectionJSONPointer(),
	}, diags
}

func validateGroups(groups []string) error {
	hasAll := false
	for _, group := range groups {
		if group == "all" {
			hasAll = true
			break
		}
	}

	if hasAll && len(groups) > 1 {
		return fmt.Errorf(`host_groups cannot contain "all" with other host group IDs`)
	}

	return nil
}

// TODO: remove once gofalcon marks detection_json as optional instead of required.
func detectionJSONPointer() *string {
	return utils.Addr("")
}
