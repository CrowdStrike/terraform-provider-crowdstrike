package ioaexclusion

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ioa_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
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
	ID              types.String `tfsdk:"id"`
	LastUpdated     types.String `tfsdk:"last_updated"`
	Name            types.String `tfsdk:"name"`
	Description     types.String `tfsdk:"description"`
	PatternID       types.String `tfsdk:"pattern_id"`
	PatternName     types.String `tfsdk:"pattern_name"`
	ClRegex         types.String `tfsdk:"cl_regex"`
	IfnRegex        types.String `tfsdk:"ifn_regex"`
	Groups          types.Set    `tfsdk:"groups"`
	Comment         types.String `tfsdk:"comment"`
	AppliedGlobally types.Bool   `tfsdk:"applied_globally"`
	CreatedBy       types.String `tfsdk:"created_by"`
	CreatedOn       types.String `tfsdk:"created_on"`
	ModifiedBy      types.String `tfsdk:"modified_by"`
	LastModified    types.String `tfsdk:"last_modified"`
}

func (m *IOAExclusionResourceModel) wrap(
	ctx context.Context,
	exclusion *models.IoaExclusionsIoaExclusionRespV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(exclusion.ID)
	m.Name = types.StringPointerValue(exclusion.Name)
	m.Description = types.StringPointerValue(exclusion.Description)
	m.PatternID = types.StringPointerValue(exclusion.PatternID)
	m.PatternName = utils.PlanAwareStringValue(m.PatternName, exclusion.PatternName)
	m.ClRegex = types.StringPointerValue(exclusion.ClRegex)
	m.IfnRegex = types.StringPointerValue(exclusion.IfnRegex)
	m.AppliedGlobally = types.BoolPointerValue(exclusion.AppliedGlobally)
	m.CreatedBy = utils.OptionalString(exclusion.CreatedBy)
	m.CreatedOn = dateTimeValue(exclusion.CreatedOn)
	m.ModifiedBy = utils.OptionalString(exclusion.ModifiedBy)
	m.LastModified = dateTimeValue(exclusion.LastModified)

	if exclusion.AppliedGlobally != nil && *exclusion.AppliedGlobally {
		groups, groupDiags := types.SetValueFrom(ctx, types.StringType, []string{"all"})
		diags.Append(groupDiags...)
		if diags.HasError() {
			return diags
		}
		m.Groups = groups
		return diags
	}

	groups, groupDiags := hostgroups.ConvertHostGroupsToSet(ctx, exclusion.Groups)
	diags.Append(groupDiags...)
	if diags.HasError() {
		return diags
	}

	m.Groups = groups

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
			"IOA Exclusion",
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
				Required:            true,
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
			"pattern_name": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional name of the IOA pattern. If omitted, an empty string is sent to the API.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
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
			"groups": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Host group IDs that receive this exclusion. Use `[\"all\"]` to apply globally.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
				},
			},
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
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"created_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "User who created the exclusion.",
			},
			"created_on": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp when the exclusion was created.",
			},
			"modified_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "User who last modified the exclusion.",
			},
			"last_modified": schema.StringAttribute{
				Computed:            true,
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

	groups, groupDiags := setStrings(ctx, config.Groups)
	resp.Diagnostics.Append(groupDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := validateGroups(groups); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("groups"), "Invalid groups value", err.Error())
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
	resp.Diagnostics.Append(readDiags...)
	if tferrors.HasNotFoundError(resp.Diagnostics) {
		resp.Diagnostics = nil
		resp.State.RemoveResource(ctx)
		return
	}
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
	groups, diags := setStrings(ctx, plan.Groups)
	if diags.HasError() {
		return nil, diags
	}

	return &models.IoaExclusionsIoaExclusionCreateReqV1{
		Name:          utils.Addr(plan.Name.ValueString()),
		Description:   utils.Addr(plan.Description.ValueString()),
		PatternID:     utils.Addr(plan.PatternID.ValueString()),
		PatternName:   patternNamePointer(plan.PatternName),
		ClRegex:       utils.Addr(plan.ClRegex.ValueString()),
		IfnRegex:      utils.Addr(plan.IfnRegex.ValueString()),
		Groups:        groups,
		Comment:       optionalStringValue(plan.Comment),
		DetectionJSON: detectionJSONPointer(),
	}, diags
}

func expandUpdateRequest(
	ctx context.Context,
	plan IOAExclusionResourceModel,
) (*models.IoaExclusionsIoaExclusionUpdateReqV1, diag.Diagnostics) {
	groups, diags := setStrings(ctx, plan.Groups)
	if diags.HasError() {
		return nil, diags
	}

	return &models.IoaExclusionsIoaExclusionUpdateReqV1{
		ID:            utils.Addr(plan.ID.ValueString()),
		Name:          utils.Addr(plan.Name.ValueString()),
		Description:   utils.Addr(plan.Description.ValueString()),
		PatternID:     utils.Addr(plan.PatternID.ValueString()),
		PatternName:   patternNamePointer(plan.PatternName),
		ClRegex:       utils.Addr(plan.ClRegex.ValueString()),
		IfnRegex:      utils.Addr(plan.IfnRegex.ValueString()),
		Groups:        groups,
		Comment:       optionalStringValue(plan.Comment),
		DetectionJSON: detectionJSONPointer(),
	}, diags
}

func setStrings(ctx context.Context, value types.Set) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	if value.IsNull() || value.IsUnknown() {
		return nil, diags
	}

	var out []string
	diags.Append(value.ElementsAs(ctx, &out, false)...)
	return out, diags
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
		return fmt.Errorf(`groups cannot contain "all" with other host group IDs`)
	}

	return nil
}

func patternNamePointer(value types.String) *string {
	if value.IsNull() || value.IsUnknown() {
		return utils.Addr("")
	}

	return utils.Addr(value.ValueString())
}

func optionalStringValue(value types.String) string {
	if value.IsNull() || value.IsUnknown() {
		return ""
	}

	return value.ValueString()
}

func detectionJSONPointer() *string {
	return utils.Addr("")
}

func dateTimeValue(value *strfmt.DateTime) types.String {
	if value == nil || value.IsZero() {
		return types.StringNull()
	}

	return types.StringValue(value.String())
}
