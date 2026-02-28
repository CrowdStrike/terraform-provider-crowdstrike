package mlexclusion

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ml_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	mlExclusionGlobalHostGroupID = "all"
	mlExcludedFromBlocking       = "blocking"
	mlExcludedFromExtraction     = "extraction"
)

var (
	_ resource.Resource                   = &mlExclusionResource{}
	_ resource.ResourceWithConfigure      = &mlExclusionResource{}
	_ resource.ResourceWithImportState    = &mlExclusionResource{}
	_ resource.ResourceWithValidateConfig = &mlExclusionResource{}
)

var mlExclusionRequiredScopes = []scopes.Scope{
	{
		Name:  "Machine Learning Exclusions",
		Read:  true,
		Write: true,
	},
}

func NewMLExclusionResource() resource.Resource {
	return &mlExclusionResource{}
}

type mlExclusionResource struct {
	client *client.CrowdStrikeAPISpecification
}

type mlExclusionResourceModel struct {
	ID                types.String `tfsdk:"id"`
	Pattern           types.String `tfsdk:"pattern"`
	HostGroups        types.Set    `tfsdk:"host_groups"`
	ExcludeDetections types.Bool   `tfsdk:"exclude_detections"`
	ExcludeUploads    types.Bool   `tfsdk:"exclude_uploads"`
	RegexpValue       types.String `tfsdk:"regexp_value"`
	ValueHash         types.String `tfsdk:"value_hash"`
	AppliedGlobally   types.Bool   `tfsdk:"applied_globally"`
	LastModified      types.String `tfsdk:"last_modified"`
	ModifiedBy        types.String `tfsdk:"modified_by"`
	CreatedOn         types.String `tfsdk:"created_on"`
	CreatedBy         types.String `tfsdk:"created_by"`
	LastUpdated       types.String `tfsdk:"last_updated"`
}

func (m *mlExclusionResourceModel) wrap(
	ctx context.Context,
	exclusion *models.ExclusionsExclusionV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(exclusion.ID)
	m.Pattern = types.StringPointerValue(exclusion.Value)
	m.RegexpValue = types.StringPointerValue(exclusion.RegexpValue)
	m.ValueHash = types.StringPointerValue(exclusion.ValueHash)
	m.CreatedBy = types.StringPointerValue(exclusion.CreatedBy)
	m.ModifiedBy = types.StringPointerValue(exclusion.ModifiedBy)
	m.ExcludeDetections = types.BoolValue(hasExcludedFrom(exclusion.ExcludedFrom, mlExcludedFromBlocking))
	m.ExcludeUploads = types.BoolValue(hasExcludedFrom(exclusion.ExcludedFrom, mlExcludedFromExtraction))

	appliedGlobally := exclusion.AppliedGlobally != nil && *exclusion.AppliedGlobally
	m.AppliedGlobally = types.BoolValue(appliedGlobally)

	if exclusion.CreatedOn != nil {
		m.CreatedOn = types.StringValue(exclusion.CreatedOn.String())
	} else {
		m.CreatedOn = types.StringNull()
	}

	if exclusion.LastModified != nil {
		m.LastModified = types.StringValue(exclusion.LastModified.String())
	} else {
		m.LastModified = types.StringNull()
	}

	if appliedGlobally {
		hostGroupSet, hostGroupDiags := types.SetValueFrom(
			ctx,
			types.StringType,
			[]string{mlExclusionGlobalHostGroupID},
		)
		diags.Append(hostGroupDiags...)
		if diags.HasError() {
			return diags
		}
		m.HostGroups = hostGroupSet
		return diags
	}

	hostGroupSet, hostGroupDiags := hostgroups.ConvertHostGroupsToSet(ctx, exclusion.Groups)
	diags.Append(hostGroupDiags...)
	if diags.HasError() {
		return diags
	}

	m.HostGroups = hostGroupSet
	return diags
}

func (r *mlExclusionResource) Configure(
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
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	r.client = providerConfig.Client
}

func (r *mlExclusionResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_ml_exclusion"
}

func (r *mlExclusionResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Machine Learning Exclusion",
			"Manages machine learning exclusions for trusted file paths in the CrowdStrike Falcon Platform. "+
				"At least one exclusion mode must be enabled via `exclude_detections` and/or `exclude_uploads`. "+
				"Changes to `host_groups` require replacement.",
			mlExclusionRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The unique identifier for the machine learning exclusion.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"pattern": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The file path or pattern to exclude from machine learning detections.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"host_groups": schema.SetAttribute{
				Required:            true,
				MarkdownDescription: "The set of host group IDs this exclusion applies to. Use `all` to apply globally.",
				ElementType:         types.StringType,
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
				},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
			},
			"exclude_detections": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether to exclude matching files from machine learning detections and preventions.",
				Default:             booldefault.StaticBool(false),
			},
			"exclude_uploads": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether to exclude matching files from cloud extraction/uploads.",
				Default:             booldefault.StaticBool(false),
			},
			"regexp_value": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The regular expression representation of `pattern` generated by Falcon.",
			},
			"value_hash": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The hash of the configured exclusion pattern value.",
			},
			"applied_globally": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether Falcon reports this exclusion as globally applied.",
			},
			"last_modified": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when the exclusion was last modified.",
			},
			"modified_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who last modified the exclusion.",
			},
			"created_on": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when the exclusion was created.",
			},
			"created_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who created the exclusion.",
			},
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The RFC850 timestamp of the last update to this resource by Terraform.",
			},
		},
	}
}

func (r *mlExclusionResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan mlExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var hostGroups []string
	resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &hostGroups, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := &models.ExclusionsCreateReqV1{
		Value:        plan.Pattern.ValueString(),
		Groups:       hostGroups,
		ExcludedFrom: buildExcludedFrom(plan.ExcludeDetections.ValueBool(), plan.ExcludeUploads.ValueBool()),
		Comment:      "created by terraform crowdstrike provider",
	}

	params := ml_exclusions.NewCreateMLExclusionsV1ParamsWithContext(ctx)
	params.SetBody(createReq)

	createResp, err := r.client.MlExclusions.CreateMLExclusionsV1(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create,
			err,
			mlExclusionRequiredScopes,
		))
		return
	}

	if createResp == nil || createResp.Payload == nil || len(createResp.Payload.Resources) == 0 ||
		createResp.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, createResp.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, createResp.Payload.Resources[0])...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *mlExclusionResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state mlExclusionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exclusion, diags := getMLExclusion(ctx, r.client, state.ID.ValueString())
	if tferrors.HasNotFoundError(diags) {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, exclusion)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *mlExclusionResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan mlExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := plan.ID.ValueString()
	updateReq := &mlExclusionUpdateReqV1{
		ID:           &id,
		Value:        plan.Pattern.ValueString(),
		ExcludedFrom: buildExcludedFrom(plan.ExcludeDetections.ValueBool(), plan.ExcludeUploads.ValueBool()),
	}

	params := ml_exclusions.NewUpdateMLExclusionsV1ParamsWithContext(ctx)
	updateResp, err := r.client.MlExclusions.UpdateMLExclusionsV1(
		params,
		func(operation *runtime.ClientOperation) {
			// SDK update params use the wrong body model (SvExclusionsUpdateReqV1),
			// so we override the request writer with the ML-compatible payload.
			operation.Params = &mlExclusionUpdateParams{Body: updateReq}
		},
	)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Update,
			err,
			mlExclusionRequiredScopes,
		))
		return
	}

	if updateResp == nil || updateResp.Payload == nil || len(updateResp.Payload.Resources) == 0 ||
		updateResp.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, updateResp.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, updateResp.Payload.Resources[0])...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *mlExclusionResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state mlExclusionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := ml_exclusions.NewDeleteMLExclusionsV1ParamsWithContext(ctx)
	params.SetIds([]string{state.ID.ValueString()})
	comment := "deleted by terraform crowdstrike provider"
	params.SetComment(&comment)

	deleteResp, err := r.client.MlExclusions.DeleteMLExclusionsV1(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, mlExclusionRequiredScopes)
		if diag != nil {
			if diag.Summary() == tferrors.NotFoundErrorSummary {
				return
			}
			resp.Diagnostics.Append(diag)
		}
		return
	}

	if deleteResp != nil && deleteResp.Payload != nil {
		if payloadHasNotFoundError(deleteResp.Payload.Errors) {
			return
		}

		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Delete, deleteResp.Payload.Errors); diag != nil {
			resp.Diagnostics.Append(diag)
		}
	}
}

func (r *mlExclusionResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *mlExclusionResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config mlExclusionResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.ExcludeDetections.IsUnknown() || config.ExcludeUploads.IsUnknown() || config.HostGroups.IsUnknown() {
		return
	}

	if !config.ExcludeDetections.ValueBool() && !config.ExcludeUploads.ValueBool() {
		resp.Diagnostics.AddAttributeError(
			path.Root("exclude_detections"),
			"Invalid Configuration",
			"At least one of `exclude_detections` or `exclude_uploads` must be set to true.",
		)
	}

	if config.HostGroups.IsNull() {
		return
	}

	var hostGroups []string
	resp.Diagnostics.Append(config.HostGroups.ElementsAs(ctx, &hostGroups, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if hasGlobalHostGroup(hostGroups) && len(hostGroups) > 1 {
		resp.Diagnostics.AddAttributeError(
			path.Root("host_groups"),
			"Invalid Host Group Configuration",
			"`host_groups` cannot include `all` with additional host group IDs.",
		)
	}
}

func buildExcludedFrom(excludeDetections, excludeUploads bool) []string {
	excludedFrom := make([]string, 0, 2)
	if excludeDetections {
		excludedFrom = append(excludedFrom, mlExcludedFromBlocking)
	}

	if excludeUploads {
		excludedFrom = append(excludedFrom, mlExcludedFromExtraction)
	}

	return excludedFrom
}

func hasExcludedFrom(excludedFrom []string, expected string) bool {
	for _, exclusionMode := range excludedFrom {
		if strings.EqualFold(exclusionMode, expected) {
			return true
		}
	}
	return false
}

func hasGlobalHostGroup(hostGroups []string) bool {
	for _, hostGroup := range hostGroups {
		if strings.EqualFold(hostGroup, mlExclusionGlobalHostGroupID) {
			return true
		}
	}
	return false
}

type mlExclusionUpdateReqV1 struct {
	ID           *string  `json:"id"`
	ExcludedFrom []string `json:"excluded_from"`
	Value        string   `json:"value,omitempty"`
}

type mlExclusionUpdateParams struct {
	Body *mlExclusionUpdateReqV1
}

func (p *mlExclusionUpdateParams) WriteToRequest(r runtime.ClientRequest, _ strfmt.Registry) error {
	if p.Body != nil {
		if err := r.SetBodyParam(p.Body); err != nil {
			return err
		}
	}

	return nil
}
