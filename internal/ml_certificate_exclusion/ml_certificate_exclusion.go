package mlcertificateexclusion

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/certificate_based_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
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
)

const (
	mlCertificateExclusionGlobalHostGroupID = "all"
)

var (
	_ resource.Resource                   = &mlCertificateExclusionResource{}
	_ resource.ResourceWithConfigure      = &mlCertificateExclusionResource{}
	_ resource.ResourceWithImportState    = &mlCertificateExclusionResource{}
	_ resource.ResourceWithValidateConfig = &mlCertificateExclusionResource{}
)

var mlCertificateExclusionRequiredScopes = []scopes.Scope{
	{Name: "Certificate Based Exclusions", Read: true, Write: true},
}

func NewMLCertificateExclusionResource() resource.Resource {
	return &mlCertificateExclusionResource{}
}

type mlCertificateExclusionResource struct {
	client *client.CrowdStrikeAPISpecification
}

type mlCertificateExclusionResourceModel struct {
	ID              types.String      `tfsdk:"id"`
	Name            types.String      `tfsdk:"name"`
	Description     types.String      `tfsdk:"description"`
	Comment         types.String      `tfsdk:"comment"`
	Enabled         types.Bool        `tfsdk:"enabled"`
	AppliedGlobally types.Bool        `tfsdk:"applied_globally"`
	HostGroups      types.Set         `tfsdk:"host_groups"`
	Certificate     types.Object      `tfsdk:"certificate"`
	CreatedBy       types.String      `tfsdk:"created_by"`
	CreatedOn       timetypes.RFC3339 `tfsdk:"created_on"`
	ModifiedBy      types.String      `tfsdk:"modified_by"`
	ModifiedOn      timetypes.RFC3339 `tfsdk:"modified_on"`
}

type certificateModel struct {
	Issuer     types.String      `tfsdk:"issuer"`
	Serial     types.String      `tfsdk:"serial"`
	Subject    types.String      `tfsdk:"subject"`
	Thumbprint types.String      `tfsdk:"thumbprint"`
	ValidFrom  timetypes.RFC3339 `tfsdk:"valid_from"`
	ValidTo    timetypes.RFC3339 `tfsdk:"valid_to"`
}

func (certificateModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"issuer":     types.StringType,
		"serial":     types.StringType,
		"subject":    types.StringType,
		"thumbprint": types.StringType,
		"valid_from": timetypes.RFC3339Type{},
		"valid_to":   timetypes.RFC3339Type{},
	}
}

func (m *mlCertificateExclusionResourceModel) wrap(
	ctx context.Context,
	exclusion *models.APICertBasedExclusionV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(exclusion.ID)
	m.Name = types.StringValue(exclusion.Name)
	m.Description = flex.StringValueToFramework(exclusion.Description)
	m.Comment = flex.StringValueToFramework(exclusion.Comment)
	m.Enabled = types.BoolValue(exclusion.Status == "enabled")
	m.AppliedGlobally = types.BoolValue(exclusion.AppliedGlobally)
	m.CreatedBy = flex.StringValueToFramework(exclusion.CreatedBy)
	m.CreatedOn = flex.DateTimeValueToFramework(exclusion.CreatedOn)
	m.ModifiedBy = flex.StringValueToFramework(exclusion.ModifiedBy)
	m.ModifiedOn = flex.DateTimeValueToFramework(exclusion.ModifiedOn)

	var hostGroupDiags diag.Diagnostics
	if exclusion.AppliedGlobally {
		m.HostGroups, hostGroupDiags = types.SetValueFrom(ctx, types.StringType, []string{mlCertificateExclusionGlobalHostGroupID})
	} else {
		m.HostGroups, hostGroupDiags = types.SetValueFrom(ctx, types.StringType, exclusion.HostGroups)
	}
	diags.Append(hostGroupDiags...)
	if diags.HasError() {
		return diags
	}

	certificateObj, certificateDiags := flattenCertificate(ctx, exclusion.Certificate)
	diags.Append(certificateDiags...)
	if diags.HasError() {
		return diags
	}
	m.Certificate = certificateObj

	return diags
}

func (r *mlCertificateExclusionResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_ml_certificate_exclusion"
}

func (r *mlCertificateExclusionResource) Configure(
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

func (r *mlCertificateExclusionResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Endpoint Security",
			"An ML certificate exclusion defines a machine learning exclusion scoped to a certificate and either all hosts or specific host groups.",
			mlCertificateExclusionRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier of the ML certificate exclusion.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Display name of the ML certificate exclusion.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional description of the ML certificate exclusion.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional comment stored with the ML certificate exclusion.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"enabled": schema.BoolAttribute{
				Required:            true,
				MarkdownDescription: "Whether the ML certificate exclusion is enabled.",
			},
			"applied_globally": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether Falcon reports this exclusion as globally applied. Set `host_groups` to `[\"all\"]` to target all hosts.",
			},
			"host_groups": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "The set of host group IDs this exclusion applies to. Use `[\"all\"]` to apply the exclusion globally to all hosts.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
				},
			},
			"certificate": schema.SingleNestedAttribute{
				Required:            true,
				MarkdownDescription: "Certificate fields that identify the certificate to exclude.",
				Attributes: map[string]schema.Attribute{
					"issuer": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Certificate issuer.",
						Validators:          []validator.String{fwvalidators.StringNotWhitespace()},
					},
					"serial": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Certificate serial number.",
						Validators:          []validator.String{fwvalidators.StringNotWhitespace()},
					},
					"subject": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Certificate subject.",
						Validators:          []validator.String{fwvalidators.StringNotWhitespace()},
					},
					"thumbprint": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Certificate thumbprint.",
						Validators:          []validator.String{fwvalidators.StringNotWhitespace()},
					},
					"valid_from": schema.StringAttribute{
						Required:            true,
						CustomType:          timetypes.RFC3339Type{},
						MarkdownDescription: "Certificate validity start timestamp in RFC3339 format.",
					},
					"valid_to": schema.StringAttribute{
						Required:            true,
						CustomType:          timetypes.RFC3339Type{},
						MarkdownDescription: "Certificate validity end timestamp in RFC3339 format.",
					},
				},
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
			"modified_on": schema.StringAttribute{
				Computed:            true,
				CustomType:          timetypes.RFC3339Type{},
				MarkdownDescription: "Timestamp when the exclusion was last modified.",
			},
		},
	}
}

func (r *mlCertificateExclusionResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config mlCertificateExclusionResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hostGroups, ok := flex.ExpandKnownSet[string](ctx, config.HostGroups, &resp.Diagnostics)
	if !ok {
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

func (r *mlCertificateExclusionResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan mlCertificateExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	certificateRequest, certificateDiags := expandCertificateRequest(ctx, plan.Certificate)
	resp.Diagnostics.Append(certificateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	hostGroups := flex.ExpandSetAs[string](ctx, plan.HostGroups, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	appliedGlobally := hasGlobalHostGroup(hostGroups)
	if appliedGlobally {
		hostGroups = nil
	}

	createRequest := &models.APICertBasedExclusionsCreateReqV1{
		Exclusions: []*models.APICertBasedExclusionCreateReqV1{
			{
				AppliedGlobally: appliedGlobally,
				Certificate:     certificateRequest,
				Comment:         plan.Comment.ValueString(),
				Description:     plan.Description.ValueString(),
				HostGroups:      hostGroups,
				Name:            plan.Name.ValueStringPointer(),
				Status:          enabledStatus(plan.Enabled.ValueBool()),
			},
		},
	}

	params := certificate_based_exclusions.NewCbExclusionsCreateV1ParamsWithContext(ctx)
	params.SetBody(createRequest)

	res, err := r.client.CertificateBasedExclusions.CbExclusionsCreateV1(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create,
			err,
			mlCertificateExclusionRequiredScopes,
		))
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, res.Payload.Resources[0])...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *mlCertificateExclusionResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state mlCertificateExclusionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exclusion, diags := getMLCertificateExclusion(ctx, r.client, state.ID.ValueString())
	if tferrors.HasNotFoundError(diags) {
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

func (r *mlCertificateExclusionResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan mlCertificateExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	certificateRequest, certificateDiags := expandCertificateRequest(ctx, plan.Certificate)
	resp.Diagnostics.Append(certificateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	hostGroups := flex.ExpandSetAs[string](ctx, plan.HostGroups, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	appliedGlobally := hasGlobalHostGroup(hostGroups)
	if appliedGlobally {
		hostGroups = nil
	}

	id := plan.ID.ValueString()
	updateReq := &certExclusionUpdateReqV1{
		AppliedGlobally: appliedGlobally,
		Certificate:     certificateRequest,
		Comment:         plan.Comment.ValueString(),
		Description:     plan.Description.ValueString(),
		HostGroups:      hostGroups,
		ID:              &id,
		Name:            plan.Name.ValueString(),
		Status:          enabledStatus(plan.Enabled.ValueBool()),
	}

	params := certificate_based_exclusions.NewCbExclusionsUpdateV1ParamsWithContext(ctx)

	res, err := r.client.CertificateBasedExclusions.CbExclusionsUpdateV1(
		params,
		func(op *runtime.ClientOperation) {
			op.Params = &certExclusionsUpdateParams{
				Body: &certExclusionsUpdateReqV1{
					Exclusions: []*certExclusionUpdateReqV1{updateReq},
				},
			}
		},
	)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Update,
			err,
			mlCertificateExclusionRequiredScopes,
		))
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, res.Payload.Resources[0])...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *mlCertificateExclusionResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state mlCertificateExclusionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := certificate_based_exclusions.NewCbExclusionsDeleteV1ParamsWithContext(ctx)
	params.SetIds([]string{state.ID.ValueString()})

	res, err := r.client.CertificateBasedExclusions.CbExclusionsDeleteV1(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(
			tferrors.Delete,
			err,
			mlCertificateExclusionRequiredScopes,
			tferrors.WithNotFoundDetail(fmt.Sprintf("ML certificate exclusion with ID %s was not found.", state.ID.ValueString())),
		)
		if diag != nil && diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	if res != nil && res.Payload != nil {
		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Delete, res.Payload.Errors); diag != nil {
			if diag.Summary() == tferrors.NotFoundErrorSummary {
				return
			}
			resp.Diagnostics.Append(diag)
		}
	}
}

func (r *mlCertificateExclusionResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func hasGlobalHostGroup(hostGroups []string) bool {
	for _, hostGroup := range hostGroups {
		if strings.EqualFold(hostGroup, mlCertificateExclusionGlobalHostGroupID) {
			return true
		}
	}
	return false
}

func flattenCertificate(
	ctx context.Context,
	apiCertificate *models.APICertificateV1,
) (types.Object, diag.Diagnostics) {
	if apiCertificate == nil {
		return types.ObjectNull(certificateModel{}.AttributeTypes()), nil
	}

	certificate := certificateModel{
		Issuer:     types.StringPointerValue(apiCertificate.Issuer),
		Serial:     types.StringPointerValue(apiCertificate.Serial),
		Subject:    types.StringPointerValue(apiCertificate.Subject),
		Thumbprint: types.StringPointerValue(apiCertificate.Thumbprint),
		ValidFrom:  flex.DateTimePointerToFramework(apiCertificate.ValidFrom),
		ValidTo:    flex.DateTimePointerToFramework(apiCertificate.ValidTo),
	}

	return utils.ConvertModelToTerraformObject(ctx, &certificate)
}

func expandCertificateRequest(ctx context.Context, object types.Object) (*models.APICertificateReqV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	var certificate certificateModel
	diags.Append(object.As(ctx, &certificate, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil, diags
	}

	validFrom, fromDiags := flex.FrameworkToDateTimePointer(certificate.ValidFrom)
	diags.Append(fromDiags...)
	if diags.HasError() {
		return nil, diags
	}

	validTo, toDiags := flex.FrameworkToDateTimePointer(certificate.ValidTo)
	diags.Append(toDiags...)
	if diags.HasError() {
		return nil, diags
	}

	return &models.APICertificateReqV1{
		Issuer:     certificate.Issuer.ValueStringPointer(),
		Serial:     certificate.Serial.ValueStringPointer(),
		Subject:    certificate.Subject.ValueStringPointer(),
		Thumbprint: certificate.Thumbprint.ValueStringPointer(),
		ValidFrom:  validFrom,
		ValidTo:    validTo,
	}, diags
}

func enabledStatus(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func getMLCertificateExclusion(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	exclusionID string,
) (*models.APICertBasedExclusionV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := certificate_based_exclusions.NewCbExclusionsGetV1ParamsWithContext(ctx)
	params.SetIds([]string{exclusionID})

	res, err := client.CertificateBasedExclusions.CbExclusionsGetV1(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Read,
			err,
			mlCertificateExclusionRequiredScopes,
			tferrors.WithNotFoundDetail(fmt.Sprintf("ML certificate exclusion with ID %s was not found.", exclusionID)),
		))
		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewNotFoundError(
			fmt.Sprintf("ML certificate exclusion with ID %s was not found.", exclusionID),
		))
		return nil, diags
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		diags.Append(diag)
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

// certExclusionUpdateReqV1 mirrors models.APICertBasedExclusionUpdateReqV1 but drops
// `omitempty` from `description`, `comment`, and `applied_globally` so the API PATCH
// receives zero values explicitly. Without this, the service preserves the prior value
// when a user clears `description`/`comment` or switches `applied_globally` from true
// to false.
type certExclusionUpdateReqV1 struct {
	AppliedGlobally bool                        `json:"applied_globally"`
	Certificate     *models.APICertificateReqV1 `json:"certificate,omitempty"`
	Comment         string                      `json:"comment"`
	Description     string                      `json:"description"`
	HostGroups      []string                    `json:"host_groups"`
	ID              *string                     `json:"id"`
	Name            string                      `json:"name,omitempty"`
	Status          string                      `json:"status,omitempty"`
}

type certExclusionsUpdateReqV1 struct {
	Exclusions []*certExclusionUpdateReqV1 `json:"exclusions"`
}

type certExclusionsUpdateParams struct {
	Body *certExclusionsUpdateReqV1
}

func (p *certExclusionsUpdateParams) WriteToRequest(r runtime.ClientRequest, _ strfmt.Registry) error {
	if p.Body == nil {
		return nil
	}
	return r.SetBodyParam(p.Body)
}
