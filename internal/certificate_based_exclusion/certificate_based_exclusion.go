package certificatebasedexclusion

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/certificate_based_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

var (
	_ resource.Resource                   = &certificateBasedExclusionResource{}
	_ resource.ResourceWithConfigure      = &certificateBasedExclusionResource{}
	_ resource.ResourceWithImportState    = &certificateBasedExclusionResource{}
	_ resource.ResourceWithValidateConfig = &certificateBasedExclusionResource{}
)

var certificateBasedExclusionRequiredScopes = []scopes.Scope{
	{Name: "Certificate Based Exclusions", Read: true, Write: true},
}

func NewCertificateBasedExclusionResource() resource.Resource {
	return &certificateBasedExclusionResource{}
}

type certificateBasedExclusionResource struct {
	client *client.CrowdStrikeAPISpecification
}

type CertificateBasedExclusionResourceModel struct {
	ID              types.String `tfsdk:"id"`
	LastUpdated     types.String `tfsdk:"last_updated"`
	Name            types.String `tfsdk:"name"`
	Description     types.String `tfsdk:"description"`
	Comment         types.String `tfsdk:"comment"`
	AppliedGlobally types.Bool   `tfsdk:"applied_globally"`
	HostGroups      types.Set    `tfsdk:"host_groups"`
	Certificate     types.Object `tfsdk:"certificate"`
	CreatedBy       types.String `tfsdk:"created_by"`
	CreatedOn       types.String `tfsdk:"created_on"`
	ModifiedBy      types.String `tfsdk:"modified_by"`
	ModifiedOn      types.String `tfsdk:"modified_on"`
}

type certificateModel struct {
	Issuer     types.String `tfsdk:"issuer"`
	Serial     types.String `tfsdk:"serial"`
	Subject    types.String `tfsdk:"subject"`
	Thumbprint types.String `tfsdk:"thumbprint"`
	ValidFrom  types.String `tfsdk:"valid_from"`
	ValidTo    types.String `tfsdk:"valid_to"`
}

func (certificateModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"issuer":     types.StringType,
		"serial":     types.StringType,
		"subject":    types.StringType,
		"thumbprint": types.StringType,
		"valid_from": types.StringType,
		"valid_to":   types.StringType,
	}
}

func (m *CertificateBasedExclusionResourceModel) wrap(
	ctx context.Context,
	exclusion *models.APICertBasedExclusionV1,
) diag.Diagnostics {
	var diags diag.Diagnostics
	currentCertificate := certificateModel{
		Issuer:     types.StringNull(),
		Serial:     types.StringNull(),
		Subject:    types.StringNull(),
		Thumbprint: types.StringNull(),
		ValidFrom:  types.StringNull(),
		ValidTo:    types.StringNull(),
	}

	m.ID = types.StringPointerValue(exclusion.ID)
	m.Name = types.StringValue(exclusion.Name)
	m.Description = utils.PlanAwareStringValue(m.Description, utils.Addr(exclusion.Description))
	m.Comment = utils.PlanAwareStringValue(m.Comment, utils.Addr(exclusion.Comment))
	m.AppliedGlobally = types.BoolValue(exclusion.AppliedGlobally)
	m.CreatedBy = utils.OptionalString(utils.Addr(exclusion.CreatedBy))
	m.CreatedOn = dateTimeValue(exclusion.CreatedOn)
	m.ModifiedBy = utils.OptionalString(utils.Addr(exclusion.ModifiedBy))
	m.ModifiedOn = dateTimeValue(exclusion.ModifiedOn)

	hostGroups, hostGroupDiags := types.SetValueFrom(ctx, types.StringType, exclusion.HostGroups)
	diags.Append(hostGroupDiags...)
	if diags.HasError() {
		return diags
	}
	if !m.HostGroups.IsNull() || len(exclusion.HostGroups) != 0 {
		m.HostGroups = hostGroups
	}

	if !m.Certificate.IsNull() && !m.Certificate.IsUnknown() {
		diags.Append(m.Certificate.As(ctx, &currentCertificate, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return diags
		}
	}

	certificateObj, certificateDiags := flattenCertificate(ctx, currentCertificate, exclusion.Certificate)
	diags.Append(certificateDiags...)
	if diags.HasError() {
		return diags
	}
	m.Certificate = certificateObj

	return diags
}

func (r *certificateBasedExclusionResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_certificate_based_exclusion"
}

func (r *certificateBasedExclusionResource) Configure(
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

func (r *certificateBasedExclusionResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Certificate Based Exclusion",
			"A certificate based exclusion defines a machine learning exclusion scoped to a certificate and either all hosts or specific host groups.",
			certificateBasedExclusionRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier of the certificate based exclusion.",
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
				MarkdownDescription: "Display name of the certificate based exclusion.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional description of the certificate based exclusion.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional comment stored with the certificate based exclusion.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"applied_globally": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to apply the exclusion globally to all hosts. Cannot be set together with `host_groups`.",
			},
			"host_groups": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Host group IDs that should receive the certificate based exclusion. Cannot be set together with `applied_globally`.",
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
						MarkdownDescription: "Certificate validity start timestamp in RFC3339 format.",
						Validators:          []validator.String{fwvalidators.StringNotWhitespace()},
					},
					"valid_to": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Certificate validity end timestamp in RFC3339 format.",
						Validators:          []validator.String{fwvalidators.StringNotWhitespace()},
					},
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
			"modified_on": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp when the exclusion was last modified.",
			},
		},
	}
}

func (r *certificateBasedExclusionResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config CertificateBasedExclusionResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.AppliedGlobally.IsUnknown() || config.HostGroups.IsUnknown() || config.Certificate.IsUnknown() {
		return
	}

	hostGroupCount := 0
	if !config.HostGroups.IsNull() {
		hostGroupCount = len(config.HostGroups.Elements())
	}

	if err := validateTargetingMode(config.AppliedGlobally.ValueBool(), hostGroupCount); err != nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("applied_globally"),
			"Invalid Configuration",
			err.Error(),
		)
	}

	if config.Certificate.IsNull() {
		return
	}

	var certificate certificateModel
	resp.Diagnostics.Append(config.Certificate.As(ctx, &certificate, basetypes.ObjectAsOptions{})...)
	if resp.Diagnostics.HasError() {
		return
	}

	validateCertificateModel(path.Root("certificate"), certificate, &resp.Diagnostics)
}

func (r *certificateBasedExclusionResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan CertificateBasedExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	certificateRequest, certificateDiags := expandCertificateRequest(ctx, plan.Certificate)
	resp.Diagnostics.Append(certificateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	hostGroups, hostGroupDiags := expandHostGroups(ctx, plan.HostGroups)
	resp.Diagnostics.Append(hostGroupDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createRequest := &models.APICertBasedExclusionsCreateReqV1{
		Exclusions: []*models.APICertBasedExclusionCreateReqV1{
			{
				AppliedGlobally: plan.AppliedGlobally.ValueBool(),
				Certificate:     certificateRequest,
				Comment:         plan.Comment.ValueString(),
				Description:     plan.Description.ValueString(),
				HostGroups:      hostGroups,
				Name:            plan.Name.ValueStringPointer(),
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
			certificateBasedExclusionRequiredScopes,
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

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, res.Payload.Resources[0])...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *certificateBasedExclusionResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state CertificateBasedExclusionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exclusion, diags := getCertificateBasedExclusion(ctx, r.client, state.ID.ValueString())
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

func (r *certificateBasedExclusionResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan CertificateBasedExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	certificateRequest, certificateDiags := expandCertificateRequest(ctx, plan.Certificate)
	resp.Diagnostics.Append(certificateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	hostGroups, hostGroupDiags := expandHostGroups(ctx, plan.HostGroups)
	resp.Diagnostics.Append(hostGroupDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateRequest := &models.APICertBasedExclusionsUpdateReqV1{
		Exclusions: []*models.APICertBasedExclusionUpdateReqV1{
			{
				AppliedGlobally: plan.AppliedGlobally.ValueBool(),
				Certificate:     certificateRequest,
				Comment:         plan.Comment.ValueString(),
				Description:     plan.Description.ValueString(),
				HostGroups:      hostGroups,
				ID:              plan.ID.ValueStringPointer(),
				Name:            plan.Name.ValueString(),
			},
		},
	}

	params := certificate_based_exclusions.NewCbExclusionsUpdateV1ParamsWithContext(ctx)
	params.SetBody(updateRequest)

	res, err := r.client.CertificateBasedExclusions.CbExclusionsUpdateV1(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Update,
			err,
			certificateBasedExclusionRequiredScopes,
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

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, res.Payload.Resources[0])...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *certificateBasedExclusionResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state CertificateBasedExclusionResourceModel
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
			certificateBasedExclusionRequiredScopes,
			tferrors.WithNotFoundDetail(fmt.Sprintf("Certificate based exclusion with ID %s was not found.", state.ID.ValueString())),
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

func (r *certificateBasedExclusionResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func validateTargetingMode(appliedGlobally bool, hostGroupCount int) error {
	switch {
	case appliedGlobally && hostGroupCount > 0:
		return fmt.Errorf("cannot specify both applied_globally=true and host_groups; use either applied_globally=true for global exclusions or provide specific host_groups")
	case !appliedGlobally && hostGroupCount == 0:
		return fmt.Errorf("must specify either applied_globally=true or provide host_groups; the exclusion must target either all host groups or specific ones")
	default:
		return nil
	}
}

func validateCertificateModel(basePath path.Path, certificate certificateModel, diags *diag.Diagnostics) {
	validateCertificateDate(basePath.AtName("valid_from"), certificate.ValidFrom, diags)
	validateCertificateDate(basePath.AtName("valid_to"), certificate.ValidTo, diags)
}

func validateCertificateDate(attributePath path.Path, value types.String, diags *diag.Diagnostics) {
	if value.IsNull() || value.IsUnknown() {
		return
	}

	if _, err := strfmt.ParseDateTime(value.ValueString()); err != nil {
		diags.AddAttributeError(
			attributePath,
			"Invalid Certificate Timestamp",
			fmt.Sprintf("Expected an RFC3339 timestamp, got %q: %s", value.ValueString(), err),
		)
	}
}

func flattenCertificate(
	ctx context.Context,
	currentCertificate certificateModel,
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
		ValidFrom:  planAwareDateTimeValue(currentCertificate.ValidFrom, apiCertificate.ValidFrom),
		ValidTo:    planAwareDateTimeValue(currentCertificate.ValidTo, apiCertificate.ValidTo),
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

	validFrom, err := strfmt.ParseDateTime(certificate.ValidFrom.ValueString())
	if err != nil {
		diags.AddError("Invalid certificate valid_from", err.Error())
		return nil, diags
	}

	validTo, err := strfmt.ParseDateTime(certificate.ValidTo.ValueString())
	if err != nil {
		diags.AddError("Invalid certificate valid_to", err.Error())
		return nil, diags
	}

	return &models.APICertificateReqV1{
		Issuer:     certificate.Issuer.ValueStringPointer(),
		Serial:     certificate.Serial.ValueStringPointer(),
		Subject:    certificate.Subject.ValueStringPointer(),
		Thumbprint: certificate.Thumbprint.ValueStringPointer(),
		ValidFrom:  &validFrom,
		ValidTo:    &validTo,
	}, diags
}

func expandHostGroups(ctx context.Context, hostGroups types.Set) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	if hostGroups.IsNull() || hostGroups.IsUnknown() {
		return nil, diags
	}

	var ids []string
	diags.Append(hostGroups.ElementsAs(ctx, &ids, false)...)
	return ids, diags
}

func dateTimeValue(value strfmt.DateTime) types.String {
	if (&value).IsZero() {
		return types.StringNull()
	}
	return types.StringValue(value.String())
}

func planAwareDateTimeValue(planned types.String, value *strfmt.DateTime) types.String {
	if value == nil || value.IsZero() {
		return types.StringNull()
	}

	if !planned.IsNull() && !planned.IsUnknown() {
		plannedDateTime, err := strfmt.ParseDateTime(planned.ValueString())
		if err == nil && time.Time(plannedDateTime).Equal(time.Time(*value)) {
			return planned
		}
	}

	return types.StringValue(value.String())
}
