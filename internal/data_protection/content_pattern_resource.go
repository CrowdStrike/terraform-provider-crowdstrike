package dataprotection

import (
	"context"
	"fmt"
	"regexp"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &dataProtectionContentPatternResource{}
	_ resource.ResourceWithConfigure      = &dataProtectionContentPatternResource{}
	_ resource.ResourceWithImportState    = &dataProtectionContentPatternResource{}
	_ resource.ResourceWithValidateConfig = &dataProtectionContentPatternResource{}
)

var contentPatternResourceRequiredScopes = []scopes.Scope{
	{Name: "Data Protection", Read: true, Write: true},
}

func NewDataProtectionContentPatternResource() resource.Resource {
	return &dataProtectionContentPatternResource{}
}

type dataProtectionContentPatternResource struct {
	client *client.CrowdStrikeAPISpecification
}

type dataProtectionContentPatternResourceModel struct {
	ID                types.String `tfsdk:"id"`
	LastUpdated       types.String `tfsdk:"last_updated"`
	Name              types.String `tfsdk:"name"`
	Description       types.String `tfsdk:"description"`
	Regex             types.String `tfsdk:"regex"`
	MinMatchThreshold types.Int32  `tfsdk:"min_match_threshold"`
}

func (r *dataProtectionContentPatternResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_dataprotection_content_pattern"
}

func (r *dataProtectionContentPatternResource) Configure(
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

func (r *dataProtectionContentPatternResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Data Protection",
			"A content pattern defines custom regex-based patterns to detect sensitive data.",
			contentPatternResourceRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier of the content pattern.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the content pattern.",
				Required:    true,
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},

			"regex": schema.StringAttribute{
				Description: "Regular expression pattern to match against content.",
				Required:    true,
			},
			"min_match_threshold": schema.Int32Attribute{
				Description: "Minimum number of matches required for detection (must be >= 1).",
				Required:    true,
				Validators: []validator.Int32{
					int32validator.AtLeast(1),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of the content pattern.",
				Optional:    true,
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
				// Backend API bug: description cannot be cleared once set, so require replacement
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIf(func(ctx context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
						if req.State.Raw.IsNull() {
							return
						}

						var stateValue types.String
						diags := req.State.GetAttribute(ctx, req.Path, &stateValue)
						if diags.HasError() {
							return
						}

						// If the field was previously set and is now being cleared, require replacement
						if !stateValue.IsNull() && stateValue.ValueString() != "" {
							if req.ConfigValue.IsNull() || req.ConfigValue.ValueString() == "" {
								resp.RequiresReplace = true
							}
						}
					}, "Requires replacement if cleared once set (backend API limitation)", "Requires replacement if cleared once set (backend API limitation)"),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
		},
	}
}

func (r *dataProtectionContentPatternResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan dataProtectionContentPatternResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createRequest := &models.APIContentPatternCreateRequestV1{
		Name:              plan.Name.ValueString(),
		Description:       flex.FrameworkToStringPointer(plan.Description),
		MinMatchThreshold: plan.MinMatchThreshold.ValueInt32Pointer(),
		Regexes:           []string{plan.Regex.ValueString()},
		Category:          utils.Addr("Custom"),
		Region:            utils.Addr("ALL"),
	}

	params := data_protection_configuration.NewEntitiesContentPatternCreateParams().
		WithContext(ctx).
		WithBody(createRequest)

	res, err := r.client.DataProtectionConfiguration.EntitiesContentPatternCreate(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create,
			err,
			contentPatternResourceRequiredScopes,
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
	plan.wrap(*res.Payload.Resources[0])
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dataProtectionContentPatternResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state dataProtectionContentPatternResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := data_protection_configuration.NewEntitiesContentPatternGetParams().
		WithContext(ctx).
		WithIds([]string{state.ID.ValueString()})

	res, err := r.client.DataProtectionConfiguration.EntitiesContentPatternGet(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(
			tferrors.Read,
			err,
			contentPatternResourceRequiredScopes,
		)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	state.wrap(*res.Payload.Resources[0])
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dataProtectionContentPatternResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan dataProtectionContentPatternResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateRequest := &models.APIContentPatternUpdateRequestV1{
		ID:                utils.Addr(plan.ID.ValueString()),
		Name:              plan.Name.ValueString(),
		Description:       flex.FrameworkToStringPointer(plan.Description),
		MinMatchThreshold: plan.MinMatchThreshold.ValueInt32Pointer(),
		Regexes:           []string{plan.Regex.ValueString()},
		Category:          utils.Addr("Custom"),
		Region:            utils.Addr("ALL"),
	}

	params := data_protection_configuration.NewEntitiesContentPatternPatchParams().
		WithContext(ctx).
		WithID(plan.ID.ValueString()).
		WithBody(updateRequest)

	res, err := r.client.DataProtectionConfiguration.EntitiesContentPatternPatch(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Update,
			err,
			contentPatternResourceRequiredScopes,
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
	plan.wrap(*res.Payload.Resources[0])
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dataProtectionContentPatternResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state dataProtectionContentPatternResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := data_protection_configuration.NewEntitiesContentPatternDeleteParams().
		WithContext(ctx).
		WithIds([]string{state.ID.ValueString()})

	_, err := r.client.DataProtectionConfiguration.EntitiesContentPatternDelete(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(
			tferrors.Delete,
			err,
			contentPatternResourceRequiredScopes,
		)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}
}

func (r *dataProtectionContentPatternResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *dataProtectionContentPatternResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config dataProtectionContentPatternResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.Regex.IsNull() && !config.Regex.IsUnknown() {
		regexStr := config.Regex.ValueString()
		if _, err := regexp.Compile(regexStr); err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("regex"),
				"Invalid Regular Expression",
				fmt.Sprintf("The provided regex pattern is invalid: %s", err.Error()),
			)
		}
	}
}

// wrap converts the API model to the Terraform model.
func (m *dataProtectionContentPatternResourceModel) wrap(
	pattern models.APIContentPatternV1,
) {
	m.ID = flex.StringPointerToFramework(pattern.ID)
	m.Name = flex.StringValueToFramework(pattern.Name)
	m.Description = flex.StringPointerToFramework(pattern.Description)

	var regex string
	if len(pattern.Regexes) > 0 {
		regex = pattern.Regexes[0]
	}
	m.Regex = flex.StringValueToFramework(regex)

	m.MinMatchThreshold = flex.Int32PointerToFramework(pattern.MinMatchThreshold)
}
