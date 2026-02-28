package dataprotection

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
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
	_ resource.Resource                = &dataProtectionSensitivityLabelResource{}
	_ resource.ResourceWithConfigure   = &dataProtectionSensitivityLabelResource{}
	_ resource.ResourceWithImportState = &dataProtectionSensitivityLabelResource{}
)

var sensitivityLabelResourceRequiredScopes = []scopes.Scope{
	{Name: "Data Protection", Read: true, Write: true},
}

func NewDataProtectionSensitivityLabelResource() resource.Resource {
	return &dataProtectionSensitivityLabelResource{}
}

type dataProtectionSensitivityLabelResource struct {
	client *client.CrowdStrikeAPISpecification
}

type dataProtectionSensitivityLabelResourceModel struct {
	ID                     types.String `tfsdk:"id"`
	CID                    types.String `tfsdk:"cid"`
	Name                   types.String `tfsdk:"name"`
	DisplayName            types.String `tfsdk:"display_name"`
	ExternalID             types.String `tfsdk:"external_id"`
	LabelProvider          types.String `tfsdk:"label_provider"`
	PluginsConfigurationID types.String `tfsdk:"plugins_configuration_id"`
	CoAuthoring            types.Bool   `tfsdk:"co_authoring"`
	Synced                 types.Bool   `tfsdk:"synced"`
	CreatedAt              types.String `tfsdk:"created_at"`
	LastUpdated            types.String `tfsdk:"last_updated"`
}

func (r *dataProtectionSensitivityLabelResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_data_protection_sensitivity_label"
}

func (r *dataProtectionSensitivityLabelResource) Configure(
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

func (r *dataProtectionSensitivityLabelResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Data Protection",
			"A sensitivity label manages an external data protection label in CrowdStrike Falcon. The underlying API supports create, read, and delete operations only, so changing any configurable attribute forces replacement.",
			sensitivityLabelResourceRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier of the sensitivity label.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cid": schema.StringAttribute{
				Computed:    true,
				Description: "CID that owns the sensitivity label.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Canonical name of the sensitivity label.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"display_name": schema.StringAttribute{
				Required:    true,
				Description: "Human-readable display name of the sensitivity label.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"external_id": schema.StringAttribute{
				Required:    true,
				Description: "External identifier for the sensitivity label in the upstream label provider.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"label_provider": schema.StringAttribute{
				Required:    true,
				Description: "Source system that provides the sensitivity label.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"plugins_configuration_id": schema.StringAttribute{
				Required:    true,
				Description: "Plugin configuration identifier associated with the sensitivity label provider.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"co_authoring": schema.BoolAttribute{
				Required:    true,
				Description: "Whether co-authoring is enabled for the sensitivity label.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},
			"synced": schema.BoolAttribute{
				Required:    true,
				Description: "Whether the sensitivity label is synchronized from the upstream label provider.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the sensitivity label was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the sensitivity label was last updated in CrowdStrike.",
			},
		},
	}
}

func (r *dataProtectionSensitivityLabelResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan dataProtectionSensitivityLabelResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createRequest := &models.APISensitivityLabelCreateRequestV2{
		CoAuthoring:            plan.CoAuthoring.ValueBoolPointer(),
		DisplayName:            plan.DisplayName.ValueStringPointer(),
		ExternalID:             plan.ExternalID.ValueStringPointer(),
		LabelProvider:          plan.LabelProvider.ValueStringPointer(),
		Name:                   plan.Name.ValueStringPointer(),
		PluginsConfigurationID: plan.PluginsConfigurationID.ValueStringPointer(),
		Synced:                 plan.Synced.ValueBoolPointer(),
	}

	params := data_protection_configuration.NewEntitiesSensitivityLabelCreateV2Params().
		WithContext(ctx).
		WithBody(createRequest)

	res, err := r.client.DataProtectionConfiguration.EntitiesSensitivityLabelCreateV2(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create,
			err,
			sensitivityLabelResourceRequiredScopes,
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

	plan.wrap(*res.Payload.Resources[0])
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dataProtectionSensitivityLabelResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state dataProtectionSensitivityLabelResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := data_protection_configuration.NewEntitiesSensitivityLabelGetV2Params().
		WithContext(ctx).
		WithIds([]string{state.ID.ValueString()})

	res, err := r.client.DataProtectionConfiguration.EntitiesSensitivityLabelGetV2(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(
			tferrors.Read,
			err,
			sensitivityLabelResourceRequiredScopes,
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

	if res.Payload.Resources[0].Deleted != nil && *res.Payload.Resources[0].Deleted {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}

	state.wrap(*res.Payload.Resources[0])
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dataProtectionSensitivityLabelResource) Update(
	_ context.Context,
	_ resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	resp.Diagnostics.AddError(
		"Update Not Supported by CrowdStrike API",
		"The CrowdStrike API does not provide an update operation for data protection sensitivity labels. Changing any configurable attribute requires resource replacement.",
	)
}

func (r *dataProtectionSensitivityLabelResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state dataProtectionSensitivityLabelResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := data_protection_configuration.NewEntitiesSensitivityLabelDeleteV2Params().
		WithContext(ctx).
		WithIds([]string{state.ID.ValueString()})

	_, err := r.client.DataProtectionConfiguration.EntitiesSensitivityLabelDeleteV2(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(
			tferrors.Delete,
			err,
			sensitivityLabelResourceRequiredScopes,
		)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}
}

func (r *dataProtectionSensitivityLabelResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (m *dataProtectionSensitivityLabelResourceModel) wrap(
	label models.APISensitivityLabelV2,
) {
	m.ID = flex.StringPointerToFramework(label.ID)
	m.CID = flex.StringPointerToFramework(label.Cid)
	m.Name = flex.StringPointerToFramework(label.Name)
	m.DisplayName = flex.StringPointerToFramework(label.DisplayName)
	m.ExternalID = flex.StringPointerToFramework(label.ExternalID)
	m.LabelProvider = flex.StringPointerToFramework(label.LabelProvider)
	m.PluginsConfigurationID = flex.StringPointerToFramework(label.PluginsConfigurationID)

	if label.CoAuthoring != nil {
		m.CoAuthoring = types.BoolValue(*label.CoAuthoring)
	} else {
		m.CoAuthoring = types.BoolNull()
	}

	if label.Synced != nil {
		m.Synced = types.BoolValue(*label.Synced)
	} else {
		m.Synced = types.BoolNull()
	}

	if label.Created != nil {
		m.CreatedAt = types.StringValue(label.Created.String())
	} else {
		m.CreatedAt = types.StringNull()
	}

	if label.LastUpdated != nil {
		m.LastUpdated = types.StringValue(label.LastUpdated.String())
	} else {
		m.LastUpdated = types.StringNull()
	}
}
