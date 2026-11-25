package installtoken

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/installation_tokens"
	"github.com/crowdstrike/gofalcon/falcon/client/installation_tokens_settings"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/clientoverrides"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &installTokenSettingsResource{}
	_ resource.ResourceWithConfigure   = &installTokenSettingsResource{}
	_ resource.ResourceWithImportState = &installTokenSettingsResource{}
)

// installTokenSettingsID identifies the CID's installation token settings. The API
// keeps a single set of settings per CID and has no identifier for it.
const installTokenSettingsID = "install_token_settings"

func NewInstallTokenSettingsResource() resource.Resource {
	return &installTokenSettingsResource{}
}

type installTokenSettingsResource struct {
	client *client.CrowdStrikeAPISpecification
}

type installTokenSettingsResourceModel struct {
	ID              types.String `tfsdk:"id"`
	TokensRequired  types.Bool   `tfsdk:"tokens_required"`
	MaxActiveTokens types.Int64  `tfsdk:"max_active_tokens"`
	LastUpdated     types.String `tfsdk:"last_updated"`
}

func (m *installTokenSettingsResourceModel) wrap(settings models.APICustomerSettingsResourceV1) {
	m.ID = types.StringValue(installTokenSettingsID)
	m.TokensRequired = types.BoolPointerValue(settings.TokensRequired)
	m.MaxActiveTokens = types.Int64Value(settings.MaxActiveTokens)
}

func (r *installTokenSettingsResource) Configure(
	ctx context.Context,
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

func (r *installTokenSettingsResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_install_token_settings"
}

func (r *installTokenSettingsResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Host Setup and Management",
			"Manages the installation token settings of a CID, including whether sensor installations require an installation token (Require Tokens). "+
				"A CID has a single set of these settings, so manage them with at most one instance of this resource per CID. "+
				"Destroying this resource sets `tokens_required` to `false` and leaves `max_active_tokens` unchanged.",
			settingsAPIScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the installation token settings. A CID has a single set of these settings, so this is always `install_token_settings`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"tokens_required": schema.BoolAttribute{
				Required:    true,
				Description: "Whether sensor installations in the CID must provide a valid installation token.",
			},
			"max_active_tokens": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "The maximum number of active installation tokens allowed in the CID. If not set, the current limit is kept.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
				Validators: []validator.Int64{
					int64validator.AtLeast(1),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
		},
	}
}

func (r *installTokenSettingsResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan installTokenSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.apply(ctx, &plan, tferrors.Create)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *installTokenSettingsResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state installTokenSettingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	settings, diags := r.read(ctx, tferrors.Read)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.wrap(*settings)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *installTokenSettingsResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan installTokenSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.apply(ctx, &plan, tferrors.Update)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete turns the token requirement off, which is the Falcon default, so that
// removing the resource does not leave sensor installations requiring a token that
// Terraform no longer manages. The token limit is left as it is.
func (r *installTokenSettingsResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	diags := r.update(ctx, &models.APICustomerSettingsPatchRequestV1{TokensRequired: false}, tferrors.Delete)
	if tferrors.HasNotFoundError(diags) {
		return
	}
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reset install token settings to not require tokens")
}

func (r *installTokenSettingsResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// apply writes the planned settings, then reads them back into the plan so state
// reflects what the API stored.
func (r *installTokenSettingsResource) apply(
	ctx context.Context,
	plan *installTokenSettingsResourceModel,
	operation tferrors.Operation,
) diag.Diagnostics {
	body := &models.APICustomerSettingsPatchRequestV1{
		TokensRequired: plan.TokensRequired.ValueBool(),
	}
	if !plan.MaxActiveTokens.IsNull() && !plan.MaxActiveTokens.IsUnknown() {
		body.MaxActiveTokens = plan.MaxActiveTokens.ValueInt64()
	}

	diags := r.update(ctx, body, operation)
	if diags.HasError() {
		return diags
	}

	settings, readDiags := r.read(ctx, operation)
	diags.Append(readDiags...)
	if diags.HasError() {
		return diags
	}

	plan.wrap(*settings)
	plan.LastUpdated = utils.GenerateUpdateTimestamp()

	tflog.Info(ctx, "Successfully applied install token settings", map[string]any{
		"tokens_required":   plan.TokensRequired.ValueBool(),
		"max_active_tokens": plan.MaxActiveTokens.ValueInt64(),
	})

	return diags
}

func (r *installTokenSettingsResource) update(
	ctx context.Context,
	body *models.APICustomerSettingsPatchRequestV1,
	operation tferrors.Operation,
) diag.Diagnostics {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "Calling CrowdStrike API to update install token settings")
	res, err := r.client.InstallationTokensSettings.CustomerSettingsUpdate(
		&installation_tokens_settings.CustomerSettingsUpdateParams{
			Context: ctx,
			Body:    body,
		},
		clientoverrides.SendInstallTokensRequired,
	)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(operation, err, settingsAPIScopes))
		return diags
	}

	if res == nil || res.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(operation))
		return diags
	}

	if payloadDiag := tferrors.NewDiagnosticFromPayloadErrors(operation, res.Payload.Errors); payloadDiag != nil {
		diags.Append(payloadDiag)
	}

	return diags
}

func (r *installTokenSettingsResource) read(
	ctx context.Context,
	operation tferrors.Operation,
) (*models.APICustomerSettingsResourceV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	res, err := r.client.InstallationTokens.CustomerSettingsRead(
		&installation_tokens.CustomerSettingsReadParams{Context: ctx},
	)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(operation, err, settingsAPIScopes))
		return nil, diags
	}

	if res == nil || res.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(operation))
		return nil, diags
	}

	if payloadDiag := tferrors.NewDiagnosticFromPayloadErrors(operation, res.Payload.Errors); payloadDiag != nil {
		diags.Append(payloadDiag)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(operation))
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}
