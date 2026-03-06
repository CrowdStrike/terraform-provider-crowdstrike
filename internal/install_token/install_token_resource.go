package installtoken

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/installation_tokens"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &installTokenResource{}
	_ resource.ResourceWithConfigure   = &installTokenResource{}
	_ resource.ResourceWithImportState = &installTokenResource{}
)

func NewInstallTokenResource() resource.Resource {
	return &installTokenResource{}
}

type installTokenResource struct {
	client *client.CrowdStrikeAPISpecification
}

type installTokenResourceModel struct {
	ID                types.String      `tfsdk:"id"`
	Name              types.String      `tfsdk:"name"`
	ExpiresTimestamp  timetypes.RFC3339 `tfsdk:"expires_timestamp"`
	Revoked           types.Bool        `tfsdk:"revoked"`
	Value             types.String      `tfsdk:"value"`
	Status            types.String      `tfsdk:"status"`
	CreatedTimestamp  timetypes.RFC3339 `tfsdk:"created_timestamp"`
	LastUsedTimestamp timetypes.RFC3339 `tfsdk:"last_used_timestamp"`
	RevokedTimestamp  timetypes.RFC3339 `tfsdk:"revoked_timestamp"`
}

func (r *installTokenResource) Configure(
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
}

func (r *installTokenResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_install_token"
}

func (r *installTokenResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Host Setup and Management",
			"Manages installation tokens in CrowdStrike Falcon. Installation tokens are used to authenticate sensor installations and deployments.",
			apiScopesReadWrite,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The unique identifier of the installation token.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The display name for the installation token.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"expires_timestamp": schema.StringAttribute{
				CustomType:  timetypes.RFC3339Type{},
				Optional:    true,
				Description: "The token's expiration time in RFC-3339 format. If not set, the token never expires. Set to null to reset an existing token to never expire.",
			},
			"revoked": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Set to true to revoke the token, false to restore it. Defaults to false.",
				Default:     booldefault.StaticBool(false),
			},
			"value": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "The actual token value. Marked as sensitive.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "The current status of the token.",
			},
			"created_timestamp": schema.StringAttribute{
				CustomType:  timetypes.RFC3339Type{},
				Computed:    true,
				Description: "When the token was created (RFC-3339 format).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_used_timestamp": schema.StringAttribute{
				CustomType:  timetypes.RFC3339Type{},
				Computed:    true,
				Description: "When the token was last used (RFC-3339 format).",
			},
			"revoked_timestamp": schema.StringAttribute{
				CustomType:  timetypes.RFC3339Type{},
				Computed:    true,
				Description: "When the token was revoked (RFC-3339 format).",
			},
		},
	}
}

func dateTimeToRFC3339(dt *strfmt.DateTime) timetypes.RFC3339 {
	if dt == nil || time.Time(*dt).IsZero() {
		return timetypes.NewRFC3339Null()
	}
	t := time.Time(*dt)
	return timetypes.NewRFC3339TimeValue(t)
}

func (m *installTokenResourceModel) wrap(token *models.APITokenDetailsResourceV1) {
	m.ID = flex.StringPointerToFramework(token.ID)
	m.Name = flex.StringPointerToFramework(token.Label)
	m.Value = flex.StringPointerToFramework(token.Value)
	m.Status = flex.StringPointerToFramework(token.Status)

	if token.Status != nil && *token.Status == "revoked" {
		m.Revoked = types.BoolValue(true)
	} else {
		m.Revoked = types.BoolValue(false)
	}

	m.RevokedTimestamp = dateTimeToRFC3339(token.RevokedTimestamp)
	m.ExpiresTimestamp = dateTimeToRFC3339(token.ExpiresTimestamp)
	m.CreatedTimestamp = dateTimeToRFC3339(token.CreatedTimestamp)
	m.LastUsedTimestamp = dateTimeToRFC3339(token.LastUsedTimestamp)
}

func (r *installTokenResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	tflog.Trace(ctx, "Starting install token create")

	var plan installTokenResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := &models.APITokenCreateRequestV1{
		Label: plan.Name.ValueString(),
		Type:  "customer_managed",
	}

	if !plan.ExpiresTimestamp.IsNull() {
		expiresTime, diags := plan.ExpiresTimestamp.ValueRFC3339Time()
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		createReq.ExpiresTimestamp = strfmt.DateTime(expiresTime)
	}

	tokenParams := installation_tokens.TokensCreateParams{
		Context: ctx,
		Body:    createReq,
	}

	tflog.Debug(ctx, "Calling CrowdStrike API to create install token")
	res, err := r.client.InstallationTokens.TokensCreate(&tokenParams)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create,
			err,
			apiScopesReadWrite,
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

	token := res.Payload.Resources[0]
	plan.wrap(token)

	tflog.Info(ctx, "Successfully created install token", map[string]interface{}{
		"token_id": plan.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *installTokenResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state installTokenResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tokenParams := installation_tokens.TokensReadParams{
		Context: ctx,
		Ids:     []string{state.ID.ValueString()},
	}

	res, err := r.client.InstallationTokens.TokensRead(&tokenParams)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesReadWrite)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	token := res.Payload.Resources[0]
	state.wrap(token)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *installTokenResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	tflog.Trace(ctx, "Starting install token update")

	var plan installTokenResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateReq := &models.APITokenPatchRequestV1{
		Label:   plan.Name.ValueString(),
		Revoked: plan.Revoked.ValueBoolPointer(),
	}

	if !plan.ExpiresTimestamp.IsNull() {
		expiresTime, diags := plan.ExpiresTimestamp.ValueRFC3339Time()
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		updateReq.ExpiresTimestamp = strfmt.DateTime(expiresTime)
	}

	tokenParams := installation_tokens.TokensUpdateParams{
		Context: ctx,
		Body:    updateReq,
		Ids:     []string{plan.ID.ValueString()},
	}

	tflog.Debug(ctx, "Calling CrowdStrike API to update install token")
	res, err := r.client.InstallationTokens.TokensUpdate(&tokenParams)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite))
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

	token := res.Payload.Resources[0]
	plan.wrap(token)

	tflog.Info(ctx, "Successfully updated install token", map[string]interface{}{
		"token_id": plan.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *installTokenResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state installTokenResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tokenParams := installation_tokens.TokensDeleteParams{
		Context: ctx,
		Ids:     []string{state.ID.ValueString()},
	}

	tflog.Debug(ctx, "Calling CrowdStrike API to delete install token")
	_, err := r.client.InstallationTokens.TokensDelete(&tokenParams)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopesReadWrite)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	tflog.Info(ctx, "Successfully deleted install token", map[string]interface{}{
		"token_id": state.ID.ValueString(),
	})
}

func (r *installTokenResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
