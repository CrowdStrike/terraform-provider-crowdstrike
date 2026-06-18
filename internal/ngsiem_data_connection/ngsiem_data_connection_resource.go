package ngsiemdataconnection

import (
	"context"
	"fmt"
	"strings"

	apiclient "github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/runtime"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &ngsiemDataConnectionResource{}
	_ resource.ResourceWithConfigure   = &ngsiemDataConnectionResource{}
	_ resource.ResourceWithImportState = &ngsiemDataConnectionResource{}
)

var (
	documentationSection        string = "Next-Gen SIEM"
	resourceMarkdownDescription string = "Manages a CrowdStrike Next-Gen SIEM data connection: a push-based source that receives data at an ingest URL secured by an ingest token. Use it with any push connector (for example HEC or Cribl); look one up with the `crowdstrike_ngsiem_data_connectors` data source. Pull-based connectors, which fetch from a source and require credentials, are not supported.\n\n" +
		"~> CrowdStrike returns the ingest token only once, when the connection is created, so Terraform keeps it in state; secure your state backend as you would for any secret. `name`, `parser`, `description`, `log_sources` and the enrichment flags update in place; changing `connector_id` replaces the connection and issues a new token."
	requiredScopes []scopes.Scope = apiScopesReadWrite
)

func NewNgsiemDataConnectionResource() resource.Resource {
	return &ngsiemDataConnectionResource{}
}

type ngsiemDataConnectionResource struct {
	client *apiclient.CrowdStrikeAPISpecification
}

type ngsiemDataConnectionResourceModel struct {
	ID                   types.String `tfsdk:"id"`
	ConnectorID          types.String `tfsdk:"connector_id"`
	Name                 types.String `tfsdk:"name"`
	Parser               types.String `tfsdk:"parser"`
	Description          types.String `tfsdk:"description"`
	EnableHostEnrichment types.Bool   `tfsdk:"enable_host_enrichment"`
	EnableUserEnrichment types.Bool   `tfsdk:"enable_user_enrichment"`
	LogSources           types.List   `tfsdk:"log_sources"`
	Status               types.String `tfsdk:"status"`
	IngestURL            types.String `tfsdk:"ingest_url"`
	IngestToken          types.String `tfsdk:"ingest_token"`
	TokenExpiresAt       types.String `tfsdk:"token_expires_at"`
}

// wrap refreshes the fields the read API returns (name, status, ingest_url). name and ingest_url are
// guarded against an empty read so a blank response can't null the Required name or a captured URL.
// parser, the config-only fields, and the write-once token/expiry aren't returned, so aren't written back.
func (m *ngsiemDataConnectionResourceModel) wrap(conn models.DataconnectionmanagementDataConnection) {
	if conn.Name != nil && *conn.Name != "" {
		m.Name = flex.StringPointerToFramework(conn.Name)
	}
	m.Status = flex.StringPointerToFramework(conn.Status)
	if conn.IngestURL != "" {
		m.IngestURL = flex.StringValueToFramework(conn.IngestURL)
	}
}

func (r *ngsiemDataConnectionResource) Configure(
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

func (r *ngsiemDataConnectionResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_ngsiem_data_connection"
}

func (r *ngsiemDataConnectionResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(documentationSection, resourceMarkdownDescription, requiredScopes),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The connection ID assigned by CrowdStrike.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"connector_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the push connector to use (for example the HEC or Cribl connector). Look this up with the `crowdstrike_ngsiem_data_connectors` data source. Changing this forces replacement. Not returned by the read API; supply it via the composite import ID `connector_id:connection_id`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Display name of the data connection. Updated in place (no token rotation).",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"parser": schema.StringAttribute{
				Required:    true,
				Description: "Parser to apply to ingested data. Must be a valid installed parser package name (e.g. `aws-cloudtrail`); generic names like `json` are rejected by the API. Updated in place.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Optional description for the data connection. Set, changed, or cleared in place (clearing sends an explicit empty value, so no replacement and no token rotation). Config-only: the read API does not return it, so out-of-band edits are not surfaced as drift. Note that, unlike the enrichment flags and `log_sources`, the description is always sent on update, so a description set out of band or before import is cleared on the next update unless it is also set in config.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"enable_host_enrichment": schema.BoolAttribute{
				Optional:    true,
				Description: "Enrich ingested third-party events with CrowdStrike host (hostname) entities. Optional and write-only: set it and Terraform manages the flag in place (an explicit `true` or `false` is sent); leave it unset and Terraform omits it from updates, so a value set out of band or before import is preserved. The API never returns it, so an out-of-band change to a managed value is not surfaced as drift.",
			},
			"enable_user_enrichment": schema.BoolAttribute{
				Optional:    true,
				Description: "Enrich ingested third-party events with CrowdStrike user entities. Optional and write-only: set it and Terraform manages the flag in place (an explicit `true` or `false` is sent); leave it unset and Terraform omits it from updates, so a value set out of band or before import is preserved. The API never returns it, so an out-of-band change to a managed value is not surfaced as drift.",
			},
			"log_sources": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Log sources associated with the connection. Set it and Terraform manages the list in place; leave it unset and Terraform omits it from updates, preserving any value set out of band. Only meaningful for connectors that support sub-sources; generic push connectors (e.g. HEC, Cribl) ignore it. Write-only: the API never returns it, so an out-of-band change is not surfaced as drift.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
				},
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "Provisioning status reported by CrowdStrike (e.g. `Pending`, `Active`).",
			},
			"ingest_url": schema.StringAttribute{
				Computed:    true,
				Description: "Ingest URL for this connection.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"ingest_token": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "Ingest token for this connection. CrowdStrike returns it only at creation, so it is not populated on import. If you need a new token, regenerate one for the connection in CrowdStrike.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"token_expires_at": schema.StringAttribute{
				Computed:    true,
				Description: "Expiry timestamp of the ingest token.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *ngsiemDataConnectionResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan ngsiemDataConnectionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Make the computed attributes known (null) before any partial save on an error path.
	plan.Status = types.StringNull()
	plan.IngestURL = types.StringNull()
	plan.IngestToken = types.StringNull()
	plan.TokenExpiresAt = types.StringNull()

	logSources := flex.ExpandListAs[string](ctx, plan.LogSources, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Custom body (see requests.go) so an explicit enable_*_enrichment false isn't dropped by omitempty.
	body := &createDataConnectionBody{
		ConnectorID:          plan.ConnectorID.ValueString(),
		Name:                 plan.Name.ValueString(),
		Parser:               plan.Parser.ValueString(),
		Description:          plan.Description.ValueString(),
		EnableHostEnrichment: plan.EnableHostEnrichment.ValueBool(),
		EnableUserEnrichment: plan.EnableUserEnrichment.ValueBool(),
		LogSources:           logSources,
	}
	createParams := ngsiem.NewExternalCreateDataConnectionParams()
	createParams.Context = ctx

	res, err := r.client.Ngsiem.ExternalCreateDataConnection(createParams, func(op *runtime.ClientOperation) {
		op.Params = bodyOverrideParams{inner: op.Params, body: body}
	})
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, requiredScopes))
		return
	}
	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}
	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}
	// Guard the ID itself: a 200 with a nil/empty ID would persist an untrackable resource and poll
	// the token endpoint with ids="".
	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil ||
		res.Payload.Resources[0].ID == nil || *res.Payload.Resources[0].ID == "" {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	// Persist the ID before any further failable work, so an interrupted create still leaves the
	// connection deletable. (See CONTRIBUTING "Early State Updates".)
	plan.ID = flex.StringPointerToFramework(res.Payload.Resources[0].ID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// CrowdStrike returns the token only at creation, so this is the one chance to record it in state.
	tok, err := waitForIngestToken(ctx, r.client, plan.ID.ValueString())
	if err != nil {
		// The token endpoint's errors aren't gofalcon-typed (custom reader), so append the scopes
		// manually for an actionable permission hint.
		resp.Diagnostics.AddError(
			"Created connection but failed to obtain its ingest token",
			fmt.Sprintf("%s\n\n%s", err.Error(), scopes.GenerateScopeDescription(requiredScopes)),
		)
		return
	}
	applyToken(&plan, tok)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	conn, err := r.getConnection(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, requiredScopes))
		return
	}
	if conn != nil {
		plan.wrap(*conn)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ngsiemDataConnectionResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state ngsiemDataConnectionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	conn, err := r.getConnection(ctx, state.ID.ValueString())
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, requiredScopes)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}
	if conn == nil {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}

	state.wrap(*conn)

	// Warn when there's no ingest token in state (after an import, or a create interrupted before
	// capture). Harmless if the collector is already configured; the warning explains how to get one.
	if state.IngestToken.IsNull() || state.IngestToken.ValueString() == "" {
		resp.Diagnostics.AddWarning(
			"Ingest token is not stored for this data connection",
			fmt.Sprintf("Terraform has no ingest token in state for connection %q (CrowdStrike returns the token "+
				"only at creation, so it isn't populated on import). This is harmless if the connection's collector "+
				"is already configured with its token. If you need a fresh token, regenerate one for this connection "+
				"in CrowdStrike, or recreate the resource with `terraform apply -replace='<resource address>'` to have "+
				"Terraform manage a new one.", state.ID.ValueString()),
		)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ngsiemDataConnectionResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan, state ngsiemDataConnectionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	logSources := flex.ExpandListAs[string](ctx, plan.LogSources, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Custom body (see requests.go) for the cleared-description and omit-when-unset wire shapes.
	body := &updateDataConnectionBody{
		Name:                 plan.Name.ValueString(),
		Parser:               plan.Parser.ValueString(),
		Description:          plan.Description.ValueString(),
		EnableHostEnrichment: plan.EnableHostEnrichment.ValueBoolPointer(),
		EnableUserEnrichment: plan.EnableUserEnrichment.ValueBoolPointer(),
		LogSources:           logSources,
	}
	updateParams := ngsiem.NewExternalUpdateDataConnectionParams()
	updateParams.Context = ctx
	updateParams.Ids = state.ID.ValueString()

	res, err := r.client.Ngsiem.ExternalUpdateDataConnection(updateParams, func(op *runtime.ClientOperation) {
		op.Params = bodyOverrideParams{inner: op.Params, body: body}
	})
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, requiredScopes))
		return
	}
	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}
	// A failure can come back as 200 + populated Errors; surface it instead of saving rejected values.
	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	conn, err := r.getConnection(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, requiredScopes))
		return
	}
	// If the connection can't be re-read, carry the prior status forward so a computed (unknown) status
	// isn't persisted, which Terraform rejects.
	if conn != nil {
		plan.wrap(*conn)
	} else {
		plan.Status = state.Status
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ngsiemDataConnectionResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state ngsiemDataConnectionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteParams := ngsiem.NewExternalDeleteDataConnectionParams()
	deleteParams.Context = ctx
	deleteParams.Ids = state.ID.ValueString()

	res, err := r.client.Ngsiem.ExternalDeleteDataConnection(deleteParams)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, requiredScopes)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return // already deleted
		}
		resp.Diagnostics.Append(diag)
		return
	}
	// A delete can fail with a 200 + populated Errors (e.g. a locked connection); surface it so
	// Terraform doesn't drop a still-live resource from state.
	if res != nil && res.Payload != nil {
		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Delete, res.Payload.Errors); diag != nil {
			resp.Diagnostics.Append(diag)
		}
	}
}

// ImportState parses the composite import ID `connector_id:connection_id`; connector_id is required
// because the read API doesn't return it. The token/expiry aren't populated on import (returned only at
// creation).
func (r *ngsiemDataConnectionResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	connectorID, connectionID, err := parseConnectionImportID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Expected format `connector_id:connection_id`, got: %q. The connector_id is required because "+
				"the read API does not return it.", req.ID),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), connectionID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("connector_id"), connectorID)...)
}

// getConnection returns (nil, nil) when the connection no longer exists so the caller can drop it from
// state. A populated Payload.Errors surfaces as an error, not mistaken for not-found, so a still-existing
// resource is never wrongly removed.
func (r *ngsiemDataConnectionResource) getConnection(ctx context.Context, id string) (*models.DataconnectionmanagementDataConnection, error) {
	params := ngsiem.NewExternalGetDataConnectionByIDParams()
	params.Context = ctx
	params.Ids = []string{id}

	res, err := r.client.Ngsiem.ExternalGetDataConnectionByID(params)
	if err != nil {
		return nil, err
	}
	if res == nil || res.Payload == nil {
		return nil, nil
	}
	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		return nil, fmt.Errorf("%s: %s", diag.Summary(), diag.Detail())
	}
	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		return nil, nil
	}
	return res.Payload.Resources[0], nil
}

func applyToken(m *ngsiemDataConnectionResourceModel, tok ingestToken) {
	m.IngestToken = types.StringValue(tok.Token)
	m.IngestURL = flex.StringValueToFramework(tok.IngestURL)
	m.TokenExpiresAt = flex.StringValueToFramework(tok.ExpiresAt)
}

func parseConnectionImportID(id string) (connectorID, connectionID string, err error) {
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("expected connector_id:connection_id")
	}
	return parts[0], parts[1], nil
}
