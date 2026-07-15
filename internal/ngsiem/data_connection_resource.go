package ngsiem

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &dataConnectionResource{}
	_ resource.ResourceWithConfigure   = &dataConnectionResource{}
	_ resource.ResourceWithImportState = &dataConnectionResource{}
)

var dataConnectionRequiredScopes = []scopes.Scope{
	{
		Name:  "NGSIEM Data Connections API",
		Read:  true,
		Write: true,
	},
}

// NewDataConnectionResource creates a new NG-SIEM data connection resource.
func NewDataConnectionResource() resource.Resource {
	return &dataConnectionResource{}
}

type dataConnectionResource struct {
	client *client.CrowdStrikeAPISpecification
}

type dataConnectionResourceModel struct {
	ID                       types.String      `tfsdk:"id"`
	Name                     types.String      `tfsdk:"name"`
	ConnectorID              types.String      `tfsdk:"connector_id"`
	Parser                   types.String      `tfsdk:"parser"`
	EnableHostEnrichment     types.Bool        `tfsdk:"enable_host_enrichment"`
	EnableUserEnrichment     types.Bool        `tfsdk:"enable_user_enrichment"`
	Description              types.String      `tfsdk:"description"`
	ConfigID                 types.String      `tfsdk:"config_id"`
	LogSources               types.Set         `tfsdk:"log_sources"`
	Custom                   types.Map         `tfsdk:"custom"`
	Status                   types.String      `tfsdk:"status"`
	ConnectorType            types.String      `tfsdk:"connector_type"`
	VendorName               types.String      `tfsdk:"vendor_name"`
	VendorProductName        types.String      `tfsdk:"vendor_product_name"`
	LastIngested             timetypes.RFC3339 `tfsdk:"last_ingested"`
	LastIngestedVolumeOneDay types.String      `tfsdk:"last_ingested_volume_one_day"`
	IngestURL                types.String      `tfsdk:"ingest_url"`
}

func (r *dataConnectionResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_ngsiem_data_connection"
}

func (r *dataConnectionResource) Configure(
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

func (r *dataConnectionResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Next-Gen SIEM",
			"Manages a single NG-SIEM data connection that ingests logs from an external source into the CrowdStrike Falcon platform. A connection instantiates a connector from the catalog; pull connectors reference a `crowdstrike_ngsiem_data_connector_config` via `config_id`, while push connectors (e.g. HEC) take no config and expose an ingest URL.",
			dataConnectionRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The ID of the data connection.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the data connection.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.LengthAtMost(50),
				},
			},
			"connector_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The connector catalog ID this connection instantiates. Changing this forces a new resource to be created.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"enable_host_enrichment": schema.BoolAttribute{
				Required:            true,
				MarkdownDescription: "Whether to enrich ingested events with host data. Required; the Falcon console defaults this to `true`, but this resource requires an explicit value.",
			},
			"enable_user_enrichment": schema.BoolAttribute{
				Required:            true,
				MarkdownDescription: "Whether to enrich ingested events with user data. Required; the Falcon console defaults this to `true`, but this resource requires an explicit value.",
			},
			"parser": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The parser applied to ingested events. The API requires a parser and does not default one. Use the `crowdstrike_ngsiem_data_connector` data source's `parsers` for the connector's supported parsers; a parser that does not match the connector's event format may not parse correctly.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "A human-readable description of the data connection.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.LengthAtMost(500),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"config_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "ID of a `crowdstrike_ngsiem_data_connector_config` to use for a pull connection.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"log_sources": schema.SetAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Optional log-source tags for the connection.",
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
				},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
			},
			"custom": schema.MapAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Free-form key/value metadata sent to the API. Not returned by the API on read.",
				PlanModifiers: []planmodifier.Map{
					mapplanmodifier.UseStateForUnknown(),
				},
			},
			"status": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The runtime status of the connection (e.g. `Active`, `Idle`, `Pending`).",
			},
			"connector_type": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The connector type, derived from the connector catalog (`Pull` or `Push`).",
			},
			"vendor_name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The vendor name, derived from the connector catalog.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"vendor_product_name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The vendor product name, derived from the connector catalog.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_ingested": schema.StringAttribute{
				Computed:            true,
				CustomType:          timetypes.RFC3339Type{},
				MarkdownDescription: "Timestamp (RFC3339) of the most recent ingestion. Empty until data is ingested.",
			},
			"last_ingested_volume_one_day": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Human-readable volume ingested in the last 24 hours (e.g. `1.23 GB`).",
			},
			"ingest_url": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The HEC ingest URL. Populated for push connections only, and only after an ingest token has been generated for the connection; null for pull connections and before a token exists.",
			},
		},
	}
}

func (r *dataConnectionResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan dataConnectionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createRequest := &models.DataconnectionmanagementCreateDataConnectionRequest{
		ConnectorID:          plan.ConnectorID.ValueStringPointer(),
		Name:                 plan.Name.ValueString(),
		Parser:               plan.Parser.ValueString(),
		EnableHostEnrichment: plan.EnableHostEnrichment.ValueBool(),
		EnableUserEnrichment: plan.EnableUserEnrichment.ValueBool(),
		Description:          plan.Description.ValueString(),
		ConfigID:             plan.ConfigID.ValueString(),
	}

	resp.Diagnostics.Append(r.expandLogSources(ctx, plan.LogSources, &createRequest.LogSources)...)
	resp.Diagnostics.Append(r.expandCustom(ctx, plan.Custom, &createRequest.Custom)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := ngsiem.NewExternalCreateDataConnectionParams().
		WithContext(ctx).
		WithBody(createRequest)

	res, err := r.client.Ngsiem.ExternalCreateDataConnection(
		params,
		withCreateEnrichmentOverride(createRequest),
	)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create,
			err,
			dataConnectionRequiredScopes,
		))
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

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	plan.ID = flex.StringPointerToFramework(res.Payload.Resources[0].ID)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	connection, diags := r.getDataConnection(ctx, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.wrap(*connection)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dataConnectionResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state dataConnectionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := ngsiem.NewExternalGetDataConnectionByIDParams().
		WithContext(ctx).
		WithIds([]string{state.ID.ValueString()})

	res, err := r.client.Ngsiem.ExternalGetDataConnectionByID(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(
			tferrors.Read,
			err,
			dataConnectionRequiredScopes,
		)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}

	state.wrap(*res.Payload.Resources[0])
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dataConnectionResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan dataConnectionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateRequest := &models.DataconnectionmanagementUpdateDataConnectionRequest{
		Name:                 plan.Name.ValueString(),
		Parser:               plan.Parser.ValueString(),
		EnableHostEnrichment: plan.EnableHostEnrichment.ValueBool(),
		EnableUserEnrichment: plan.EnableUserEnrichment.ValueBool(),
		Description:          plan.Description.ValueString(),
		ConfigID:             plan.ConfigID.ValueString(),
	}

	resp.Diagnostics.Append(r.expandLogSources(ctx, plan.LogSources, &updateRequest.LogSources)...)
	resp.Diagnostics.Append(r.expandCustom(ctx, plan.Custom, &updateRequest.Custom)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := ngsiem.NewExternalUpdateDataConnectionParams().
		WithContext(ctx).
		WithIds(plan.ID.ValueString()).
		WithBody(updateRequest)

	_, err := r.client.Ngsiem.ExternalUpdateDataConnection(
		params,
		withUpdateEnrichmentOverride(updateRequest, plan.ID.ValueString()),
	)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Update,
			err,
			dataConnectionRequiredScopes,
		))
		return
	}

	connection, diags := r.getDataConnection(ctx, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.wrap(*connection)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dataConnectionResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state dataConnectionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := ngsiem.NewExternalDeleteDataConnectionParams().
		WithContext(ctx).
		WithIds(state.ID.ValueString())

	_, err := r.client.Ngsiem.ExternalDeleteDataConnection(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(
			tferrors.Delete,
			err,
			dataConnectionRequiredScopes,
		)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}
}

func (r *dataConnectionResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// getDataConnection reads a single data connection by id and returns the API model.
func (r *dataConnectionResource) getDataConnection(
	ctx context.Context,
	id string,
) (*models.DataconnectionmanagementDataConnection, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := ngsiem.NewExternalGetDataConnectionByIDParams().
		WithContext(ctx).
		WithIds([]string{id})

	res, err := r.client.Ngsiem.ExternalGetDataConnectionByID(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Read,
			err,
			dataConnectionRequiredScopes,
		))
		return nil, diags
	}

	if res == nil || res.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		diags.Append(diag)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func (r *dataConnectionResource) expandLogSources(
	ctx context.Context,
	set types.Set,
	dest *[]string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	if !utils.IsKnown(set) {
		return diags
	}
	*dest = flex.ExpandSetAs[string](ctx, set, &diags)
	return diags
}

func (r *dataConnectionResource) expandCustom(
	ctx context.Context,
	m types.Map,
	dest *map[string]string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	if !utils.IsKnown(m) {
		return diags
	}
	out := make(map[string]string, len(m.Elements()))
	diags.Append(m.ElementsAs(ctx, &out, false)...)
	*dest = out
	return diags
}

// wrap maps the API data connection response onto the Terraform model. Fields
// not echoed by the read API (description, connector_id, enrichment flags,
// log_sources, custom, config_id) are intentionally left untouched so their
// prior plan/state values are preserved.
func (m *dataConnectionResourceModel) wrap(
	connection models.DataconnectionmanagementDataConnection,
) {
	m.ID = flex.StringPointerToFramework(connection.ID)
	m.Name = flex.StringPointerToFramework(connection.Name)
	m.Parser = flex.StringPointerToFramework(connection.ParserName)
	m.ConnectorType = flex.StringPointerToFramework(connection.SourceType)
	m.Status = flex.StringPointerToFramework(connection.Status)
	m.VendorName = flex.StringPointerToFramework(connection.VendorName)
	m.VendorProductName = flex.StringPointerToFramework(connection.VendorProductName)
	m.IngestURL = flex.StringValueToFramework(connection.IngestURL)
	m.LastIngestedVolumeOneDay = flex.StringValueToFramework(connection.LastIngestedVolumeOneDay)
	m.LastIngested = flex.DateTimeValueToFramework(connection.LastIngested)
}
