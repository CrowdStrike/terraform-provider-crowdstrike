package ngsiemdataconnection

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &ngsiemDataConnectionResource{}
	_ resource.ResourceWithConfigure      = &ngsiemDataConnectionResource{}
	_ resource.ResourceWithImportState    = &ngsiemDataConnectionResource{}
	_ resource.ResourceWithValidateConfig = &ngsiemDataConnectionResource{}
)

var (
	documentationSection        string         = "Next-Gen SIEM"
	resourceMarkdownDescription string         = "Manages a CrowdStrike Falcon Next-Gen SIEM data connection (data connector), for example an AWS CloudTrail/S3 log source ingested via SQS notifications."
	requiredScopes              []scopes.Scope = []scopes.Scope{
		{Name: "Data connectors (NGSIEM)", Read: true, Write: true},
	}
)

func NewNgsiemDataConnectionResource() resource.Resource {
	return &ngsiemDataConnectionResource{}
}

type ngsiemDataConnectionResource struct {
	client *client.CrowdStrikeAPISpecification
}

type connectorConfigModel struct {
	Name   types.String `tfsdk:"name"`
	Auth   types.String `tfsdk:"auth"`
	Params types.String `tfsdk:"params"`
}

type ngsiemDataConnectionResourceModel struct {
	ID                   types.String          `tfsdk:"id"`
	LastUpdated          types.String          `tfsdk:"last_updated"`
	Name                 types.String          `tfsdk:"name"`
	ConnectorID          types.String          `tfsdk:"connector_id"`
	ConnectorType        types.String          `tfsdk:"connector_type"`
	LogSources           types.List            `tfsdk:"log_sources"`
	Description          types.String          `tfsdk:"description"`
	Parser               types.String          `tfsdk:"parser"`
	VendorName           types.String          `tfsdk:"vendor_name"`
	VendorProductName    types.String          `tfsdk:"vendor_product_name"`
	EnableHostEnrichment types.Bool            `tfsdk:"enable_host_enrichment"`
	EnableUserEnrichment types.Bool            `tfsdk:"enable_user_enrichment"`
	Config               *connectorConfigModel `tfsdk:"config"`
	Status               types.String          `tfsdk:"status"`
	IngestURL            types.String          `tfsdk:"ingest_url"`
}

// wrap maps the fields the API returns on read back into the model. Input-only
// fields that the API does not echo (connector_id, connector_type, log_sources,
// description, enrichment flags, config) are intentionally left untouched so
// they are preserved from plan/state.
func (m *ngsiemDataConnectionResourceModel) wrap(dc models.DataconnectionmanagementDataConnection) {
	m.ID = types.StringPointerValue(dc.ID)
	m.Name = types.StringPointerValue(dc.Name)
	m.Status = types.StringPointerValue(dc.Status)
	m.Parser = types.StringPointerValue(dc.ParserName)
	m.VendorName = types.StringPointerValue(dc.VendorName)
	m.VendorProductName = types.StringPointerValue(dc.VendorProductName)
	if dc.IngestURL != "" {
		m.IngestURL = types.StringValue(dc.IngestURL)
	} else {
		m.IngestURL = types.StringNull()
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
				Computed:            true,
				MarkdownDescription: "Identifier for the Next-Gen SIEM data connection.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp of the last Terraform update of the resource.",
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the data connection.",
			},
			"connector_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Identifier of the connector definition this connection is created from. Changing this forces a new resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"connector_type": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Type of the connector. Changing this forces a new resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"log_sources": schema.ListAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Log source identifiers associated with this data connection.",
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Description of the data connection.",
			},
			"parser": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Parser used to normalize ingested data.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"vendor_name": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Vendor name associated with the data connection.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"vendor_product_name": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Vendor product name associated with the data connection.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"enable_host_enrichment": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Whether host enrichment is enabled for ingested data.",
			},
			"enable_user_enrichment": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Whether user enrichment is enabled for ingested data.",
			},
			"config": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Connector-specific configuration. The shape of `auth` and `params` depends on `connector_type` (for an AWS connector, `params` carries the bucket/SQS/region details).",
				Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Name of the connector configuration.",
					},
					"auth": schema.StringAttribute{
						Optional:            true,
						Sensitive:           true,
						MarkdownDescription: "Authentication settings for the connector, as a JSON-encoded object.",
					},
					"params": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Connector parameters, as a JSON-encoded object.",
					},
				},
			},
			"status": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Current status of the data connection.",
			},
			"ingest_url": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Ingest URL for the data connection, when applicable.",
			},
		},
	}
}

// buildConfigRequest converts the optional config block into the API model,
// decoding the JSON-encoded auth/params strings into their generic forms.
func (r *ngsiemDataConnectionResource) buildConfigRequest(
	cfg *connectorConfigModel,
	diags *diag.Diagnostics,
) *models.DataconnectionmanagementConnectorConfigRequest {
	if cfg == nil {
		return nil
	}
	out := &models.DataconnectionmanagementConnectorConfigRequest{
		Name: cfg.Name.ValueStringPointer(),
	}
	if !cfg.Auth.IsNull() && cfg.Auth.ValueString() != "" {
		var auth interface{}
		if err := json.Unmarshal([]byte(cfg.Auth.ValueString()), &auth); err != nil {
			diags.AddAttributeError(path.Root("config").AtName("auth"), "Invalid JSON in config.auth", err.Error())
			return nil
		}
		out.Auth = auth
	}
	if !cfg.Params.IsNull() && cfg.Params.ValueString() != "" {
		var params interface{}
		if err := json.Unmarshal([]byte(cfg.Params.ValueString()), &params); err != nil {
			diags.AddAttributeError(path.Root("config").AtName("params"), "Invalid JSON in config.params", err.Error())
			return nil
		}
		out.Params = params
	}
	return out
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

	var logSources []string
	resp.Diagnostics.Append(plan.LogSources.ElementsAs(ctx, &logSources, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := &models.DataconnectionmanagementCreateDataConnectionRequest{
		ConnectorID:          plan.ConnectorID.ValueStringPointer(),
		ConnectorType:        plan.ConnectorType.ValueString(),
		Name:                 plan.Name.ValueString(),
		Description:          plan.Description.ValueString(),
		Parser:               plan.Parser.ValueString(),
		VendorName:           plan.VendorName.ValueString(),
		VendorProductName:    plan.VendorProductName.ValueString(),
		EnableHostEnrichment: plan.EnableHostEnrichment.ValueBool(),
		EnableUserEnrichment: plan.EnableUserEnrichment.ValueBool(),
		LogSources:           logSources,
		Config:               r.buildConfigRequest(plan.Config, &resp.Diagnostics),
	}
	if resp.Diagnostics.HasError() {
		return
	}

	res, err := r.client.Ngsiem.ExternalCreateDataConnection(
		ngsiem.NewExternalCreateDataConnectionParamsWithContext(ctx).WithBody(body),
	)
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
	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil || res.Payload.Resources[0].ID == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	plan.ID = types.StringPointerValue(res.Payload.Resources[0].ID)

	if dc := r.read(ctx, plan.ID.ValueString(), tferrors.Create, &resp.Diagnostics); dc != nil {
		plan.wrap(*dc)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// read fetches a single data connection by id, returning nil if not found.
func (r *ngsiemDataConnectionResource) read(
	ctx context.Context,
	id string,
	op tferrors.Operation,
	diags *diag.Diagnostics,
) *models.DataconnectionmanagementDataConnection {
	res, err := r.client.Ngsiem.ExternalGetDataConnectionByID(
		ngsiem.NewExternalGetDataConnectionByIDParamsWithContext(ctx).WithIds([]string{id}),
	)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(op, err, requiredScopes)
		diags.Append(diag)
		return nil
	}
	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		return nil
	}
	if diag := tferrors.NewDiagnosticFromPayloadErrors(op, res.Payload.Errors); diag != nil {
		diags.Append(diag)
		return nil
	}
	return res.Payload.Resources[0]
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

	res, err := r.client.Ngsiem.ExternalGetDataConnectionByID(
		ngsiem.NewExternalGetDataConnectionByIDParamsWithContext(ctx).WithIds([]string{state.ID.ValueString()}),
	)
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

func (r *ngsiemDataConnectionResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan ngsiemDataConnectionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var logSources []string
	resp.Diagnostics.Append(plan.LogSources.ElementsAs(ctx, &logSources, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cfg := r.buildConfigRequest(plan.Config, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	body := &models.DataconnectionmanagementUpdateDataConnectionRequest{
		Name:                 plan.Name.ValueString(),
		Description:          plan.Description.ValueString(),
		Parser:               plan.Parser.ValueString(),
		EnableHostEnrichment: plan.EnableHostEnrichment.ValueBool(),
		EnableUserEnrichment: plan.EnableUserEnrichment.ValueBool(),
		LogSources:           logSources,
		Config:               cfg,
	}

	res, err := r.client.Ngsiem.ExternalUpdateDataConnection(
		ngsiem.NewExternalUpdateDataConnectionParamsWithContext(ctx).
			WithIds(plan.ID.ValueString()).
			WithBody(body),
	)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, requiredScopes))
		return
	}
	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}
	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	if dc := r.read(ctx, plan.ID.ValueString(), tferrors.Update, &resp.Diagnostics); dc != nil {
		plan.wrap(*dc)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
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

	_, err := r.client.Ngsiem.ExternalDeleteDataConnection(
		ngsiem.NewExternalDeleteDataConnectionParamsWithContext(ctx).WithIds(state.ID.ValueString()),
	)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, requiredScopes)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}
}

func (r *ngsiemDataConnectionResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *ngsiemDataConnectionResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var data ngsiemDataConnectionResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.Config != nil {
		if !data.Config.Auth.IsNull() && !data.Config.Auth.IsUnknown() {
			var v interface{}
			if err := json.Unmarshal([]byte(data.Config.Auth.ValueString()), &v); err != nil {
				resp.Diagnostics.AddAttributeError(path.Root("config").AtName("auth"), "Invalid JSON", "config.auth must be a JSON-encoded object: "+err.Error())
			}
		}
		if !data.Config.Params.IsNull() && !data.Config.Params.IsUnknown() {
			var v interface{}
			if err := json.Unmarshal([]byte(data.Config.Params.ValueString()), &v); err != nil {
				resp.Diagnostics.AddAttributeError(path.Root("config").AtName("params"), "Invalid JSON", "config.params must be a JSON-encoded object: "+err.Error())
			}
		}
	}
}
