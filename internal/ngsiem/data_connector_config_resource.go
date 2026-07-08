package ngsiem

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &dataConnectorConfigResource{}
	_ resource.ResourceWithConfigure      = &dataConnectorConfigResource{}
	_ resource.ResourceWithImportState    = &dataConnectorConfigResource{}
	_ resource.ResourceWithValidateConfig = &dataConnectorConfigResource{}
)

var dataConnectorConfigRequiredScopes = []scopes.Scope{
	{
		Name:  "NGSIEM Data Connections API",
		Read:  true,
		Write: true,
	},
}

// NewDataConnectorConfigResource creates a new instance of the NG-SIEM connector
// config resource.
func NewDataConnectorConfigResource() resource.Resource {
	return &dataConnectorConfigResource{}
}

type dataConnectorConfigResource struct {
	client *client.CrowdStrikeAPISpecification
}

type dataConnectorConfigResourceModel struct {
	ID          types.String         `tfsdk:"id"`
	ConnectorID types.String         `tfsdk:"connector_id"`
	Name        types.String         `tfsdk:"name"`
	Params      jsontypes.Normalized `tfsdk:"params"`
	Auth        jsontypes.Normalized `tfsdk:"auth"`
}

func (r *dataConnectorConfigResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_ngsiem_data_connector_config"
}

func (r *dataConnectorConfigResource) Configure(
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

func (r *dataConnectorConfigResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Next-Gen SIEM",
			"Manages a reusable NG-SIEM data connector configuration. A config holds the per-connector connection parameters and credentials, is scoped to a single connector, and is referenced by one or more data connections via `config_id`. Editing a config affects every connection that references it.",
			dataConnectorConfigRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The ID of the connector config.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"connector_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The connector catalog ID this config belongs to. Changing this forces a new resource to be created.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the connector config.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"params": schema.StringAttribute{
				Required:            true,
				CustomType:          jsontypes.NormalizedType{},
				MarkdownDescription: "Per-connector connection parameters, encoded as a JSON string. The shape is connector-specific and validated server-side.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"auth": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				CustomType:          jsontypes.NormalizedType{},
				MarkdownDescription: "Per-connector auth blob, encoded as a JSON string. Required for connectors that split credentials out (Okta, Slack, Salesforce, Box, Atlassian, etc.); may be omitted for connectors (like AWS S3) that carry credentials inside `params`. Not returned by the API on read.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *dataConnectorConfigResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan dataConnectorConfigResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	connectorID := plan.ConnectorID.ValueString()

	body, diags := buildConfigRequest(plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createParams := ngsiem.NewExternalCreateConnectorConfigParams().
		WithContext(ctx).
		WithBody(body)

	// The generated reader parses the 201 body into a model whose `id` is a
	// top-level field, but the API nests it under `resources.id`, so the
	// generated Payload.ID is always nil. The reader override captures the real
	// envelope and exposes the created id directly.
	reader := &createConnectorConfigReader{}
	_, err := r.client.Ngsiem.ExternalCreateConnectorConfig(
		createParams,
		withCreateConnectorConfigReader(reader),
	)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create,
			err,
			dataConnectorConfigRequiredScopes,
		))
		return
	}

	if reader.response == nil || reader.response.Resources == nil || reader.response.Resources.ID == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}
	newID := *reader.response.Resources.ID

	// Set the id early so Terraform can track the resource for cleanup even if
	// the subsequent read fails.
	plan.ID = types.StringValue(newID)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	config, diags := r.readConfig(ctx, connectorID, newID)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if config == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	resp.Diagnostics.Append(plan.wrap(*config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dataConnectorConfigResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state dataConnectorConfigResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	config, diags := r.readConfig(ctx, state.ConnectorID.ValueString(), state.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if config == nil {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(state.wrap(*config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dataConnectorConfigResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan dataConnectorConfigResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body, diags := buildConfigRequest(plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	patchParams := ngsiem.NewExternalPatchConnectorConfigParams().
		WithContext(ctx).
		WithIds(plan.ID.ValueString()).
		WithBody(body)

	res, err := r.client.Ngsiem.ExternalPatchConnectorConfig(patchParams)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Update,
			err,
			dataConnectorConfigRequiredScopes,
		))
		return
	}

	if res != nil && res.Payload != nil {
		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, res.Payload.Errors); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	config, diags := r.readConfig(ctx, plan.ConnectorID.ValueString(), plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if config == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	resp.Diagnostics.Append(plan.wrap(*config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dataConnectorConfigResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state dataConnectorConfigResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteParams := ngsiem.NewExternalDeleteConnectorConfigsParams().
		WithContext(ctx).
		WithConnectorID(state.ConnectorID.ValueString()).
		WithIds([]string{state.ID.ValueString()})

	_, err := r.client.Ngsiem.ExternalDeleteConnectorConfigs(deleteParams)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(
			tferrors.Delete,
			err,
			dataConnectorConfigRequiredScopes,
		)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}
}

func (r *dataConnectorConfigResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Read is keyed by connector id, so import needs both the connector id and
	// the config id: "<connector_id>,<config_id>".
	parts := strings.Split(req.ID, ",")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		resp.Diagnostics.AddError(
			"Unexpected Import Identifier",
			fmt.Sprintf("Expected import identifier in the format \"<connector_id>,<config_id>\", got: %q", req.ID),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("connector_id"), strings.TrimSpace(parts[0]))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), strings.TrimSpace(parts[1]))...)
}

// ValidateConfig rejects params supplied already wrapped in a top-level "path"
// key. The resource adds that wrapper on write and expects flat params, so a
// user-supplied wrapper would be double-wrapped; catch it at plan time with a
// clear message rather than a server-side 400.
func (r *dataConnectorConfigResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config dataConnectorConfigResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !utils.IsKnown(config.Params) {
		return
	}

	var params map[string]interface{}
	if err := json.Unmarshal([]byte(config.Params.ValueString()), &params); err != nil {
		return
	}
	if _, ok := params["path"]; ok && len(params) == 1 {
		resp.Diagnostics.AddAttributeError(
			path.Root("params"),
			"Unexpected \"path\" Wrapper in params",
			"Supply the connector fields directly in params; do not wrap them in a top-level \"path\" object. The wrapper is added automatically.",
		)
	}
}

// buildConfigRequest builds the create/patch request body from the plan,
// unmarshalling the params and auth JSON strings into the interface{} fields the
// API expects. Users supply params flat; the API requires them wrapped under a
// "path" key, so the wrapper is added here. The API rejects an empty-object
// auth (`{}`) with a 403, so when auth is not set the field is left as JSON
// null.
func buildConfigRequest(
	plan dataConnectorConfigResourceModel,
) (*models.DataconnectionmanagementCreateConnectorConfigRequest, diag.Diagnostics) {
	var diags diag.Diagnostics

	var params interface{}
	diags.Append(plan.Params.Unmarshal(&params)...)
	if diags.HasError() {
		return nil, diags
	}
	params = map[string]interface{}{"path": params}

	var auth interface{}
	if utils.IsKnown(plan.Auth) {
		diags.Append(plan.Auth.Unmarshal(&auth)...)
		if diags.HasError() {
			return nil, diags
		}
	}

	connectorID := plan.ConnectorID.ValueString()
	name := plan.Name.ValueString()

	return &models.DataconnectionmanagementCreateConnectorConfigRequest{
		ConnectorID: &connectorID,
		Config: &models.DataconnectionmanagementConnectorConfigRequest{
			Name:   &name,
			Params: params,
			Auth:   auth,
		},
	}, diags
}

// readConfig lists the connector's configs and returns the one matching the
// given config id, or nil if not found.
func (r *dataConnectorConfigResource) readConfig(
	ctx context.Context,
	connectorID string,
	configID string,
) (*models.DataconnectionmanagementConfig, diag.Diagnostics) {
	var diags diag.Diagnostics

	configs, listDiags := r.listConfigs(ctx, connectorID, tferrors.Read)
	diags = append(diags, listDiags...)
	if diags.HasError() {
		return nil, diags
	}

	for _, c := range configs {
		if c != nil && c.ID != nil && *c.ID == configID {
			return c, diags
		}
	}

	return nil, diags
}

// listConfigs lists all configs for a connector.
func (r *dataConnectorConfigResource) listConfigs(
	ctx context.Context,
	connectorID string,
	operation tferrors.Operation,
) ([]*models.DataconnectionmanagementConfig, diag.Diagnostics) {
	var diags diag.Diagnostics

	listParams := ngsiem.NewExternalListConnectorConfigsParams().
		WithContext(ctx).
		WithIds(connectorID)

	res, err := r.client.Ngsiem.ExternalListConnectorConfigs(listParams)
	if err != nil {
		diags = append(diags, tferrors.NewDiagnosticFromAPIError(
			operation,
			err,
			dataConnectorConfigRequiredScopes,
		))
		return nil, diags
	}

	if res == nil || res.Payload == nil {
		diags = append(diags, tferrors.NewEmptyResponseError(operation))
		return nil, diags
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(operation, res.Payload.Errors); diag != nil {
		diags = append(diags, diag)
		return nil, diags
	}

	return res.Payload.Resources, diags
}

// wrap converts the API model into the Terraform model.
//
// The API returns params flat (the object the request stored under "path" is
// returned at the top level), which is the shape users supply, so params is
// stored as-is. Secrets stored inside params read back as the literal
// "[SECRET]"; those keys are restored from the prior params (state on read, plan
// on create/update) so they do not drift. auth and connector_id are not echoed
// by the API and are preserved from prior state/config.
func (m *dataConnectorConfigResourceModel) wrap(
	config models.DataconnectionmanagementConfig,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = flex.StringPointerToFramework(config.ID)
	m.Name = flex.StringPointerToFramework(config.Name)

	params, wrapDiags := normalizeParams(config.Params, m.Params)
	diags = append(diags, wrapDiags...)
	if diags.HasError() {
		return diags
	}

	if !params.IsNull() {
		m.Params = params
	}

	return diags
}

// secretRedaction is the placeholder the API returns for secret values stored
// inside params; the real value is never echoed back.
const secretRedaction = "[SECRET]"

// normalizeParams encodes the flat params object returned by the API as a JSON
// string, matching the flat shape users supply. Any key the API redacts as
// "[SECRET]" is restored from prior (the params value held in state/plan before
// this read) so secret-in-params connectors do not drift. When prior holds no
// value for a redacted key (e.g. on import) the redaction is left as-is.
func normalizeParams(params interface{}, prior jsontypes.Normalized) (jsontypes.Normalized, diag.Diagnostics) {
	var diags diag.Diagnostics

	if params == nil {
		return jsontypes.NewNormalizedNull(), diags
	}

	paramsMap, ok := params.(map[string]interface{})
	if !ok {
		// Unexpected shape; marshal as-is so the value round-trips.
		b, err := json.Marshal(params)
		if err != nil {
			diags.AddError(
				"Unable to Encode params",
				fmt.Sprintf("Could not marshal the params returned by the API: %s", err.Error()),
			)
			return jsontypes.NewNormalizedNull(), diags
		}
		return jsontypes.NewNormalizedValue(string(b)), diags
	}

	priorParams := priorParamsMap(prior)
	for k, v := range paramsMap {
		if s, ok := v.(string); ok && s == secretRedaction {
			if pv, ok := priorParams[k]; ok {
				paramsMap[k] = pv
			}
		}
	}

	b, err := json.Marshal(paramsMap)
	if err != nil {
		diags.AddError(
			"Unable to Encode params",
			fmt.Sprintf("Could not marshal the params returned by the API: %s", err.Error()),
		)
		return jsontypes.NewNormalizedNull(), diags
	}

	return jsontypes.NewNormalizedValue(string(b)), diags
}

// priorParamsMap decodes a prior params value into a map so redacted secrets can
// be restored key by key. It returns nil when prior is null/unknown (e.g. on
// import) or is not a JSON object.
func priorParamsMap(prior jsontypes.Normalized) map[string]interface{} {
	if !utils.IsKnown(prior) {
		return nil
	}

	var m map[string]interface{}
	if err := json.Unmarshal([]byte(prior.ValueString()), &m); err != nil {
		return nil
	}
	return m
}
