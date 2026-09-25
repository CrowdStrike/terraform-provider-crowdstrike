package fusionsoar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/workflows"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/runtime"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &fusionWorkflowResource{}
	_ resource.ResourceWithConfigure   = &fusionWorkflowResource{}
	_ resource.ResourceWithImportState = &fusionWorkflowResource{}
)

var requiredScopes = []scopes.Scope{
	{
		Name:  "Workflow",
		Read:  true,
		Write: true,
	},
}

// NewFusionWorkflowResource creates a new Fusion SOAR workflow resource.
func NewFusionWorkflowResource() resource.Resource {
	return &fusionWorkflowResource{}
}

type fusionWorkflowResource struct {
	client *client.CrowdStrikeAPISpecification
}

type fusionWorkflowResourceModel struct {
	ID         types.String    `tfsdk:"id"`
	Definition definitionValue `tfsdk:"definition"`
	Enabled    types.Bool      `tfsdk:"enabled"`
}

// remoteWorkflow is a workflow as stored by the API.
type remoteWorkflow struct {
	definition          string
	enabled             bool
	hasValidationErrors bool
}

func (m *fusionWorkflowResourceModel) wrap(workflow remoteWorkflow) {
	m.Definition = newDefinitionValue(workflow.definition)
	m.Enabled = types.BoolValue(workflow.enabled)
}

func (r *fusionWorkflowResource) Configure(
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

func (r *fusionWorkflowResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_fusion_soar_workflow"
}

func (r *fusionWorkflowResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Fusion SOAR",
			"Manages a Falcon Fusion SOAR workflow. The workflow is defined by a YAML document in the format the Falcon console exports, so the easiest way to author one is to build it in the console, export it, and pass the file to `definition`. Only the keys set in `definition` are managed: keys the API adds, and changes made outside Terraform to keys the configuration does not set, are not reported as drift. The API sets the trigger's `name` and each action's `default_name` itself, so values given for them are ignored. The API drops keys it does not recognize, so a misspelled key fails the apply with the path of the key that was dropped. A definition exported from another CID can reference activities and plugin configurations that do not exist in this CID; the workflow is then saved with validation errors and cannot be enabled.",
			requiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the workflow.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"definition": schema.StringAttribute{
				CustomType:          definitionType{},
				Required:            true,
				MarkdownDescription: "The workflow definition as a YAML document, in the format produced by exporting a workflow from the Falcon console. It must set a top-level `name`, which must be unique in the CID. Renaming the workflow updates it in place. Actions should set `version_constraint`; the API treats an omitted constraint as `~0`.",
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Whether the workflow is enabled and runs when its trigger fires. A workflow with validation errors cannot be enabled. Defaults to `false`.",
			},
		},
	}
}

func (r *fusionWorkflowResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan fusionWorkflowResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	definition := plan.Definition.ValueString()

	params := workflows.NewWorkflowDefinitionsImportParamsWithContext(ctx).
		WithDataFile(runtime.NamedReader("workflow.yaml", strings.NewReader(definition)))

	res, err := r.client.Workflows.WorkflowDefinitionsImport(params)
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

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil || res.Payload.Resources[0].ID == "" {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	plan.ID = types.StringValue(res.Payload.Resources[0].ID)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "workflow_id", plan.ID.ValueString())
	tflog.Debug(ctx, "Imported workflow definition")

	// Import always creates the workflow disabled.
	if plan.Enabled.ValueBool() {
		resp.Diagnostics.Append(r.setEnabled(ctx, tferrors.Create, plan.ID.ValueString(), true)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(r.refresh(ctx, tferrors.Create, &plan, &resp.State)...)
}

func (r *fusionWorkflowResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state fusionWorkflowResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	workflow, diags := r.getWorkflow(ctx, tferrors.Read, state.ID.ValueString())
	if tferrors.HasNotFoundError(diags) {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.wrap(*workflow)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *fusionWorkflowResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan, state fusionWorkflowResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := plan.ID.ValueString()
	ctx = tflog.SetField(ctx, "workflow_id", id)

	// Every update creates a new workflow version, so skip it when only enabled changed.
	if !plan.Definition.Equal(state.Definition) {
		resp.Diagnostics.Append(r.updateDefinition(ctx, id, plan.Definition.ValueString(), false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		tflog.Debug(ctx, "Updated workflow definition")

		// Record the new definition so it is kept if changing the enabled state fails.
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("definition"), plan.Definition)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	if !plan.Enabled.Equal(state.Enabled) {
		resp.Diagnostics.Append(r.setEnabled(ctx, tferrors.Update, id, plan.Enabled.ValueBool())...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(r.refresh(ctx, tferrors.Update, &plan, &resp.State)...)
}

func (r *fusionWorkflowResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state fusionWorkflowResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	res, err := deleteWorkflow(ctx, r.client, state.ID.ValueString())
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, requiredScopes)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	if res != nil && res.Payload != nil {
		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Delete, res.Payload.Errors); diag != nil {
			resp.Diagnostics.Append(diag)
		}
	}
}

func (r *fusionWorkflowResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// refresh reads the workflow back after a write and stores it in state. It
// reports an error when the stored definition does not contain a configured
// value, which happens when the API drops a key it does not recognize, and a
// warning when the workflow has validation errors.
func (r *fusionWorkflowResource) refresh(
	ctx context.Context,
	operation tferrors.Operation,
	model *fusionWorkflowResourceModel,
	state *tfsdk.State,
) diag.Diagnostics {
	var diags diag.Diagnostics

	id := model.ID.ValueString()
	configured := model.Definition.ValueString()

	workflow, readDiags := r.getWorkflow(ctx, operation, id)
	diags.Append(readDiags...)
	if diags.HasError() {
		return diags
	}

	mismatch, err := definitionDiff(configured, workflow.definition)
	switch {
	case err != nil:
		diags.AddAttributeError(
			path.Root("definition"),
			fmt.Sprintf("Failed to %s: definition not applied", operation),
			fmt.Sprintf("The workflow definition returned by the API could not be compared with the configured definition: %s", err),
		)
	case mismatch != nil:
		diags.AddAttributeError(
			path.Root("definition"),
			fmt.Sprintf("Failed to %s: definition not applied", operation),
			fmt.Sprintf("%s\n\nThe workflow was saved as the API stored it.", mismatch.detail()),
		)
	case workflow.hasValidationErrors:
		diags.Append(r.validationWarning(ctx, id, configured))
	}

	model.wrap(*workflow)
	diags.Append(state.Set(ctx, model)...)
	return diags
}

// validationWarning builds a warning for a workflow the API saved with
// validation errors. The import endpoint saves such definitions without
// reporting why, so the definition is re-submitted as a validate-only update
// to recover the reason when the API provides one.
func (r *fusionWorkflowResource) validationWarning(ctx context.Context, id, definition string) diag.Diagnostic {
	detail := "The workflow was saved with validation errors, so it cannot be enabled until they are fixed. Open the workflow in the Falcon console to see the errors."

	for _, d := range r.updateDefinition(ctx, id, definition, true).Errors() {
		detail += "\n\n" + d.Detail()
	}

	return diag.NewAttributeWarningDiagnostic(path.Root("definition"), "Workflow has validation errors", detail)
}

// updateDefinition replaces the workflow definition. With validateOnly set, the
// API validates the definition without saving it.
func (r *fusionWorkflowResource) updateDefinition(ctx context.Context, id, definition string, validateOnly bool) diag.Diagnostics {
	var diags diag.Diagnostics

	body, err := definitionWithID(definition, id)
	if err != nil {
		diags.AddAttributeError(path.Root("definition"), "Invalid Workflow Definition", err.Error())
		return diags
	}

	params := workflows.NewWorkflowDefinitionsUpdateParamsWithContext(ctx).
		WithValidateOnly(&validateOnly)

	res, err := r.client.Workflows.WorkflowDefinitionsUpdate(params, withDefinitionBody(body))
	if err != nil {
		// The API answers 404 both for an unknown workflow and for a definition
		// that references an unknown activity, so report its messages instead
		// of a generic not-found error.
		var notFound *workflows.WorkflowDefinitionsUpdateNotFound
		if errors.As(err, &notFound) && notFound.Payload != nil {
			if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, notFound.Payload.Errors); diag != nil {
				diags.Append(diag)
				return diags
			}
		}
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, requiredScopes))
		return diags
	}

	if res != nil && res.Payload != nil {
		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, res.Payload.Errors); diag != nil {
			diags.Append(diag)
		}
	}

	return diags
}

// setEnabled enables or disables the workflow.
func (r *fusionWorkflowResource) setEnabled(ctx context.Context, operation tferrors.Operation, id string, enabled bool) diag.Diagnostics {
	var diags diag.Diagnostics

	action := "disable"
	if enabled {
		action = "enable"
	}

	params := workflows.NewWorkflowDefinitionsActionParamsWithContext(ctx).
		WithActionName(action).
		WithBody(&models.ClientActionRequest{Ids: []string{id}})

	ok, accepted, err := r.client.Workflows.WorkflowDefinitionsAction(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(operation, err, requiredScopes))
		return diags
	}

	// The API reports why a workflow cannot be enabled, such as a missing
	// plugin configuration, as payload errors on a 200 response.
	var payload *models.DefinitionsDefinitionEntitiesResponse
	switch {
	case ok != nil:
		payload = ok.Payload
	case accepted != nil:
		payload = accepted.Payload
	}
	if payload != nil {
		if diag := tferrors.NewDiagnosticFromPayloadErrors(operation, payload.Errors); diag != nil {
			diags.Append(diag)
			return diags
		}
	}

	tflog.Debug(ctx, "Changed workflow enabled state", map[string]any{"action": action})
	return diags
}

// getWorkflow reads a workflow's metadata and YAML definition.
func (r *fusionWorkflowResource) getWorkflow(ctx context.Context, operation tferrors.Operation, id string) (*remoteWorkflow, diag.Diagnostics) {
	var diags diag.Diagnostics
	notFoundDetail := fmt.Sprintf("Workflow %s was not found during %s.", id, operation)

	summaries, err := queryDefinitions(ctx, r.client, fmt.Sprintf("id:'%s'", id))
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(operation, err, requiredScopes))
		return nil, diags
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(operation, summaries.Errors); diag != nil {
		diags.Append(diag)
		return nil, diags
	}

	// The combined endpoint returns an empty result rather than a 404 for an
	// unknown id.
	if len(summaries.Resources) == 0 {
		diags.Append(tferrors.NewNotFoundError(notFoundDetail))
		return nil, diags
	}
	summary := summaries.Resources[0]

	var definition bytes.Buffer
	params := workflows.NewWorkflowDefinitionsExportParamsWithContext(ctx).
		WithID(id).
		WithSanitize(utils.Addr(false))

	// Export answers 299 instead of 200 when the workflow uses custom trigger or
	// action configuration; both carry the definition.
	_, _, err = r.client.Workflows.WorkflowDefinitionsExport(params, &definition, withYAMLExport())
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(operation, err, requiredScopes, tferrors.WithNotFoundDetail(notFoundDetail)))
		return nil, diags
	}

	return &remoteWorkflow{
		definition:          definition.String(),
		enabled:             summary.Enabled,
		hasValidationErrors: summary.HasValidationErrors,
	}, diags
}

// queryDefinitions lists workflow definitions matching an FQL filter.
func queryDefinitions(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
	filter string,
) (*definitionSummaryResponse, error) {
	var response definitionSummaryResponse
	params := workflows.NewWorkflowDefinitionsCombinedParamsWithContext(ctx).
		WithFilter(filter)

	if _, err := apiClient.Workflows.WorkflowDefinitionsCombined(params, withDefinitionSummaryReader(&response)); err != nil {
		return nil, err
	}

	return &response, nil
}

// deleteWorkflow deletes a workflow and all of its versions.
func deleteWorkflow(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
	id string,
) (*workflows.WorkflowDefinitionsDeleteOK, error) {
	params := workflows.NewWorkflowDefinitionsDeleteParamsWithContext(ctx).
		WithIds([]string{id})

	return apiClient.Workflows.WorkflowDefinitionsDelete(params)
}
