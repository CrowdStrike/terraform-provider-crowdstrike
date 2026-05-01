package rtrscript

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_admin"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwplanmodifiers "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/planmodifiers"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/retry"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	_ resource.Resource                = &rtrScriptResource{}
	_ resource.ResourceWithConfigure   = &rtrScriptResource{}
	_ resource.ResourceWithImportState = &rtrScriptResource{}
)

var apiScopesReadWrite = []scopes.Scope{
	{Name: "Real Time Response (Admin)", Read: true, Write: true},
}

const contentNotRetrieved = "<COULD NOT RETRIEVE>"

func NewRTRScriptResource() resource.Resource {
	return &rtrScriptResource{}
}

type rtrScriptResource struct {
	client *client.CrowdStrikeAPISpecification
}

type rtrScriptResourceModel struct {
	ID                  types.String      `tfsdk:"id"`
	Name                types.String      `tfsdk:"name"`
	Description         types.String      `tfsdk:"description"`
	Content             types.String      `tfsdk:"content"`
	PlatformName        types.String      `tfsdk:"platform_name"`
	PermissionType      types.String      `tfsdk:"permission_type"`
	CommentsForAuditLog types.String      `tfsdk:"comments_for_audit_log"`
	SHA256              types.String      `tfsdk:"sha256"`
	Size                types.Int64       `tfsdk:"size"`
	CreatedBy           types.String      `tfsdk:"created_by"`
	CreatedTimestamp    timetypes.RFC3339 `tfsdk:"created_timestamp"`
	ModifiedBy          types.String      `tfsdk:"modified_by"`
	ModifiedTimestamp   timetypes.RFC3339 `tfsdk:"modified_timestamp"`
}

func (m *rtrScriptResourceModel) wrap(script *models.EmpowerapiRemoteCommandPutFileV2) {
	m.ID = flex.StringValueToFramework(script.ID)
	m.Name = flex.StringValueToFramework(script.Name)
	m.Description = flex.StringValueToFramework(script.Description)
	m.Content = flex.StringValueToFramework(script.Content)
	m.PermissionType = flex.StringValueToFramework(script.PermissionType)
	m.SHA256 = flex.StringValueToFramework(script.Sha256)
	m.CommentsForAuditLog = flex.StringValueToFramework(script.CommentsForAuditLog)
	m.CreatedBy = flex.StringValueToFramework(script.CreatedBy)
	m.CreatedTimestamp = flex.DateTimePointerToFramework(&script.CreatedTimestamp)
	m.ModifiedBy = flex.StringValueToFramework(script.ModifiedBy)
	m.ModifiedTimestamp = flex.DateTimePointerToFramework(&script.ModifiedTimestamp)

	m.Size = types.Int64PointerValue(script.Size)

	if len(script.Platform) > 0 {
		caser := cases.Title(language.English)
		m.PlatformName = types.StringValue(caser.String(script.Platform[0]))
	} else {
		m.PlatformName = types.StringNull()
	}
}

func (r *rtrScriptResource) Configure(
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
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	r.client = providerConfig.Client
}

func (r *rtrScriptResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_rtr_script"
}

func (r *rtrScriptResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Host Setup and Management",
			"Manages Real Time Response (RTR) custom scripts in CrowdStrike Falcon. RTR scripts allow administrators to upload and manage custom scripts that can be executed on remote hosts during response sessions.",
			apiScopesReadWrite,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The ID of the RTR script.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the RTR script.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.LengthAtMost(255),
				},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The description of the RTR script. Once set, clearing this field requires resource replacement.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.LengthAtMost(4096),
				},
				PlanModifiers: []planmodifier.String{
					fwplanmodifiers.RequiresReplaceIfCleared(
						"Requires replacement if description is cleared once set.",
						"Description cannot be cleared once set via the API, so clearing it requires resource replacement.",
					),
				},
			},
			"content": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The script content. Use Terraform's `file()` function to reference external script files.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"platform_name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The platform the script targets. Valid values: `Windows`, `Mac`, `Linux`.",
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Linux", "Mac"),
				},
			},
			"permission_type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Who can use the script. Valid values: `private` (only the creator), `group` (RTR Admins), `public` (RTR Admins and Active Responders).",
				Validators: []validator.String{
					stringvalidator.OneOf("private", "group", "public"),
				},
			},
			"comments_for_audit_log": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Audit log comment for the change. Once set, clearing this field requires resource replacement.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
				PlanModifiers: []planmodifier.String{
					fwplanmodifiers.RequiresReplaceIfCleared(
						"Requires replacement if comments_for_audit_log is cleared once set.",
						"Comments for audit log cannot be cleared once set via the API, so clearing it requires resource replacement.",
					),
				},
			},
			"sha256": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The SHA-256 hash of the script content.",
			},
			"size": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "The file size of the script in bytes.",
			},
			"created_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who created the script.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_timestamp": schema.StringAttribute{
				CustomType:          timetypes.RFC3339Type{},
				Computed:            true,
				MarkdownDescription: "The timestamp when the script was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"modified_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who last modified the script.",
			},
			"modified_timestamp": schema.StringAttribute{
				CustomType:          timetypes.RFC3339Type{},
				Computed:            true,
				MarkdownDescription: "The timestamp when the script was last modified.",
			},
		},
	}
}

func (r *rtrScriptResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan rtrScriptResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := plan.Name.ValueString()
	content := plan.Content.ValueString()
	platform := []string{strings.ToLower(plan.PlatformName.ValueString())}
	permissionType := plan.PermissionType.ValueString()
	description := plan.Description.ValueString()

	params := real_time_response_admin.NewRTRCreateScriptsV2ParamsWithContext(ctx)
	params.Name = &name
	params.Content = &content
	params.Platform = platform
	params.PermissionType = permissionType
	params.Description = description
	params.CommentsForAuditLog = flex.FrameworkToStringPointer(plan.CommentsForAuditLog)

	res, err := r.client.RealTimeResponseAdmin.RTRCreateScriptsV2(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create, err, apiScopesReadWrite,
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

	plan.ID = flex.StringValueToFramework(res.Payload.Resources[0].ID)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	script, readDiags := getRTRScriptWithContent(ctx, r.client, plan.ID.ValueString())
	resp.Diagnostics.Append(readDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.wrap(script)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *rtrScriptResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state rtrScriptResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	script, readDiags := getRTRScriptWithContent(ctx, r.client, state.ID.ValueString())
	if tferrors.HasNotFoundError(readDiags) {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(readDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.wrap(script)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *rtrScriptResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan rtrScriptResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := plan.ID.ValueString()
	name := plan.Name.ValueString()
	content := plan.Content.ValueString()
	platform := []string{strings.ToLower(plan.PlatformName.ValueString())}
	permissionType := plan.PermissionType.ValueString()

	params := real_time_response_admin.NewRTRUpdateScriptsV2ParamsWithContext(ctx)
	params.ID = id
	params.Name = &name
	params.Content = &content
	params.Platform = platform
	params.PermissionType = &permissionType

	params.Description = flex.FrameworkToStringPointer(plan.Description)
	params.CommentsForAuditLog = flex.FrameworkToStringPointer(plan.CommentsForAuditLog)

	_, err := r.client.RealTimeResponseAdmin.RTRUpdateScriptsV2(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Update, err, apiScopesReadWrite,
		))
		return
	}

	script, readDiags := getRTRScriptWithContent(ctx, r.client, id)
	resp.Diagnostics.Append(readDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.wrap(script)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *rtrScriptResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state rtrScriptResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := real_time_response_admin.NewRTRDeleteScriptsParamsWithContext(ctx)
	params.SetIds(state.ID.ValueString())

	_, err := r.client.RealTimeResponseAdmin.RTRDeleteScripts(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopesReadWrite)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}
}

func (r *rtrScriptResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func getRTRScript(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
	id string,
) (*models.EmpowerapiRemoteCommandPutFileV2, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := real_time_response_admin.NewRTRGetScriptsV2ParamsWithContext(ctx)
	params.SetIds([]string{id})

	res, err := apiClient.RealTimeResponseAdmin.RTRGetScriptsV2(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesReadWrite))
		return nil, diags
	}

	if res == nil || res.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	if diagErr := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diagErr != nil {
		diags.Append(diagErr)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func getRTRScriptWithContent(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
	id string,
) (*models.EmpowerapiRemoteCommandPutFileV2, diag.Diagnostics) {
	var script *models.EmpowerapiRemoteCommandPutFileV2
	var readDiags diag.Diagnostics

	err := retry.RetryUntilNoError(ctx, 30*time.Second, 5*time.Second, func() error {
		script, readDiags = getRTRScript(ctx, apiClient, id)
		if readDiags.HasError() {
			return nil
		}
		if script.Content == contentNotRetrieved {
			return fmt.Errorf("content not yet available")
		}
		return nil
	})

	if err != nil && !readDiags.HasError() {
		readDiags.AddError(
			"Error reading RTR script...",
			"The API returned a placeholder for the script content. This is typically a temporary condition. Please try again.",
		)
	}

	return script, readDiags
}
