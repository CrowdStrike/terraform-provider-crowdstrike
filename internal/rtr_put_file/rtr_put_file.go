package rtrputfile

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_admin"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &rtrPutFileResource{}
	_ resource.ResourceWithConfigure   = &rtrPutFileResource{}
	_ resource.ResourceWithImportState = &rtrPutFileResource{}
)

var requiredScopes = []scopes.Scope{
	{Name: "Real Time Response (Admin)", Read: true, Write: true},
}

var (
	documentationSection        = "Host Setup and Management"
	resourceMarkdownDescription = "Manages an RTR put file, which can be deployed to hosts via the RTR `put` command. The underlying API supports create, read, and delete operations only, so changing any configurable attribute forces replacement."
)

func NewRtrPutFileResource() resource.Resource {
	return &rtrPutFileResource{}
}

type rtrPutFileResource struct {
	client *client.CrowdStrikeAPISpecification
}

type rtrPutFileResourceModel struct {
	ID                  types.String      `tfsdk:"id"`
	Name                types.String      `tfsdk:"name"`
	Description         types.String      `tfsdk:"description"`
	Source              types.String      `tfsdk:"source"`
	ContentSha256       types.String      `tfsdk:"content_sha256"`
	CommentsForAuditLog types.String      `tfsdk:"comments_for_audit_log"`
	Sha256              types.String      `tfsdk:"sha256"`
	FileType            types.String      `tfsdk:"file_type"`
	Size                types.Int64       `tfsdk:"size"`
	Platform            types.List        `tfsdk:"platform"`
	PermissionType      types.String      `tfsdk:"permission_type"`
	CreatedBy           types.String      `tfsdk:"created_by"`
	CreatedTimestamp    timetypes.RFC3339 `tfsdk:"created_timestamp"`
	ModifiedBy          types.String      `tfsdk:"modified_by"`
	ModifiedTimestamp   timetypes.RFC3339 `tfsdk:"modified_timestamp"`
}

func (m *rtrPutFileResourceModel) wrap(
	ctx context.Context,
	file models.EmpowerapiRemoteCommandPutFileV2,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = flex.StringValueToFramework(file.ID)
	m.Name = flex.StringValueToFramework(file.Name)
	m.Description = flex.StringValueToFramework(file.Description)
	m.Sha256 = flex.StringValueToFramework(file.Sha256)
	m.ContentSha256 = flex.StringValueToFramework(file.Sha256)
	m.CommentsForAuditLog = flex.StringValueToFramework(file.CommentsForAuditLog)
	m.FileType = flex.StringValueToFramework(file.FileType)
	m.PermissionType = flex.StringValueToFramework(file.PermissionType)
	m.CreatedBy = flex.StringValueToFramework(file.CreatedBy)
	m.ModifiedBy = flex.StringValueToFramework(file.ModifiedBy)
	m.CreatedTimestamp = flex.DateTimeValueToFramework(file.CreatedTimestamp)
	m.ModifiedTimestamp = flex.DateTimeValueToFramework(file.ModifiedTimestamp)
	m.Size = types.Int64PointerValue(file.Size)

	platformList, d := flex.FlattenStringValueList(ctx, file.Platform)
	diags.Append(d...)
	m.Platform = platformList

	return diags
}

func (r *rtrPutFileResource) Configure(
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

func (r *rtrPutFileResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_rtr_put_file"
}

func (r *rtrPutFileResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(documentationSection, resourceMarkdownDescription, requiredScopes),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the RTR put file.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the RTR put file.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the RTR put file.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"source": schema.StringAttribute{
				Required:    true,
				Description: "Path to a local file to upload.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"content_sha256": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "SHA256 hash of the source file for change detection. Use `filesha256()` to trigger replacement when file content changes.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"comments_for_audit_log": schema.StringAttribute{
				Optional:    true,
				Description: "Audit log comment for the put file creation.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"sha256": schema.StringAttribute{
				Computed:    true,
				Description: "SHA256 hash of the uploaded file.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"file_type": schema.StringAttribute{
				Computed:    true,
				Description: "Detected file type.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"size": schema.Int64Attribute{
				Computed:    true,
				Description: "Size of the uploaded file in bytes.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"platform": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Platforms the file is available on.",
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"permission_type": schema.StringAttribute{
				Computed:    true,
				Description: "Permission type of the file.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_by": schema.StringAttribute{
				Computed:    true,
				Description: "User who created the file.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_timestamp": schema.StringAttribute{
				Computed:    true,
				CustomType:  timetypes.RFC3339Type{},
				Description: "Timestamp when the file was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"modified_by": schema.StringAttribute{
				Computed:    true,
				Description: "User who last modified the file.",
			},
			"modified_timestamp": schema.StringAttribute{
				Computed:    true,
				CustomType:  timetypes.RFC3339Type{},
				Description: "Timestamp when the file was last modified.",
			},
		},
	}
}

func (r *rtrPutFileResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan rtrPutFileResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	file, err := os.Open(plan.Source.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Open Source File",
			fmt.Sprintf("Could not open file at %q: %s", plan.Source.ValueString(), err),
		)
		return
	}
	defer file.Close()

	params := real_time_response_admin.NewRTRCreatePutFilesV2ParamsWithContext(ctx).
		WithDescription(plan.Description.ValueString()).
		WithFile(file).
		WithName(plan.Name.ValueStringPointer())

	if utils.IsKnown(plan.CommentsForAuditLog) {
		params.WithCommentsForAuditLog(plan.CommentsForAuditLog.ValueStringPointer())
	}

	res, err := r.client.RealTimeResponseAdmin.RTRCreatePutFilesV2(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create, err, requiredScopes,
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

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), types.StringValue(res.Payload.Resources[0].ID))...)

	resp.Diagnostics.Append(plan.wrap(ctx, *res.Payload.Resources[0])...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *rtrPutFileResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state rtrPutFileResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := real_time_response_admin.NewRTRGetPutFilesV2ParamsWithContext(ctx).
		WithIds([]string{state.ID.ValueString()})

	res, err := r.client.RealTimeResponseAdmin.RTRGetPutFilesV2(params)
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

	resp.Diagnostics.Append(state.wrap(ctx, *res.Payload.Resources[0])...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *rtrPutFileResource) Update(
	_ context.Context,
	_ resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	resp.Diagnostics.AddError(
		"Update Not Supported by CrowdStrike API",
		"The CrowdStrike API does not provide an update operation for RTR put files. Changing any configurable attribute requires resource replacement.",
	)
}

func (r *rtrPutFileResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state rtrPutFileResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := real_time_response_admin.NewRTRDeletePutFilesParamsWithContext(ctx).
		WithIds(state.ID.ValueString())

	_, err := r.client.RealTimeResponseAdmin.RTRDeletePutFiles(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, requiredScopes)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}
}

func (r *rtrPutFileResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
