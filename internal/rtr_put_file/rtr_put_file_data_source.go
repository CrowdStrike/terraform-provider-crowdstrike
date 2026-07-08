package rtrputfile

import (
	"context"
	"fmt"

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
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	dataSourceDocumentationSection = "Host Setup and Management"
	dataSourceMarkdownDescription  = "This data source provides information about a single RTR put file in Falcon. Use this to look up a put file by name or ID and reference its attributes in other resources."
)

var dataSourceApiScopes = []scopes.Scope{
	{Name: "Real Time Response (Admin)", Read: true, Write: false},
}

var (
	_ datasource.DataSource              = &rtrPutFileDataSource{}
	_ datasource.DataSourceWithConfigure = &rtrPutFileDataSource{}
)

type rtrPutFileDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type rtrPutFileDataSourceModel struct {
	ID                  types.String      `tfsdk:"id"`
	Name                types.String      `tfsdk:"name"`
	Description         types.String      `tfsdk:"description"`
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

func (m *rtrPutFileDataSourceModel) wrap(
	ctx context.Context,
	file models.EmpowerapiRemoteCommandPutFileV2,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = flex.StringValueToFramework(file.ID)
	m.Name = flex.StringValueToFramework(file.Name)
	m.Description = flex.StringValueToFramework(file.Description)
	m.Sha256 = flex.StringValueToFramework(file.Sha256)
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

func NewRtrPutFileDataSource() datasource.DataSource {
	return &rtrPutFileDataSource{}
}

func (d *rtrPutFileDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	d.client = providerConfig.Client
}

func (d *rtrPutFileDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_rtr_put_file"
}

func (d *rtrPutFileDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			dataSourceDocumentationSection,
			dataSourceMarkdownDescription,
			dataSourceApiScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The RTR put file ID. Exactly one of 'id' or 'name' must be provided.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					fwvalidators.StringNotWhitespace(),
					stringvalidator.ExactlyOneOf(path.MatchRoot("name"), path.MatchRoot("id")),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The RTR put file name. Exactly one of 'id' or 'name' must be provided.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Description of the RTR put file.",
			},
			"comments_for_audit_log": schema.StringAttribute{
				Computed:    true,
				Description: "Audit log comment for the put file creation.",
			},
			"sha256": schema.StringAttribute{
				Computed:    true,
				Description: "SHA256 hash of the uploaded file.",
			},
			"file_type": schema.StringAttribute{
				Computed:    true,
				Description: "Detected file type.",
			},
			"size": schema.Int64Attribute{
				Computed:    true,
				Description: "Size of the uploaded file in bytes.",
			},
			"platform": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Platforms the file is available on.",
			},
			"permission_type": schema.StringAttribute{
				Computed:    true,
				Description: "Permission type of the file.",
			},
			"created_by": schema.StringAttribute{
				Computed:    true,
				Description: "User who created the file.",
			},
			"created_timestamp": schema.StringAttribute{
				Computed:    true,
				CustomType:  timetypes.RFC3339Type{},
				Description: "Timestamp when the file was created.",
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

func (d *rtrPutFileDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data rtrPutFileDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var id string
	if utils.IsKnown(data.ID) {
		id = data.ID.ValueString()
		tflog.Debug(ctx, "[datasource] Looking up RTR put file by ID", map[string]any{
			"id": id,
		})
	} else {
		name := data.Name.ValueString()
		tflog.Debug(ctx, "[datasource] Looking up RTR put file by name", map[string]any{
			"name": name,
		})

		filter := fmt.Sprintf("name:'%s'", name)
		listParams := real_time_response_admin.NewRTRListPutFilesParamsWithContext(ctx).
			WithFilter(&filter)

		listRes, err := d.client.RealTimeResponseAdmin.RTRListPutFiles(listParams)
		notFoundDetail := fmt.Sprintf("No RTR put file found with name %q.", name)
		if err != nil {
			resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
				tferrors.Read, err, dataSourceApiScopes, tferrors.WithNotFoundDetail(notFoundDetail),
			))
			return
		}

		if listRes == nil || listRes.Payload == nil {
			resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Read))
			return
		}

		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, listRes.Payload.Errors); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}

		if len(listRes.Payload.Resources) == 0 {
			resp.Diagnostics.Append(tferrors.NewNotFoundError(notFoundDetail))
			return
		}

		if len(listRes.Payload.Resources) > 1 {
			resp.Diagnostics.AddError(
				"Multiple RTR put files matched",
				fmt.Sprintf(
					"The name %q matched %d RTR put files, but this data source must resolve to exactly one. Provide a more specific name or use the 'id' attribute to look up a specific put file.",
					name, len(listRes.Payload.Resources),
				),
			)
			return
		}

		id = listRes.Payload.Resources[0]
	}

	file, readDiags := getRTRPutFile(ctx, d.client, id, dataSourceApiScopes)
	resp.Diagnostics.Append(readDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(data.wrap(ctx, *file)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
