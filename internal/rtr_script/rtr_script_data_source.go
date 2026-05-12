package rtrscript

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
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	dataSourceDocumentationSection = "Host Setup and Management"
	dataSourceMarkdownDescription  = "This data source provides information about a single Real Time Response (RTR) custom script in CrowdStrike Falcon. Use this to look up an RTR script by name or ID and reference its attributes."
)

var dataSourceApiScopes = []scopes.Scope{
	{Name: "Real Time Response (Admin)", Read: true, Write: false},
}

var (
	_ datasource.DataSource              = &rtrScriptDataSource{}
	_ datasource.DataSourceWithConfigure = &rtrScriptDataSource{}
)

type rtrScriptDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type rtrScriptDataSourceModel struct {
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

func (m *rtrScriptDataSourceModel) wrap(script *models.EmpowerapiRemoteCommandPutFileV2) {
	m.ID = flex.StringValueToFramework(script.ID)
	m.Name = flex.StringValueToFramework(script.Name)
	m.Description = flex.StringValueToFramework(script.Description)
	m.Content = flex.StringValueToFramework(script.Content)
	m.PermissionType = flex.StringValueToFramework(script.PermissionType)
	m.SHA256 = flex.StringValueToFramework(script.Sha256)
	m.CommentsForAuditLog = flex.StringValueToFramework(script.CommentsForAuditLog)
	m.CreatedBy = flex.StringValueToFramework(script.CreatedBy)
	m.CreatedTimestamp = flex.DateTimeValueToFramework(script.CreatedTimestamp)
	m.ModifiedBy = flex.StringValueToFramework(script.ModifiedBy)
	m.ModifiedTimestamp = flex.DateTimeValueToFramework(script.ModifiedTimestamp)

	m.Size = types.Int64PointerValue(script.Size)

	if len(script.Platform) > 0 {
		caser := cases.Title(language.English)
		m.PlatformName = types.StringValue(caser.String(script.Platform[0]))
	} else {
		m.PlatformName = types.StringNull()
	}
}

func NewRTRScriptDataSource() datasource.DataSource {
	return &rtrScriptDataSource{}
}

func (d *rtrScriptDataSource) Configure(
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

func (d *rtrScriptDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_rtr_script"
}

func (d *rtrScriptDataSource) Schema(
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
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The ID of the RTR script. Exactly one of `id` or `name` must be provided.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					fwvalidators.StringNotWhitespace(),
					stringvalidator.ExactlyOneOf(path.MatchRoot("name"), path.MatchRoot("id")),
				},
			},
			"name": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The name of the RTR script. Exactly one of `id` or `name` must be provided.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The description of the RTR script.",
			},
			"content": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The script content.",
			},
			"platform_name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The platform the script targets (`Windows`, `Mac`, or `Linux`).",
			},
			"permission_type": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Who can use the script: `private`, `group`, or `public`.",
			},
			"comments_for_audit_log": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Audit log comment for the script.",
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
			},
			"created_timestamp": schema.StringAttribute{
				CustomType:          timetypes.RFC3339Type{},
				Computed:            true,
				MarkdownDescription: "The timestamp when the script was created.",
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

func (d *rtrScriptDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data rtrScriptDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var scriptID string
	if utils.IsKnown(data.ID) {
		scriptID = data.ID.ValueString()
		tflog.Debug(ctx, "[datasource] Looking up RTR script by ID", map[string]any{
			"id": scriptID,
		})
	} else {
		name := data.Name.ValueString()
		tflog.Debug(ctx, "[datasource] Looking up RTR script by name", map[string]any{
			"name": name,
		})

		filter := fmt.Sprintf("name:'%s'", name)
		listParams := real_time_response_admin.NewRTRListScriptsParamsWithContext(ctx)
		listParams.Filter = &filter

		notFoundDetail := fmt.Sprintf("No RTR script found with name %q.", name)

		listRes, err := d.client.RealTimeResponseAdmin.RTRListScripts(listParams)
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

		if d := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, listRes.Payload.Errors); d != nil {
			resp.Diagnostics.Append(d)
			return
		}

		if len(listRes.Payload.Resources) == 0 {
			resp.Diagnostics.Append(tferrors.NewNotFoundError(notFoundDetail))
			return
		}

		if len(listRes.Payload.Resources) > 1 {
			resp.Diagnostics.AddError(
				"Multiple RTR scripts matched",
				fmt.Sprintf(
					"The name %q matched %d RTR scripts, but this data source must resolve to exactly one. Provide a more specific name or use the 'id' attribute to look up a specific script.",
					name, len(listRes.Payload.Resources),
				),
			)
			return
		}

		scriptID = listRes.Payload.Resources[0]
	}

	script, readDiags := getRTRScriptWithContent(ctx, d.client, scriptID, dataSourceApiScopes)
	resp.Diagnostics.Append(readDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.wrap(script)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
