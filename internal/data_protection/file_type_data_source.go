package dataprotection

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
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

var (
	_ datasource.DataSource              = &fileTypeDataSource{}
	_ datasource.DataSourceWithConfigure = &fileTypeDataSource{}
)

var (
	fileTypeDataSourceDocumentationSection = "Data Protection"
	fileTypeDataSourceMarkdownDescription  = "This data source provides information about a single file type in the Falcon Data Protection file type catalog. File types are a CrowdStrike-managed reference catalog (for example PDF, DOCX, and source code file types) used when configuring Data Protection policies. Use this to look up a file type by ID or name and reference its attributes in other resources. This is a read-only catalog API; there is no corresponding resource to create, update, or delete file types."
	fileTypeDataSourceRequiredScopes       = []scopes.Scope{
		{Name: "Data Protection", Read: true},
	}
)

// NewFileTypeDataSource is a helper function to simplify the provider implementation.
func NewFileTypeDataSource() datasource.DataSource {
	return &fileTypeDataSource{}
}

type fileTypeDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type fileTypeDataSourceModel struct {
	ID                        types.String      `tfsdk:"id"`
	Name                      types.String      `tfsdk:"name"`
	CategoryID                types.String      `tfsdk:"category_id"`
	Description               types.String      `tfsdk:"description"`
	SupportedPlatforms        types.List        `tfsdk:"supported_platforms"`
	SupportsContentInspection types.Bool        `tfsdk:"supports_content_inspection"`
	SupportsMipExtraction     types.Bool        `tfsdk:"supports_mip_extraction"`
	Created                   timetypes.RFC3339 `tfsdk:"created"`
	LastUpdated               timetypes.RFC3339 `tfsdk:"last_updated"`
}

// wrap converts an APIFileTypeV1 API model into the Terraform data source model.
func (m *fileTypeDataSourceModel) wrap(
	ctx context.Context,
	fileType models.APIFileTypeV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = flex.StringPointerToFramework(fileType.ID)
	m.Name = flex.StringValueToFramework(fileType.Name)
	m.CategoryID = flex.StringPointerToFramework(fileType.CategoryID)
	m.Description = flex.StringValueToFramework(fileType.Description)
	m.SupportsContentInspection = types.BoolPointerValue(fileType.SupportsContentInspection)
	m.SupportsMipExtraction = types.BoolPointerValue(fileType.SupportsMipExtraction)
	m.Created = flex.DateTimeValueToFramework(fileType.Created)
	m.LastUpdated = flex.DateTimeValueToFramework(fileType.LastUpdated)

	platforms, platformDiags := flex.FlattenStringValueList(ctx, fileType.SupportedPlatforms)
	diags.Append(platformDiags...)
	m.SupportedPlatforms = platforms

	return diags
}

// Configure adds the provider configured client to the data source.
func (d *fileTypeDataSource) Configure(
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

// Metadata returns the data source type name.
func (d *fileTypeDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_data_protection_file_type"
}

// Schema defines the schema for the data source.
func (d *fileTypeDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			fileTypeDataSourceDocumentationSection,
			fileTypeDataSourceMarkdownDescription,
			fileTypeDataSourceRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The ID of the file type. Exactly one of `id` or `name` must be provided.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					fwvalidators.StringNotWhitespace(),
					stringvalidator.ExactlyOneOf(path.MatchRoot("name"), path.MatchRoot("id")),
				},
			},
			"name": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The name of the file type (for example `PDF` or `Microsoft Word`). Exactly one of `id` or `name` must be provided.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					fwvalidators.StringNotWhitespace(),
				},
			},
			"category_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The ID of the category the file type belongs to.",
			},
			"description": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The description of the file type.",
			},
			"supported_platforms": schema.ListAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				MarkdownDescription: "The platforms that support this file type.",
			},
			"supports_content_inspection": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether this file type supports content inspection.",
			},
			"supports_mip_extraction": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether this file type supports Microsoft Information Protection (MIP) label extraction.",
			},
			"created": schema.StringAttribute{
				CustomType:          timetypes.RFC3339Type{},
				Computed:            true,
				MarkdownDescription: "The timestamp when the file type was created.",
			},
			"last_updated": schema.StringAttribute{
				CustomType:          timetypes.RFC3339Type{},
				Computed:            true,
				MarkdownDescription: "The timestamp when the file type was last updated.",
			},
		},
	}
}

// Read refreshes the Terraform state with the latest data.
func (d *fileTypeDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data fileTypeDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var fileTypeID string
	if utils.IsKnown(data.ID) {
		fileTypeID = data.ID.ValueString()
		tflog.Debug(ctx, "[datasource] Looking up file type by ID", map[string]any{
			"id": fileTypeID,
		})
	} else {
		name := data.Name.ValueString()
		tflog.Debug(ctx, "[datasource] Looking up file type by name", map[string]any{
			"name": name,
		})

		filter := fmt.Sprintf("name:'%s'", name)
		queryParams := data_protection_configuration.NewQueriesFileTypeGetV2ParamsWithContext(ctx)
		queryParams.Filter = &filter

		notFoundDetail := fmt.Sprintf("No file type found with name %q.", name)

		queryRes, err := d.client.DataProtectionConfiguration.QueriesFileTypeGetV2(queryParams)
		if err != nil {
			resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
				tferrors.Read, err, fileTypeDataSourceRequiredScopes, tferrors.WithNotFoundDetail(notFoundDetail),
			))
			return
		}

		if queryRes == nil || queryRes.Payload == nil {
			resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Read))
			return
		}

		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, queryRes.Payload.Errors); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}

		if len(queryRes.Payload.Resources) == 0 {
			resp.Diagnostics.Append(tferrors.NewNotFoundError(notFoundDetail))
			return
		}

		if len(queryRes.Payload.Resources) > 1 {
			resp.Diagnostics.AddError(
				"Multiple file types matched",
				fmt.Sprintf(
					"The name %q matched %d file types, but this data source must resolve to exactly one. Provide a more specific name or use the 'id' attribute to look up a specific file type.",
					name, len(queryRes.Payload.Resources),
				),
			)
			return
		}

		fileTypeID = queryRes.Payload.Resources[0]
	}

	entityParams := data_protection_configuration.NewEntitiesFileTypeGetParamsWithContext(ctx)
	entityParams.Ids = []string{fileTypeID}

	notFoundDetail := fmt.Sprintf("No file type found with ID %q.", fileTypeID)

	res, err := d.client.DataProtectionConfiguration.EntitiesFileTypeGet(entityParams)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Read, err, fileTypeDataSourceRequiredScopes, tferrors.WithNotFoundDetail(notFoundDetail),
		))
		return
	}

	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewNotFoundError(notFoundDetail))
		return
	}

	resp.Diagnostics.Append(data.wrap(ctx, *res.Payload.Resources[0])...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
