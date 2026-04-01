package lookupfile

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &ngsiemlookupFileDataSource{}
	_ datasource.DataSourceWithConfigure = &ngsiemlookupFileDataSource{}
)

func NewNGSIEMLookupFileDataSource() datasource.DataSource {
	return &ngsiemlookupFileDataSource{}
}

type ngsiemlookupFileDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type lookupFileDataModel struct {
	ID         types.String `tfsdk:"id"`
	Filename   types.String `tfsdk:"filename"`
	Repository types.String `tfsdk:"repository"`
}

func (m lookupFileDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":         types.StringType,
		"filename":   types.StringType,
		"repository": types.StringType,
	}
}

type ngsiemlookupFileDataSourceModel struct {
	Repository  types.String `tfsdk:"repository"`
	Filter      types.String `tfsdk:"filter"`
	LookupFiles types.List   `tfsdk:"lookup_files"`
}

func (d *ngsiemlookupFileDataSourceModel) wrap(
	ctx context.Context,
	filenames []string,
	repository string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	files := make([]lookupFileDataModel, 0, len(filenames))
	for _, name := range filenames {
		files = append(files, lookupFileDataModel{
			ID:         types.StringValue(buildResourceID(repository, name)),
			Filename:   types.StringValue(name),
			Repository: types.StringValue(repository),
		})
	}

	d.LookupFiles = utils.SliceToListTypeObject(ctx, files, lookupFileDataModel{}.AttributeTypes(), &diags)
	return diags
}

func (d *ngsiemlookupFileDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(config.ProviderConfig)
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

	d.client = config.Client
}

func (d *ngsiemlookupFileDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_ngsiem_lookup_files"
}

func (d *ngsiemlookupFileDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Next-Gen SIEM",
			"Use this data source to list lookup files in a CrowdStrike Falcon Next-Gen SIEM repository.",
			apiScopesRead,
		),
		Attributes: map[string]schema.Attribute{
			"repository": schema.StringAttribute{
				Required:    true,
				Description: "The repository to list files from. Valid values include: `all`, `search-all`, `investigate_view`, `falcon`, `third-party`, `falcon_for_it_view`, `forensics_view`, `forensics`, `3pi_parsers`.",
				Validators: []validator.String{
					stringvalidator.OneOf(validRepositories...),
				},
			},
			"filter": schema.StringAttribute{
				Optional:    true,
				Description: "Filter to apply to the lookup file names. Uses the text match (`~`) operator. Example: `name:~'my_lookup'`.",
			},
			"lookup_files": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of lookup files in the repository.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The unique identifier of the lookup file in the format `repository:filename`.",
						},
						"filename": schema.StringAttribute{
							Computed:    true,
							Description: "The name of the lookup file.",
						},
						"repository": schema.StringAttribute{
							Computed:    true,
							Description: "The repository the file belongs to.",
						},
					},
				},
			},
		},
	}
}

func (d *ngsiemlookupFileDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	tflog.Trace(ctx, "Starting NGSIEM lookup file data source read")

	var data ngsiemlookupFileDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	repository := data.Repository.ValueString()
	var allFilenames []string
	limit := "5000"
	offset := "0"

	for {
		params := &ngsiem.ListLookupFilesParams{
			Context:      ctx,
			SearchDomain: &repository,
			Limit:        &limit,
			Offset:       &offset,
		}

		if utils.IsKnown(data.Filter) {
			filter := data.Filter.ValueString()
			params.Filter = &filter
		}

		tflog.Debug(ctx, "Calling CrowdStrike API to list NGSIEM lookup files", map[string]any{
			"repository": repository,
			"offset":     offset,
		})

		res, err := d.client.Ngsiem.ListLookupFiles(params)
		if err != nil {
			resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesRead))
			return
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			break
		}

		allFilenames = append(allFilenames, res.Payload.Resources...)

		if res.Payload.Meta == nil || res.Payload.Meta.Pagination == nil ||
			res.Payload.Meta.Pagination.Total == nil {
			break
		}

		total := int(*res.Payload.Meta.Pagination.Total)
		if len(allFilenames) >= total {
			break
		}

		offset = fmt.Sprintf("%d", len(allFilenames))
	}

	tflog.Info(ctx, "Successfully listed NGSIEM lookup files", map[string]any{
		"repository": repository,
		"count":      len(allFilenames),
	})

	resp.Diagnostics.Append(data.wrap(ctx, allFilenames, repository)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
