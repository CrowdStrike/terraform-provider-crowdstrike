package {{.PackageName}}

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &{{.CamelCaseName}}DataSource{}
	_ datasource.DataSourceWithConfigure = &{{.CamelCaseName}}DataSource{}
)

var (
  documentationSection       string         = "section"
  dataSourceMarkdownDescription string         = "<description>"
  requiredScopes              []scopes.Scope = []scopes.Scope{}
)

func New{{.PascalCaseName}}DataSource() datasource.DataSource {
	return &{{.CamelCaseName}}DataSource{}
}

type {{.CamelCaseName}}DataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type {{.CamelCaseName}}DataSourceModel struct {
	ID types.String `tfsdk:"id"`
	// TODO: Define data source model
}

func (m *{{.CamelCaseName}}DataSourceModel) wrap(
	// apiResponse models.ApiResponseV1,
) {
	// m.ID = flex.StringPointerToFramework(apiResponse.ID)
}

func (d *{{.CamelCaseName}}DataSource) Configure(
	ctx context.Context,
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

func (d *{{.CamelCaseName}}DataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_{{.SnakeCaseName}}"
}

func (d *{{.CamelCaseName}}DataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(documentationSection, dataSourceMarkdownDescription, requiredScopes),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the {{.Name}}.",
			},
		},
	}
}

func (d *{{.CamelCaseName}}DataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var state {{.CamelCaseName}}DataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// res, err := d.client.SomeService.GetOperation(params)
	// if err != nil {
	// 	resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
	// 		tferrors.Read, err, requiredScopes,
	// 	))
	// 	return
	// }
	//
	// if res == nil || res.Payload == nil {
	// 	resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Read))
	// 	return
	// }
	//
	// if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
	// 	resp.Diagnostics.Append(diag)
	// 	return
	// }
	//
	// if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
	// 	resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Read))
	// 	return
	// }
	//
	// state.wrap(*res.Payload.Resources[0])

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
