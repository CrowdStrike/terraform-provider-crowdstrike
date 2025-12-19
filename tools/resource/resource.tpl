package {{.PackageName}}

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
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
	_ resource.Resource                   = &{{.CamelCaseName}}Resource{}
	_ resource.ResourceWithConfigure      = &{{.CamelCaseName}}Resource{}
	_ resource.ResourceWithImportState    = &{{.CamelCaseName}}Resource{}
	_ resource.ResourceWithValidateConfig = &{{.CamelCaseName}}Resource{}
)

var (
  documentationSection       string         = "section"
  resourceMarkdownDescription string         = "<description>"
  requiredScopes              []scopes.Scope = []scopes.Scope{}
)

func New{{.PascalCaseName}}Resource() resource.Resource {
	return &{{.CamelCaseName}}Resource{}
}

type {{.CamelCaseName}}Resource struct {
	client *client.CrowdStrikeAPISpecification
}

type {{.CamelCaseName}}ResourceModel struct {
	ID          types.String `tfsdk:"id"`
	LastUpdated types.String `tfsdk:"last_updated"`
  // TODO: Define resource model
}

func (m *{{.CamelCaseName}}ResourceModel) wrap(
	ctx context.Context,
	// api response object
) diag.Diagnostics {
	var diags diag.Diagnostics

	// m.ID = types.StringValue(*apiresponse.ID)
	// etc

	return diags
}

func (r *{{.CamelCaseName}}Resource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(config.ProviderConfig)

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

	r.client = config.Client
}

func (r *{{.CamelCaseName}}Resource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_{{.SnakeCaseName}}"
}

func (r *{{.CamelCaseName}}Resource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(documentationSection, resourceMarkdownDescription, requiredScopes),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the {{.Name}}.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
		},
	}
}

func (r *{{.CamelCaseName}}Resource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan {{.CamelCaseName}}ResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// resp.Diagnostics.Append(plan.wrap(ctx, *apiresponse)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *{{.CamelCaseName}}Resource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state {{.CamelCaseName}}ResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// resp.Diagnostics.Append(state.wrap(ctx, *apiresponse)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *{{.CamelCaseName}}Resource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan {{.CamelCaseName}}ResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	// resp.Diagnostics.Append(plan.wrap(ctx, *apiresponse)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *{{.CamelCaseName}}Resource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state {{.CamelCaseName}}ResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *{{.CamelCaseName}}Resource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *{{.CamelCaseName}}Resource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config {{.CamelCaseName}}ResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
}
