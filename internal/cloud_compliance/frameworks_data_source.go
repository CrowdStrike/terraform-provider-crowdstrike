package cloudcompliance

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	// frameworksQueryPageLimit is the page size used when enumerating framework
	// identifiers. 500 is the maximum the QueryComplianceFrameworks endpoint
	// accepts.
	frameworksQueryPageLimit int64 = 500

	// frameworksGetBatchSize caps how many identifiers are hydrated per
	// GetComplianceFrameworks call.
	frameworksGetBatchSize = 100
)

var (
	_ datasource.DataSource              = &cloudComplianceFrameworksDataSource{}
	_ datasource.DataSourceWithConfigure = &cloudComplianceFrameworksDataSource{}
)

var (
	frameworksDataSourceDocumentationSection = "Falcon Cloud Security"
	frameworksDataSourceMarkdownDescription  = "This data source provides information about compliance frameworks, built-in and custom, in the CrowdStrike Falcon Platform. Return every framework, narrow the set with an FQL filter, or hydrate a specific list of framework identifiers."
	frameworksDataSourceRequiredScopes       = cloudComplianceFrameworkScopes
)

// NewCloudComplianceFrameworksDataSource is a helper function to simplify the provider implementation.
func NewCloudComplianceFrameworksDataSource() datasource.DataSource {
	return &cloudComplianceFrameworksDataSource{}
}

// cloudComplianceFrameworksDataSource is the data source implementation.
type cloudComplianceFrameworksDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

// cloudComplianceFrameworksDataSourceModel represents the plural data source
// model. filter and ids are mutually exclusive selection arguments; frameworks
// is the resolved collection.
type cloudComplianceFrameworksDataSourceModel struct {
	Filter     types.String `tfsdk:"filter"`
	IDs        types.List   `tfsdk:"ids"`
	Frameworks types.List   `tfsdk:"frameworks"`
}

// cloudComplianceFrameworkModel represents a single framework element. Its
// attributes are limited to the fields the QueryComplianceFrameworks and
// GetComplianceFrameworks endpoints return.
type cloudComplianceFrameworkModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Authority   types.String `tfsdk:"authority"`
	Version     types.String `tfsdk:"version"`
	Active      types.Bool   `tfsdk:"active"`
}

// AttributeTypes returns the attribute types for a framework element, used when
// converting the slice of frameworks into a types.List.
func (m cloudComplianceFrameworkModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":          types.StringType,
		"name":        types.StringType,
		"description": types.StringType,
		"authority":   types.StringType,
		"version":     types.StringType,
		"active":      types.BoolType,
	}
}

// mapFrameworkToModel converts an API framework into its element model.
func mapFrameworkToModel(framework *models.ApimodelsSecurityFramework) cloudComplianceFrameworkModel {
	return cloudComplianceFrameworkModel{
		ID:          types.StringValue(framework.UUID),
		Name:        flex.StringPointerToFramework(framework.Name),
		Description: flex.StringValueToFramework(framework.Description),
		Authority:   flex.StringPointerToFramework(framework.Authority),
		Version:     flex.StringPointerToFramework(framework.Version),
		Active:      types.BoolValue(framework.Active),
	}
}

// Configure adds the provider configured client to the data source.
func (d *cloudComplianceFrameworksDataSource) Configure(
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

// Metadata returns the data source type name.
func (d *cloudComplianceFrameworksDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_compliance_frameworks"
}

// Schema defines the schema for the data source.
func (d *cloudComplianceFrameworksDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			frameworksDataSourceDocumentationSection,
			frameworksDataSourceMarkdownDescription,
			frameworksDataSourceRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "FQL filter used to narrow the frameworks returned. Filterable properties are `compliance_framework_name`, `compliance_framework_version`, and `compliance_framework_authority`, for example `compliance_framework_authority:'CIS'`. Cannot be combined with `ids`. If neither `filter` nor `ids` is set, all frameworks are returned.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.ConflictsWith(path.MatchRoot("ids")),
				},
			},
			"ids": schema.ListAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "List of compliance framework identifiers to look up. Cannot be combined with `filter`. If neither `filter` nor `ids` is set, all frameworks are returned.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
					listvalidator.ConflictsWith(path.MatchRoot("filter")),
				},
			},
			"frameworks": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The list of compliance frameworks matching the selection. Empty when nothing matches.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Identifier for the compliance framework.",
						},
						"name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The name of the compliance framework.",
						},
						"description": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "A description of the compliance framework.",
						},
						"authority": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The authority that defines the compliance framework, for example `CIS` for a built-in benchmark or `Custom` for a user-defined framework.",
						},
						"version": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The version of the compliance framework. Custom frameworks are created with version `1.0`; built-in frameworks carry the version of the benchmark release.",
						},
						"active": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Whether the compliance framework is active.",
						},
					},
				},
			},
		},
	}
}

// Read refreshes the Terraform state with the latest data.
func (d *cloudComplianceFrameworksDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data cloudComplianceFrameworksDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reading compliance frameworks", map[string]any{
		"filter":  data.Filter.ValueString(),
		"ids_set": utils.IsKnown(data.IDs),
	})

	ids := flex.ExpandListAs[string](ctx, data.IDs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// When ids are not supplied, enumerate the framework identifiers matching the
	// optional filter. A nil filter returns every framework.
	if len(ids) == 0 {
		var filter *string
		if utils.IsKnown(data.Filter) {
			f := data.Filter.ValueString()
			filter = &f
		}

		queriedIDs, queryDiags := d.queryFrameworkIDs(ctx, filter)
		resp.Diagnostics.Append(queryDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		ids = queriedIDs
	}

	frameworks, hydrateDiags := d.hydrateFrameworks(ctx, ids)
	resp.Diagnostics.Append(hydrateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	frameworkModels := make([]cloudComplianceFrameworkModel, 0, len(frameworks))
	for _, framework := range frameworks {
		if framework == nil {
			continue
		}
		frameworkModels = append(frameworkModels, mapFrameworkToModel(framework))
	}

	data.Frameworks = utils.SliceToListTypeObject(ctx, frameworkModels, cloudComplianceFrameworkModel{}.AttributeTypes(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// queryFrameworkIDs pages through every framework identifier matching filter. A
// nil filter enumerates all frameworks. The API may return fewer identifiers per
// page than the reported total, so the read loops on offset until it has
// collected them all.
func (d *cloudComplianceFrameworksDataSource) queryFrameworkIDs(
	ctx context.Context,
	filter *string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allIDs []string
	var offset int64

	for {
		limit := frameworksQueryPageLimit
		queryResp, err := d.client.CloudPolicies.QueryComplianceFrameworks(
			cloud_policies.NewQueryComplianceFrameworksParamsWithContext(ctx).
				WithFilter(filter).
				WithLimit(&limit).
				WithOffset(&offset),
		)
		if err != nil {
			diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, frameworksDataSourceRequiredScopes))
			return nil, diags
		}

		if queryResp == nil || queryResp.Payload == nil {
			break
		}
		if payloadDiag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, queryResp.Payload.Errors); payloadDiag != nil {
			diags.Append(payloadDiag)
			return nil, diags
		}

		pageCount := len(queryResp.Payload.Resources)
		allIDs = append(allIDs, queryResp.Payload.Resources...)

		var total int64
		if queryResp.Payload.Meta != nil && queryResp.Payload.Meta.Pagination != nil &&
			queryResp.Payload.Meta.Pagination.Total != nil {
			total = *queryResp.Payload.Meta.Pagination.Total
		}

		tflog.Debug(ctx, "[datasource] Retrieved compliance framework ids page", map[string]any{
			"page_count":  pageCount,
			"total_count": len(allIDs),
			"total":       total,
		})

		if pageCount == 0 || (total > 0 && int64(len(allIDs)) >= total) {
			break
		}
		offset += int64(pageCount)
	}

	return allIDs, diags
}

// hydrateFrameworks resolves the supplied identifiers into full framework
// objects, batching the GetComplianceFrameworks calls. An empty id list returns
// no frameworks without calling the API.
func (d *cloudComplianceFrameworksDataSource) hydrateFrameworks(
	ctx context.Context,
	ids []string,
) ([]*models.ApimodelsSecurityFramework, diag.Diagnostics) {
	var diags diag.Diagnostics
	if len(ids) == 0 {
		return nil, diags
	}

	frameworks := make([]*models.ApimodelsSecurityFramework, 0, len(ids))

	for start := 0; start < len(ids); start += frameworksGetBatchSize {
		end := start + frameworksGetBatchSize
		if end > len(ids) {
			end = len(ids)
		}
		batch := ids[start:end]

		getResp, err := d.client.CloudPolicies.GetComplianceFrameworks(
			cloud_policies.NewGetComplianceFrameworksParamsWithContext(ctx).WithIds(batch),
		)
		if err != nil {
			diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, frameworksDataSourceRequiredScopes))
			return nil, diags
		}

		if getResp == nil || getResp.Payload == nil {
			diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
			return nil, diags
		}
		if payloadDiag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, getResp.Payload.Errors); payloadDiag != nil {
			diags.Append(payloadDiag)
			return nil, diags
		}

		frameworks = append(frameworks, getResp.Payload.Resources...)
	}

	return frameworks, diags
}
