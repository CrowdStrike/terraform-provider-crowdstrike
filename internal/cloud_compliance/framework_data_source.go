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
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// frameworkFilterQueryLimit caps the page size of the filter lookup.
// Resolving to a single framework only requires knowing whether more than one
// matched, and the pagination metadata carries the true match count for the
// error message.
const frameworkFilterQueryLimit int64 = 2

var (
	_ datasource.DataSource              = &cloudComplianceFrameworkDataSource{}
	_ datasource.DataSourceWithConfigure = &cloudComplianceFrameworkDataSource{}
)

var (
	frameworkDataSourceDocumentationSection = "Falcon Cloud Security"
	frameworkDataSourceMarkdownDescription  = "This data source provides information about a single compliance framework, built-in or custom, in the CrowdStrike Falcon Platform. Look the framework up by ID, or with an FQL filter that matches exactly one framework, and reference its attributes in other resources."
	frameworkDataSourceRequiredScopes       = cloudComplianceFrameworkScopes
)

// NewCloudComplianceFrameworkDataSource is a helper function to simplify the provider implementation.
func NewCloudComplianceFrameworkDataSource() datasource.DataSource {
	return &cloudComplianceFrameworkDataSource{}
}

// cloudComplianceFrameworkDataSource is the data source implementation.
type cloudComplianceFrameworkDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

// cloudComplianceFrameworkDataSourceModel represents the data source model. Its
// attributes are limited to the fields the QueryComplianceFrameworks and
// GetComplianceFrameworks endpoints return.
type cloudComplianceFrameworkDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	Filter      types.String `tfsdk:"filter"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Authority   types.String `tfsdk:"authority"`
	Version     types.String `tfsdk:"version"`
	Active      types.Bool   `tfsdk:"active"`
}

// wrap transforms API response values to their terraform model values. The
// resolved identifier is passed in because it is the authoritative id for both
// the by-id and by-filter lookup paths.
func (d *cloudComplianceFrameworkDataSourceModel) wrap(
	id string,
	framework models.ApimodelsSecurityFramework,
) {
	d.ID = types.StringValue(id)
	d.Name = flex.StringPointerToFramework(framework.Name)
	d.Description = flex.StringValueToFramework(framework.Description)
	d.Authority = flex.StringPointerToFramework(framework.Authority)
	d.Version = flex.StringPointerToFramework(framework.Version)
	d.Active = types.BoolValue(framework.Active)
}

// Configure adds the provider configured client to the data source.
func (d *cloudComplianceFrameworkDataSource) Configure(
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
func (d *cloudComplianceFrameworkDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_compliance_framework"
}

// Schema defines the schema for the data source.
func (d *cloudComplianceFrameworkDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			frameworkDataSourceDocumentationSection,
			frameworkDataSourceMarkdownDescription,
			frameworkDataSourceRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Identifier for the compliance framework. Exactly one of `id` or `filter` must be provided.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.ExactlyOneOf(path.MatchRoot("filter"), path.MatchRoot("id")),
				},
			},
			"filter": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "FQL filter used to find the compliance framework. It must resolve to exactly one framework: the lookup fails if it matches none or more than one. Exactly one of `id` or `filter` must be provided. Filterable properties are `compliance_framework_name`, `compliance_framework_version`, and `compliance_framework_authority`. See the Filtering section for examples.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
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
	}
}

// Read refreshes the Terraform state with the latest data.
func (d *cloudComplianceFrameworkDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data cloudComplianceFrameworkDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reading compliance framework", map[string]any{
		"id":     data.ID.ValueString(),
		"filter": data.Filter.ValueString(),
	})

	id, framework, lookupDiags := d.lookupFramework(ctx, data.ID.ValueString(), data.Filter.ValueString())
	resp.Diagnostics.Append(lookupDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.wrap(id, *framework)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// lookupFramework resolves a single compliance framework by ID or by
// FQL filter, returning the resolved identifier alongside the framework.
// Exactly one of id or filter must be non-empty; the schema validator enforces
// that.
func (d *cloudComplianceFrameworkDataSource) lookupFramework(
	ctx context.Context,
	id string,
	filter string,
) (string, *models.ApimodelsSecurityFramework, diag.Diagnostics) {
	var diags diag.Diagnostics

	if id == "" {
		resolvedID, resolveDiags := d.resolveFrameworkIDFromFilter(ctx, filter)
		diags.Append(resolveDiags...)
		if diags.HasError() {
			return "", nil, diags
		}

		id = resolvedID
	}

	framework, getDiags := d.getFrameworkByID(ctx, id)
	diags.Append(getDiags...)
	if diags.HasError() {
		return "", nil, diags
	}

	return id, framework, diags
}

// resolveFrameworkIDFromFilter returns the identifier of the single compliance
// framework matching filter, erroring when the filter matches none or
// more than one.
func (d *cloudComplianceFrameworkDataSource) resolveFrameworkIDFromFilter(
	ctx context.Context,
	filter string,
) (string, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "[datasource] Looking up compliance framework by filter", map[string]any{
		"filter": filter,
	})

	limit := frameworkFilterQueryLimit
	queryResp, err := d.client.CloudPolicies.QueryComplianceFrameworks(
		cloud_policies.NewQueryComplianceFrameworksParamsWithContext(ctx).
			WithFilter(&filter).
			WithLimit(&limit),
	)
	notFoundDetail := fmt.Sprintf("No compliance framework matched the filter %q.", filter)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Read,
			err,
			frameworkDataSourceRequiredScopes,
			tferrors.WithNotFoundDetail(notFoundDetail),
		))
		return "", diags
	}

	if queryResp == nil || queryResp.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return "", diags
	}

	if payloadDiag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, queryResp.Payload.Errors); payloadDiag != nil {
		diags.Append(payloadDiag)
		return "", diags
	}

	if len(queryResp.Payload.Resources) == 0 {
		diags.Append(tferrors.NewNotFoundError(notFoundDetail))
		return "", diags
	}

	// The page is capped at frameworkFilterQueryLimit, so the pagination
	// total is the only reliable source for how many frameworks actually matched.
	matched := int64(len(queryResp.Payload.Resources))
	if queryResp.Payload.Meta != nil && queryResp.Payload.Meta.Pagination != nil &&
		queryResp.Payload.Meta.Pagination.Total != nil {
		matched = *queryResp.Payload.Meta.Pagination.Total
	}

	if matched > 1 {
		diags.AddError(
			"Multiple compliance frameworks matched",
			fmt.Sprintf(
				"The filter %q matched %d compliance frameworks, but exactly one is required. Narrow the filter until it matches a single framework, or look the framework up by id.",
				filter,
				matched,
			),
		)
		return "", diags
	}

	return queryResp.Payload.Resources[0], diags
}

// getFrameworkByID returns the compliance framework with the supplied identifier.
func (d *cloudComplianceFrameworkDataSource) getFrameworkByID(
	ctx context.Context,
	id string,
) (*models.ApimodelsSecurityFramework, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "[datasource] Looking up compliance framework by ID", map[string]any{
		"id": id,
	})

	getResp, err := d.client.CloudPolicies.GetComplianceFrameworks(
		cloud_policies.NewGetComplianceFrameworksParamsWithContext(ctx).WithIds([]string{id}),
	)
	notFoundDetail := fmt.Sprintf("No compliance framework found with ID %q.", id)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Read,
			err,
			frameworkDataSourceRequiredScopes,
			tferrors.WithNotFoundDetail(notFoundDetail),
		))
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

	if len(getResp.Payload.Resources) == 0 || getResp.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewNotFoundError(notFoundDetail))
		return nil, diags
	}

	return getResp.Payload.Resources[0], diags
}
