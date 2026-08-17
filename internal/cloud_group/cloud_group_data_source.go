package cloudgroup

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
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

const (
	dataSourceDocumentationSection = "Falcon Cloud Security"
	dataSourceMarkdownDescription  = "This data source provides information about a single CrowdStrike Cloud Group. Look the group up by ID, or with an FQL filter that matches exactly one group, and reference its attributes in other resources."

	// filterQueryLimit caps the page size of the filter lookup. Resolving to a
	// single group only requires knowing whether more than one matched, and the
	// pagination metadata carries the true match count for the error message.
	// The API takes the limit as a string holding an int64.
	filterQueryLimit = "2"
)

var dataSourceApiScopes = []scopes.Scope{
	{
		Name:  "Cloud Groups V2",
		Read:  true,
		Write: false,
	},
}

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &cloudGroupDataSource{}
	_ datasource.DataSourceWithConfigure = &cloudGroupDataSource{}
)

// cloudGroupDataSource is the data source implementation.
type cloudGroupDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

// cloudGroupDataSourceModel describes the data source's data model. It mirrors
// cloudGroupResourceModel (the schema matches the crowdstrike_cloud_group resource
// 1:1), minus the "last_updated" bookkeeping field, which only exists in the
// resource to track state drift and is never populated from the API, plus the
// filter used to find the group.
type cloudGroupDataSourceModel struct {
	ID             types.String `tfsdk:"id"`
	Filter         types.String `tfsdk:"filter"`
	Name           types.String `tfsdk:"name"`
	Description    types.String `tfsdk:"description"`
	BusinessImpact types.String `tfsdk:"business_impact"`
	BusinessUnit   types.String `tfsdk:"business_unit"`
	Environment    types.String `tfsdk:"environment"`
	Owners         types.List   `tfsdk:"owners"`
	AWS            types.Object `tfsdk:"aws"`
	Azure          types.Object `tfsdk:"azure"`
	GCP            types.Object `tfsdk:"gcp"`
	Images         types.List   `tfsdk:"images"`
	CreatedAt      types.String `tfsdk:"created_at"`
	CreatedBy      types.String `tfsdk:"created_by"`
}

// wrap converts an API cloud group response to the data source's Terraform model.
// It delegates to the resource's wrap logic via a shared cloudGroupResourceModel so
// the flattening logic (selectors, images, owners, etc.) is defined in exactly one
// place, then copies the relevant fields over.
func (m *cloudGroupDataSourceModel) wrap(
	ctx context.Context,
	apiGroup *models.AssetgroupmanagerV1CloudGroup,
) diag.Diagnostics {
	var resourceModel cloudGroupResourceModel
	diags := resourceModel.wrap(ctx, apiGroup)
	if diags.HasError() {
		return diags
	}

	m.ID = resourceModel.ID
	m.Name = resourceModel.Name
	m.Description = resourceModel.Description
	m.BusinessImpact = resourceModel.BusinessImpact
	m.BusinessUnit = resourceModel.BusinessUnit
	m.Environment = resourceModel.Environment
	m.Owners = resourceModel.Owners
	m.AWS = resourceModel.AWS
	m.Azure = resourceModel.Azure
	m.GCP = resourceModel.GCP
	m.Images = resourceModel.Images
	m.CreatedAt = resourceModel.CreatedAt
	m.CreatedBy = resourceModel.CreatedBy

	return diags
}

// NewCloudGroupDataSource is a helper function to simplify the provider implementation.
func NewCloudGroupDataSource() datasource.DataSource {
	return &cloudGroupDataSource{}
}

// Configure adds the provider configured client to the data source.
func (d *cloudGroupDataSource) Configure(
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
func (d *cloudGroupDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_group"
}

// Schema defines the schema for the data source. It mirrors the crowdstrike_cloud_group
// resource schema 1:1, with all non-lookup attributes marked Computed.
func (d *cloudGroupDataSource) Schema(
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
				MarkdownDescription: "The UUID of the cloud group. Set this to look the group up directly by identifier. Exactly one of `id` or `filter` must be provided.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					fwvalidators.StringNotWhitespace(),
					stringvalidator.ExactlyOneOf(path.MatchRoot("filter"), path.MatchRoot("id")),
				},
			},
			"filter": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "An FQL filter that resolves to exactly one cloud group: the lookup fails if it matches none or more than one. Exactly one of `id` or `filter` must be provided. See the [Filtering with Falcon Query Language](https://registry.terraform.io/providers/crowdstrike/crowdstrike/latest/docs/guides/falcon-query-language) guide for the syntax, and the Filtering section of this page for the properties cloud groups can be filtered on and the caveats that apply to them.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					fwvalidators.StringNotWhitespace(),
				},
			},
			"name": schema.StringAttribute{
				Computed:    true,
				Description: "The name of the cloud group.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "The description of the cloud group.",
			},
			"business_impact": schema.StringAttribute{
				Computed:    true,
				Description: "An impact level that reflects how critical the cloud group's assets are to business operations. Valid values: high, moderate, low.",
			},
			"business_unit": schema.StringAttribute{
				Computed:    true,
				Description: "A free-text label used to associate the cloud group with an internal team.",
			},
			"environment": schema.StringAttribute{
				Computed:    true,
				Description: "Environment designation for the group. Valid values: dev, test, stage, prod.",
			},
			"owners": schema.ListAttribute{
				Computed:    true,
				Description: "Contact information for stakeholders responsible for the cloud group. List of email addresses.",
				ElementType: types.StringType,
			},
			"aws": schema.SingleNestedAttribute{
				Description: "AWS cloud resource configuration",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"account_ids": schema.ListAttribute{
						Description: "The cloud account identifiers (AWS account IDs) included in the group. When empty, resources across all accounts in the cloud provider are accessible to the group.",
						Computed:    true,
						ElementType: types.StringType,
					},
					"filters": schema.SingleNestedAttribute{
						Description: "Filters for AWS cloud resources",
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"region": schema.ListAttribute{
								Description: "List of AWS regions included",
								Computed:    true,
								ElementType: types.StringType,
							},
							"tags": schema.ListAttribute{
								Description: "List of tags filtered by (format: key=value)",
								Computed:    true,
								ElementType: types.StringType,
							},
						},
					},
				},
			},
			"azure": schema.SingleNestedAttribute{
				Description: "Azure cloud resource configuration",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"account_ids": schema.ListAttribute{
						Description: "The cloud account identifiers (Azure subscription IDs) included in the group. When empty, resources across all accounts in the cloud provider are accessible to the group.",
						Computed:    true,
						ElementType: types.StringType,
					},
					"filters": schema.SingleNestedAttribute{
						Description: "Filters for Azure cloud resources",
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"region": schema.ListAttribute{
								Description: "List of Azure regions included",
								Computed:    true,
								ElementType: types.StringType,
							},
							"tags": schema.ListAttribute{
								Description: "List of tags filtered by (format: key=value)",
								Computed:    true,
								ElementType: types.StringType,
							},
						},
					},
				},
			},
			"gcp": schema.SingleNestedAttribute{
				Description: "GCP cloud resource configuration",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"account_ids": schema.ListAttribute{
						Description: "The cloud account identifiers (GCP project IDs) included in the group. When empty, resources across all accounts in the cloud provider are accessible to the group.",
						Computed:    true,
						ElementType: types.StringType,
					},
					"filters": schema.SingleNestedAttribute{
						Description: "Filters for GCP cloud resources. Note: GCP does not support tag filtering.",
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"region": schema.ListAttribute{
								Description: "List of GCP regions included",
								Computed:    true,
								ElementType: types.StringType,
							},
						},
					},
				},
			},
			"images": schema.ListNestedAttribute{
				Description: "The container images accessible to the group. Each entry includes a registry and filters for repositories and tags.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"registry": schema.StringAttribute{
							Description: "The container registry included in the group.",
							Computed:    true,
						},
						"repositories": schema.ListAttribute{
							Description: "The container image repositories within the specified registry filtered by.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"tags": schema.ListAttribute{
							Description: "The container image tags filtered by.",
							Computed:    true,
							ElementType: types.StringType,
						},
					},
				},
			},
			// Computed attributes
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "The timestamp when the group was created.",
			},
			"created_by": schema.StringAttribute{
				Computed:    true,
				Description: "The API client ID that created the group.",
			},
		},
	}
}

// Read refreshes the Terraform state with the latest data.
func (d *cloudGroupDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data cloudGroupDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiGroup, diags := lookupCloudGroup(ctx, d.client, data.ID, data.Filter)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(data.wrap(ctx, apiGroup)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// notFoundPayloadErrorCode is the code the cloud group lookup APIs report in the
// response payload when a requested group does not exist. The by-ID API answers
// with HTTP 200, an empty resource list, and an error entry carrying this code and
// the requested id, rather than with a 404.
const notFoundPayloadErrorCode = "NotFound"

// diagnosticFromPayloadErrors mirrors tferrors.NewDiagnosticFromPayloadErrors for the
// assetgroupmanager v1 error shape returned by the cloud group lookup APIs, which
// carries a string Code rather than the numeric Code used by models.MsaAPIError, so
// it cannot go through the shared helper directly. A NotFound code becomes a not found
// error described by notFoundDetail. Returns nil when there are no payload errors.
func diagnosticFromPayloadErrors(
	operation tferrors.Operation,
	payloadErrors []*models.AssetgroupmanagerV1Error,
	notFoundDetail string,
) diag.Diagnostic {
	var messages []string
	for _, apiErr := range payloadErrors {
		if apiErr == nil {
			continue
		}

		if apiErr.Code == notFoundPayloadErrorCode {
			return tferrors.NewNotFoundError(notFoundDetail)
		}

		// A NotFound entry carries no message at all, and other entries may
		// describe the failure with the code alone, so fall back to the code
		// instead of emitting an empty detail.
		msg := apiErr.Message
		switch {
		case msg == "":
			msg = apiErr.Code
		case apiErr.Code != "":
			msg = fmt.Sprintf("%s (%s)", msg, apiErr.Code)
		}
		if msg != "" {
			messages = append(messages, msg)
		}
	}

	if len(messages) == 0 {
		return nil
	}

	return tferrors.NewOperationError(operation, errors.New(strings.Join(messages, "; ")))
}

// lookupCloudGroup resolves a single cloud group by ID or by FQL filter. Exactly
// one of id or filter must be known; callers rely on schema validators to enforce
// that.
func lookupCloudGroup(
	ctx context.Context,
	falconClient *client.CrowdStrikeAPISpecification,
	idValue types.String,
	filterValue types.String,
) (*models.AssetgroupmanagerV1CloudGroup, diag.Diagnostics) {
	var diags diag.Diagnostics

	if utils.IsKnown(idValue) {
		id := idValue.ValueString()

		tflog.Debug(ctx, "[datasource] Looking up cloud group by ID", map[string]any{
			"id": id,
		})

		res, err := falconClient.CloudSecurity.ListCloudGroupsByIDExternal(
			&cloud_security.ListCloudGroupsByIDExternalParams{
				Context: ctx,
				Ids:     []string{id},
			},
		)
		notFoundDetail := fmt.Sprintf("No cloud group found with ID %q.", id)
		if err != nil {
			diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, dataSourceApiScopes, tferrors.WithNotFoundDetail(notFoundDetail)))
			return nil, diags
		}

		if res == nil || res.Payload == nil {
			diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
			return nil, diags
		}

		if payloadDiag := diagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors, notFoundDetail); payloadDiag != nil {
			diags.Append(payloadDiag)
			return nil, diags
		}

		if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
			diags.Append(tferrors.NewNotFoundError(notFoundDetail))
			return nil, diags
		}

		return res.Payload.Resources[0], diags
	}

	filter := filterValue.ValueString()

	tflog.Debug(ctx, "[datasource] Looking up cloud group by filter", map[string]any{
		"filter": filter,
	})

	limit := filterQueryLimit
	res, err := falconClient.CloudSecurity.ListCloudGroupsExternal(
		&cloud_security.ListCloudGroupsExternalParams{
			Context: ctx,
			Filter:  &filter,
			Limit:   &limit,
		},
	)
	notFoundDetail := fmt.Sprintf("No cloud group matched the filter %q.", filter)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, dataSourceApiScopes, tferrors.WithNotFoundDetail(notFoundDetail)))
		return nil, diags
	}

	if res == nil || res.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	if payloadDiag := diagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors, notFoundDetail); payloadDiag != nil {
		diags.Append(payloadDiag)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewNotFoundError(notFoundDetail))
		return nil, diags
	}

	// The page is capped at filterQueryLimit, so the pagination total is the only
	// reliable source for how many groups actually matched. Fall back to the page
	// size if a response ever arrives without it.
	matched := int64(len(res.Payload.Resources))
	if res.Payload.Meta != nil && res.Payload.Meta.Pagination != nil &&
		res.Payload.Meta.Pagination.Total > 0 {
		matched = res.Payload.Meta.Pagination.Total
	}

	if matched > 1 {
		diags.AddError(
			"Multiple cloud groups matched",
			fmt.Sprintf("The filter %q matched %d cloud groups, but exactly one is required. Narrow the filter until it matches a single group, for example by adding environment or business_unit, or look the group up by id.", filter, matched),
		)
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}
