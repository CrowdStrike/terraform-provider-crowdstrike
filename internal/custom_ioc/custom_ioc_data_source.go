package customioc

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ioc"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"

	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource                   = &customIOCDataSource{}
	_ datasource.DataSourceWithConfigure      = &customIOCDataSource{}
	_ datasource.DataSourceWithValidateConfig = &customIOCDataSource{}
)

var customIOCDataSourceScopes = []scopes.Scope{{Name: "IOC Management", Read: true}}

type customIOCDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

func NewCustomIOCDataSource() datasource.DataSource { return &customIOCDataSource{} }

func (d *customIOCDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_custom_ioc"
}

func (d *customIOCDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	providerConfig, ok := req.ProviderData.(config.ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type", fmt.Sprintf("Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.", req.ProviderData))
		return
	}
	d.client = providerConfig.Client
}

func (d *customIOCDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription("Endpoint Security", "Looks up a single custom IOC by ID or by type and exact value. The lookup fails if no object or multiple objects match. Use an ID to disambiguate matches.", customIOCDataSourceScopes),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier. Specify either `id` or both `type` and `value`.",
				Optional:            true,
				Validators:          []validator.String{fwvalidators.StringNotWhitespace()},
			},
			"type": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "IOC type. Required with `value` when `id` is omitted.",
				Optional:            true,
				Validators:          []validator.String{fwvalidators.StringNotWhitespace(), stringvalidator.OneOf(allTypes...)},
			},
			"value": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Exact, case-sensitive indicator value. Required with `type` when `id` is omitted.",
				Optional:            true,
				Validators:          []validator.String{fwvalidators.StringNotWhitespace()},
			},
			"action": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The action on non-mobile platforms (`windows`, `mac`, `linux`), or null when it does not apply.",
			},
			"mobile_action": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The action on mobile platforms (`ios`, `android`), or null when it does not apply.",
			},
			"severity": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The severity level of the IOC indicator, if configured.",
			},
			"description": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "A description of the IOC indicator.",
			},
			"platforms": schema.SetAttribute{
				Computed:            true,
				MarkdownDescription: "The platforms this IOC indicator applies to. Valid values are: `windows`, `mac`, `linux`, `ios`, `android`. Hash types (`sha256`, `md5`) only support non-mobile platforms (`windows`, `mac`, `linux`); `all_subdomains` only supports mobile platforms (`ios`, `android`).",
				ElementType:         types.StringType,
			},
			"host_groups": schema.SetAttribute{
				Computed:            true,
				MarkdownDescription: "Host group IDs that receive this indicator. Contains `[\"all\"]` when applied globally.",
				ElementType:         types.StringType,
			},
			"applied_globally": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the indicator is applied globally to all hosts.",
			},
			"expiration": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The expiration date in RFC3339 format, or null if the indicator does not expire.",
				CustomType:          timetypes.RFC3339Type{},
			},
			"source": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The source of the IOC indicator.",
			},
			"tags": schema.SetAttribute{
				Computed:            true,
				MarkdownDescription: "The tags attached to the IOC indicator.",
				ElementType:         types.StringType,
			},
			"created_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who created the IOC indicator.",
			},
			"created_on": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when the IOC indicator was created.",
			},
			"modified_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who last modified the IOC indicator.",
			},
			"modified_on": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when the IOC indicator was last modified.",
			},
		},
	}
}

func (d *customIOCDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data customIOCResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, diags := d.lookup(ctx, data.ID.ValueString(), data.Type.ValueString(), data.Value.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(data.wrap(ctx, result)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *customIOCDataSource) get(ctx context.Context, ids []string) ([]*models.APIIndicatorV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	params := ioc.NewIndicatorGetV1ParamsWithContext(ctx).WithIds(ids)
	response, err := d.client.Ioc.IndicatorGetV1(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, customIOCDataSourceScopes))
		return nil, diags
	}
	if response == nil || response.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}
	if diagnostic := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, response.Payload.Errors); diagnostic != nil {
		diags.Append(diagnostic)
		return nil, diags
	}
	return response.Payload.Resources, diags
}

func (d *customIOCDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var data customIOCResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Unknown lookup values are resolved before Read and still count as configured.
	hasID, hasType, hasValue := !data.ID.IsNull(), !data.Type.IsNull(), !data.Value.IsNull()
	if (hasID && (hasType || hasValue)) || (!hasID && (!hasType || !hasValue)) {
		resp.Diagnostics.AddError("Invalid IOC lookup", "Specify either id or both type and value.")
	}
}

func (d *customIOCDataSource) lookup(ctx context.Context, id, indicatorType, value string) (*models.APIIndicatorV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	if id != "" {
		results, readDiags := d.get(ctx, []string{id})
		diags.Append(readDiags...)
		if diags.HasError() {
			return nil, diags
		}
		for _, result := range results {
			if result != nil && !result.Deleted && result.ID == id {
				return result, diags
			}
		}
		diags.Append(tferrors.NewNotFoundError(fmt.Sprintf("No custom IOC found with ID %q.", id)))
		return nil, diags
	}
	escaped := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(value)
	filter := fmt.Sprintf("type:'%s'+value:'%s'", indicatorType, escaped)
	const limit int64 = 100
	var after string
	var retrieved int64
	var match *models.APIIndicatorV1
	seenCursors := map[string]bool{}
	for {
		params := ioc.NewIndicatorCombinedV1ParamsWithContext(ctx).WithFilter(&filter).WithLimit(utils.Addr(limit))
		if after != "" {
			params.SetAfter(&after)
		}
		response, err := d.client.Ioc.IndicatorCombinedV1(params)
		if err != nil {
			diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, customIOCDataSourceScopes))
			return nil, diags
		}
		if response == nil || response.Payload == nil {
			diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
			return nil, diags
		}
		payload := response.Payload
		if diagnostic := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, payload.Errors); diagnostic != nil {
			diags.Append(diagnostic)
			return nil, diags
		}
		for _, result := range payload.Resources {
			if result == nil || result.Deleted || result.Type != indicatorType || result.Value != value {
				continue
			}
			if result.ID == "" {
				diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
				return nil, diags
			}
			if match != nil && match.ID != result.ID {
				diags.AddError("Ambiguous custom IOC lookup", "More than one custom IOC matches the exact type and value. Specify an ID instead.")
				return nil, diags
			}
			match = result
		}
		next := ""
		retrieved += int64(len(payload.Resources))
		var total *int64
		if payload.Meta != nil && payload.Meta.Pagination != nil {
			next = payload.Meta.Pagination.After
			total = payload.Meta.Pagination.Total
		}
		if next == "" {
			if (total != nil && retrieved < *total) || (total == nil && int64(len(payload.Resources)) >= limit) {
				diags.AddError("Incomplete custom IOC lookup", "The API did not provide a continuation token for the remaining results. Retry the lookup or use an ID.")
				return nil, diags
			}
			break
		}
		if seenCursors[next] {
			diags.AddError("Incomplete custom IOC lookup", "The API pagination did not advance. Retry the lookup.")
			return nil, diags
		}
		seenCursors[next] = true
		after = next
	}
	if match == nil {
		diags.Append(tferrors.NewNotFoundError(fmt.Sprintf("No custom IOC found with exact type %q and value %q.", indicatorType, value)))
	}
	return match, diags
}
