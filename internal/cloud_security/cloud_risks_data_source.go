package cloudsecurity

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &cloudRisksDataSource{}
	_ datasource.DataSourceWithConfigure = &cloudRisksDataSource{}
)

var cloudRisksScopes = []scopes.Scope{
	{
		Name:  "Cloud Security Risks",
		Read:  true,
		Write: false,
	},
	{
		Name:  "Cloud Security Assets",
		Read:  true,
		Write: false,
	},
}

func NewCloudRisksDataSource() datasource.DataSource {
	return &cloudRisksDataSource{}
}

type cloudRisksDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudRisksDataSourceModel struct {
	Filter        types.String `tfsdk:"filter"`
	Sort          types.String `tfsdk:"sort"`
	Limit         types.Int64  `tfsdk:"limit"`
	Offset        types.Int64  `tfsdk:"offset"`
	Risks         types.Set    `tfsdk:"risks"`
	TotalCount    types.Int64  `tfsdk:"total_count"`
	ReturnedCount types.Int64  `tfsdk:"returned_count"`
	HasMore       types.Bool   `tfsdk:"has_more"`
}

type cloudRiskModel struct {
	ID              types.String `tfsdk:"id"`
	AccountID       types.String `tfsdk:"account_id"`
	AccountName     types.String `tfsdk:"account_name"`
	AssetGCRN       types.String `tfsdk:"asset_gcrn"`
	AssetID         types.String `tfsdk:"asset_id"`
	AssetName       types.String `tfsdk:"asset_name"`
	AssetRegion     types.String `tfsdk:"asset_region"`
	AssetType       types.String `tfsdk:"asset_type"`
	AssetTags       types.List   `tfsdk:"asset_tags"`
	CloudProvider   types.String `tfsdk:"cloud_provider"`
	CloudGroups     types.List   `tfsdk:"cloud_groups"`
	FirstSeen       types.String `tfsdk:"first_seen"`
	LastSeen        types.String `tfsdk:"last_seen"`
	ResolvedAt      types.String `tfsdk:"resolved_at"`
	RuleID          types.String `tfsdk:"rule_id"`
	RuleName        types.String `tfsdk:"rule_name"`
	RuleDescription types.String `tfsdk:"rule_description"`
	ServiceCategory types.String `tfsdk:"service_category"`
	Severity        types.String `tfsdk:"severity"`
	Status          types.String `tfsdk:"status"`
}

func (m cloudRiskModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":               types.StringType,
		"account_id":       types.StringType,
		"account_name":     types.StringType,
		"asset_gcrn":       types.StringType,
		"asset_id":         types.StringType,
		"asset_name":       types.StringType,
		"asset_region":     types.StringType,
		"asset_type":       types.StringType,
		"asset_tags":       types.ListType{ElemType: types.StringType},
		"cloud_provider":   types.StringType,
		"cloud_groups":     types.ListType{ElemType: types.StringType},
		"first_seen":       types.StringType,
		"last_seen":        types.StringType,
		"resolved_at":      types.StringType,
		"rule_id":          types.StringType,
		"rule_name":        types.StringType,
		"rule_description": types.StringType,
		"service_category": types.StringType,
		"severity":         types.StringType,
		"status":           types.StringType,
	}
}

func (r *cloudRisksDataSource) Configure(
	ctx context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.CrowdStrikeAPISpecification)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf(
				"Expected *client.CrowdStrikeAPISpecification, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	r.client = client
}

func (r *cloudRisksDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_risks"
}

func (r *cloudRisksDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Falcon Cloud Security",
			"This data source retrieves cloud risks with full details based on filters and sort criteria. Cloud risks represent security findings and misconfigurations detected in cloud environments. For advanced queries, use Falcon Query Language (FQL) filters. For more information, refer to the [Cloud Risks API documentation](https://falcon.crowdstrike.com/documentation/page/ed2aed27/cloud-risks).",
			cloudRisksScopes,
		),
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "FQL filter string. Supported fields: `account_id`, `account_name`, `asset_gcrn`, `asset_id`, `asset_name`, `asset_region`, `asset_type`, `cloud_group`, `cloud_provider`, `first_seen`, `last_seen`, `resolved_at`, `risk_factor`, `rule_id`, `rule_name`, `service_category`, `severity`, `status`, `suppressed_by`, `suppressed_reason`, `tags`. Example: `severity:'High'+status:'open'`",
			},
			"sort": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The field to sort on. Use `|asc` or `|desc` suffix to specify sort direction. Supported fields: `account_id`, `account_name`, `asset_id`, `asset_name`, `asset_region`, `asset_type`, `cloud_provider`, `first_seen`, `last_seen`, `resolved_at`, `rule_name`, `service_category`, `severity`, `status`. Example: `first_seen|desc`",
			},
			"limit": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "The maximum number of items to return (page size). Default is 500. Maximum is 1000.",
			},
			"offset": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "The starting index for pagination (0-based). Default is 0. Use with `limit`, `has_more`, and `returned_count` to implement pagination by incrementing offset by the page size until `has_more` is false.",
			},
			"risks": schema.SetNestedAttribute{
				Computed:    true,
				Description: "List of cloud risks",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Unique identifier of the cloud risk.",
						},
						"account_id": schema.StringAttribute{
							Computed:    true,
							Description: "Cloud account ID where the risk was detected.",
						},
						"account_name": schema.StringAttribute{
							Computed:    true,
							Description: "Cloud account name where the risk was detected.",
						},
						"asset_gcrn": schema.StringAttribute{
							Computed:    true,
							Description: "Global Cloud Resource Name (GCRN) of the asset.",
						},
						"asset_id": schema.StringAttribute{
							Computed:    true,
							Description: "Unique identifier of the affected asset.",
						},
						"asset_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the affected asset.",
						},
						"asset_region": schema.StringAttribute{
							Computed:    true,
							Description: "Cloud region where the asset resides.",
						},
						"asset_type": schema.StringAttribute{
							Computed:    true,
							Description: "Type of the affected asset (e.g., 'instance', 'bucket', 'database').",
						},
						"asset_tags": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Tags associated with the asset.",
						},
						"cloud_provider": schema.StringAttribute{
							Computed:    true,
							Description: "Cloud provider where the risk was detected (e.g., 'aws', 'azure', 'gcp').",
						},
						"cloud_groups": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Cloud groups associated with the risk.",
						},
						"first_seen": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the risk was first detected.",
						},
						"last_seen": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the risk was last seen.",
						},
						"resolved_at": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the risk was resolved.",
						},
						"rule_id": schema.StringAttribute{
							Computed:    true,
							Description: "Unique identifier of the rule that detected this risk.",
						},
						"rule_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the rule that detected this risk.",
						},
						"rule_description": schema.StringAttribute{
							Computed:    true,
							Description: "Description of the rule that detected this risk.",
						},
						"service_category": schema.StringAttribute{
							Computed:    true,
							Description: "Service category of the affected resource.",
						},
						"severity": schema.StringAttribute{
							Computed:    true,
							Description: "Severity level of the risk (e.g., 'Critical', 'High', 'Medium', 'Low', 'Informational').",
						},
						"status": schema.StringAttribute{
							Computed:    true,
							Description: "Current status of the risk (e.g., 'open', 'resolved', 'suppressed').",
						},
					},
				},
			},
			"total_count": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Total number of risks available matching the filter criteria.",
			},
			"returned_count": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Number of risks returned in this response.",
			},
			"has_more": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Indicates if there are more results available beyond the current page. Use this with manual pagination to determine when to stop.",
			},
		},
	}
}

func (r *cloudRisksDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data cloudRisksDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	risks, diags := r.getRisks(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.Risks = risks

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudRisksDataSource) getRisks(
	ctx context.Context,
	config *cloudRisksDataSourceModel,
) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics
	allRisks := make([]cloudRiskModel, 0)

	defaultResponse := types.SetValueMust(
		types.ObjectType{AttrTypes: cloudRiskModel{}.AttributeTypes()},
		[]attr.Value{},
	)

	// Set up parameters
	params := cloud_security.NewCombinedCloudRisksParams().WithContext(ctx)

	if !config.Filter.IsNull() {
		filter := config.Filter.ValueString()
		params.SetFilter(&filter)
	}

	if !config.Sort.IsNull() {
		sort := config.Sort.ValueString()
		params.SetSort(&sort)
	}

	// Set user's requested limit if provided (this controls page size, not total results)
	if !config.Limit.IsNull() {
		limit := config.Limit.ValueInt64()
		params.SetLimit(&limit)
	}

	// Determine pagination mode
	var offset int64
	if !config.Offset.IsNull() {
		offset = config.Offset.ValueInt64()
	} else {
		offset = 0
	}
	params.SetOffset(&offset)

	tflog.Debug(ctx, "Fetching cloud risks", map[string]interface{}{
		"offset": offset,
		"filter": config.Filter.ValueString(),
	})

	response, err := r.client.CloudSecurity.CombinedCloudRisks(params)
	if err != nil {
		diags.AddError(
			"Error Querying Cloud Risks",
			fmt.Sprintf("Failed to query cloud risks: %s", err),
		)
		return defaultResponse, diags
	}

	if response == nil || response.Payload == nil {
		diags.AddError(
			"Error Fetching Cloud Risks",
			"The API returned an empty payload.",
		)
		return defaultResponse, diags
	}

	payload := response.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Fetching Cloud Risks",
			fmt.Sprintf("Failed to fetch cloud risks: %s", err.Error()),
		)
		return defaultResponse, diags
	}

	// Convert API response to Terraform models
	for _, risk := range payload.Resources {
		riskModel := cloudRiskModel{
			ID:              types.StringPointerValue(risk.ID),
			AccountID:       types.StringPointerValue(risk.AccountID),
			AccountName:     types.StringPointerValue(risk.AccountName),
			AssetGCRN:       types.StringPointerValue(risk.AssetGcrn),
			AssetID:         types.StringPointerValue(risk.AssetID),
			AssetName:       types.StringPointerValue(risk.AssetName),
			AssetRegion:     types.StringValue(risk.AssetRegion),
			AssetType:       types.StringPointerValue(risk.AssetType),
			CloudProvider:   types.StringPointerValue(risk.Provider),
			RuleID:          types.StringPointerValue(risk.RuleID),
			RuleName:        types.StringPointerValue(risk.RuleName),
			RuleDescription: types.StringPointerValue(risk.RuleDescription),
			ServiceCategory: types.StringPointerValue(risk.ServiceCategory),
			Severity:        types.StringPointerValue(risk.Severity),
			Status:          types.StringPointerValue(risk.Status),
			FirstSeen:       types.StringValue(risk.FirstSeen.String()),
			LastSeen:        types.StringValue(risk.LastSeen.String()),
			ResolvedAt:      types.StringNull(),
		}

		if !risk.ResolvedAt.IsZero() {
			riskModel.ResolvedAt = types.StringValue(risk.ResolvedAt.String())
		}

		// Convert asset tags
		if len(risk.AssetTags) > 0 {
			riskModel.AssetTags, diags = types.ListValueFrom(ctx, types.StringType, risk.AssetTags)
			if diags.HasError() {
				return defaultResponse, diags
			}
		} else {
			riskModel.AssetTags = types.ListValueMust(types.StringType, []attr.Value{})
		}

		// Convert cloud groups
		if len(risk.CloudGroups) > 0 {
			riskModel.CloudGroups, diags = types.ListValueFrom(ctx, types.StringType, risk.CloudGroups)
			if diags.HasError() {
				return defaultResponse, diags
			}
		} else {
			riskModel.CloudGroups = types.ListValueMust(types.StringType, []attr.Value{})
		}

		allRisks = append(allRisks, riskModel)
	}

	if payload.Meta == nil || payload.Meta.Pagination == nil || payload.Meta.Pagination.Total == nil {
		diags.AddError(
			"Error Fetching Cloud Risks",
			"The API returned a response without pagination metadata. Cannot safely paginate results.",
		)
		return defaultResponse, diags
	}
	// Set pagination metadata
	totalAvailable := *payload.Meta.Pagination.Total
	config.TotalCount = types.Int64Value(totalAvailable)
	config.ReturnedCount = types.Int64Value(int64(len(allRisks)))
	nextOffset := offset + int64(len(allRisks))
	config.HasMore = types.BoolValue(nextOffset < totalAvailable)

	tflog.Info(ctx, "Total risks collected", map[string]interface{}{
		"count": len(allRisks),
	})

	risksSet, diags := types.SetValueFrom(
		ctx,
		types.ObjectType{AttrTypes: cloudRiskModel{}.AttributeTypes()},
		allRisks,
	)
	if diags.HasError() {
		return defaultResponse, diags
	}

	return risksSet, diags
}
