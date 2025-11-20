package cloudsecurity

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &cloudRisksAllDataSource{}
	_ datasource.DataSourceWithConfigure = &cloudRisksAllDataSource{}
)

func NewCloudRisksAllDataSource() datasource.DataSource {
	return &cloudRisksAllDataSource{}
}

type cloudRisksAllDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudRisksAllDataSourceModel struct {
	Filter types.String `tfsdk:"filter"`
	Sort   types.String `tfsdk:"sort"`
	Risks  types.Set    `tfsdk:"risks"`
}

func (r *cloudRisksAllDataSource) Configure(
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

func (r *cloudRisksAllDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_risks_all"
}

func (r *cloudRisksAllDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Falcon Cloud Security",
			"This data source automatically retrieves **all** cloud risks matching the specified filter criteria by handling pagination internally. Unlike `crowdstrike_cloud_risks`, this data source fetches all pages automatically and returns the complete set of results. Use this when you need all risks without manually managing pagination. For pagination control and metadata, use `crowdstrike_cloud_risks` instead. Cloud risks represent security findings and misconfigurations detected in cloud environments. For advanced queries, use Falcon Query Language (FQL) filters. For more information, refer to the [Cloud Risks API documentation](https://falcon.crowdstrike.com/documentation/page/ed2aed27/cloud-risks).",
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
			"risks": schema.SetNestedAttribute{
				Computed:    true,
				Description: "Complete list of all cloud risks matching the filter criteria",
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
		},
	}
}

func (r *cloudRisksAllDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data cloudRisksAllDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	risks, diags := r.getAllRisks(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.Risks = risks

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudRisksAllDataSource) getAllRisks(
	ctx context.Context,
	config *cloudRisksAllDataSourceModel,
) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics
	allRisks := make([]cloudRiskModel, 0)

	defaultResponse := types.SetValueMust(
		types.ObjectType{AttrTypes: cloudRiskModel{}.AttributeTypes()},
		[]attr.Value{},
	)

	// Set up parameters with automatic pagination
	limit := int64(500) // Use larger page size for efficiency
	offset := int64(0)

	for {
		params := cloud_security.NewCombinedCloudRisksParams().WithContext(ctx)
		params.SetLimit(&limit)
		params.SetOffset(&offset)

		if !config.Filter.IsNull() {
			filter := config.Filter.ValueString()
			params.SetFilter(&filter)
		}

		if !config.Sort.IsNull() {
			sort := config.Sort.ValueString()
			params.SetSort(&sort)
		}

		tflog.Debug(ctx, "Fetching cloud risks page", map[string]interface{}{
			"offset": offset,
			"limit":  limit,
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

		// Check pagination - stop if we've fetched all results
		if payload.Meta == nil || payload.Meta.Pagination == nil || payload.Meta.Pagination.Total == nil {
			diags.AddError(
				"Error Fetching Cloud Risks",
				"The API returned a response without pagination metadata. Cannot safely paginate results.",
			)
			return defaultResponse, diags
		}

		pagination := payload.Meta.Pagination
		totalAvailable := *pagination.Total

		tflog.Debug(ctx, "Cloud risks page fetched", map[string]interface{}{
			"offset":   offset,
			"returned": len(payload.Resources),
			"total":    totalAvailable,
		})

		// Check if we've reached the end
		nextOffset := offset + int64(len(payload.Resources))
		if nextOffset >= totalAvailable {
			tflog.Info(ctx, "Pagination complete", map[string]interface{}{
				"total_fetched": len(allRisks),
				"total":         totalAvailable,
			})
			break
		}

		offset = nextOffset
	}

	tflog.Info(ctx, "All cloud risks collected", map[string]interface{}{
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
