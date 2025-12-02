package cloudsecurity

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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

var (
	_ datasource.DataSource              = &cloudRiskFindingsDataSource{}
	_ datasource.DataSourceWithConfigure = &cloudRiskFindingsDataSource{}
)

func NewCloudRiskFindingsDataSource() datasource.DataSource {
	return &cloudRiskFindingsDataSource{}
}

type cloudRiskFindingsDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudRiskFindingsDataSourceModel struct {
	Filter types.String `tfsdk:"filter"`
	Sort   types.String `tfsdk:"sort"`
	Risks  types.Set    `tfsdk:"risks"`
}

func (r *cloudRiskFindingsDataSource) Configure(
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

func (r *cloudRiskFindingsDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_risk_findings"
}

func (r *cloudRiskFindingsDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Falcon Cloud Security",
			"This data source retrieves cloud risk findings from Falcon Cloud Security. Cloud risks represent security findings and misconfigurations detected in cloud environments. For advanced queries, use Falcon Query Language (FQL) filters. For more information, refer to the [Cloud Risks API documentation](https://docs.crowdstrike.com/r/ed2aed27).",
			cloudRisksScopes,
		),
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "FQL filter string. Supported fields: `account_id`, `account_name`, `asset_gcrn`, `asset_id`, `asset_name`, `asset_region`, `asset_type`, `cloud_group`, `cloud_provider`, `first_seen`, `last_seen`, `resolved_at`, `risk_factor`, `rule_id`, `rule_name`, `service_category`, `severity`, `status`, `suppressed_by`, `suppressed_reason`, `tags`. Example: `severity:'High'+status:'open'`",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"sort": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The field to sort on. Use `.asc` or `.desc` suffix to specify sort direction. Supported fields: `account_id`, `account_name`, `asset_id`, `asset_name`, `asset_region`, `asset_type`, `cloud_provider`, `first_seen`, `last_seen`, `resolved_at`, `rule_name`, `service_category`, `severity`, `status`. Example: `first_seen.desc`",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
					validators.SortField([]string{
						"account_id", "account_name", "asset_id", "asset_name",
						"asset_region", "asset_type", "cloud_provider", "first_seen",
						"last_seen", "resolved_at", "rule_name", "service_category",
						"severity", "status",
					}),
				},
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

func (r *cloudRiskFindingsDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data cloudRiskFindingsDataSourceModel

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

func (r *cloudRiskFindingsDataSource) getAllRisks(
	ctx context.Context,
	config *cloudRiskFindingsDataSourceModel,
) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics
	allRisks := make([]cloudRiskModel, 0)

	limit := int64(500)
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

		tflog.Debug(ctx, "Fetching cloud risk findings page", map[string]interface{}{
			"offset": offset,
			"limit":  limit,
			"filter": config.Filter.ValueString(),
		})

		response, err := r.client.CloudSecurity.CombinedCloudRisks(params)
		if err != nil {
			diags.Append(tferrors.NewOperationError(tferrors.Read, err))
			break
		}

		if response == nil || response.Payload == nil || len(response.Payload.Resources) == 0 {
			break
		}

		payload := response.GetPayload()

		if err = falcon.AssertNoError(payload.Errors); err != nil {
			diags.Append(tferrors.NewOperationError(tferrors.Read, err))
			break
		}

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
				AssetTags:       types.ListValueMust(types.StringType, []attr.Value{}),
				CloudProvider:   types.StringPointerValue(risk.Provider),
				CloudGroups:     types.ListValueMust(types.StringType, []attr.Value{}),
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

			if len(risk.AssetTags) > 0 {
				assetTags, diag := types.ListValueFrom(ctx, types.StringType, risk.AssetTags)
				diags.Append(diag...)
				if diags.HasError() {
					break
				}
				riskModel.AssetTags = assetTags
			}

			if len(risk.CloudGroups) > 0 {
				cloudGroups, diag := types.ListValueFrom(ctx, types.StringType, risk.CloudGroups)
				diags.Append(diag...)
				if diags.HasError() {
					break
				}
				riskModel.CloudGroups = cloudGroups
			}

			allRisks = append(allRisks, riskModel)
		}

		if diags.HasError() {
			break
		}

		offset += limit
	}

	risksSet, convertDiags := types.SetValueFrom(
		ctx,
		types.ObjectType{AttrTypes: cloudRiskModel{}.AttributeTypes()},
		allRisks,
	)
	diags.Append(convertDiags...)

	return risksSet, diags
}
