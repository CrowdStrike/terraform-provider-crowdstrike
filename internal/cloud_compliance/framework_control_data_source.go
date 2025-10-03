package cloudcompliance

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &cloudComplianceFrameworkControlDataSource{}
	_ datasource.DataSourceWithConfigure = &cloudComplianceFrameworkControlDataSource{}
)

func NewCloudComplianceFrameworkControlDataSource() datasource.DataSource {
	return &cloudComplianceFrameworkControlDataSource{}
}

type cloudComplianceFrameworkControlDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudComplianceFrameworkControlDataSourceModel struct {
	Controls    types.Set    `tfsdk:"controls"`
	Name        types.String `tfsdk:"control_name"`
	Benchmark   types.String `tfsdk:"benchmark"`
	Requirement types.String `tfsdk:"requirement"`
	Section     types.String `tfsdk:"section"`
	FQL         types.String `tfsdk:"fql"`
}

type cloudComplianceFrameworkControlModel struct {
	Authority   types.String `tfsdk:"authority"`
	Code        types.String `tfsdk:"code"`
	Requirement types.String `tfsdk:"requirement"`
	Benchmark   types.String `tfsdk:"benchmark"`
	Name        types.String `tfsdk:"name"`
	Section     types.String `tfsdk:"section"`
	Id          types.String `tfsdk:"id"`
}

type fqlFilters struct {
	value string
	field string
}

func (m cloudComplianceFrameworkControlModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"authority":   types.StringType,
		"code":        types.StringType,
		"requirement": types.StringType,
		"benchmark":   types.StringType,
		"name":        types.StringType,
		"section":     types.StringType,
		"id":          types.StringType,
	}
}

func (r *cloudComplianceFrameworkControlDataSource) Configure(
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
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected *client.CrowdStrikeAPISpecification, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)

		return
	}

	r.client = client
}

func (r *cloudComplianceFrameworkControlDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_compliance_framework_controls"
}

func (r *cloudComplianceFrameworkControlDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Cloud Compliance",
			"This data source retrieves all or a subset of controls within compliance benchmarks. "+
				"All non-FQL fields can accept wildcards `*` and query Falcon using logical AND. If FQL is defined, all other fields will be ignored. "+
				"For advanced queries to further narrow your search, please use a Falcon Query Language (FQL) filter. "+
				"For additional information on FQL filtering and usage, refer to the official CrowdStrike documentation: "+
				"[Falcon Query Language (FQL)](https://falcon.crowdstrike.com/documentation/page/d3c84a1b/falcon-query-language-fql)",
			cloudComplianceFrameworkScopes,
		),
		Attributes: map[string]schema.Attribute{
			"control_name": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Name of the control. Examples: " +
					"`Ensure security contact phone is set`, " +
					"`Ensure that Azure Defender*`",
			},
			"benchmark": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Name of the compliance benchmark in the framework. Examples: " +
					"`AWS Foundational Security Best Practices v1.*`, " +
					"`CIS 1.2.0 GCP`, " +
					"`CIS 1.8.0 GKE`",
			},
			"requirement": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Requirement of the control(s) within the framework. Examples: " +
					"`2.*`, " +
					"`1.1`",
			},
			"section": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Section of the benchmark where the control(s) reside. Examples: " +
					"`Data Protection`, " +
					"`Data*`",
			},
			"fql": schema.StringAttribute{
				Optional: true,
				Description: "Falcon Query Language (FQL) filter for advanced control searches. " +
					"FQL filter, allowed props: " +
					"`compliance_control_name`, " +
					"`compliance_control_authority`, " +
					"`compliance_control_type`, " +
					"`compliance_control_section`, " +
					"`compliance_control_requirement`, " +
					"`compliance_control_benchmark_name`, " +
					"`compliance_control_benchmark_version`",
			},
			"controls": schema.SetNestedAttribute{
				Computed:    true,
				Description: "Security framework and compliance rule information.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"authority": schema.StringAttribute{
							Computed:    true,
							Description: "The compliance authority for the framework",
						},
						"code": schema.StringAttribute{
							Computed:    true,
							Description: "The unique compliance framework rule code.",
						},
						"requirement": schema.StringAttribute{
							Computed:    true,
							Description: "The compliance framework requirement.",
						},
						"benchmark": schema.StringAttribute{
							Computed:    true,
							Description: "The compliance benchmark within the framework.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "The name of the control.",
						},
						"section": schema.StringAttribute{
							Computed:    true,
							Description: "The section within the compliance benchmark.",
						},
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The id of the compliance control.",
						},
					},
				},
			},
		},
	}
}

func (r *cloudComplianceFrameworkControlDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data cloudComplianceFrameworkControlDataSourceModel
	var diags diag.Diagnostics
	var controls []cloudComplianceFrameworkControlModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	fqlFilters := []fqlFilters{
		{data.Benchmark.ValueString(), "compliance_control_benchmark_name"},
		{data.Name.ValueString(), "compliance_control_name"},
		{data.Requirement.ValueString(), "compliance_control_requirement"},
		{data.Section.ValueString(), "compliance_control_section"},
	}

	controls, diags = r.getControls(
		ctx,
		data.FQL.ValueString(),
		fqlFilters,
	)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	data.Controls, diags = types.SetValueFrom(
		ctx,
		types.ObjectType{AttrTypes: cloudComplianceFrameworkControlModel{}.AttributeTypes()},
		controls,
	)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Set State
	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *cloudComplianceFrameworkControlDataSource) getControls(
	ctx context.Context,
	fql string,
	fqlFilters []fqlFilters,
) ([]cloudComplianceFrameworkControlModel, diag.Diagnostics) {
	var controls []cloudComplianceFrameworkControlModel
	var diags diag.Diagnostics
	var filter string
	offset := int64(0)
	limit := int64(500)

	params := cloud_policies.QueryComplianceControlsParams{
		Context: ctx,
		Limit:   &limit,
		Offset:  &offset,
	}

	if fql == "" {
		var filters []string
		for _, f := range fqlFilters {
			if f.value != "" {
				value := strings.ReplaceAll(f.value, "\\", "\\\\\\\\")
				filters = append(filters, fmt.Sprintf("%s:*'%s'", f.field, value))
			}
		}

		if len(filters) > 0 {
			filter = strings.Join(filters, "+")
		}

		if filter != "" {
			params.Filter = &filter
		}
	} else {
		params.Filter = &fql
	}

	for {
		resp, err := r.client.CloudPolicies.QueryComplianceControls(&params)
		if err != nil {
			if badRequest, ok := err.(*cloud_policies.QueryComplianceControlsBadRequest); ok {
				diags.AddError(
					"Error Retrieving Control IDs",
					fmt.Sprintf("Failed to retrieve controls (400): %+v", *badRequest.Payload.Errors[0].Message),
				)
				return controls, diags
			}

			if internalServerError, ok := err.(*cloud_policies.QueryComplianceControlsInternalServerError); ok {
				diags.AddError(
					"Error Retrieving Control IDs",
					fmt.Sprintf("Failed to retrieve controls (500): %+v", *internalServerError.Payload.Errors[0].Message),
				)
				return controls, diags
			}

			diags.AddError(
				"Error Retrieving Control IDs",
				fmt.Sprintf("Failed to retrieve controls: %+v", err),
			)

			return controls, diags
		}

		if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
			return controls, diags
		}

		payload := resp.GetPayload()

		if err = falcon.AssertNoError(payload.Errors); err != nil {
			diags.AddError(
				"Error Retrieving Control IDs",
				fmt.Sprintf("Failed to retrieve control IDs: %s", err.Error()),
			)
			return controls, diags
		}

		if len(payload.Resources) < 1 {
			return controls, diags
		}

		controlsInfo, diags := r.describeControls(ctx, payload.Resources)
		if diags.HasError() {
			return controls, diags
		}

		for _, control := range controlsInfo {
			var benchmark types.String
			if control.SecurityFramework != nil {
				benchmark = types.StringPointerValue(control.SecurityFramework[0].Name)
			}
			controls = append(controls, cloudComplianceFrameworkControlModel{
				Authority:   types.StringPointerValue(control.Authority),
				Code:        types.StringPointerValue(control.Code),
				Requirement: types.StringValue(control.Requirement),
				Benchmark:   benchmark,
				Name:        types.StringPointerValue(control.Name),
				Section:     types.StringValue(control.SectionName),
				Id:          types.StringPointerValue(control.UUID),
			})
		}

		if payload.Meta != nil && payload.Meta.Pagination != nil {
			pagination := payload.Meta.Pagination
			if pagination.Offset != nil && pagination.Total != nil && *pagination.Offset >= int32(*pagination.Total) {
				tflog.Info(ctx, "Pagination complete", map[string]any{"meta": payload.Meta})
				break
			}
		}

		offset += limit
	}

	return controls, diags
}

func (r *cloudComplianceFrameworkControlDataSource) describeControls(ctx context.Context, ids []string) ([]*models.ApimodelsControl, diag.Diagnostics) {
	var diags diag.Diagnostics
	var controls []*models.ApimodelsControl
	params := cloud_policies.GetComplianceControlsParams{
		Context: ctx,
		Ids:     ids,
	}

	resp, err := r.client.CloudPolicies.GetComplianceControls(&params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.GetComplianceControlsBadRequest); ok {
			diags.AddError(
				"Error Retrieving Compliance Control Information",
				fmt.Sprintf("Failed to retrieve compliance control information (400): %+v", *badRequest.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if notFound, ok := err.(*cloud_policies.GetComplianceControlsNotFound); ok {
			diags.AddError(
				"Error Retrieving Compliance Control Information",
				fmt.Sprintf("Failed to retrieve compliance control information (404): %+v", *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.GetComplianceControlsInternalServerError); ok {
			diags.AddError(
				"Error Retrieving Compliance Control Information",
				fmt.Sprintf("Failed to retrieve compliance control information (500): %+v", *internalServerError.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Retrieving Compliance Control Information",
			fmt.Sprintf("Failed to retrieve compliance control information: %+v", err),
		)

		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Retrieving Compliance Control Information",
			"Failed to retrieve compliance control information: The API returned an empty payload.",
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Retrieving Compliance Control Information",
			fmt.Sprintf("Failed to retrieve compliance controls: %s", err.Error()),
		)
		return nil, diags
	}

	controls = payload.Resources

	return controls, diags
}
