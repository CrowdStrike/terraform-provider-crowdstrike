package itautomation

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/it_automation"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	policiesDataSourceDocumentationSection = "IT Automation"
	policiesDataSourceMarkdownDescription  = "This data source provides information about IT Automation policies in CrowdStrike Falcon. Use this to look up policies by platform, name, or other attributes and reference them in other resources."
)

var policiesDataSourceApiScopes = []scopes.Scope{
	{
		Name:  "IT Automation - Policies",
		Read:  true,
		Write: false,
	},
}

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource                   = &itAutomationPoliciesDataSource{}
	_ datasource.DataSourceWithConfigure      = &itAutomationPoliciesDataSource{}
	_ datasource.DataSourceWithValidateConfig = &itAutomationPoliciesDataSource{}
)

// NewItAutomationPoliciesDataSource is a helper function to simplify the provider implementation.
func NewItAutomationPoliciesDataSource() datasource.DataSource {
	return &itAutomationPoliciesDataSource{}
}

// itAutomationPoliciesDataSource is the data source implementation.
type itAutomationPoliciesDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

// itAutomationPolicyDataModel represents a single policy in the data source output.
type itAutomationPolicyDataModel struct {
	ID                              types.String `tfsdk:"id"`
	Name                            types.String `tfsdk:"name"`
	Description                     types.String `tfsdk:"description"`
	PlatformName                    types.String `tfsdk:"platform_name"`
	Enabled                         types.Bool   `tfsdk:"enabled"`
	Precedence                      types.Int32  `tfsdk:"precedence"`
	HostGroups                      types.List   `tfsdk:"host_groups"`
	ConcurrentHostFileTransferLimit types.Int32  `tfsdk:"concurrent_host_file_transfer_limit"`
	ConcurrentHostLimit             types.Int32  `tfsdk:"concurrent_host_limit"`
	ConcurrentTaskLimit             types.Int32  `tfsdk:"concurrent_task_limit"`
	CPUSchedulingPriority           types.String `tfsdk:"cpu_scheduling_priority"`
	CPUThrottle                     types.Int32  `tfsdk:"cpu_throttle"`
	EnableOsQuery                   types.Bool   `tfsdk:"enable_os_query"`
	EnablePythonExecution           types.Bool   `tfsdk:"enable_python_execution"`
	EnableScriptExecution           types.Bool   `tfsdk:"enable_script_execution"`
	ExecutionTimeout                types.Int32  `tfsdk:"execution_timeout"`
	ExecutionTimeoutUnit            types.String `tfsdk:"execution_timeout_unit"`
	MemoryAllocation                types.Int32  `tfsdk:"memory_allocation"`
	MemoryAllocationUnit            types.String `tfsdk:"memory_allocation_unit"`
	MemoryPressureLevel             types.String `tfsdk:"memory_pressure_level"`
	CreatedAt                       types.String `tfsdk:"created_at"`
	CreatedBy                       types.String `tfsdk:"created_by"`
	ModifiedAt                      types.String `tfsdk:"modified_at"`
	ModifiedBy                      types.String `tfsdk:"modified_by"`
}

func (m itAutomationPolicyDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                                  types.StringType,
		"name":                                types.StringType,
		"description":                         types.StringType,
		"platform_name":                       types.StringType,
		"enabled":                             types.BoolType,
		"precedence":                          types.Int32Type,
		"host_groups":                         types.ListType{ElemType: types.StringType},
		"concurrent_host_file_transfer_limit": types.Int32Type,
		"concurrent_host_limit":               types.Int32Type,
		"concurrent_task_limit":               types.Int32Type,
		"cpu_scheduling_priority":             types.StringType,
		"cpu_throttle":                        types.Int32Type,
		"enable_os_query":                     types.BoolType,
		"enable_python_execution":             types.BoolType,
		"enable_script_execution":             types.BoolType,
		"execution_timeout":                   types.Int32Type,
		"execution_timeout_unit":              types.StringType,
		"memory_allocation":                   types.Int32Type,
		"memory_allocation_unit":              types.StringType,
		"memory_pressure_level":               types.StringType,
		"created_at":                          types.StringType,
		"created_by":                          types.StringType,
		"modified_at":                         types.StringType,
		"modified_by":                         types.StringType,
	}
}

// wrapPolicy converts an API policy into the data model.
func (m *itAutomationPolicyDataModel) wrapPolicy(
	ctx context.Context,
	policy *models.ItautomationPolicy,
) diag.Diagnostics {
	var diags diag.Diagnostics
	if policy == nil {
		return diags
	}

	m.ID = types.StringPointerValue(policy.ID)
	m.Name = types.StringPointerValue(policy.Name)
	m.Description = types.StringPointerValue(policy.Description)
	m.PlatformName = types.StringPointerValue(policy.Target)
	m.Enabled = types.BoolValue(policy.IsEnabled)
	m.Precedence = types.Int32Value(policy.Precedence)
	m.CreatedAt = types.StringPointerValue(policy.CreatedAt)
	m.CreatedBy = types.StringPointerValue(policy.CreatedBy)
	m.ModifiedAt = types.StringPointerValue(policy.ModifiedAt)
	m.ModifiedBy = types.StringPointerValue(policy.ModifiedBy)

	m.HostGroups = utils.SliceToListTypeString(ctx, policy.HostGroups, &diags)

	m.wrapConcurrency(policy.Config)
	m.wrapExecution(policy.Config)
	m.wrapResources(policy.Config, policy.Target)

	return diags
}

func (m *itAutomationPolicyDataModel) wrapConcurrency(config *models.ItautomationPolicyConfig) {
	if config == nil || config.Concurrency == nil {
		m.ConcurrentHostFileTransferLimit = types.Int32Null()
		m.ConcurrentHostLimit = types.Int32Null()
		m.ConcurrentTaskLimit = types.Int32Null()
		return
	}

	c := config.Concurrency
	m.ConcurrentHostFileTransferLimit = types.Int32Value(c.ConcurrentHostFileTransferLimit)
	m.ConcurrentHostLimit = types.Int32Value(c.ConcurrentHostLimit)
	m.ConcurrentTaskLimit = types.Int32Value(c.ConcurrentTaskLimit)
}

func (m *itAutomationPolicyDataModel) wrapExecution(config *models.ItautomationPolicyConfig) {
	if config == nil || config.Execution == nil {
		m.EnableOsQuery = types.BoolNull()
		m.EnablePythonExecution = types.BoolNull()
		m.EnableScriptExecution = types.BoolNull()
		m.ExecutionTimeout = types.Int32Null()
		m.ExecutionTimeoutUnit = types.StringNull()
		return
	}

	e := config.Execution
	m.EnableOsQuery = types.BoolPointerValue(e.EnableOsQuery)
	m.EnablePythonExecution = types.BoolPointerValue(e.EnablePythonExecution)
	m.EnableScriptExecution = types.BoolPointerValue(e.EnableScriptExecution)
	m.ExecutionTimeout = types.Int32Value(e.ExecutionTimeout)
	m.ExecutionTimeoutUnit = types.StringValue(e.ExecutionTimeoutUnit)
}

func (m *itAutomationPolicyDataModel) wrapResources(
	config *models.ItautomationPolicyConfig,
	target *string,
) {
	m.CPUSchedulingPriority = types.StringNull()
	m.MemoryPressureLevel = types.StringNull()
	m.CPUThrottle = types.Int32Null()
	m.MemoryAllocation = types.Int32Null()
	m.MemoryAllocationUnit = types.StringNull()

	if config == nil || config.Resources == nil {
		return
	}

	r := config.Resources

	if target != nil && *target == "Mac" {
		m.CPUSchedulingPriority = types.StringValue(r.CPUScheduling)
		m.MemoryPressureLevel = types.StringValue(r.MemoryPressureLevel)
		return
	}

	m.CPUThrottle = types.Int32Value(r.CPUThrottle)
	m.MemoryAllocation = types.Int32Value(r.MemoryAllocation)
	m.MemoryAllocationUnit = types.StringValue(r.MemoryAllocationUnit)
}

// itAutomationPoliciesDataSourceModel is the top level data source model.
type itAutomationPoliciesDataSourceModel struct {
	IDs          types.List   `tfsdk:"ids"`
	PlatformName types.String `tfsdk:"platform_name"`
	Sort         types.String `tfsdk:"sort"`
	Name         types.String `tfsdk:"name"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	Policies     types.List   `tfsdk:"policies"`
}

func (m itAutomationPoliciesDataSourceModel) hasFilterAttributes() bool {
	return utils.IsKnown(m.PlatformName) ||
		utils.IsKnown(m.Name) ||
		utils.IsKnown(m.Enabled)
}

func (m *itAutomationPoliciesDataSourceModel) wrap(
	ctx context.Context,
	policies []*models.ItautomationPolicy,
) diag.Diagnostics {
	var diags diag.Diagnostics
	policyModels := make([]itAutomationPolicyDataModel, 0, len(policies))
	for _, policy := range policies {
		if policy == nil {
			continue
		}

		pm := itAutomationPolicyDataModel{}
		diags.Append(pm.wrapPolicy(ctx, policy)...)
		if diags.HasError() {
			return diags
		}
		policyModels = append(policyModels, pm)
	}

	m.Policies = utils.SliceToListTypeObject(
		ctx,
		policyModels,
		itAutomationPolicyDataModel{}.AttributeTypes(),
		&diags,
	)
	return diags
}

// Configure adds the provider configured client to the data source.
func (d *itAutomationPoliciesDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	cfg, ok := req.ProviderData.(config.ProviderConfig)
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

	d.client = cfg.Client
}

// Metadata returns the data source type name.
func (d *itAutomationPoliciesDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_it_automation_policies"
}

// Schema defines the schema for the data source.
func (d *itAutomationPoliciesDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			policiesDataSourceDocumentationSection,
			policiesDataSourceMarkdownDescription,
			policiesDataSourceApiScopes,
		),
		Attributes: map[string]schema.Attribute{
			"ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of policy IDs to retrieve. Cannot be used together with other filter attributes.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.LengthBetween(32, 32),
					),
					listvalidator.SizeAtLeast(1),
					listvalidator.UniqueValues(),
				},
			},
			"platform_name": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by platform. One of: `Windows`, `Linux`, `Mac`. When omitted and `ids` is not set, queries all platforms. Cannot be used together with `ids`.",
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Linux", "Mac"),
				},
			},
			"sort": schema.StringAttribute{
				Optional:    true,
				Description: "Sort expression for the results. Allowed sort fields: `precedence`, `created_timestamp`, `modified_timestamp`. Example: `precedence|asc`.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by name. Supports wildcard matching with `*`. Matching is case insensitive. Applied client-side after fetching results. Cannot be used together with `ids`.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Filter policies by enabled status. Applied client-side after fetching results. Cannot be used together with `ids`.",
			},
			"policies": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of IT Automation policies.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Identifier for the policy.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the policy.",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "Description of the policy.",
						},
						"platform_name": schema.StringAttribute{
							Computed:    true,
							Description: "Platform for the policy (`Windows`, `Linux`, or `Mac`).",
						},
						"enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the policy is enabled.",
						},
						"precedence": schema.Int32Attribute{
							Computed:    true,
							Description: "Priority level of the policy.",
						},
						"host_groups": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Host group IDs associated with this policy.",
						},
						"concurrent_host_file_transfer_limit": schema.Int32Attribute{
							Computed:    true,
							Description: "Maximum number of hosts that can transfer files simultaneously.",
						},
						"concurrent_host_limit": schema.Int32Attribute{
							Computed:    true,
							Description: "Maximum number of hosts that can run operations simultaneously.",
						},
						"concurrent_task_limit": schema.Int32Attribute{
							Computed:    true,
							Description: "Maximum number of tasks that can run in parallel.",
						},
						"cpu_scheduling_priority": schema.StringAttribute{
							Computed:    true,
							Description: "CPU scheduling priority (Mac only).",
						},
						"cpu_throttle": schema.Int32Attribute{
							Computed:    true,
							Description: "CPU usage limit as a percentage (Windows/Linux only).",
						},
						"enable_os_query": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether OSQuery functionality is enabled.",
						},
						"enable_python_execution": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether Python script execution is enabled.",
						},
						"enable_script_execution": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether script execution is enabled.",
						},
						"execution_timeout": schema.Int32Attribute{
							Computed:    true,
							Description: "Maximum time a script can run before timing out.",
						},
						"execution_timeout_unit": schema.StringAttribute{
							Computed:    true,
							Description: "Unit of time for execution timeout.",
						},
						"memory_allocation": schema.Int32Attribute{
							Computed:    true,
							Description: "Amount of memory allocated (Windows/Linux only).",
						},
						"memory_allocation_unit": schema.StringAttribute{
							Computed:    true,
							Description: "Unit for memory allocation (Windows/Linux only).",
						},
						"memory_pressure_level": schema.StringAttribute{
							Computed:    true,
							Description: "Memory pressure level (Mac only).",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the policy was created.",
						},
						"created_by": schema.StringAttribute{
							Computed:    true,
							Description: "User who created the policy.",
						},
						"modified_at": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the policy was last modified.",
						},
						"modified_by": schema.StringAttribute{
							Computed:    true,
							Description: "User who last modified the policy.",
						},
					},
				},
			},
		},
	}
}

// ValidateConfig validates mutually exclusive attributes.
func (d *itAutomationPoliciesDataSource) ValidateConfig(
	ctx context.Context,
	req datasource.ValidateConfigRequest,
	resp *datasource.ValidateConfigResponse,
) {
	var data itAutomationPoliciesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasIDs := utils.IsKnown(data.IDs) && len(data.IDs.Elements()) > 0

	if hasIDs && data.hasFilterAttributes() {
		resp.Diagnostics.AddError(
			"Invalid Attribute Combination",
			"Cannot specify `ids` together with filter attributes (`platform_name`, `name`, `enabled`). Use either `ids` for direct lookups or filter attributes for a query.",
		)
	}
}

// Read fetches the policies based on the provided filters.
func (d *itAutomationPoliciesDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data itAutomationPoliciesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var policies []*models.ItautomationPolicy

	if utils.IsKnown(data.IDs) && len(data.IDs.Elements()) > 0 {
		requestedIDs := utils.ListTypeAs[string](ctx, data.IDs, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		fetched, diags := d.getPoliciesByIDs(ctx, requestedIDs)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		policies = fetched
	} else {
		platforms := []string{"Windows", "Linux", "Mac"}
		if utils.IsKnown(data.PlatformName) {
			platforms = []string{data.PlatformName.ValueString()}
		}

		sortExpr := data.Sort.ValueString()

		for _, platform := range platforms {
			ids, diags := d.queryPolicyIDs(ctx, platform, sortExpr)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}

			if len(ids) == 0 {
				continue
			}

			fetched, diags := d.getPoliciesByIDs(ctx, ids)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}
			policies = append(policies, fetched...)
		}

		policies = filterPoliciesClientSide(policies, &data)
	}

	resp.Diagnostics.Append(data.wrap(ctx, policies)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// queryPolicyIDs paginates through ITAutomationQueryPolicies for a given platform.
func (d *itAutomationPoliciesDataSource) queryPolicyIDs(
	ctx context.Context,
	platform string,
	sort string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allIDs []string

	limit := int64(paginationLimit)
	offset := int64(0)

	for {
		params := &it_automation.ITAutomationQueryPoliciesParams{
			Context:  ctx,
			Limit:    &limit,
			Offset:   &offset,
			Platform: platform,
		}
		if sort != "" {
			params.Sort = &sort
		}

		res, err := d.client.ItAutomation.ITAutomationQueryPolicies(params)
		if err != nil {
			diags.AddError(
				"Error querying IT automation policies",
				fmt.Sprintf("Could not query policies for platform %s: %s", platform, err.Error()),
			)
			return allIDs, diags
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			break
		}

		allIDs = append(allIDs, res.Payload.Resources...)

		tflog.Debug(ctx, "[datasource] Retrieved page of IT automation policy ids",
			map[string]any{
				"platform":    platform,
				"page_count":  len(res.Payload.Resources),
				"total_count": len(allIDs),
				"offset":      offset,
			})

		if len(res.Payload.Resources) < int(limit) {
			break
		}

		offset += limit
	}

	return allIDs, diags
}

// getPoliciesByIDs fetches full policy objects in batches.
func (d *itAutomationPoliciesDataSource) getPoliciesByIDs(
	ctx context.Context,
	ids []string,
) ([]*models.ItautomationPolicy, diag.Diagnostics) {
	var diags diag.Diagnostics
	var all []*models.ItautomationPolicy

	if len(ids) == 0 {
		return all, diags
	}

	batchSize := 100
	for start := 0; start < len(ids); start += batchSize {
		end := min(start+batchSize, len(ids))
		batch := ids[start:end]

		res, err := d.client.ItAutomation.ITAutomationGetPolicies(
			&it_automation.ITAutomationGetPoliciesParams{
				Context: ctx,
				Ids:     batch,
			},
		)
		if err != nil {
			diags.AddError(
				"Error reading IT automation policies",
				fmt.Sprintf("Could not read policies: %s", err.Error()),
			)
			return all, diags
		}

		if res == nil || res.Payload == nil {
			continue
		}

		all = append(all, res.Payload.Resources...)
	}

	return all, diags
}

// filterPoliciesClientSide applies the name and enabled filters.
func filterPoliciesClientSide(
	policies []*models.ItautomationPolicy,
	data *itAutomationPoliciesDataSourceModel,
) []*models.ItautomationPolicy {
	if !utils.IsKnown(data.Name) && !utils.IsKnown(data.Enabled) {
		return policies
	}

	filtered := make([]*models.ItautomationPolicy, 0, len(policies))
	for _, policy := range policies {
		if policy == nil {
			continue
		}

		if utils.IsKnown(data.Name) {
			if policy.Name == nil || !utils.MatchesWildcard(*policy.Name, data.Name.ValueString()) {
				continue
			}
		}

		if utils.IsKnown(data.Enabled) {
			if policy.IsEnabled != data.Enabled.ValueBool() {
				continue
			}
		}

		filtered = append(filtered, policy)
	}
	return filtered
}
