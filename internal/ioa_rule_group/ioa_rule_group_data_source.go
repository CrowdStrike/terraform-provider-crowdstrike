package ioarulegroup

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/custom_ioa"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
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
)

var (
	_ datasource.DataSource              = &ioaRuleGroupDataSource{}
	_ datasource.DataSourceWithConfigure = &ioaRuleGroupDataSource{}
)

var dataSourceScopes = []scopes.Scope{{Name: "Custom IOA Rules", Read: true}}

func NewIOARuleGroupDataSource() datasource.DataSource {
	return &ioaRuleGroupDataSource{}
}

type ioaRuleGroupDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type ioaRuleGroupDataSourceModel ioaRuleGroupResourceModel

func (m *ioaRuleGroupDataSourceModel) wrap(ctx context.Context, group models.APIRuleGroupV1) diag.Diagnostics {
	// The API can reorder rules between reads. Instance IDs retain distinct rules
	// with the same name and provide a stable order for this computed list.
	group.Rules = slices.Clone(group.Rules)
	slices.SortStableFunc(group.Rules, func(a, b *models.APIRuleV1) int {
		var aID, bID string
		if a != nil && a.InstanceID != nil {
			aID = *a.InstanceID
		}
		if b != nil && b.InstanceID != nil {
			bID = *b.InstanceID
		}
		return strings.Compare(aID, bID)
	})
	return (*ioaRuleGroupResourceModel)(m).wrap(ctx, &group, nil)
}

func (d *ioaRuleGroupDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *ioaRuleGroupDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ioa_rule_group"
}

func (d *ioaRuleGroupDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	attributes := map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "The IOA rule group ID. Exactly one of `id` or `name` must be provided.",
			Validators:  []validator.String{stringvalidator.LengthBetween(32, 32), stringvalidator.ExactlyOneOf(path.MatchRoot("id"), path.MatchRoot("name"))},
		},
		"name": schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "The exact, case-sensitive name of the IOA rule group. Exactly one of `id` or `name` must be provided.",
			Validators:  []validator.String{validators.StringNotWhitespace()},
		},
		"platform": schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Limit the lookup to `Windows`, `Linux`, or `Mac`. When omitted, names must identify a single group across all platforms.",
			Validators:  []validator.String{stringvalidator.OneOf("Windows", "Linux", "Mac")},
		},
		"enabled": schema.BoolAttribute{Computed: true, Description: "Whether the IOA rule group is enabled."},
		"deleted": schema.BoolAttribute{Computed: true, Description: "Whether the IOA rule group has been deleted. Deleted groups are excluded from lookups."},
		"rules": schema.ListNestedAttribute{
			Computed:     true,
			Description:  "Current IOA rules, ordered by instance ID. Deleted rules are excluded.",
			NestedObject: schema.NestedAttributeObject{Attributes: ioaRuleDataSourceAttributes()},
		},
	}
	for name, description := range map[string]string{
		"description":  "The description of the IOA rule group.",
		"comment":      "The latest audit comment returned by the API for the IOA rule group.",
		"created_by":   "The user who created the rule group.",
		"created_on":   "The timestamp when the rule group was created.",
		"modified_by":  "The user who last modified the rule group.",
		"modified_on":  "The timestamp when the rule group was last modified.",
		"committed_on": "The timestamp when the rule group was committed.",
		"cid":          "The customer ID associated with the rule group.",
	} {
		attributes[name] = schema.StringAttribute{Computed: true, Description: description}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription("Endpoint Security", "Reads a single existing IOA (Indicator of Attack) rule group by ID or exact name, optionally restricted to a platform. Use this data source to reference groups managed outside Terraform or in a separate state. The group must exist before the lookup runs; this data source does not create groups or assign them to policies.", dataSourceScopes),
		Attributes:          attributes,
	}
}

func ioaRuleDataSourceAttributes() map[string]schema.Attribute {
	attributes := map[string]schema.Attribute{
		"enabled":         schema.BoolAttribute{Computed: true, Description: "Whether the rule is enabled."},
		"file_type":       schema.SetAttribute{Computed: true, ElementType: types.StringType, Description: "File types to match for File Creation rules."},
		"connection_type": schema.SetAttribute{Computed: true, ElementType: types.StringType, Description: "Connection types to match for Network Connection rules."},
	}
	for name, description := range map[string]string{
		"instance_id":      "The unique instance ID of the rule.",
		"name":             "The name of the IOA rule.",
		"description":      "The description of the IOA rule.",
		"comment":          "The latest audit comment returned by the API for the rule.",
		"pattern_severity": "The severity of the pattern.",
		"type":             "The rule type.",
		"action":           "The action to take when the rule triggers.",
	} {
		attributes[name] = schema.StringAttribute{Computed: true, Description: description}
	}
	for _, name := range excludableFieldNames {
		attributes[name] = schema.SingleNestedAttribute{
			Computed:    true,
			Description: "Match criteria for `" + name + "`.",
			Attributes: map[string]schema.Attribute{
				"include": schema.StringAttribute{Computed: true, Description: "Regex pattern for inclusion."},
				"exclude": schema.StringAttribute{Computed: true, Description: "Regex pattern for exclusion."},
			},
		}
	}
	return attributes
}

func (d *ioaRuleGroupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state ioaRuleGroupDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	group, diags := d.lookup(ctx, state.ID.ValueString(), state.Name.ValueString(), state.Platform.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(state.wrap(ctx, *group)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (d *ioaRuleGroupDataSource) lookup(ctx context.Context, id, name, platform string) (*models.APIRuleGroupV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	notFound := fmt.Sprintf("No IOA rule group found with exact name %q.", name)
	if id != "" {
		notFound = fmt.Sprintf("No IOA rule group found with ID %q.", id)
	}
	if platform != "" {
		notFound += fmt.Sprintf(" The lookup is restricted to platform %q.", platform)
	}

	if id != "" {
		params := custom_ioa.NewGetRuleGroupsMixin0ParamsWithContext(ctx)
		params.Ids = []string{id}
		res, err := d.client.CustomIoa.GetRuleGroupsMixin0(params)
		if err != nil {
			diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, dataSourceScopes, tferrors.WithNotFoundDetail(notFound)))
			return nil, diags
		}
		if res == nil || res.Payload == nil {
			diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
			return nil, diags
		}
		if diagnostic := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diagnostic != nil {
			diags.Append(diagnostic)
			return nil, diags
		}
		for _, group := range res.Payload.Resources {
			if matchesIOARuleGroup(group, "", platform) && *group.ID == id {
				return group, diags
			}
		}
		diags.Append(tferrors.NewNotFoundError(notFound))
		return nil, diags
	}

	// FQL can return partial matches; verify exact names and platforms below.
	escapedName := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(name)
	filter := fmt.Sprintf("name:'%s'", escapedName)
	if platform != "" {
		filter += fmt.Sprintf("+platform:'%s'", platformToAPI[platform])
	}
	limit := int64(100)
	var offset int64
	var matched *models.APIRuleGroupV1
	for {
		params := custom_ioa.NewQueryRuleGroupsFullParamsWithContext(ctx)
		offsetString := strconv.FormatInt(offset, 10)
		params.Filter = &filter
		params.Limit = &limit
		params.Offset = &offsetString
		res, err := d.client.CustomIoa.QueryRuleGroupsFull(params)
		if err != nil {
			diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, dataSourceScopes, tferrors.WithNotFoundDetail(notFound)))
			return nil, diags
		}
		if res == nil || res.Payload == nil {
			diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
			return nil, diags
		}
		if diagnostic := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diagnostic != nil {
			diags.Append(diagnostic)
			return nil, diags
		}
		for _, group := range res.Payload.Resources {
			if !matchesIOARuleGroup(group, name, platform) {
				continue
			}
			if matched != nil && *matched.ID != *group.ID {
				diags.AddError("Multiple IOA rule groups found", fmt.Sprintf("More than one IOA rule group matches name %q. Specify a platform or use the group ID to identify a single group.", name))
				return nil, diags
			}
			matched = group
		}
		offset += int64(len(res.Payload.Resources))
		pagination := res.Payload.Meta
		if pagination != nil && pagination.Pagination != nil && pagination.Pagination.Total != nil {
			if offset >= *pagination.Pagination.Total {
				break
			}
			if len(res.Payload.Resources) == 0 {
				diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
				return nil, diags
			}
		} else if len(res.Payload.Resources) < int(limit) {
			break
		}
	}
	if matched == nil {
		diags.Append(tferrors.NewNotFoundError(notFound))
	}
	return matched, diags
}

func matchesIOARuleGroup(group *models.APIRuleGroupV1, name, platform string) bool {
	return group != nil && group.ID != nil && *group.ID != "" &&
		(group.Deleted == nil || !*group.Deleted) &&
		(name == "" || group.Name != nil && *group.Name == name) &&
		(platform == "" || group.Platform != nil && normalizePlatform(*group.Platform) == platform)
}
