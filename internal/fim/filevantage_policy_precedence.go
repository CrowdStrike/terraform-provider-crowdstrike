package fim

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/filevantage"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	_ resource.Resource                   = &filevantagePolicyPrecedenceResource{}
	_ resource.ResourceWithConfigure      = &filevantagePolicyPrecedenceResource{}
	_ resource.ResourceWithValidateConfig = &filevantagePolicyPrecedenceResource{}
)

var (
	precedenceDocumentationSection string = "FileVantage"
	precedenceMarkdownDescription  string = "This resource allows you to set the precedence of FileVantage Policies based on the order of IDs.\n\n" +
		"In a Flight Control (MSSP) environment the precedence API only manages the policies that belong to the CID authenticated by the provider. " +
		"Policies belonging to other CIDs (parent or child) are returned by the API but cannot be reordered, so they are excluded automatically. " +
		"Resolving the authenticated CID requires the `Sensor Download: Read` scope; without it, precedence can only be managed for tenants that are not part of a Flight Control hierarchy."

	dynamicEnforcement = "dynamic"
)

func NewFilevantagePolicyPrecedenceResource() resource.Resource {
	return &filevantagePolicyPrecedenceResource{}
}

type filevantagePolicyPrecedenceResource struct {
	client *client.CrowdStrikeAPISpecification
}

type filevantagePolicyPrecedenceResourceModel struct {
	IDs          types.List   `tfsdk:"ids"`
	Enforcement  types.String `tfsdk:"enforcement"`
	PlatformName types.String `tfsdk:"platform_name"`
	LastUpdated  types.String `tfsdk:"last_updated"`
}

func (d *filevantagePolicyPrecedenceResourceModel) wrap(
	ctx context.Context,
	policies []string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	policyList, diag := types.ListValueFrom(ctx, types.StringType, policies)
	diags.Append(diag...)
	if diags.HasError() {
		return diags
	}

	d.IDs = policyList

	return diags
}

func (r *filevantagePolicyPrecedenceResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(config.ProviderConfig)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)

		return
	}

	r.client = config.Client
}

func (r *filevantagePolicyPrecedenceResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_filevantage_policy_precedence"
}

func (r *filevantagePolicyPrecedenceResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(precedenceDocumentationSection, precedenceMarkdownDescription, precedenceRequiredScopes),
		Attributes: map[string]schema.Attribute{
			"ids": schema.ListAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "The policy ids in order. The first ID specified will have the highest precedence and the last ID specified will have the lowest.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.UniqueValues(),
				},
			},
			"enforcement": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The enforcement type for this resource. `strict` requires all non-default filevantage policy ids for platform to be provided. `dynamic` will ensure the provided policies have precedence over others. When using dynamic, policy ids not included in `ids` will retain their current ordering after the managed ids.",
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive("strict", "dynamic"),
				},
			},
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "That platform of the filevantage policies. (Windows, Mac, Linux)",
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive("Windows", "Linux", "Mac"),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
		},
	}
}

func (r *filevantagePolicyPrecedenceResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan filevantagePolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var planPolicyIDs []string
	resp.Diagnostics.Append(plan.IDs.ElementsAs(ctx, &planPolicyIDs, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(plan.Enforcement.ValueString(), dynamicEnforcement) {
		dynamicOrderedPolicyIDs, diags := r.generateDynamicPolicyOrder(
			ctx,
			planPolicyIDs,
			plan.PlatformName.ValueString(),
		)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		planPolicyIDs = dynamicOrderedPolicyIDs
	}

	resp.Diagnostics.Append(
		r.setFilevantagePolicyPrecedence(ctx, planPolicyIDs, plan.PlatformName.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getFilevantagePoilciesByPrecedence(ctx, plan.PlatformName.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(plan.Enforcement.ValueString(), dynamicEnforcement) {
		if len(policies) > len(plan.IDs.Elements()) {
			policies = policies[:len(plan.IDs.Elements())]
		}
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, policies)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *filevantagePolicyPrecedenceResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state filevantagePolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getFilevantagePoilciesByPrecedence(ctx, state.PlatformName.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(state.Enforcement.ValueString(), dynamicEnforcement) {
		if len(policies) > len(state.IDs.Elements()) {
			policies = policies[:len(state.IDs.Elements())]
		}
	}

	resp.Diagnostics.Append(state.wrap(ctx, policies)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *filevantagePolicyPrecedenceResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan filevantagePolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var planPolicyIDs []string
	resp.Diagnostics.Append(plan.IDs.ElementsAs(ctx, &planPolicyIDs, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(plan.Enforcement.ValueString(), dynamicEnforcement) {
		dynamicOrderedPolicyIDs, diags := r.generateDynamicPolicyOrder(
			ctx,
			planPolicyIDs,
			plan.PlatformName.ValueString(),
		)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		planPolicyIDs = dynamicOrderedPolicyIDs
	}

	resp.Diagnostics.Append(
		r.setFilevantagePolicyPrecedence(ctx, planPolicyIDs, plan.PlatformName.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getFilevantagePoilciesByPrecedence(ctx, plan.PlatformName.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(plan.Enforcement.ValueString(), dynamicEnforcement) {
		if len(policies) > len(plan.IDs.Elements()) {
			policies = policies[:len(plan.IDs.Elements())]
		}
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, policies)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *filevantagePolicyPrecedenceResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
}

func (r *filevantagePolicyPrecedenceResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config filevantagePolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
}

// defaultPolicyName returns the name of the per-CID default filevantage policy
// for a platform. FileVantage identifies the default policy only by this name;
// there is no is_default flag or platform_default marker.
func defaultPolicyName(platform string) string {
	return fmt.Sprintf("Default Policy (%s)", platform)
}

// policyRef holds the fields needed to scope precedence policies to the caller's CID.
type policyRef struct {
	id   string
	cid  string
	name string
}

// getFilevantagePoilciesByPrecedence returns filevantage policy ids ordered by
// precedence, scoped to the caller's own CID and excluding the default policy.
//
// The filevantage query endpoint returns policies from every CID visible to the
// caller (parent and children in a Flight Control hierarchy) interleaved with one
// default policy per CID. The precedence API only manages the caller's own-CID
// policies, so policies belonging to other CIDs and the per-CID default policy are
// excluded here.
//
// Policy details are fetched in a second call because the query endpoint returns
// ids only. Ordering comes from the query (sort=precedence|asc); the precedence
// field on the details is null, so the query order is preserved by mapping details
// back onto the ordered id list.
func (r *filevantagePolicyPrecedenceResource) getFilevantagePoilciesByPrecedence(
	ctx context.Context,
	platformName string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	caser := cases.Title(language.English)
	platform := caser.String(platformName)

	sort := "precedence|asc"
	limit := int64(500)
	offset := int64(0)

	var orderedIDs []string
	for {
		res, err := r.client.Filevantage.QueryPolicies(
			&filevantage.QueryPoliciesParams{
				Context: ctx,
				Type:    platform,
				Sort:    &sort,
				Limit:   &limit,
				Offset:  &offset,
			},
		)
		if err != nil {
			diags.AddError(
				"Error reading CrowdStrike filevantage policies",
				fmt.Sprintf(
					"Could not read CrowdStrike filevantage policies\n\n %s",
					err.Error(),
				),
			)
			return nil, diags
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			break
		}

		orderedIDs = append(orderedIDs, res.Payload.Resources...)

		if res.Payload.Meta == nil || res.Payload.Meta.Pagination == nil ||
			res.Payload.Meta.Pagination.Offset == nil || res.Payload.Meta.Pagination.Total == nil {
			tflog.Warn(ctx, "Missing pagination metadata in API response, using offset+limit for next page",
				map[string]interface{}{
					"meta": res.Payload.Meta,
				})
			offset += limit
			continue
		}

		offset = int64(*res.Payload.Meta.Pagination.Offset) + int64(*res.Payload.Meta.Pagination.Limit)
		if offset >= *res.Payload.Meta.Pagination.Total {
			break
		}
	}

	if len(orderedIDs) == 0 {
		return []string{}, diags
	}

	details, err := r.getPolicyDetails(ctx, orderedIDs)
	if err != nil {
		diags.AddError(
			"Error reading CrowdStrike filevantage policies",
			fmt.Sprintf(
				"Could not read CrowdStrike filevantage policies\n\n %s",
				err.Error(),
			),
		)
		return nil, diags
	}

	defaultName := defaultPolicyName(platform)
	nonDefault := make([]policyRef, 0, len(orderedIDs))
	for _, id := range orderedIDs {
		policy, ok := details[id]
		if !ok || policy == nil {
			continue
		}
		ref := policyRef{id: id, name: policy.Name}
		if policy.Cid != nil {
			ref.cid = *policy.Cid
		}
		if ref.name == defaultName {
			continue
		}
		nonDefault = append(nonDefault, ref)
	}

	distinct := distinctCIDs(nonDefault)
	var ownCID string
	switch len(distinct) {
	case 0:
		return []string{}, diags
	case 1:
		ownCID = distinct[0]
	default:
		cid, err := r.getCallerCID(ctx)
		if err != nil {
			tflog.Warn(ctx, "Could not resolve authenticated CID from the sensor installers CCID endpoint",
				map[string]interface{}{
					"error": err.Error(),
				})
			diags.AddError(
				"Unable to determine the authenticated CID",
				"FileVantage policies from multiple CIDs were returned, which happens in a Flight Control (MSSP) environment. "+
					"The provider could not determine which CID it is authenticated as to scope precedence correctly. "+
					"Grant the `Sensor Download: Read` scope to the API client so the authenticated CID can be resolved.",
			)
			return nil, diags
		}
		ownCID = cid
	}

	return filterPoliciesByCID(nonDefault, ownCID), diags
}

// getPolicyDetails fetches filevantage policy details for the given ids and returns
// them keyed by id. It batches requests since the details endpoint accepts at most
// 500 ids per call.
func (r *filevantagePolicyPrecedenceResource) getPolicyDetails(
	ctx context.Context,
	ids []string,
) (map[string]*models.PoliciesPolicy, error) {
	details := make(map[string]*models.PoliciesPolicy, len(ids))

	const batchSize = 500
	for start := 0; start < len(ids); start += batchSize {
		end := start + batchSize
		if end > len(ids) {
			end = len(ids)
		}

		res, err := r.client.Filevantage.GetPolicies(
			&filevantage.GetPoliciesParams{
				Context: ctx,
				Ids:     ids[start:end],
			},
		)
		if err != nil {
			return nil, err
		}

		if res == nil || res.Payload == nil {
			continue
		}

		for _, policy := range res.Payload.Resources {
			if policy == nil || policy.ID == nil {
				continue
			}
			details[*policy.ID] = policy
		}
	}

	return details, nil
}

// getCallerCID returns the CID authenticated by the provider, normalized to the
// lowercase 32-character form used in policy responses. It reads the sensor installers
// CCID endpoint, which requires the Sensor Download: Read scope.
func (r *filevantagePolicyPrecedenceResource) getCallerCID(ctx context.Context) (string, error) {
	res, err := r.client.SensorDownload.GetSensorInstallersCCIDByQuery(
		sensor_download.NewGetSensorInstallersCCIDByQueryParamsWithContext(ctx),
	)
	if err != nil {
		return "", err
	}
	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		return "", fmt.Errorf("ccid query returned no data")
	}

	return stripChecksum(res.Payload.Resources[0]), nil
}

// filterPoliciesByCID returns the ids of policies belonging to cid, preserving order.
func filterPoliciesByCID(policies []policyRef, cid string) []string {
	ids := make([]string, 0, len(policies))
	for _, p := range policies {
		if strings.EqualFold(p.cid, cid) {
			ids = append(ids, p.id)
		}
	}
	return ids
}

// distinctCIDs returns the unique, non-empty CIDs across policies, preserving first-seen order.
func distinctCIDs(policies []policyRef) []string {
	seen := make(map[string]struct{}, len(policies))
	var cids []string
	for _, p := range policies {
		if p.cid == "" {
			continue
		}
		key := strings.ToLower(p.cid)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		cids = append(cids, key)
	}
	return cids
}

// stripChecksum normalizes a CCID (32-character CID plus a "-YY" checksum) to the
// lowercase 32-character CID used in policy responses.
func stripChecksum(ccid string) string {
	idx := strings.LastIndex(ccid, "-")
	if idx < 0 {
		return strings.ToLower(ccid)
	}
	return strings.ToLower(ccid[:idx])
}

// generateDynamicPolicyOrder takes the dynamic managed policies and returns a slice of all policies in the correct order.
func (r *filevantagePolicyPrecedenceResource) generateDynamicPolicyOrder(
	ctx context.Context,
	managedPolicyIDs []string,
	platformName string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	allPolicies, diag := r.getFilevantagePoilciesByPrecedence(ctx, platformName)
	diags.Append(diag...)
	if diags.HasError() {
		return managedPolicyIDs, diags
	}

	missingPolicies := utils.MissingElements(managedPolicyIDs, allPolicies)
	if len(missingPolicies) > 0 {
		diags.AddAttributeError(
			path.Root("ids"),
			"Invalid policy ids provided.",
			fmt.Sprintf(
				"ids contains policy ids that do not exist for platform: %s, the following ids are invalid:\n\n%s",
				platformName,
				strings.Join(missingPolicies, "\n"),
			),
		)
	}

	for _, id := range allPolicies {
		if !slices.Contains(managedPolicyIDs, id) {
			managedPolicyIDs = append(managedPolicyIDs, id)
		}
	}

	return managedPolicyIDs, diags
}

// setFilevantagePolicyPrecedence sets the precedence of the filevantage polices.
func (r *filevantagePolicyPrecedenceResource) setFilevantagePolicyPrecedence(
	ctx context.Context,
	policyIDs []string,
	platformName string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	caser := cases.Title(language.English)
	platform := caser.String(platformName)

	_, err := r.client.Filevantage.UpdatePolicyPrecedence(
		&filevantage.UpdatePolicyPrecedenceParams{
			Context: ctx,
			Ids:     policyIDs,
			Type:    platform,
		},
	)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			diags.AddAttributeError(
				path.Root("ids"),
				"Error setting CrowdStrike filevantage policies precedence",
				"One or more filevantage policy ids were not found. Verify all the filevantage policy ids provided are valid for the platform you are targeting.",
			)

			return diags
		}
		diags.AddError(
			"Error setting CrowdStrike filevantage policies precedence",
			fmt.Sprintf(
				"Could not set CrowdStrike filevantage policies precedence\n\n %s",
				err.Error(),
			),
		)
		return diags
	}

	return diags
}
