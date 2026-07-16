package preventionpolicy

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
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
	_ resource.Resource                   = &preventionPolicyPrecedenceResource{}
	_ resource.ResourceWithConfigure      = &preventionPolicyPrecedenceResource{}
	_ resource.ResourceWithValidateConfig = &preventionPolicyPrecedenceResource{}
)

var (
	precedenceDocumentationSection string = "Prevention Policy"
	precedenceMarkdownDescription  string = "This resource allows you set the precedence of Prevention Policies based on the order of IDs.\n\n" +
		"In a Flight Control (MSSP) environment the precedence API only manages the policies that belong to the CID authenticated by the provider. " +
		"Policies belonging to other CIDs (parent or child) are returned by the API but cannot be reordered, so they are excluded automatically. " +
		"Resolving the authenticated CID requires the `Sensor Download: Read` scope; without it, precedence can only be managed for tenants that are not part of a Flight Control hierarchy."
	precedenceRequiredScopes []scopes.Scope = []scopes.Scope{
		{
			Name:  "Prevention policies",
			Read:  true,
			Write: true,
		},
		{
			Name: "Sensor Download",
			Read: true,
		},
	}

	dynamicEnforcement = "dynamic"
)

func NewPreventionPolicyPrecedenceResource() resource.Resource {
	return &preventionPolicyPrecedenceResource{}
}

type preventionPolicyPrecedenceResource struct {
	client *client.CrowdStrikeAPISpecification
}

type preventionPolicyPrecedenceResourceModel struct {
	IDs          types.List   `tfsdk:"ids"`
	Enforcement  types.String `tfsdk:"enforcement"`
	PlatformName types.String `tfsdk:"platform_name"`
	LastUpdated  types.String `tfsdk:"last_updated"`
}

func (d *preventionPolicyPrecedenceResourceModel) wrap(
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

func (r *preventionPolicyPrecedenceResource) Configure(
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

func (r *preventionPolicyPrecedenceResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_prevention_policy_precedence"
}

func (r *preventionPolicyPrecedenceResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			precedenceDocumentationSection,
			precedenceMarkdownDescription,
			precedenceRequiredScopes,
		),
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
				MarkdownDescription: "The enforcement type for this resource. `strict` requires all non-default prevention policy ids for platform to be provided. `dynamic` will ensure the provided policies have precedence over others. When using dynamic, policy ids not included in `ids` will retain their current ordering after the managed ids.",
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive("strict", "dynamic"),
				},
			},
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "That platform of the prevention policies. (Windows, Mac, Linux)",
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

func (r *preventionPolicyPrecedenceResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan preventionPolicyPrecedenceResourceModel
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
		r.setPreventionPolicyPrecedence(ctx, planPolicyIDs, plan.PlatformName.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getPreventionPoliciesByPrecedence(ctx, plan.PlatformName.ValueString())
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

func (r *preventionPolicyPrecedenceResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state preventionPolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getPreventionPoliciesByPrecedence(ctx, state.PlatformName.ValueString())
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

func (r *preventionPolicyPrecedenceResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan preventionPolicyPrecedenceResourceModel
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
		r.setPreventionPolicyPrecedence(ctx, planPolicyIDs, plan.PlatformName.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getPreventionPoliciesByPrecedence(ctx, plan.PlatformName.ValueString())
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

func (r *preventionPolicyPrecedenceResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
}

func (r *preventionPolicyPrecedenceResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config preventionPolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
}

// defaultPolicyName is the name of the default prevention policy that exists in every CID.
const defaultPolicyName = "platform_default"

// policyRef holds the fields needed to scope precedence policies to the caller's CID.
type policyRef struct {
	id   string
	cid  string
	name string
}

// getPreventionPoliciesByPrecedence returns prevention policy ids ordered by precedence,
// scoped to the caller's own CID and excluding the default prevention policy.
//
// The combined prevention policy endpoint returns policies from every CID visible to the
// caller (parent and children in a Flight Control hierarchy). The precedence API only
// manages the caller's own-CID policies, so policies belonging to other CIDs and the
// per-CID default policy are excluded here.
func (r *preventionPolicyPrecedenceResource) getPreventionPoliciesByPrecedence(
	ctx context.Context,
	platformName string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var refs []policyRef

	caser := cases.Title(language.English)

	filter := fmt.Sprintf("platform_name:'%s'", caser.String(platformName))
	sort := "precedence.asc"
	limit := int64(5000)
	offset := int64(0)

	for {
		res, err := r.client.PreventionPolicies.QueryCombinedPreventionPolicies(
			&prevention_policies.QueryCombinedPreventionPoliciesParams{
				Context: ctx,
				Filter:  &filter,
				Sort:    &sort,
				Limit:   &limit,
				Offset:  &offset,
			},
		)
		if err != nil {
			diags.AddError(
				"Error reading CrowdStrike prevention policies",
				fmt.Sprintf(
					"Could not read CrowdStrike prevention policies\n\n %s",
					err.Error(),
				),
			)
			return nil, diags
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			break
		}

		for _, policy := range res.Payload.Resources {
			if policy == nil || policy.ID == nil {
				continue
			}

			ref := policyRef{id: *policy.ID}
			if policy.Cid != nil {
				ref.cid = *policy.Cid
			}
			if policy.Name != nil {
				ref.name = *policy.Name
			}
			refs = append(refs, ref)
		}

		if res.Payload.Meta == nil || res.Payload.Meta.Pagination == nil ||
			res.Payload.Meta.Pagination.Offset == nil || res.Payload.Meta.Pagination.Total == nil {

			tflog.Warn(ctx, "Missing pagination metadata in API response, using offset+limit for next page",
				map[string]interface{}{
					"meta": res.Payload.Meta,
				})
			offset += limit
			continue
		}

		offset = int64(*res.Payload.Meta.Pagination.Offset)
		if offset >= *res.Payload.Meta.Pagination.Total {
			break
		}
	}

	nonDefault := make([]policyRef, 0, len(refs))
	for _, ref := range refs {
		if ref.name == defaultPolicyName {
			continue
		}
		nonDefault = append(nonDefault, ref)
	}

	if len(nonDefault) == 0 {
		return []string{}, diags
	}

	ownCID, cidDiags := r.resolveCallerCID(ctx, nonDefault)
	diags.Append(cidDiags...)
	if diags.HasError() {
		return nil, diags
	}

	return filterPoliciesByCID(nonDefault, ownCID), diags
}

// resolveCallerCID determines the CID authenticated by the provider so precedence can be
// scoped to the caller's own policies.
//
// The authoritative source is the sensor installers CCID endpoint (requires the
// Sensor Download: Read scope). When that lookup is unavailable the caller's CID is
// inferred from the policies themselves: a single distinct CID is unambiguously the
// caller's, but multiple distinct CIDs (a Flight Control hierarchy without the scope
// granted) cannot be disambiguated and produce an error rather than a silent guess.
func (r *preventionPolicyPrecedenceResource) resolveCallerCID(
	ctx context.Context,
	policies []policyRef,
) (string, diag.Diagnostics) {
	var diags diag.Diagnostics

	res, err := r.client.SensorDownload.GetSensorInstallersCCIDByQuery(
		sensor_download.NewGetSensorInstallersCCIDByQueryParamsWithContext(ctx),
	)
	if err == nil && res != nil && res.Payload != nil && len(res.Payload.Resources) > 0 {
		return stripChecksum(res.Payload.Resources[0]), diags
	}

	if err != nil {
		tflog.Warn(ctx, "Could not resolve authenticated CID from the sensor installers CCID endpoint, falling back to policy CIDs",
			map[string]interface{}{
				"error": err.Error(),
			})
	}

	distinct := distinctCIDs(policies)
	switch len(distinct) {
	case 0:
		return "", diags
	case 1:
		return distinct[0], diags
	default:
		diags.AddError(
			"Unable to determine the authenticated CID",
			"Prevention policies from multiple CIDs were returned, which happens in a Flight Control (MSSP) environment. "+
				"The provider could not determine which CID it is authenticated as to scope precedence correctly. "+
				"Grant the `Sensor Download: Read` scope to the API client so the authenticated CID can be resolved.",
		)
		return "", diags
	}
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
func (r *preventionPolicyPrecedenceResource) generateDynamicPolicyOrder(
	ctx context.Context,
	managedPolicyIDs []string,
	platformName string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	allPolicies, diag := r.getPreventionPoliciesByPrecedence(ctx, platformName)
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

// setPreventionPolicyPrecedence sets the precedence of the prevention polices.
func (r *preventionPolicyPrecedenceResource) setPreventionPolicyPrecedence(
	ctx context.Context,
	policyIDs []string,
	platformName string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	caser := cases.Title(language.English)
	platform := caser.String(platformName)

	_, err := r.client.PreventionPolicies.SetPreventionPoliciesPrecedence(
		&prevention_policies.SetPreventionPoliciesPrecedenceParams{
			Context: ctx,
			Body: &models.BaseSetPolicyPrecedenceReqV1{
				Ids:          policyIDs,
				PlatformName: &platform,
			},
		},
	)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			diags.AddAttributeError(
				path.Root("ids"),
				"Error setting CrowdStrike prevention policies precedence",
				"One or more prevention policy ids were not found. Verify all the prevention policy ids provided are valid for the platform you are targeting.",
			)

			return diags
		}
		diags.AddError(
			"Error setting CrowdStrike prevention policies precedence",
			fmt.Sprintf(
				"Could not set CrowdStrike prevention policies precedence\n\n %s",
				err.Error(),
			),
		)
		return diags
	}

	return diags
}
