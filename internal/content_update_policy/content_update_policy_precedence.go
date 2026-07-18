package contentupdatepolicy

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
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
)

var (
	_ resource.Resource                   = &contentUpdatePolicyPrecedenceResource{}
	_ resource.ResourceWithConfigure      = &contentUpdatePolicyPrecedenceResource{}
	_ resource.ResourceWithValidateConfig = &contentUpdatePolicyPrecedenceResource{}
)

var (
	precedenceDocumentationSection string = "Content Update Policy"
	precedenceMarkdownDescription  string = "This resource allows you to set the precedence of Content Update Policies based on the order of IDs.\n\n" +
		"In a Flight Control (MSSP) environment the precedence API only manages the policies that belong to the CID authenticated by the provider. " +
		"Policies belonging to other CIDs (parent or child) are returned by the API but cannot be reordered, so they are excluded automatically. " +
		"Resolving the authenticated CID requires the `Sensor Download: Read` scope; without it, precedence can only be managed for tenants that are not part of a Flight Control hierarchy."
	precedenceRequiredScopes []scopes.Scope = []scopes.Scope{
		{
			Name:  "Content Update Policy",
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

func NewContentUpdatePolicyPrecedenceResource() resource.Resource {
	return &contentUpdatePolicyPrecedenceResource{}
}

type contentUpdatePolicyPrecedenceResource struct {
	client *client.CrowdStrikeAPISpecification
}

type contentUpdatePolicyPrecedenceResourceModel struct {
	IDs         types.List   `tfsdk:"ids"`
	Enforcement types.String `tfsdk:"enforcement"`
	LastUpdated types.String `tfsdk:"last_updated"`
}

func (d *contentUpdatePolicyPrecedenceResourceModel) wrap(
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

func (r *contentUpdatePolicyPrecedenceResource) Configure(
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

func (r *contentUpdatePolicyPrecedenceResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_content_update_policy_precedence"
}

func (r *contentUpdatePolicyPrecedenceResource) Schema(
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
				MarkdownDescription: "The enforcement type for this resource. `strict` requires all non-default content update policy ids to be provided. `dynamic` will ensure the provided policies have precedence over others. When using dynamic, policy ids not included in `ids` will retain their current ordering after the managed ids.",
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive("strict", "dynamic"),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
		},
	}
}

func (r *contentUpdatePolicyPrecedenceResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan contentUpdatePolicyPrecedenceResourceModel
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
		)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		planPolicyIDs = dynamicOrderedPolicyIDs
	}

	resp.Diagnostics.Append(
		r.setContentUpdatePolicyPrecedence(ctx, planPolicyIDs)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getContentUpdatePoliciesByPrecedence(ctx)
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

func (r *contentUpdatePolicyPrecedenceResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state contentUpdatePolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getContentUpdatePoliciesByPrecedence(ctx)
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

func (r *contentUpdatePolicyPrecedenceResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan contentUpdatePolicyPrecedenceResourceModel
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
		)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		planPolicyIDs = dynamicOrderedPolicyIDs
	}

	resp.Diagnostics.Append(
		r.setContentUpdatePolicyPrecedence(ctx, planPolicyIDs)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getContentUpdatePoliciesByPrecedence(ctx)
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

func (r *contentUpdatePolicyPrecedenceResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
}

func (r *contentUpdatePolicyPrecedenceResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config contentUpdatePolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
}

// defaultPolicyName is the name of the default content update policy that exists in every CID.
const defaultPolicyName = "platform_default"

// policyRef holds the fields needed to scope precedence policies to the caller's CID.
type policyRef struct {
	id   string
	cid  string
	name string
}

// getContentUpdatePoliciesByPrecedence returns content update policy ids ordered by
// precedence, scoped to the caller's own CID and excluding the default content update policy.
//
// The combined content update policy endpoint returns policies from every CID visible to the
// caller (parent and children in a Flight Control hierarchy). The precedence API only
// manages the caller's own-CID policies, so policies belonging to other CIDs and the
// per-CID default policy are excluded here.
func (r *contentUpdatePolicyPrecedenceResource) getContentUpdatePoliciesByPrecedence(
	ctx context.Context,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var refs []policyRef

	sort := "precedence.asc"
	limit := int64(5000)
	offset := int64(0)

	for {
		res, err := r.client.ContentUpdatePolicies.QueryCombinedContentUpdatePolicies(
			&content_update_policies.QueryCombinedContentUpdatePoliciesParams{
				Context: ctx,
				Sort:    &sort,
				Limit:   &limit,
				Offset:  &offset,
			},
		)
		if err != nil {
			diags.AddError(
				"Error reading CrowdStrike content update policies",
				fmt.Sprintf(
					"Could not read CrowdStrike content update policies\n\n %s",
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
				"Content update policies from multiple CIDs were returned, which happens in a Flight Control (MSSP) environment. "+
					"The provider could not determine which CID it is authenticated as to scope precedence correctly. "+
					"Grant the `Sensor Download: Read` scope to the API client so the authenticated CID can be resolved.",
			)
			return nil, diags
		}
		ownCID = cid
	}

	return filterPoliciesByCID(nonDefault, ownCID), diags
}

// getCallerCID returns the CID authenticated by the provider, normalized to the
// lowercase 32-character form used in policy responses. It reads the sensor installers
// CCID endpoint, which requires the Sensor Download: Read scope.
func (r *contentUpdatePolicyPrecedenceResource) getCallerCID(ctx context.Context) (string, error) {
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
func (r *contentUpdatePolicyPrecedenceResource) generateDynamicPolicyOrder(
	ctx context.Context,
	managedPolicyIDs []string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	allPolicies, diag := r.getContentUpdatePoliciesByPrecedence(ctx)
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
				"ids contains policy ids that do not exist, the following ids are invalid:\n\n%s",
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

// setContentUpdatePolicyPrecedence sets the precedence of the content update policies.
func (r *contentUpdatePolicyPrecedenceResource) setContentUpdatePolicyPrecedence(
	ctx context.Context,
	policyIDs []string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	_, err := r.client.ContentUpdatePolicies.SetContentUpdatePoliciesPrecedence(
		&content_update_policies.SetContentUpdatePoliciesPrecedenceParams{
			Context: ctx,
			Body: &models.BaseSetContentUpdatePolicyPrecedenceReqV1{
				Ids: policyIDs,
			},
		},
	)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			diags.AddAttributeError(
				path.Root("ids"),
				"Error setting CrowdStrike content update policies precedence",
				"One or more content update policy ids were not found. Verify all the content update policy ids provided are valid.",
			)

			return diags
		}
		diags.AddError(
			"Error setting CrowdStrike content update policies precedence",
			fmt.Sprintf(
				"Could not set CrowdStrike content update policies precedence\n\n %s",
				err.Error(),
			),
		)
		return diags
	}

	return diags
}
