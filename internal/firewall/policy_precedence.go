package firewall

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
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

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = &firewallPolicyPrecedenceResource{}
	_ resource.ResourceWithConfigure = &firewallPolicyPrecedenceResource{}
)

const dynamicEnforcement = "dynamic"

var precedenceMarkdownDescription = "This resource allows you to set the precedence of Firewall Policies based on the order of IDs.\n\n" +
	"In a Flight Control (MSSP) environment the precedence API only manages the policies that belong to the CID authenticated by the provider. " +
	"Policies belonging to other CIDs (parent or child) are returned by the API but cannot be reordered, so they are excluded automatically. " +
	"Resolving the authenticated CID requires the `Sensor Download: Read` scope; without it, precedence can only be managed for tenants that are not part of a Flight Control hierarchy."

var precedenceRequiredScopes = []scopes.Scope{
	{
		Name:  "Firewall management",
		Read:  true,
		Write: true,
	},
	{
		Name: "Sensor Download",
		Read: true,
	},
}

// NewFirewallPolicyPrecedenceResource is a helper function to simplify the provider implementation.
func NewFirewallPolicyPrecedenceResource() resource.Resource {
	return &firewallPolicyPrecedenceResource{}
}

// firewallPolicyPrecedenceResource is the resource implementation.
type firewallPolicyPrecedenceResource struct {
	client *client.CrowdStrikeAPISpecification
}

// firewallPolicyPrecedenceResourceModel maps the resource schema data.
type firewallPolicyPrecedenceResourceModel struct {
	IDs          types.List   `tfsdk:"ids"`
	Enforcement  types.String `tfsdk:"enforcement"`
	PlatformName types.String `tfsdk:"platform_name"`
}

// wrap transforms API response values to their terraform model values.
func (m *firewallPolicyPrecedenceResourceModel) wrap(
	ctx context.Context,
	policies []string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	policyList, d := types.ListValueFrom(ctx, types.StringType, policies)
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}

	m.IDs = policyList

	return diags
}

// Configure adds the provider configured client to the resource.
func (r *firewallPolicyPrecedenceResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)
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

	r.client = providerConfig.Client
}

// Metadata returns the resource type name.
func (r *firewallPolicyPrecedenceResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_firewall_policy_precedence"
}

// Schema defines the schema for the resource.
func (r *firewallPolicyPrecedenceResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Firewall Management",
			precedenceMarkdownDescription,
			precedenceRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"ids": schema.ListAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "The policy IDs in order. The first ID specified will have the highest precedence and the last ID specified will have the lowest.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.UniqueValues(),
				},
			},
			"enforcement": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The enforcement type for this resource. `strict` requires all non-default firewall policy IDs for the platform to be provided. `dynamic` will ensure the provided policies have precedence over others. When using dynamic, policy IDs not included in `ids` will retain their current ordering after the managed IDs.",
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive("strict", "dynamic"),
				},
			},
			"platform_name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The platform of the firewall policies. (Windows, Mac, Linux)",
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive("Windows", "Linux", "Mac"),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *firewallPolicyPrecedenceResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan firewallPolicyPrecedenceResourceModel
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
		r.setFirewallPolicyPrecedence(ctx, planPolicyIDs, plan.PlatformName.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getFirewallPoliciesByPrecedence(ctx, plan.PlatformName.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(plan.Enforcement.ValueString(), dynamicEnforcement) {
		if len(policies) > len(plan.IDs.Elements()) {
			policies = policies[:len(plan.IDs.Elements())]
		}
	}

	resp.Diagnostics.Append(plan.wrap(ctx, policies)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *firewallPolicyPrecedenceResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state firewallPolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getFirewallPoliciesByPrecedence(ctx, state.PlatformName.ValueString())
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

// Update updates the resource and sets the updated Terraform state on success.
func (r *firewallPolicyPrecedenceResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan firewallPolicyPrecedenceResourceModel
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
		r.setFirewallPolicyPrecedence(ctx, planPolicyIDs, plan.PlatformName.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getFirewallPoliciesByPrecedence(ctx, plan.PlatformName.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(plan.Enforcement.ValueString(), dynamicEnforcement) {
		if len(policies) > len(plan.IDs.Elements()) {
			policies = policies[:len(plan.IDs.Elements())]
		}
	}

	resp.Diagnostics.Append(plan.wrap(ctx, policies)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *firewallPolicyPrecedenceResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	// Precedence resources don't have a delete operation - removing from state only
}

// defaultPolicyName is the name of the default firewall policy that exists in every CID.
const defaultPolicyName = "platform_default"

// policyRef holds the fields needed to scope precedence policies to the caller's CID.
type policyRef struct {
	id   string
	cid  string
	name string
}

// getFirewallPoliciesByPrecedence returns firewall policy IDs ordered by precedence,
// scoped to the caller's own CID and excluding the default firewall policy.
//
// The combined firewall policy endpoint returns policies from every CID visible to the
// caller (parent and children in a Flight Control hierarchy). The precedence API only
// manages the caller's own-CID policies, so policies belonging to other CIDs and the
// per-CID default policy are excluded here.
func (r *firewallPolicyPrecedenceResource) getFirewallPoliciesByPrecedence(
	ctx context.Context,
	platformName string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var refs []policyRef

	caser := cases.Title(language.English)

	filter := fmt.Sprintf("platform_name:'%s'", caser.String(platformName))
	sort := "precedence.asc"
	res, err := r.client.FirewallPolicies.QueryCombinedFirewallPolicies(
		&firewall_policies.QueryCombinedFirewallPoliciesParams{
			Context: ctx,
			Filter:  &filter,
			Sort:    &sort,
		},
	)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesRead))
		return nil, diags
	}

	if res != nil && res.Payload != nil {
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
				"Firewall policies from multiple CIDs were returned, which happens in a Flight Control (MSSP) environment. "+
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
func (r *firewallPolicyPrecedenceResource) getCallerCID(ctx context.Context) (string, error) {
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
func (r *firewallPolicyPrecedenceResource) generateDynamicPolicyOrder(
	ctx context.Context,
	managedPolicyIDs []string,
	platformName string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	allPolicies, d := r.getFirewallPoliciesByPrecedence(ctx, platformName)
	diags.Append(d...)
	if diags.HasError() {
		return managedPolicyIDs, diags
	}

	missingPolicies := utils.MissingElements(managedPolicyIDs, allPolicies)
	if len(missingPolicies) > 0 {
		diags.AddAttributeError(
			path.Root("ids"),
			"Invalid policy IDs provided.",
			fmt.Sprintf(
				"ids contains policy IDs that do not exist for platform: %s, the following IDs are invalid:\n\n%s",
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

// setFirewallPolicyPrecedence sets the precedence of the firewall policies.
func (r *firewallPolicyPrecedenceResource) setFirewallPolicyPrecedence(
	ctx context.Context,
	policyIDs []string,
	platformName string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	caser := cases.Title(language.English)
	platform := caser.String(platformName)

	_, err := r.client.FirewallPolicies.SetFirewallPoliciesPrecedence(
		&firewall_policies.SetFirewallPoliciesPrecedenceParams{
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
				"Error setting CrowdStrike firewall policies precedence",
				"One or more firewall policy IDs were not found. Verify all the firewall policy IDs provided are valid for the platform you are targeting.",
			)

			return diags
		}
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite))
		return diags
	}

	return diags
}
