package networkcontainment

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/containment_allowlist_rules"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

var (
	_ resource.Resource                   = &networkContainmentAllowlistRuleResource{}
	_ resource.ResourceWithConfigure      = &networkContainmentAllowlistRuleResource{}
	_ resource.ResourceWithImportState    = &networkContainmentAllowlistRuleResource{}
	_ resource.ResourceWithValidateConfig = &networkContainmentAllowlistRuleResource{}
)

const (
	documentationSection = "Host Setup and Management"

	// allowlistContext is the only context the allowlist API accepts.
	allowlistContext = "containment"

	ruleTypeIPRange = "ip_range"
	ruleTypeFQDN    = "fqdn"
	ruleTypeIPDNS   = "ip_dns"
)

var (
	ruleTypes = []string{ruleTypeIPRange, ruleTypeFQDN, ruleTypeIPDNS}

	requiredScopes = []scopes.Scope{
		{Name: "Network Containment Allowlist", Read: true, Write: true},
	}

	// fqdnRegex matches a domain of at least two labels. Wildcards, schemes,
	// paths, and ports are rejected, matching the Falcon console.
	fqdnRegex = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// NewNetworkContainmentAllowlistRuleResource creates a new network containment allowlist rule resource.
func NewNetworkContainmentAllowlistRuleResource() resource.Resource {
	return &networkContainmentAllowlistRuleResource{}
}

// networkContainmentAllowlistRuleResource manages a single network containment allowlist rule.
type networkContainmentAllowlistRuleResource struct {
	client *client.CrowdStrikeAPISpecification
}

// firstRule returns the single rule a create or update response carries.
func firstRule(
	op tferrors.Operation,
	payload *models.IpwhitelistAllowlistResponse,
) (*models.IpwhitelistinteractorAllowlistRule, diag.Diagnostic) {
	if payload == nil {
		return nil, tferrors.NewEmptyResponseError(op)
	}
	if d := tferrors.NewDiagnosticFromPayloadErrors(op, payload.Errors); d != nil {
		return nil, d
	}
	if len(payload.Resources) == 0 || payload.Resources[0] == nil {
		return nil, tferrors.NewEmptyResponseError(op)
	}
	return payload.Resources[0], nil
}

func (r *networkContainmentAllowlistRuleResource) Configure(
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

func (r *networkContainmentAllowlistRuleResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_network_containment_allowlist_rule"
}

func (r *networkContainmentAllowlistRuleResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(documentationSection, "Manages a network containment allowlist rule. Contained hosts can always communicate with the IP ranges, DNS servers, and FQDNs on the allowlist. `fqdn` rules require at least one `ip_dns` rule: the API rejects creating an `fqdn` rule when no `ip_dns` rule exists, and rejects deleting the last `ip_dns` rule while any `fqdn` rule remains. When both are managed in the same configuration, add `depends_on` from each `fqdn` rule to an `ip_dns` rule so Terraform creates the DNS rule first and destroys it last.", requiredScopes),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Identifier of the allowlist rule, derived from the rule: `containment|<rule>` for `ip_range` and `fqdn` rules, and `containment|dns|<rule>` for `ip_dns` rules.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Rule type. One of `ip_range` (an IP address or CIDR block), `ip_dns` (a DNS server contained hosts may use for domain resolution, shown as **DNS** in the Falcon console), or `fqdn` (a domain contained hosts may reach). Changing this value forces a new resource.",
				Validators: []validator.String{
					stringvalidator.OneOf(ruleTypes...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"rule": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Value to allow: an IPv4 or IPv6 address or CIDR block for `ip_range`, an IPv4 or IPv6 address for `ip_dns`, or a domain such as `updates.example.com` for `fqdn`. The value is stored exactly as given. Changing this value forces a new resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the allowlist rule.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"allow_subdomains": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Also allow one level of subdomains beyond the domain. For example, allowing subdomains for `example.com` allows `calendar.example.com` and `mail.example.com`, but not `my.maps.example.com`. Only valid for `fqdn` rules. Defaults to `false`. Some services let anyone register a subdomain, which then resolves to infrastructure that subdomain's owner controls. Changing this value forces a new resource.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *networkContainmentAllowlistRuleResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan allowlistRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := containment_allowlist_rules.NewCreateContainmentAllowlistRulesParamsWithContext(ctx).
		WithBody(&models.IpwhitelistAllowlistRequest{
			Rules: []*models.IpwhitelistinteractorAllowlistRule{plan.expand()},
		})

	res, err := r.client.ContainmentAllowlistRules.CreateContainmentAllowlistRules(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, requiredScopes))
		return
	}

	rule, d := firstRule(tferrors.Create, res.GetPayload())
	if d != nil {
		resp.Diagnostics.Append(d)
		return
	}

	plan.flatten(*rule)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *networkContainmentAllowlistRuleResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state allowlistRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := containment_allowlist_rules.NewGetContainmentAllowlistRulesParamsWithContext(ctx).
		WithIds([]string{state.ID.ValueString()})

	res, err := r.client.ContainmentAllowlistRules.GetContainmentAllowlistRules(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, requiredScopes)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	// A missing rule is answered with 200 and no resources rather than a 404.
	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}

	state.flatten(*res.Payload.Resources[0])
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *networkContainmentAllowlistRuleResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan allowlistRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Only the label is mutable; every other attribute forces replacement.
	params := containment_allowlist_rules.NewUpdateContainmentAllowlistRulesParamsWithContext(ctx).
		WithBody(&models.IpwhitelistAllowlistRequest{
			Rules: []*models.IpwhitelistinteractorAllowlistRule{plan.expand()},
		})

	res, err := r.client.ContainmentAllowlistRules.UpdateContainmentAllowlistRules(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, requiredScopes))
		return
	}

	rule, d := firstRule(tferrors.Update, res.GetPayload())
	if d != nil {
		resp.Diagnostics.Append(d)
		return
	}

	plan.flatten(*rule)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *networkContainmentAllowlistRuleResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state allowlistRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := containment_allowlist_rules.NewDeleteContainmentAllowlistRulesParamsWithContext(ctx).
		WithIds([]string{state.ID.ValueString()})

	res, err := r.client.ContainmentAllowlistRules.DeleteContainmentAllowlistRules(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, requiredScopes)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	if res != nil && res.Payload != nil {
		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Delete, res.Payload.Errors); diag != nil {
			resp.Diagnostics.Append(diag)
		}
	}
}

func (r *networkContainmentAllowlistRuleResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// The API answers an ID that is not a composite with a 500, so reject it
	// here with a message that shows the expected shape.
	if !strings.HasPrefix(req.ID, allowlistContext+"|") {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Expected containment|<rule> for ip_range and fqdn rules, or containment|dns|<rule> for ip_dns rules, got %q.", req.ID),
		)
		return
	}

	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *networkContainmentAllowlistRuleResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config allowlistRuleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !utils.IsKnown(config.Type) {
		return
	}
	ruleType := config.Type.ValueString()

	if ruleType != ruleTypeFQDN && config.AllowSubdomains.ValueBool() {
		resp.Diagnostics.AddAttributeError(
			path.Root("allow_subdomains"),
			"Invalid attribute combination",
			fmt.Sprintf("allow_subdomains can only be true for %q rules, got type %q.", ruleTypeFQDN, ruleType),
		)
	}

	if !utils.IsKnown(config.Rule) {
		return
	}

	if detail := validateRule(ruleType, config.Rule.ValueString()); detail != "" {
		resp.Diagnostics.AddAttributeError(path.Root("rule"), "Invalid rule", detail)
	}
}

// validateRule checks a rule value against the format its type requires,
// mirroring the Falcon console's checks. It returns an empty string when the
// value is valid.
func validateRule(ruleType, rule string) string {
	switch ruleType {
	case ruleTypeIPRange:
		if _, err := netip.ParseAddr(rule); err == nil {
			return ""
		}
		if _, err := netip.ParsePrefix(rule); err == nil {
			return ""
		}
		return fmt.Sprintf("%q is not a valid IP address or CIDR block, which %q rules require.", rule, ruleTypeIPRange)
	case ruleTypeIPDNS:
		if _, err := netip.ParseAddr(rule); err == nil {
			return ""
		}
		return fmt.Sprintf("%q is not a valid IP address, which %q rules require.", rule, ruleTypeIPDNS)
	case ruleTypeFQDN:
		if len(rule) <= 253 && fqdnRegex.MatchString(rule) {
			return ""
		}
		return fmt.Sprintf("%q is not a valid FQDN, which %q rules require. Use a domain such as updates.example.com, without a wildcard, scheme, path, or port.", rule, ruleTypeFQDN)
	}
	return ""
}
