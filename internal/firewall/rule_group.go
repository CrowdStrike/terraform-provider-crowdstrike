package firewall

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/swag"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &firewallRuleGroupResource{}
	_ resource.ResourceWithConfigure      = &firewallRuleGroupResource{}
	_ resource.ResourceWithImportState    = &firewallRuleGroupResource{}
	_ resource.ResourceWithValidateConfig = &firewallRuleGroupResource{}
)

// protocolMapping maps human-readable protocol names to IANA numbers used by CrowdStrike API.
var protocolMapping = map[string]string{
	"ICMPV4":             "1",
	"IGMP":               "2",
	"IP-IN-IP":           "4",
	"TCP":                "6",
	"UDP":                "17",
	"IPV6 ENCAPSULATION": "41",
	"GRE":                "47",
	"ESP":                "50",
	"ICMPV6":             "58",
	"ANY":                "*",
}

// linuxUnsupportedProtocols lists protocols not available on Linux platform.
var linuxUnsupportedProtocols = []string{"IGMP", "IP-IN-IP", "IPV6 ENCAPSULATION", "GRE", "ESP"}

// NewFirewallRuleGroupResource is a helper function to simplify the provider implementation.
func NewFirewallRuleGroupResource() resource.Resource {
	return &firewallRuleGroupResource{}
}

// firewallRuleGroupResource is the resource implementation.
type firewallRuleGroupResource struct {
	client *client.CrowdStrikeAPISpecification
}

// firewallRuleGroupResourceModel maps the resource schema data.
type firewallRuleGroupResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Platform    types.String `tfsdk:"platform"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Rules       types.List   `tfsdk:"rules"`
}

// firewallRuleModel maps a single firewall rule.
type firewallRuleModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Description     types.String `tfsdk:"description"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	Action          types.String `tfsdk:"action"`
	Direction       types.String `tfsdk:"direction"`
	Protocol        types.String `tfsdk:"protocol"`
	AddressFamily   types.String `tfsdk:"address_family"`
	LocalAddress    types.List   `tfsdk:"local_address"`
	RemoteAddress   types.List   `tfsdk:"remote_address"`
	LocalPort       types.List   `tfsdk:"local_port"`
	RemotePort      types.List   `tfsdk:"remote_port"`
	Fqdn            types.String `tfsdk:"fqdn"`
	NetworkLocation types.String `tfsdk:"network_location"`
	ExecutablePath  types.String `tfsdk:"executable_path"`
	ServiceName     types.String `tfsdk:"service_name"`
	IcmpType        types.String `tfsdk:"icmp_type"`
	IcmpCode        types.String `tfsdk:"icmp_code"`
	WatchMode       types.Bool   `tfsdk:"watch_mode"`
}

// addressRangeModel maps an IP address with netmask.
type addressRangeModel struct {
	Address types.String `tfsdk:"address"`
	Netmask types.Int64  `tfsdk:"netmask"`
}

// portRangeModel maps a port or port range.
type portRangeModel struct {
	Start types.Int64 `tfsdk:"start"`
	End   types.Int64 `tfsdk:"end"`
}

func (f firewallRuleModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":               types.StringType,
		"name":             types.StringType,
		"description":      types.StringType,
		"enabled":          types.BoolType,
		"action":           types.StringType,
		"direction":        types.StringType,
		"protocol":         types.StringType,
		"address_family":   types.StringType,
		"local_address":    types.ListType{ElemType: types.ObjectType{AttrTypes: addressRangeAttrTypes()}},
		"remote_address":   types.ListType{ElemType: types.ObjectType{AttrTypes: addressRangeAttrTypes()}},
		"local_port":       types.ListType{ElemType: types.ObjectType{AttrTypes: portRangeAttrTypes()}},
		"remote_port":      types.ListType{ElemType: types.ObjectType{AttrTypes: portRangeAttrTypes()}},
		"fqdn":             types.StringType,
		"network_location": types.StringType,
		"executable_path":  types.StringType,
		"service_name":     types.StringType,
		"icmp_type":        types.StringType,
		"icmp_code":        types.StringType,
		"watch_mode":       types.BoolType,
	}
}

func addressRangeAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"address": types.StringType,
		"netmask": types.Int64Type,
	}
}

func portRangeAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"start": types.Int64Type,
		"end":   types.Int64Type,
	}
}

// wildcardAddressList is the canonical "any address": a single wildcard entry with a
// netmask of 0. See apiWildcard for why that one spelling serves configuration, plan
// and state alike.
func wildcardAddressList() types.List {
	return types.ListValueMust(
		types.ObjectType{AttrTypes: addressRangeAttrTypes()},
		[]attr.Value{
			types.ObjectValueMust(addressRangeAttrTypes(), map[string]attr.Value{
				"address": types.StringValue(apiWildcard),
				"netmask": types.Int64Value(0),
			}),
		},
	)
}

// Configure adds the provider configured client to the resource.
func (r *firewallRuleGroupResource) Configure(
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
func (r *firewallRuleGroupResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_firewall_rule_group"
}

// Schema defines the schema for the resource.
func (r *firewallRuleGroupResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Firewall Management",
			"This resource allows management of CrowdStrike Firewall rule groups. A rule group is a collection of firewall rules that can be assigned to firewall policies.",
			apiScopesReadWrite,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Identifier for the firewall rule group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the firewall rule group.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 255),
				},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Description of the firewall rule group.",
				Validators: []validator.String{
					stringvalidator.LengthAtMost(500),
					fwvalidators.StringNotWhitespace(),
				},
			},
			"platform": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Platform for the rule group. One of: `Windows`, `Mac`, `Linux`.",
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Mac", "Linux"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"enabled": schema.BoolAttribute{
				Required:            true,
				MarkdownDescription: "Whether the rule group is enabled.",
			},
			"rules": schema.ListNestedAttribute{
				Optional:            true,
				MarkdownDescription: "List of firewall rules in this rule group. Rule precedence is determined by the order in the list.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: ruleSchemaAttributes(),
					Validators: []validator.Object{
						ruleAttributeApplicability(),
					},
				},
			},
		},
	}
}

// ruleSchemaAttributes returns the schema attributes for a firewall rule.
func ruleSchemaAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Identifier for the firewall rule. This is the Rule ID shown in the Falcon console and in firewall events. Falcon assigns it when the rule is created and the rule keeps it for its lifetime: editing the rule's settings, renaming it, and moving it within the group all preserve it. Renaming a rule and changing its settings in the same apply replaces the rule, which assigns a new identifier.",
		},
		"name": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "Name of the firewall rule.",
			Validators: []validator.String{
				stringvalidator.LengthBetween(1, 255),
			},
		},
		"description": schema.StringAttribute{
			Optional:            true,
			MarkdownDescription: "Description of the firewall rule.",
			Validators: []validator.String{
				fwvalidators.StringNotWhitespace(),
			},
		},
		"enabled": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Whether the rule is enabled. Defaults to `true`.",
			Default:             booldefault.StaticBool(true),
		},
		"action": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "Action to take when the rule matches. One of: `ALLOW`, `DENY`.",
			Validators: []validator.String{
				stringvalidator.OneOf("ALLOW", "DENY"),
			},
		},
		"direction": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "Traffic direction for the rule. One of: `IN`, `OUT`, `BOTH`.",
			Validators: []validator.String{
				stringvalidator.OneOf("IN", "OUT", "BOTH"),
			},
		},
		"protocol": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "Protocol for the rule. Named protocols: `TCP`, `UDP`, `ICMPV4`, `ICMPV6`, `IPV6 ENCAPSULATION`, `ANY`. Additional protocols reachable via the console's Advanced (numeric protocol) option: `GRE`, `ESP`, `IGMP`, `IP-IN-IP`. Note: Some protocols have platform restrictions (see platform documentation).",
			Validators: []validator.String{
				stringvalidator.OneOf("TCP", "UDP", "ICMPV4", "ICMPV6", "IGMP", "IP-IN-IP", "IPV6 ENCAPSULATION", "GRE", "ESP", "ANY"),
			},
		},
		"address_family": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Address family for the rule. One of: `IP4`, `IP6`, `ANY` (`ANY` matches any address family and clears any configured addresses). Must be `IP6` or `ANY` on an `ICMPV6` rule, and `IP4` or `ANY` on an `ICMPV4` rule, because each ICMP protocol runs over only its own address family. Defaults to `IP4`.",
			Default:             stringdefault.StaticString("IP4"),
			Validators: []validator.String{
				stringvalidator.OneOf("IP4", "IP6", "ANY"),
			},
		},
		"local_address": schema.ListNestedAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Local IP addresses for the rule. Omit it, or use a single entry whose `address` is `*`, to match any local address. Defaults to a single entry with `address` `*` and `netmask` 0.",
			NestedObject: schema.NestedAttributeObject{
				Attributes: addressRangeSchemaAttributes(),
			},
			// The API reports a single wildcard entry for a rule that does not restrict
			// addresses, so that is what an omitted list has to plan as. Defaulting
			// rather than leaving it computed also keeps the planned value known, which
			// correlating rules across an update depends on.
			Default: listdefault.StaticValue(wildcardAddressList()),
			Validators: []validator.List{
				// An explicitly empty list records no entries in the API, which reports
				// the wildcard for it, so it could never equal the configuration.
				listvalidator.SizeAtLeast(1),
			},
		},
		"remote_address": schema.ListNestedAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Remote IP addresses for the rule. Omit it, or use a single entry whose `address` is `*`, to match any remote address. Defaults to a single entry with `address` `*` and `netmask` 0.",
			NestedObject: schema.NestedAttributeObject{
				Attributes: addressRangeSchemaAttributes(),
			},
			// See local_address.
			Default: listdefault.StaticValue(wildcardAddressList()),
			Validators: []validator.List{
				listvalidator.SizeAtLeast(1),
			},
		},
		"local_port": schema.ListNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Local ports for the rule. Only applicable for TCP/UDP protocols. Omit it to match any port.",
			NestedObject: schema.NestedAttributeObject{
				Attributes: portRangeSchemaAttributes(),
			},
			Validators: []validator.List{
				// An explicitly empty list records no entries in the API, which the read
				// reports as unset, so it could never equal the configuration. Omitting
				// the attribute is how to say "any".
				listvalidator.SizeAtLeast(1),
			},
		},
		"remote_port": schema.ListNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Remote ports for the rule. Only applicable for TCP/UDP protocols. Omit it to match any port.",
			NestedObject: schema.NestedAttributeObject{
				Attributes: portRangeSchemaAttributes(),
			},
			Validators: []validator.List{
				listvalidator.SizeAtLeast(1),
			},
		},
		"fqdn": schema.StringAttribute{
			Optional:            true,
			MarkdownDescription: "Fully qualified domain name for the rule. Only valid for outbound rules. Multiple FQDNs can be separated by semicolons. Wildcard (`*.example.com`) and glob syntax are supported. Removing this attribute turns the rule back into an IP address rule; the API has no way to erase the stored domain, so it remains on the rule server-side without effect.",
			Validators: []validator.String{
				// Remove the attribute to unset it. An empty string is not a
				// second way of spelling that: the API rejects an empty fqdn,
				// so it could never round-trip.
				fwvalidators.StringNotWhitespace(),
			},
		},
		"network_location": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Network location restriction. One of the built-in values `ANY`, `DOMAIN`, `PRIVATE`, `PUBLIC`, or a custom network location ID. Only `ANY` is valid on Linux. Defaults to `ANY`.",
			Default:             stringdefault.StaticString("ANY"),
		},
		"executable_path": schema.StringAttribute{
			Optional:            true,
			MarkdownDescription: "Path to executable that this rule applies to.",
			Validators: []validator.String{
				// Remove the attribute to unset it. An empty value is how the
				// fields array clears the entry, so accepting "" here would
				// make two different configurations produce identical state.
				fwvalidators.StringNotWhitespace(),
			},
		},
		"service_name": schema.StringAttribute{
			Optional:            true,
			MarkdownDescription: "Windows service name that this rule applies to. Only valid for Windows platform.",
			Validators: []validator.String{
				// See executable_path.
				fwvalidators.StringNotWhitespace(),
			},
		},
		"icmp_type": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "ICMP type for ICMP protocol rules. Omit it, or use `*`, to match any ICMP type. Only valid for `ICMPV4` and `ICMPV6`; it is null on every other protocol. Defaults to `*` on `ICMPV4` and `ICMPV6` rules.",
			Validators: []validator.String{
				// The API stores the wildcard for a value submitted empty, so an empty
				// string would read back as "*" and never equal the configuration.
				stringvalidator.LengthAtLeast(1),
			},
			PlanModifiers: []planmodifier.String{
				icmpValueDefault(),
			},
		},
		"icmp_code": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "ICMP code for ICMP protocol rules. Omit it, or use `*`, to match any ICMP code. Only valid for `ICMPV4` and `ICMPV6`; it is null on every other protocol. Defaults to `*` on `ICMPV4` and `ICMPV6` rules.",
			Validators: []validator.String{
				// See icmp_type.
				stringvalidator.LengthAtLeast(1),
			},
			PlanModifiers: []planmodifier.String{
				icmpValueDefault(),
			},
		},
		"watch_mode": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Enable watch mode (monitoring) for this rule instead of enforcing. Defaults to `false`.",
			Default:             booldefault.StaticBool(false),
		},
	}
}

// addressRangeSchemaAttributes returns schema attributes for IP address ranges.
func addressRangeSchemaAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"address": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "IP address for the rule, or `*` to match any address.",
			Validators: []validator.String{
				stringvalidator.LengthAtLeast(1),
			},
		},
		"netmask": schema.Int64Attribute{
			Optional: true,
			Computed: true,
			// Defaulted rather than left to be computed so the planned value is
			// always known. Correlating rules across an update compares plan
			// against state attribute by attribute, and an unknown value would
			// make an unchanged rule look edited.
			Default:             int64default.StaticInt64(0),
			MarkdownDescription: "CIDR netmask. Use 0 for a single IP, and for the `*` address. Defaults to `0`.",
			Validators: []validator.Int64{
				int64validator.Between(0, 128),
			},
		},
	}
}

// portRangeSchemaAttributes returns schema attributes for port ranges.
func portRangeSchemaAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"start": schema.Int64Attribute{
			Required:            true,
			MarkdownDescription: "Start port (1-65535).",
			Validators: []validator.Int64{
				int64validator.Between(1, 65535),
			},
		},
		"end": schema.Int64Attribute{
			Optional: true,
			Computed: true,
			// 0 is what the API stores and reports for a single port, and
			// defaulting keeps the planned value known. See netmask above.
			Default:             int64default.StaticInt64(0),
			MarkdownDescription: "End port for a range. Must be greater than `start`. Omit it, or use 0, for a single port. Defaults to `0`.",
			Validators: []validator.Int64{
				int64validator.Between(0, 65535),
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *firewallRuleGroupResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan firewallRuleGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Creating firewall rule group", map[string]interface{}{
		"name":     plan.Name.ValueString(),
		"platform": plan.Platform.ValueString(),
	})

	rules, diags := buildRulesPayload(ctx, plan.Rules, plan.Platform.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// API expects lowercase platform values
	platform := strings.ToLower(plan.Platform.ValueString())

	createReq := &models.FwmgrAPIRuleGroupCreateRequestV1{
		Name:        swag.String(plan.Name.ValueString()),
		Description: flex.FrameworkToStringPointer(plan.Description),
		Platform:    swag.String(platform),
		Enabled:     swag.Bool(plan.Enabled.ValueBool()),
		Rules:       rules,
	}

	params := firewall_management.NewCreateRuleGroupParams().
		WithContext(ctx).
		WithBody(createReq)

	result, err := r.client.FirewallManagement.CreateRuleGroup(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create,
			err,
			apiScopesReadWrite,
		))
		return
	}

	if result == nil || result.Payload == nil || len(result.Payload.Resources) == 0 {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	ruleGroupID := result.Payload.Resources[0]
	plan.ID = flex.StringValueToFramework(ruleGroupID)

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, diags = r.readRuleGroupState(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Created firewall rule group", map[string]interface{}{
		"id":   plan.ID.ValueString(),
		"name": plan.Name.ValueString(),
	})
}

// Read refreshes the Terraform state with the latest data.
func (r *firewallRuleGroupResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state firewallRuleGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading firewall rule group", map[string]interface{}{
		"id": state.ID.ValueString(),
	})

	removed, diags := r.readRuleGroupState(ctx, &state)
	if removed {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *firewallRuleGroupResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan firewallRuleGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state firewallRuleGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating firewall rule group", map[string]interface{}{
		"id":   plan.ID.ValueString(),
		"name": plan.Name.ValueString(),
	})

	ruleGroup, removed, diags := r.getRuleGroup(ctx, plan.ID.ValueString(), tferrors.Update)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if removed {
		resp.Diagnostics.AddError(
			"Firewall rule group not found",
			fmt.Sprintf("Firewall rule group '%s' was not found. It may have been deleted outside of Terraform.", plan.ID.ValueString()),
		)
		return
	}

	diffOps, newRuleIDs, newRuleVersions, diags := buildDiffOperations(ctx, plan, state, ruleGroup)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// rule_ids carries precedence, so a permutation alone is a real change.
	// It differs from the current array exactly when a rule was added,
	// removed, rewritten (temp_id placeholder), or moved.
	if len(diffOps) > 0 || !slices.Equal(newRuleIDs, ruleGroup.RuleIds) {
		updateReq := &models.FwmgrAPIRuleGroupModifyRequestV1{
			ID:             swag.String(plan.ID.ValueString()),
			Tracking:       ruleGroup.Tracking,
			DiffType:       swag.String("application/json-patch+json"),
			DiffOperations: diffOps,
			RuleIds:        newRuleIDs,
			RuleVersions:   newRuleVersions,
		}

		params := firewall_management.NewUpdateRuleGroupParams().
			WithContext(ctx).
			WithBody(updateReq)

		_, err := r.client.FirewallManagement.UpdateRuleGroup(params)
		if err != nil {
			resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
				tferrors.Update,
				err,
				apiScopesReadWrite,
			))
			return
		}
	}

	_, diags = r.readRuleGroupState(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Updated firewall rule group", map[string]interface{}{
		"id":   plan.ID.ValueString(),
		"name": plan.Name.ValueString(),
	})
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *firewallRuleGroupResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state firewallRuleGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()
	if id == "" {
		return
	}

	tflog.Debug(ctx, "Deleting firewall rule group", map[string]interface{}{
		"id": id,
	})

	// Disable the rule group before deleting (required by CrowdStrike)
	if state.Enabled.ValueBool() {
		tflog.Debug(ctx, "Disabling firewall rule group before deletion", map[string]interface{}{
			"id": id,
		})

		ruleGroup, removed, diags := r.getRuleGroup(ctx, id, tferrors.Delete)
		if removed {
			tflog.Info(ctx, "Firewall rule group already deleted", map[string]interface{}{
				"id": id,
			})
			return
		}
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		disableReq := &models.FwmgrAPIRuleGroupModifyRequestV1{
			ID:       swag.String(id),
			Tracking: ruleGroup.Tracking,
			DiffType: swag.String("application/json-patch+json"),
			DiffOperations: []*models.FwmgrAPIJSONDiff{
				{
					Op:    swag.String("replace"),
					Path:  swag.String("/enabled"),
					Value: false,
				},
			},
			RuleIds:      ruleGroup.RuleIds,
			RuleVersions: make([]int64, len(ruleGroup.RuleIds)),
		}

		disableParams := firewall_management.NewUpdateRuleGroupParams().
			WithContext(ctx).
			WithBody(disableReq)

		_, err := r.client.FirewallManagement.UpdateRuleGroup(disableParams)
		if err != nil {
			diagErr := tferrors.NewDiagnosticFromAPIError(
				tferrors.Delete,
				err,
				apiScopesReadWrite,
			)
			if diagErr.Summary() == tferrors.NotFoundErrorSummary {
				return
			}
			resp.Diagnostics.Append(diagErr)
			return
		}
	}

	params := firewall_management.NewDeleteRuleGroupsParams().
		WithContext(ctx).
		WithIds([]string{id})

	_, err := r.client.FirewallManagement.DeleteRuleGroups(params)
	if err != nil {
		diagErr := tferrors.NewDiagnosticFromAPIError(
			tferrors.Delete,
			err,
			apiScopesReadWrite,
		)
		if diagErr.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diagErr)
		return
	}

	tflog.Info(ctx, "Deleted firewall rule group", map[string]interface{}{
		"id": id,
	})
}

// ImportState implements the logic to support resource imports.
func (r *firewallRuleGroupResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig validates the resource configuration.
func (r *firewallRuleGroupResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config firewallRuleGroupResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	platform := config.Platform.ValueString()
	if platform == "" {
		return
	}

	rules := utils.ListTypeAs[*firewallRuleModel](ctx, config.Rules, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	for i, rule := range rules {
		if rule == nil {
			continue
		}
		resp.Diagnostics.Append(
			validateRuleForPlatform(ctx, platform, rule, path.Root("rules").AtListIndex(i))...,
		)
	}
}

// validateRuleForPlatform holds the rule checks that need the group's platform, so
// they cannot live on the rules element the way ruleAttributeApplicability's do.
func validateRuleForPlatform(
	ctx context.Context,
	platform string,
	rule *firewallRuleModel,
	rulePath path.Path,
) diag.Diagnostics {
	var diags diag.Diagnostics

	fqdn := rule.Fqdn.ValueString()

	// FQDN validations
	if !rule.Fqdn.IsNull() && fqdn != "" {
		// FQDN only supports OUT direction
		if rule.Direction.ValueString() != "OUT" {
			diags.AddAttributeError(
				rulePath.AtName("fqdn"),
				"Invalid FQDN configuration",
				"FQDN rules must have direction set to 'OUT'.",
			)
		}

		// FQDN cannot be used with remote_address. A wildcard entry is not a
		// restriction, and it is what an omitted list defaults to, so it is
		// as acceptable here as omitting the attribute.
		remoteAddresses := utils.ListTypeAs[*addressRangeModel](ctx, rule.RemoteAddress, &diags)
		if namesSpecificAddresses(remoteAddresses) {
			diags.AddAttributeError(
				rulePath.AtName("fqdn"),
				"Invalid FQDN configuration",
				"FQDN and remote_address cannot be used together. FQDN rules use domain resolution instead of IP addresses.",
			)
		}

		// FQDN not supported on Linux
		if platform == "Linux" {
			diags.AddAttributeError(
				rulePath.AtName("fqdn"),
				"Invalid FQDN configuration",
				"FQDN is not supported on Linux platform.",
			)
		}

		// FQDN should not contain subdirectories
		if strings.Contains(fqdn, "/") {
			diags.AddAttributeError(
				rulePath.AtName("fqdn"),
				"Invalid FQDN configuration",
				"FQDN should not contain subdirectories (e.g., 'example.com/api' is invalid).",
			)
		}
	}

	// service_name is Windows only.
	//
	// The ValueString() != "" test in this check and the two like it below
	// looks redundant now that these attributes reject the empty string, but
	// it is what skips unknown values: ValueString() returns "" for unknown,
	// so dropping it would make an interpolated service_name, executable_path
	// or fqdn fail validation before its value is even known.
	if platform != "Windows" && !rule.ServiceName.IsNull() && rule.ServiceName.ValueString() != "" {
		diags.AddAttributeError(
			rulePath.AtName("service_name"),
			"Invalid service_name configuration",
			"service_name is only supported on Windows platform.",
		)
	}

	// executable_path not supported on Linux (but works on Mac and Windows)
	if platform == "Linux" && !rule.ExecutablePath.IsNull() && rule.ExecutablePath.ValueString() != "" {
		diags.AddAttributeError(
			rulePath.AtName("executable_path"),
			"Invalid executable_path configuration",
			"executable_path is not supported on Linux platform.",
		)
	}

	// Linux protocol restrictions
	if platform == "Linux" {
		protocol := rule.Protocol.ValueString()
		for _, unsupported := range linuxUnsupportedProtocols {
			if protocol == unsupported {
				diags.AddAttributeError(
					rulePath.AtName("protocol"),
					"Unsupported protocol for Linux",
					fmt.Sprintf("Protocol '%s' is not supported on Linux platform.", protocol),
				)
				break
			}
		}
	}

	// network_location is restricted to ANY on Linux. The attribute takes
	// arbitrary strings so that custom network location IDs work, so the
	// platform restriction can only be enforced here. This reads the config,
	// where an omitted value is null, so the "ANY" default is never rejected.
	if platform == "Linux" && utils.IsKnown(rule.NetworkLocation) &&
		rule.NetworkLocation.ValueString() != "ANY" {
		diags.AddAttributeError(
			rulePath.AtName("network_location"),
			"Invalid network_location configuration",
			"network_location must be 'ANY' on Linux platform.",
		)
	}

	protocol := rule.Protocol.ValueString()

	if protocol != "TCP" && protocol != "UDP" {
		if !rule.LocalPort.IsNull() && len(rule.LocalPort.Elements()) > 0 {
			diags.AddAttributeError(
				rulePath.AtName("local_port"),
				"Invalid port configuration",
				"local_port is only valid for TCP or UDP protocols.",
			)
		}
		if !rule.RemotePort.IsNull() && len(rule.RemotePort.Elements()) > 0 {
			diags.AddAttributeError(
				rulePath.AtName("remote_port"),
				"Invalid port configuration",
				"remote_port is only valid for TCP or UDP protocols.",
			)
		}
	}

	return diags
}
