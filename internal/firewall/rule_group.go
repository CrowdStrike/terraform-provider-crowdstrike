package firewall

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/swag"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
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
var linuxUnsupportedProtocols = []string{"IGMP", "IP-IN-IP", "IPV6 ENCAPSULATION", "GRE"}

// extractAPIError extracts error messages from API error responses.
func extractAPIError(err error) string {
	if err == nil {
		return "unknown error"
	}

	if badReq, ok := err.(*firewall_management.CreateRuleGroupBadRequest); ok {
		if badReq.Payload != nil && len(badReq.Payload.Errors) > 0 {
			var msgs []string
			for _, e := range badReq.Payload.Errors {
				if e.Message != nil {
					msgs = append(msgs, *e.Message)
				}
			}
			if len(msgs) > 0 {
				return fmt.Sprintf("%s (API errors: %v)", err.Error(), msgs)
			}
		}
	}

	return err.Error()
}

// extractUpdateAPIError extracts error messages from update API error responses.
func extractUpdateAPIError(err error) string {
	if err == nil {
		return "unknown error"
	}

	if badReq, ok := err.(*firewall_management.UpdateRuleGroupBadRequest); ok {
		if badReq.Payload != nil && len(badReq.Payload.Errors) > 0 {
			var msgs []string
			for _, e := range badReq.Payload.Errors {
				if e.Message != nil {
					msgs = append(msgs, *e.Message)
				}
			}
			if len(msgs) > 0 {
				return fmt.Sprintf("%s (API errors: %v)", err.Error(), msgs)
			}
		}
	}

	return err.Error()
}

// extractPolicyAPIError extracts error messages from firewall policy API error responses.
func extractPolicyAPIError(err error) string {
	if err == nil {
		return "unknown error"
	}
	// The firewall policy errors use a common error structure
	// Just return the error string as the SDK handles formatting
	return err.Error()
}

// extractContainerAPIError extracts error messages from policy container API error responses.
func extractContainerAPIError(err error) string {
	if err == nil {
		return "unknown error"
	}
	return err.Error()
}

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
	LastUpdated types.String `tfsdk:"last_updated"`
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
	Log             types.Bool   `tfsdk:"log"`
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
		"log":              types.BoolType,
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
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp of the last Terraform update of the resource.",
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
				Computed:            true,
				MarkdownDescription: "Description of the firewall rule group.",
				Default:             stringdefault.StaticString(""),
				Validators: []validator.String{
					stringvalidator.LengthAtMost(500),
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
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether the rule group is enabled.",
				Default:             booldefault.StaticBool(true),
			},
			"rules": schema.ListNestedAttribute{
				Optional:            true,
				MarkdownDescription: "List of firewall rules in this rule group. Rule precedence is determined by the order in the list.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: ruleSchemaAttributes(),
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
			MarkdownDescription: "Identifier for the firewall rule. Note: Rule IDs may change when the rule group is updated.",
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
			Computed:            true,
			MarkdownDescription: "Description of the firewall rule.",
			Default:             stringdefault.StaticString(""),
		},
		"enabled": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Whether the rule is enabled.",
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
			MarkdownDescription: "Protocol for the rule. Common protocols: `TCP`, `UDP`, `ICMPV4`, `ICMPV6`, `ANY`. Advanced protocols (API-only, not available in console UI): `GRE`, `ESP`, `IGMP`, `IP-IN-IP`, `IPV6 ENCAPSULATION`. Note: Some protocols have platform restrictions (see platform documentation).",
			Validators: []validator.String{
				stringvalidator.OneOf("TCP", "UDP", "ICMPV4", "ICMPV6", "IGMP", "IP-IN-IP", "IPV6 ENCAPSULATION", "GRE", "ESP", "ANY"),
			},
		},
		"address_family": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Address family for the rule. One of: `IP4`, `IP6`.",
			Default:             stringdefault.StaticString("IP4"),
			Validators: []validator.String{
				stringvalidator.OneOf("IP4", "IP6"),
			},
		},
		"local_address": schema.ListNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Local IP addresses for the rule. If empty, matches any local address.",
			NestedObject: schema.NestedAttributeObject{
				Attributes: addressRangeSchemaAttributes(),
			},
		},
		"remote_address": schema.ListNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Remote IP addresses for the rule. If empty, matches any remote address.",
			NestedObject: schema.NestedAttributeObject{
				Attributes: addressRangeSchemaAttributes(),
			},
		},
		"local_port": schema.ListNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Local ports for the rule. Only applicable for TCP/UDP protocols. If empty, matches any port.",
			NestedObject: schema.NestedAttributeObject{
				Attributes: portRangeSchemaAttributes(),
			},
		},
		"remote_port": schema.ListNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Remote ports for the rule. Only applicable for TCP/UDP protocols. If empty, matches any port.",
			NestedObject: schema.NestedAttributeObject{
				Attributes: portRangeSchemaAttributes(),
			},
		},
		"fqdn": schema.StringAttribute{
			Optional:            true,
			MarkdownDescription: "Fully qualified domain name for the rule. Only valid for outbound rules. Multiple FQDNs can be separated by semicolons.",
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.UseStateForUnknown(),
			},
		},
		"network_location": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Network location restriction. One of: `ANY`, or a specific network location ID.",
			Default:             stringdefault.StaticString("ANY"),
		},
		"executable_path": schema.StringAttribute{
			Optional:            true,
			MarkdownDescription: "Path to executable that this rule applies to.",
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.UseStateForUnknown(),
			},
		},
		"service_name": schema.StringAttribute{
			Optional:            true,
			MarkdownDescription: "Windows service name that this rule applies to. Only valid for Windows platform.",
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.UseStateForUnknown(),
			},
		},
		"icmp_type": schema.StringAttribute{
			Optional:            true,
			MarkdownDescription: "ICMP type for ICMP protocol rules. Use `*` for any.",
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.UseStateForUnknown(),
			},
		},
		"icmp_code": schema.StringAttribute{
			Optional:            true,
			MarkdownDescription: "ICMP code for ICMP protocol rules. Use `*` for any.",
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.UseStateForUnknown(),
			},
		},
		"watch_mode": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Enable watch mode (monitoring) for this rule instead of enforcing.",
			Default:             booldefault.StaticBool(false),
			PlanModifiers: []planmodifier.Bool{
				boolplanmodifier.UseStateForUnknown(),
			},
		},
		"log": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Enable logging for this rule.",
			Default:             booldefault.StaticBool(false),
			PlanModifiers: []planmodifier.Bool{
				boolplanmodifier.UseStateForUnknown(),
			},
		},
	}
}

// addressRangeSchemaAttributes returns schema attributes for IP address ranges.
func addressRangeSchemaAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"address": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "IP address or `*` for any.",
		},
		"netmask": schema.Int64Attribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "CIDR netmask (0-32 for IPv4, 0-128 for IPv6). Use 0 for single IP or any.",
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
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "End port for range (1-65535). Use 0 for single port.",
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

	rules, diags := r.buildRulesPayload(ctx, plan.Rules, plan.Platform.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// API expects lowercase platform values
	platform := strings.ToLower(plan.Platform.ValueString())

	createReq := &models.FwmgrAPIRuleGroupCreateRequestV1{
		Name:        swag.String(plan.Name.ValueString()),
		Description: swag.String(plan.Description.ValueString()),
		Platform:    swag.String(platform),
		Enabled:     swag.Bool(plan.Enabled.ValueBool()),
		Rules:       rules,
	}

	params := firewall_management.NewCreateRuleGroupParams().
		WithContext(ctx).
		WithBody(createReq)

	result, err := r.client.FirewallManagement.CreateRuleGroup(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to create firewall rule group",
			fmt.Sprintf("Could not create firewall rule group '%s': %s", plan.Name.ValueString(), extractAPIError(err)),
		)
		return
	}

	if result.Payload == nil || len(result.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Failed to create firewall rule group",
			"API returned empty response when creating firewall rule group.",
		)
		return
	}

	ruleGroupID := result.Payload.Resources[0]
	plan.ID = types.StringValue(ruleGroupID)

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(r.readRuleGroupState(ctx, &plan, plan.Rules)...)
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

	// For Read, use state.Rules as the plan since we want to preserve existing order
	resp.Diagnostics.Append(r.readRuleGroupState(ctx, &state, state.Rules)...)
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

	ruleGroup, diags := r.getRuleGroup(ctx, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diffOps, newRuleIDs, newRuleVersions, diags := r.buildDiffOperations(ctx, plan, state, ruleGroup)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(diffOps) > 0 || r.hasRuleOrderChanged(plan, state) {
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
			resp.Diagnostics.AddError(
				"Failed to update firewall rule group",
				fmt.Sprintf("Could not update firewall rule group '%s': %s", plan.ID.ValueString(), extractUpdateAPIError(err)),
			)
			return
		}
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(r.readRuleGroupState(ctx, &plan, plan.Rules)...)
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

		ruleGroup, diags := r.getRuleGroup(ctx, id)
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
			resp.Diagnostics.AddError(
				"Failed to disable firewall rule group before deletion",
				fmt.Sprintf("Could not disable firewall rule group '%s': %s", id, err.Error()),
			)
			return
		}
	}

	params := firewall_management.NewDeleteRuleGroupsParams().
		WithContext(ctx).
		WithIds([]string{id})

	_, err := r.client.FirewallManagement.DeleteRuleGroups(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to delete firewall rule group",
			fmt.Sprintf("Could not delete firewall rule group '%s': %s", id, err.Error()),
		)
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
		rulePath := path.Root("rules").AtListIndex(i)
		fqdn := rule.Fqdn.ValueString()

		// FQDN validations
		if !rule.Fqdn.IsNull() && fqdn != "" {
			// FQDN only supports OUT direction
			if rule.Direction.ValueString() != "OUT" {
				resp.Diagnostics.AddAttributeError(
					rulePath.AtName("fqdn"),
					"Invalid FQDN configuration",
					"FQDN rules must have direction set to 'OUT'.",
				)
			}

			// FQDN cannot be used with remote_address
			if !rule.RemoteAddress.IsNull() && len(rule.RemoteAddress.Elements()) > 0 {
				resp.Diagnostics.AddAttributeError(
					rulePath.AtName("fqdn"),
					"Invalid FQDN configuration",
					"FQDN and remote_address cannot be used together. FQDN rules use domain resolution instead of IP addresses.",
				)
			}

			// FQDN not supported on Linux
			if platform == "Linux" {
				resp.Diagnostics.AddAttributeError(
					rulePath.AtName("fqdn"),
					"Invalid FQDN configuration",
					"FQDN is not supported on Linux platform.",
				)
			}

			// FQDN should not contain subdirectories
			if strings.Contains(fqdn, "/") {
				resp.Diagnostics.AddAttributeError(
					rulePath.AtName("fqdn"),
					"Invalid FQDN configuration",
					"FQDN should not contain subdirectories (e.g., 'example.com/api' is invalid).",
				)
			}
		}

		// service_name is Windows only
		if platform != "Windows" && !rule.ServiceName.IsNull() && rule.ServiceName.ValueString() != "" {
			resp.Diagnostics.AddAttributeError(
				rulePath.AtName("service_name"),
				"Invalid service_name configuration",
				"service_name is only supported on Windows platform.",
			)
		}

		// executable_path not supported on Linux (but works on Mac and Windows)
		if platform == "Linux" && !rule.ExecutablePath.IsNull() && rule.ExecutablePath.ValueString() != "" {
			resp.Diagnostics.AddAttributeError(
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
					resp.Diagnostics.AddAttributeError(
						rulePath.AtName("protocol"),
						"Unsupported protocol for Linux",
						fmt.Sprintf("Protocol '%s' is not supported on Linux platform.", protocol),
					)
					break
				}
			}
		}

		protocol := rule.Protocol.ValueString()
		isICMP := protocol == "ICMPV4" || protocol == "ICMPV6"

		if !isICMP {
			if !rule.IcmpType.IsNull() && rule.IcmpType.ValueString() != "" {
				resp.Diagnostics.AddAttributeError(
					rulePath.AtName("icmp_type"),
					"Invalid ICMP configuration",
					"icmp_type is only valid for ICMPV4 or ICMPV6 protocols.",
				)
			}
			if !rule.IcmpCode.IsNull() && rule.IcmpCode.ValueString() != "" {
				resp.Diagnostics.AddAttributeError(
					rulePath.AtName("icmp_code"),
					"Invalid ICMP configuration",
					"icmp_code is only valid for ICMPV4 or ICMPV6 protocols.",
				)
			}
		}

		if protocol != "TCP" && protocol != "UDP" {
			if !rule.LocalPort.IsNull() && len(rule.LocalPort.Elements()) > 0 {
				resp.Diagnostics.AddAttributeError(
					rulePath.AtName("local_port"),
					"Invalid port configuration",
					"local_port is only valid for TCP or UDP protocols.",
				)
			}
			if !rule.RemotePort.IsNull() && len(rule.RemotePort.Elements()) > 0 {
				resp.Diagnostics.AddAttributeError(
					rulePath.AtName("remote_port"),
					"Invalid port configuration",
					"remote_port is only valid for TCP or UDP protocols.",
				)
			}
		}
	}
}
