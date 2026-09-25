package networkcontainment

import (
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// allowlistRuleModel is the Terraform model of an allowlist rule, shared by the
// resource and the elements of the data source's rules list.
type allowlistRuleModel struct {
	ID              types.String `tfsdk:"id"`
	Type            types.String `tfsdk:"type"`
	Rule            types.String `tfsdk:"rule"`
	Name            types.String `tfsdk:"name"`
	AllowSubdomains types.Bool   `tfsdk:"allow_subdomains"`
}

// AttributeTypes returns the object attribute types of the model, used to build
// the data source's rules list.
func (m allowlistRuleModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":               types.StringType,
		"type":             types.StringType,
		"rule":             types.StringType,
		"name":             types.StringType,
		"allow_subdomains": types.BoolType,
	}
}

// flatten sets the model from an API allowlist rule.
func (m *allowlistRuleModel) flatten(rule models.IpwhitelistinteractorAllowlistRule) {
	m.ID = flex.StringValueToFramework(rule.ID)
	m.Type = flex.StringPointerToFramework(rule.Type)
	m.Rule = flex.StringPointerToFramework(rule.Rule)
	m.Name = flex.StringPointerToFramework(rule.Label)
	m.AllowSubdomains = types.BoolValue(rule.Options != nil && rule.Options.AllowSubdomain)
}

// expand builds the API allowlist rule for create and update requests. The ID
// is empty on create, where the API derives it from the rule.
func (m allowlistRuleModel) expand() *models.IpwhitelistinteractorAllowlistRule {
	rule := &models.IpwhitelistinteractorAllowlistRule{
		ID:      m.ID.ValueString(),
		Context: utils.Addr(allowlistContext),
		Type:    m.Type.ValueStringPointer(),
		Rule:    m.Rule.ValueStringPointer(),
		Label:   m.Name.ValueStringPointer(),
	}
	if m.AllowSubdomains.ValueBool() {
		rule.Options = &models.IpwhitelistinteractorRuleOption{AllowSubdomain: true}
	}
	return rule
}
