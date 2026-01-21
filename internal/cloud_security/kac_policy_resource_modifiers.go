package cloudsecurity

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func UseDefaultRuleGroupModifier() planmodifier.Object {
	return defaultRuleGroupModifier{}
}

// defaultRuleGroupModifier implements the plan modifier.
type defaultRuleGroupModifier struct{}

func (m defaultRuleGroupModifier) Description(_ context.Context) string {
	return "Combines state with default values for the default rule group."
}

func (m defaultRuleGroupModifier) MarkdownDescription(_ context.Context) string {
	return "Combines state with default values for the default rule group."
}

// PlanModifyObject implements the plan modification logic.
func (m defaultRuleGroupModifier) PlanModifyObject(ctx context.Context, req planmodifier.ObjectRequest, resp *planmodifier.ObjectResponse) {
	// Do nothing if there is no state value.
	if req.StateValue.IsNull() {
		return
	}

	// Do nothing if there is a known planned value.
	if !req.PlanValue.IsUnknown() {
		return
	}

	var stateDefaultRuleGroup ruleGroupTFModel
	stateDefaultRuleGroup.DefaultRules.ToObjectValue(ctx)
	resp.Diagnostics.Append(req.StateValue.As(ctx, &stateDefaultRuleGroup, basetypes.ObjectAsOptions{})...)
	if resp.Diagnostics.HasError() {
		return
	}

	defaultRuleGroupValue := types.ObjectValueMust(
		ruleGroupAttrMap,
		map[string]attr.Value{
			"id":            stateDefaultRuleGroup.ID,
			"name":          stateDefaultRuleGroup.Name,
			"description":   stateDefaultRuleGroup.Description,
			"deny_on_error": types.BoolValue(false),
			"image_assessment": types.ObjectValueMust(
				imageAssessmentAttrMap,
				map[string]attr.Value{
					"enabled":             types.BoolValue(false),
					"unassessed_handling": types.StringValue("Allow Without Alert"),
				},
			),
			"namespaces":    stateDefaultRuleGroup.Namespaces,
			"labels":        stateDefaultRuleGroup.Labels,
			"default_rules": defaultRulesDefaultValue,
		},
	)

	resp.PlanValue = defaultRuleGroupValue
}
