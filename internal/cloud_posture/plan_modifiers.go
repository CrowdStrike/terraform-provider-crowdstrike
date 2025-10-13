package cloudposture

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func CustomPlanModifierAlertRemediationInfo() planmodifier.List {
	return requiresReplaceIfEmptyModifier{}
}

type requiresReplaceIfEmptyModifier struct{}

func (m requiresReplaceIfEmptyModifier) Description(_ context.Context) string {
	return "If the value becomes empty or null, Terraform will destroy and recreate the resource."
}

func (m requiresReplaceIfEmptyModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m requiresReplaceIfEmptyModifier) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	// Don't do anything during create
	if req.State.Raw.IsNull() {
		return
	}

	var config cloudPostureCustomRuleResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !req.ConfigValue.IsUnknown() && !req.ConfigValue.IsNull() && len(req.ConfigValue.Elements()) == 0 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid List Length",
			fmt.Sprintf("The list for attribute '%s' cannot be empty. Either omit the field entirely or provide at least one element.", req.Path.String()),
		)
		return
	}

	if !config.ParentRuleId.IsUnknown() && config.ParentRuleId.IsNull() {
		if req.ConfigValue.IsNull() || len(req.ConfigValue.Elements()) == 0 {
			if !req.StateValue.IsNull() && len(req.StateValue.Elements()) > 0 {
				resp.RequiresReplace = true
				resp.PlanValue = req.ConfigValue
			}
		}
	}

	if !config.ParentRuleId.IsUnknown() && !config.ParentRuleId.IsNull() {
		if req.ConfigValue.IsNull() {
			resp.PlanValue = types.ListUnknown(types.StringType)
		}
	}

}
