package cloudsecurity

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

const defaultRuleGroupName = "Default"

var ruleGroupAttributeMap = map[string]attr.Type{
	"id":            types.StringType,
	"name":          types.StringType,
	"description":   types.StringType,
	"deny_on_error": types.BoolType,
	"image_assessment": types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"enabled":             types.BoolType,
			"unassessed_handling": types.StringType,
		},
	},
	"namespaces": types.SetType{ElemType: types.StringType},
	"labels": types.SetType{ElemType: types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"key":      types.StringType,
			"value":    types.StringType,
			"operator": types.StringType,
		},
	}},
	"default_rules": types.ObjectType{
		AttrTypes: defaultRulesAttributeMap,
	},
}

type ruleGroupUpdates struct {
	updateRuleGroupParams          *models.APIUpdateRuleGroup
	replaceRuleGroupSelectorParams *models.APIReplaceRuleGroupSelectors
}

//func (m *cloudSecurityKacPolicyResourceModel) toRuleGroupsApiModel(ctx context.Context) ([]models.PolicyhandlerKACPolicyRuleGroup, diag.Diagnostics) {
//	var diags diag.Diagnostics
//	var ruleGroups []models.PolicyhandlerKACPolicyRuleGroup
//
//	if !m.RuleGroups.IsNull() && !m.RuleGroups.IsUnknown() {
//		var tfRuleGroups []ruleGroupTFModel
//		diags.Append(m.RuleGroups.ElementsAs(ctx, &tfRuleGroups, false)...)
//		if diags.HasError() {
//			return nil, diags
//		}
//
//		ruleGroups = make([]models.PolicyhandlerKACPolicyRuleGroup, len(tfRuleGroups))
//		for i, tfRG := range tfRuleGroups {
//			domainRG, convertDiags := tfRG.toApiModel(ctx)
//			diags.Append(convertDiags...)
//			if diags.HasError() {
//				return nil, diags
//			}
//			ruleGroups[i] = domainRG
//		}
//	}
//
//	return ruleGroups, diags
//}

func (m *cloudSecurityKacPolicyResourceModel) getRuleGroupIds(ctx context.Context) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var ruleGroupIds []string

	if !m.RuleGroups.IsNull() && !m.RuleGroups.IsUnknown() {
		var tfRuleGroups []ruleGroupTFModel
		diags.Append(m.RuleGroups.ElementsAs(ctx, &tfRuleGroups, false)...)
		if diags.HasError() {
			return nil, diags
		}

		ruleGroupIds = make([]string, 0, len(tfRuleGroups))
		for _, tfRG := range tfRuleGroups {
			if !tfRG.ID.IsNull() && !tfRG.ID.IsUnknown() {
				ruleGroupIds = append(ruleGroupIds, tfRG.ID.ValueString())
			}
		}
	}

	return ruleGroupIds, diags
}

func (m *ruleGroupTFModel) wrapRuleGroup(ctx context.Context, rg *models.PolicyhandlerKACPolicyRuleGroup) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringValue(*rg.ID)
	m.Name = types.StringValue(*rg.Name)
	m.Description = flex.StringPointerToFramework(rg.Description)
	m.DenyOnError = types.BoolPointerValue(rg.DenyOnError.Deny)

	imageAssessment := imageAssessmentTFModel{}
	imageAssessment.Enabled = types.BoolPointerValue(rg.ImageAssessment.Enabled)
	imageAssessment.UnassessedHandling = flex.StringPointerToFramework(rg.ImageAssessment.UnassessedHandling)
	imageAssessmentObj, objectDiags := types.ObjectValueFrom(ctx, map[string]attr.Type{
		"enabled":             types.BoolType,
		"unassessed_handling": types.StringType,
	}, imageAssessment)
	diags.Append(objectDiags...)
	if !diags.HasError() {
		m.ImageAssessment = imageAssessmentObj
	}

	if rg.Namespaces != nil {
		namespaces := make([]string, len(rg.Namespaces))
		for i, ns := range rg.Namespaces {
			if ns.Value != nil {
				namespaces[i] = *ns.Value
			}
		}
		namespaceSet, setDiags := types.SetValueFrom(ctx, types.StringType, namespaces)
		diags.Append(setDiags...)
		if !diags.HasError() {
			m.Namespaces = namespaceSet
		}
	}

	if rg.Labels != nil {
		labels := make([]labelTFModel, len(rg.Labels))
		for i, l := range rg.Labels {
			label := labelTFModel{}
			if l.Key != nil {
				label.Key = types.StringValue(*l.Key)
			}
			if l.Value != nil {
				label.Value = types.StringValue(*l.Value)
			}
			if l.Operator != nil {
				label.Operator = types.StringValue(*l.Operator)
			}
			labels[i] = label
		}
		labelSet, setDiags := types.SetValueFrom(ctx, types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"key":      types.StringType,
				"value":    types.StringType,
				"operator": types.StringType,
			},
		}, labels)
		diags.Append(setDiags...)
		if !diags.HasError() {
			m.Labels = labelSet
		}
	}

	// Convert DefaultRules from API response to TF model structure
	defaultRules := defaultRulesTFModel{}
	for _, apiRule := range rg.DefaultRules {
		diags.Append(defaultRules.wrapDefaultRule(ctx, apiRule)...)
	}

	defaultRulesObj, objDiags := types.ObjectValueFrom(ctx, defaultRulesAttributeMap, defaultRules)
	diags.Append(objDiags...)

	if !diags.HasError() {
		m.DefaultRules = defaultRulesObj
	}

	return diags
}

func (m *ruleGroupTFModel) toApiModel(ctx context.Context) (models.PolicyhandlerKACPolicyRuleGroup, diag.Diagnostics) {
	var diags diag.Diagnostics
	apiModel := models.PolicyhandlerKACPolicyRuleGroup{}

	if m.Name.ValueString() == defaultRuleGroupName {
		isDefault := true
		apiModel.IsDefault = &isDefault
	} else {
		isNotDefault := false
		apiModel.IsDefault = &isNotDefault
	}

	// Basic fields
	apiModel.ID = m.ID.ValueStringPointer()
	apiModel.Name = m.Name.ValueStringPointer()
	apiModel.Description = m.Description.ValueStringPointer()

	if !m.DenyOnError.IsNull() && !m.DenyOnError.IsUnknown() {
		apiModel.DenyOnError = &models.PolicyhandlerKACPolicyRuleGroupDenyOnError{
			Deny: m.DenyOnError.ValueBoolPointer(),
		}
	}

	// Image assessment
	if !m.ImageAssessment.IsNull() && !m.ImageAssessment.IsUnknown() {
		var tfImageAssessment imageAssessmentTFModel
		diags.Append(m.ImageAssessment.As(ctx, &tfImageAssessment, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			apiModel.ImageAssessment = &models.PolicyhandlerKACPolicyRuleGroupImageAssessment{
				Enabled:            tfImageAssessment.Enabled.ValueBoolPointer(),
				UnassessedHandling: tfImageAssessment.UnassessedHandling.ValueStringPointer(),
			}
		}
	}

	// Namespaces
	if !m.Namespaces.IsNull() && !m.Namespaces.IsUnknown() {
		var namespaces []string
		diags.Append(m.Namespaces.ElementsAs(ctx, &namespaces, false)...)
		if !diags.HasError() {
			apiModel.Namespaces = make([]*models.PolicyhandlerKACPolicyRuleGroupNamespace, len(namespaces))
			for i, ns := range namespaces {
				apiModel.Namespaces[i] = &models.PolicyhandlerKACPolicyRuleGroupNamespace{Value: &ns}
			}
		}
	}

	// Labels
	if !m.Labels.IsNull() && !m.Labels.IsUnknown() {
		var tfLabels []labelTFModel
		diags.Append(m.Labels.ElementsAs(ctx, &tfLabels, false)...)
		if !diags.HasError() {
			apiModel.Labels = make([]*models.PolicyhandlerKACPolicyRuleGroupLabel, len(tfLabels))
			for i, tfLabel := range tfLabels {
				apiModel.Labels[i] = &models.PolicyhandlerKACPolicyRuleGroupLabel{
					Key:      tfLabel.Key.ValueStringPointer(),
					Value:    tfLabel.Value.ValueStringPointer(),
					Operator: tfLabel.Operator.ValueStringPointer(),
				}
			}
		}
	}

	// Default rules
	if !m.DefaultRules.IsNull() && !m.DefaultRules.IsUnknown() {
		var tfDefaultRules defaultRulesTFModel
		apiDefaultRuleActions, defaultRuleDiags := tfDefaultRules.toApiDefaultRuleActions(ctx, ruleGroupTFModel{DefaultRules: m.DefaultRules})
		diags.Append(defaultRuleDiags...)
		if !diags.HasError() {
			apiModel.DefaultRules = make([]*models.PolicyhandlerKACDefaultPolicyRule, len(apiDefaultRuleActions))
			for i, apiAction := range apiDefaultRuleActions {
				apiModel.DefaultRules[i] = &models.PolicyhandlerKACDefaultPolicyRule{
					Code:   apiAction.Code,
					Action: apiAction.Action,
				}
			}
		}
	}

	return apiModel, diags
}

func findRuleGroupsToDelete(stateIds, planIds []string) []string {
	planIdSet := make(map[string]bool)
	for _, id := range planIds {
		planIdSet[id] = true
	}

	var toDelete []string
	for _, stateId := range stateIds {
		if !planIdSet[stateId] {
			toDelete = append(toDelete, stateId)
		}
	}
	return toDelete
}

func buildRuleGroupUpdates(plan, state *models.PolicyhandlerKACPolicyRuleGroup) ruleGroupUpdates {
	updates := ruleGroupUpdates{}
	var updateRuleGroupParams models.APIUpdateRuleGroup
	var replaceSelectorsParams models.APIReplaceRuleGroupSelectors

	// Compare basic fields
	if !*plan.IsDefault && (!nameEqual(plan, state) || !descriptionEqual(plan, state)) {
		updates.updateRuleGroupParams = &updateRuleGroupParams
		updateRuleGroupParams.ID = plan.ID
		updateRuleGroupParams.Name = plan.Name
		updateRuleGroupParams.Description = plan.Description

		updates.updateRuleGroupParams = &updateRuleGroupParams
	}

	// Compare deny on error
	if !denyOnErrorUnchanged(plan, state) {
		if updates.updateRuleGroupParams == nil {
			updates.updateRuleGroupParams = &updateRuleGroupParams
			updates.updateRuleGroupParams.ID = plan.ID
		}

		updates.updateRuleGroupParams.DenyOnError = plan.DenyOnError
	}

	// Compare image assessment
	if !imageAssessmentUnchanged(plan, state) {
		if updates.updateRuleGroupParams == nil {
			updates.updateRuleGroupParams = &updateRuleGroupParams
			updates.updateRuleGroupParams.ID = plan.ID
		}

		updates.updateRuleGroupParams.ImageAssessment = plan.ImageAssessment
	}

	// Compare namespaces
	if !*plan.IsDefault && !namespacesUnchanged(plan, state) {
		if updates.replaceRuleGroupSelectorParams == nil {
			updates.replaceRuleGroupSelectorParams = &replaceSelectorsParams
			replaceSelectorsParams.ID = plan.ID
		}

		apiReplaceNamespaces := make([]*models.APIReplacePolicyRuleGroupNamespace, len(plan.Namespaces))
		for i, namespace := range plan.Namespaces {
			apiReplaceNamespaces[i] = &models.APIReplacePolicyRuleGroupNamespace{Value: namespace.Value}
		}

		replaceSelectorsParams.Namespaces = apiReplaceNamespaces
	}

	// Compare labels
	if !*plan.IsDefault && !labelsUnchanged(plan, state) {
		if updates.replaceRuleGroupSelectorParams == nil {
			updates.replaceRuleGroupSelectorParams = &replaceSelectorsParams
			replaceSelectorsParams.ID = plan.ID
		}

		apiReplaceLabels := make([]*models.APIReplacePolicyRuleGroupLabel, len(plan.Labels))
		for i, label := range plan.Labels {
			apiReplaceLabels[i] = &models.APIReplacePolicyRuleGroupLabel{
				Key:      label.Key,
				Value:    label.Value,
				Operator: label.Operator,
			}
		}

		replaceSelectorsParams.Labels = apiReplaceLabels
	}

	// Compare default rules
	if state == nil || !defaultRulesUnchanged(plan, state) {
		if updates.updateRuleGroupParams == nil {
			updates.updateRuleGroupParams = &updateRuleGroupParams
			updates.updateRuleGroupParams.ID = plan.ID
		}

		apiUpdateDefaultRules := make([]*models.APIUpdateDefaultRuleAction, len(plan.DefaultRules))
		for i, defaultRule := range plan.DefaultRules {
			apiUpdateDefaultRules[i] = &models.APIUpdateDefaultRuleAction{
				Action: defaultRule.Action,
				Code:   defaultRule.Code,
			}
		}

		updates.updateRuleGroupParams.DefaultRules = apiUpdateDefaultRules
	}

	return updates
}

func nameEqual(plan, state *models.PolicyhandlerKACPolicyRuleGroup) bool {
	if plan.Name == nil && (state == nil || state.Name == nil) {
		return true
	}

	return plan.Name != nil && state.Name != nil && *plan.Name == *state.Name
}

func descriptionEqual(plan, state *models.PolicyhandlerKACPolicyRuleGroup) bool {
	if plan.Description == nil && (state == nil || state.Description == nil) {
		return true
	}

	return plan.Description != nil && state.Description != nil && *plan.Description == *state.Description
}

func denyOnErrorUnchanged(plan, state *models.PolicyhandlerKACPolicyRuleGroup) bool {
	if plan.DenyOnError == nil {
		return true
	}

	return state.DenyOnError != nil && *plan.DenyOnError.Deny == *state.DenyOnError.Deny
}

func imageAssessmentUnchanged(plan, state *models.PolicyhandlerKACPolicyRuleGroup) bool {
	if plan.ImageAssessment == nil {
		return true
	}

	return state.ImageAssessment != nil &&
		*plan.ImageAssessment.Enabled == *state.ImageAssessment.Enabled &&
		*plan.ImageAssessment.UnassessedHandling == *state.ImageAssessment.UnassessedHandling
}

func namespacesUnchanged(plan, state *models.PolicyhandlerKACPolicyRuleGroup) bool {
	if plan.Namespaces == nil || *plan.IsDefault {
		return true
	}

	if state.Namespaces == nil || len(plan.Namespaces) != len(state.Namespaces) {
		return false
	}

	planNamespaceSet := make(map[string]bool)
	for _, ns := range plan.Namespaces {
		planNamespaceSet[*ns.Value] = true
	}
	for _, ns := range state.Namespaces {
		if !planNamespaceSet[*ns.Value] {
			return false
		}
	}

	return true
}

func labelsUnchanged(plan, state *models.PolicyhandlerKACPolicyRuleGroup) bool {
	if plan.Labels == nil || *plan.IsDefault {
		return true
	}

	if state.Labels == nil || len(plan.Labels) != len(state.Labels) {
		return false
	}

	planLabelMap := make(map[string]models.PolicyhandlerKACPolicyRuleGroupLabel)
	for _, label := range plan.Labels {
		key := *label.Key + "|" + *label.Value + "|" + *label.Operator
		planLabelMap[key] = *label
	}

	for _, stateLabel := range state.Labels {
		key := *stateLabel.Key + "|" + *stateLabel.Value + "|" + *stateLabel.Operator
		if planLabel, exists := planLabelMap[key]; !exists || planLabel.Value != stateLabel.Value {
			return false
		}
	}

	return true
}

func defaultRulesUnchanged(plan, state *models.PolicyhandlerKACPolicyRuleGroup) bool {
	if plan.DefaultRules == nil {
		return true
	}

	if state.DefaultRules == nil || len(plan.DefaultRules) != len(state.DefaultRules) {
		return false
	}

	planDefaultRuleMap := make(map[string]string)
	for _, dr := range plan.DefaultRules {
		planDefaultRuleMap[*dr.Code] = *dr.Action
	}

	for _, stateDR := range state.DefaultRules {
		if planAction, exists := planDefaultRuleMap[*stateDR.Code]; !exists || planAction != *stateDR.Action {
			return false
		}
	}

	return true
}
