package cloudsecurity

import (
	"context"
	"errors"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client/admission_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

var customRulesSchema = schema.SetNestedAttribute{
	Computed: true,
	Optional: true,
	Default:  setdefault.StaticValue(types.SetNull(types.ObjectType{AttrTypes: customRulesAttrMap})),
	MarkdownDescription: "Manage custom rules for your KAC policy. Adding a custom rule to one " +
		"rule group also adds the custom rule to all other rule groups in the same policy. " +
		"Custom rules are set to `\"Disabled\"` by default. Action must be one of:\n" +
		" - `\"Disabled\"`: Do nothing\n" +
		" - `\"Alert\"`: Send an alert\n" +
		" - `\"Prevent\"`: Prevent the object from running",
	NestedObject: schema.NestedAttributeObject{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "Identifier for the KAC custom rule.",
			},
			"action": schema.StringAttribute{
				Required:    true,
				Description: "Determines what action Falcon KAC takes when assessing the custom rule.",
				Validators: []validator.String{
					stringvalidator.OneOf("Alert", "Prevent", "Disabled"),
				},
			},
		},
	},
}

func (cr *customRuleTFModel) wrapCustomRule(apiCustomRule *models.ModelsKACCustomPolicyRule) {
	if apiCustomRule.ID != nil {
		cr.ID = types.StringValue(*apiCustomRule.ID)
	}
	if apiCustomRule.Action != nil {
		cr.Action = types.StringValue(*apiCustomRule.Action)
	}
}

// validateCustomRulesPropagation validates that if custom_rules is explicitly set in any rule group's config,
// it must contain all unique custom rule IDs that exist across the entire policy.
// This ensures the provider does not run into a validation error for the count of custom rules in the config
// compared to the plan, when custom rules are propagated across all rule groups.
func (r *cloudSecurityKacPolicyResource) validateCustomRulesPropagation(
	ctx context.Context,
	config cloudSecurityKacPolicyResourceModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if config.RuleGroups.IsNull() {
		return diags
	}

	uniqueCustomRuleIDs := make(map[string]bool)
	type ruleGroupInfo struct {
		name  string
		count int
		path  path.Path
	}
	var ruleGroupsWithCustomRules []ruleGroupInfo

	planRuleGroups := flex.ExpandListAs[ruleGroupTFModel](ctx, config.RuleGroups, &diags)
	if diags.HasError() {
		return diags
	}

	if utils.IsKnown(config.DefaultRuleGroup) {
		var defaultRG ruleGroupTFModel
		diags.Append(config.DefaultRuleGroup.As(ctx, &defaultRG, basetypes.ObjectAsOptions{})...)
		defaultRG.Name = types.StringValue("Default")
		if diags.HasError() {
			return diags
		}

		planRuleGroups = append(planRuleGroups, defaultRG)
	}

	for idx, rg := range planRuleGroups {
		if !utils.IsKnown(rg.CustomRules) {
			continue
		}

		customRules := flex.ExpandSetAs[customRuleTFModel](ctx, rg.CustomRules, &diags)
		if diags.HasError() {
			return diags
		}

		rgPath := path.Root("rule_groups").AtListIndex(idx).AtName("custom_rules")
		rgName := rg.Name.ValueString()
		if rg.Name.ValueString() == "Default" {
			rgPath = path.Root("default_rule_group").AtName("custom_rules")
		}

		ruleGroupsWithCustomRules = append(ruleGroupsWithCustomRules, ruleGroupInfo{
			name:  rgName,
			count: len(customRules),
			path:  rgPath,
		})

		for _, cr := range customRules {
			uniqueCustomRuleIDs[cr.ID.ValueString()] = true
		}
	}

	totalUniqueRules := len(uniqueCustomRuleIDs)
	for _, rgInfo := range ruleGroupsWithCustomRules {
		if rgInfo.count != totalUniqueRules {
			diags.AddAttributeError(
				rgInfo.path,
				"Incomplete custom rules configuration",
				fmt.Sprintf(
					"Rule group %q has %d custom rule(s), but the policy has %d unique custom rule(s) total. "+
						"All rule groups with custom_rules defined must include all custom rules attached to the policy.",
					rgInfo.name,
					rgInfo.count,
					totalUniqueRules,
				),
			)
		}
	}

	return diags
}

// propagateCustomRules ensures custom rules are propagated across all rule groups according to the following parameters:
// - When a custom rule is added to one rule group, it's automatically added to all other rule groups with action "Disabled".
// - When a custom rule is removed from one rule group but exists in another, it's set to "Disabled" instead of deleted.
// - A custom rule is only fully removed when it's not present in any rule group in the config.
// Before propagating custom rules we validate the count of custom rules in the config for each rule group,
// so we can safely assume any custom rules in the config have already been propagated.
func (r *cloudSecurityKacPolicyResource) propagateCustomRules(
	ctx context.Context,
	plan cloudSecurityKacPolicyResourceModel,
) (cloudSecurityKacPolicyResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	modifiedPlan := plan

	if plan.RuleGroups.IsNull() {
		return modifiedPlan, diags
	}

	planRuleGroups := flex.ExpandListAs[ruleGroupTFModel](ctx, plan.RuleGroups, &diags)
	if diags.HasError() {
		return modifiedPlan, diags
	}

	var defaultRG ruleGroupTFModel
	diags.Append(plan.DefaultRuleGroup.As(ctx, &defaultRG, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return modifiedPlan, diags
	}

	planRuleGroups = append(planRuleGroups, defaultRG)
	customRuleIDs := make([]string, 0, 10)
	for _, rg := range planRuleGroups {
		if rg.CustomRules.IsNull() || rg.CustomRules.IsUnknown() {
			continue
		}

		customRules := flex.ExpandSetAs[customRuleTFModel](ctx, rg.CustomRules, &diags)
		if diags.HasError() {
			return modifiedPlan, diags
		}

		for _, cr := range customRules {
			customRuleIDs = append(customRuleIDs, cr.ID.ValueString())
		}

		// we only need the custom rules from the first rule group with custom rules configured
		break
	}

	if len(customRuleIDs) == 0 {
		return modifiedPlan, diags
	}

	for rgIdx, rg := range planRuleGroups {
		// skip any known custom rules, custom rules propagation in the config has already been validated
		if utils.IsKnown(rg.CustomRules) {
			continue
		}

		propagatedCustomRules := make([]customRuleTFModel, 0, len(customRuleIDs))
		for _, customRuleID := range customRuleIDs {
			customRuleCopy := customRuleTFModel{
				ID:     types.StringValue(customRuleID),
				Action: types.StringValue("Disabled"),
			}

			propagatedCustomRules = append(propagatedCustomRules, customRuleCopy)
		}

		customRuleSet, setDiags := types.SetValueFrom(ctx, types.ObjectType{
			AttrTypes: customRulesAttrMap,
		}, propagatedCustomRules)
		diags.Append(setDiags...)
		if diags.HasError() {
			return modifiedPlan, diags
		}

		planRuleGroups[rgIdx].CustomRules = customRuleSet
	}

	defaultRGIdx := len(planRuleGroups) - 1
	defaultRGObj, objDiags := types.ObjectValueFrom(ctx, ruleGroupAttrMap, planRuleGroups[defaultRGIdx])
	diags.Append(objDiags...)
	if diags.HasError() {
		return modifiedPlan, diags
	}

	modifiedRuleGroupsList, listDiags := types.ListValueFrom(ctx, plan.RuleGroups.ElementType(ctx), planRuleGroups[:defaultRGIdx])
	diags.Append(listDiags...)
	if diags.HasError() {
		return modifiedPlan, diags
	}

	modifiedPlan.RuleGroups = modifiedRuleGroupsList
	modifiedPlan.DefaultRuleGroup = defaultRGObj

	return modifiedPlan, diags
}

func (r *cloudSecurityKacPolicyResource) reconcileCustomRules(
	ctx context.Context,
	policyID string,
	planRuleGroupsWithDefaultRG []ruleGroupTFModel,
	apiKacPolicy *models.ModelsKACPolicy,
) (*models.ModelsKACPolicy, diag.Diagnostics) {
	var diags diag.Diagnostics

	planCustomRuleIDs := types.SetNull(types.StringType)
	planDefaultRG := planRuleGroupsWithDefaultRG[len(planRuleGroupsWithDefaultRG)-1]
	if utils.IsKnown(planDefaultRG.CustomRules) {
		customRules := flex.ExpandSetAs[customRuleTFModel](ctx, planDefaultRG.CustomRules, &diags)
		if diags.HasError() {
			return nil, diags
		}

		ids := make([]string, 0, len(customRules))
		for _, cr := range customRules {
			ids = append(ids, cr.ID.ValueString())
		}

		planCustomRuleIDs, diags = flex.FlattenStringValueSet(ctx, ids)
		if diags.HasError() {
			return nil, diags
		}
	}

	stateDefaultRG := apiKacPolicy.RuleGroups[len(apiKacPolicy.RuleGroups)-1]
	stateCustomRuleIDs := types.SetNull(types.StringType)
	if len(stateDefaultRG.CustomRules) > 0 {
		ids := make([]string, 0, len(stateDefaultRG.CustomRules))
		for _, cr := range stateDefaultRG.CustomRules {
			if cr.ID != nil {
				ids = append(ids, *cr.ID)
			}
		}

		stateCustomRuleIDs, diags = flex.FlattenStringValueSet(ctx, ids)
		if diags.HasError() {
			return nil, diags
		}
	}

	idsToAdd, idsToRemove, setDiags := utils.SetIDsToModify(ctx, planCustomRuleIDs, stateCustomRuleIDs)
	diags.Append(setDiags...)
	if diags.HasError() {
		return nil, diags
	}

	if len(idsToAdd) > 0 {
		updatedPolicy := r.addCustomRules(ctx, &diags, policyID, *stateDefaultRG.ID, idsToAdd)
		if diags.HasError() {
			return nil, diags
		}

		if updatedPolicy != nil {
			apiKacPolicy = updatedPolicy
		}
	}

	if len(idsToRemove) > 0 {
		updatedPolicy := r.removeCustomRules(ctx, &diags, policyID, idsToRemove)
		if diags.HasError() {
			return nil, diags
		}

		if updatedPolicy != nil {
			apiKacPolicy = updatedPolicy
		}
	}

	customRulesToUpdate, updateDiags := r.determineCustomRulesToUpdate(ctx, planRuleGroupsWithDefaultRG, apiKacPolicy)
	diags.Append(updateDiags...)
	if diags.HasError() {
		return nil, diags
	}

	if len(customRulesToUpdate) > 0 {
		updatedPolicy := r.updateCustomRuleActions(ctx, &diags, policyID, customRulesToUpdate)
		if diags.HasError() {
			return nil, diags
		}

		if updatedPolicy != nil {
			apiKacPolicy = updatedPolicy
		}
	}

	return apiKacPolicy, diags
}

func (r *cloudSecurityKacPolicyResource) determineCustomRulesToUpdate(
	ctx context.Context,
	planRuleGroups []ruleGroupTFModel,
	apiKacPolicy *models.ModelsKACPolicy,
) (map[string][]*models.ModelsUpdateCustomRuleAction, diag.Diagnostics) {
	var diags diag.Diagnostics
	toUpdate := make(map[string][]*models.ModelsUpdateCustomRuleAction)

	stateRuleGroupsMap := make(map[string]*models.ModelsKACPolicyRuleGroup)
	for _, apiRG := range apiKacPolicy.RuleGroups {
		stateRuleGroupsMap[*apiRG.ID] = apiRG
	}

	for _, planRG := range planRuleGroups {
		rgID := planRG.ID.ValueString()
		stateRG := stateRuleGroupsMap[rgID]

		var stateCustomRulesSet types.Set
		if len(stateRG.CustomRules) > 0 {
			stateCustomRules := make([]customRuleTFModel, 0, len(stateRG.CustomRules))
			for _, cr := range stateRG.CustomRules {
				customRule := customRuleTFModel{}
				customRule.wrapCustomRule(cr)
				stateCustomRules = append(stateCustomRules, customRule)
			}

			var setDiags diag.Diagnostics
			stateCustomRulesSet, setDiags = types.SetValueFrom(ctx, types.ObjectType{
				AttrTypes: customRulesAttrMap,
			}, stateCustomRules)
			diags.Append(setDiags...)
			if diags.HasError() {
				return nil, diags
			}
		}

		if planRG.CustomRules.Equal(stateCustomRulesSet) {
			continue
		}

		if utils.IsKnown(planRG.CustomRules) && len(planRG.CustomRules.Elements()) > 0 {
			planCustomRules := flex.ExpandSetAs[customRuleTFModel](ctx, planRG.CustomRules, &diags)
			if diags.HasError() {
				return nil, diags
			}

			customRuleActions := make([]*models.ModelsUpdateCustomRuleAction, 0, len(planCustomRules))
			for _, cr := range planCustomRules {
				customRuleActions = append(customRuleActions, &models.ModelsUpdateCustomRuleAction{
					ID:     cr.ID.ValueStringPointer(),
					Action: cr.Action.ValueStringPointer(),
				})
			}

			toUpdate[rgID] = customRuleActions
		}
	}

	return toUpdate, diags
}

func (r *cloudSecurityKacPolicyResource) addCustomRules(
	ctx context.Context,
	diags *diag.Diagnostics,
	policyID string,
	ruleGroupId string,
	customRulesToAdd []string,
) *models.ModelsKACPolicy {
	disabled := "Disabled"
	customRules := make([]*models.ModelsCustomRule, len(customRulesToAdd))
	for i, customRuleId := range customRulesToAdd {
		customRules[i] = &models.ModelsCustomRule{
			ID:     &customRuleId,
			Action: &disabled,
		}
	}

	ruleGroups := []*models.ModelsAddRuleGroupRule{
		{
			ID:          &ruleGroupId,
			CustomRules: customRules,
		},
	}

	addRequest := &models.ModelsAddPolicyRuleGroupCustomRuleRequest{
		ID:         &policyID,
		RuleGroups: ruleGroups,
	}

	params := admission_control_policies.NewAdmissionControlAddRuleGroupCustomRuleParamsWithContext(ctx).
		WithBody(addRequest)

	addResponse, err := r.client.AdmissionControlPolicies.AdmissionControlAddRuleGroupCustomRule(params)
	if err != nil {
		var forbiddenError *admission_control_policies.AdmissionControlAddRuleGroupCustomRuleForbidden
		if errors.As(err, &forbiddenError) {
			diags.Append(tferrors.NewForbiddenError(tferrors.Update, cloudSecurityKacPolicyScopes))
			return nil
		}

		diags.Append(tferrors.NewOperationError(tferrors.Update, err))
		return nil
	}

	if addResponse == nil || addResponse.Payload == nil || len(addResponse.Payload.Resources) == 0 {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return nil
	}

	return addResponse.Payload.Resources[0]
}

func (r *cloudSecurityKacPolicyResource) removeCustomRules(
	ctx context.Context,
	diags *diag.Diagnostics,
	policyID string,
	customRuleIDsToRemove []string,
) *models.ModelsKACPolicy {
	params := admission_control_policies.NewAdmissionControlRemoveRuleGroupCustomRuleParamsWithContext(ctx).
		WithPolicyID(policyID).
		WithCustomRuleIds(customRuleIDsToRemove)

	removeResponse, err := r.client.AdmissionControlPolicies.AdmissionControlRemoveRuleGroupCustomRule(params)
	if err != nil {
		var forbiddenError *admission_control_policies.AdmissionControlRemoveRuleGroupCustomRuleForbidden
		if errors.As(err, &forbiddenError) {
			diags.Append(tferrors.NewForbiddenError(tferrors.Update, cloudSecurityKacPolicyScopes))
			return nil
		}

		diags.Append(tferrors.NewOperationError(tferrors.Update, err))
		return nil
	}

	if removeResponse == nil || removeResponse.Payload == nil || len(removeResponse.Payload.Resources) == 0 {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return nil
	}

	return removeResponse.Payload.Resources[0]
}

func (r *cloudSecurityKacPolicyResource) updateCustomRuleActions(
	ctx context.Context,
	diags *diag.Diagnostics,
	policyID string,
	customRulesToUpdate map[string][]*models.ModelsUpdateCustomRuleAction,
) *models.ModelsKACPolicy {
	updateRuleGroups := make([]*models.ModelsUpdateRuleGroup, 0)

	for rgID, customRules := range customRulesToUpdate {
		updateRG := &models.ModelsUpdateRuleGroup{
			ID:          &rgID,
			CustomRules: customRules,
		}
		updateRuleGroups = append(updateRuleGroups, updateRG)
	}

	updateRequest := &models.ModelsUpdatePolicyRuleGroupRequest{
		ID:         &policyID,
		RuleGroups: updateRuleGroups,
	}

	params := admission_control_policies.NewAdmissionControlUpdateRuleGroupsParamsWithContext(ctx).
		WithBody(updateRequest)

	updateResponse, err := r.client.AdmissionControlPolicies.AdmissionControlUpdateRuleGroups(params)
	if err != nil {
		var forbiddenError *admission_control_policies.AdmissionControlUpdateRuleGroupsForbidden
		if errors.As(err, &forbiddenError) {
			diags.Append(tferrors.NewForbiddenError(tferrors.Update, cloudSecurityKacPolicyScopes))
			return nil
		}

		diags.Append(tferrors.NewOperationError(tferrors.Update, err))
		return nil
	}

	if updateResponse == nil || updateResponse.Payload == nil || len(updateResponse.Payload.Resources) == 0 {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return nil
	}

	return updateResponse.Payload.Resources[0]
}
