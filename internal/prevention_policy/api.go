package preventionpolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var windowsPlatformName = "Windows"
var linuxPlatformName = "Linux"
var macPlatformName = "Mac"

var apiScopes = []scopes.Scope{
	{
		Name:  "Prevention policies",
		Read:  true,
		Write: true,
	},
}

// getDefaultPolicy gets the default prevention update policy based on platformName.
func getDefaultPolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	platformName string,
) (*models.PreventionPolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	caser := cases.Title(language.English)
	platformName = caser.String(platformName)

	filter := fmt.Sprintf(
		`platform_name:'%s'+name.raw:'platform_default'`,
		platformName,
	)
	sort := "precedence.desc"

	res, err := client.PreventionPolicies.QueryCombinedPreventionPolicies(
		&prevention_policies.QueryCombinedPreventionPoliciesParams{
			Context: ctx,
			Filter:  &filter,
			Sort:    &sort,
		},
	)

	if err != nil {
		diags.AddError(
			"Failed to get default prevention policy",
			fmt.Sprintf("Failed to get default prevention policy: %s", err),
		)

		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Unable to find default prevention policy",
			fmt.Sprintf(
				"No policy matched filter: %s, a default policy should exist. Please report this issue to the provider developers.",
				filter,
			),
		)

		return nil, diags
	}

	// we sort by descending precedence, default policy is always first
	defaultPolicy := res.Payload.Resources[0]

	return defaultPolicy, diags
}

// ruleGroupAction for prevention policy action api.
type ruleGroupAction int

const (
	removeRuleGroup ruleGroupAction = iota
	addRuleGroup
)

// convertRuleGroupToSet converts a slice of models.IoaRuleGroupsRuleGroupV1 to a terraform set.
func convertRuleGroupToSet(
	ctx context.Context,
	groups []*models.IoaRuleGroupsRuleGroupV1,
) (basetypes.SetValue, diag.Diagnostics) {
	ruleGroups := make([]types.String, 0, len(groups))
	for _, ruleGroup := range groups {
		ruleGroups = append(ruleGroups, types.StringValue(*ruleGroup.ID))
	}

	ruleGroupIDs, diags := types.SetValueFrom(ctx, types.StringType, ruleGroups)

	return ruleGroupIDs, diags
}

// String convert ruleGroupAction to string value the api accepts.
func (r ruleGroupAction) String() string {
	return [...]string{"remove-rule-group", "add-rule-group"}[r]
}

// syncRuleGroups will sync the rule groups from the resource model to the api.
func syncRuleGroups(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	planGroups, stateGroups types.Set,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	groupsToAdd, groupsToRemove, diags := utils.SetIDsToModify(
		ctx,
		planGroups,
		stateGroups,
	)

	diags.Append(diags...)
	if diags.HasError() {
		return diags
	}

	diags.Append(updateRuleGroups(ctx, client, addRuleGroup, groupsToAdd, id)...)
	diags.Append(updateRuleGroups(ctx, client, removeRuleGroup, groupsToRemove, id)...)

	return diags
}

// updateRuleGroups will remove or add a slice of rule groups
// to a slice of prevention policies.
func updateRuleGroups(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	action ruleGroupAction,
	ruleGroupIDs []string,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	if len(ruleGroupIDs) == 0 {
		return diags
	}

	var actionParams []*models.MsaspecActionParameter
	actionMsg := "adding"
	if action == removeRuleGroup {
		actionMsg = "removing"
	}
	name := "rule_group_id"

	for _, g := range ruleGroupIDs {
		gCopy := g
		actionParam := &models.MsaspecActionParameter{
			Name:  &name,
			Value: &gCopy,
		}

		actionParams = append(actionParams, actionParam)
	}

	res, err := client.PreventionPolicies.PerformPreventionPoliciesAction(
		&prevention_policies.PerformPreventionPoliciesActionParams{
			Context:    ctx,
			ActionName: action.String(),
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: actionParams,
				Ids:              []string{id},
			},
		},
	)

	if err != nil {
		diags.AddError("Error updating prevention policy rule groups", fmt.Sprintf(
			"Error %s rule groups (%s) to prevention policy (%s): %s",
			actionMsg,
			strings.Join(ruleGroupIDs, ", "),
			id,
			err.Error(),
		))
	}

	returnedRuleGroups := make(map[string]bool)

	if res != nil && res.Payload != nil {
		for _, r := range res.Payload.Resources {
			groups := r.IoaRuleGroups

			for _, group := range groups {
				returnedRuleGroups[*group.ID] = true
			}
		}
	}

	if action == removeRuleGroup {
		for _, group := range ruleGroupIDs {
			_, ok := returnedRuleGroups[group]
			if ok {
				diags.AddError(
					"Error updating prevention policy rule groups",
					fmt.Sprintf(
						"Error %s rule groups (%s) to prevention policy (%s): %s",
						actionMsg,
						group,
						id,
						"Remove failed",
					),
				)
			}
		}
	}

	if action == addRuleGroup {
		for _, group := range ruleGroupIDs {
			_, ok := returnedRuleGroups[group]
			if !ok {
				diags.AddError(
					"Error updating prevention policy rule groups",
					fmt.Sprintf(
						"Error %s rule groups (%s) to prevention policy (%s): %s",
						actionMsg,
						group,
						id,
						"Adding failed, ensure the rule group is valid.",
					),
				)
			}
		}
	}

	if res == nil || res.Payload == nil {
		for _, err := range res.Payload.Errors {
			diags.AddError(
				"Error updating prevention policy rule groups",
				fmt.Sprintf(
					"Error %s rule group (%s) to prevention policy (%s): %s",
					actionMsg,
					err.ID,
					id,
					err.String(),
				),
			)
		}
	}

	return diags
}

// updatePolicyEnabledState enables or disables a prevention policy.
func updatePolicyEnabledState(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	id string,
	enabled bool,
) (*prevention_policies.PerformPreventionPoliciesActionOK, diag.Diagnostics) {
	var diags diag.Diagnostics

	state := "disable"
	if enabled {
		state = "enable"
	}

	res, err := client.PreventionPolicies.PerformPreventionPoliciesAction(
		&prevention_policies.PerformPreventionPoliciesActionParams{
			ActionName: state,
			Context:    ctx,
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{id},
			},
		},
	)

	if err != nil {
		diags.AddError(
			"Error changing enabled state on prevention policy",
			fmt.Sprintf(
				"Could not %s prevention policy, unexpected error: \n\n %s",
				state,
				err.Error(),
			),
		)
	}

	return res, diags
}

// mapPreventionSettings converts prevention settings returned by the CrowdStrike api
// into the correct types used in the resource model and schema.
func mapPreventionSettings(
	categories []*models.PreventionCategoryRespV1,
) (map[string]types.Bool, map[string]*mlSlider, map[string]*detectionMlSlider) {
	toggleSettings := map[string]types.Bool{}
	mlSliderSettings := map[string]*mlSlider{}
	detectionMlSliderSettings := map[string]*detectionMlSlider{}

	for _, c := range categories {
		for _, s := range c.Settings {
			sID := *s.ID
			sValue := s.Value
			sType := *s.Type
			// the only slider that only supports detection instead of both prevention and detection.
			if sID == "ExtendedUserModeDataSlider" {
				v, _ := sValue.(map[string]interface{})
				detection, _ := v["detection"].(string)
				detectionMlSliderSettings[sID] = &detectionMlSlider{
					Detection: types.StringValue(detection),
				}
				continue
			}

			switch strings.ToLower(sType) {
			case "toggle":
				v, _ := sValue.(map[string]interface{})
				enabled, _ := v["enabled"].(bool)
				toggleSettings[sID] = types.BoolValue(enabled)
			case "mlslider":
				v, _ := sValue.(map[string]interface{})
				detection, _ := v["detection"].(string)
				prevention, _ := v["prevention"].(string)

				mlSliderSettings[sID] = &mlSlider{
					Detection:  types.StringValue(detection),
					Prevention: types.StringValue(prevention),
				}
			}
		}
	}

	return toggleSettings, mlSliderSettings, detectionMlSliderSettings
}

type updatePreventionPolicyOptions struct {
	Name        string
	Description string
}

// updatePreventionPolicy updates a prevention policy with the provided settings.
func updatePreventionPolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	preventionSettings []*models.PreventionSettingReqV1,
	id string,
	options updatePreventionPolicyOptions,
) (*models.PreventionPolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	var preventionPolicy *models.PreventionPolicyV1

	updateParams := prevention_policies.UpdatePreventionPoliciesParams{
		Context: ctx,
		Body: &models.PreventionUpdatePoliciesReqV1{
			Resources: []*models.PreventionUpdatePolicyReqV1{
				{
					ID: &id,
				},
			},
		},
	}

	if options.Name != "" {
		updateParams.Body.Resources[0].Name = options.Name
	}

	updateParams.Body.Resources[0].Description = options.Description

	updateParams.Body.Resources[0].Settings = preventionSettings

	res, err := client.PreventionPolicies.UpdatePreventionPolicies(&updateParams)

	// todo: if we should handle scope and timeout errors instead of giving a vague error
	if err != nil {
		diags.AddError(
			"Error updating prevention policy",
			fmt.Sprintf(
				"Could not update prevention policy, unexpected error: \n\n%s",
				err.Error(),
			),
		)
		return preventionPolicy, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Error updating prevention policy",
			fmt.Sprintf("No policy found with id: %s", id),
		)
	}

	preventionPolicy = res.Payload.Resources[0]

	return preventionPolicy, diags
}

// getPreventionPolicy retrieves a prevention policy by id.
func getPreventionPolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
) (*models.PreventionPolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	var preventionPolicy *models.PreventionPolicyV1

	res, err := client.PreventionPolicies.GetPreventionPolicies(
		&prevention_policies.GetPreventionPoliciesParams{
			Context: ctx,
			Ids:     []string{policyID},
		},
	)

	if err != nil {
		if _, ok := err.(*prevention_policies.GetPreventionPoliciesNotFound); ok {
			diags.Append(
				newNotFoundError(
					fmt.Sprintf("No prevention policy with id: %s found.", policyID),
				),
			)
			return preventionPolicy, diags
		}
		diags.AddError(
			"Error reading CrowdStrike prevention policy",
			fmt.Sprintf(
				"Could not read CrowdStrike prevention policy: %s \n\n %s",
				policyID,
				err.Error(),
			),
		)
		return preventionPolicy, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Error reading CrowdStrike prevention policy",
			fmt.Sprintf(
				"Could not read CrowdStrike prevention policy: %s \n\n %s",
				policyID,
				"No policy found",
			),
		)
		return preventionPolicy, diags
	}

	preventionPolicy = res.GetPayload().Resources[0]
	return preventionPolicy, diags
}

// createPreventionPolicy creates a new prevention policy.
func createPreventionPolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	name, description, platformName string,
	preventionSettings []*models.PreventionSettingReqV1,
) (*prevention_policies.CreatePreventionPoliciesCreated, diag.Diagnostics) {
	var diags diag.Diagnostics
	var res *prevention_policies.CreatePreventionPoliciesCreated

	createParams := prevention_policies.CreatePreventionPoliciesParams{
		Context: ctx,
		Body: &models.PreventionCreatePoliciesReqV1{
			Resources: []*models.PreventionCreatePolicyReqV1{
				{
					Name:         &name,
					Description:  description,
					PlatformName: &platformName,
				},
			},
		},
	}

	createParams.Body.Resources[0].Settings = preventionSettings

	res, err := client.PreventionPolicies.CreatePreventionPolicies(&createParams)

	// todo: if we should handle scope and timeout errors instead of giving a vague error
	if err != nil {
		if strings.Contains(err.Error(), "least one ID must be provided") {
			diags.AddError(
				"Error creating prevention policy",
				"A prevention policy with the same name may already exist.",
			)
		} else {
			diags.AddError(
				"Error creating prevention policy",
				"Could not create prevention policy, unexpected error: "+err.Error(),
			)
		}
	}

	return res, diags
}

// updateHostGroups will remove or add a slice of host groups
// to a slice of prevention policies.
func updateHostGroups(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	action hostgroups.HostGroupAction,
	hostGroupIDs []string,
	policyID string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	if len(hostGroupIDs) == 0 {
		return diags
	}

	var actionParams []*models.MsaspecActionParameter
	actionMsg := "adding"
	if action == hostgroups.RemoveHostGroup {
		actionMsg = "removing"
	}
	name := "group_id"

	for _, g := range hostGroupIDs {
		gCopy := g
		actionParam := &models.MsaspecActionParameter{
			Name:  &name,
			Value: &gCopy,
		}

		actionParams = append(actionParams, actionParam)
	}

	res, err := client.PreventionPolicies.PerformPreventionPoliciesAction(
		&prevention_policies.PerformPreventionPoliciesActionParams{
			Context:    ctx,
			ActionName: action.String(),
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: actionParams,
				Ids:              []string{policyID},
			},
		},
	)

	if err != nil {
		diags.AddError("Error updating prevention policy host groups", fmt.Sprintf(
			"Error %s host groups (%s) to prevention policy (%s): %s",
			actionMsg,
			strings.Join(hostGroupIDs, ", "),
			policyID,
			err.Error(),
		))

		return diags
	}

	returnedHostGroups := make(map[string]bool)

	if res != nil && res.Payload != nil {
		for _, r := range res.Payload.Resources {
			groups := r.Groups

			for _, group := range groups {
				returnedHostGroups[*group.ID] = true
			}
		}
	}

	if action == hostgroups.RemoveHostGroup {
		for _, group := range hostGroupIDs {
			_, ok := returnedHostGroups[group]
			if ok {
				diags.AddError(
					"Error updating prevention policy host groups",
					fmt.Sprintf(
						"Error %s host groups (%s) to prevention policy (%s): %s",
						actionMsg,
						group,
						policyID,
						"Remove failed",
					),
				)
			}
		}
	}

	if action == hostgroups.AddHostGroup {
		for _, group := range hostGroupIDs {
			_, ok := returnedHostGroups[group]
			if !ok {
				diags.AddError(
					"Error updating prevention policy host groups",
					fmt.Sprintf(
						"Error %s host groups (%s) to prevention policy (%s): %s",
						actionMsg,
						group,
						policyID,
						"Adding failed, ensure the host group is valid.",
					),
				)
			}
		}
	}

	if res != nil && res.Payload != nil {
		for _, err := range res.Payload.Errors {
			diags.AddError(
				"Error updating prevention policy host groups",
				fmt.Sprintf(
					"Error %s host groups (%s) to prevention policy (%s): %s",
					actionMsg,
					err.ID,
					policyID,
					err.String(),
				),
			)
		}
	}

	return diags
}

// syncHostGroups will sync the host groups from the resource model to the api.
func syncHostGroups(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	planGroups, stateGroups types.Set,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	groupsToAdd, groupsToRemove, diags := utils.SetIDsToModify(
		ctx,
		planGroups,
		stateGroups,
	)
	diags.Append(diags...)
	if diags.HasError() {
		return diags
	}

	diags.Append(updateHostGroups(ctx, client, hostgroups.AddHostGroup, groupsToAdd, id)...)
	diags.Append(updateHostGroups(ctx, client, hostgroups.RemoveHostGroup, groupsToRemove, id)...)

	return diags
}

// defaultBoolFalse sets the default value of a bool to false if it is not set.
func defaultBoolFalse(v types.Bool) types.Bool {
	if !v.ValueBool() {
		return types.BoolValue(false)
	}

	return v
}

// deletePreventionPolicy deletes a prevention policy by id.
func deletePreventionPolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	_, diags = updatePolicyEnabledState(ctx, client, id, false)

	if diags.HasError() {
		return diags
	}

	_, err := client.PreventionPolicies.DeletePreventionPolicies(
		&prevention_policies.DeletePreventionPoliciesParams{
			Context: ctx,
			Ids:     []string{id},
		},
	)

	if err != nil {
		diags.AddError(
			"Error deleting prevention policy",
			fmt.Sprintf("Could not delete prevention policy: %s \n\n %s", id, err.Error()),
		)
		return diags
	}

	return diags
}
