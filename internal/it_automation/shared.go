package itautomation

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/it_automation"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	timeFormat          = time.RFC850
	paginationLimit     = 100
	AccessTypePublic    = "Public"
	AccessTypeShared    = "Shared"
	TaskTypeQuery       = "query"
	TaskTypeAction      = "action"
	TaskTypeRemediation = "remediation"
)

// stringSliceToSet converts a Go string slice to a Terraform Framework Set.
func stringSliceToSet(ctx context.Context, stringSlice []string) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(stringSlice) == 0 {
		return types.SetNull(types.StringType), diags
	}

	values := make([]types.String, 0, len(stringSlice))
	for _, str := range stringSlice {
		values = append(values, types.StringValue(str))
	}

	set, setDiags := types.SetValueFrom(ctx, types.StringType, values)
	diags.Append(setDiags...)

	return set, diags
}

// setToStringSlice converts a Terraform Framework Set to a Go string slice.
func setToStringSlice(ctx context.Context, set types.Set) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	if set.IsNull() || set.IsUnknown() {
		return []string{}, diags
	}

	var tfList []types.String
	diags.Append(set.ElementsAs(ctx, &tfList, false)...)
	if diags.HasError() {
		return []string{}, diags
	}

	result := make([]string, 0, len(tfList))
	for _, item := range tfList {
		if !item.IsNull() && !item.IsUnknown() {
			result = append(result, item.ValueString())
		}
	}

	return result, diags
}

// preserveStringField preserves configured field values over API values.
func preserveStringField(apiVal *string, current types.String, target *types.String) {
	if !current.IsNull() {
		*target = current
	} else if apiVal != nil && *apiVal != "" {
		*target = types.StringValue(*apiVal)
	}
}

// setBoolPointer sets a boolean pointer field if the terraform field is not null.
func setBoolPointer(field types.Bool, target **bool) {
	if !field.IsNull() {
		val := field.ValueBool()
		*target = &val
	}
}

// idsDiff performs the diff on a list of planned and current IDs and returns two string slices of IDs to remove and add.
func idsDiff(
	ctx context.Context,
	currentIds []string,
	plannedIds types.Set,
) (diag.Diagnostics, []string, []string) {
	var planIds []string
	diags := plannedIds.ElementsAs(ctx, &planIds, false)
	currentIdsMap := make(map[string]bool)
	for _, id := range currentIds {
		currentIdsMap[id] = true
	}

	var idsToAdd []string
	for _, id := range planIds {
		if !currentIdsMap[id] {
			idsToAdd = append(idsToAdd, id)
		}
		delete(currentIdsMap, id)
	}

	var idsToRemove []string
	for id := range currentIdsMap {
		idsToRemove = append(idsToRemove, id)
	}
	return diags, idsToAdd, idsToRemove
}

// getItAutomationTask retrieves a task by ID.
func getItAutomationTask(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	taskID string,
) (*models.ItautomationTask, diag.Diagnostics) {
	var diags diag.Diagnostics

	getResponse, err := client.ItAutomation.ITAutomationGetTasks(
		&it_automation.ITAutomationGetTasksParams{
			Context: ctx,
			Ids:     []string{taskID},
		})

	if getResponse != nil && getResponse.Payload != nil && len(getResponse.Payload.Resources) > 0 {
		return getResponse.Payload.Resources[0], diags
	}

	if err != nil {
		if _, ok := err.(*it_automation.ITAutomationGetTasksNotFound); ok {
			diags.Append(
				newTaskNotFoundError(
					fmt.Sprintf("No IT automation task with id: %s found.", taskID),
				),
			)
		} else {
			diags.AddError(
				"Error reading IT automation task",
				fmt.Sprintf("Could not read task ID %s: %s", taskID, err.Error()),
			)
		}
	} else {
		diags.Append(
			newTaskNotFoundError(
				fmt.Sprintf("Task ID %s not found in API response", taskID),
			),
		)
	}

	return nil, diags
}

// getItAutomationTaskGroup retrieves a task group by ID.
func getItAutomationTaskGroup(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	groupID string,
) (*models.ItautomationTaskGroup, diag.Diagnostics) {
	var diags diag.Diagnostics

	ok, multi, err := client.ItAutomation.ITAutomationGetTaskGroups(
		&it_automation.ITAutomationGetTaskGroupsParams{
			Context: ctx,
			Ids:     []string{groupID},
		})

	if ok != nil && ok.Payload != nil && len(ok.Payload.Resources) > 0 {
		return ok.Payload.Resources[0], diags
	}

	if multi != nil && multi.Payload != nil && len(multi.Payload.Resources) > 0 {
		return multi.Payload.Resources[0], diags
	}

	if err != nil {
		if isNotFoundError(err) {
			diags.Append(
				newTaskGroupNotFoundError(
					fmt.Sprintf("No IT automation task group with id: %s found.", groupID),
				),
			)
		} else {
			diags.AddError(
				"Error reading IT automation task group",
				fmt.Sprintf("Could not read task group ID %s: %s", groupID, err.Error()),
			)
		}
	} else {
		diags.Append(
			newTaskGroupNotFoundError(
				fmt.Sprintf("Task group ID %s not found in API response", groupID),
			),
		)
	}

	return nil, diags
}

// getItAutomationPolicy retrieves a policy by ID.
func getItAutomationPolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
) (*models.ItautomationPolicy, diag.Diagnostics) {
	var diags diag.Diagnostics
	var policy *models.ItautomationPolicy

	params := &it_automation.ITAutomationGetPoliciesParams{
		Context: ctx,
		Ids:     []string{policyID},
	}

	ok, err := client.ItAutomation.ITAutomationGetPolicies(params)
	if ok != nil && ok.Payload != nil && len(ok.Payload.Resources) > 0 {
		policy = ok.Payload.Resources[0]
		return policy, diags
	}

	if err != nil {
		if isNotFoundError(err) {
			diags.Append(
				newPolicyNotFoundError(
					fmt.Sprintf("No IT automation policy with id: %s found.", policyID),
				),
			)
		} else {
			diags.AddError(
				"Error reading IT automation policies",
				fmt.Sprintf("Could not read policy ID %s: %s", policyID, err.Error()),
			)
		}
	} else {
		diags.Append(
			newPolicyNotFoundError(
				fmt.Sprintf("Policy ID %s not found in API response", policyID),
			),
		)
	}

	return nil, diags
}

// isDefaultPolicy checks if a policy name matches the Default Policy pattern.
func isDefaultPolicy(name string) bool {
	return strings.HasPrefix(name, "Default Policy (") && strings.HasSuffix(name, ")")
}

// getItAutomationPolicies returns all policies and a string slice of IDs in precedence order.
func getItAutomationPolicies(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	platform string,
) ([]*models.ItautomationPolicy, []string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var policies []*models.ItautomationPolicy
	var precedence []string
	var allPolicyIds []string

	limit := int64(paginationLimit)
	offset := int64(0)

	for {
		queryParams := &it_automation.ITAutomationQueryPoliciesParams{
			Context:  ctx,
			Limit:    &limit,
			Offset:   &offset,
			Platform: platform,
		}

		ok, err := client.ItAutomation.ITAutomationQueryPolicies(queryParams)
		if err != nil {
			diags.AddError(
				"Error querying IT automation policies",
				fmt.Sprintf("Could not query IT automation policies: %s", err.Error()),
			)
			return policies, precedence, diags
		}

		if ok == nil || ok.Payload == nil {
			break
		}

		if len(ok.Payload.Resources) > 0 {
			allPolicyIds = append(allPolicyIds, ok.Payload.Resources...)
		}

		if len(ok.Payload.Resources) < int(limit) {
			break
		}

		offset += limit
	}

	if len(allPolicyIds) == 0 {
		diags.AddError(
			"No IT automation policies found",
			fmt.Sprintf("No policies found for platform %s", platform),
		)
		return policies, precedence, diags
	}

	getParams := &it_automation.ITAutomationGetPoliciesParams{
		Context: ctx,
		Ids:     allPolicyIds,
	}

	getResp, err := client.ItAutomation.ITAutomationGetPolicies(getParams)
	if err != nil {
		diags.AddError(
			"Error reading IT automation policies",
			fmt.Sprintf("Could not read IT automation policies: %s", err.Error()),
		)
		return policies, precedence, diags
	}

	if getResp == nil || getResp.Payload == nil || len(getResp.Payload.Resources) == 0 {
		diags.AddError(
			"Error reading IT automation policies",
			"No policies were returned in the API response",
		)
		return policies, precedence, diags
	}

	policies = getResp.Payload.Resources

	sort.Slice(policies, func(i, j int) bool {
		if policies[i] == nil {
			return false
		}
		if policies[j] == nil {
			return true
		}
		return policies[i].Precedence < policies[j].Precedence
	})

	precedence = make([]string, 0, len(policies))
	for _, policy := range policies {
		if policy != nil && policy.ID != nil && policy.Name != nil && !isDefaultPolicy(*policy.Name) {
			precedence = append(precedence, *policy.ID)
		}
	}

	return policies, precedence, diags
}

// hasTaskGroupMembership checks if a task has group memberships.
func hasTaskGroupMembership(groups any) bool {
	switch g := groups.(type) {
	case []*models.FalconforitapiGroupMembership:
		return len(g) > 0 && g[0] != nil && g[0].ID != nil
	case []*models.ItautomationTaskGroup:
		return len(g) > 0 && g[0] != nil && g[0].ID != nil
	default:
		return false
	}
}

// isNotFoundError checks if an error indicates a resource was not found.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return strings.Contains(strings.ToLower(errMsg), "not found") || strings.Contains(errMsg, "404")
}
