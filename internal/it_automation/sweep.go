package itautomation

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/it_automation"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_it_automation_task_group", sweepTaskGroups)
	sweep.Register("crowdstrike_it_automation_task", sweepTasks,
		"crowdstrike_it_automation_task_group",
	)
	sweep.Register("crowdstrike_it_automation_policy", sweepPolicies)
}

func sweepTasks(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := it_automation.NewITAutomationGetTasksByQueryParams()
	params.WithContext(ctx)

	resp, err := client.ItAutomation.ITAutomationGetTasksByQuery(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping IT Automation Task sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing IT automation tasks: %w", err)
	}

	if resp.Payload == nil || resp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, task := range resp.Payload.Resources {
		if task.Name == nil {
			continue
		}
		name := *task.Name

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping IT Automation Task %s (not a test resource)", name)
			continue
		}

		if task.ID == nil {
			continue
		}
		id := *task.ID

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			deleteTask,
		))
	}

	return sweepables, nil
}

func deleteTask(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := it_automation.NewITAutomationDeleteTaskParams()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.ItAutomation.ITAutomationDeleteTask(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for IT automation task %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}

func sweepTaskGroups(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := it_automation.NewITAutomationGetTaskGroupsByQueryParams()
	params.WithContext(ctx)

	resp, _, err := client.ItAutomation.ITAutomationGetTaskGroupsByQuery(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping IT Automation Task Group sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing IT automation task groups: %w", err)
	}

	if resp == nil || resp.Payload == nil || resp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, taskGroup := range resp.Payload.Resources {
		if taskGroup.Name == nil {
			continue
		}
		name := *taskGroup.Name

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping IT Automation Task Group %s (not a test resource)", name)
			continue
		}

		if taskGroup.ID == nil {
			continue
		}
		id := *taskGroup.ID

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			deleteTaskGroup,
		))
	}

	return sweepables, nil
}

func deleteTaskGroup(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := it_automation.NewITAutomationDeleteTaskGroupsParams()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, _, err := client.ItAutomation.ITAutomationDeleteTaskGroups(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for IT automation task group %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}

func sweepPolicies(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable
	platforms := []string{"Windows", "Linux", "Mac"}
	var allPolicyIDs []string

	for _, platform := range platforms {
		queryParams := it_automation.NewITAutomationQueryPoliciesParams()
		queryParams.WithContext(ctx)
		queryParams.Platform = platform

		queryResp, err := client.ItAutomation.ITAutomationQueryPolicies(queryParams)
		if sweep.SkipSweepError(err) {
			sweep.Warn("Skipping IT Automation Policy sweep for platform %s: %s", platform, err)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("error listing IT automation policies for platform %s: %w", platform, err)
		}

		if queryResp.Payload != nil && queryResp.Payload.Resources != nil && len(queryResp.Payload.Resources) > 0 {
			allPolicyIDs = append(allPolicyIDs, queryResp.Payload.Resources...)
		}
	}

	if len(allPolicyIDs) == 0 {
		return sweepables, nil
	}

	getParams := it_automation.NewITAutomationGetPoliciesParams()
	getParams.WithContext(ctx)
	getParams.Ids = allPolicyIDs

	getResp, err := client.ItAutomation.ITAutomationGetPolicies(getParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping IT Automation Policy sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting IT automation policies: %w", err)
	}

	if getResp.Payload == nil || getResp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, policy := range getResp.Payload.Resources {
		if policy.Name == nil {
			continue
		}
		name := *policy.Name

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping IT Automation Policy %s (not a test resource)", name)
			continue
		}

		if policy.ID == nil {
			continue
		}
		id := *policy.ID
		isEnabled := policy.IsEnabled

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			makeSweepDeletePolicy(isEnabled),
		))
	}

	return sweepables, nil
}

func makeSweepDeletePolicy(isEnabled bool) func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	return func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
		if isEnabled {
			if err := disablePolicy(ctx, client, id); err != nil {
				return err
			}
		}
		return deletePolicy(ctx, client, id)
	}
}

func disablePolicy(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	isEnabledFalse := false
	params := it_automation.NewITAutomationUpdatePoliciesParams()
	params.WithContext(ctx)
	params.Body = &models.ItautomationUpdatePolicyRequest{
		ID:        id,
		IsEnabled: &isEnabledFalse,
	}

	_, err := client.ItAutomation.ITAutomationUpdatePolicies(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for IT automation policy %s: %s", id, err)
			return nil
		}
		return err
	}

	sweep.Info("Successfully disabled IT automation policy: %s", id)
	return nil
}

func deletePolicy(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := it_automation.NewITAutomationDeletePolicyParams()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.ItAutomation.ITAutomationDeletePolicy(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for IT automation policy %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
