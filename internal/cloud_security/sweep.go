package cloudsecurity

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/admission_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_cloud_security_custom_rule", sweepCustomRules)
	sweep.Register("crowdstrike_cloud_security_kac_policy_precedence", sweepKACPolicyPrecedence)
	sweep.Register("crowdstrike_cloud_security_kac_policy", sweepKACPolicies,
		"crowdstrike_cloud_security_kac_policy_precedence",
	)
	sweep.Register("crowdstrike_cloud_security_suppression_rule", sweepSuppressionRules)
}

func sweepCustomRules(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	queryParams := cloud_policies.NewQueryRuleParams()
	queryParams.WithContext(ctx)

	queryResp, err := client.CloudPolicies.QueryRule(queryParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Cloud Security Custom Rule sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error querying custom rules: %w", err)
	}

	if queryResp == nil || queryResp.Payload == nil || queryResp.Payload.Resources == nil {
		return sweepables, nil
	}

	ruleIDs := queryResp.Payload.Resources
	if len(ruleIDs) == 0 {
		return sweepables, nil
	}

	getParams := cloud_policies.NewGetRuleParams()
	getParams.WithContext(ctx)
	getParams.Ids = ruleIDs

	getResp, err := client.CloudPolicies.GetRule(getParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Cloud Security Custom Rule sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting custom rules: %w", err)
	}

	if getResp == nil || getResp.Payload == nil || getResp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, rule := range getResp.Payload.Resources {
		if rule.Name == nil || rule.UUID == nil {
			continue
		}

		name := *rule.Name
		id := *rule.UUID

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping Custom Rule %s (not a test resource)", name)
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			deleteCustomRule,
		))
	}

	return sweepables, nil
}

func deleteCustomRule(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := cloud_policies.NewDeleteRuleMixin0Params()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.CloudPolicies.DeleteRuleMixin0(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for custom rule %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}

func sweepKACPolicies(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	queryParams := admission_control_policies.NewAdmissionControlQueryPoliciesParams()
	queryParams.WithContext(ctx)

	queryResp, err := client.AdmissionControlPolicies.AdmissionControlQueryPolicies(queryParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping KAC Policy sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error querying KAC policies: %w", err)
	}

	if queryResp == nil || queryResp.Payload == nil || queryResp.Payload.Resources == nil {
		return sweepables, nil
	}

	policyIDs := queryResp.Payload.Resources
	if len(policyIDs) == 0 {
		return sweepables, nil
	}

	getParams := admission_control_policies.NewAdmissionControlGetPoliciesParams()
	getParams.WithContext(ctx)
	getParams.Ids = policyIDs

	getResp, err := client.AdmissionControlPolicies.AdmissionControlGetPolicies(getParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping KAC Policy sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting KAC policies: %w", err)
	}

	if getResp == nil || getResp.Payload == nil || getResp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, policy := range getResp.Payload.Resources {
		if policy.Name == nil || policy.ID == nil {
			continue
		}

		name := *policy.Name
		id := *policy.ID

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping KAC Policy %s (not a test resource)", name)
			continue
		}

		isEnabled := policy.IsEnabled != nil && *policy.IsEnabled

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			makeSweepDeleteKACPolicy(isEnabled),
		))
	}

	return sweepables, nil
}

func makeSweepDeleteKACPolicy(isEnabled bool) func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	return func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
		if isEnabled {
			if err := sweepDisableKACPolicy(ctx, client, id); err != nil {
				return err
			}
		}
		return sweepDeleteKACPolicy(ctx, client, id)
	}
}

func sweepDisableKACPolicy(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := admission_control_policies.NewAdmissionControlUpdatePolicyParams()
	params.WithContext(ctx)
	params.Ids = id
	params.Body = &models.ModelsUpdatePolicyRequest{
		IsEnabled: new(bool),
	}
	*params.Body.IsEnabled = false

	_, err := client.AdmissionControlPolicies.AdmissionControlUpdatePolicy(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for KAC policy %s: %s", id, err)
			return nil
		}
		return err
	}

	sweep.Info("Successfully disabled KAC policy: %s", id)
	return nil
}

func sweepDeleteKACPolicy(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := admission_control_policies.NewAdmissionControlDeletePoliciesParams()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.AdmissionControlPolicies.AdmissionControlDeletePolicies(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for KAC policy %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}

func sweepKACPolicyPrecedence(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	sweep.Info("KAC Policy Precedence is managed via policies - no separate cleanup needed")
	return nil, nil
}

func sweepSuppressionRules(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	queryParams := cloud_policies.NewQuerySuppressionRulesParams()
	queryParams.WithContext(ctx)
	queryParams.Filter = new(string)
	// Match test resources: starts with "TF Test" OR exact matches for example resources
	*queryParams.Filter = "name:~'TF Test'"

	queryResp, err := client.CloudPolicies.QuerySuppressionRules(queryParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Cloud Security Suppression Rule sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error querying suppression rules: %w", err)
	}

	if queryResp == nil || queryResp.Payload == nil || queryResp.Payload.Resources == nil {
		return sweepables, nil
	}

	ruleIDs := queryResp.Payload.Resources
	if len(ruleIDs) == 0 {
		return sweepables, nil
	}

	getParams := cloud_policies.NewGetSuppressionRulesParams()
	getParams.WithContext(ctx)
	getParams.Ids = ruleIDs

	getResp, err := client.CloudPolicies.GetSuppressionRules(getParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Cloud Security Suppression Rule sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting suppression rules: %w", err)
	}

	if getResp == nil || getResp.Payload == nil || getResp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, rule := range getResp.Payload.Resources {
		if rule.Name == nil || rule.ID == nil {
			continue
		}

		name := *rule.Name
		id := *rule.ID

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			deleteSuppressionRule,
		))
	}

	return sweepables, nil
}

func deleteSuppressionRule(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := cloud_policies.NewDeleteSuppressionRulesParams()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.CloudPolicies.DeleteSuppressionRules(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for suppression rule %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
