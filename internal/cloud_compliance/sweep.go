package cloudcompliance

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_cloud_compliance_custom_framework", sweepCustomFrameworks)
}

func sweepCustomFrameworks(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	queryParams := cloud_policies.NewQueryComplianceFrameworksParams()
	queryParams.WithContext(ctx)

	queryResp, err := client.CloudPolicies.QueryComplianceFrameworks(queryParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Cloud Compliance Custom Framework sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error querying compliance frameworks: %w", err)
	}

	if queryResp == nil || queryResp.Payload == nil || queryResp.Payload.Resources == nil {
		return sweepables, nil
	}

	frameworkIDs := queryResp.Payload.Resources
	if len(frameworkIDs) == 0 {
		return sweepables, nil
	}

	getParams := cloud_policies.NewGetComplianceFrameworksParams()
	getParams.WithContext(ctx)
	getParams.Ids = frameworkIDs

	getResp, err := client.CloudPolicies.GetComplianceFrameworks(getParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Cloud Compliance Custom Framework sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting compliance frameworks: %w", err)
	}

	if getResp == nil || getResp.Payload == nil || getResp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, framework := range getResp.Payload.Resources {
		if framework.Name == nil {
			continue
		}

		name := *framework.Name

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping Compliance Framework %s (not a test resource)", name)
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			framework.UUID,
			name,
			deleteCustomFramework,
		))
	}

	return sweepables, nil
}

func deleteCustomFramework(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := cloud_policies.NewDeleteComplianceFrameworkParams()
	params.WithContext(ctx)
	params.SetIds(id)

	_, err := client.CloudPolicies.DeleteComplianceFramework(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for custom framework %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
