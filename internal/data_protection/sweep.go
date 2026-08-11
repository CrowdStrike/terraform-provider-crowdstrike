package dataprotection

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_data_protection_content_pattern", sweepDataProtectionContentPatterns)
	sweep.Register("crowdstrike_data_protection_policy", sweepDataProtectionPolicies)
	sweep.Register("crowdstrike_data_protection_sensitivity_label", sweepDataProtectionSensitivityLabels)
}

func sweepDataProtectionContentPatterns(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := data_protection_configuration.NewQueriesContentPatternGetV2Params()
	params.WithContext(ctx)
	params.Filter = utils.Addr(fmt.Sprintf("deleted:false+name:~'%s'", sweep.ResourcePrefix))

	resp, err := client.DataProtectionConfiguration.QueriesContentPatternGetV2(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Data Protection Content Pattern sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing data protection content patterns: %w", err)
	}

	if resp == nil || resp.Payload == nil || resp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, id := range resp.Payload.Resources {
		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			id,
			deleteDataProtectionContentPattern,
		))
	}

	return sweepables, nil
}

func deleteDataProtectionContentPattern(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := data_protection_configuration.NewEntitiesContentPatternDeleteParams()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.DataProtectionConfiguration.EntitiesContentPatternDelete(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for data protection content pattern %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}

func sweepDataProtectionSensitivityLabels(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := data_protection_configuration.NewQueriesSensitivityLabelGetV2Params()
	params.WithContext(ctx)
	params.Filter = utils.Addr(fmt.Sprintf("deleted:false+name:~'%s'", sweep.ResourcePrefix))

	resp, err := client.DataProtectionConfiguration.QueriesSensitivityLabelGetV2(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Data Protection Sensitivity Label sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing data protection sensitivity labels: %w", err)
	}

	if resp == nil || resp.Payload == nil || resp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, id := range resp.Payload.Resources {
		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			id,
			deleteDataProtectionSensitivityLabel,
		))
	}

	return sweepables, nil
}

func deleteDataProtectionSensitivityLabel(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := data_protection_configuration.NewEntitiesSensitivityLabelDeleteV2Params()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.DataProtectionConfiguration.EntitiesSensitivityLabelDeleteV2(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for data protection sensitivity label %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}

// policySweepPageSize is both the query page size and the hydration batch size.
const policySweepPageSize = 100

func sweepDataProtectionPolicies(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	// The query endpoint partitions policies by platform and takes the wire value,
	// so it is enumerated once per platform.
	for _, wirePlatform := range []string{apiPlatformWin, apiPlatformMac} {
		ids, skipped, err := listPolicyIDs(ctx, client, wirePlatform)
		if skipped {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}

		// The query endpoint returns IDs only, and its FQL name filter is
		// unreliable, so names are matched client-side after hydrating each page.
		for chunk := range slices.Chunk(ids, policySweepPageSize) {
			policies, err := getPolicies(ctx, client, chunk)
			if err != nil {
				return nil, err
			}

			for _, policy := range policies {
				if policy == nil || policy.ID == nil || policy.Name == nil {
					continue
				}
				if !strings.HasPrefix(*policy.Name, sweep.ResourcePrefix) {
					continue
				}

				sweepables = append(sweepables, sweep.NewSweepResource(
					*policy.ID,
					*policy.Name,
					deleteDataProtectionPolicyOn(wirePlatform),
				))
			}
		}
	}

	return sweepables, nil
}

// listPolicyIDs pages through every policy on one platform. Pagination is driven
// by meta.pagination.total because the endpoint echoes the requested offset back
// even when it exceeds the total, making offset useless as a stop condition.
func listPolicyIDs(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	wirePlatform string,
) (ids []string, skipped bool, err error) {
	for offset := int64(0); ; offset += policySweepPageSize {
		params := data_protection_configuration.NewQueriesPolicyGetV2Params()
		params.WithContext(ctx)
		params.PlatformName = wirePlatform
		params.Limit = utils.Addr(int64(policySweepPageSize))
		params.Offset = utils.Addr(offset)

		resp, err := client.DataProtectionConfiguration.QueriesPolicyGetV2(params)
		if sweep.SkipSweepError(err) {
			sweep.Warn("Skipping Data Protection Policy sweep: %s", err)
			return nil, true, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("error listing data protection policies (%s): %w", wirePlatform, err)
		}

		if resp == nil || resp.Payload == nil {
			return ids, false, nil
		}

		ids = append(ids, resp.Payload.Resources...)

		total := int64(0)
		if resp.Payload.Meta != nil && resp.Payload.Meta.Pagination != nil &&
			resp.Payload.Meta.Pagination.Total != nil {
			total = *resp.Payload.Meta.Pagination.Total
		}

		if int64(len(ids)) >= total || len(resp.Payload.Resources) == 0 {
			return ids, false, nil
		}
	}
}

// getPolicies hydrates one batch of IDs. Names and platforms are only available
// from the entity endpoint.
func getPolicies(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	ids []string,
) ([]*models.PolicymanagerExternalPolicy, error) {
	params := data_protection_configuration.NewEntitiesPolicyGetV2Params()
	params.WithContext(ctx)
	params.Ids = ids

	resp, err := client.DataProtectionConfiguration.EntitiesPolicyGetV2(params)
	if err != nil {
		return nil, fmt.Errorf("error reading data protection policies: %w", err)
	}

	if resp == nil || resp.Payload == nil {
		return nil, nil
	}

	return resp.Payload.Resources, nil
}

// deleteDataProtectionPolicyOn returns a delete function bound to a platform,
// which the delete endpoint requires as a query parameter.
func deleteDataProtectionPolicyOn(
	wirePlatform string,
) func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	return func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
		// The API refuses to delete an enabled policy.
		disable := &models.PolicymanagerUpdatePoliciesRequest{
			Resources: []*models.PolicymanagerExternalPolicyPatch{
				{ID: &id, IsEnabled: utils.Addr(false)},
			},
		}

		patchParams := data_protection_configuration.NewEntitiesPolicyPatchV2Params()
		patchParams.WithContext(ctx)
		patchParams.PlatformName = wirePlatform
		patchParams.Body = disable

		if _, err := client.DataProtectionConfiguration.EntitiesPolicyPatchV2(patchParams); err != nil {
			if sweep.ShouldIgnoreError(err) {
				sweep.Debug("Ignoring error disabling data protection policy %s: %s", id, err)
				return nil
			}
			return fmt.Errorf("disabling data protection policy %s: %w", id, err)
		}

		deleteParams := data_protection_configuration.NewEntitiesPolicyDeleteV2Params()
		deleteParams.WithContext(ctx)
		deleteParams.PlatformName = wirePlatform
		deleteParams.Ids = []string{id}

		if _, err := client.DataProtectionConfiguration.EntitiesPolicyDeleteV2(deleteParams); err != nil {
			if sweep.ShouldIgnoreError(err) {
				sweep.Debug("Ignoring error for data protection policy %s: %s", id, err)
				return nil
			}
			return err
		}

		return nil
	}
}
