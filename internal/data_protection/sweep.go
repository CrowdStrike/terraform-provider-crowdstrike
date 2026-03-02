package dataprotection

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_data_protection_content_pattern", sweepDataProtectionContentPatterns)
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
