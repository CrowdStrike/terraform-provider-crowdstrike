package certificatebasedexclusion

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/certificate_based_exclusions"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_certificate_based_exclusion", sweepCertificateBasedExclusions)
}

func sweepCertificateBasedExclusions(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := certificate_based_exclusions.NewCbExclusionsQueryV1Params()
	params.WithContext(ctx)
	params.Filter = utils.Addr(fmt.Sprintf("name:~'%s'", sweep.ResourcePrefix))

	resp, err := client.CertificateBasedExclusions.CbExclusionsQueryV1(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Certificate Based Exclusion sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing certificate based exclusions: %w", err)
	}

	if resp == nil || resp.Payload == nil || resp.Payload.Resources == nil || len(resp.Payload.Resources) == 0 {
		return sweepables, nil
	}

	getParams := certificate_based_exclusions.NewCbExclusionsGetV1Params()
	getParams.WithContext(ctx)
	getParams.SetIds(resp.Payload.Resources)

	getResp, err := client.CertificateBasedExclusions.CbExclusionsGetV1(getParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Certificate Based Exclusion sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting certificate based exclusions: %w", err)
	}

	if getResp == nil || getResp.Payload == nil || getResp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, exclusion := range getResp.Payload.Resources {
		if exclusion == nil || exclusion.ID == nil {
			continue
		}

		if !strings.HasPrefix(exclusion.Name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping Certificate Based Exclusion %s (not a test resource)", exclusion.Name)
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			*exclusion.ID,
			exclusion.Name,
			deleteCertificateBasedExclusion,
		))
	}

	return sweepables, nil
}

func deleteCertificateBasedExclusion(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := certificate_based_exclusions.NewCbExclusionsDeleteV1ParamsWithContext(ctx)
	params.SetIds([]string{id})

	_, err := client.CertificateBasedExclusions.CbExclusionsDeleteV1(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for certificate based exclusion %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
