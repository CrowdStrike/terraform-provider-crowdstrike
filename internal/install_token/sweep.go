package installtoken

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/installation_tokens"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_install_token", sweepInstallTokens)
}

func sweepInstallTokens(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := installation_tokens.NewTokensQueryParams()
	params.WithContext(ctx)

	resp, err := client.InstallationTokens.TokensQuery(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing install tokens: %w", err)
	}

	if resp.Payload == nil || resp.Payload.Resources == nil {
		return sweepables, nil
	}

	getParams := installation_tokens.TokensReadParams{
		Context: ctx,
		Ids:     resp.Payload.Resources,
	}

	getResp, err := client.InstallationTokens.TokensRead(&getParams)
	if err != nil {
		if sweep.SkipSweepError(err) {
			sweep.Warn("Skipping sweep: %s", err)
			return nil, nil
		}
		return nil, fmt.Errorf("error getting install tokens: %w", err)
	}

	if getResp == nil || getResp.Payload == nil || getResp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, token := range getResp.Payload.Resources {
		if token.Label == nil || token.ID == nil {
			continue
		}

		if !strings.HasPrefix(*token.Label, sweep.ResourcePrefix) {
			sweep.Trace("Skipping %s (not a test resource)", *token.Label)
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			*token.ID,
			*token.Label,
			deleteInstallToken,
		))
	}

	return sweepables, nil
}

func deleteInstallToken(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := installation_tokens.TokensDeleteParams{
		Context: ctx,
		Ids:     []string{id},
	}

	_, err := client.InstallationTokens.TokensDelete(&params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for install token %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
