package fcs

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cspm_registration"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_cloud_aws_account", sweepCloudAWSAccounts)
}

func sweepCloudAWSAccounts(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := cspm_registration.NewGetCSPMAwsAccountParams()
	params.WithContext(ctx)

	resp, _, err := client.CspmRegistration.GetCSPMAwsAccount(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping AWS Cloud Account sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing AWS cloud accounts: %w", err)
	}

	if resp == nil || resp.Payload == nil || resp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, account := range resp.Payload.Resources {
		accountID := account.AccountID
		orgID := account.OrganizationID

		// Only sweep test accounts (account ID starts with 000000 AND org ID starts with o-tfacctest)
		isTestAccount := strings.HasPrefix(accountID, "000000")
		isTestOrg := orgID == "" || strings.HasPrefix(orgID, "o-tfacctest")

		if !isTestAccount || !isTestOrg {
			sweep.Trace("Skipping AWS account %s (not a test account)", accountID)
			continue
		}

		isMaster := account.IsMaster

		id := fmt.Sprintf("%s/%s/%t", accountID, orgID, isMaster)
		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			accountID,
			deleteCloudAWSAccount,
		))
	}

	return sweepables, nil
}

func deleteCloudAWSAccount(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	parts := strings.Split(id, "/")
	if len(parts) != 3 {
		return fmt.Errorf("invalid AWS account ID format: %s", id)
	}
	accountID, orgID, isMasterStr := parts[0], parts[1], parts[2]

	isMaster := isMasterStr == "true"

	params := cspm_registration.NewDeleteCSPMAwsAccountParams()
	params.WithContext(ctx)

	if isMaster && orgID != "" {
		sweep.Info("Deleting master account via organization deletion: %s (org: %s)", accountID, orgID)
		params.OrganizationIds = []string{orgID}
	} else {
		params.Ids = []string{accountID}
		if orgID != "" {
			params.OrganizationIds = []string{orgID}
		}
	}

	_, _, err := client.CspmRegistration.DeleteCSPMAwsAccount(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for AWS account %s: %s", accountID, err)
			return nil
		}
		return err
	}

	return nil
}
