package user

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_user", sweepUser)
}

func sweepUser(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	filter := fmt.Sprintf("uid:*'*%s*'", sweep.ResourcePrefix)
	queryParams := user_management.NewQueryUserV1ParamsWithContext(ctx)
	queryParams.Filter = &filter

	queryResp, err := client.UserManagement.QueryUserV1(queryParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping user sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing users: %w", err)
	}

	if queryResp == nil || queryResp.Payload == nil || len(queryResp.Payload.Resources) == 0 {
		return sweepables, nil
	}

	getParams := user_management.NewRetrieveUsersGETV1ParamsWithContext(ctx)
	getParams.Body = &models.MsaspecIdsRequest{Ids: queryResp.Payload.Resources}

	getResp, err := client.UserManagement.RetrieveUsersGETV1(getParams)
	if err != nil {
		if sweep.SkipSweepError(err) {
			sweep.Warn("Skipping user sweep: %s", err)
			return nil, nil
		}
		return nil, fmt.Errorf("error getting users: %w", err)
	}

	if getResp == nil || getResp.Payload == nil {
		return sweepables, nil
	}

	for _, user := range getResp.Payload.Resources {
		if user == nil || user.UUID == "" {
			continue
		}

		if !strings.Contains(user.UID, sweep.ResourcePrefix) {
			sweep.Trace("Skipping user %s (not a test resource)", user.UID)
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			user.UUID,
			user.UID,
			deleteUser,
		))
	}

	return sweepables, nil
}

func deleteUser(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	deleteParams := user_management.NewDeleteUserV1ParamsWithContext(ctx)
	deleteParams.UserUUID = id

	_, err := client.UserManagement.DeleteUserV1(deleteParams)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for user %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
